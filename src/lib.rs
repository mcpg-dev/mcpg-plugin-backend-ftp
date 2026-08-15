//! FTP/FTPS file-integration backend binding plugin for mcpg.
//!
//! Implements [`FtpBackendPlugin`] — `BackendPlugin` for `kind: "ftp"`.
//! `op: list` lists a directory, `op: get` reads a file, `op: put` writes a
//! file, over FTP with explicit AUTH-TLS (FTPS) required by default
//! (suppaftp on a pure-Rust rustls/ring stack). The target path comes from
//! the call arguments (with `..` rejected), joined under the
//! operator-configured `path` base. Structurally mirrors the sftp backend;
//! protocol machinery lives in [`ftp`] + [`envelope`].

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    ResourcePage, firstparty_manifest,
};
use mcpg_plugin_sdk::HostHandle;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::debug;

/// cdylib sync bridge.
pub mod cdylib;
mod envelope;
mod ftp;
/// MCP surface shaping (tool vs file-as-resource).
pub mod surface;
mod types;
/// Polling directory-watch `watch_strategy` entity (kind `ftp_dir_poll`).
pub mod watch;

use envelope::{FtpOutcome, build_result_envelope, classify_error};
use ftp::FtpConn;
use surface::Surface;
pub use types::{FtpBackendSpec, FtpOp};

/// Embedded plugin descriptor.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

// --------------------------------------------------------------------- obs

fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.ftp.request_timeout"),
        "transport_error" => Some("dev.mcpg.backend.ftp.request_failed"),
        "ftp_error" => Some("dev.mcpg.backend.ftp.operation_rejected"),
        "invalid_spec" => Some("dev.mcpg.backend.ftp.request_failed"),
        _ => None,
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.ftp".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn finalize_payload(envelope: Value) -> Result<BackendResponse, BackendError> {
    let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
        message: format!("FTP plugin envelope serialization failed: {e}"),
    })?;
    Ok(BackendResponse {
        payload,
        truncated: false,
    })
}

fn extract_put_content(args: &Value) -> Result<Vec<u8>, String> {
    if let Some(b64) = args.get("content").and_then(|v| v.as_str()) {
        use base64::Engine as _;
        return base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("'content' is not valid base64: {e}"));
    }
    if let Some(text) = args.get("text").and_then(|v| v.as_str()) {
        return Ok(text.as_bytes().to_vec());
    }
    Err("put requires a 'content' (base64) or 'text' argument".to_owned())
}

// ------------------------------------------------------------------ plugin

/// Per-binding FTP runtime. Cheap to clone; FTP connect per call.
#[derive(Clone)]
struct FtpProfile {
    op: FtpOp,
    conn: FtpConn,
    base_path: String,
    max_bytes: usize,
    timeout: Duration,
    surface: Surface,
    uri_template: String,
}

/// `BackendPlugin` implementation for `kind: "ftp"`.
pub struct FtpBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, FtpProfile>>,
    host_handle: OnceLock<HostHandle>,
}

impl Default for FtpBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl FtpBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.ftp",
                name: "FTP Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_ftp_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_ftp_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );
        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("ftp-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("ftp-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(target: "mcpg::ftp::host_handle", error = %join_err, "audit spawn_blocking failed");
            }
        }
    }
}

impl std::fmt::Debug for FtpBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for FtpBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "ftp"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        _host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: FtpBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("FTP binding spec: {e}"),
            })?;

        let invalid = |m: String| BackendError::InvalidSpec { message: m };
        if parsed.host.trim().is_empty() {
            return Err(invalid("host must not be empty".into()));
        }
        if parsed.user.trim().is_empty() {
            return Err(invalid("user must not be empty".into()));
        }
        if parsed.password.is_empty() {
            return Err(invalid("password must not be empty".into()));
        }
        if parsed.password.starts_with("cred://") {
            return Err(invalid(
                "password must not be a cred:// URI — per-caller credentials are unsupported; \
                 use ${env.X} / vault:// (resolved at config load)"
                    .into(),
            ));
        }
        if parsed.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0".into()));
        }
        if parsed.max_bytes == 0 {
            return Err(invalid("max_bytes must be greater than 0".into()));
        }

        debug!(
            backend = %backend_name,
            op = parsed.op.as_str(),
            host = %parsed.host,
            tls = parsed.tls,
            "registered FTP binding profile"
        );

        self.profiles.write().await.insert(
            backend_name.to_owned(),
            FtpProfile {
                op: parsed.op,
                conn: FtpConn {
                    host: parsed.host,
                    port: parsed.port,
                    user: parsed.user,
                    password: parsed.password,
                    tls: parsed.tls,
                },
                base_path: parsed.path,
                max_bytes: parsed.max_bytes,
                timeout: Duration::from_millis(parsed.timeout_ms),
                surface: parsed.surface,
                uri_template: parsed.uri,
            },
        );
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let started = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "ftp_backend.execute",
                json!({ "backend": backend_name, "request_id": request_id }),
            )
        });

        let profile = {
            let guard = self.profiles.read().await;
            match guard.get(backend_name).cloned() {
                Some(p) => p,
                None => {
                    let err = BackendError::ProfileNotFound {
                        backend_name: backend_name.to_owned(),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "profile_not_found",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| backend_name.to_owned());

        let arguments: Value = if request.payload.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&request.payload).unwrap_or(Value::Null)
        };
        // On the resource surface the gateway supplies the requested resource
        // URI; recover the file path from it (via the `uri` template) so a
        // `resources/read` fetches the right file. The tool surface reads the
        // path straight from the `path` argument.
        let path_arg = match profile.surface {
            Surface::Tool => arguments
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            Surface::Resource => {
                surface::resolve_read_path(&profile.uri_template, &arguments).unwrap_or_default()
            }
        };

        // Connect + run, bounded by the per-call timeout. The resource surface
        // always fetches a single file (a `resources/read`), independent of the
        // configured `op`; the tool surface runs the configured `op`.
        let work = async {
            if matches!(profile.surface, Surface::Resource) && path_arg.trim().is_empty() {
                return Err(
                    "resource surface requires a resolvable `uri` (or `path`) to read".to_owned(),
                );
            }
            if matches!(profile.surface, Surface::Tool)
                && matches!(profile.op, FtpOp::Get | FtpOp::Put)
                && path_arg.trim().is_empty()
            {
                return Err(format!(
                    "op '{}' requires a 'path' argument",
                    profile.op.as_str()
                ));
            }
            let resolved = ftp::resolve_path(&profile.base_path, &path_arg)?;
            if matches!(profile.surface, Surface::Resource) {
                return ftp::get(&profile.conn, &resolved, profile.max_bytes)
                    .await
                    .map(|data| FtpOutcome {
                        size: Some(data.len()),
                        content: Some(ftp::decode_content(&data)),
                        ..Default::default()
                    });
            }
            match profile.op {
                FtpOp::List => {
                    ftp::list(&profile.conn, &resolved)
                        .await
                        .map(|entries| FtpOutcome {
                            entries: Some(entries),
                            ..Default::default()
                        })
                }
                FtpOp::Get => ftp::get(&profile.conn, &resolved, profile.max_bytes)
                    .await
                    .map(|data| FtpOutcome {
                        size: Some(data.len()),
                        content: Some(ftp::decode_content(&data)),
                        ..Default::default()
                    }),
                FtpOp::Put => {
                    let content = extract_put_content(&arguments)?;
                    if content.len() > profile.max_bytes {
                        return Err(format!("content exceeds max_bytes ({})", profile.max_bytes));
                    }
                    ftp::put(&profile.conn, &resolved, &content)
                        .await
                        .map(|n| FtpOutcome {
                            written: Some(n),
                            ..Default::default()
                        })
                }
            }
        };
        let result = match tokio::time::timeout(profile.timeout, work).await {
            Ok(r) => r,
            Err(_) => Err("FTP operation timed out".to_owned()),
        };

        let (envelope, outcome_label, audit_reason): (Value, &'static str, Option<String>) =
            match result {
                // The resource surface reshapes a fetched file into the
                // `resources/read` `{contents:[…]}` body the gateway decoder
                // requires; the tool surface keeps the historical envelope.
                Ok(outcome) if matches!(profile.surface, Surface::Resource) => {
                    let uri = surface::fill_uri_template(&profile.uri_template, &path_arg);
                    let mime = surface::mime_type_for(&path_arg);
                    let content = outcome.content.clone().unwrap_or(Value::Null);
                    (
                        surface::resource_contents_body(&uri, mime, &content),
                        "ok",
                        None,
                    )
                }
                Ok(outcome) => (
                    build_result_envelope(
                        &tool_name,
                        backend_name,
                        profile.op.as_str(),
                        &profile.conn.host,
                        &path_arg,
                        Some(&outcome),
                        started.elapsed().as_millis(),
                        None,
                        None,
                    ),
                    "ok",
                    None,
                ),
                Err(message) => {
                    let downstream = classify_error(&message);
                    let lower = message.to_ascii_lowercase();
                    let label = if lower.contains("timed out") || lower.contains("timeout") {
                        "timeout"
                    } else if downstream["kind"] == json!("transport_error") {
                        "transport_error"
                    } else {
                        "ftp_error"
                    };
                    let env = build_result_envelope(
                        &tool_name,
                        backend_name,
                        profile.op.as_str(),
                        &profile.conn.host,
                        &path_arg,
                        None,
                        started.elapsed().as_millis(),
                        Some(&downstream),
                        Some(&message),
                    );
                    (env, label, Some(message))
                }
            };

        self.emit_host_observability(
            backend_name,
            outcome_label,
            audit_reason.as_deref(),
            identity.as_ref(),
            &request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("ftp.transport".to_owned(), json!("plugin"));
        map
    }

    /// Enumerate the configured `path` directory into one resource per file for
    /// `resources/list`. Only `surface: resource` bindings list; `tool`
    /// bindings inherit the empty page (the trait default). FTP `LIST` is not
    /// natively paginated, so the whole directory returns in one page (no
    /// `next_cursor`). The `..`-reject applies to the base path.
    async fn list_resources(
        &self,
        backend_name: &str,
        _cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        if profile.surface != Surface::Resource {
            return Ok(ResourcePage::empty());
        }
        let resolved = ftp::resolve_path(&profile.base_path, "")
            .map_err(|message| BackendError::InvalidSpec { message })?;
        let entries = tokio::time::timeout(profile.timeout, ftp::list(&profile.conn, &resolved))
            .await
            .map_err(|_| BackendError::Transport {
                message: "FTP list timed out".to_owned(),
            })?
            .map_err(|message| BackendError::Transport { message })?;
        Ok(surface::entries_to_resource_page(
            &entries,
            &profile.base_path,
            &profile.uri_template,
        ))
    }

    /// Completion for the `{path}` resource-template variable: list the `path`
    /// directory and return the entry names that start with `prefix`. Only
    /// `surface: resource` bindings complete; others inherit the empty list.
    async fn complete_template_variable(
        &self,
        backend_name: &str,
        _variable_name: &str,
        prefix: &str,
        _config: &Value,
        _context: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let profile = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        if profile.surface != Surface::Resource {
            return Ok(vec![]);
        }
        let resolved = ftp::resolve_path(&profile.base_path, "")
            .map_err(|message| BackendError::InvalidSpec { message })?;
        let entries = tokio::time::timeout(profile.timeout, ftp::list(&profile.conn, &resolved))
            .await
            .map_err(|_| BackendError::Transport {
                message: "FTP list timed out".to_owned(),
            })?
            .map_err(|message| BackendError::Transport { message })?;
        Ok(surface::entries_to_completion_values(&entries, prefix, 100))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        Arc::new(NoOpHost)
    }

    fn minimal_spec() -> Value {
        json!({
            "op": "list",
            "host": "ftp.example.com",
            "user": "svc",
            "password": "${env.FTP_PW}",
        })
    }

    #[test]
    fn kind_is_ftp() {
        assert_eq!(FtpBackendPlugin::new().kind(), "ftp");
    }

    #[tokio::test]
    async fn register_accepts_minimal_spec() {
        let plugin = FtpBackendPlugin::new();
        plugin
            .register_profile("files", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("files").unwrap();
        assert_eq!(p.op, FtpOp::List);
        // tls defaults to true → FTPS required.
        assert!(p.conn.tls);
    }

    #[tokio::test]
    async fn register_accepts_plaintext_opt_out() {
        let plugin = FtpBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["tls"] = json!(false);
        plugin
            .register_profile("plain", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        assert!(!profiles.get("plain").unwrap().conn.tls);
    }

    #[tokio::test]
    async fn register_rejects_cred_password() {
        let plugin = FtpBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["password"] = json!("cred://vault/ftp");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("cred password");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_defaults_to_tool_surface() {
        let plugin = FtpBackendPlugin::new();
        plugin
            .register_profile("files", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("files").unwrap();
        assert_eq!(p.surface, Surface::Tool);
        assert_eq!(p.uri_template, "ftp://{path}");
    }

    #[tokio::test]
    async fn register_parses_resource_surface() {
        let plugin = FtpBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["op"] = json!("get");
        spec["surface"] = json!("resource");
        spec["uri"] = json!("file://partner/{path}");
        plugin
            .register_profile("res", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("res").unwrap();
        assert_eq!(p.surface, Surface::Resource);
        assert_eq!(p.uri_template, "file://partner/{path}");
    }

    #[tokio::test]
    async fn list_resources_empty_on_tool_surface() {
        let plugin = FtpBackendPlugin::new();
        plugin
            .register_profile("files", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        // Tool-surface bindings short-circuit to the empty page before any
        // connection, so this needs no live FTP server.
        let page = BackendPlugin::list_resources(&plugin, "files", None)
            .await
            .expect("list");
        assert!(page.resources.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn complete_empty_on_tool_surface() {
        let plugin = FtpBackendPlugin::new();
        plugin
            .register_profile("files", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let got = BackendPlugin::complete_template_variable(
            &plugin,
            "files",
            "path",
            "a",
            &json!({}),
            &BTreeMap::new(),
        )
        .await
        .expect("complete");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn execute_unknown_profile_is_profile_not_found() {
        let plugin = FtpBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    struct NoOpHost;

    #[async_trait]
    impl BackendHost for NoOpHost {
        async fn invoke_tool(
            &self,
            _ctx: &mcpg_plugin_protocol::BackendInvocationContext,
            _tool_name: &str,
            _args: &serde_json::Value,
        ) -> Result<serde_json::Value, mcpg_plugin_protocol::BackendHostError> {
            Err(mcpg_plugin_protocol::BackendHostError::NotImplemented)
        }
    }
}
