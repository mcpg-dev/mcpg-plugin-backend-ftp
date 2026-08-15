//! `watch_strategy` entity (`ftp_dir_poll`) — the POLLING directory-watch path.
//!
//! FTP has no native change-push channel, so this strategy polls a directory
//! `LIST` on a cadence and signals a change whenever the listing's fingerprint
//! moves. The poll thread, the cursor diff, the stop signal and the opaque
//! handle round-trip all live in the shared [`mcpg_plugin_sdk::watch`] helper —
//! this entity only supplies the per-tick `poll` closure that reopens an FTP
//! connection, lists the watched directory and folds the entries into a
//! deterministic fingerprint.
//!
//! The fingerprint is the sorted set of `name|size` over the directory entries.
//! FTP `LIST` exposes name/type/size but no reliable mtime, so a same-size
//! in-place overwrite of a file is NOT detected — only adds, removes, renames
//! and size changes move the fingerprint.
//!
//! The helper's loop is synchronous and the suppaftp client is async, so a
//! single current-thread tokio runtime is built once in [`watch`] and moved
//! into the closure; each tick `block_on`s one connect + list (sequential
//! ticks, so a single-thread runtime is enough). Connect / list failures map to
//! the closure's `Err(String)` — the helper logs and retries on the next tick.

use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::watch::{cancel_polling_watch, spawn_polling_watch};
use serde::Deserialize;
use serde_json::Value;

use crate::ftp::{self, FtpConn};

pub const PLUGIN_ID: &str = "dev.mcpg.backend.ftp";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "ftp_dir_poll";

/// Default poll cadence when `interval_ms` is omitted (1 minute).
fn default_interval_ms() -> u64 {
    60_000
}

/// Default per-tick connect + list budget when `timeout_ms` is omitted
/// (10 seconds).
fn default_timeout_ms() -> u64 {
    10_000
}

fn default_port() -> u16 {
    21
}

fn default_tls() -> bool {
    true
}

/// Per-watch spec: the FTP connection fields (reusing the backend's connection
/// shape, including the gateway's `username`/`root` materialized-field aliases)
/// plus the directory `path` to watch and the poll cadence. The connection is
/// carried per-watch (not at plugin level), so a watcher is self-contained.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// FTP host. Operator-configured.
    host: String,
    /// FTP control port (default 21).
    #[serde(default = "default_port")]
    port: u16,
    /// FTP login user. Accepts `username` (the gateway's materialized field
    /// name) as an alias.
    #[serde(alias = "username")]
    user: String,
    /// FTP password — a literal, or `${env.X}` / `vault://…` resolved at config
    /// load. Per-caller `cred://` is rejected.
    password: String,
    /// Directory to watch (default `""` = the login's default directory). May
    /// not contain `..` segments. Accepts `root` (the gateway's materialized
    /// field name) as an alias.
    #[serde(default, alias = "root")]
    path: String,
    /// Require explicit FTPS (AUTH TLS) (default `true`). When `false`,
    /// plaintext FTP is used — dev / trusted-network only.
    #[serde(default = "default_tls")]
    tls: bool,
    /// Poll cadence in milliseconds (default 60000; floored by the SDK helper).
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    /// Per-tick connect + list budget in milliseconds (default 10000).
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

/// `watch_strategy` entity. Stateless beyond its manifest — every watcher's
/// connection + directory arrive on the per-watch spec.
pub struct FtpWatchCdylib {
    manifest: PluginManifest,
}

impl FtpWatchCdylib {
    /// Infallible cdylib factory. `config_json` + host are ignored — the watch
    /// carries no plugin-level config (the connection + directory arrive via
    /// the per-watch spec).
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.ftp",
                name: "FTP Directory Poll Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

/// Fold a directory listing into a deterministic fingerprint: each entry's
/// `name|size`, sorted, joined by newlines. Sorting makes the fingerprint
/// independent of the order the server returns entries; `name|size` moves on
/// add / remove / rename / size change. A same-size in-place overwrite is NOT
/// reflected (FTP `LIST` carries no reliable mtime).
fn fingerprint(entries: &[Value]) -> String {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|e| {
            let name = e.get("name").and_then(Value::as_str).unwrap_or_default();
            let size = match e.get("size") {
                Some(Value::Number(n)) => n.to_string(),
                _ => "?".to_owned(),
            };
            format!("{name}|{size}")
        })
        .collect();
    lines.sort_unstable();
    lines.join("\n")
}

impl SyncWatchStrategyPlugin for FtpWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let parsed: WatchSpec =
            serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
                message: format!("invalid ftp_dir_poll watch spec: {e}"),
            })?;

        let invalid = |m: String| WatchError::InvalidSpec { message: m };
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
        // Reuse the backend's traversal guard: the watched directory may not
        // escape via `..`. An empty path resolves to the login directory (".").
        let dir = ftp::resolve_path("", &parsed.path).map_err(invalid)?;

        let conn = FtpConn {
            host: parsed.host,
            port: parsed.port,
            user: parsed.user,
            password: parsed.password,
            tls: parsed.tls,
        };
        let timeout = Duration::from_millis(parsed.timeout_ms);

        // One current-thread runtime, moved into the closure: ticks are
        // sequential, so a single-thread runtime is enough to `block_on` each
        // connect + list.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| WatchError::Subscribe {
                message: format!("ftp_dir_poll: tokio runtime init failed: {e}"),
            })?;

        // Initial connect + list probe: a watcher that can never reach the
        // directory should fail to subscribe rather than spin silently.
        rt.block_on(async {
            tokio::time::timeout(timeout, ftp::list(&conn, &dir))
                .await
                .map_err(|_| "FTP connect/list timed out".to_owned())
                .and_then(|r| r)
        })
        .map_err(|e| WatchError::Subscribe {
            message: format!("ftp_dir_poll: initial connect/list failed: {e}"),
        })?;

        let poll = move || -> Result<Option<String>, String> {
            let entries = rt.block_on(async {
                tokio::time::timeout(timeout, ftp::list(&conn, &dir))
                    .await
                    .map_err(|_| "FTP connect/list timed out".to_owned())
                    .and_then(|r| r)
            })?;
            Ok(Some(fingerprint(&entries)))
        };

        Ok(spawn_polling_watch(
            resource_uri,
            Duration::from_millis(parsed.interval_ms),
            emit_event,
            poll,
        ))
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        cancel_polling_watch(watch_handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stub_host() -> HostHandle {
        // SAFETY: `stub_host_ref` returns a process-static no-op host ref; the
        // factory ignores the host entirely.
        #[allow(unsafe_code)]
        unsafe {
            HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref())
        }
    }

    fn plugin() -> FtpWatchCdylib {
        FtpWatchCdylib::from_host_config("", stub_host())
    }

    fn emit_noop() -> Box<dyn Fn(&str) + Send + Sync + 'static> {
        Box::new(|_| {})
    }

    #[test]
    fn manifest_and_kind_are_correct() {
        use mcpg_plugin_protocol::PluginClass;
        let p = plugin();
        let m = SyncWatchStrategyPlugin::manifest(&p);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::WatchStrategy);
        assert_eq!(p.kind(), WATCH_KIND);
    }

    #[test]
    fn spec_parses_with_defaults() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "host": "ftp.example.com",
            "user": "svc",
            "password": "${env.FTP_PW}",
        }))
        .unwrap();
        assert_eq!(parsed.port, 21);
        assert_eq!(parsed.path, "");
        assert!(parsed.tls);
        assert_eq!(parsed.interval_ms, 60_000);
        assert_eq!(parsed.timeout_ms, 10_000);
    }

    #[test]
    fn spec_parses_overrides_and_aliases() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "host": "h",
            "username": "svc",
            "password": "p",
            "root": "/inbox",
            "port": 2121,
            "tls": false,
            "interval_ms": 30_000,
            "timeout_ms": 5_000,
        }))
        .unwrap();
        assert_eq!(parsed.user, "svc");
        assert_eq!(parsed.path, "/inbox");
        assert_eq!(parsed.port, 2121);
        assert!(!parsed.tls);
        assert_eq!(parsed.interval_ms, 30_000);
        assert_eq!(parsed.timeout_ms, 5_000);
    }

    #[test]
    fn unknown_field_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "ftp://inbox",
                &json!({
                    "host": "h",
                    "user": "u",
                    "password": "p",
                    "bogus": true,
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn traversal_path_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "ftp://inbox",
                &json!({
                    "host": "h",
                    "user": "u",
                    "password": "p",
                    "path": "../etc",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn cred_password_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "ftp://inbox",
                &json!({
                    "host": "h",
                    "user": "u",
                    "password": "cred://vault/ftp",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn empty_host_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "ftp://inbox",
                &json!({ "host": "  ", "user": "u", "password": "p" }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn fingerprint_is_order_independent() {
        let a = vec![
            json!({ "name": "a.csv", "type": "file", "size": 10 }),
            json!({ "name": "b.csv", "type": "file", "size": 20 }),
        ];
        let b = vec![
            json!({ "name": "b.csv", "type": "file", "size": 20 }),
            json!({ "name": "a.csv", "type": "file", "size": 10 }),
        ];
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_on_listing_change() {
        let base = vec![json!({ "name": "a.csv", "type": "file", "size": 10 })];
        // A new entry.
        let added = vec![
            json!({ "name": "a.csv", "type": "file", "size": 10 }),
            json!({ "name": "c.csv", "type": "file", "size": 5 }),
        ];
        // Same name, different size.
        let resized = vec![json!({ "name": "a.csv", "type": "file", "size": 11 })];
        // A rename.
        let renamed = vec![json!({ "name": "z.csv", "type": "file", "size": 10 })];
        let fp = fingerprint(&base);
        assert_ne!(fp, fingerprint(&added));
        assert_ne!(fp, fingerprint(&resized));
        assert_ne!(fp, fingerprint(&renamed));
    }
}
