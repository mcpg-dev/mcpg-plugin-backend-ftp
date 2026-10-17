//! `watch_strategy` entity (`ftp_dir_poll`): a directory on an FTP server
//! as an inventory.
//!
//! FTP has no change-push channel, so the strategy `LIST`s the directory
//! (and its subdirectories with `recursive`) every `interval_ms` over one
//! connection. A resource watch gets one change per listing that changed
//! anything; an MCP Events source gets each file created, modified or
//! deleted as the shared `object.changed` event, through the SDK's
//! inventory helper, which also resumes after a restart. `LIST` reports a
//! file's time to the minute at best, so a same-size overwrite within the
//! same minute is not seen.

use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::inventory::{
    DirItem, InventoryOptions, InventoryStart, Pattern, WalkOptions, acknowledge_inventory_watch,
    cancel_inventory_watch, defaults, spawn_inventory_watch, walk,
};
use serde::Deserialize;
use serde_json::Value;

use crate::ftp::{self, FtpConn, FtpLister};

pub const PLUGIN_ID: &str = "dev.mcpg.backend.ftp";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "ftp_dir_poll";

/// Default listing cadence when `interval_ms` is omitted (1 minute).
fn default_interval_ms() -> u64 {
    60_000
}

/// Default budget of one listing when `timeout_ms` is omitted (10 seconds).
fn default_timeout_ms() -> u64 {
    10_000
}

fn default_port() -> u16 {
    21
}

fn default_tls() -> bool {
    true
}

/// Per-watch spec: the FTP connection fields (mirroring the backend's
/// connection shape), the directory to watch, and how it is listed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// FTP host. Operator-configured.
    host: String,
    /// FTP port (default 21).
    #[serde(default = "default_port")]
    port: u16,
    /// Login user (`username` is accepted as an alias).
    #[serde(alias = "username")]
    user: String,
    /// Password: a literal, `${env.X}`, `${secret.X}` or `vault://…`,
    /// resolved before the watch starts. Per-caller `cred://` is rejected.
    password: String,
    /// The directory to watch (`root` is accepted as an alias; default
    /// `""` = the login directory). May not contain `..` segments.
    #[serde(default, alias = "root")]
    path: String,
    /// Require explicit FTPS (AUTH TLS). Default `true`.
    #[serde(default = "default_tls")]
    tls: bool,
    /// Listing cadence in milliseconds (default 60000, at least 250).
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    /// Budget of one listing in milliseconds (default 10000).
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    /// List the subdirectories too.
    #[serde(default)]
    recursive: bool,
    /// Keep only the files whose path relative to the directory matches
    /// this glob (`*.csv`, `**/*.json`).
    #[serde(default)]
    pattern: Option<String>,
    /// Most files listed (default 10000).
    #[serde(default = "defaults::max_files")]
    max_files: usize,
    /// `now` (default): the files there at a first start are the baseline;
    /// `existing`: each is reported as created.
    #[serde(default)]
    start_at: InventoryStart,
    /// Largest snapshot of the listing an event carries (default 131072).
    #[serde(default = "defaults::snapshot_bytes")]
    snapshot_bytes: usize,
    /// Most changes emitted ahead of the gateway's acknowledgements.
    #[serde(default = "defaults::max_in_flight")]
    max_in_flight: usize,
    /// How long a change waits for its acknowledgement (default 60000).
    #[serde(default = "defaults::ack_timeout_ms")]
    ack_timeout_ms: u64,
}

/// `watch_strategy` entity. Stateless beyond its manifest — every watcher's
/// connection + directory arrive on the per-watch spec.
pub struct FtpWatchCdylib {
    manifest: PluginManifest,
}

impl FtpWatchCdylib {
    /// Infallible cdylib factory; the watch carries no plugin-level config.
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

/// Run one step of a listing on `rt`, failing when the listing's `deadline`
/// passes.
fn within<T>(
    rt: &tokio::runtime::Runtime,
    deadline: tokio::time::Instant,
    step: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    rt.block_on(async {
        tokio::time::timeout_at(deadline, step)
            .await
            .map_err(|_| "FTP listing timed out".to_owned())?
    })
}

/// One listing entry as the inventory reads it; `None` for an entry that is
/// neither a file nor a directory.
fn dir_item(entry: &Value) -> Option<DirItem> {
    let name = entry.get("name").and_then(Value::as_str)?.to_owned();
    let is_dir = match entry.get("type").and_then(Value::as_str) {
        Some("dir") => true,
        Some("file") => false,
        _ => return None,
    };
    Some(DirItem {
        name,
        is_dir,
        size: entry.get("size").and_then(Value::as_u64),
        modified_at_ms: entry
            .get("mtime")
            .and_then(Value::as_i64)
            .map(|secs| secs.saturating_mul(1_000)),
    })
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
        let (spec, resume) = mcpg_plugin_protocol::take_watch_resume(spec);
        let parsed: WatchSpec =
            serde_json::from_value(spec).map_err(|e| WatchError::InvalidSpec {
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
                 use ${env.X} / ${secret.X} / vault:// (resolved before the watch starts)"
                    .into(),
            ));
        }
        if parsed.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0".into()));
        }
        if !(1..=100_000).contains(&parsed.max_files) {
            return Err(invalid("max_files must be 1 to 100000".into()));
        }
        let pattern = parsed
            .pattern
            .as_deref()
            .map(Pattern::new)
            .transpose()
            .map_err(|e| invalid(format!("pattern: {e}")))?;
        // Reuse the backend's traversal guard: the watched directory may not
        // escape via `..`. An empty path resolves to the login directory (".").
        let dir = ftp::resolve_path("", &parsed.path).map_err(invalid)?;
        let location = format!(
            "ftp://{}:{}/{}",
            parsed.host,
            parsed.port,
            if dir == "." {
                ""
            } else {
                dir.trim_start_matches('/')
            }
        );

        let conn = FtpConn {
            host: parsed.host,
            port: parsed.port,
            user: parsed.user,
            password: parsed.password,
            tls: parsed.tls,
        };
        let timeout = Duration::from_millis(parsed.timeout_ms);
        // One current-thread runtime, moved into the listing: listings are
        // sequential, so a single-thread runtime is enough.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| WatchError::Subscribe {
                message: format!("ftp_dir_poll: tokio runtime init failed: {e}"),
            })?;
        let walk_options = WalkOptions {
            recursive: parsed.recursive,
            pattern,
            max_files: parsed.max_files,
            max_dirs: defaults::max_dirs(),
        };
        // A server that cannot be reached now is listed again at the next
        // interval: the source is not lost to a transient outage.
        let list = move || {
            // The session drops inside the runtime that drives it.
            let _runtime = rt.enter();
            let deadline = tokio::time::Instant::now() + timeout;
            let mut lister = within(&rt, deadline, FtpLister::open(&conn, &dir))?;
            walk(&walk_options, |relative| {
                let entries = within(&rt, deadline, lister.list(relative))?;
                Ok(entries.iter().filter_map(dir_item).collect())
            })
        };

        spawn_inventory_watch(
            resource_uri,
            InventoryOptions {
                store: "ftp".into(),
                location,
                interval: Duration::from_millis(parsed.interval_ms),
                start: parsed.start_at,
                snapshot_bytes: parsed.snapshot_bytes,
                max_in_flight: parsed.max_in_flight,
                ack_timeout: Duration::from_millis(parsed.ack_timeout_ms),
            },
            resume,
            emit_event,
            list,
        )
    }

    fn acknowledge(&self, watch_handle: &WatchHandleBox, position: &Value) {
        acknowledge_inventory_watch(watch_handle, position);
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        cancel_inventory_watch(watch_handle);
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

    fn refused(spec: Value) -> String {
        match plugin().watch("ftp://inbox", &spec, emit_noop()) {
            Err(WatchError::InvalidSpec { message }) => message,
            Err(other) => panic!("not a spec error: {other:?}"),
            Ok(handle) => {
                plugin().cancel(handle);
                panic!("accepted {spec}");
            }
        }
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
        assert!(!parsed.recursive);
        assert_eq!(parsed.start_at, InventoryStart::Now);
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
            "recursive": true,
            "pattern": "*.csv",
        }))
        .unwrap();
        assert_eq!(parsed.user, "svc");
        assert_eq!(parsed.path, "/inbox");
        assert_eq!(parsed.port, 2121);
        assert!(!parsed.tls);
        assert!(parsed.recursive);
        assert_eq!(parsed.pattern.as_deref(), Some("*.csv"));
    }

    #[test]
    fn a_bad_spec_is_refused_before_anything_connects() {
        let base = json!({ "host": "h", "user": "u", "password": "p" });
        let with = |extra: Value| {
            let mut spec = base.clone();
            for (k, v) in extra.as_object().unwrap() {
                spec[k] = v.clone();
            }
            spec
        };
        assert!(refused(with(json!({ "bogus": true }))).contains("unknown field"));
        assert!(refused(with(json!({ "path": "../etc" }))).contains(".."));
        assert!(refused(with(json!({ "password": "cred://vault/ftp" }))).contains("cred://"));
        assert!(refused(with(json!({ "host": "  " }))).contains("host"));
        assert!(refused(with(json!({ "pattern": "[a" }))).contains("pattern"));
        assert!(refused(with(json!({ "max_files": 0 }))).contains("max_files"));
        assert!(refused(with(json!({ "interval_ms": 10 }))).contains("interval_ms"));
    }

    #[test]
    fn an_unreachable_server_is_listed_again_not_a_failed_watch() {
        let handle = plugin()
            .watch(
                "mcpg-event://inbox",
                &json!({
                    "host": "127.0.0.1",
                    "port": 1,
                    "user": "u",
                    "password": "p",
                    "tls": false,
                    "timeout_ms": 200,
                    "interval_ms": 250,
                }),
                emit_noop(),
            )
            .expect("the watch starts and retries in the background");
        std::thread::sleep(Duration::from_millis(300));
        plugin().cancel(handle);
    }

    #[test]
    fn listing_entries_become_files_and_directories() {
        let line =
            crate::ftp::line_to_json("-rw-r--r-- 1 owner group 4096 Jan 12 10:11 report.csv");
        let item = dir_item(&line).unwrap();
        assert_eq!(item.name, "report.csv");
        assert!(!item.is_dir);
        assert_eq!(item.size, Some(4096));
        assert!(item.modified_at_ms.is_some());
        let dir = crate::ftp::line_to_json("drwxr-xr-x 2 owner group 4096 Jan 12 10:11 inbox");
        assert!(dir_item(&dir).unwrap().is_dir);
        assert_eq!(dir_item(&crate::ftp::line_to_json("not a line")), None);
    }
}
