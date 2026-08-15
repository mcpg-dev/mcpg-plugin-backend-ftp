//! cdylib sync bridge — adapts the async [`FtpBackendPlugin`] onto the sync
//! FFI trait the cdylib vtable expects ([`SyncBackendPlugin`]). A private
//! multi-thread runtime `block_on`s the async methods (suppaftp runs on it);
//! the make-time [`HostHandle`] is wrapped as `Arc<dyn BackendHost>` for
//! `register_profile` and installed on the inner plugin for observability.

use std::sync::Arc;

use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, PluginManifest, ResourcePage,
};
use mcpg_plugin_sdk::ffi::SyncBackendPlugin;
use mcpg_plugin_sdk::{HostHandle, HostHandleBackendHost};

use crate::FtpBackendPlugin;
use crate::watch::FtpWatchCdylib;

fn build_bridge_runtime(thread_name: &str) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(thread_name.to_owned())
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("ftp cdylib: tokio runtime init failed: {e}"))
}

/// `SyncBackendPlugin` bridge over [`FtpBackendPlugin`].
pub struct FtpBackendCdylib {
    inner: FtpBackendPlugin,
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    rt: tokio::runtime::Runtime,
}

impl FtpBackendCdylib {
    /// Infallible cdylib factory. `config_json` is ignored — FTP carries no
    /// plugin-level config (per-binding host / op arrive via `register_profile`).
    pub fn from_host_config(_config_json: &str, host: HostHandle) -> Self {
        let inner = FtpBackendPlugin::new();
        let _installed = inner.set_host_handle(host.clone());
        Self {
            inner,
            host: Arc::new(HostHandleBackendHost::new(host)),
            rt: build_bridge_runtime("mcpg-backend-ftp"),
        }
    }
}

impl SyncBackendPlugin for FtpBackendCdylib {
    fn manifest(&self) -> &PluginManifest {
        BackendPlugin::manifest(&self.inner)
    }

    fn kind(&self) -> &str {
        BackendPlugin::kind(&self.inner)
    }

    fn register_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
    ) -> Result<(), BackendError> {
        self.rt.block_on(BackendPlugin::register_profile(
            &self.inner,
            profile_name,
            spec,
            Arc::clone(&self.host),
        ))
    }

    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.rt
            .block_on(BackendPlugin::execute(&self.inner, profile_name, request))
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, serde_json::Value> {
        BackendPlugin::audit_metadata(&self.inner, profile_name)
    }

    fn list_resources(
        &self,
        profile_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        self.rt.block_on(BackendPlugin::list_resources(
            &self.inner,
            profile_name,
            cursor,
        ))
    }

    fn complete_template_variable(
        &self,
        profile_name: &str,
        variable_name: &str,
        prefix: &str,
        config: &serde_json::Value,
        context: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        self.rt.block_on(BackendPlugin::complete_template_variable(
            &self.inner,
            profile_name,
            variable_name,
            prefix,
            config,
            context,
        ))
    }
}

// cdylib export — two entities under `dev.mcpg.backend.ftp`: the `backend`
// binding (list / get / put) and the `watch_strategy` directory poller (kind
// `ftp_dir_poll`). FTP is network-only, so the single static capability is
// `NetworkOutbound` — matching the plugin.yaml `network_outbound` entry; the
// poll watcher uses the same outbound capability for its directory LIST. The
// watch entity self-describes via its `manifest()` slot and is distinguished by
// its `inner_name` slug.
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.backend.ftp",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[::mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    backend_profile: ::mcpg_plugin_protocol::manifest::BackendProfile {
        pipeline_capable: true,
        ..::core::default::Default::default()
    },
    entities: [
        backend as binding {
            inner_name: "",
            plugin_type: FtpBackendCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                FtpBackendCdylib::from_host_config(cfg, host),
        },
        watch_strategy as watch {
            inner_name: "watch",
            plugin_type: FtpWatchCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                FtpWatchCdylib::from_host_config(cfg, host),
        },
    ],
}
