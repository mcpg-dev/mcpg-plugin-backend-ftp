//! Operator-facing spec for the FTP/FTPS backend plugin.
//!
//! One binding = one operation = one MCP tool (or resource). `op: list`
//! lists a directory, `op: get` reads a file, `op: put` writes a file — the
//! target path comes from the call arguments (with `..` rejected), joined
//! under the operator-configured `path` base.

use serde::Deserialize;

/// The file operation a binding performs.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FtpOp {
    /// List a directory's entries.
    #[default]
    List,
    /// Read a file's contents.
    Get,
    /// Write a file (content from the `content`/`text` argument).
    Put,
}

impl FtpOp {
    pub fn as_str(self) -> &'static str {
        match self {
            FtpOp::List => "list",
            FtpOp::Get => "get",
            FtpOp::Put => "put",
        }
    }

    /// Whether the op only reads (does not mutate the remote). `put` mutates.
    pub fn is_read_only(self) -> bool {
        matches!(self, FtpOp::List | FtpOp::Get)
    }
}

/// Operator-facing spec the gateway serializes when calling
/// `register_profile`. Mirrors `FtpBackendConfig` in the gateway crate.
// NOTE: intentionally NOT #[serde(deny_unknown_fields)] — the gateway injects
// the reserved `__mcpg_secret_refs` hint key into this spec at register_profile
// (secret-rotation scoping); denying unknown fields would reject it. The
// operator-facing schema is closed on the gateway-side FtpBackendConfig instead.
#[derive(Debug, Clone, Deserialize)]
pub struct FtpBackendSpec {
    /// The operation (default `list`).
    #[serde(default)]
    pub op: FtpOp,

    /// FTP host. Operator-configured.
    pub host: String,

    /// FTP control port (default 21).
    #[serde(default = "default_port")]
    pub port: u16,

    /// FTP login user. Accepts `username` (the gateway's materialized field
    /// name, matching the sibling sftp/smb file backends) as an alias.
    #[serde(alias = "username")]
    pub user: String,

    /// FTP password — a literal, or `${env.X}` / `vault://…` resolved at
    /// config load. Per-caller `cred://` is rejected.
    pub password: String,

    /// Base directory the caller-supplied path is joined under (default `""`
    /// = the login's default directory). The caller path may not contain
    /// `..` segments. Accepts `root` (the gateway's materialized field name,
    /// matching the sibling sftp/smb file backends) as an alias.
    #[serde(default, alias = "root")]
    pub path: String,

    /// Require explicit FTPS (AUTH TLS) on the control + data channels
    /// (default `true`). When `false`, plaintext FTP is permitted — dev /
    /// trusted-network only.
    #[serde(default = "default_tls")]
    pub tls: bool,

    /// Cap on bytes read (`get`) / written (`put`) (default 10 MiB).
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,

    /// Per-call timeout (ms) for connect + auth + the operation (default
    /// 15 s).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// MCP surface this binding serves. `tool` (default) emits the unchanged
    /// tool envelope (`op: list` / `get` / `put`); `resource` exposes files as
    /// MCP resources — `resources/list` enumerates the `path` directory into
    /// one resource per file and `resources/read` fetches a file's bytes. Set
    /// to match the capability list the binding is placed under
    /// (`resources[]` / `resource_templates[]`).
    #[serde(default)]
    pub surface: crate::surface::Surface,

    /// URI template for the `resource` surface — `{path}` is filled with each
    /// file's path (relative to the login dir, leading `/` trimmed). The same
    /// template recovers the file path from a `resources/read` request's URI.
    /// Ignored on the `tool` surface. Default `ftp://{path}`.
    #[serde(default = "default_uri_template")]
    pub uri: String,
}

fn default_port() -> u16 {
    21
}
fn default_tls() -> bool {
    true
}
fn default_max_bytes() -> usize {
    10 * 1024 * 1024
}
fn default_timeout_ms() -> u64 {
    15_000
}
fn default_uri_template() -> String {
    "ftp://{path}".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_defaults_to_list() {
        assert_eq!(FtpOp::default(), FtpOp::List);
    }

    #[test]
    fn read_only_classification() {
        assert!(FtpOp::List.is_read_only());
        assert!(FtpOp::Get.is_read_only());
        assert!(!FtpOp::Put.is_read_only());
    }

    #[test]
    fn spec_applies_defaults() {
        let spec: FtpBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "ftp.example.com",
            "user": "svc",
            "password": "${env.FTP_PW}",
        }))
        .unwrap();
        assert_eq!(spec.op, FtpOp::List);
        assert_eq!(spec.port, 21);
        assert_eq!(spec.path, "");
        assert!(spec.tls);
        assert_eq!(spec.max_bytes, 10 * 1024 * 1024);
        assert_eq!(spec.timeout_ms, 15_000);
        // Surface defaults to tool (preserves current behavior); the uri
        // template defaults to `ftp://{path}`.
        assert_eq!(spec.surface, crate::surface::Surface::Tool);
        assert_eq!(spec.uri, "ftp://{path}");
    }

    #[test]
    fn parses_resource_surface_with_uri_template() {
        let spec: FtpBackendSpec = serde_json::from_value(serde_json::json!({
            "op": "get",
            "host": "h", "user": "u", "password": "p",
            "path": "/outbound",
            "surface": "resource",
            "uri": "file://partner/{path}",
        }))
        .unwrap();
        assert_eq!(spec.surface, crate::surface::Surface::Resource);
        assert_eq!(spec.uri, "file://partner/{path}");
    }

    #[test]
    fn parses_get_and_put_and_plaintext() {
        let get: FtpBackendSpec = serde_json::from_value(serde_json::json!({
            "op": "get", "host": "h", "user": "u", "password": "p",
        }))
        .unwrap();
        assert_eq!(get.op, FtpOp::Get);
        let put: FtpBackendSpec = serde_json::from_value(serde_json::json!({
            "op": "put", "host": "h", "user": "u", "password": "p",
            "path": "/upload", "tls": false,
        }))
        .unwrap();
        assert_eq!(put.op, FtpOp::Put);
        assert_eq!(put.path, "/upload");
        assert!(!put.tls);
    }

    #[test]
    fn accepts_gateway_username_and_root_aliases() {
        let spec: FtpBackendSpec = serde_json::from_value(serde_json::json!({
            "host": "h", "username": "svc", "password": "p", "root": "/inbox",
        }))
        .unwrap();
        assert_eq!(spec.user, "svc");
        assert_eq!(spec.path, "/inbox");
    }
}
