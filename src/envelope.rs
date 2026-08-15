//! FTP structured response envelope — the `BackendResponse.payload` the
//! gateway projects onto `tools/call`. A non-null `downstreamError` slot is
//! the gateway's `is_error` signal (same contract as the other backends).

use serde_json::{Value, json};

/// Result of a completed FTP operation.
#[derive(Default)]
pub struct FtpOutcome {
    /// `list`: the directory entries.
    pub entries: Option<Vec<Value>>,
    /// `get`: the decoded file content (`{text}` / `{base64}`).
    pub content: Option<Value>,
    /// `get`: the byte size.
    pub size: Option<usize>,
    /// `put`: bytes written.
    pub written: Option<usize>,
}

/// Build a downstream-error object for the envelope's `downstreamError` slot.
pub fn ftp_downstream_error(kind: &str, message: &str, retryable: bool) -> Value {
    json!({
        "kind": kind,
        "code": format!("mcpg.downstream_ftp.{kind}"),
        "message": message,
        "retryable": retryable,
        "retryClass": if retryable { "with_backoff" } else { "do_not_retry" },
        "suggestedAction": if retryable { "check_ftp_connectivity_and_retry" } else { "inspect_ftp_error" },
    })
}

/// Classify a failure string. Connect / timeout / TLS-handshake / channel
/// failures are retryable transport errors; auth rejections, missing files,
/// traversal rejections, and size-cap violations are caller/config problems
/// and are not.
pub fn classify_error(message: &str) -> Value {
    let lower = message.to_ascii_lowercase();
    let retryable = lower.contains("connect failed")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("auth tls failed")
        || lower.contains("broken pipe")
        || lower.contains("connection reset")
        || lower.contains("connection refused");
    let kind = if retryable {
        "transport_error"
    } else {
        "ftp_error"
    };
    ftp_downstream_error(kind, message, retryable)
}

/// Build the FTP structured-content envelope.
#[allow(clippy::too_many_arguments)]
pub fn build_result_envelope(
    tool_name: &str,
    profile_name: &str,
    op: &str,
    host: &str,
    path: &str,
    outcome: Option<&FtpOutcome>,
    duration_ms: u128,
    downstream_error: Option<&Value>,
    error: Option<&str>,
) -> Value {
    let response = match outcome {
        Some(o) => json!({
            "entries": o.entries,
            "count": o.entries.as_ref().map(Vec::len),
            "content": o.content,
            "size": o.size,
            "written": o.written,
            "durationMs": duration_ms,
        }),
        None => Value::Null,
    };
    json!({
        "toolName": tool_name,
        "profile": profile_name,
        "request": {
            "op": op,
            "host": host,
            "path": path,
        },
        "response": response,
        "downstreamError": downstream_error,
        "downstreamErrors": downstream_error
            .map(|d| vec![d.clone()])
            .unwrap_or_default(),
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_failure_is_retryable_transport_error() {
        let e = classify_error("FTP connect failed: connection refused");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn auth_failure_is_not_retryable() {
        let e = classify_error("FTP auth failed: 530 Login incorrect");
        assert_eq!(e["kind"], json!("ftp_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn list_envelope_has_entries_and_count() {
        let outcome = FtpOutcome {
            entries: Some(vec![json!({ "name": "a.txt" })]),
            ..Default::default()
        };
        let env = build_result_envelope(
            "fs.list",
            "fs.list",
            "list",
            "ftp.x",
            "/up",
            Some(&outcome),
            8,
            None,
            None,
        );
        assert_eq!(env["response"]["count"], json!(1));
        assert_eq!(env["response"]["entries"][0]["name"], json!("a.txt"));
    }

    #[test]
    fn put_envelope_has_written() {
        let outcome = FtpOutcome {
            written: Some(42),
            ..Default::default()
        };
        let env = build_result_envelope(
            "fs.put",
            "fs.put",
            "put",
            "ftp.x",
            "/up/a.txt",
            Some(&outcome),
            5,
            None,
            None,
        );
        assert_eq!(env["response"]["written"], json!(42));
    }
}
