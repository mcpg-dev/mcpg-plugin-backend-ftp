//! FTP/FTPS machinery: connect + (optional) explicit AUTH-TLS + login, the
//! three operations (list / get / put), and LIST-line → JSON projection.

use std::sync::Arc;

use serde_json::{Value, json};
use suppaftp::list::ListParser;
use suppaftp::tokio::{AsyncFtpStream, AsyncRustlsConnector, AsyncRustlsFtpStream};
use suppaftp::types::FileType;
use tokio::io::AsyncReadExt;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Per-connection settings (clone-cheap).
#[derive(Clone)]
pub struct FtpConn {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    /// Require explicit FTPS (AUTH TLS). When `false`, plaintext FTP is used.
    pub tls: bool,
}

/// Either a plaintext or a TLS-secured suppaftp stream. The two share no base
/// type, so the operations are written against this enum.
enum FtpSession {
    Plain(Box<AsyncFtpStream>),
    Secure(Box<AsyncRustlsFtpStream>),
}

/// Build a rustls `ClientConfig` over the webpki Mozilla trust anchors (ring
/// provider — no openssl / native-tls).
fn rustls_client_config() -> Arc<ClientConfig> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

/// Connect, optionally upgrade to FTPS (explicit AUTH TLS), and authenticate.
async fn open_session(conn: &FtpConn) -> Result<FtpSession, String> {
    let addr = format!("{}:{}", conn.host, conn.port);
    if conn.tls {
        let unsecured = AsyncRustlsFtpStream::connect(&addr)
            .await
            .map_err(|e| format!("FTP connect failed: {e}"))?;
        let connector = TlsConnector::from(rustls_client_config());
        let mut secure = unsecured
            .into_secure(AsyncRustlsConnector::from(connector), &conn.host)
            .await
            .map_err(|e| format!("FTPS AUTH TLS failed: {e}"))?;
        secure
            .login(&conn.user, &conn.password)
            .await
            .map_err(|e| format!("FTP auth failed: {e}"))?;
        Ok(FtpSession::Secure(Box::new(secure)))
    } else {
        let mut plain = AsyncFtpStream::connect(&addr)
            .await
            .map_err(|e| format!("FTP connect failed: {e}"))?;
        plain
            .login(&conn.user, &conn.password)
            .await
            .map_err(|e| format!("FTP auth failed: {e}"))?;
        Ok(FtpSession::Plain(Box::new(plain)))
    }
}

/// Resolve the caller path under `base`, rejecting `..` traversal.
pub fn resolve_path(base: &str, caller: &str) -> Result<String, String> {
    if caller.split('/').any(|seg| seg == "..") {
        return Err("path must not contain '..' segments".to_owned());
    }
    let caller = caller.trim_start_matches('/');
    if base.trim().is_empty() {
        Ok(if caller.is_empty() {
            ".".to_owned()
        } else {
            caller.to_owned()
        })
    } else {
        let base = base.trim_end_matches('/');
        Ok(if caller.is_empty() {
            base.to_owned()
        } else {
            format!("{base}/{caller}")
        })
    }
}

/// List a directory's entries.
pub async fn list(conn: &FtpConn, path: &str) -> Result<Vec<Value>, String> {
    let arg = if path == "." { None } else { Some(path) };
    let lines = match open_session(conn).await? {
        FtpSession::Plain(mut s) => s
            .list(arg)
            .await
            .map_err(|e| format!("FTP list '{path}' failed: {e}"))?,
        FtpSession::Secure(mut s) => s
            .list(arg)
            .await
            .map_err(|e| format!("FTP list '{path}' failed: {e}"))?,
    };
    Ok(lines.iter().map(|l| line_to_json(l)).collect())
}

/// Read a file's contents (capped at `max_bytes`). Reads one extra byte to
/// detect a file that exceeds the cap.
pub async fn get(conn: &FtpConn, path: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    let cap = max_bytes as u64 + 1;
    match open_session(conn).await? {
        FtpSession::Plain(mut s) => {
            s.transfer_type(FileType::Binary)
                .await
                .map_err(|e| format!("FTP type binary failed: {e}"))?;
            retr_capped(
                s.retr(path, |mut stream| {
                    Box::pin(async move {
                        let mut buf = Vec::new();
                        let mut limited = (&mut stream).take(cap);
                        limited.read_to_end(&mut buf).await.map_err(|e| {
                            suppaftp::FtpError::ConnectionError(std::io::Error::other(e))
                        })?;
                        Ok((buf, stream))
                    })
                })
                .await,
                path,
                max_bytes,
            )
        }
        FtpSession::Secure(mut s) => {
            s.transfer_type(FileType::Binary)
                .await
                .map_err(|e| format!("FTP type binary failed: {e}"))?;
            retr_capped(
                s.retr(path, |mut stream| {
                    Box::pin(async move {
                        let mut buf = Vec::new();
                        let mut limited = (&mut stream).take(cap);
                        limited.read_to_end(&mut buf).await.map_err(|e| {
                            suppaftp::FtpError::ConnectionError(std::io::Error::other(e))
                        })?;
                        Ok((buf, stream))
                    })
                })
                .await,
                path,
                max_bytes,
            )
        }
    }
}

/// Map a retr result onto a capped byte buffer.
fn retr_capped(
    result: Result<Vec<u8>, suppaftp::FtpError>,
    path: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let buf = result.map_err(|e| format!("FTP retr '{path}' failed: {e}"))?;
    if buf.len() > max_bytes {
        return Err(format!("file exceeds max_bytes ({max_bytes})"));
    }
    Ok(buf)
}

/// Write a file (truncate/create). Returns the byte count.
pub async fn put(conn: &FtpConn, path: &str, content: &[u8]) -> Result<usize, String> {
    match open_session(conn).await? {
        FtpSession::Plain(mut s) => {
            s.transfer_type(FileType::Binary)
                .await
                .map_err(|e| format!("FTP type binary failed: {e}"))?;
            let mut reader = content;
            s.put_file(path, &mut reader)
                .await
                .map_err(|e| format!("FTP put '{path}' failed: {e}"))?;
        }
        FtpSession::Secure(mut s) => {
            s.transfer_type(FileType::Binary)
                .await
                .map_err(|e| format!("FTP type binary failed: {e}"))?;
            let mut reader = content;
            s.put_file(path, &mut reader)
                .await
                .map_err(|e| format!("FTP put '{path}' failed: {e}"))?;
        }
    }
    Ok(content.len())
}

/// Project a raw `LIST` output line to JSON, parsing POSIX then DOS formats;
/// when neither parses, the raw line is surfaced as the name.
pub fn line_to_json(line: &str) -> Value {
    if let Ok(file) = ListParser::parse_posix(line).or_else(|_| ListParser::parse_dos(line)) {
        let kind = if file.is_directory() {
            "dir"
        } else if file.is_symlink() {
            "symlink"
        } else {
            "file"
        };
        return json!({
            "name": file.name(),
            "type": kind,
            "size": file.size(),
        });
    }
    json!({ "name": line, "type": "unknown", "size": Value::Null })
}

/// Decode file bytes for the envelope: UTF-8 text when valid, else base64.
pub fn decode_content(data: &[u8]) -> Value {
    match std::str::from_utf8(data) {
        Ok(s) => json!({ "text": s }),
        Err(_) => {
            use base64::Engine as _;
            json!({ "base64": base64::engine::general_purpose::STANDARD.encode(data) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rejects_traversal() {
        assert!(resolve_path("", "../etc/passwd").is_err());
        assert!(resolve_path("/home/svc", "a/../../b").is_err());
    }

    #[test]
    fn resolve_joins_under_base() {
        assert_eq!(
            resolve_path("/upload", "report.csv").unwrap(),
            "/upload/report.csv"
        );
        assert_eq!(
            resolve_path("/upload/", "/report.csv").unwrap(),
            "/upload/report.csv"
        );
        assert_eq!(resolve_path("", "sub/file").unwrap(), "sub/file");
        assert_eq!(resolve_path("", "").unwrap(), ".");
        assert_eq!(resolve_path("/data", "").unwrap(), "/data");
    }

    #[test]
    fn parse_posix_list_line() {
        let v = line_to_json("-rw-r--r-- 1 owner group 4096 Jan 12 10:11 report.csv");
        assert_eq!(v["name"], json!("report.csv"));
        assert_eq!(v["type"], json!("file"));
        assert_eq!(v["size"], json!(4096));
    }

    #[test]
    fn parse_posix_dir_line() {
        let v = line_to_json("drwxr-xr-x 2 owner group 4096 Jan 12 10:11 inbox");
        assert_eq!(v["name"], json!("inbox"));
        assert_eq!(v["type"], json!("dir"));
    }

    #[test]
    fn unparseable_line_falls_back_to_raw_name() {
        let v = line_to_json("totally not a list line");
        assert_eq!(v["name"], json!("totally not a list line"));
        assert_eq!(v["type"], json!("unknown"));
    }

    #[test]
    fn decode_text_vs_base64() {
        assert_eq!(decode_content(b"hello")["text"], json!("hello"));
        assert_eq!(decode_content(&[0xff, 0xfe])["base64"], json!("//4="));
    }
}
