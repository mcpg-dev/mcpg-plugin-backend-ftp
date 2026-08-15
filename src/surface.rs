//! MCP surface shaping for the file-as-resource binding.
//!
//! A binding is a tool by default; the operator may instead place it under
//! `mcp.capabilities.resources[]` / `resource_templates[]`. The gateway routes
//! those reads to the same `execute()` path but applies a strict decoder over
//! the response body — `{contents:[…]}` for `resources/read`. The tool surface
//! keeps the raw envelope.
//!
//! On the resource surface the gateway materializes the requested URI into the
//! call arguments as a top-level `uri`; this module recovers the file path from
//! that URI via the binding's `uri` template, lists a directory into one
//! resource per file, and wraps a fetched file's bytes into a `resources/read`
//! body. The `..`-traversal reject in [`crate::ftp::resolve_path`] still applies
//! to every recovered path.

use mcpg_plugin_protocol::{ListedResource, ResourcePage};
use serde::Deserialize;
use serde_json::{Value, json};

/// Which MCP surface a binding serves. `Tool` (default) keeps the historical
/// tool-shaped envelope byte-for-byte; `Resource` exposes files as MCP
/// resources (`resources/list` + `resources/read`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// Tool surface — unchanged envelope.
    #[default]
    Tool,
    /// `resources/list` + `resources/read` surface over files.
    Resource,
}

impl Surface {
    /// Stable label for diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Tool => "tool",
            Surface::Resource => "resource",
        }
    }
}

/// The placeholder a `uri` template substitutes the file path into.
const PATH_PLACEHOLDER: &str = "{path}";

/// Fill a `uri` template's `{path}` placeholder with `path`. The leading `/`
/// of an absolute path is trimmed so the URI stays clean (`ftp://a/b`, not
/// `ftp://a//b`). Templates without a `{path}` placeholder are returned
/// verbatim.
pub fn fill_uri_template(template: &str, path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    template.replace(PATH_PLACEHOLDER, trimmed)
}

/// Recover the file path from a requested resource `uri`, given the binding's
/// `uri` template. The template is split on `{path}`; when the URI carries the
/// template's prefix and suffix, the middle segment is the path. A template
/// without a `{path}` placeholder, or a URI that doesn't match the template's
/// fixed parts, yields `None` (the caller then falls back to a literal `path`
/// argument or surfaces a clean error).
pub fn path_from_uri(template: &str, uri: &str) -> Option<String> {
    let (prefix, suffix) = template.split_once(PATH_PLACEHOLDER)?;
    let body = uri.strip_prefix(prefix)?;
    let body = if suffix.is_empty() {
        body
    } else {
        body.strip_suffix(suffix)?
    };
    if body.is_empty() {
        return None;
    }
    Some(body.to_owned())
}

/// Resolve the file path for a `resources/read`: prefer recovering it from the
/// gateway-supplied `uri` via the `uri` template, then fall back to a literal
/// `path` argument. Returns `None` when neither yields a non-empty path so the
/// caller can emit a clean error rather than a decoder-invalid body.
pub fn resolve_read_path(template: &str, arguments: &Value) -> Option<String> {
    if let Some(uri) = arguments.get("uri").and_then(Value::as_str)
        && let Some(path) = path_from_uri(template, uri)
        && !path.trim().is_empty()
    {
        return Some(path);
    }
    arguments
        .get("path")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|p| !p.trim().is_empty())
}

/// Map a file's extension to an IANA media type. Unknown / extension-less
/// names yield `application/octet-stream`. Lower-cased before matching so
/// `.CSV` and `.csv` agree.
pub fn mime_type_for(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "txt" | "log" | "text" => "text/plain",
        "csv" => "text/csv",
        "tsv" => "text/tab-separated-values",
        "json" => "application/json",
        "ndjson" | "jsonl" => "application/x-ndjson",
        "xml" => "application/xml",
        "yaml" | "yml" => "application/yaml",
        "html" | "htm" => "text/html",
        "md" | "markdown" => "text/markdown",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "parquet" => "application/vnd.apache.parquet",
        _ => "application/octet-stream",
    }
}

/// Project a directory listing (the JSON entries [`crate::ftp::line_to_json`]
/// produces) into a [`ResourcePage`]. One resource per **file** entry; `dir` /
/// `symlink` / `unknown` entries are skipped (a resource read targets a single
/// readable file). The resource `uri` fills `uri_template` with the entry's
/// path under `dir_path`, `name` is the filename, `mimeType` derives from the
/// extension, and the entry's `size` (when present) flows into the description.
/// The listing is returned in one page (FTP `LIST` is not natively paginated).
pub fn entries_to_resource_page(
    entries: &[Value],
    dir_path: &str,
    uri_template: &str,
) -> ResourcePage {
    let mut resources: Vec<ListedResource> = Vec::with_capacity(entries.len());
    for entry in entries {
        let Value::Object(obj) = entry else { continue };
        if obj.get("type").and_then(Value::as_str) != Some("file") {
            continue;
        }
        let Some(name) = obj.get("name").and_then(Value::as_str) else {
            continue;
        };
        if name.trim().is_empty() {
            continue;
        }
        let full_path = join_dir(dir_path, name);
        let size = obj.get("size").and_then(Value::as_u64);
        resources.push(ListedResource {
            uri: fill_uri_template(uri_template, &full_path),
            name: Some(name.to_owned()),
            description: size.map(|n| format!("{n} bytes")),
            mime_type: Some(mime_type_for(name).to_owned()),
        });
    }
    ResourcePage {
        resources,
        next_cursor: None,
    }
}

/// Join a directory path and a filename into a single path, collapsing the
/// `/`-separator. An empty `dir` (the login's default directory) yields the
/// bare filename.
fn join_dir(dir: &str, name: &str) -> String {
    let dir = dir.trim_end_matches('/');
    if dir.is_empty() || dir == "." {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

/// Wrap a fetched file's decoded content into the `resources/read` contract
/// body — `{contents:[{uri, text|blob, mimeType}]}`. `content` is the
/// [`crate::ftp::decode_content`] shape (`{text}` for valid UTF-8, `{base64}`
/// otherwise); UTF-8 maps to a `text` content, binary to a `blob` content
/// (per the MCP resource-content schema).
pub fn resource_contents_body(uri: &str, mime_type: &str, content: &Value) -> Value {
    let mut entry = serde_json::Map::new();
    entry.insert("uri".to_owned(), json!(uri));
    entry.insert("mimeType".to_owned(), json!(mime_type));
    if let Some(text) = content.get("text").and_then(Value::as_str) {
        entry.insert("text".to_owned(), json!(text));
    } else if let Some(b64) = content.get("base64").and_then(Value::as_str) {
        entry.insert("blob".to_owned(), json!(b64));
    } else {
        // No decodable content — emit an empty text body so the decoder still
        // sees a well-formed `{contents}` entry.
        entry.insert("text".to_owned(), json!(""));
    }
    json!({ "contents": [Value::Object(entry)] })
}

/// Extract completion candidates for the `{path}` template variable from a
/// directory listing: the file/dir names that start with `prefix`, capped at
/// `max`. Directories are included (a caller drilling into a subtree completes
/// against them); the match is on the bare entry name.
pub fn entries_to_completion_values(entries: &[Value], prefix: &str, max: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(entries.len().min(max));
    for entry in entries {
        if out.len() >= max {
            break;
        }
        let Value::Object(obj) = entry else { continue };
        let Some(name) = obj.get("name").and_then(Value::as_str) else {
            continue;
        };
        if name.starts_with(prefix) {
            out.push(name.to_owned());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_default_is_tool() {
        assert_eq!(Surface::default(), Surface::Tool);
    }

    #[test]
    fn surface_parses_snake_case() {
        let s: Surface = serde_json::from_value(json!("resource")).unwrap();
        assert_eq!(s, Surface::Resource);
        let s: Surface = serde_json::from_value(json!("tool")).unwrap();
        assert_eq!(s, Surface::Tool);
    }

    #[test]
    fn uri_template_fills_and_trims_leading_slash() {
        assert_eq!(
            fill_uri_template("ftp://{path}", "/inbox/a.csv"),
            "ftp://inbox/a.csv"
        );
        assert_eq!(fill_uri_template("ftp://{path}", "a.csv"), "ftp://a.csv");
        assert_eq!(
            fill_uri_template("file://partner/{path}", "/reports/q1.json"),
            "file://partner/reports/q1.json"
        );
    }

    #[test]
    fn path_recovered_from_uri() {
        assert_eq!(
            path_from_uri("ftp://{path}", "ftp://inbox/a.csv").as_deref(),
            Some("inbox/a.csv")
        );
        assert_eq!(
            path_from_uri("file://partner/{path}", "file://partner/reports/q1.json").as_deref(),
            Some("reports/q1.json")
        );
        // URI that doesn't match the template's fixed parts.
        assert_eq!(path_from_uri("ftp://{path}", "https://x/y"), None);
        // Template with no placeholder cannot recover a path.
        assert_eq!(path_from_uri("ftp://static", "ftp://static"), None);
    }

    #[test]
    fn resolve_read_prefers_uri_then_path_argument() {
        let from_uri = json!({ "uri": "ftp://inbox/a.csv" });
        assert_eq!(
            resolve_read_path("ftp://{path}", &from_uri).as_deref(),
            Some("inbox/a.csv")
        );
        let from_arg = json!({ "path": "inbox/b.csv" });
        assert_eq!(
            resolve_read_path("ftp://{path}", &from_arg).as_deref(),
            Some("inbox/b.csv")
        );
        assert_eq!(resolve_read_path("ftp://{path}", &json!({})), None);
        assert_eq!(
            resolve_read_path("ftp://{path}", &json!({ "path": "  " })),
            None
        );
    }

    #[test]
    fn mime_type_from_extension() {
        assert_eq!(mime_type_for("report.csv"), "text/csv");
        assert_eq!(mime_type_for("notes.TXT"), "text/plain");
        assert_eq!(mime_type_for("data.json"), "application/json");
        assert_eq!(mime_type_for("archive.tar"), "application/octet-stream");
        assert_eq!(mime_type_for("noext"), "application/octet-stream");
    }

    fn listing() -> Vec<Value> {
        vec![
            json!({ "name": "report.csv", "type": "file", "size": 4096 }),
            json!({ "name": "notes.txt", "type": "file", "size": 12 }),
            json!({ "name": "inbox", "type": "dir", "size": Value::Null }),
            json!({ "name": "link", "type": "symlink", "size": Value::Null }),
        ]
    }

    #[test]
    fn entries_map_to_file_resources_only() {
        let page = entries_to_resource_page(&listing(), "/outbound", "ftp://{path}");
        // Only the two files; dir + symlink skipped.
        assert_eq!(page.resources.len(), 2);
        assert!(page.next_cursor.is_none());

        let first = &page.resources[0];
        assert_eq!(first.uri, "ftp://outbound/report.csv");
        assert_eq!(first.name.as_deref(), Some("report.csv"));
        assert_eq!(first.mime_type.as_deref(), Some("text/csv"));
        assert_eq!(first.description.as_deref(), Some("4096 bytes"));
    }

    #[test]
    fn entries_at_login_dir_use_bare_filename() {
        let page = entries_to_resource_page(&listing(), "", "ftp://{path}");
        assert_eq!(page.resources[0].uri, "ftp://report.csv");
    }

    #[test]
    fn read_body_text_satisfies_decoder_shape() {
        let content = json!({ "text": "a,b\n1,2\n" });
        let body = resource_contents_body("ftp://outbound/report.csv", "text/csv", &content);
        let contents = body["contents"].as_array().expect("contents array");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!("ftp://outbound/report.csv"));
        assert_eq!(contents[0]["mimeType"], json!("text/csv"));
        assert_eq!(contents[0]["text"], json!("a,b\n1,2\n"));
        assert!(contents[0].get("blob").is_none());
    }

    #[test]
    fn read_body_binary_uses_blob() {
        let content = json!({ "base64": "//4=" });
        let body =
            resource_contents_body("ftp://outbound/x.bin", "application/octet-stream", &content);
        let contents = body["contents"].as_array().unwrap();
        assert_eq!(contents[0]["blob"], json!("//4="));
        assert!(contents[0].get("text").is_none());
    }

    #[test]
    fn completion_filters_by_prefix_and_caps() {
        let entries = vec![
            json!({ "name": "alpha.csv", "type": "file", "size": 1 }),
            json!({ "name": "alphabet.csv", "type": "file", "size": 2 }),
            json!({ "name": "beta.csv", "type": "file", "size": 3 }),
        ];
        let got = entries_to_completion_values(&entries, "alpha", 10);
        assert_eq!(got, vec!["alpha.csv".to_owned(), "alphabet.csv".to_owned()]);
        let capped = entries_to_completion_values(&entries, "alpha", 1);
        assert_eq!(capped, vec!["alpha.csv".to_owned()]);
        let none = entries_to_completion_values(&entries, "zzz", 10);
        assert!(none.is_empty());
    }
}
