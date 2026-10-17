# `mcpg-plugin-backend-ftp`

FTP / FTPS file-integration backend binding plugin for mcpg (`kind: ftp`).
Lists a directory, reads a file, or writes a file over FTP — with explicit
AUTH-TLS (FTPS) required by default — as MCP **tools** and **resources**.

Transport is [`suppaftp`] on a pure-Rust **rustls (ring)** TLS stack — no
OpenSSL / native-tls. Complements the `sftp` backend.

## How it works

One binding = one operation = one MCP tool (or resource):

| `op` | Behaviour | Returns | Mutates? |
|---|---|---|---|
| `list` (default) | List a directory's entries. | `{ entries, count }` | no (read-only) |
| `get` | Read a file (capped at `max_bytes`). | `{ content, size }` | no (read-only) |
| `put` | Write a file from the `content` (base64) / `text` argument. | `{ written }` | **yes** |

The target path comes from the call's `path` argument, joined under the
operator-configured `path` base — `..` segments are **rejected** before any
FTP call, so a caller cannot escape the base. A connection is opened per call.

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `op` | `list`\|`get`\|`put` | `list` | The operation. `put` mutates; `list`/`get` are read-only. |
| `host` | string (required) | — | FTP host. Operator-configured. |
| `port` | int | `21` | FTP control port. |
| `user` | string (required) | — | FTP login user. |
| `password` | string (required) | — | Resolved via the gateway secret-resolver (`${env.X}` / `vault://…`). Per-caller `cred://` is **not** supported. |
| `path` | string | `""` | Base dir the caller path joins under (`""` = the login's default dir). |
| `tls` | bool | `true` | Require explicit FTPS (AUTH TLS). Set `false` only for plaintext FTP on a trusted network. |
| `max_bytes` | int | `10485760` | Cap on bytes read (`get`) / written (`put`). |
| `timeout_ms` | int | `15000` | connect + auth + operation timeout. |
| `surface` | `tool`\|`resource` | `tool` | MCP surface. `tool` keeps the tool envelope; `resource` exposes files as MCP resources. |
| `uri` | string | `ftp://{path}` | `resource` surface URI template; `{path}` is filled with each file's path. Ignored on the `tool` surface. |

### As a list/get tool

```yaml
mcp:
  capabilities:
    tools:
      - name: dropbox.read
        description: Read a file from the partner drop directory.
        input_schema:
          type: object
          properties: { path: { type: string } }
          required: [path]
        backend:
          kind: ftp
          op: get
          host: "ftp.partner.example.com"
          user: "svc-mcpg"
          password: "${env.FTP_PASSWORD}"
          tls: true                 # require FTPS (default)
          path: "/outbound"
```

### As a put tool

```yaml
      backend:
        kind: ftp
        op: put
        host: "ftp.partner.example.com"
        user: "svc-mcpg"
        password: "${env.FTP_PASSWORD}"
        path: "/inbound"
        # the tool's `content` (base64) or `text` argument becomes the file body
```

### As a resource surface

With `surface: resource` the binding exposes the `path` directory as MCP
resources instead of a tool:

- **`resources/list`** enumerates `path` into one resource per **file** (dirs /
  symlinks skipped). Each resource's `uri` fills the `uri` template with the
  file path, `name` is the filename, `mimeType` derives from the extension, and
  `description` carries the byte size.
- **`resources/read`** recovers the file path from the requested `uri` (via the
  same `uri` template), `get`s the file under `max_bytes`, and returns it as
  `{contents:[{uri, text|blob, mimeType}]}` — `text` for valid UTF-8, `blob`
  (base64) for binary.
- **Completion** of the `{path}` template variable lists the directory and
  returns the entry names that start with the typed prefix.

The `..`-traversal reject still applies to every resolved path.

```yaml
mcp:
  capabilities:
    resources:
      - uri: ftp://outbound
        name: Partner outbound drop
        backend:
          kind: ftp
          surface: resource         # expose files as MCP resources
          uri: "ftp://{path}"       # uri template (default)
          host: "ftp.partner.example.com"
          user: "svc-mcpg"
          password: "${env.FTP_PASSWORD}"
          tls: true
          path: "/outbound"         # directory listed + read under
```

A `resources/read` for `ftp://outbound/report.csv` recovers the file path
`outbound/report.csv`, fetches it, and returns:

```jsonc
{
  "contents": [
    { "uri": "ftp://outbound/report.csv", "mimeType": "text/csv", "text": "a,b\n1,2\n" }
  ]
}
```

## Response envelope

```jsonc
{
  "toolName": "dropbox.list",
  "profile":  "dropbox.list",
  "request":  { "op": "list", "host": "ftp.partner.example.com", "path": "" },
  "response": {                       // op: list
    "entries": [ { "name": "report.csv", "type": "file", "size": 4096 } ],
    "count": 1, "content": null, "size": null, "written": null, "durationMs": 80
  },
  "downstreamError": null,            // non-null ⇒ isError:true (ftp_error / transport_error)
  "downstreamErrors": [],
  "error": null
}
```

`op: get` populates `content` (`{text}` / `{base64}`) + `size`; `op: put`
populates `written`.

## Security

- **Path-traversal defense.** The caller `path` is joined under the base with
  `..` segments rejected before any FTP call.
- **FTPS by default.** Explicit AUTH-TLS is required unless `tls: false` is
  set; plaintext is opt-in (trusted-network only).
- **No plaintext secrets.** The `password` resolves through the gateway
  secret-resolver; per-caller `cred://` is rejected.
- **Size cap.** `get`/`put` are bounded by `max_bytes`.
- **Pure-Rust TLS.** rustls (ring) — no OpenSSL / native-tls.

## Build / test

```bash
cargo build  -p mcpg-plugin-backend-ftp
cargo test   -p mcpg-plugin-backend-ftp                              # unit tests
cargo test   -p mcpg-plugin-backend-ftp --features integration-tests # against a live FTP server
cargo clippy -p mcpg-plugin-backend-ftp --all-targets -- -D warnings
```

The integration suite targets an operator-provided FTP/FTPS server (gated on
`FTP_TEST_HOST` / `FTP_TEST_USER` / `FTP_TEST_PASSWORD`, optional
`FTP_TEST_PORT` / `FTP_TEST_PATH` / `FTP_TEST_TLS`) and is **skipped** when
`FTP_TEST_HOST` is unset. `MCPG_REQUIRE_SERVICE=1` makes a missing server a
failure; the CI row `Event sources / file-shares` sets it and starts the
server on `127.0.0.1`. A containerised server is not started by the suite
because FTP passive-mode advertises a server-chosen data port that
testcontainers' random host-port remapping cannot rewrite. A server on the
host network works; Pure-FTPd advertises passive ports 30000-30009.

```bash
docker run -d --rm --name ftp-it --network host \
  -e PUBLICHOST=127.0.0.1 -e FTP_USER_NAME=testuser -e FTP_USER_PASS=testpass \
  -e FTP_USER_HOME=/home/testuser \
  stilliard/pure-ftpd:trixie-1.0.50@sha256:6435d108eb3fad29730f1b6748c1d49f3fa13e5d0fb49979ec3e0e96c5dbd94a
FTP_TEST_HOST=127.0.0.1 FTP_TEST_USER=testuser FTP_TEST_PASSWORD=testpass \
  cargo test -p mcpg-plugin-backend-ftp --features integration-tests
```

Besides the put → list → get round-trip, the suite runs an `ftp_dir_poll`
event source through a create, a modification, a delete and a restart.

## Directory watch (`ftp_dir_poll`)

This plugin also ships a `watch_strategy` entity (kind `ftp_dir_poll`) that
watches a directory by polling. FTP has no native change-push channel, so
each listing opens one connection, runs `LIST` on the watched directory (and
its subdirectories with `recursive`), and compares the files with the last
listing the gateway stored. A resource watch gets
`notifications/resources/updated` when a file is added, removed, or modified;
an MCP Events source gets each such file as the shared `object.changed` event
(see MCP Events, "Files and objects").

> **Time precision.** `LIST` reports a file's time to the minute at best.
> Adds, removes, renames, size changes and time changes are detected; an
> overwrite that keeps the size within the same minute is **not**.

| Field | Type | Default | Notes |
|---|---|---|---|
| `host` | string (required) | — | FTP host. |
| `port` | int | `21` | FTP control port. |
| `user` | string (required) | — | FTP login user (alias: `username`). |
| `password` | string (required) | — | Resolved via the gateway secret-resolver (`${env.X}` / `vault://…`); `cred://` is rejected. |
| `path` | string | `""` | Directory to watch (`""` = login dir; `..` rejected). Alias: `root`. |
| `tls` | bool | `true` | Require explicit FTPS (AUTH TLS). |
| `interval_ms` | int | `60000` | Listing cadence (at least 250 ms). |
| `timeout_ms` | int | `10000` | Budget of one listing: connect and every directory. |
| `recursive` | bool | `false` | Go into subdirectories, at most 1000 of them. |
| `pattern` | string | — | Keep only the files whose path relative to the directory matches this glob: `*` stays in a directory, `**` crosses them (`**/*.csv`). |
| `max_files` | int | `10000` | Most files listed (1 to 100000); past it the first in path order are kept, with a warning. |
| `start_at` | `now` \| `existing` | `now` | `now`: the files there at a first start are the baseline. `existing`: each is reported as created. |
| `snapshot_bytes` | int | `131072` | Largest snapshot of the listing an event carries, for an exact restart (at most 196608). |
| `max_in_flight` | int | `256` | Most changes emitted ahead of the gateway's acknowledgements (1 to 1000). |
| `ack_timeout_ms` | int | `60000` | How long a change waits for its acknowledgement before it is offered again. |

Keys are file paths relative to `path`, with `/` between parts; `location`
is `ftp://host:port/<directory>`, without credentials. A directory that
cannot be listed fails the whole listing, and the next interval tries again,
so a part that cannot be read is never reported as deleted. An unreachable
server does not fail the watch: it is listed again at the next interval.

As a resource watch:

```yaml
mcp:
  capabilities:
    resources:
      - uri: ftp://partner/inbox
        name: Partner inbox
        watch:
          strategy:
            type: plugin
            kind: ftp_dir_poll
            host: "ftp.partner.example.com"
            user: "svc-mcpg"
            password: "${env.FTP_PASSWORD}"
            path: "/inbound"
            interval_ms: 30000
```

As an MCP Events source, each file as `object.changed`:

```yaml
mcp:
  capabilities:
    events:
      - name: partner.inbox
        description: A file arrived in, changed in, or left the partner inbox.
        source:
          watch:
            strategy:
              type: plugin
              kind: ftp_dir_poll
              host: "ftp.partner.example.com"
              user: "svc-mcpg"
              password: "${env.FTP_PASSWORD}"
              path: "/inbound"
              recursive: true
            event_type: object.changed
```

## Scope / deferred

- **Public-key / client-cert auth** — v1 is password auth.
- **Implicit FTPS (port 990)** — v1 is explicit AUTH-TLS; implicit is
  deprecated upstream.
- **Recursive / streaming transfers, rename/mkdir/rm** — v1 is single-file
  `list` / `get` / `put`.
- **Connection pooling** — v1 connects per call.

[`suppaftp`]: https://crates.io/crates/suppaftp
