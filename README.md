# emailulator

Catch the email your application sends in development. Nothing is ever
delivered: every message is stored and shown to you instead.

- **In** over SMTP or an HTTP API.
- **Out** through a web UI, a REST API, an MCP server for agents, and a native
  desktop app.
- **One binary**, no runtime dependencies, SQLite inside. The same program is
  the server (`emailulator run`) and the desktop app (`emailulator app`).
- **Each recipient is a mailbox.** Mail to `bob@example.test` lands in Bob's
  mailbox, including mail he was only Bcc'd on.

```
your app ──SMTP :1025──▶ ┌─────────────┐ ──▶ web UI      http://127.0.0.1:8025/
your app ──POST /api/v1─▶ │ emailulator │ ──▶ REST API    /api/v1
                         └─────────────┘ ──▶ MCP         /mcp  (or stdio)
                                         ──▶ desktop app
```

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/webteractive/emailulator/main/install.sh | sh
```

That downloads the release for your platform, verifies its checksum, and puts
`emailulator` in `~/.local/bin`. Set `EMAILULATOR_INSTALL_DIR` to put it
elsewhere, or `EMAILULATOR_VERSION=0.1.0` to pin a release instead of taking the
latest.

| Platform | What you get |
| --- | --- |
| macOS, Apple silicon | Server and desktop app, in the one binary; Developer ID signed and notarized |
| Linux, x86-64 and arm64 | Server, statically linked: runs on any distro and in a bare container |

From a checkout, `./install.sh --source` builds it with cargo instead.

## Run it

```sh
emailulator run
```

```
emailulator 0.1.0
  SMTP   127.0.0.1:1025  (no auth, no TLS)
  HTTP   http://127.0.0.1:8025  (no auth)
         web UI   http://127.0.0.1:8025/
         API      http://127.0.0.1:8025/api/v1
         MCP      http://127.0.0.1:8025/mcp
```

Or, on a Mac, skip the terminal: `emailulator app` opens the desktop app, which
runs the same servers itself.

Point your app at it. For Laravel:

```dotenv
MAIL_MAILER=smtp
MAIL_HOST=127.0.0.1
MAIL_PORT=1025
```

With no options it listens on this machine only and needs no credentials.
Messages are kept in the platform data directory
(`~/Library/Application Support/emailulator` on macOS,
`~/.local/share/emailulator` on Linux); `--memory` keeps them in RAM instead.

## Sending without SMTP

```sh
curl -X POST http://127.0.0.1:8025/api/v1/messages \
  -H 'Content-Type: application/json' \
  -d '{
    "from": "Shop <shop@example.test>",
    "to": ["bob@example.test"],
    "subject": "Your order shipped",
    "text": "Plain body",
    "html": "<p>Rich body</p>"
  }'
```

Also accepted: `cc`, `bcc`, `reply_to`, `headers` (an object), and `attachments`
(`[{"filename", "content": "<base64>", "content_type"?, "content_id"?}]`).
Addresses are `"a@b"`, `"Name <a@b>"` or `{"name", "address"}`.

To deliver a complete RFC 5322 message, post it with any other content type;
`?from=` and `?to=a@x,b@x` set the envelope, which otherwise comes from the
message's own headers.

## REST API

| Method and path | Does |
| --- | --- |
| `GET /api/v1/messages` | List, newest first. `mailbox`, `q`, `unread`, `starred`, `before`, `after`, `since`, `limit` |
| `POST /api/v1/messages` | Deliver a message (above) |
| `PATCH /api/v1/messages?mailbox=` | `{"read": true}` marks all read |
| `DELETE /api/v1/messages?mailbox=` | Delete all, or one mailbox |
| `GET /api/v1/messages/{id}` | Headers, bodies, attachment list |
| `PATCH /api/v1/messages/{id}` | `{"read": bool, "starred": bool}` |
| `DELETE /api/v1/messages/{id}` | Delete one |
| `GET /api/v1/messages/{id}/raw` | The message as received (`.eml`) |
| `GET /api/v1/messages/{id}/html` | The HTML body, sandboxed, inline images embedded |
| `GET /api/v1/messages/{id}/links` | Links with their anchor text |
| `GET /api/v1/messages/{id}/attachments/{index}` | One attachment |
| `GET /api/v1/mailboxes` | Mailboxes with total and unread counts |
| `GET /api/v1/events` | Server-sent events as mail arrives and changes |
| `GET /api/v1/info` | Version, ports, limits, counts |
| `GET /healthz` | `ok` |

Search (`q`) takes bare words plus `from:`, `to:`, `subject:`, `is:unread`,
`is:read`, `is:starred` and `has:attachment`. Quote phrases:
`subject:"reset link"`.

## MCP

Agents can read the mail their own actions caused. Over HTTP, against a running
server:

```sh
claude mcp add --transport http emailulator http://127.0.0.1:8025/mcp
# with a token:
claude mcp add --transport http emailulator https://mail.example.com/mcp \
  --header "Authorization: Bearer $EMAILULATOR_AUTH_TOKEN"
```

Or over stdio, reading the message store on this machine directly (no server
needs to be running, though one must have caught the mail):

```sh
claude mcp add emailulator -- emailulator mcp
```

Tools: `list_messages`, `get_message`, `wait_for_message`, `get_links`,
`get_attachment`, `get_raw_message`, `list_mailboxes`, `mark_message`,
`send_message`, `delete_messages`.

`wait_for_message` is the one built for tests: trigger a sign-up or a password
reset, then wait for the mail by recipient and get its body and links back in a
single call. It also matches mail that arrived in the last minute, so it is safe
to call after the action.

## Desktop app

```sh
emailulator app
```

A native mail client built with [gpui](https://www.gpui.rs): mailboxes, message
list, reading pane, search, and HTML, text, headers, raw and links views. It is
part of the `emailulator` binary on macOS, and the command returns as soon as the
window is open (`--foreground` keeps it attached to the terminal).

The app runs the same SMTP and HTTP servers inside itself, on this machine only,
and reads the same message store as `emailulator run`. If the ports are already
taken — by `emailulator run`, say — it opens as a viewer on that store instead.
`--smtp-addr`, `--http-addr` and `--data-dir` work as they do for `run`.

Keys: `j`/`k` or arrows to move, `s` star, `u` unread, `#` or delete to delete,
`/` or `⌘F` to search, `Esc` to clear.

Message bodies render in the system webview with JavaScript disabled. The app is
a local tool: it does not connect to a remote emailulator.

The Linux release is the server alone, because a binary that links the windowing
system cannot start on a headless host. There, `emailulator app` says so; use the
web UI. To build the app into a binary yourself on any platform:
`cargo build --release --features desktop`.

## Deploying

Away from `127.0.0.1`, emailulator **will not start without credentials**:

```
error: the HTTP listener on 0.0.0.0:8025 is reachable from other machines but
has no auth token, so anyone who can reach it could read every captured email.
```

```sh
export EMAILULATOR_AUTH_TOKEN=$(openssl rand -hex 32)      # API, MCP and web UI
export EMAILULATOR_SMTP_AUTH=app:$(openssl rand -hex 32)   # SMTP, as user:password
docker compose up -d
```

(`emailulator token` prints the same kind of value.) To run it without Docker,
install it with the one-liner above and start `emailulator run` under whatever
supervises your services, with the same variables set.

`compose.yaml` runs it as an unprivileged user on a read-only root filesystem
with all capabilities dropped, data on a volume, and both ports published on the
host's loopback. The image is distroless: no shell, no package manager.

For anything reachable over a network, add TLS. Either terminate it at a reverse
proxy in front of port 8025, or give emailulator a certificate, which turns on
HTTPS and SMTP `STARTTLS` together:

```sh
emailulator run --tls-cert fullchain.pem --tls-key privkey.pem
```

A proxy should pass the original host through, as `Host` or `X-Forwarded-Host`,
and set `X-Forwarded-Proto: https`: the first is how the server tells its own
web UI from another site, the second is what marks the session cookie `Secure`.
A proxy only covers HTTP, so SMTP still needs the certificate to be encrypted.

### Options

Every flag has an environment variable; `emailulator run --help` lists them all.

| Variable | Default | |
| --- | --- | --- |
| `EMAILULATOR_SMTP_ADDR` | `127.0.0.1:1025` | SMTP listener |
| `EMAILULATOR_HTTP_ADDR` | `127.0.0.1:8025` | Web UI, API and MCP |
| `EMAILULATOR_DATA_DIR` | platform data dir | Where the database lives |
| `EMAILULATOR_MEMORY` | off | Keep messages in memory only |
| `EMAILULATOR_AUTH_TOKEN` / `_FILE` | none | Token for API, MCP and web UI (16+ characters) |
| `EMAILULATOR_SMTP_AUTH` / `_FILE` | none | `user:password` SMTP clients must present |
| `EMAILULATOR_TLS_CERT`, `EMAILULATOR_TLS_KEY` | none | PEM files; enables HTTPS and STARTTLS |
| `EMAILULATOR_ALLOW_ANONYMOUS_HTTP` | off | Serve an exposed HTTP listener with no token |
| `EMAILULATOR_ALLOW_ANONYMOUS_SMTP` | off | Accept SMTP from anyone on an exposed listener |
| `EMAILULATOR_MAX_MESSAGE_SIZE` | `25MB` | Largest message accepted |
| `EMAILULATOR_MAX_MESSAGES` | `1000` | Oldest are dropped beyond this; `0` keeps all |
| `EMAILULATOR_MAX_STORAGE` | `1GB` | Oldest are dropped beyond this; `0` for no cap |
| `EMAILULATOR_NO_UI` | off | API and MCP only |

Prefer the environment or the `_FILE` variants for secrets: a command-line
argument is visible to every user of the machine in the process list.

## Security model

Captured mail is sensitive — it is where password-reset links go — and email
content is written by whoever sends it. The design assumes both.

**Who gets in**

- A listener on a non-loopback address needs credentials, or an explicit
  `--allow-anonymous-*` flag. There is no silent open mode.
- The API and MCP endpoint take `Authorization: Bearer <token>`. The web UI
  signs in with the token and gets a random session id in an
  `HttpOnly; SameSite=Strict` cookie (`Secure` over HTTPS); the token itself is
  never stored in the browser. Sessions end on sign-out, after seven days, or
  when the server restarts.
- Secrets are compared in constant time. Failed sign-ins and SMTP logins are
  delayed; three bad SMTP logins close the connection.
- With TLS configured, SMTP offers and accepts `AUTH` only after `STARTTLS`
  (clients on the same machine excepted). Anything a client sends in the clear
  after `STARTTLS` drops the connection rather than being read as if it were
  encrypted.
- With no token on a loopback listener, requests must be addressed to
  `localhost` or a loopback IP, which stops a web page from reaching the server
  through DNS rebinding. State-changing requests from another origin are refused.

**What email content can do**

- HTML bodies are served with `Content-Security-Policy: sandbox` and no script
  source, and framed with a matching `sandbox` attribute: scripts do not run and
  the document cannot reach the API or the session.
- Attachments are always downloads, also sandboxed, with `nosniff`.
- The web UI builds the page from text nodes only and runs under
  `default-src 'self'`, with no inline script or style.
- The desktop app's webview has JavaScript disabled, may not navigate, and opens
  a link in your browser only when you click it. Saved attachments are written
  to Downloads under a sanitized name and never overwrite a file.
- Remote images in an email **are** loaded when you view it, as a mail client
  would, so the sender's server learns that you did.

**What it will not do**

- Relay. There is no code path that sends mail anywhere.
- Fill the disk. Message size, recipients per message, concurrent SMTP
  connections, message count and total stored bytes are all capped.

The database file is created `0600` in a `0700` directory. It is not encrypted
at rest.

## Development

```sh
cargo test                           # the server
cargo test --features desktop-test   # plus the desktop app, driven headlessly
cargo run --features desktop -- app  # the desktop app from source
cargo deny check                     # licenses, sources, advisories, banned crates
```

In a debug build the web UI is read from `ui/` on every request, so editing it
needs no rebuild. It is plain HTML, CSS and one ES module: no build step.

The desktop app can test itself against a real window: set
`EMAILULATOR_APP_SELFTEST=1` and run `emailulator app --foreground` with a
scratch `--data-dir`. It opens a message, visits every tab, and exits non-zero
if the message view did not come up.

## Releasing

```sh
scripts/release.sh patch      # or minor, major, X.Y.Z, or `current` for no bump
```

A release is assembled from two places, and the script drives both:

- **macOS** is built on a Mac by `scripts/package.sh`: Developer ID signed with
  the hardened runtime, self-tested, and notarized. It needs the "Developer ID
  Application" certificate in the keychain and a notarytool keychain profile
  named `notary`; `scripts/package.sh --preflight` checks for both, and the
  release script runs that before it changes anything.
- **Linux** is built by the release workflow when the tag is pushed. It leaves
  its archives on a draft release.

The script then adds the macOS archive and a `checksums.txt` covering all three
archives, and publishes. Until that last step the release is a draft, which
`install.sh` cannot see, so a half-assembled release is never installable.
