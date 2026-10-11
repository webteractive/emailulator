<img src="ui/icon.svg" width="64" height="64" alt="">

# emailulator

Catch the email your application sends in development. Nothing is ever
delivered: every message is stored and shown to you instead.

- **In** over SMTP or an HTTP API.
- **Out** through a web UI, a REST API, an MCP server for agents, and a native
  desktop app.
- **Inboxes, one per app.** Each inbox has its own API keys. A key is what lets
  an app deliver into the inbox, and what confines a reader — a script, an
  agent — to it.
- **One binary**, no runtime dependencies, SQLite inside. The same program is
  the server (`emailulator run`) and the desktop app (`emailulator app`).

```
billing app ──SMTP as billing-app + key──▶ ┌─────────────┐ ──▶ web UI, desktop app
marketing  ───POST /api/v1 with its key──▶ │ emailulator │ ──▶ REST API   (key ⇒ its inbox)
anything, no key, on this machine ───────▶ └─────────────┘ ──▶ MCP        (key ⇒ its inbox)
                                             └ lands in `default`
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
  SMTP   127.0.0.1:1025  (no auth; unauthenticated mail goes to the default inbox, no TLS)
  HTTP   http://127.0.0.1:8025  (no auth)
         web UI   http://127.0.0.1:8025/
         API      http://127.0.0.1:8025/api/v1
         MCP      http://127.0.0.1:8025/mcp
```

Or, on a Mac, skip the terminal: `emailulator app` opens the desktop app, which
runs the same servers itself.

Point your app at it and mail shows up in the `default` inbox. For Laravel:

```dotenv
MAIL_MAILER=smtp
MAIL_HOST=127.0.0.1
MAIL_PORT=1025
```

With no options it listens on this machine only and needs no credentials.
Messages are kept in the platform data directory
(`~/Library/Application Support/emailulator` on macOS,
`~/.local/share/emailulator` on Linux); `--memory` keeps them in RAM instead.

## Inboxes and API keys

Give each app its own inbox, so its mail is not mixed with another's:

```sh
emailulator inbox create "Billing app" --description "Invoices and receipts"
```

```
Created inbox "Billing app" with the id billing-app.

API key, shown this once:

  emu_3fa9c2d17b0e4c58a1d6f2e9b7c4a03d5e8f1a6b2c9d4e70

SMTP   username  billing-app
       password  the key
API    Authorization: Bearer <the key>
```

An inbox has a **name** for people and an **id** for machines. The id is made
from the name when the inbox is created (`Billing app` becomes `billing-app`,
or `billing-app-2` if that is taken) and then never changes, so renaming an
inbox does not break the apps configured with it.

The **id is the SMTP username and one of the inbox's keys is the password**:

```dotenv
MAIL_MAILER=smtp
MAIL_HOST=127.0.0.1
MAIL_PORT=1025
MAIL_USERNAME=billing-app
MAIL_PASSWORD=emu_3fa9c2d1…
```

A key works only with its own inbox's id; the same key under another id is
refused. The same key, as a bearer token, reads and sends within that inbox over
the API and MCP, and signs the web UI in to a view of that inbox alone.

- An inbox comes with its first key, and can have several, so one can be
  replaced without downtime: `emailulator key create billing-app`, then
  `emailulator key revoke <id>`.
- `emailulator key regenerate <id>` replaces a key's value in place, keeping its
  label. The old value stops working at once.
- A key is shown once, when it is created or regenerated. Only a hash of it is
  kept; `key list` shows its first characters and whether it has been used.
- `default` always exists and cannot be deleted. It is where mail without a key
  goes, which is what keeps a local setup working with nothing configured.
- Deleting an inbox deletes its messages and keys.

`inbox` and `key` work on the message store on this machine, as the web UI and
desktop app do; they take an inbox by id or by name, and every listing takes
`--json`. Against a remote server, use its web UI or the API below with the
admin token.

## Sending without SMTP

```sh
curl -X POST http://127.0.0.1:8025/api/v1/messages \
  -H 'Authorization: Bearer emu_3fa9c2d1…' \
  -H 'Content-Type: application/json' \
  -d '{
    "from": "Shop <shop@example.test>",
    "to": ["bob@example.test"],
    "subject": "Your order shipped",
    "text": "Plain body",
    "html": "<p>Rich body</p>"
  }'
```

The key decides the inbox. Without one (on an open local server) the message
goes to `default`, or to `?inbox=<id>`.

Also accepted: `cc`, `bcc`, `reply_to`, `headers` (an object), and `attachments`
(`[{"filename", "content": "<base64>", "content_type"?, "content_id"?}]`).
Addresses are `"a@b"`, `"Name <a@b>"` or `{"name", "address"}`.

To deliver a complete RFC 5322 message, post it with any other content type;
`?from=` and `?to=a@x,b@x` set the envelope, which otherwise comes from the
message's own headers.

## REST API

A request acts as an **inbox key** (that inbox only) or as the **admin** (the
admin token; or anyone, on a local server that has no token).

| Method and path | Does |
| --- | --- |
| `GET /api/v1/messages` | List, newest first; see the filters below |
| `POST /api/v1/messages` | Deliver a message (above) |
| `PATCH /api/v1/messages` | `{"read": true}` marks read everything the filters select |
| `DELETE /api/v1/messages` | Delete everything the filters select |
| `GET /api/v1/messages/{id}` | Headers, bodies, attachment list |
| `PATCH /api/v1/messages/{id}` | `{"read": bool, "starred": bool}` |
| `DELETE /api/v1/messages/{id}` | Delete one |
| `GET /api/v1/messages/{id}/raw` | The message as received (`.eml`) |
| `GET /api/v1/messages/{id}/html` | The HTML body, sandboxed, inline images embedded |
| `GET /api/v1/messages/{id}/links` | Links with their anchor text |
| `GET /api/v1/messages/{id}/check` | Which email clients support what the message uses; `?clients=outlook,gmail` narrows it |
| `GET /api/v1/messages/{id}/attachments/{index}` | One attachment |
| `GET /api/v1/inboxes` | Inboxes with counts: all for the admin, its own for a key |
| `POST /api/v1/inboxes` | *Admin.* `{"name", "description"?}` creates an inbox and returns it with its id and first key, once |
| `PATCH /api/v1/inboxes/{id}` | *Admin.* `{"name"?, "description"?}`; the id does not change |
| `DELETE /api/v1/inboxes/{id}` | *Admin.* Delete an inbox, its messages and keys |
| `GET /api/v1/inboxes/{id}/keys` | *Admin.* Its keys, never the keys themselves |
| `POST /api/v1/inboxes/{id}/keys` | *Admin.* `{"label"?}` creates a key and returns it, once |
| `POST /api/v1/inboxes/{id}/keys/{key_id}/regenerate` | *Admin.* Replace a key's value and return the new one, once |
| `DELETE /api/v1/inboxes/{id}/keys/{key_id}` | *Admin.* Revoke a key |
| `GET /api/v1/events` | Server-sent events as mail arrives and changes |
| `GET /api/v1/info` | Version, ports, limits, counts, and who you are acting as |
| `GET /healthz` | `ok` |

Filters, as query parameters: `inbox` (admin; a key is already confined), `to`
(an exact recipient), `q`, `unread`, `starred`, `before`, `after`, `since`,
`limit`. An unknown parameter is an error rather than ignored, so a misspelled
filter cannot widen a bulk delete.

Search (`q`) takes bare words plus `from:`, `to:`, `subject:`, `is:unread`,
`is:read`, `is:starred` and `has:attachment`. Quote phrases:
`subject:"reset link"`.

A message in another inbox is, to a key, a message that does not exist: `404`,
in the same words.

`POST /api/v1/inboxes` with `"dry_run": true` creates nothing and answers with
the id the name would get and a fresh key, for a form that shows both before the
inbox exists; sending that `id` and `key` back creates the inbox with exactly
those.

## MCP

Agents can read the mail their own actions caused. Give an agent an inbox's key
and it works inside that inbox:

```sh
claude mcp add --transport http emailulator http://127.0.0.1:8025/mcp \
  --header "Authorization: Bearer emu_3fa9c2d1…"
```

On an open local server the header can be left off, for access to every inbox.
Or over stdio, reading the message store on this machine directly (no server
needs to be running, though one must have caught the mail):

```sh
claude mcp add emailulator -- emailulator mcp --inbox billing-app   # id or name
```

Tools: `list_messages`, `get_message`, `wait_for_message`, `get_links`,
`check_message`, `get_attachment`, `get_raw_message`, `list_inboxes`,
`mark_message`, `send_message`, `delete_messages`.

`wait_for_message` is the one built for tests: trigger a sign-up or a password
reset, then wait for the mail by recipient (`to`) and get its body and links
back in a single call. It also matches mail that arrived in the last minute, so
it is safe to call after the action.

## Will it render? The client check

No tool can show you exactly what Outlook or Gmail will do with an email:
Outlook for Windows lays mail out with Word's engine, and Gmail rewrites the
markup on its servers. What can be known from the message itself is which HTML
and CSS features it uses and which clients support them, and that is the
**Check** tab, in the web UI and the desktop app:

```
Gmail 20 of 24    Outlook 10 of 24    Apple Mail 24 of 24    Yahoo! Mail 17 of 24

Not supported (1)
  border-radius   used 1 time
    Outlook       not supported on Windows, Windows Mail
```

- It reads the markup; it does not render it. Treat it as a list of things to
  go and look at, not as a screenshot.
- The data is [caniemail.com](https://www.caniemail.com)'s (MIT licensed),
  bundled into the binary: about 300 features across 22 clients. The tab shows
  the five most mail is read in, and every client on request. To refresh it:
  `curl -o data/caniemail.json https://www.caniemail.com/api/data.json`.
- A feature counts as unsupported for a client if it fails on any of that
  client's platforms, since someone is reading there.
- It also notes what is not about one feature: HTML over the 102 KB at which
  Gmail clips a message, a missing plain-text part, images without alt text,
  attachment types Gmail and Outlook refuse to deliver, and messages over the
  main providers' size limits.
- Contents of Outlook conditional comments (`<!--[if mso]>`) are not checked.

For an agent it is the `check_message` tool: change a template, send it, check
it, repeat.

## Desktop app

```sh
emailulator app
```

A native mail client built with [gpui](https://www.gpui.rs): inboxes, message
list, reading pane, search, and HTML, text, headers, raw, links and check views,
with the HTML view at desktop, tablet or mobile width. It is
part of the `emailulator` binary on macOS, and the command returns as soon as the
window is open (`--foreground` keeps it attached to the terminal).

**New** in the sidebar creates an inbox: give it a name and it shows the id and
key it will have before you confirm. **Connect**, at the top of an inbox, shows
what an app needs to deliver into it — host, port, the inbox id as username —
and creates, regenerates and revokes its keys. A new key is shown until you
leave the inbox.

The app runs the same SMTP and HTTP servers inside itself, on this machine only,
and reads the same message store as `emailulator run`. If ports 1025 and 8025
are taken — by another mail catcher, say — it uses 1026 and 8026 (then 2525 and
8525) and shows which in the sidebar. `--smtp-addr`, `--http-addr` and
`--data-dir` work as they do for `run`.

Keys: `j`/`k` or arrows to move, `s` star, `u` unread, `#` or delete to delete,
`/` or `⌘F` to search, `Esc` to clear.

Message bodies render in the system webview with JavaScript disabled. The app is
a local tool: it does not connect to a remote emailulator.

The Linux release is the server alone, because a binary that links the windowing
system cannot start on a headless host. There, `emailulator app` says so; use the
web UI. To build the app into a binary yourself on any platform:
`cargo build --release --features desktop`.

## Deploying

Away from `127.0.0.1`, two things change:

- **HTTP needs an admin token**, or the server will not start:

  ```
  error: the HTTP listener on 0.0.0.0:8025 is reachable from other machines but
  has no auth token, so anyone who can reach it could read every captured email.
  ```

- **SMTP needs an inbox id and key** from every client. There is no anonymous
  mail, so there is nothing to send until an inbox has a key.

```sh
export EMAILULATOR_AUTH_TOKEN=$(openssl rand -hex 32)                 # admin
export EMAILULATOR_PROVISION=billing-app=$(openssl rand -hex 32)      # inbox=key
docker compose up -d
```

`EMAILULATOR_PROVISION` makes inbox keys valid at startup — `inbox-id=key` pairs
separated by commas, each inbox created if missing and named after its id — so a deployment can hand an
app its key through configuration instead of minting one by hand. Keys can also
be created afterwards in the web UI, signed in with the admin token.

`compose.yaml` runs it as an unprivileged user on a read-only root filesystem
with all capabilities dropped, data on a volume, and both ports published on the
host's loopback. The image is distroless: no shell, no package manager.

To run it without Docker, install it with the one-liner above and start
`emailulator run` under whatever supervises your services, with the same
variables set.

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
| `EMAILULATOR_AUTH_TOKEN` / `_FILE` | none | The admin token (16+ characters) |
| `EMAILULATOR_PROVISION` | none | `inbox=key,…` made valid at startup |
| `EMAILULATOR_TLS_CERT`, `EMAILULATOR_TLS_KEY` | none | PEM files; enables HTTPS and STARTTLS |
| `EMAILULATOR_ALLOW_ANONYMOUS_HTTP` | off | Serve an exposed HTTP listener with no token |
| `EMAILULATOR_ALLOW_ANONYMOUS_SMTP` | off | Accept keyless SMTP on an exposed listener, into `default` |
| `EMAILULATOR_MAX_MESSAGE_SIZE` | `25MB` | Largest message accepted |
| `EMAILULATOR_MAX_MESSAGES` | `1000` | Oldest are dropped beyond this, across all inboxes; `0` keeps all |
| `EMAILULATOR_MAX_STORAGE` | `1GB` | Oldest are dropped beyond this; `0` for no cap |
| `EMAILULATOR_NO_UI` | off | API and MCP only |

Prefer the environment or the `_FILE` variant for secrets: a command-line
argument is visible to every user of the machine in the process list.

## Security model

Captured mail is sensitive — it is where password-reset links go — and email
content is written by whoever sends it. The design assumes both.

**Who gets in**

- A listener on a non-loopback address needs credentials, or an explicit
  `--allow-anonymous-*` flag. There is no silent open mode.
- There are two kinds of credential. The **admin token** reaches every inbox and
  manages inboxes and keys. An **inbox API key** reaches the messages of one
  inbox and nothing else: not other inboxes, not their existence, not key
  management.
- Keys are stored as SHA-256 hashes and shown once. Revoking or regenerating a
  key also ends any browser session opened with it.
- The web UI signs in with either credential and gets a random session id in an
  `HttpOnly; SameSite=Strict` cookie (`Secure` over HTTPS); the credential
  itself is never stored in the browser. Sessions end on sign-out, after seven
  days, or when the server restarts.
- The admin token is compared in constant time. Failed sign-ins and SMTP logins
  are delayed; three bad SMTP logins close the connection. A credential that is
  presented and wrong is refused even on a server that needs none, so a revoked
  key fails loudly.
- With TLS configured, SMTP offers and accepts `AUTH` only after `STARTTLS`
  (clients on the same machine excepted). Anything a client sends in the clear
  after `STARTTLS` drops the connection rather than being read as if it were
  encrypted.
- With no token on a loopback listener, requests must be addressed to
  `localhost` or a loopback IP, which stops a web page from reaching the server
  through DNS rebinding. State-changing requests from another origin are refused.
- The server will not start on a port something else already answers on, rather
  than bind beside it and take its traffic.

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
