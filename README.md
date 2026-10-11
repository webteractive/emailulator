<img src="ui/icon.svg" width="64" height="64" alt="">

# emailulator

Catch the email your application sends in development. Nothing is ever
delivered: every message is stored and shown to you instead.

- **In** over SMTP or an HTTP API.
- **Out** through a web UI, a REST API, an MCP server for agents, and a macOS
  desktop app.
- **One inbox per app**, each with its own API keys.
- **One binary**, SQLite inside, no runtime dependencies.

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

It verifies the download's checksum and installs to `~/.local/bin`
(`EMAILULATOR_INSTALL_DIR` to change it, `EMAILULATOR_VERSION=0.1.0` to pin a
release).

| Platform | What you get |
| --- | --- |
| macOS, Apple silicon | Server and desktop app; Developer ID signed and notarized |
| Linux, x86-64 and arm64 | Server, statically linked |

## Run it

```sh
emailulator run      # SMTP on 127.0.0.1:1025, web UI, API and MCP on http://127.0.0.1:8025
emailulator app      # or the desktop app, on a Mac
```

Point your app at it and mail lands in the `default` inbox. For Laravel:

```dotenv
MAIL_MAILER=smtp
MAIL_HOST=127.0.0.1
MAIL_PORT=1025
```

On this machine it needs no credentials. Mail is kept in the platform data
directory, or in RAM with `--memory`. In the web UI, `j`/`k` move, `s` stars,
`u` marks unread, `#` deletes and `/` searches.

## Inboxes and keys

Give each app its own inbox:

```sh
emailulator inbox create "Billing app"
```

```
Created inbox "Billing app" with the id billing-app.

API key, shown this once:

  emu_3fa9c2d17b0e4c58a1d6f2e9b7c4a03d5e8f1a6b2c9d4e70
```

The **id is the SMTP username and a key is the password**:

```dotenv
MAIL_USERNAME=billing-app
MAIL_PASSWORD=emu_3fa9c2d1…
```

The same key, as `Authorization: Bearer`, reads and sends within that inbox
over the API and MCP, and signs the web UI in to that inbox alone.

- The id never changes, so renaming an inbox breaks nothing.
- An inbox can have several keys: `emailulator key create billing-app`, then
  `key revoke <id>` to rotate without downtime. `key regenerate <id>` replaces a
  value in place.
- Keys are shown once and stored as hashes. The exception is `default`'s
  **starter key**, kept readable so there is one to hand out; regenerate it
  before an app on another machine uses it.
- `inbox` and `key` act on the store on this machine. For a remote server, use
  its web UI or the API with the admin token.

## Sending over HTTP

```sh
curl -X POST http://127.0.0.1:8025/api/v1/messages \
  -H 'Authorization: Bearer emu_3fa9c2d1…' \
  -H 'Content-Type: application/json' \
  -d '{"from": "Shop <shop@example.test>", "to": ["bob@example.test"],
       "subject": "Your order shipped", "text": "Plain body", "html": "<p>Rich body</p>"}'
```

Also accepted: `cc`, `bcc`, `reply_to`, `headers`, and `attachments`
(`[{"filename", "content": "<base64>", "content_type"?}]`). Any other content
type is taken as a raw RFC 5322 message, with `?from=` and `?to=` for the
envelope.

## REST API

A request acts as an **inbox key** (that inbox only) or as the **admin** (the
admin token, or anyone on a local server without one).

| Method and path | Does |
| --- | --- |
| `GET /api/v1/messages` | List, newest first, with filters |
| `POST /api/v1/messages` | Deliver a message |
| `PATCH`, `DELETE /api/v1/messages` | Mark read, or delete, everything the filters select |
| `GET /api/v1/messages/{id}` | Headers, bodies, attachment list |
| `PATCH`, `DELETE /api/v1/messages/{id}` | `{"read", "starred"}`, or delete |
| `GET /api/v1/messages/{id}/raw` · `/html` · `/links` · `/check` | The `.eml`, the sandboxed HTML, its links, the client check |
| `GET /api/v1/messages/{id}/attachments/{index}` | One attachment |
| `GET /api/v1/inboxes` | Inboxes with counts |
| `POST`, `PATCH`, `DELETE /api/v1/inboxes[/{id}]` | *Admin.* Manage inboxes |
| `GET`, `POST /api/v1/inboxes/{id}/keys` | *Admin.* List keys, or create one |
| `POST …/keys/{key_id}/regenerate`, `DELETE …/keys/{key_id}` | *Admin.* Replace or revoke a key |
| `GET /api/v1/events` | Server-sent events as mail arrives and changes |
| `GET /api/v1/info` · `GET /healthz` | Server details · `ok` |

Filters: `inbox` (admin), `to`, `q`, `unread`, `starred`, `before`, `after`,
`since`, `limit`. An unknown filter is an error, so a typo cannot widen a bulk
delete. `q` takes words plus `from:`, `to:`, `subject:`, `is:unread`, `is:read`,
`is:starred`, `has:attachment` and `"quoted phrases"`.

## MCP

Give an agent an inbox's key and it can read the mail its own actions caused:

```sh
claude mcp add --transport http emailulator http://127.0.0.1:8025/mcp \
  --header "Authorization: Bearer emu_3fa9c2d1…"
```

Or over stdio, straight from the store on this machine:
`claude mcp add emailulator -- emailulator mcp --inbox billing-app`.

Tools: `list_messages`, `get_message`, `wait_for_message`, `get_links`,
`check_message`, `get_attachment`, `get_raw_message`, `list_inboxes`,
`mark_message`, `send_message`, `delete_messages`. `wait_for_message` is for
tests: trigger a sign-up, then wait for the mail by recipient and get its body
and links in one call.

## Client check

The **Check** tab (and `check_message` for agents) lists the HTML and CSS a
message uses and which email clients support it, from
[caniemail.com](https://www.caniemail.com)'s data: about 300 features across 22
clients.

```
Gmail 20 of 24    Outlook 10 of 24    Apple Mail 24 of 24    Yahoo! Mail 17 of 24

Not supported (1)
  border-radius   used 1 time
    Outlook       not supported on Windows, Windows Mail
```

It reads the markup and does not render it, so treat it as a list of things to
look at. It also flags HTML past Gmail's 102 KB clipping point, a missing
plain-text part, images without alt text, and attachments Gmail or Outlook
refuse. Outlook conditional comments are not checked.

## Desktop app

`emailulator app` opens the web UI in a window of its own on macOS, running the
same servers and store as `emailulator run`. If ports 1025 and 8025 are taken it
moves to 1026 and 8026 (then 2525 and 8525) and shows which. It is a local tool:
it does not connect to a remote server.

## Deploying

Away from `127.0.0.1`:

- **HTTP needs an admin token**, or the server refuses to start.
- **SMTP needs an inbox id and key** from every client.

```sh
export EMAILULATOR_AUTH_TOKEN=$(openssl rand -hex 32)              # admin
export EMAILULATOR_PROVISION=billing-app=$(openssl rand -hex 32)   # inbox=key, comma-separated
docker compose up -d
```

`EMAILULATOR_PROVISION` makes inbox keys valid at startup, creating the inboxes,
so an app can get its key from configuration. `compose.yaml` runs a distroless
image as an unprivileged user on a read-only filesystem, with both ports on the
host's loopback. Without Docker, run `emailulator run` under your service
manager with the same variables.

**TLS.** Terminate it at a reverse proxy, or pass `--tls-cert` and `--tls-key`,
which turns on HTTPS and SMTP `STARTTLS` together. A proxy covers HTTP only, so
SMTP from other machines still needs the certificate.

**Behind a proxy on the same machine** (Laravel Forge, for instance) the server
listens on loopback, where no token is required. Set one anyway, with
`EMAILULATOR_REQUIRE_AUTH_TOKEN=1` so it will not start without it: a proxy that
does not pass `Host` through would otherwise expose every captured email.

```sh
EMAILULATOR_REQUIRE_AUTH_TOKEN=1 EMAILULATOR_AUTH_TOKEN_FILE=/home/emailulator/token emailulator run
```

```nginx
location / {
    proxy_pass http://127.0.0.1:8025;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;        # the live event stream
    proxy_read_timeout 1h;
    client_max_body_size 25m;   # the largest message accepted
}
```

### Options

Every flag has an environment variable; `emailulator run --help` lists them.
On/off variables take `1`/`0`, `true`/`false`, `yes`/`no` or `on`/`off`.

| Variable | Default | |
| --- | --- | --- |
| `EMAILULATOR_SMTP_ADDR` | `127.0.0.1:1025` | SMTP listener |
| `EMAILULATOR_HTTP_ADDR` | `127.0.0.1:8025` | Web UI, API and MCP |
| `EMAILULATOR_DATA_DIR` | platform data dir | Where the database lives |
| `EMAILULATOR_MEMORY` | off | Keep messages in memory only |
| `EMAILULATOR_AUTH_TOKEN` / `_FILE` | none | The admin token (16+ characters) |
| `EMAILULATOR_REQUIRE_AUTH_TOKEN` | off | Refuse to start without the admin token, even on loopback |
| `EMAILULATOR_PROVISION` | none | `inbox=key,…` made valid at startup |
| `EMAILULATOR_TLS_CERT`, `EMAILULATOR_TLS_KEY` | none | PEM files; enables HTTPS and STARTTLS |
| `EMAILULATOR_ALLOW_ANONYMOUS_HTTP` | off | Serve an exposed HTTP listener with no token |
| `EMAILULATOR_ALLOW_ANONYMOUS_SMTP` | off | Accept keyless SMTP on an exposed listener, into `default` |
| `EMAILULATOR_MAX_MESSAGE_SIZE` | `25MB` | Largest message accepted |
| `EMAILULATOR_MAX_MESSAGES` | `1000` | Oldest dropped beyond this, across all inboxes; `0` keeps all |
| `EMAILULATOR_MAX_STORAGE` | `1GB` | Oldest dropped beyond this; `0` for no cap |
| `EMAILULATOR_NO_UI` | off | API and MCP only |

Pass secrets through the environment or a `_FILE`, not a flag: arguments are
visible to every user in the process list.

## Security model

Captured mail holds password-reset links, and its content is written by
whoever sends it. The design assumes both.

- **No silent open mode.** An exposed listener needs credentials, or an
  `--allow-anonymous-*` flag that says so.
- **Two credentials.** The admin token reaches everything. An inbox key reaches
  one inbox's messages and nothing else, not even which other inboxes exist.
- **Keys are hashed** and shown once; only the starter key is kept readable.
  Revoking or regenerating a key ends the browser sessions, event streams and
  MCP calls using it, including when done from the command line.
- **Sessions** are a random id in an `HttpOnly; SameSite=Strict` cookie,
  `Secure` over HTTPS; the credential never reaches the browser. They end on
  sign-out, after seven days, or on restart.
- **Guessing is slowed.** The admin token is compared in constant time, failed
  sign-ins are delayed, and three bad SMTP logins close the connection. With
  TLS, SMTP accepts `AUTH` only after `STARTTLS`.
- **Browsers are kept out.** Without a token, only `localhost` names are served,
  which stops DNS rebinding; state-changing requests from other origins are
  refused.
- **Email content is contained.** HTML bodies are sandboxed with no scripts,
  attachments are always downloads, and the UI renders text nodes only under a
  strict CSP. Remote images do load when you open a message, as in a mail
  client.
- **It never relays**, and size, recipients, connections, message count and
  storage are all capped.

The database is created `0600` in a `0700` directory, unencrypted.

## Development

Building from source, tests and releasing: [DEVELOPMENT.md](DEVELOPMENT.md).

## License

[MIT](LICENSE), © Webteractive. The bundled client-support data is
[caniemail.com](https://www.caniemail.com)'s, also MIT
([data/caniemail.LICENSE](data/caniemail.LICENSE)).
