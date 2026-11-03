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

### Updating

`emailulator self-update` installs the latest release when it is newer, after
checking that the release's checksums are signed with the emailulator release
key and that the download matches them; `--check` only reports. On a server,
run it daily from cron as the user that runs the server, with `--restart` so
its supervisor (a Forge daemon, systemd) starts it on the new binary:

```
0 4 * * * /home/emailulator/.local/bin/emailulator self-update --restart
```

A restart signs everyone out of the web UI. Self-update arrived in 0.1.1, so
0.1.0 is updated once by hand, with the install command above.

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

Also accepted: `cc`, `bcc`, `reply_to`, `headers`, `attachments`
(`[{"filename", "content": "<base64>", "content_type"?}]`), and `tags`
(`[{"name", "value"}]` or an object), which the message's
[webhook](#webhooks) events carry. Any other content
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
| `GET /api/v1/messages/{id}/raw` · `/html` · `/links` · `/check` | The `.eml`, the sandboxed HTML, its links, the client and deliverability check |
| `GET /api/v1/messages/{id}/attachments/{index}` | One attachment |
| `POST /api/v1/messages/{id}/events` | Send its inbox's webhooks an event: `{"type", "link"?}` |
| `GET /api/v1/inboxes` | Inboxes with counts |
| `POST`, `PATCH`, `DELETE /api/v1/inboxes[/{id}]` | *Admin.* Manage inboxes |
| `GET`, `POST /api/v1/inboxes/{id}/keys` | *Admin.* List keys, or create one |
| `POST …/keys/{key_id}/regenerate`, `DELETE …/keys/{key_id}` | *Admin.* Replace or revoke a key |
| `GET`, `POST /api/v1/webhooks` | *Admin.* List webhooks, or add one: `{"inbox"?, "endpoint", "events"?, "verify_tls"?}` |
| `GET`, `PATCH`, `DELETE /api/v1/webhooks/{id}` | *Admin.* One webhook; `PATCH` takes `endpoint`, `events`, `enabled`, `verify_tls` |
| `GET /api/v1/deliveries` | The webhook delivery log, newest first; filters `inbox`, `webhook`, `message`, `limit` |
| `POST /api/v1/deliveries/{id}/replay` | Send a delivery again |
| `GET /api/v1/events` | Server-sent events as mail arrives and changes |
| `GET /api/v1/info` · `GET /healthz` | Server details · `ok` |

`{id}` is a message's number or its `em_…` email ID.

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
`mark_message`, `send_message`, `delete_messages`, `simulate_event`,
`list_webhook_deliveries`. `wait_for_message` is for tests: trigger a sign-up,
then wait for the mail by recipient and get its body and links in one call.

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

### Deliverability

Above the clients, the same tab (and the `deliverability` field of the check)
says what the message itself shows of how receivers will treat it, worst first:

- **DKIM**: each signature's tags, and whether its body hash still matches the
  body, for the first five signatures. The signature proper needs the key from
  DNS, which the receiver looks up and this does not.
- **DMARC alignment**: whether a signature, or else the envelope sender, is for
  the From address's domain.
- **One-click unsubscribe**: `List-Unsubscribe` with an `https:` address,
  `List-Unsubscribe-Post`, and both under the DKIM signature, as Gmail and Yahoo
  require of bulk mail.
- **Headers** spam filters score when missing or odd: From, Date, Message-ID,
  Subject.
- **Links**: to this machine or network (a wrong `APP_URL`), to bare IP
  addresses, through shorteners, or whose text names another site.
- **Image-only HTML**.

For a spam score as well, point it at a SpamAssassin `spamd`:

```sh
emailulator run --spamassassin 127.0.0.1:783
```

The score and the rules that matched then appear with the findings. Messages
over 500 KB are not scored, as `spamc` would not score them either. What
SpamAssassin's network tests find depends on how that `spamd` is set up.

## Webhooks

An inbox can post events about its mail to your application, so the handler
that would hear of deliveries and bounces from an email provider can be tested
locally. As mail arrives, each of the inbox's webhooks gets `email.sent` then
`email.delivered`. Mail to a test address has the outcome it names instead,
with or without a `+label`:

| Recipient | Events |
| --- | --- |
| `bounced@emailulator.test` | `email.sent`, `email.bounced` |
| `suppressed@emailulator.test` | `email.suppressed` |
| `complained@emailulator.test` | `email.sent`, `email.delivered`, `email.complained` |

Any other event (`email.opened`, `email.clicked`, `email.failed`,
`email.delivery_delayed`, `email.scheduled` and the rest) is sent on demand
from a message's Webhooks tab, `POST /api/v1/messages/{id}/events`, or the
`simulate_event` MCP tool.

```sh
emailulator webhook add billing-app http://localhost:8000/webhooks/email
emailulator webhook list
emailulator webhook show <id>        # its secret and latest deliveries
emailulator webhook disable <id>     # enable, remove
```

Each event is a JSON body of `{"type", "created_at", "data"}`, where `data`
has the message's `email_id` (`em_…`), `from`, `to`, `subject`, `message_id`
and `tags`, and a `bounce`, `click`, `failed` or `suppressed` block for those
events. It is signed as [Standard Webhooks](https://www.standardwebhooks.com)
describes: `webhook-id`, `webhook-timestamp` and `webhook-signature` headers,
an HMAC-SHA256 with the webhook's `whsec_…` secret, so any Standard Webhooks
library verifies it.

Anything but a 2xx answer is tried again after 5 seconds, 5 minutes,
30 minutes, 2, 5, 10 and 10 hours, then marked failed. The delivery log, in
the web UI and at `GET /api/v1/deliveries`, keeps each answer, and a delivery
can be replayed. An `https` endpoint is checked against the system's trusted
certificates; add the webhook with `--insecure`, or tick *Accept any TLS certificate* in
the web UI, for a self-signed one. A server with an admin token, or one
reachable from other machines, posts only to public addresses unless started
with `--allow-private-webhooks`. A webhook holds at most 1,000 deliveries
waiting to be sent, beyond which the oldest are marked failed, and keeps its
latest 1,000 finished ones in the log.

## Desktop app

`emailulator app` opens the web UI in a window of its own on macOS, running the
same servers and store as `emailulator run`. If ports 1025 and 8025 are taken it
moves to 1026 and 8026 (then 2525 and 8525) and shows which. It is a local tool:
it does not connect to a remote server.

## Keep it running on a Mac

`emailulator service install` runs `emailulator run` as a LaunchAgent: it starts
at login, starts again whenever it stops, and needs nothing left open.
`self-update --restart` brings it back on the new binary. Installing again
replaces the agent, and if the new one cannot start, the old one is started
again. Options for `run` go after `--`:

```sh
emailulator service install -- --max-messages 5000
emailulator service status     # --json for scripts; exits 0 answering, 3 not, 4 not installed
emailulator service uninstall  # messages and the log stay
```

While it runs it is the one server on the Mac: `emailulator app` opens its
window on the agent's web UI instead of starting servers of its own, and
`emailulator run` refuses to start a second one. The agent does not see your
shell's environment, so pass what it needs as options; it will not take
`--auth-token` or `--provision`, whose values would show in the process list
(use `--auth-token-file`). It logs to `~/Library/Logs/emailulator/server.log`.

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
SMTP from other machines still needs the certificate, and a host name of its
own: set `EMAILULATOR_SMTP_HOST` to it so the web UI's connection details point
apps there rather than at the proxied name.

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
| `EMAILULATOR_SMTP_HOST` | the SMTP listener's address | The SMTP host the web UI tells apps to use |
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
| `EMAILULATOR_SPAMASSASSIN` | none | SpamAssassin's `spamd` as `host[:port]`, for a spam score in the check |
| `EMAILULATOR_ALLOW_PRIVATE_WEBHOOKS` | off | Post webhooks to this machine and private networks from a server with a token or an exposed listener |

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
- **Webhooks stay off the local network** unless the server is yours alone:
  with an admin token or an exposed HTTP listener, only public addresses are
  posted to. This machine, private, link-local and other special-purpose
  addresses are refused, including those carried inside NAT64 and 6to4
  addresses, and the address checked is the one connected to. A loopback
  server with no token, or `--allow-private-webhooks`, allows them. Only the
  admin adds webhooks.

The database is created `0600` in a `0700` directory, unencrypted.

## Development

Building from source, tests and releasing: [DEVELOPMENT.md](DEVELOPMENT.md).

## License

[MIT](LICENSE), © Webteractive. The bundled client-support data is
[caniemail.com](https://www.caniemail.com)'s, also MIT
([data/caniemail.LICENSE](data/caniemail.LICENSE)).
