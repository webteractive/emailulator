//! The HTTP side: REST API, live events, the MCP endpoint and the web UI.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::compose::SendRequest;
use crate::mcp::Mcp;
use crate::model::{ListFilter, Source};
use crate::security::Auth;
use crate::store::{Incoming, Store};

const SESSION_COOKIE: &str = "emailulator_session";
const LOGIN_FAILURE_DELAY: Duration = Duration::from_millis(750);

/// Applied to the web UI: everything from this origin, nothing inline.
const UI_CSP: &str = "default-src 'self'; img-src 'self' data:; object-src 'none'; \
    base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// Applied to anything that is data rather than a page.
const DATA_CSP: &str = "default-src 'none'; frame-ancestors 'none'";

/// Applied to email HTML. `sandbox` gives the document an opaque origin, so it
/// cannot reach the API or the session; the absence of `allow-scripts` and of
/// any `script-src` keeps it inert. Links may open a new, unsandboxed tab.
const EMAIL_CSP: &str = "sandbox allow-popups allow-popups-to-escape-sandbox; default-src 'none'; \
    img-src data: http: https:; media-src data: http: https:; font-src data: http: https:; \
    style-src 'unsafe-inline' http: https:; form-action 'none'; frame-ancestors 'self'";

/// Applied to attachments, which are always downloads.
const ATTACHMENT_CSP: &str = "sandbox; default-src 'none'";

#[derive(RustEmbed)]
#[folder = "ui/"]
struct Assets;

/// What a client may know about the server it is talking to.
#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub smtp_port: u16,
    pub smtp_starttls: bool,
    pub smtp_auth_required: bool,
    pub http_tls: bool,
    pub auth_required: bool,
    pub max_message_size: usize,
    pub max_messages: usize,
}

pub struct HttpConfig {
    pub auth: Option<Arc<Auth>>,
    pub info: ServerInfo,
    /// Serve the web UI. The API and MCP endpoint are served either way.
    pub ui: bool,
    /// The listener is reachable from this machine only.
    pub loopback: bool,
}

struct AppState {
    store: Arc<Store>,
    mcp: Mcp,
    config: HttpConfig,
}

type Shared = Arc<AppState>;

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn not_found(what: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::NOT_FOUND, format!("{what} not found"))
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        // The cause goes to the log, not to the caller.
        tracing::error!(%error, "request failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

type ApiResult<T> = Result<T, ApiError>;

/// Run a store operation off the async threads.
async fn store<T, F>(state: &Shared, f: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Store) -> anyhow::Result<T> + Send + 'static,
{
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || f(&store))
        .await
        .map_err(|e| ApiError::from(anyhow::Error::from(e)))?
        .map_err(ApiError::from)
}

pub fn router(store: Arc<Store>, config: HttpConfig) -> Router {
    let max_message_size = config.info.max_message_size;
    let state: Shared = Arc::new(AppState {
        mcp: Mcp::new(store.clone(), max_message_size),
        store,
        config,
    });

    let mut router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/api/v1/session",
            get(session_status).post(session_open).delete(session_close),
        )
        .route("/api/v1/info", get(info))
        .route("/api/v1/mailboxes", get(mailboxes))
        .route("/api/v1/events", get(events))
        .route(
            "/api/v1/messages",
            get(list_messages)
                .post(send_message)
                .patch(update_messages)
                .delete(delete_messages),
        )
        .route(
            "/api/v1/messages/{id}",
            get(get_message)
                .patch(update_message)
                .delete(delete_message),
        )
        .route("/api/v1/messages/{id}/raw", get(message_raw))
        .route("/api/v1/messages/{id}/html", get(message_html))
        .route("/api/v1/messages/{id}/links", get(message_links))
        .route(
            "/api/v1/messages/{id}/attachments/{index}",
            get(message_attachment),
        )
        .route("/mcp", post(mcp));

    if state.config.ui {
        router = router.fallback(ui);
    }

    router
        // A JSON send carries attachments as base64, a third larger than the
        // bytes it encodes; leave room for that on top of the message limit.
        .layer(DefaultBodyLimit::max(max_message_size / 2 * 3 + 64 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Access control and response hardening
// ---------------------------------------------------------------------------

fn header_str(headers: &HeaderMap, name: impl header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    header_str(headers, header::COOKIE)?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(name, value)| (name == SESSION_COOKIE).then_some(value))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = header_str(headers, header::AUTHORIZATION)?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
}

fn authenticated(auth: &Auth, headers: &HeaderMap) -> bool {
    bearer_token(headers).is_some_and(|token| auth.token_matches(token))
        || session_cookie(headers).is_some_and(|id| auth.session_valid(id))
}

/// The host of a `Host` header or an origin's authority, without the port.
fn hostname(authority: &str) -> &str {
    match authority.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host),
    }
}

fn is_local_name(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Whether a request's `Origin` names this server. Behind a reverse proxy the
/// `Host` header may have been rewritten to the upstream's name, so the host
/// the proxy says the browser asked for counts too. A page on another site
/// cannot forge that header: adding it makes the request one that needs a CORS
/// preflight, which this server never grants.
fn same_origin(origin: &str, headers: &HeaderMap) -> bool {
    let Some((_, authority)) = origin.split_once("://") else {
        // `null`, as sent by sandboxed frames and local files.
        return false;
    };
    [
        header_str(headers, header::HOST),
        header_str(headers, "x-forwarded-host"),
    ]
    .into_iter()
    .flatten()
    .any(|host| host.eq_ignore_ascii_case(authority))
}

fn is_https(state: &AppState, headers: &HeaderMap) -> bool {
    state.config.info.http_tls
        || header_str(headers, "x-forwarded-proto").is_some_and(|p| p.eq_ignore_ascii_case("https"))
}

fn forbidden(message: &str) -> Response {
    ApiError::new(StatusCode::FORBIDDEN, message).into_response()
}

async fn guard(State(state): State<Shared>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let path = request.uri().path().to_string();
    let host = header_str(headers, header::HOST).unwrap_or_default();

    // With no token and a loopback listener, the only thing keeping a web page
    // out is the same-origin policy, and DNS rebinding walks around that by
    // pointing its own hostname at 127.0.0.1. Such a request still carries the
    // page's hostname, so only names that mean "this machine" are served.
    let https = is_https(&state, headers);
    let mut response =
        if state.config.auth.is_none() && state.config.loopback && !is_local_name(hostname(host)) {
            forbidden(
                "this server has no auth token, so it only answers to localhost; \
             set an auth token to reach it by another name",
            )
        } else if !matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        ) && header_str(headers, header::ORIGIN)
            .is_some_and(|origin| !same_origin(origin, headers))
        {
            // A state-changing request a browser sent on behalf of another site.
            forbidden("cross-origin request refused")
        } else if (path.starts_with("/api/") || path == "/mcp")
            && path != "/api/v1/session"
            && state
                .config
                .auth
                .as_ref()
                .is_some_and(|auth| !authenticated(auth, headers))
        {
            let mut response =
                ApiError::new(StatusCode::UNAUTHORIZED, "authentication required").into_response();
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            response
        } else {
            next.run(request).await
        };

    let headers = response.headers_mut();
    let mut default = |name: HeaderName, value: &'static str| {
        headers
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    };
    default(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    default(header::REFERRER_POLICY, "no-referrer");
    default(header::X_FRAME_OPTIONS, "DENY");
    default(header::CONTENT_SECURITY_POLICY, DATA_CSP);
    default(
        HeaderName::from_static("cross-origin-resource-policy"),
        "same-origin",
    );
    // Captured mail is someone's reset link; keep it out of shared caches.
    default(header::CACHE_CONTROL, "no-store");
    if https {
        default(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000");
    }
    response
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

async fn session_status(State(state): State<Shared>, headers: HeaderMap) -> Json<Value> {
    let required = state.config.auth.is_some();
    let authenticated = state
        .config
        .auth
        .as_ref()
        .is_none_or(|auth| authenticated(auth, &headers));
    Json(json!({"auth_required": required, "authenticated": authenticated}))
}

#[derive(Deserialize)]
struct Login {
    token: String,
}

fn cookie(value: &str, max_age: u64, secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"
    );
    HeaderValue::from_str(&cookie).expect("session ids are ASCII")
}

async fn session_open(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(login): Json<Login>,
) -> ApiResult<Response> {
    let Some(auth) = &state.config.auth else {
        return Ok(Json(json!({"authenticated": true})).into_response());
    };
    if !auth.token_matches(login.token.trim()) {
        tracing::warn!("web UI sign-in failed");
        tokio::time::sleep(LOGIN_FAILURE_DELAY).await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "that token is not right",
        ));
    }
    let id = auth.open_session();
    let mut response = Json(json!({"authenticated": true})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie(
            &id,
            auth.session_ttl().as_secs(),
            is_https(&state, &headers),
        ),
    );
    Ok(response)
}

async fn session_close(State(state): State<Shared>, headers: HeaderMap) -> Response {
    if let (Some(auth), Some(id)) = (&state.config.auth, session_cookie(&headers)) {
        auth.close_session(id);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie("", 0, is_https(&state, &headers)),
    );
    response
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

async fn info(State(state): State<Shared>) -> ApiResult<Json<Value>> {
    let stats = store(&state, |s| s.stats()).await?;
    let mut info = serde_json::to_value(&state.config.info).map_err(anyhow::Error::from)?;
    info["stats"] = json!(stats);
    Ok(Json(info))
}

async fn mailboxes(State(state): State<Shared>) -> ApiResult<Json<Value>> {
    let mailboxes = store(&state, |s| s.mailboxes()).await?;
    let stats = store(&state, |s| s.stats()).await?;
    Ok(Json(json!({"mailboxes": mailboxes, "stats": stats})))
}

#[derive(Deserialize)]
struct ListQuery {
    mailbox: Option<String>,
    q: Option<String>,
    unread: Option<bool>,
    starred: Option<bool>,
    before: Option<i64>,
    after: Option<i64>,
    since: Option<i64>,
    limit: Option<usize>,
}

async fn list_messages(
    State(state): State<Shared>,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let filter = ListFilter {
        mailbox: query.mailbox,
        query: query.q,
        unread: query.unread,
        starred: query.starred,
        before_id: query.before,
        after_id: query.after,
        since: query.since,
        limit: query.limit,
    };
    let page = store(&state, move |s| s.list(&filter)).await?;
    Ok(Json(json!(page)))
}

#[derive(Deserialize)]
struct RawEnvelope {
    from: Option<String>,
    /// Comma-separated envelope recipients.
    to: Option<String>,
}

async fn send_message(
    State(state): State<Shared>,
    Query(envelope): Query<RawEnvelope>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let is_json = header_str(&headers, header::CONTENT_TYPE)
        .is_some_and(|t| t.to_ascii_lowercase().starts_with("application/json"));

    let incoming = if is_json {
        let request: SendRequest = serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request(format!("invalid message: {e}")))?;
        request
            .build()
            .map_err(|e| ApiError::bad_request(e.to_string()))?
    } else {
        // Anything else is taken as a complete RFC 5322 message.
        if body.is_empty() {
            return Err(ApiError::bad_request(
                "send JSON with Content-Type: application/json, or a raw RFC 5322 message",
            ));
        }
        Incoming {
            raw: body.to_vec(),
            envelope_from: envelope.from,
            envelope_to: envelope
                .to
                .map(|to| {
                    to.split(',')
                        .map(|a| a.trim().to_string())
                        .filter(|a| !a.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            source: Source::Api,
        }
    };

    if incoming.raw.len() > state.config.info.max_message_size {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "the message exceeds the {} byte limit",
                state.config.info.max_message_size
            ),
        ));
    }

    let summary = store(&state, move |s| s.insert(incoming)).await?;
    tracing::info!(
        id = summary.id,
        recipients = summary.mailboxes.len(),
        size = summary.size,
        "message received over the API"
    );
    Ok((StatusCode::CREATED, Json(summary)).into_response())
}

#[derive(Deserialize)]
struct MailboxQuery {
    mailbox: Option<String>,
}

#[derive(Deserialize)]
struct Flags {
    read: Option<bool>,
    starred: Option<bool>,
}

async fn update_messages(
    State(state): State<Shared>,
    Query(query): Query<MailboxQuery>,
    Json(flags): Json<Flags>,
) -> ApiResult<Json<Value>> {
    if flags.read != Some(true) || flags.starred.is_some() {
        return Err(ApiError::bad_request(
            "the only bulk update is {\"read\": true}; flag single messages by id",
        ));
    }
    let updated = store(&state, move |s| s.mark_all_read(query.mailbox.as_deref())).await?;
    Ok(Json(json!({"updated": updated})))
}

async fn delete_messages(
    State(state): State<Shared>,
    Query(query): Query<MailboxQuery>,
) -> ApiResult<Json<Value>> {
    let deleted = store(&state, move |s| s.clear(query.mailbox.as_deref())).await?;
    Ok(Json(json!({"deleted": deleted})))
}

async fn get_message(State(state): State<Shared>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let detail = store(&state, move |s| s.get(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format_args!("message {id}")))?;
    Ok(Json(json!(detail)))
}

async fn update_message(
    State(state): State<Shared>,
    Path(id): Path<i64>,
    Json(flags): Json<Flags>,
) -> ApiResult<Json<Value>> {
    if flags.read.is_none() && flags.starred.is_none() {
        return Err(ApiError::bad_request("give `read`, `starred`, or both"));
    }
    let summary = store(&state, move |s| {
        s.set_flags(id, flags.read, flags.starred)?;
        s.summary(id)
    })
    .await?
    .ok_or_else(|| ApiError::not_found(format_args!("message {id}")))?;
    Ok(Json(json!(summary)))
}

async fn delete_message(State(state): State<Shared>, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    if store(&state, move |s| s.delete(id)).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format_args!("message {id}")))
    }
}

/// A `Content-Disposition: attachment` value for an untrusted filename.
fn attachment_disposition(filename: &str) -> HeaderValue {
    let ascii: String = filename
        .chars()
        .map(|c| match c {
            c if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ' | '(' | ')') => c,
            _ => '_',
        })
        .collect();
    let ascii = ascii.trim_matches([' ', '.']);
    let ascii = if ascii.is_empty() {
        "attachment"
    } else {
        ascii
    };
    let mut encoded = String::new();
    for byte in filename.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    HeaderValue::from_str(&format!(
        "attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}"
    ))
    .unwrap_or(HeaderValue::from_static("attachment"))
}

async fn message_raw(State(state): State<Shared>, Path(id): Path<i64>) -> ApiResult<Response> {
    let raw = store(&state, move |s| s.raw(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format_args!("message {id}")))?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("message/rfc822"),
            ),
            (
                header::CONTENT_DISPOSITION,
                attachment_disposition(&format!("message-{id}.eml")),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(ATTACHMENT_CSP),
            ),
        ],
        raw,
    )
        .into_response())
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

async fn message_html(State(state): State<Shared>, Path(id): Path<i64>) -> ApiResult<Response> {
    let html = match store(&state, move |s| s.rendered_html(id)).await? {
        Some(html) => html,
        // No HTML part: show the text the way a mail client would.
        None => {
            let detail = store(&state, move |s| s.get(id))
                .await?
                .ok_or_else(|| ApiError::not_found(format_args!("message {id}")))?;
            format!(
                "<pre style=\"white-space:pre-wrap;font:14px/1.5 ui-monospace,monospace\">{}</pre>",
                escape_html(detail.text.as_deref().unwrap_or_default())
            )
        }
    };
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(EMAIL_CSP),
            ),
            (
                header::X_FRAME_OPTIONS,
                HeaderValue::from_static("SAMEORIGIN"),
            ),
        ],
        html,
    )
        .into_response())
}

async fn message_links(State(state): State<Shared>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let links = store(&state, move |s| s.links(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format_args!("message {id}")))?;
    Ok(Json(json!({"links": links})))
}

async fn message_attachment(
    State(state): State<Shared>,
    Path((id, index)): Path<(i64, usize)>,
) -> ApiResult<Response> {
    let (meta, bytes) = store(&state, move |s| s.attachment(id, index))
        .await?
        .ok_or_else(|| ApiError::not_found(format_args!("attachment {index} of message {id}")))?;
    let content_type = HeaderValue::from_str(&meta.content_type)
        .unwrap_or(HeaderValue::from_static("application/octet-stream"));
    let filename = meta
        .filename
        .unwrap_or_else(|| format!("attachment-{index}"));
    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            // Always a download, and sandboxed besides: an HTML or SVG
            // attachment must never run as a page of this origin.
            (
                header::CONTENT_DISPOSITION,
                attachment_disposition(&filename),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(ATTACHMENT_CSP),
            ),
        ],
        bytes,
    )
        .into_response())
}

async fn events(
    State(state): State<Shared>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let stream = BroadcastStream::new(state.store.subscribe()).map(|event| {
        Ok(match event {
            Ok(event) => SseEvent::default().json_data(&event).unwrap_or_default(),
            // The viewer fell behind and missed events; tell it to reload.
            Err(_) => SseEvent::default().data(r#"{"type":"resync"}"#),
        })
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn mcp(State(state): State<Shared>, body: Bytes) -> Response {
    let message: Value = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(error) => {
            let reply = json!({"jsonrpc": "2.0", "id": null,
                               "error": {"code": -32700, "message": format!("parse error: {error}")}});
            return (StatusCode::BAD_REQUEST, Json(reply)).into_response();
        }
    };
    match state.mcp.handle(message).await {
        Some(reply) => Json(reply).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Web UI
// ---------------------------------------------------------------------------

async fn ui(request: Request) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = request.uri().path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    let Some(asset) = Assets::get(path) else {
        return ApiError::not_found("page").into_response();
    };
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime.as_ref())
                    .unwrap_or(HeaderValue::from_static("application/octet-stream")),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(UI_CSP),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        ],
        Body::from(asset.data.into_owned()),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Serving
// ---------------------------------------------------------------------------

/// Accepts TCP connections and completes their TLS handshakes off the accept
/// path, so one stalled handshake cannot hold up the rest.
pub struct TlsListener {
    local_addr: SocketAddr,
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
}

impl TlsListener {
    pub fn new(listener: TcpListener, acceptor: TlsAcceptor) -> std::io::Result<Self> {
        let local_addr = listener.local_addr()?;
        let (sender, ready) = mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(%error, "HTTPS accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let sender = sender.clone();
                tokio::spawn(async move {
                    let handshake =
                        tokio::time::timeout(Duration::from_secs(15), acceptor.accept(stream));
                    if let Ok(Ok(stream)) = handshake.await {
                        let _ = sender.send((stream, peer)).await;
                    }
                });
            }
        });
        Ok(Self { local_addr, ready })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(accepted) => accepted,
            // The accept task only ends with the runtime.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

pub async fn serve(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    router: Router,
) -> anyhow::Result<()> {
    match tls {
        Some(acceptor) => axum::serve(TlsListener::new(listener, acceptor)?, router).await?,
        None => axum::serve(listener, router).await?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames_are_read_from_authorities() {
        assert_eq!(hostname("localhost:8025"), "localhost");
        assert_eq!(hostname("127.0.0.1"), "127.0.0.1");
        assert_eq!(hostname("[::1]:8025"), "::1");
        assert_eq!(hostname("mail.example.com:443"), "mail.example.com");
    }

    #[test]
    fn only_this_machine_counts_as_local() {
        for local in [
            "localhost",
            "LOCALHOST",
            "app.localhost",
            "127.0.0.1",
            "::1",
        ] {
            assert!(is_local_name(local), "{local}");
        }
        for remote in [
            "example.com",
            "localhost.example.com",
            "10.0.0.5",
            "0.0.0.0",
        ] {
            assert!(!is_local_name(remote), "{remote}");
        }
    }

    #[test]
    fn dispositions_neutralize_hostile_filenames() {
        let value = attachment_disposition("a\"b\r\nX: y/../é.pdf");
        let value = value.to_str().unwrap();
        assert!(
            value.starts_with("attachment; filename=\"a_b__X_ y_.._"),
            "{value}"
        );
        assert!(!value.contains('\r') && !value.contains('\n'));
        assert!(
            value.contains("filename*=UTF-8''a%22b%0D%0AX%3A%20y%2F..%2F%C3%A9.pdf"),
            "{value}"
        );
    }

    use axum::body::to_bytes;
    use tower::ServiceExt;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn app(token: Option<&str>, loopback: bool) -> (Router, Arc<Store>) {
        let store = Arc::new(Store::in_memory().unwrap());
        let config = HttpConfig {
            auth: token.map(|t| Arc::new(Auth::new(t.to_string()).unwrap())),
            info: ServerInfo {
                name: "emailulator",
                version: "test",
                smtp_port: 1025,
                smtp_starttls: false,
                smtp_auth_required: false,
                http_tls: false,
                auth_required: token.is_some(),
                max_message_size: 4096,
                max_messages: 100,
            },
            ui: true,
            loopback,
        };
        (router(store.clone(), config), store)
    }

    fn app_with_token_on_loopback() -> (Router, Arc<Store>) {
        app(Some(TOKEN), true)
    }

    fn request(method: &str, uri: &str) -> axum::http::request::Builder {
        axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "localhost:8025")
    }

    async fn send(
        app: &Router,
        request: axum::http::Request<Body>,
    ) -> (StatusCode, HeaderMap, String) {
        let response = app.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        (
            parts.status,
            parts.headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    fn json_body(value: Value) -> Body {
        Body::from(serde_json::to_vec(&value).unwrap())
    }

    async fn seed(app: &Router, token: Option<&str>) -> i64 {
        let mut builder =
            request("POST", "/api/v1/messages").header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let body = json_body(json!({
            "from": "app@x.test", "to": "bob@x.test", "subject": "Hello",
            "html": "<p>Hi<script>alert(1)</script></p>",
            "attachments": [{"filename": "evil.html", "content": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}],
        }));
        let (status, _, body) = send(app, builder.body(body).unwrap()).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        serde_json::from_str::<Value>(&body).unwrap()["id"]
            .as_i64()
            .unwrap()
    }

    #[tokio::test]
    async fn api_round_trip_without_auth() {
        let (app, _) = app(None, true);
        let id = seed(&app, None).await;

        let (status, _, body) = send(
            &app,
            request("GET", "/api/v1/messages?mailbox=bob@x.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(page["total"], 1);
        assert_eq!(page["messages"][0]["subject"], "Hello");

        let patch = request("PATCH", &format!("/api/v1/messages/{id}"))
            .header("content-type", "application/json")
            .body(json_body(json!({"read": true, "starred": true})))
            .unwrap();
        let (status, _, body) = send(&app, patch).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"starred\":true"), "{body}");

        let (status, _, _) = send(
            &app,
            request("DELETE", &format!("/api/v1/messages/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _, _) = send(
            &app,
            request("GET", &format!("/api/v1/messages/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn accepts_a_raw_message_with_an_envelope() {
        let (app, store) = app(None, true);
        let raw = "From: a@x.test\r\nTo: shown@x.test\r\nSubject: Raw\r\n\r\nbody\r\n";
        let post = request(
            "POST",
            "/api/v1/messages?from=bounce@x.test&to=one@x.test,two@x.test",
        )
        .header("content-type", "message/rfc822")
        .body(Body::from(raw))
        .unwrap();
        let (status, _, body) = send(&app, post).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let detail = store.get(1).unwrap().unwrap();
        assert_eq!(detail.summary.mailboxes, vec!["one@x.test", "two@x.test"]);
        assert_eq!(detail.envelope_from.as_deref(), Some("bounce@x.test"));

        let big = request("POST", "/api/v1/messages")
            .header("content-type", "message/rfc822")
            .body(Body::from(vec![b'x'; 5000]))
            .unwrap();
        assert_eq!(send(&app, big).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn a_token_gates_the_api_and_mcp_but_not_the_shell() {
        let (app, _) = app(Some(TOKEN), false);

        for path in [
            "/api/v1/messages",
            "/api/v1/info",
            "/api/v1/events",
            "/api/v1/messages/1/raw",
        ] {
            let (status, headers, _) =
                send(&app, request("GET", path).body(Body::empty()).unwrap()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(headers["www-authenticate"], "Bearer");
        }
        let mcp = request("POST", "/mcp").body(Body::from("{}")).unwrap();
        assert_eq!(send(&app, mcp).await.0, StatusCode::UNAUTHORIZED);

        let wrong = request("GET", "/api/v1/messages")
            .header("authorization", "Bearer nope")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&app, wrong).await.0, StatusCode::UNAUTHORIZED);

        let right = request("GET", "/api/v1/messages")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&app, right).await.0, StatusCode::OK);

        // The static shell and the health probe carry no mail.
        assert_eq!(
            send(&app, request("GET", "/").body(Body::empty()).unwrap())
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            send(
                &app,
                request("GET", "/healthz").body(Body::empty()).unwrap()
            )
            .await
            .0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn the_ui_signs_in_with_a_cookie_and_out_again() {
        let (app, _) = app(Some(TOKEN), false);
        let login = |token: &str| {
            request("POST", "/api/v1/session")
                .header("content-type", "application/json")
                .body(json_body(json!({"token": token})))
                .unwrap()
        };

        let (status, headers, _) = send(&app, login(TOKEN)).await;
        assert_eq!(status, StatusCode::OK);
        let set_cookie = headers["set-cookie"].to_str().unwrap().to_string();
        assert!(
            set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"),
            "{set_cookie}"
        );
        assert!(
            !set_cookie.contains(TOKEN),
            "the cookie is a session id, not the token"
        );
        let cookie = set_cookie.split(';').next().unwrap().to_string();

        let with_cookie = |method: &str, path: &str| {
            request(method, path)
                .header("cookie", cookie.clone())
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            send(&app, with_cookie("GET", "/api/v1/messages")).await.0,
            StatusCode::OK
        );
        let (_, _, status_body) = send(&app, with_cookie("GET", "/api/v1/session")).await;
        assert!(status_body.contains("\"authenticated\":true"));

        assert_eq!(
            send(&app, with_cookie("DELETE", "/api/v1/session")).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            send(&app, with_cookie("GET", "/api/v1/messages")).await.0,
            StatusCode::UNAUTHORIZED
        );

        let secure = request("POST", "/api/v1/session")
            .header("content-type", "application/json")
            .header("x-forwarded-proto", "https")
            .body(json_body(json!({"token": TOKEN})))
            .unwrap();
        let (_, headers, _) = send(&app, secure).await;
        assert!(headers["set-cookie"].to_str().unwrap().contains("; Secure"));
        assert!(headers.contains_key("strict-transport-security"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_wrong_token_does_not_sign_in() {
        let (app, _) = app(Some(TOKEN), false);
        let login = request("POST", "/api/v1/session")
            .header("content-type", "application/json")
            .body(json_body(json!({"token": "guess"})))
            .unwrap();
        let (status, headers, _) = send(&app, login).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!headers.contains_key("set-cookie"));
    }

    #[tokio::test]
    async fn an_unauthenticated_loopback_server_answers_only_to_local_names() {
        let (app, _) = app(None, true);
        let rebound = axum::http::Request::builder()
            .uri("/api/v1/messages")
            .header("host", "attacker.example:8025")
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, rebound).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("only answers to localhost"), "{body}");

        // With a token, the token is the gate and any hostname may be used.
        let (with_token, _) = app_with_token_on_loopback();
        let named = axum::http::Request::builder()
            .uri("/api/v1/messages")
            .header("host", "mail.example.com")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&with_token, named).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn cross_origin_writes_are_refused() {
        let (app, store) = app(None, true);
        let forged = request("DELETE", "/api/v1/messages")
            .header("origin", "https://evil.example")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&app, forged).await.0, StatusCode::FORBIDDEN);

        let forged_post = request("POST", "/api/v1/messages")
            .header("origin", "http://evil.example")
            .header("content-type", "text/plain")
            .body(Body::from("Subject: spam\r\n\r\nx"))
            .unwrap();
        assert_eq!(send(&app, forged_post).await.0, StatusCode::FORBIDDEN);
        assert_eq!(store.stats().unwrap().total, 0);

        let own = request("DELETE", "/api/v1/messages")
            .header("origin", "http://localhost:8025")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&app, own).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn sandboxed_and_proxied_origins_are_told_apart() {
        let (open, _) = app(None, true);
        let sandboxed = request("DELETE", "/api/v1/messages")
            .header("origin", "null")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&open, sandboxed).await.0, StatusCode::FORBIDDEN);

        // A proxy that rewrites Host must not lock the UI out of its own API.
        let (app, _) = app(Some(TOKEN), false);
        let proxied = |forwarded: &str| {
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/api/v1/messages")
                .header("host", "emailulator:8025")
                .header("x-forwarded-host", forwarded)
                .header("origin", "https://mail.example.com")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            send(&app, proxied("mail.example.com")).await.0,
            StatusCode::OK
        );
        assert_eq!(
            send(&app, proxied("other.example.com")).await.0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn email_content_is_served_inert() {
        let (app, _) = app(None, true);
        let id = seed(&app, None).await;

        let (status, headers, body) = send(
            &app,
            request("GET", &format!("/api/v1/messages/{id}/html"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.starts_with("sandbox allow-popups"), "{csp}");
        assert!(
            !csp.contains("allow-scripts") && !csp.contains("allow-same-origin"),
            "{csp}"
        );
        assert!(
            csp.contains("default-src 'none'") && !csp.contains("script-src"),
            "{csp}"
        );
        assert!(
            body.contains("<script>"),
            "the source is untouched; the policy is what disarms it"
        );

        let (status, headers, _) = send(
            &app,
            request("GET", &format!("/api/v1/messages/{id}/attachments/0"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            headers["content-disposition"]
                .to_str()
                .unwrap()
                .starts_with("attachment;")
        );
        assert_eq!(headers["content-security-policy"], ATTACHMENT_CSP);
        assert_eq!(headers["x-content-type-options"], "nosniff");

        let (_, headers, _) = send(
            &app,
            request("GET", &format!("/api/v1/messages/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(headers["content-security-policy"], DATA_CSP);
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["referrer-policy"], "no-referrer");
    }

    #[tokio::test]
    async fn mcp_speaks_json_rpc_over_post() {
        let (app, _) = app(None, true);
        seed(&app, None).await;
        let call = request("POST", "/mcp")
            .header("content-type", "application/json")
            .body(json_body(
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": "list_mailboxes", "arguments": {}}}),
            ))
            .unwrap();
        let (status, _, body) = send(&app, call).await;
        assert_eq!(status, StatusCode::OK);
        let reply: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            reply["result"]["structuredContent"]["mailboxes"][0]["address"],
            "bob@x.test"
        );

        let note = request("POST", "/mcp")
            .body(json_body(
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            ))
            .unwrap();
        assert_eq!(send(&app, note).await.0, StatusCode::ACCEPTED);
        assert_eq!(
            send(&app, request("GET", "/mcp").body(Body::empty()).unwrap())
                .await
                .0,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
}
