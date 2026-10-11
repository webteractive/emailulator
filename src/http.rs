//! The HTTP side: REST API, live events, the MCP endpoint and the web UI.
//!
//! Every request is resolved to an [`Access`] before it reaches a handler: the
//! admin token opens everything, an inbox's API key opens that inbox alone.

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
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::ReceiverStream;

use crate::compose::SendRequest;
use crate::mcp::{Liveness, Mcp};
use crate::model::{Event, ListFilter, Source};
use crate::security::{Access, Auth, Credential, InboxKey, Session, hash_api_key};
use crate::store::{DEFAULT_INBOX, InboxError, Incoming, Store};

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
    /// Whether SMTP clients must authenticate with an inbox id and API key.
    pub smtp_auth_required: bool,
    pub http_tls: bool,
    pub auth_required: bool,
    pub max_message_size: usize,
    pub max_messages: usize,
}

pub struct HttpConfig {
    pub auth: Arc<Auth>,
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

    fn admin_only() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "this needs the admin token; an inbox API key reaches only its own inbox's messages",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        // A refused inbox operation is the caller's to fix, and says how.
        if let Some(refused) = error.downcast_ref::<InboxError>() {
            let status = match refused {
                InboxError::InvalidId(_) | InboxError::InvalidName | InboxError::WeakKey => {
                    StatusCode::BAD_REQUEST
                }
                InboxError::Exists(_) | InboxError::Protected => StatusCode::CONFLICT,
                InboxError::NotFound(_) => StatusCode::NOT_FOUND,
            };
            return Self::new(status, refused.to_string());
        }
        // Anything else is ours; the cause goes to the log, not to the caller.
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
        .route("/api/v1/inboxes", get(list_inboxes).post(create_inbox))
        .route(
            "/api/v1/inboxes/{inbox}",
            get(get_inbox).patch(update_inbox).delete(delete_inbox),
        )
        .route(
            "/api/v1/inboxes/{inbox}/keys",
            get(list_keys).post(create_key),
        )
        .route("/api/v1/inboxes/{inbox}/keys/{key}", delete(revoke_key))
        .route(
            "/api/v1/inboxes/{inbox}/keys/{key}/regenerate",
            post(regenerate_key),
        )
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
        .route("/api/v1/messages/{id}/check", get(message_check))
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

/// What a secret opens: the admin token everything, an inbox's key that inbox.
async fn access_for_secret(state: &Shared, secret: &str) -> ApiResult<Option<Access>> {
    if state.config.auth.is_admin_token(secret) {
        return Ok(Some(Access::Admin));
    }
    let secret = secret.to_string();
    let inbox = store(state, move |s| s.inbox_for_key(&secret)).await?;
    Ok(inbox.map(Access::Inbox))
}

/// What a request or session keeps of the inbox key that opened it, so it can
/// be checked again later: its hash, never the key. `None` for the admin.
fn inbox_key(access: &Access, secret: &str) -> Option<InboxKey> {
    access.inbox().map(|inbox| InboxKey {
        inbox: inbox.to_string(),
        hash: hash_api_key(secret),
    })
}

/// Who is asking, and how they showed it. `None` means nobody the server
/// recognizes. The credential is kept beside the access it grants, so a
/// request that outlives its own authorization can check it again.
async fn resolve(state: &Shared, headers: &HeaderMap) -> ApiResult<Option<(Access, Credential)>> {
    // A credential that was presented and is wrong is refused even where none
    // is needed: falling back to open access would hide a revoked key.
    if let Some(token) = bearer_token(headers) {
        let access = access_for_secret(state, token).await?;
        return Ok(access.map(|access| {
            let credential =
                inbox_key(&access, token).map_or(Credential::Standing, Credential::Key);
            (access, credential)
        }));
    }
    if let Some(id) = session_cookie(headers)
        && let Some(session) = state.config.auth.session(id)
    {
        // A session outlives the request that opened it, so check that the key
        // it was opened with still opens its inbox. That also ends it when the
        // key was revoked or regenerated from the command line, or the inbox
        // was deleted and made again under the same id. A session whose key is
        // gone is refused, not let through as open access: on a server that
        // asks for nothing, that would turn an inbox's viewer into an admin.
        if session_holds(state, &session).await? {
            return Ok(Some((
                session.access(),
                Credential::Session(id.to_string()),
            )));
        }
        state.config.auth.close_session(id);
        return Ok(None);
    }
    // A cookie for a session that has ended, as after a restart, is no
    // credential at all.
    Ok((!state.config.auth.required()).then_some((Access::Admin, Credential::Standing)))
}

async fn key_holds(state: &Shared, key: &InboxKey) -> ApiResult<bool> {
    let InboxKey { inbox, hash } = key.clone();
    store(state, move |s| s.key_hash_opens(&hash, &inbox)).await
}

async fn session_holds(state: &Shared, session: &Session) -> ApiResult<bool> {
    match session {
        Session::Admin => Ok(true),
        Session::Inbox(key) => key_holds(state, key).await,
    }
}

/// Whether a long-lived request's caller still may: `None` when the store
/// could not say, as when another process holds a write lock past the busy
/// timeout. What to do about not knowing is the caller's to decide.
async fn credential_holds(state: &Shared, credential: &Credential) -> Option<bool> {
    let holds = match credential {
        Credential::Standing => Ok(true),
        Credential::Key(key) => key_holds(state, key).await,
        Credential::Session(id) => match state.config.auth.session(id) {
            Some(session) => session_holds(state, &session).await,
            None => Ok(false),
        },
    };
    match holds {
        Ok(holds) => Some(holds),
        Err(error) => {
            tracing::warn!(error = %error.message, "could not check a credential");
            None
        }
    }
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

async fn guard(State(state): State<Shared>, mut request: Request, next: Next) -> Response {
    let headers = request.headers();
    let path = request.uri().path().to_string();
    let host = header_str(headers, header::HOST).unwrap_or_default();
    let https = is_https(&state, headers);
    let protected = (path.starts_with("/api/") || path == "/mcp") && path != "/api/v1/session";

    // With no admin token and a loopback listener, the only thing keeping a web
    // page out is the same-origin policy, and DNS rebinding walks around that
    // by pointing its own hostname at 127.0.0.1. Such a request still carries
    // the page's hostname, so only names that mean "this machine" are served.
    let mut response =
        if !state.config.auth.required() && state.config.loopback && !is_local_name(hostname(host))
        {
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
        } else if protected {
            match resolve(&state, headers).await {
                Ok(Some((access, credential))) => {
                    request.extensions_mut().insert(access);
                    request.extensions_mut().insert(credential);
                    next.run(request).await
                }
                Ok(None) => {
                    let mut response =
                        ApiError::new(StatusCode::UNAUTHORIZED, "authentication required")
                            .into_response();
                    response
                        .headers_mut()
                        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
                    response
                }
                Err(error) => error.into_response(),
            }
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

fn require_admin(access: &Access) -> ApiResult<()> {
    match access {
        Access::Admin => Ok(()),
        Access::Inbox(_) => Err(ApiError::admin_only()),
    }
}

/// The inbox a request is about: the caller's own if it is confined to one,
/// otherwise the one it names, or all of them when it names none.
async fn scope(
    state: &Shared,
    access: &Access,
    requested: Option<String>,
) -> ApiResult<Option<String>> {
    match (access, requested) {
        (Access::Inbox(own), Some(other)) if *own != other => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            format!("this API key is for the `{own}` inbox, not `{other}`"),
        )),
        (Access::Inbox(own), _) => Ok(Some(own.clone())),
        (Access::Admin, None) => Ok(None),
        (Access::Admin, Some(inbox)) => {
            let name = inbox.clone();
            if store(state, move |s| s.inbox_exists(&name)).await? {
                Ok(Some(inbox))
            } else {
                Err(ApiError::from(anyhow::Error::from(InboxError::NotFound(
                    inbox,
                ))))
            }
        }
    }
}

/// Refuse a message outside the caller's inbox, in the same words as a message
/// that does not exist: a key must not learn what other inboxes hold.
async fn authorize(state: &Shared, access: &Access, id: i64) -> ApiResult<()> {
    if let Access::Inbox(own) = access {
        let owner = store(state, move |s| s.message_inbox(id)).await?;
        if owner.as_deref() != Some(own.as_str()) {
            return Err(ApiError::not_found(format_args!("message {id}")));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

fn describe(access: Option<&Access>) -> Value {
    match access {
        Some(Access::Admin) => json!({"authenticated": true, "access": "admin", "inbox": null}),
        Some(Access::Inbox(inbox)) => {
            json!({"authenticated": true, "access": "inbox", "inbox": inbox})
        }
        None => json!({"authenticated": false, "access": null, "inbox": null}),
    }
}

async fn session_status(State(state): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let access = resolve(&state, &headers).await?.map(|(access, _)| access);
    let mut status = describe(access.as_ref());
    status["auth_required"] = json!(state.config.auth.required());
    Ok(Json(status))
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

/// Sign the web UI in with the admin token, or with an inbox's API key for a
/// view of that inbox alone.
async fn session_open(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(login): Json<Login>,
) -> ApiResult<Response> {
    let Some(access) = access_for_secret(&state, login.token.trim()).await? else {
        tracing::warn!("web UI sign-in failed");
        tokio::time::sleep(LOGIN_FAILURE_DELAY).await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "that is neither the admin token nor an inbox API key",
        ));
    };
    let auth = &state.config.auth;
    let body = describe(Some(&access));
    let session = inbox_key(&access, login.token.trim()).map_or(Session::Admin, Session::Inbox);
    let id = auth.open_session(session);
    let mut response = Json(body).into_response();
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
    if let Some(id) = session_cookie(&headers) {
        state.config.auth.close_session(id);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie("", 0, is_https(&state, &headers)),
    );
    response
}

// ---------------------------------------------------------------------------
// Inboxes and keys
// ---------------------------------------------------------------------------

async fn info(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
) -> ApiResult<Json<Value>> {
    let own = access.inbox().map(str::to_string);
    let stats = store(&state, move |s| s.stats(own.as_deref())).await?;
    let mut info = serde_json::to_value(&state.config.info).map_err(anyhow::Error::from)?;
    info["stats"] = json!(stats);
    info["access"] = describe(Some(&access))["access"].clone();
    info["inbox"] = json!(access.inbox());
    Ok(Json(info))
}

/// Every inbox for the admin; a key sees its own.
async fn list_inboxes(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
) -> ApiResult<Json<Value>> {
    let own = access.inbox().map(str::to_string);
    let (inboxes, stats) = store(&state, move |s| {
        let mut inboxes = s.inboxes()?;
        if let Some(own) = &own {
            inboxes.retain(|inbox| &inbox.id == own);
        }
        Ok((inboxes, s.stats(own.as_deref())?))
    })
    .await?;
    Ok(Json(json!({"inboxes": inboxes, "stats": stats})))
}

#[derive(Deserialize)]
struct NewInbox {
    /// What people will call the inbox. Required unless `id` is given, in
    /// which case the inbox is named after its id.
    name: Option<String>,
    #[serde(default)]
    description: String,
    /// Normally left out and generated. A client that showed the user an id
    /// and key before creating the inbox sends them, to get exactly those.
    id: Option<String>,
    key: Option<String>,
    /// Create nothing: answer with the id this name would get and a fresh key,
    /// for a form that shows both before the inbox exists.
    #[serde(default)]
    dry_run: bool,
}

/// Create an inbox. It comes with a first API key, returned here and only here.
async fn create_inbox(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Json(new): Json<NewInbox>,
) -> ApiResult<Response> {
    require_admin(&access)?;
    let Some(name) = new.name.clone().or_else(|| new.id.clone()) else {
        return Err(ApiError::bad_request("an inbox needs a `name`"));
    };
    if new.dry_run {
        let id = store(&state, move |s| s.suggest_inbox_id(&name)).await?;
        let preview = json!({"id": id, "key": crate::security::generate_api_key()});
        return Ok(Json(preview).into_response());
    }
    let draft = crate::store::NewInbox {
        name,
        description: new.description,
        id: new.id,
        key: new.key,
    };
    let (inbox, key) = store(&state, move |s| s.create_inbox_named(draft)).await?;
    tracing::info!(inbox = %inbox.id, name = %inbox.name, "inbox created");
    let mut body = serde_json::to_value(&inbox).map_err(anyhow::Error::from)?;
    body["key"] = json!(key);
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

#[derive(Deserialize)]
struct InboxChanges {
    name: Option<String>,
    description: Option<String>,
}

/// Rename an inbox or change its description. Its id, and so what
/// applications sign in with, stays as it is.
async fn update_inbox(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(inbox): Path<String>,
    Json(changes): Json<InboxChanges>,
) -> ApiResult<Json<Value>> {
    require_admin(&access)?;
    if changes.name.is_none() && changes.description.is_none() {
        return Err(ApiError::bad_request("give `name`, `description`, or both"));
    }
    let updated = store(&state, move |s| {
        s.update_inbox(
            &inbox,
            changes.name.as_deref(),
            changes.description.as_deref(),
        )
    })
    .await?;
    Ok(Json(json!(updated)))
}

async fn get_inbox(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(inbox): Path<String>,
) -> ApiResult<Json<Value>> {
    let inbox = scope(&state, &access, Some(inbox))
        .await?
        .unwrap_or_default();
    let found = store(&state, move |s| s.inbox(&inbox)).await?;
    Ok(Json(json!(found)))
}

async fn delete_inbox(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(inbox): Path<String>,
) -> ApiResult<StatusCode> {
    require_admin(&access)?;
    let name = inbox.clone();
    store(&state, move |s| s.delete_inbox(&name)).await?;
    state.config.auth.close_inbox_sessions(&inbox);
    tracing::info!(%inbox, "inbox deleted");
    Ok(StatusCode::NO_CONTENT)
}

async fn list_keys(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(inbox): Path<String>,
) -> ApiResult<Json<Value>> {
    require_admin(&access)?;
    let inbox = scope(&state, &access, Some(inbox)).await?;
    let keys = store(&state, move |s| s.keys(inbox.as_deref())).await?;
    Ok(Json(json!({"keys": keys})))
}

#[derive(Deserialize, Default)]
struct NewKey {
    #[serde(default)]
    label: String,
}

/// Mint a key. The response is the only time the key itself is ever shown.
async fn create_key(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(inbox): Path<String>,
    body: Bytes,
) -> ApiResult<Response> {
    require_admin(&access)?;
    // The body is optional: a key needs no label.
    let new: NewKey = if body.iter().all(u8::is_ascii_whitespace) {
        NewKey::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))?
    };
    let (record, key) = store(&state, move |s| s.create_key(&inbox, &new.label)).await?;
    tracing::info!(inbox = %record.inbox, key = record.id, "API key created");
    let mut body = serde_json::to_value(&record).map_err(anyhow::Error::from)?;
    body["key"] = json!(key);
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// Replace a key's value. The old one stops working at once; the response is
/// the only time the new one is shown.
async fn regenerate_key(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path((inbox, key)): Path<(String, i64)>,
) -> ApiResult<Json<Value>> {
    require_admin(&access)?;
    let name = inbox.clone();
    let Some((record, value)) = store(&state, move |s| s.regenerate_key(key, Some(&name))).await?
    else {
        return Err(ApiError::not_found(format_args!(
            "key {key} of inbox `{inbox}`"
        )));
    };
    // Sessions opened with the old value end on their next request, when
    // their key's hash no longer matches; those opened with the inbox's other
    // keys go on.
    tracing::info!(%inbox, key, "API key regenerated");
    let mut body = serde_json::to_value(&record).map_err(anyhow::Error::from)?;
    body["key"] = json!(value);
    Ok(Json(body))
}

async fn revoke_key(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path((inbox, key)): Path<(String, i64)>,
) -> ApiResult<StatusCode> {
    require_admin(&access)?;
    let name = inbox.clone();
    if !store(&state, move |s| s.revoke_key(key, Some(&name))).await? {
        return Err(ApiError::not_found(format_args!(
            "key {key} of inbox `{inbox}`"
        )));
    }
    // Sessions opened with this key end on their next request; those opened
    // with the inbox's other keys go on.
    tracing::info!(%inbox, key, "API key revoked");
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Which messages a request is about. Unknown parameters are refused rather
/// than ignored: a misspelled filter on a bulk delete would otherwise widen it
/// to everything.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Selection {
    inbox: Option<String>,
    /// An exact envelope recipient.
    to: Option<String>,
    q: Option<String>,
    unread: Option<bool>,
    starred: Option<bool>,
    before: Option<i64>,
    after: Option<i64>,
    since: Option<i64>,
    limit: Option<usize>,
}

async fn filter(state: &Shared, access: &Access, selection: Selection) -> ApiResult<ListFilter> {
    Ok(ListFilter {
        inbox: scope(state, access, selection.inbox).await?,
        to: selection.to,
        query: selection.q,
        unread: selection.unread,
        starred: selection.starred,
        before_id: selection.before,
        after_id: selection.after,
        since: selection.since,
        limit: selection.limit,
    })
}

async fn list_messages(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Query(selection): Query<Selection>,
) -> ApiResult<Json<Value>> {
    let filter = filter(&state, &access, selection).await?;
    let page = store(&state, move |s| s.list(&filter)).await?;
    Ok(Json(json!(page)))
}

#[derive(Deserialize)]
struct Delivery {
    /// The inbox to deliver into, for a caller not confined to one.
    inbox: Option<String>,
    from: Option<String>,
    /// Comma-separated envelope recipients.
    to: Option<String>,
}

async fn send_message(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Query(delivery): Query<Delivery>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let inbox = scope(&state, &access, delivery.inbox)
        .await?
        .unwrap_or_else(|| DEFAULT_INBOX.to_string());
    let is_json = header_str(&headers, header::CONTENT_TYPE)
        .is_some_and(|t| t.to_ascii_lowercase().starts_with("application/json"));

    let incoming = if is_json {
        let request: SendRequest = serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request(format!("invalid message: {e}")))?;
        request
            .build(&inbox)
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
            inbox,
            envelope_from: delivery.from,
            envelope_to: delivery
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
        inbox = %summary.inbox,
        recipients = summary.recipients.len(),
        size = summary.size,
        "message received over the API"
    );
    Ok((StatusCode::CREATED, Json(summary)).into_response())
}

#[derive(Deserialize)]
struct Flags {
    read: Option<bool>,
    starred: Option<bool>,
}

/// Mark read everything the query selects.
async fn update_messages(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Query(selection): Query<Selection>,
    Json(flags): Json<Flags>,
) -> ApiResult<Json<Value>> {
    if flags.read != Some(true) || flags.starred.is_some() {
        return Err(ApiError::bad_request(
            "the only bulk update is {\"read\": true}; flag single messages by id",
        ));
    }
    let filter = filter(&state, &access, selection).await?;
    let updated = store(&state, move |s| s.mark_all_read(&filter)).await?;
    Ok(Json(json!({"updated": updated})))
}

/// Delete everything the query selects: an inbox, a search within one, or,
/// for the admin with no filter at all, every message there is.
async fn delete_messages(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Query(selection): Query<Selection>,
) -> ApiResult<Json<Value>> {
    let filter = filter(&state, &access, selection).await?;
    let deleted = store(&state, move |s| s.clear(&filter)).await?;
    Ok(Json(json!({"deleted": deleted})))
}

async fn get_message(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &access, id).await?;
    let detail = store(&state, move |s| s.get(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format_args!("message {id}")))?;
    Ok(Json(json!(detail)))
}

async fn update_message(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(id): Path<i64>,
    Json(flags): Json<Flags>,
) -> ApiResult<Json<Value>> {
    if flags.read.is_none() && flags.starred.is_none() {
        return Err(ApiError::bad_request("give `read`, `starred`, or both"));
    }
    authorize(&state, &access, id).await?;
    let summary = store(&state, move |s| {
        s.set_flags(id, flags.read, flags.starred)?;
        s.summary(id)
    })
    .await?
    .ok_or_else(|| ApiError::not_found(format_args!("message {id}")))?;
    Ok(Json(json!(summary)))
}

async fn delete_message(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    authorize(&state, &access, id).await?;
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

async fn message_raw(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(id): Path<i64>,
) -> ApiResult<Response> {
    authorize(&state, &access, id).await?;
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

async fn message_html(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(id): Path<i64>,
) -> ApiResult<Response> {
    authorize(&state, &access, id).await?;
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

async fn message_links(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &access, id).await?;
    let links = store(&state, move |s| s.links(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format_args!("message {id}")))?;
    Ok(Json(json!({"links": links})))
}

#[derive(Deserialize)]
struct CheckQuery {
    /// Comma-separated client families to check against; all of them otherwise.
    clients: Option<String>,
}

/// Which email clients will render the message as written.
async fn message_check(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path(id): Path<i64>,
    Query(query): Query<CheckQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&state, &access, id).await?;
    let only: Option<Vec<String>> = query.clients.map(|clients| {
        clients
            .split(',')
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect()
    });
    let report = store(&state, move |s| {
        Ok(s.get(id)?
            .map(|detail| crate::check::check(&detail, only.as_deref())))
    })
    .await?
    .ok_or_else(|| ApiError::not_found(format_args!("message {id}")))?;
    Ok(Json(json!(report)))
}

async fn message_attachment(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Path((id, index)): Path<(i64, usize)>,
) -> ApiResult<Response> {
    authorize(&state, &access, id).await?;
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

/// How often an idle event stream checks that its caller may still listen.
const EVENTS_RECHECK: Duration = Duration::from_secs(15);

/// How long a check of an event stream's caller stands before an event needs
/// another. A burst of mail costs a check a second, not one per message.
const EVENTS_CHECK_FRESH: Duration = Duration::from_secs(1);

/// How long an event stream goes on while its caller cannot be checked at
/// all, before it gives up.
const EVENTS_UNKNOWN_LIMIT: Duration = Duration::from_secs(60);

async fn events(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Extension(credential): Extension<Credential>,
) -> impl IntoResponse {
    // Subscribed here, before the response goes out, so nothing sent after
    // the stream opens is missed.
    let mut events = state.store.subscribe();
    let (sender, receiver) = mpsc::channel::<Result<SseEvent, Infallible>>(64);
    // The stream outlives the request that was authorized. Its caller is
    // checked again while it idles, when keys change, and before an event when
    // the last check is more than a moment old, and it ends once the caller no
    // longer may: a revoked or regenerated key, a deleted inbox, a closed
    // session. While the store cannot answer it goes on, for a while.
    tokio::spawn(async move {
        let mut recheck = tokio::time::interval(EVENTS_RECHECK);
        recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        recheck.tick().await;
        let mut checked = tokio::time::Instant::now();
        let mut unknown_since: Option<tokio::time::Instant> = None;
        let mut holds = async |checked: &mut tokio::time::Instant| -> bool {
            match credential_holds(&state, &credential).await {
                Some(holds) => {
                    unknown_since = None;
                    *checked = tokio::time::Instant::now();
                    holds
                }
                None => {
                    unknown_since
                        .get_or_insert_with(tokio::time::Instant::now)
                        .elapsed()
                        < EVENTS_UNKNOWN_LIMIT
                }
            }
        };
        loop {
            let event = tokio::select! {
                () = sender.closed() => return,
                _ = recheck.tick() => {
                    if !holds(&mut checked).await {
                        return;
                    }
                    continue;
                }
                event = events.recv() => event,
            };
            let data = match event {
                // A viewer confined to one inbox hears only of that inbox.
                Ok(event) if access.inbox().is_none_or(|inbox| event.concerns(inbox)) => {
                    if (matches!(event, Event::Inboxes) || checked.elapsed() > EVENTS_CHECK_FRESH)
                        && !holds(&mut checked).await
                    {
                        return;
                    }
                    SseEvent::default().json_data(&event).unwrap_or_default()
                }
                Ok(_) => continue,
                // The viewer fell behind and missed events; tell it to reload.
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    SseEvent::default().data(r#"{"type":"resync"}"#)
                }
                Err(broadcast::error::RecvError::Closed) => return,
            };
            if sender.send(Ok(data)).await.is_err() {
                return;
            }
        }
    });
    Sse::new(ReceiverStream::new(receiver)).keep_alive(KeepAlive::default())
}

async fn mcp(
    State(state): State<Shared>,
    Extension(access): Extension<Access>,
    Extension(credential): Extension<Credential>,
    body: Bytes,
) -> Response {
    let message: Value = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(error) => {
            let reply = json!({"jsonrpc": "2.0", "id": null,
                               "error": {"code": -32700, "message": format!("parse error: {error}")}});
            return (StatusCode::BAD_REQUEST, Json(reply)).into_response();
        }
    };
    // A request can hold a batch of calls, and wait_for_message can take
    // minutes: the caller is checked again before each call and while one
    // waits, so a key revoked mid-request stops working from that point. The
    // request was just authorized, so the first second needs no check; a store
    // that cannot answer does not stop a call.
    let alive: Liveness = {
        let state = state.clone();
        let checked = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
        Arc::new(move || {
            let state = state.clone();
            let credential = credential.clone();
            let checked = checked.clone();
            Box::pin(async move {
                let fresh = checked
                    .lock()
                    .map(|at| at.elapsed() < Duration::from_secs(1))
                    .unwrap_or(false);
                if fresh {
                    return true;
                }
                let holds = credential_holds(&state, &credential).await;
                if holds.is_some()
                    && let Ok(mut at) = checked.lock()
                {
                    *at = std::time::Instant::now();
                }
                holds.unwrap_or(true)
            })
        })
    };
    match state
        .mcp
        .handle_checked(message, &access, Some(&alive))
        .await
    {
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
    use axum::body::to_bytes;
    use tower::ServiceExt;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn app(token: Option<&str>, loopback: bool) -> (Router, Arc<Store>) {
        let store = Arc::new(Store::in_memory().unwrap());
        let config = HttpConfig {
            auth: Arc::new(Auth::new(token.map(str::to_string)).unwrap()),
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

    fn request(method: &str, uri: &str) -> axum::http::request::Builder {
        axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "localhost:8025")
    }

    fn with_key(method: &str, uri: &str, key: &str) -> axum::http::request::Builder {
        request(method, uri).header("authorization", format!("Bearer {key}"))
    }

    fn empty(builder: axum::http::request::Builder) -> axum::http::Request<Body> {
        builder.body(Body::empty()).unwrap()
    }

    fn json_request(
        builder: axum::http::request::Builder,
        value: Value,
    ) -> axum::http::Request<Body> {
        builder
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&value).unwrap()))
            .unwrap()
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

    /// Sign the web UI in with `token` and return the cookie to send back.
    async fn sign_in(app: &Router, token: &str) -> String {
        let login = json_request(request("POST", "/api/v1/session"), json!({"token": token}));
        let (status, headers, body) = send(app, login).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        headers["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    async fn json(app: &Router, request: axum::http::Request<Body>) -> (StatusCode, Value) {
        let (status, _, body) = send(app, request).await;
        (status, serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    fn sample() -> Value {
        json!({
            "from": "app@x.test", "to": "bob@x.test", "subject": "Hello",
            "html": "<p>Hi<script>alert(1)</script></p>",
            "attachments": [{"filename": "evil.html", "content": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}],
        })
    }

    /// Deliver the sample message, as `key` if one is given, and return its id.
    async fn seed(app: &Router, uri: &str, key: Option<&str>) -> i64 {
        let builder = match key {
            Some(key) => with_key("POST", uri, key),
            None => request("POST", uri),
        };
        let (status, body) = json(app, json_request(builder, sample())).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["id"].as_i64().unwrap()
    }

    #[tokio::test]
    async fn api_round_trip_without_auth() {
        let (app, _) = app(None, true);
        let id = seed(&app, "/api/v1/messages", None).await;

        let (status, page) = json(
            &app,
            empty(request("GET", "/api/v1/messages?to=bob@x.test")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["total"], 1);
        assert_eq!(page["messages"][0]["subject"], "Hello");
        assert_eq!(
            page["messages"][0]["inbox"], "default",
            "mail with no key goes to the default inbox"
        );

        let patch = json_request(
            request("PATCH", &format!("/api/v1/messages/{id}")),
            json!({"read": true, "starred": true}),
        );
        let (status, summary) = json(&app, patch).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(summary["starred"], true);

        let (status, _, _) = send(
            &app,
            empty(request("DELETE", &format!("/api/v1/messages/{id}"))),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _, _) = send(
            &app,
            empty(request("GET", &format!("/api/v1/messages/{id}"))),
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
        assert_eq!(detail.summary.recipients, vec!["one@x.test", "two@x.test"]);
        assert_eq!(detail.envelope_from.as_deref(), Some("bounce@x.test"));

        let big = request("POST", "/api/v1/messages")
            .header("content-type", "message/rfc822")
            .body(Body::from(vec![b'x'; 5000]))
            .unwrap();
        assert_eq!(send(&app, big).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn the_admin_manages_inboxes_and_their_keys() {
        let (app, _) = app(Some(TOKEN), false);
        let admin = |method: &str, uri: &str| with_key(method, uri, TOKEN);
        let create = |body: Value| json_request(admin("POST", "/api/v1/inboxes"), body);

        // A name is all it takes; the id and first key are generated.
        let (status, inbox) = json(
            &app,
            create(json!({"name": "Billing App", "description": "Invoices"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{inbox}");
        let id = inbox["id"].as_str().unwrap().to_string();
        assert_eq!(id, "billing-app", "made from the name");
        assert_eq!(inbox["name"], "Billing App");
        assert_eq!(inbox["description"], "Invoices");
        assert_eq!(inbox["keys"], 1);
        let first_key = inbox["key"].as_str().unwrap().to_string();
        assert!(first_key.starts_with("emu_"));
        assert_eq!(
            send(&app, empty(with_key("GET", "/api/v1/messages", &first_key)))
                .await
                .0,
            StatusCode::OK,
            "the key it came with works at once"
        );

        let (status, error) = json(&app, create(json!({"name": "billing app"}))).await;
        assert_eq!(status, StatusCode::CONFLICT, "{error}");
        let (status, error) = json(&app, create(json!({"name": "   "}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        let (status, _) = json(&app, create(json!({"description": "no name"}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // A form can ask what a name would get, without creating anything.
        let (status, preview) = json(
            &app,
            create(json!({"name": "Billing App", "dry_run": true})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["id"], "billing-app-2", "the plain slug is taken");
        assert!(preview["key"].as_str().unwrap().starts_with("emu_"));
        let (_, listed) = json(&app, empty(admin("GET", "/api/v1/inboxes"))).await;
        assert_eq!(
            listed["inboxes"].as_array().unwrap().len(),
            2,
            "nothing was created"
        );

        // A client that showed the user an id and key first gets exactly those.
        let shown = json!({"name": "Orders", "id": "ibx_00112233aa", "key": "emu_shown-to-the-user-already"});
        let (status, orders) = json(&app, create(shown)).await;
        assert_eq!(status, StatusCode::CREATED, "{orders}");
        assert_eq!(orders["id"], "ibx_00112233aa");
        assert_eq!(orders["key"], "emu_shown-to-the-user-already");
        let (status, _) = json(&app, create(json!({"name": "Bad", "id": "Not Valid"}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Renaming keeps the id.
        let rename = json_request(
            admin("PATCH", &format!("/api/v1/inboxes/{id}")),
            json!({"name": "Payments"}),
        );
        let (status, renamed) = json(&app, rename).await;
        assert_eq!(status, StatusCode::OK, "{renamed}");
        assert_eq!(
            (renamed["id"].as_str(), renamed["name"].as_str()),
            (Some(id.as_str()), Some("Payments"))
        );

        // Further keys are shown in full exactly once, at creation.
        let keys_uri = format!("/api/v1/inboxes/{id}/keys");
        let (status, created) = json(
            &app,
            json_request(admin("POST", &keys_uri), json!({"label": "laravel"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let key = created["key"].as_str().unwrap().to_string();
        let (_, unlabeled) = json(&app, empty(admin("POST", &keys_uri))).await;
        assert_eq!(
            unlabeled["label"], "key",
            "a label is optional: {unlabeled}"
        );

        let (status, _, listed) = send(&app, empty(admin("GET", &keys_uri))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(listed.contains("\"label\":\"laravel\""), "{listed}");
        assert!(
            !listed.contains(&key) && !listed.contains(&first_key),
            "a listing never repeats a key"
        );

        let (_, all) = json(&app, empty(admin("GET", "/api/v1/inboxes"))).await;
        let names: Vec<_> = all["inboxes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["name"].clone())
            .collect();
        assert_eq!(
            names,
            vec![json!("Default"), json!("Orders"), json!("Payments")]
        );
        assert_eq!(all["inboxes"][2]["keys"], 3);

        // Regenerating swaps the value under the same id and label.
        let key_id = created["id"].as_i64().unwrap();
        let regenerate = admin("POST", &format!("{keys_uri}/{key_id}/regenerate"));
        let (status, renewed) = json(&app, empty(regenerate)).await;
        assert_eq!(status, StatusCode::OK, "{renewed}");
        assert_eq!(
            (renewed["id"].as_i64(), renewed["label"].as_str()),
            (Some(key_id), Some("laravel"))
        );
        let old = key;
        let key = renewed["key"].as_str().unwrap().to_string();
        assert_ne!(key, old);
        assert_eq!(
            send(&app, empty(with_key("GET", "/api/v1/messages", &old)))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let missing = admin("POST", &format!("{keys_uri}/9999/regenerate"));
        assert_eq!(send(&app, empty(missing)).await.0, StatusCode::NOT_FOUND);

        // Revoking a key locks it out; deleting the inbox takes the rest.
        assert_eq!(
            send(&app, empty(with_key("GET", "/api/v1/messages", &key)))
                .await
                .0,
            StatusCode::OK
        );
        let revoke = admin("DELETE", &format!("{keys_uri}/{key_id}"));
        assert_eq!(send(&app, empty(revoke)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(
            send(&app, empty(with_key("GET", "/api/v1/messages", &key)))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );

        let delete = format!("/api/v1/inboxes/{id}");
        assert_eq!(
            send(&app, empty(admin("DELETE", &delete))).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            send(&app, empty(admin("DELETE", &delete))).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send(&app, empty(with_key("GET", "/api/v1/messages", &first_key)))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&app, empty(admin("DELETE", "/api/v1/inboxes/default")))
                .await
                .0,
            StatusCode::CONFLICT
        );
    }

    /// Two inboxes, a key for each, and one message in each.
    async fn two_inboxes() -> (Router, Arc<Store>, String, String, i64, i64) {
        let (app, store) = app(Some(TOKEN), false);
        store.create_inbox("billing").unwrap();
        store.create_inbox("marketing").unwrap();
        let (_, billing) = store.create_key("billing", "app").unwrap();
        let (_, marketing) = store.create_key("marketing", "site").unwrap();
        let invoice = seed(&app, "/api/v1/messages", Some(&billing)).await;
        let promo = seed(&app, "/api/v1/messages", Some(&marketing)).await;
        (app, store, billing, marketing, invoice, promo)
    }

    #[tokio::test]
    async fn an_inbox_key_delivers_into_and_reads_only_its_inbox() {
        let (app, store, billing, _marketing, invoice, promo) = two_inboxes().await;
        assert_eq!(
            store.message_inbox(invoice).unwrap().as_deref(),
            Some("billing")
        );
        assert_eq!(
            store.message_inbox(promo).unwrap().as_deref(),
            Some("marketing")
        );

        let (_, page) = json(&app, empty(with_key("GET", "/api/v1/messages", &billing))).await;
        assert_eq!(page["total"], 1);
        assert_eq!(page["messages"][0]["id"], invoice);

        // Its own inbox by name is fine; another's is refused, not emptied.
        let own = with_key("GET", "/api/v1/messages?inbox=billing", &billing);
        assert_eq!(send(&app, empty(own)).await.0, StatusCode::OK);
        let other = with_key("GET", "/api/v1/messages?inbox=marketing", &billing);
        assert_eq!(send(&app, empty(other)).await.0, StatusCode::FORBIDDEN);

        // Another inbox's message looks exactly like one that does not exist.
        for path in ["", "/raw", "/html", "/links", "/attachments/0"] {
            let uri = format!("/api/v1/messages/{promo}{path}");
            let (status, _, body) = send(&app, empty(with_key("GET", &uri, &billing))).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(
                body.contains(&format!("message {promo} not found")),
                "{body}"
            );
        }
        let patch = json_request(
            with_key("PATCH", &format!("/api/v1/messages/{promo}"), &billing),
            json!({"read": true}),
        );
        assert_eq!(send(&app, patch).await.0, StatusCode::NOT_FOUND);
        let delete = with_key("DELETE", &format!("/api/v1/messages/{promo}"), &billing);
        assert_eq!(send(&app, empty(delete)).await.0, StatusCode::NOT_FOUND);
        assert!(
            !store.get(promo).unwrap().unwrap().summary.read,
            "untouched"
        );

        // It sees one inbox, its own, and cannot manage any.
        let (_, inboxes) = json(&app, empty(with_key("GET", "/api/v1/inboxes", &billing))).await;
        assert_eq!(inboxes["inboxes"].as_array().unwrap().len(), 1);
        assert_eq!(inboxes["inboxes"][0]["id"], "billing");
        let (_, info) = json(&app, empty(with_key("GET", "/api/v1/info", &billing))).await;
        assert_eq!(info["access"], "inbox");
        assert_eq!(info["inbox"], "billing");
        assert_eq!(info["stats"]["total"], 1, "counts are its own inbox's");
        for (method, uri) in [
            ("POST", "/api/v1/inboxes"),
            ("PATCH", "/api/v1/inboxes/billing"),
            ("DELETE", "/api/v1/inboxes/billing"),
            ("GET", "/api/v1/inboxes/billing/keys"),
            ("POST", "/api/v1/inboxes/billing/keys"),
            ("DELETE", "/api/v1/inboxes/billing/keys/1"),
            ("POST", "/api/v1/inboxes/billing/keys/1/regenerate"),
        ] {
            let request = json_request(with_key(method, uri, &billing), json!({"id": "x"}));
            assert_eq!(
                send(&app, request).await.0,
                StatusCode::FORBIDDEN,
                "{method} {uri}"
            );
        }
    }

    #[tokio::test]
    async fn bulk_changes_stay_inside_the_callers_inbox() {
        let (app, store, billing, _marketing, _invoice, promo) = two_inboxes().await;

        let read_all = json_request(
            with_key("PATCH", "/api/v1/messages", &billing),
            json!({"read": true}),
        );
        let (_, updated) = json(&app, read_all).await;
        assert_eq!(updated["updated"], 1);
        assert!(!store.get(promo).unwrap().unwrap().summary.read);

        let (_, deleted) = json(
            &app,
            empty(with_key("DELETE", "/api/v1/messages", &billing)),
        )
        .await;
        assert_eq!(deleted["deleted"], 1);
        assert_eq!(
            store.stats(None).unwrap().total,
            1,
            "marketing's mail is still there"
        );

        // A misspelled filter is refused instead of widening the delete.
        let typo = with_key("DELETE", "/api/v1/messages?inbx=marketing", TOKEN);
        assert_eq!(send(&app, empty(typo)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(store.stats(None).unwrap().total, 1);

        // The admin can aim at one inbox, or a search within everything.
        let none = with_key(
            "DELETE",
            "/api/v1/messages?q=subject:nothing-matches",
            TOKEN,
        );
        assert_eq!(json(&app, empty(none)).await.1["deleted"], 0);
        let aimed = with_key("DELETE", "/api/v1/messages?inbox=marketing", TOKEN);
        assert_eq!(json(&app, empty(aimed)).await.1["deleted"], 1);
        let unknown = with_key("GET", "/api/v1/messages?inbox=nowhere", TOKEN);
        assert_eq!(send(&app, empty(unknown)).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_token_gates_the_api_and_mcp_but_not_the_shell() {
        let (app, _) = app(Some(TOKEN), false);

        for path in [
            "/api/v1/messages",
            "/api/v1/info",
            "/api/v1/events",
            "/api/v1/inboxes",
            "/api/v1/messages/1/raw",
        ] {
            let (status, headers, _) = send(&app, empty(request("GET", path))).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(headers["www-authenticate"], "Bearer");
        }
        let mcp = request("POST", "/mcp").body(Body::from("{}")).unwrap();
        assert_eq!(send(&app, mcp).await.0, StatusCode::UNAUTHORIZED);

        assert_eq!(
            send(&app, empty(with_key("GET", "/api/v1/messages", "nope")))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&app, empty(with_key("GET", "/api/v1/messages", TOKEN)))
                .await
                .0,
            StatusCode::OK
        );

        // The static shell and the health probe carry no mail.
        assert_eq!(
            send(&app, empty(request("GET", "/"))).await.0,
            StatusCode::OK
        );
        assert_eq!(
            send(&app, empty(request("GET", "/healthz"))).await.0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_wrong_key_is_refused_even_where_none_is_needed() {
        let (app, store) = app(None, true);
        store.create_inbox("billing").unwrap();
        let (record, key) = store.create_key("billing", "app").unwrap();

        // Open server: no credential is admin, a key confines the caller.
        assert_eq!(
            json(&app, empty(request("GET", "/api/v1/info"))).await.1["access"],
            "admin"
        );
        assert_eq!(
            json(&app, empty(with_key("GET", "/api/v1/info", &key)))
                .await
                .1["access"],
            "inbox"
        );

        store.revoke_key(record.id, None).unwrap();
        let revoked = with_key("GET", "/api/v1/info", &key);
        assert_eq!(send(&app, empty(revoked)).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_ui_signs_in_with_a_cookie_and_out_again() {
        let (app, _) = app(Some(TOKEN), false);
        let login =
            |token: &str| json_request(request("POST", "/api/v1/session"), json!({"token": token}));

        let (status, headers, body) = send(&app, login(TOKEN)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"access\":\"admin\""), "{body}");
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
            empty(request(method, path).header("cookie", cookie.clone()))
        };
        assert_eq!(
            send(&app, with_cookie("GET", "/api/v1/messages")).await.0,
            StatusCode::OK
        );
        let (_, status_body) = json(&app, with_cookie("GET", "/api/v1/session")).await;
        assert_eq!(status_body["authenticated"], true);
        assert_eq!(status_body["auth_required"], true);

        assert_eq!(
            send(&app, with_cookie("DELETE", "/api/v1/session")).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            send(&app, with_cookie("GET", "/api/v1/messages")).await.0,
            StatusCode::UNAUTHORIZED
        );

        let secure = json_request(
            request("POST", "/api/v1/session").header("x-forwarded-proto", "https"),
            json!({"token": TOKEN}),
        );
        let (_, headers, _) = send(&app, secure).await;
        assert!(headers["set-cookie"].to_str().unwrap().contains("; Secure"));
        assert!(headers.contains_key("strict-transport-security"));
    }

    #[tokio::test]
    async fn signing_in_with_an_inbox_key_shows_that_inbox_until_the_key_is_revoked() {
        let (app, _store, billing, _marketing, invoice, promo) = two_inboxes().await;
        let login = json_request(
            request("POST", "/api/v1/session"),
            json!({"token": billing}),
        );
        let (status, headers, body) = send(&app, login).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("\"inbox\":\"billing\""), "{body}");
        let cookie = headers["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let with_cookie = |method: &str, path: &str| {
            empty(request(method, path).header("cookie", cookie.clone()))
        };

        let own = format!("/api/v1/messages/{invoice}");
        let theirs = format!("/api/v1/messages/{promo}");
        assert_eq!(send(&app, with_cookie("GET", &own)).await.0, StatusCode::OK);
        assert_eq!(
            send(&app, with_cookie("GET", &theirs)).await.0,
            StatusCode::NOT_FOUND
        );

        // The session holds no key, so revoking the key has to end it too.
        let (_, keys) = json(
            &app,
            empty(with_key("GET", "/api/v1/inboxes/billing/keys", TOKEN)),
        )
        .await;
        let key_id = keys["keys"][0]["id"].as_i64().unwrap();
        let revoke = with_key(
            "DELETE",
            &format!("/api/v1/inboxes/billing/keys/{key_id}"),
            TOKEN,
        );
        assert_eq!(send(&app, empty(revoke)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(
            send(&app, with_cookie("GET", &own)).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn a_session_ends_when_its_key_is_replaced_behind_the_servers_back() {
        let (app, store, billing, _marketing, invoice, _promo) = two_inboxes().await;
        let cookie = sign_in(&app, &billing).await;
        let own = || {
            empty(
                request("GET", &format!("/api/v1/messages/{invoice}"))
                    .header("cookie", cookie.clone()),
            )
        };
        assert_eq!(send(&app, own()).await.0, StatusCode::OK);

        // As `emailulator key regenerate` does: straight to the store, which
        // cannot reach the server's sessions.
        let key = store.keys(Some("billing")).unwrap().remove(0);
        store.regenerate_key(key.id, None).unwrap().unwrap();
        assert_eq!(send(&app, own()).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_cookie_for_an_ended_session_is_no_credential_on_an_open_server() {
        let (app, _) = app(None, true);
        let stale = empty(
            request("GET", "/api/v1/messages").header("cookie", format!("{SESSION_COOKIE}=gone")),
        );
        assert_eq!(send(&app, stale).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn revoking_one_key_leaves_sessions_opened_with_another() {
        let (app, store, _billing, _marketing, invoice, _promo) = two_inboxes().await;
        let (second_key, second) = store.create_key("billing", "browser").unwrap();
        let cookie = sign_in(&app, &second).await;
        let own = || {
            empty(
                request("GET", &format!("/api/v1/messages/{invoice}"))
                    .header("cookie", cookie.clone()),
            )
        };

        // Revoke the other key, the one `two_inboxes` made, through the API.
        let first = store
            .keys(Some("billing"))
            .unwrap()
            .into_iter()
            .find(|key| key.id != second_key.id)
            .unwrap();
        let revoke = with_key(
            "DELETE",
            &format!("/api/v1/inboxes/billing/keys/{}", first.id),
            TOKEN,
        );
        assert_eq!(send(&app, empty(revoke)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, own()).await.0, StatusCode::OK, "still signed in");
    }

    #[tokio::test(start_paused = true)]
    async fn an_event_stream_ends_when_its_key_stops_working() {
        let (app, store, billing, _marketing, _invoice, _promo) = two_inboxes().await;
        let response = app
            .clone()
            .oneshot(empty(with_key("GET", "/api/v1/events", &billing)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = tokio::spawn(to_bytes(response.into_body(), usize::MAX));

        // Mail before the key goes is heard; mail after it is not.
        let deliver = |subject: &str| {
            store
                .insert(Incoming {
                    raw: format!("From: a@x.test\r\nTo: b@x.test\r\nSubject: {subject}\r\n\r\nx")
                        .into_bytes(),
                    inbox: "billing".into(),
                    envelope_from: None,
                    envelope_to: Vec::new(),
                    source: Source::Api,
                })
                .unwrap();
        };
        deliver("Before");
        let key = store.keys(Some("billing")).unwrap().remove(0);
        assert!(store.revoke_key(key.id, None).unwrap());
        deliver("After");

        let bytes = tokio::time::timeout(Duration::from_secs(120), body)
            .await
            .expect("the stream ends once its key is gone")
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("Before"), "the stream was listening: {text}");
        assert!(
            !text.contains("After"),
            "nothing is delivered after revocation: {text}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_wrong_token_does_not_sign_in() {
        let (app, _) = app(Some(TOKEN), false);
        let login = json_request(
            request("POST", "/api/v1/session"),
            json!({"token": "guess"}),
        );
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
        let (with_token, _) = super::tests::app(Some(TOKEN), true);
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
        let forged = request("DELETE", "/api/v1/messages").header("origin", "https://evil.example");
        assert_eq!(send(&app, empty(forged)).await.0, StatusCode::FORBIDDEN);

        let forged_post = request("POST", "/api/v1/messages")
            .header("origin", "http://evil.example")
            .header("content-type", "text/plain")
            .body(Body::from("Subject: spam\r\n\r\nx"))
            .unwrap();
        assert_eq!(send(&app, forged_post).await.0, StatusCode::FORBIDDEN);
        assert_eq!(store.stats(None).unwrap().total, 0);

        let own = request("DELETE", "/api/v1/messages").header("origin", "http://localhost:8025");
        assert_eq!(send(&app, empty(own)).await.0, StatusCode::OK);
        let sandboxed = request("DELETE", "/api/v1/messages").header("origin", "null");
        assert_eq!(send(&app, empty(sandboxed)).await.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_proxy_that_rewrites_host_does_not_break_the_ui() {
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
        let id = seed(&app, "/api/v1/messages", None).await;

        let (status, headers, body) = send(
            &app,
            empty(request("GET", &format!("/api/v1/messages/{id}/html"))),
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
            empty(request(
                "GET",
                &format!("/api/v1/messages/{id}/attachments/0"),
            )),
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
            empty(request("GET", &format!("/api/v1/messages/{id}"))),
        )
        .await;
        assert_eq!(headers["content-security-policy"], DATA_CSP);
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["referrer-policy"], "no-referrer");
    }

    #[tokio::test]
    async fn the_client_check_reports_on_a_message_within_reach() {
        let (app, _store, billing, marketing, invoice, _promo) = two_inboxes().await;
        let uri = format!("/api/v1/messages/{invoice}/check");

        let (status, report) = json(&app, empty(with_key("GET", &uri, &billing))).await;
        assert_eq!(status, StatusCode::OK, "{report}");
        assert!(report["features_found"].as_u64().unwrap() >= 1, "{report}");
        assert_eq!(report["clients"][0]["family"], "gmail");
        assert!(report["data_updated"].as_str().unwrap().len() == 10);

        let (_, narrowed) = json(
            &app,
            empty(with_key(
                "GET",
                &format!("{uri}?clients=outlook,%20gmail"),
                &billing,
            )),
        )
        .await;
        assert_eq!(narrowed["clients"].as_array().unwrap().len(), 2);

        // Another inbox's message is not there to be checked.
        assert_eq!(
            send(&app, empty(with_key("GET", &uri, &marketing))).await.0,
            StatusCode::NOT_FOUND
        );
        let missing = with_key("GET", "/api/v1/messages/9999/check", TOKEN);
        assert_eq!(send(&app, empty(missing)).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn mcp_speaks_json_rpc_over_post_within_the_callers_inbox() {
        let (app, _store, billing, _marketing, invoice, promo) = two_inboxes().await;
        let call = |key: &str, name: &str, arguments: Value| {
            json_request(
                with_key("POST", "/mcp", key),
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}}),
            )
        };

        let (status, reply) = json(&app, call(&billing, "list_messages", json!({}))).await;
        assert_eq!(status, StatusCode::OK);
        let listed = &reply["result"]["structuredContent"];
        assert_eq!(listed["total"], 1);
        assert_eq!(listed["messages"][0]["id"], invoice);

        let (_, reply) = json(&app, call(&billing, "get_message", json!({"id": promo}))).await;
        assert_eq!(
            reply["result"]["isError"], true,
            "another inbox's message is out of reach"
        );

        let (_, reply) = json(&app, call(TOKEN, "list_messages", json!({}))).await;
        assert_eq!(
            reply["result"]["structuredContent"]["total"], 2,
            "the admin sees every inbox"
        );

        let note = json_request(
            with_key("POST", "/mcp", &billing),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        );
        assert_eq!(send(&app, note).await.0, StatusCode::ACCEPTED);
        assert_eq!(
            send(&app, empty(with_key("GET", "/mcp", &billing))).await.0,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

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
}
