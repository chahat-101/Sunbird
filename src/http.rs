//! Routes, handlers, and the error type. Each `ApiError` variant owns its
//! status code.

use std::fmt::Display;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

use crate::app::{App, FileId, Limits, MAX_BLOB, OwnerToken, PREVIEW_LEN};
use crate::config::{MemberId, mint_token, token_sha256};
use crate::counters::Counter;
use crate::db::Registration;
use crate::google::{SigninError, query_value};
use crate::limit;

pub type Body = BoxBody<Bytes, io::Error>;

/// Every way a request is refused.
#[derive(Debug)]
pub enum ApiError {
    /// Malformed, unknown and deleted IDs get the same answer.
    NotFound,
    NoOwnerToken,
    WrongOwnerToken,
    /// No upload token, or one no member has (banned members have none).
    NotAMember,
    /// No admin token, or one no admin in the config has.
    NotAnAdmin,
    /// The same for any ID: the limiter runs before the ID is read.
    RateLimited(u64),
    BadLimits(&'static str),
    /// The body stopped before it ended: the client went away.
    Incomplete,
    TooLarge,
    /// The member's quota, with the message naming the limit and when it frees.
    OverQuota(String),
    /// Free space is at the floor, min_free_bytes.
    LowDisk,
    /// The cause is logged where it happened; the client gets only this.
    Internal(&'static str),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::NoOwnerToken | ApiError::NotAMember | ApiError::NotAnAdmin => {
                StatusCode::UNAUTHORIZED
            }
            ApiError::WrongOwnerToken => StatusCode::FORBIDDEN,
            ApiError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::BadLimits(_) | ApiError::Incomplete => StatusCode::BAD_REQUEST,
            ApiError::TooLarge | ApiError::OverQuota(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::LowDisk => StatusCode::INSUFFICIENT_STORAGE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(&self) -> &str {
        match self {
            ApiError::NotFound => "not found",
            ApiError::NoOwnerToken => "owner token required",
            ApiError::WrongOwnerToken => "wrong owner token",
            ApiError::NotAMember => "a member's upload token is required",
            ApiError::NotAnAdmin => "an admin token is required",
            ApiError::RateLimited(_) => "too many requests",
            ApiError::OverQuota(why) => why,
            ApiError::BadLimits(why) | ApiError::Internal(why) => why,
            ApiError::Incomplete => "upload did not complete",
            ApiError::TooLarge => "upload is larger than the server accepts",
            ApiError::LowDisk => "the server is low on disk space; nothing was stored",
        }
    }

    fn into_response(self) -> Response<Body> {
        let mut res = json(
            self.status(),
            &serde_json::json!({ "error": self.message() }),
        );
        if let ApiError::RateLimited(seconds) = self {
            res.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        res
    }
}

/// Logs the cause and refuses with a 500 carrying only `message`.
fn internal<E: Display>(message: &'static str) -> impl FnOnce(E) -> ApiError {
    move |cause| {
        log::error!("{message}: {cause}");
        ApiError::Internal(message)
    }
}

/// Only the page's own scripts, styles and images, plus WebAssembly for
/// hash-wasm. A backstop in case hostile metadata is ever rendered as HTML.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
    style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Answers `req`, which came over a connection from `peer`.
pub async fn handle<B>(app: Arc<App>, peer: IpAddr, req: Request<B>) -> Response<Body>
where
    B: HttpBody<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Display,
{
    let mut res = route(app, peer, req)
        .await
        .unwrap_or_else(ApiError::into_response);
    let headers = res.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    // A link preview fetches the page; only the page's script fetches the blob
    // (PrivateBin's reason).
    headers.insert(header::VARY, HeaderValue::from_static("Accept"));
    res
}

async fn route<B>(app: Arc<App>, peer: IpAddr, req: Request<B>) -> Result<Response<Body>, ApiError>
where
    B: HttpBody<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Display,
{
    let path = req.uri().path().to_owned();
    let path = path.as_str();
    // As in Go's ServeMux, a GET route answers HEAD too; hyper sends no body.
    let get = matches!(*req.method(), Method::GET | Method::HEAD);
    match *req.method() {
        Method::POST if path == "/api/upload" => upload(app, req).await,
        _ if get && (path.starts_with("/api/meta/") || path.starts_with("/api/download/")) => {
            limit_read(&app, peer, req.headers())?;
            match path.strip_prefix("/api/meta/") {
                Some(id) => serve(app, id, PREVIEW_LEN, false).await,
                None => {
                    // A HEAD transfers nothing, so it claims nothing.
                    let claim = req.method() == Method::GET;
                    serve(app, &path["/api/download/".len()..], MAX_BLOB, claim).await
                }
            }
        }
        _ if get && path == "/auth/google" => {
            limit_read(&app, peer, req.headers())?;
            Ok(signin_start(&app))
        }
        _ if get && path == "/auth/google/callback" => {
            limit_read(&app, peer, req.headers())?;
            Ok(signin_finish(app, req.uri().query()).await)
        }
        _ if get && path == "/admin/stats" => stats(&app, bearer(&req)),
        Method::POST if path.starts_with("/api/admin/ban/") => {
            let token = bearer(&req).map(str::to_owned);
            admin_ban(app, &path["/api/admin/ban/".len()..], token).await
        }
        Method::DELETE if path.starts_with("/api/admin/") => {
            let token = bearer(&req).map(str::to_owned);
            admin_delete(app, &path["/api/admin/".len()..], token).await
        }
        Method::DELETE if path.starts_with("/api/") => {
            let token = bearer(&req).map(str::to_owned);
            delete(app, &path["/api/".len()..], token).await
        }
        _ if get => client_file(path).ok_or(ApiError::NotFound),
        _ => Err(ApiError::NotFound),
    }
}

/// Counted before anything else is read, so the limit reveals nothing about IDs.
fn limit_read(app: &App, peer: IpAddr, headers: &hyper::HeaderMap) -> Result<(), ApiError> {
    let client = limit::client(
        peer,
        headers.get_all("x-forwarded-for").iter(),
        &app.config.trusted_proxies,
    );
    app.read_limit.check(limit::bucket(client)).map_err(|wait| {
        app.counters.add(Counter::RateLimitedReads, 1);
        ApiError::RateLimited(wait)
    })
}

/// The token of an "Authorization: Bearer <token>" header.
fn bearer<B>(req: &Request<B>) -> Option<&str> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").filter(|t| !t.is_empty())
}

/// Runs filesystem and database work off the async workers.
async fn blocking<T: Send + 'static>(
    app: &Arc<App>,
    f: impl FnOnce(&App) -> T + Send + 'static,
) -> T {
    let app = app.clone();
    tokio::task::spawn_blocking(move || f(&app))
        .await
        .expect("a blocking task panicked")
}

// ---- upload -----------------------------------------------------------------

/// Cheap refusals first: token (401), rate (429), limits (400), size or
/// quota (413), disk floor (507). Then the body streams to tmp/, cut off at
/// the first limit it hits. The quota is checked once more when saving.
async fn upload<B>(app: Arc<App>, req: Request<B>) -> Result<Response<Body>, ApiError>
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: Display,
{
    let token = bearer(&req).ok_or(ApiError::NotAMember)?.to_owned();
    let member = blocking(&app, move |app| app.member(&token))
        .await
        .map_err(internal("could not check the token"))?
        .ok_or(ApiError::NotAMember)?;
    app.upload_limit.check(member.id.clone()).map_err(|wait| {
        app.counters.add(Counter::RateLimitedUploads, 1);
        ApiError::RateLimited(wait)
    })?;
    let limits = Limits::parse(req.uri().query(), (app.now)()).map_err(ApiError::BadLimits)?;

    // Anything past here that stores nothing counts as a failed upload, even if
    // shutdown drops it mid-await.
    let mut failed = FailedUpload(Some(app.clone()));
    let stored = receive(&app, req.into_body(), member, limits).await;
    match &stored {
        Ok(_) | Err(ApiError::TooLarge | ApiError::OverQuota(_)) => failed.0 = None,
        Err(ApiError::LowDisk) => {
            failed.0 = None;
            app.counters.add(Counter::UploadsRefusedLowDisk, 1);
        }
        Err(_) => {}
    }
    stored
}

/// Counts a failed upload when dropped, unless disarmed.
struct FailedUpload(Option<Arc<App>>);

impl Drop for FailedUpload {
    fn drop(&mut self) {
        if let Some(app) = &self.0 {
            app.counters.add(Counter::FailedUploads, 1);
        }
    }
}

/// Free space is checked at least this often while a body streams.
const DISK_CHECK_EVERY: u64 = 1 << 20;

/// The body of an upload that has passed the checks on its headers.
async fn receive<B>(
    app: &Arc<App>,
    mut body: B,
    member: crate::config::Member,
    limits: Limits,
) -> Result<Response<Body>, ApiError>
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: Display,
{
    // hyper's size hint is the declared Content-Length, exactly; 0 if none.
    let declared = body.size_hint().lower();
    if declared > MAX_BLOB {
        return Err(ApiError::TooLarge);
    }
    // The declared length must fit the quota. With none, an empty file must.
    let usage = blocking(app, {
        let id = member.id.clone();
        move |app| app.usage(&id)
    })
    .await
    .map_err(internal("could not check the quota"))?;
    let now = (app.now)();
    member
        .quota
        .admit(&usage, declared, now)
        .map_err(ApiError::OverQuota)?;
    let room = member.quota.room(&usage);
    // The declared length must fit above the disk floor.
    disk_room(app, declared).await?;

    let tmp = TempFile(app.temp_path());
    let mut file = tokio::fs::File::create_new(&tmp.0)
        .await
        .map_err(internal("could not store upload"))?;
    let mut size = 0u64;
    let mut unchecked = 0u64;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| {
            log::warn!("upload: aborted after {size} bytes: {e}");
            ApiError::Incomplete
        })?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        size += data.len() as u64;
        if size > MAX_BLOB {
            return Err(ApiError::TooLarge);
        }
        // The second check, for a body with no length or a false one.
        if size > room {
            return Err(match member.quota.admit(&usage, size, now) {
                Err(why) => ApiError::OverQuota(why),
                Ok(()) => ApiError::TooLarge,
            });
        }
        // Check the floor again before each MiB: other uploads share the disk.
        if unchecked + data.len() as u64 > DISK_CHECK_EVERY {
            let written = size - data.len() as u64;
            disk_room(app, declared.saturating_sub(written).max(data.len() as u64)).await?;
            unchecked = 0;
        }
        unchecked += data.len() as u64;
        file.write_all(&data)
            .await
            .map_err(internal("could not store upload"))?;
    }
    file.flush()
        .await
        .map_err(internal("could not store upload"))?;
    file.sync_all()
        .await
        .map_err(internal("could not store upload"))?;
    drop(file);

    let token = OwnerToken::random();
    let owner = token.hash();
    // tmp moves in, so its name is removed only once the link has been made.
    let id = blocking(app, move |app| {
        app.commit(&tmp.0, &owner, size, limits, &member)
    })
    .await
    .map_err(internal("could not store upload"))?
    .map_err(ApiError::OverQuota)?;
    app.counters.add(Counter::Uploads, 1);
    app.counters.add(Counter::BytesUploaded, size);
    Ok(json(
        StatusCode::CREATED,
        &serde_json::json!({ "id": id.to_string(), "ownerToken": token.as_str() }),
    ))
}

/// Refuses with 507 unless `more` bytes fit above the free-space floor.
async fn disk_room(app: &Arc<App>, more: u64) -> Result<(), ApiError> {
    let fits = blocking(app, move |app| app.disk_has_room(more))
        .await
        .map_err(internal("could not check free disk space"))?;
    if !fits {
        log::warn!("upload refused: free disk space is below min_free_bytes");
        return Err(ApiError::LowDisk);
    }
    Ok(())
}

/// The upload's temp file, removed on every path.
struct TempFile(std::path::PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.0)
            && e.kind() != io::ErrorKind::NotFound
        {
            log::error!("could not remove {}: {e}", self.0.display());
        }
    }
}

// ---- meta and download ------------------------------------------------------

/// Sends the first min(limit, size) bytes, raw; the server never looks inside
/// (§3). With `claim`, a download is claimed first and held until the end.
async fn serve(
    app: Arc<App>,
    id: &str,
    limit: u64,
    claim: bool,
) -> Result<Response<Body>, ApiError> {
    let id = FileId::parse(id).ok_or(ApiError::NotFound)?;
    let size = blocking(&app, {
        let id = id.clone();
        move |app| match claim {
            true => app.db().claim(&id, (app.now)()),
            false => Ok(app.db().size(&id, (app.now)())?),
        }
    })
    .await
    .map_err(internal("could not read blob"))?
    .ok_or(ApiError::NotFound)?;
    // From here every way out, a refusal included, ends the claim.
    let claim = claim.then(|| Claim {
        app: app.clone(),
        id: id.clone(),
        completed: false,
    });
    // A delete during streaming is fine on POSIX: the open file keeps the bytes.
    let file = match tokio::fs::File::open(app.blob_path(&id)).await {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ApiError::NotFound), // deleted since the query
        file => file.map_err(internal("could not read blob"))?,
    };
    let len = size.min(limit);
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, len)
        .body(
            Blob {
                file,
                left: len,
                claim,
            }
            .boxed(),
        )
        .expect("valid response"))
}

/// A claimed download: counted if completed, refunded if not.
struct Claim {
    app: Arc<App>,
    id: FileId,
    completed: bool,
}

impl Drop for Claim {
    fn drop(&mut self) {
        let (app, id, completed) = (self.app.clone(), self.id.clone(), self.completed);
        let end = move || app.end_download(&id, completed);
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => drop(runtime.spawn_blocking(end)),
            Err(_) => end(),
        }
    }
}

/// The first `left` bytes of a blob file, read as the connection takes them.
struct Blob {
    file: tokio::fs::File,
    left: u64,
    claim: Option<Claim>,
}

/// hyper drops the body when the response ends. Completed means every byte
/// was handed to hyper, not that the client received it (see deploy/README).
impl Drop for Blob {
    fn drop(&mut self) {
        if let Some(claim) = &mut self.claim {
            claim.completed = self.left == 0;
        }
    }
}

impl HttpBody for Blob {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        if this.left == 0 {
            return Poll::Ready(None);
        }
        let mut chunk = vec![0; this.left.min(64 * 1024) as usize];
        let mut buf = ReadBuf::new(&mut chunk);
        ready!(Pin::new(&mut this.file).poll_read(cx, &mut buf))?;
        let n = buf.filled().len();
        if n == 0 {
            // The file is shorter than the row says. End short so the client sees a
            // failed transfer.
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "blob shorter than its row",
            ))));
        }
        chunk.truncate(n);
        this.left -= n as u64;
        Poll::Ready(Some(Ok(Frame::data(chunk.into()))))
    }

    fn is_end_stream(&self) -> bool {
        self.left == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.left)
    }
}

// ---- delete -----------------------------------------------------------------

async fn delete(
    app: Arc<App>,
    id: &str,
    token: Option<String>,
) -> Result<Response<Body>, ApiError> {
    let id = FileId::parse(id).ok_or(ApiError::NotFound)?;
    let token = token.ok_or(ApiError::NoOwnerToken)?;
    blocking(&app, move |app| {
        let owner = app
            .db()
            .owner(&id, (app.now)())
            .map_err(internal("could not delete"))?
            .ok_or(ApiError::NotFound)?;
        if !owner.matches(&token) {
            return Err(ApiError::WrongOwnerToken);
        }
        if !app
            .db()
            .mark_deleting(&id)
            .map_err(internal("could not delete"))?
        {
            return Err(ApiError::NotFound); // a concurrent delete won
        }
        app.purge(&id).map_err(internal(
            "the file is no longer served, but deleting it failed",
        ))
    })
    .await?;
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(empty())
        .expect("valid response"))
}

/// `DELETE /api/admin/<id>`. Unlike the owner, an admin can delete a file that
/// has expired but not been swept yet.
async fn admin_delete(
    app: Arc<App>,
    id: &str,
    token: Option<String>,
) -> Result<Response<Body>, ApiError> {
    let admin = token
        .as_deref()
        .and_then(|token| app.config.admin(token))
        .cloned()
        .ok_or(ApiError::NotAnAdmin)?;
    let id = FileId::parse(id).ok_or(ApiError::NotFound)?;
    let deleted = blocking(&app, move |app| app.admin_delete(&admin, &id))
        .await
        .map_err(internal(
            "the file is no longer served, but deleting it failed",
        ))?;
    if !deleted {
        return Err(ApiError::NotFound);
    }
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(empty())
        .expect("valid response"))
}

/// `POST /api/admin/ban/<member id>`. Their files stay until they expire.
async fn admin_ban(
    app: Arc<App>,
    id: &str,
    token: Option<String>,
) -> Result<Response<Body>, ApiError> {
    let admin = token
        .as_deref()
        .and_then(|token| app.config.admin(token))
        .cloned()
        .ok_or(ApiError::NotAnAdmin)?;
    let id = MemberId::parse(id).ok_or(ApiError::NotFound)?;
    let banned = blocking(&app, {
        let id = id.clone();
        move |app| app.db().ban_google_member(&id)
    })
    .await
    .map_err(internal("could not ban"))?;
    if !banned {
        return Err(ApiError::NotFound);
    }
    log::warn!(
        "ADMIN BAN: admin {} ({}) banned member {id}",
        admin.id,
        admin.name
    );
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(empty())
        .expect("valid response"))
}

fn signin_start(app: &App) -> Response<Body> {
    let Some(google) = &app.config.google else {
        return signin_page(
            StatusCode::NOT_FOUND,
            "Sign-in with Google is not turned on for this server.",
            None,
        );
    };
    let Some((state, nonce)) = app.signin.begin((app.now)()) else {
        return signin_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many people are signing in right now. Try again in a few minutes.",
            None,
        );
    };
    Response::builder()
        .status(StatusCode::FOUND)
        .header(
            header::LOCATION,
            app.signin.redirect_url(google, &state, &nonce),
        )
        .body(empty())
        .expect("valid response")
}

/// `GET /auth/google/callback`: ends in a page showing a new token once.
async fn signin_finish(app: Arc<App>, query: Option<&str>) -> Response<Body> {
    use StatusCode as S;
    let Some(google) = &app.config.google else {
        return signin_page(
            S::NOT_FOUND,
            "Sign-in with Google is not turned on for this server.",
            None,
        );
    };
    let now = (app.now)();
    // Spent first, whatever else is wrong.
    let Some(nonce) = query_value(query, "state").and_then(|state| app.signin.take(&state, now))
    else {
        return signin_page(
            S::BAD_REQUEST,
            "This sign-in has expired or was already used. Start again from the upload page.",
            None,
        );
    };
    let Some(code) = query_value(query, "code") else {
        return signin_page(
            S::BAD_REQUEST,
            "Google did not sign you in, so no token was made. Start again from the upload page if you want one.",
            None,
        );
    };
    let sub = match app.signin.subject(google, &code, &nonce, now).await {
        Ok(sub) => sub,
        Err(SigninError::Unreachable(why)) => {
            log::error!("google sign-in: {why}");
            return signin_page(
                S::BAD_GATEWAY,
                "Could not finish signing in with Google. Try again later.",
                None,
            );
        }
        Err(SigninError::Rejected(why)) => {
            log::warn!("google sign-in refused: {why:?}");
            return signin_page(
                S::BAD_REQUEST,
                "Google's answer could not be verified, so no token was made.",
                None,
            );
        }
    };

    // All we keep of Google's answer.
    let sub_sha256: [u8; 32] = Sha256::digest(sub.as_bytes()).into();
    let token = mint_token();
    let token_sha256 = token_sha256(&token);
    let (new_id, max_members) = (MemberId::mint(), google.max_members);
    let registered = blocking(&app, move |app| {
        app.db()
            .register_google(&sub_sha256, &new_id, &token_sha256, max_members)
    })
    .await;
    match registered {
        Ok(Registration::New(id)) => {
            log::info!("google sign-in: new member {id}");
            signin_page(S::OK, "You are signed in. Your upload token:", Some(&token))
        }
        Ok(Registration::Returning(id)) => {
            log::info!("google sign-in: member {id} came back and got a new token");
            signin_page(
                S::OK,
                "Welcome back. Your upload token, which replaces your old one:",
                Some(&token),
            )
        }
        Ok(Registration::Banned) => {
            log::warn!("google sign-in: a banned member tried to sign in");
            signin_page(
                S::FORBIDDEN,
                "This account has been blocked from this server.",
                None,
            )
        }
        Ok(Registration::Full) => {
            log::warn!("google sign-in: refused, max_members ({max_members}) reached");
            signin_page(
                S::FORBIDDEN,
                "This server has reached the number of members it allows, so no new member can sign in. Ask its admin.",
                None,
            )
        }
        Err(e) => {
            log::error!("google sign-in: could not register: {e}");
            signin_page(
                S::INTERNAL_SERVER_ERROR,
                "Something went wrong on the server. No token was made.",
                None,
            )
        }
    }
}

/// Nothing here comes from the request, so nothing needs escaping.
fn signin_page(status: StatusCode, message: &str, token: Option<&str>) -> Response<Body> {
    let token_box = token.map_or(String::new(), |token| {
        format!(
            r#"<div class="token-box"><code id="owner-token">{token}</code>
<p>Copy it now. It is shown once and the server keeps only a fingerprint of it.
Paste it into the upload page. Signing in again gives a new token and cancels this one.</p></div>"#
        )
    });
    let page = format!(
        r#"<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
<title>Sunbird</title>
<link rel="stylesheet" href="/app.css">
<header class="masthead"><h1 class="wordmark">Sunbird</h1></header>
<main>
<section class="section"><p>{message}</p>
{token_box}
<p><a href="/">Go to the upload page</a></p></section>
</main>
"#
    );
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(page)).map_err(|e| match e {}).boxed())
        .expect("valid response")
}

// ---- stats ------------------------------------------------------------------

/// `GET /admin/stats`: totals only, never a file or a member.
fn stats(app: &App, token: Option<&str>) -> Result<Response<Body>, ApiError> {
    token
        .and_then(|token| app.config.admin(token))
        .ok_or(ApiError::NotAnAdmin)?;
    Ok(json(StatusCode::OK, &app.counters.json()))
}

// ---- client -----------------------------------------------------------------

/// The page, served at / and at /d/<anything>: the link a recipient opens.
const INDEX: &[u8] = include_bytes!("../web/index.html");

/// The only files served from web/. No tests, no listings.
const ASSETS: [(&str, &str, &[u8]); 9] = [
    (
        "/app.css",
        "text/css; charset=utf-8",
        include_bytes!("../web/app.css"),
    ),
    (
        "/src/app.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../web/src/app.js"),
    ),
    (
        "/src/crypto.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../web/src/crypto.js"),
    ),
    (
        "/src/argon2.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../web/src/argon2.js"),
    ),
    (
        "/src/argon2-worker.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../web/src/argon2-worker.js"),
    ),
    (
        "/vendor/hash-wasm/argon2.umd.min.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../web/vendor/hash-wasm/argon2.umd.min.js"),
    ),
    (
        "/vendor/hash-wasm/LICENSE",
        "text/plain; charset=utf-8",
        include_bytes!("../web/vendor/hash-wasm/LICENSE"),
    ),
    (
        "/assets/sunbird.webp",
        "image/webp",
        include_bytes!("../web/assets/sunbird.webp"),
    ),
    (
        "/assets/sunbird.jpg",
        "image/jpeg",
        include_bytes!("../web/assets/sunbird.jpg"),
    ),
];

fn client_file(path: &str) -> Option<Response<Body>> {
    let page = path == "/"
        || path
            .strip_prefix("/d/")
            .is_some_and(|id| !id.is_empty() && !id.contains('/'));
    let (content_type, bytes) = if page {
        ("text/html; charset=utf-8", INDEX)
    } else {
        ASSETS
            .iter()
            .find(|(p, ..)| *p == path)
            .map(|&(_, t, b)| (t, b))?
    };
    Some(
        Response::builder()
            .header(header::CONTENT_TYPE, content_type)
            .body(
                Full::new(Bytes::from_static(bytes))
                    .map_err(|e| match e {})
                    .boxed(),
            )
            .expect("valid response"),
    )
}

// ---- helpers ----------------------------------------------------------------

fn json(status: StatusCode, value: &serde_json::Value) -> Response<Body> {
    let mut text = value.to_string();
    text.push('\n');
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(text)).map_err(|e| match e {}).boxed())
        .expect("valid response")
}

fn empty() -> Body {
    Empty::new().map_err(|e| match e {}).boxed()
}

#[cfg(test)]
pub(crate) mod tests {
    //! Endpoint tests, driven through `handle`. The helpers are shared with the
    //! app and db tests.

    use std::fs;
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, Once};
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use http_body_util::BodyExt;
    use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
    use hyper::{HeaderMap, Request, StatusCode};
    use rusqlite::OptionalExtension;
    use sha2::{Digest, Sha256};

    use super::{Body, CONTENT_SECURITY_POLICY};
    use crate::app::{App, FileId, MAX_BLOB};
    use crate::config::{Config, hex, token_sha256};
    use crate::db::Error;

    // ---- helpers ------------------------------------------------------------

    /// A directory removed when the test ends.
    pub(crate) struct TempDir(pub(crate) PathBuf);

    impl TempDir {
        pub(crate) fn new() -> TempDir {
            let dir = std::env::temp_dir().join(format!("sunbird-test-{}", FileId::random().hex()));
            fs::create_dir(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) const MEMBER_ID: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    pub(crate) const MEMBER_TOKEN: &str = "member-token";
    pub(crate) const ADMIN_ID: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    pub(crate) const ADMIN_TOKEN: &str = "admin-token";
    /// More than any test stores or sends.
    pub(crate) const LOTS: u64 = 1 << 40;
    pub(crate) const NO_LIMIT: [u64; 3] = [LOTS, LOTS, LOTS];

    /// A member entry. `quota` is (bytes, files, bytes per week).
    pub(crate) fn member(id: &str, name: &str, token: &str, quota: [u64; 3]) -> serde_json::Value {
        serde_json::json!({
            "id": id, "name": name, "token_sha256": hex(&token_sha256(token)),
            "max_active_bytes": quota[0], "max_active_files": quota[1], "max_bytes_per_week": quota[2],
        })
    }

    /// A config with `members` and one admin, parsed like the real one.
    pub(crate) fn config(
        members: Vec<serde_json::Value>,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> Config {
        let mut c = serde_json::json!({
            "members": members,
            "admins": [{ "id": ADMIN_ID, "name": "the admin", "token_sha256": hex(&token_sha256(ADMIN_TOKEN)) }],
            "trusted_proxies": [],
            "upload_rate": { "requests": u32::MAX, "seconds": 1 },
            "read_rate": { "requests": u32::MAX, "seconds": 1 },
            "min_free_bytes": 0,
        });
        edit(&mut c);
        Config::parse(c.to_string().as_bytes()).unwrap()
    }

    /// One member with no practical limits, and the admin.
    pub(crate) fn test_config() -> Config {
        config(
            vec![member(MEMBER_ID, "member", MEMBER_TOKEN, NO_LIMIT)],
            |_| {},
        )
    }

    pub(crate) fn open(dir: &Path) -> Result<App, Error> {
        App::open(dir, test_config())
    }

    pub(crate) struct Server {
        pub(crate) app: Arc<App>,
        pub(crate) dir: TempDir,
    }

    pub(crate) fn server() -> Server {
        server_with(|_| {})
    }

    pub(crate) fn server_with(setup: impl FnOnce(&mut App)) -> Server {
        server_config(test_config(), setup)
    }

    /// A disk with more free than any test uses, unless a test sets its own.
    pub(crate) fn server_config(config: Config, setup: impl FnOnce(&mut App)) -> Server {
        let dir = TempDir::new();
        let mut app = App::open(&dir.0, config).unwrap();
        app.free_space = |_| Ok(LOTS);
        setup(&mut app);
        Server {
            app: Arc::new(app),
            dir,
        }
    }

    /// The same data directory, opened again under `config`: a restart.
    pub(crate) fn restart(s: Server, config: Config, setup: impl FnOnce(&mut App)) -> Server {
        let Server { app, dir } = s;
        drop(app);
        let mut app = App::open(&dir.0, config).unwrap();
        setup(&mut app);
        Server {
            app: Arc::new(app),
            dir,
        }
    }

    /// A request body: `len` zero bytes (None: endless), then the end or an
    /// error. `read` counts what the server pulled.
    pub(crate) struct Source {
        pub(crate) data: Vec<u8>,
        pub(crate) left: Option<u64>,
        pub(crate) declared: Option<u64>,
        pub(crate) fails: bool,
        pub(crate) read: Arc<AtomicU64>,
    }

    impl Source {
        pub(crate) fn bytes(data: &[u8]) -> Source {
            Source {
                data: data.to_vec(),
                left: Some(data.len() as u64),
                declared: Some(data.len() as u64),
                fails: false,
                read: Default::default(),
            }
        }
        pub(crate) fn zeros(len: Option<u64>, declared: Option<u64>) -> Source {
            Source {
                data: vec![],
                left: len,
                declared,
                fails: false,
                read: Default::default(),
            }
        }
        pub(crate) fn counter(&self) -> Arc<AtomicU64> {
            self.read.clone()
        }
    }

    impl HttpBody for Source {
        type Data = Bytes;
        type Error = &'static str;

        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            let n = this.left.unwrap_or(u64::MAX).min(64 * 1024);
            if n == 0 {
                return Poll::Ready(this.fails.then_some(Err("client went away")));
            }
            this.left = this.left.map(|l| l - n);
            let offset = this.read.fetch_add(n, Ordering::Relaxed) as usize;
            let chunk = match this.data.is_empty() {
                true => vec![0; n as usize],
                false => this.data[offset..offset + n as usize].to_vec(),
            };
            Poll::Ready(Some(Ok(Frame::data(chunk.into()))))
        }

        fn size_hint(&self) -> SizeHint {
            self.declared.map(SizeHint::with_exact).unwrap_or_default()
        }
    }

    pub(crate) struct Reply {
        pub(crate) status: StatusCode,
        pub(crate) headers: HeaderMap,
        pub(crate) body: Vec<u8>,
    }

    impl Reply {
        pub(crate) fn json(&self) -> serde_json::Value {
            serde_json::from_slice(&self.body).unwrap()
        }
    }

    /// Where requests come from unless a test says otherwise.
    pub(crate) const PEER: &str = "127.0.0.1";

    pub(crate) async fn send(
        s: &Server,
        method: &str,
        path: &str,
        body: Source,
        token: &str,
    ) -> Reply {
        send_from(s, PEER, &[], method, path, body, token).await
    }

    /// `send`, over a connection from `peer`, with X-Forwarded-For `forwarded`.
    pub(crate) async fn send_from(
        s: &Server,
        peer: &str,
        forwarded: &[&str],
        method: &str,
        path: &str,
        body: Source,
        token: &str,
    ) -> Reply {
        let mut req = Request::builder().method(method).uri(path);
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        for line in forwarded {
            req = req.header("X-Forwarded-For", *line);
        }
        let peer: IpAddr = peer.parse().unwrap();
        let res = super::handle(s.app.clone(), peer, req.body(body).unwrap()).await;
        let (parts, body) = res.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes().to_vec(),
        }
    }

    pub(crate) async fn get(s: &Server, path: &str) -> Reply {
        send(s, "GET", path, Source::bytes(b""), "").await
    }

    pub(crate) fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// An upload a day from expiring, with no download limit.
    pub(crate) fn live_path() -> String {
        format!("/api/upload?expires_at={}&max_downloads=0", now() + 86400)
    }

    pub(crate) struct Uploaded {
        pub(crate) id: String,
        pub(crate) owner_token: String,
    }

    pub(crate) async fn upload(s: &Server, blob: &[u8]) -> Uploaded {
        upload_with(s, &live_path(), blob).await
    }

    /// An upload to `path`, which carries its limits.
    pub(crate) async fn upload_with(s: &Server, path: &str, blob: &[u8]) -> Uploaded {
        let r = send(s, "POST", path, Source::bytes(blob), MEMBER_TOKEN).await;
        assert_eq!(
            r.status,
            StatusCode::CREATED,
            "upload: {}",
            String::from_utf8_lossy(&r.body)
        );
        let v = r.json();
        Uploaded {
            id: v["id"].as_str().unwrap().into(),
            owner_token: v["ownerToken"].as_str().unwrap().into(),
        }
    }

    pub(crate) fn random_blob(n: usize) -> Vec<u8> {
        let mut b = vec![0; n];
        getrandom::fill(&mut b).unwrap();
        b
    }

    pub(crate) fn entries(s: &Server, sub: &str) -> usize {
        fs::read_dir(s.dir.0.join(sub)).unwrap().count()
    }

    pub(crate) fn rows(s: &Server) -> i64 {
        s.app
            .db()
            .conn()
            .query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))
            .unwrap()
    }

    pub(crate) fn blob_exists(s: &Server, id: &str) -> bool {
        s.app.blob_path(&FileId::parse(id).unwrap()).exists()
    }

    /// A row's (downloads, in_flight, deleting), or None if it has none.
    pub(crate) fn counts(s: &Server, id: &str) -> Option<(i64, i64, i64)> {
        s.app
            .db()
            .conn()
            .query_row(
                "SELECT downloads, in_flight, deleting FROM blobs WHERE id = ?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .unwrap()
    }

    /// Wait up to 5 s for `done`: it's recorded after the body is dropped.
    pub(crate) async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting until {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    static LOGGED: Mutex<Vec<(log::Level, String)>> = Mutex::new(Vec::new());

    struct Capture;

    impl log::Log for Capture {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            LOGGED
                .lock()
                .unwrap()
                .push((record.level(), record.args().to_string()));
        }
        fn flush(&self) {}
    }

    /// Starts recording what is logged, from every test in the process.
    pub(crate) fn capture_logs() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            log::set_logger(&Capture).unwrap();
            log::set_max_level(log::LevelFilter::Info);
        });
    }

    /// What has been logged that mentions `needle`.
    pub(crate) fn logged(needle: &str) -> Vec<(log::Level, String)> {
        LOGGED
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, message)| message.contains(needle))
            .cloned()
            .collect()
    }

    pub(crate) fn user_version(db: &rusqlite::Connection) -> i64 {
        db.pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap()
    }

    // ---- endpoints ----------------------------------------------------------

    #[tokio::test]
    async fn upload_meta_download() {
        let s = server();
        let blob = random_blob(3 * 65536 + 100);
        let u = upload(&s, &blob).await;

        assert!(
            FileId::parse(&u.id).is_some(),
            "id {} is not 16 base64url characters of 96 bits",
            u.id
        );
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&u.owner_token).map(|b| b.len()),
            Ok(32),
            "owner token {}",
            u.owner_token
        );
        let other = upload(&s, &blob).await;
        assert!(
            other.id != u.id && other.owner_token != u.owner_token,
            "two uploads share an id or owner token"
        );

        let r = get(&s, &format!("/api/meta/{}", u.id)).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(
            r.body == blob[..8192],
            "meta: {} bytes; want the first 8192",
            r.body.len()
        );
        assert_eq!(r.headers["vary"], "Accept");
        let r = get(&s, &format!("/api/download/{}", u.id)).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(
            r.body == blob,
            "download: {} bytes; want all {}",
            r.body.len(),
            blob.len()
        );
        assert_eq!(r.headers["content-length"], "196708");
        assert_eq!(r.headers["vary"], "Accept");
    }

    /// Below 8 KiB the preview is the whole blob.
    #[tokio::test]
    async fn meta_of_short_blobs() {
        let s = server();
        for n in [0, 1, 622, 8191, 8192, 8193] {
            let blob = random_blob(n);
            let u = upload(&s, &blob).await;
            let r = get(&s, &format!("/api/meta/{}", u.id)).await;
            assert_eq!(r.status, StatusCode::OK);
            assert!(
                r.body == blob[..n.min(8192)],
                "{n}-byte blob: meta gave {} bytes",
                r.body.len()
            );
        }
    }

    #[tokio::test]
    async fn max_blob_enforced_while_streaming() {
        let s = server();

        // Exactly max_blob, streamed with no declared length: accepted.
        let r = send(
            &s,
            "POST",
            &live_path(),
            Source::zeros(Some(MAX_BLOB), None),
            MEMBER_TOKEN,
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "max_blob bytes");

        // One byte over, from an endless source: cut off, not read to the end.
        let body = Source::zeros(None, None);
        let read = body.counter();
        assert_eq!(
            send(&s, "POST", &live_path(), body, MEMBER_TOKEN)
                .await
                .status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "endless body"
        );
        let read = read.load(Ordering::Relaxed);
        assert!(
            read <= MAX_BLOB + 64 * 1024,
            "server read {read} bytes of an over-limit body"
        );

        // max_blob + 1 exactly, streamed.
        let r = send(
            &s,
            "POST",
            &live_path(),
            Source::zeros(Some(MAX_BLOB + 1), None),
            MEMBER_TOKEN,
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "max_blob + 1 bytes"
        );

        // A declared length over the limit is refused before any byte is read.
        let body = Source::zeros(None, Some(MAX_BLOB + 1));
        let read = body.counter();
        assert_eq!(
            send(&s, "POST", &live_path(), body, MEMBER_TOKEN)
                .await
                .status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "declared max_blob + 1"
        );
        assert_eq!(
            read.load(Ordering::Relaxed),
            0,
            "bytes read of a body declared too large"
        );

        assert_eq!(
            (entries(&s, "tmp"), entries(&s, "blobs"), rows(&s)),
            (0, 1, 1),
            "tmp, blobs, rows after rejected uploads"
        );
    }

    #[tokio::test]
    async fn aborted_upload_leaves_nothing() {
        let s = server();
        let body = Source {
            fails: true,
            ..Source::zeros(Some(200_000), Some(1_000_000))
        };
        assert_eq!(
            send(&s, "POST", &live_path(), body, MEMBER_TOKEN)
                .await
                .status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            (entries(&s, "tmp"), entries(&s, "blobs"), rows(&s)),
            (0, 0, 0),
            "tmp, blobs, rows after abort"
        );
    }

    #[tokio::test]
    async fn owner_token_is_not_stored() {
        let s = server();
        let u = upload(&s, &random_blob(1000)).await;
        let stored: Vec<u8> = s
            .app
            .db()
            .conn()
            .query_row(
                "SELECT owner_token_hash FROM blobs WHERE id = ?",
                [&u.id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            stored == Sha256::digest(u.owner_token.as_bytes())[..],
            "stored value is not SHA-256 of the owner token"
        );
        let raw = URL_SAFE_NO_PAD.decode(&u.owner_token).unwrap();
        for name in ["sunbird.db", "sunbird.db-wal"] {
            let Ok(b) = fs::read(s.dir.0.join(name)) else {
                continue;
            };
            let contains = |needle: &[u8]| b.windows(needle.len()).any(|w| w == needle);
            assert!(
                !contains(u.owner_token.as_bytes()) && !contains(&raw),
                "{name} contains the owner token"
            );
        }
    }

    #[tokio::test]
    async fn delete() {
        let s = server();
        let u = upload(&s, &random_blob(1000)).await;
        let other = upload(&s, &random_blob(1000)).await;
        let hash_as_token = URL_SAFE_NO_PAD.encode(Sha256::digest(u.owner_token.as_bytes()));
        for (why, token, want) in [
            ("no token", "", StatusCode::UNAUTHORIZED),
            (
                "wrong token",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                StatusCode::FORBIDDEN,
            ),
            (
                "another file's token",
                &other.owner_token,
                StatusCode::FORBIDDEN,
            ),
            (
                "the hash instead of the token",
                &hash_as_token,
                StatusCode::FORBIDDEN,
            ),
        ] {
            assert_eq!(
                send(
                    &s,
                    "DELETE",
                    &format!("/api/{}", u.id),
                    Source::bytes(b""),
                    token
                )
                .await
                .status,
                want,
                "{why}"
            );
        }
        assert_eq!(
            get(&s, &format!("/api/meta/{}", u.id)).await.status,
            StatusCode::OK,
            "refused deletes removed the file"
        );

        let r = send(
            &s,
            "DELETE",
            &format!("/api/{}", u.id),
            Source::bytes(b""),
            &u.owner_token,
        )
        .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "owner delete");
        for path in [
            format!("/api/meta/{}", u.id),
            format!("/api/download/{}", u.id),
        ] {
            assert_eq!(
                get(&s, &path).await.status,
                StatusCode::NOT_FOUND,
                "GET {path} after delete"
            );
        }
        assert!(
            !blob_exists(&s, &u.id),
            "blob file still present after delete"
        );
        assert_eq!(rows(&s), 1, "row still present after delete");
        let r = send(
            &s,
            "DELETE",
            &format!("/api/{}", u.id),
            Source::bytes(b""),
            &u.owner_token,
        )
        .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "second delete");
        assert_eq!(
            get(&s, &format!("/api/meta/{}", other.id)).await.status,
            StatusCode::OK,
            "the other file went too"
        );
    }

    #[tokio::test]
    async fn client_routes() {
        let s = server();
        let page = fs::read("web/index.html").unwrap();
        for path in ["/", "/d/AAAAAAAAAAAAAAAA", "/d/anything"] {
            let r = get(&s, path).await;
            assert_eq!(r.status, StatusCode::OK, "GET {path}");
            assert!(r.body == page, "GET {path}: not index.html");
            assert_eq!(
                r.headers["content-type"], "text/html; charset=utf-8",
                "GET {path}"
            );
            assert_eq!(
                r.headers["content-security-policy"], CONTENT_SECURITY_POLICY,
                "GET {path}"
            );
            assert_eq!(r.headers["vary"], "Accept", "GET {path}");
        }
        for (path, content_type) in [
            ("/app.css", "text/css; charset=utf-8"),
            ("/src/app.js", "text/javascript; charset=utf-8"),
            ("/src/crypto.js", "text/javascript; charset=utf-8"),
            ("/src/argon2.js", "text/javascript; charset=utf-8"),
            ("/src/argon2-worker.js", "text/javascript; charset=utf-8"),
            (
                "/vendor/hash-wasm/argon2.umd.min.js",
                "text/javascript; charset=utf-8",
            ),
            ("/vendor/hash-wasm/LICENSE", "text/plain; charset=utf-8"),
            ("/assets/sunbird.webp", "image/webp"),
            ("/assets/sunbird.jpg", "image/jpeg"),
        ] {
            let r = get(&s, path).await;
            assert_eq!(r.status, StatusCode::OK, "GET {path}");
            assert_eq!(r.headers["content-type"], content_type, "GET {path}");
            assert!(
                r.body == fs::read(format!("web{path}")).unwrap(),
                "GET {path}: not the file in web/"
            );
        }
        for path in [
            "/test/crypto.html",
            "/web.go",
            "/src/",
            "/vendor/hash-wasm/",
            "/index.html/x",
            "/d/",
            "/d/a/b",
        ] {
            assert_eq!(
                get(&s, path).await.status,
                StatusCode::NOT_FOUND,
                "GET {path}"
            );
        }
    }

    #[tokio::test]
    async fn malformed_ids() {
        let s = server();
        let u = upload(&s, &random_blob(100)).await;
        for id in [
            "short".to_owned(),
            format!("{}A", u.id),          // 17 characters
            format!("{}+", &u.id[..15]),   // standard base64 alphabet
            format!("{}=", &u.id[..15]),   // padding
            "..%2F..%2Fblobs".to_owned(),  // path syntax
            "0123456789abcdef".to_owned(), // well-formed but never issued
        ] {
            for (method, prefix) in [
                ("GET", "/api/meta/"),
                ("GET", "/api/download/"),
                ("DELETE", "/api/"),
            ] {
                let r = send(
                    &s,
                    method,
                    &format!("{prefix}{id}"),
                    Source::bytes(b""),
                    &u.owner_token,
                )
                .await;
                assert_eq!(r.status, StatusCode::NOT_FOUND, "{method} {prefix}{id}");
            }
        }
    }

    /// Limits are checked against the server's clock before the body, and
    /// refused, not clamped.
    #[tokio::test]
    async fn upload_limits() {
        const NOW: i64 = 1_800_000_000;
        const WEEK: i64 = 604800;
        const MARGIN: i64 = 300;
        let s = server_with(|app| app.now = || NOW);
        let q = |e: &dyn std::fmt::Display, m: &dyn std::fmt::Display| {
            format!("/api/upload?expires_at={e}&max_downloads={m}")
        };

        let accepted = [
            ("one second ahead", q(&(NOW + 1), &1), NOW + 1, 1),
            ("exactly 7 days ahead", q(&(NOW + WEEK), &1), NOW + WEEK, 1),
            ("no download limit", q(&(NOW + 3600), &0), NOW + 3600, 0),
            (
                "the largest u32 download limit",
                q(&(NOW + 3600), &4294967295u32),
                NOW + 3600,
                4294967295,
            ),
            (
                "device clock 299 s fast, 7 days less the margin",
                q(&(NOW + 299 + WEEK - MARGIN), &1),
                NOW + 299 + WEEK - MARGIN,
                1,
            ),
        ];
        for (why, path, expires_at, limit) in &accepted {
            let r = send(&s, "POST", path, Source::bytes(b"blob"), MEMBER_TOKEN).await;
            assert_eq!(
                r.status,
                StatusCode::CREATED,
                "{why}: {}",
                String::from_utf8_lossy(&r.body)
            );
            let id = r.json()["id"].as_str().unwrap().to_owned();
            let stored: (i64, i64) = s
                .app
                .db()
                .conn()
                .query_row(
                    "SELECT expires_at, max_downloads FROM blobs WHERE id = ?",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                stored,
                (*expires_at, *limit),
                "{why}: stored limits changed"
            );
        }

        let too_late = "expires_at is more than 7 days after the server's clock. Your device's clock may be wrong.";
        let too_early =
            "expires_at is not after the server's clock. Your device's clock may be wrong.";
        let refused = [
            (
                "7 days and one second ahead",
                q(&(NOW + WEEK + 1), &1),
                too_late,
            ),
            (
                "device clock 301 s fast, 7 days less the margin",
                q(&(NOW + 301 + WEEK - MARGIN), &1),
                too_late,
            ),
            ("the largest u64", q(&u64::MAX, &1), too_late),
            (
                "expires_at equal to the server's clock",
                q(&NOW, &1),
                too_early,
            ),
            ("an hour in the past", q(&(NOW - 3600), &1), too_early),
            ("zero", q(&0, &1), too_early),
            (
                "device clock 3601 s slow, 1 hour",
                q(&(NOW - 3601 + 3600), &1),
                too_early,
            ),
            (
                "missing expires_at",
                "/api/upload?max_downloads=1".into(),
                "expires_at must be given once",
            ),
            (
                "missing max_downloads",
                format!("/api/upload?expires_at={}", NOW + 3600),
                "max_downloads must be given once",
            ),
            (
                "no parameters",
                "/api/upload".into(),
                "expires_at must be given once",
            ),
            (
                "expires_at twice",
                format!("{}&expires_at={}", q(&(NOW + 3600), &1), NOW + 3600),
                "expires_at must be given once",
            ),
            (
                "expires_at with a leading zero",
                q(&format!("0{}", NOW + 3600), &1),
                "expires_at must be given once",
            ),
            (
                "expires_at with a sign",
                q(&format!("%2B{}", NOW + 3600), &1),
                "expires_at must be given once",
            ),
            (
                "expires_at negative",
                q(&-1, &1),
                "expires_at must be given once",
            ),
            (
                "expires_at in hex",
                q(&"0x6B49D200", &1),
                "expires_at must be given once",
            ),
            (
                "max_downloads over u32",
                q(&(NOW + 3600), &4294967296u64),
                "max_downloads must be given once",
            ),
            (
                "max_downloads negative",
                q(&(NOW + 3600), &-1),
                "max_downloads must be given once",
            ),
            (
                "max_downloads empty",
                q(&(NOW + 3600), &""),
                "max_downloads must be given once",
            ),
        ];
        for (why, path, message) in &refused {
            let body = Source::bytes(b"blob");
            let read = body.counter();
            let r = send(&s, "POST", path, body, MEMBER_TOKEN).await;
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "{why}");
            let error = r.json()["error"].as_str().unwrap().to_owned();
            assert!(
                error.starts_with(message),
                "{why}: message {error:?}, want {message:?}"
            );
            assert_eq!(
                read.load(Ordering::Relaxed),
                0,
                "{why}: bytes read of a refused upload"
            );
        }
        let n = accepted.len();
        assert_eq!(
            (rows(&s), entries(&s, "blobs"), entries(&s, "tmp")),
            (n as i64, n, 0),
            "rows, blobs, tmp"
        );
    }

    // ---- expiry -------------------------------------------------------------

    fn limits_path(expires_at: i64, max_downloads: u32) -> String {
        format!("/api/upload?expires_at={expires_at}&max_downloads={max_downloads}")
    }

    /// A download whose body hasn't been read yet.
    async fn start_download(s: &Server, id: &str) -> Body {
        let req = Request::get(format!("/api/download/{id}"))
            .body(Source::bytes(b""))
            .unwrap();
        let res = super::handle(s.app.clone(), PEER.parse().unwrap(), req).await;
        assert_eq!(res.status(), StatusCode::OK, "start download");
        res.into_body()
    }

    /// Sixteen parallel downloads of a one-download file: exactly one wins, and
    /// the file is deleted. A separate check-then-claim loses this quickly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn last_download_race() {
        const ROUNDS: usize = 100;
        const RACERS: usize = 16;
        let s = Arc::new(server());
        for round in 0..ROUNDS {
            let blob = random_blob(1000);
            let u = upload_with(&s, &limits_path(now() + 3600, 1), &blob).await;
            let path = format!("/api/download/{}", u.id);
            let racers: Vec<_> = (0..RACERS)
                .map(|_| {
                    let (s, path) = (s.clone(), path.clone());
                    tokio::spawn(async move { get(&s, &path).await })
                })
                .collect();
            let mut served = 0;
            for racer in racers {
                let r = racer.await.unwrap();
                match r.status {
                    StatusCode::OK => {
                        assert!(r.body == blob, "round {round}: served the wrong bytes");
                        served += 1;
                    }
                    StatusCode::NOT_FOUND => {}
                    other => panic!("round {round}: {other}"),
                }
            }
            assert_eq!(
                served, 1,
                "round {round}: downloads served of a 1-download file"
            );
            wait_until("the used-up file is deleted", || {
                counts(&s, &u.id).is_none()
            })
            .await;
            assert!(
                !blob_exists(&s, &u.id),
                "round {round}: blob outlived its row"
            );
        }
    }

    /// A transfer that stops partway is refunded. A file isn't deleted while
    /// another download is still in flight.
    #[tokio::test]
    async fn aborted_download_is_refunded() {
        let s = server();
        let blob = random_blob(5 * 65536);
        let u = upload_with(&s, &limits_path(now() + 3600, 1), &blob).await;
        let download = format!("/api/download/{}", u.id);

        let r = send(&s, "HEAD", &download, Source::bytes(b""), "").await;
        assert_eq!(r.status, StatusCode::OK, "HEAD");
        wait_until("nothing is in flight", || {
            counts(&s, &u.id) == Some((0, 0, 0))
        })
        .await;

        // The client goes away after one chunk: hyper drops the body.
        let mut body = start_download(&s, &u.id).await;
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert!(first.len() < blob.len());
        assert_eq!(counts(&s, &u.id), Some((1, 1, 0)), "claimed, in flight");
        assert_eq!(
            get(&s, &download).await.status,
            StatusCode::NOT_FOUND,
            "a second download while the only one is in flight"
        );
        drop(body);
        wait_until("the aborted transfer ends", || {
            counts(&s, &u.id) != Some((1, 1, 0))
        })
        .await;
        assert_eq!(
            counts(&s, &u.id),
            Some((0, 0, 0)),
            "after the abort: refunded"
        );
        assert!(
            blob_exists(&s, &u.id),
            "blob deleted by an aborted transfer"
        );

        let r = get(&s, &download).await;
        assert!(
            r.status == StatusCode::OK && r.body == blob,
            "download after a refund: {}",
            r.status
        );
        wait_until("the used-up file is deleted", || {
            counts(&s, &u.id).is_none()
        })
        .await;
        assert!(!blob_exists(&s, &u.id));

        // Two in flight: one completes and uses the file up, the other fails and
        // gives one back.
        let u = upload_with(&s, &limits_path(now() + 3600, 2), &blob).await;
        let download = format!("/api/download/{}", u.id);
        let (mut a, b) = (
            start_download(&s, &u.id).await,
            start_download(&s, &u.id).await,
        );
        assert_eq!(
            get(&s, &download).await.status,
            StatusCode::NOT_FOUND,
            "a third claim"
        );
        let mut got = Vec::new();
        while let Some(frame) = a.frame().await {
            got.extend_from_slice(&frame.unwrap().into_data().unwrap());
        }
        drop(a);
        assert!(got == blob);
        wait_until("the completed transfer ends", || {
            counts(&s, &u.id) == Some((2, 1, 0))
        })
        .await;
        assert!(
            blob_exists(&s, &u.id),
            "deleted while a download was in flight"
        );
        drop(b);
        wait_until("the aborted transfer ends", || {
            counts(&s, &u.id) == Some((1, 0, 0))
        })
        .await;
        let r = get(&s, &download).await;
        assert!(
            r.status == StatusCode::OK && r.body == blob,
            "the refunded download: {}",
            r.status
        );
        wait_until("the used-up file is deleted", || {
            counts(&s, &u.id).is_none()
        })
        .await;
    }

    /// max_downloads 0 is no download limit, not zero downloads.
    #[tokio::test]
    async fn no_download_limit() {
        let s = server();
        let blob = random_blob(1000);
        let u = upload_with(&s, &limits_path(now() + 3600, 0), &blob).await;
        for i in 0..50 {
            let r = get(&s, &format!("/api/download/{}", u.id)).await;
            assert!(
                r.status == StatusCode::OK && r.body == blob,
                "download {i}: {}",
                r.status
            );
        }
        wait_until("every transfer ends", || {
            counts(&s, &u.id) == Some((50, 0, 0))
        })
        .await;
        assert_eq!(s.app.sweep().unwrap(), (0, 0), "sweep");
        assert_eq!(
            get(&s, &format!("/api/meta/{}", u.id)).await.status,
            StatusCode::OK,
            "after 50 downloads and a sweep"
        );
    }

    /// Expired or used up files look exactly like unknown IDs, before any sweep.
    #[tokio::test]
    async fn spent_files_are_not_found() {
        const T0: i64 = 1_800_000_000;
        static CLOCK: AtomicI64 = AtomicI64::new(T0);
        let s = server_with(|app| app.now = || CLOCK.load(Ordering::Relaxed));
        let blob = random_blob(1000);
        let expiring = upload_with(&s, &limits_path(T0 + 3600, 0), &blob).await;
        let used = upload_with(&s, &limits_path(T0 + 7200, 1), &blob).await;
        CLOCK.store(T0 + 3599, Ordering::Relaxed);
        assert_eq!(
            get(&s, &format!("/api/meta/{}", expiring.id)).await.status,
            StatusCode::OK,
            "a second before expires_at"
        );
        CLOCK.store(T0 + 3600, Ordering::Relaxed);
        // Its one download, claimed and not yet ended.
        let in_flight = start_download(&s, &used.id).await;

        let never = FileId::random().to_string();
        let answer = |r: Reply| {
            (
                r.status,
                r.body,
                r.headers.get("content-type").cloned(),
                r.headers.get("vary").cloned(),
            )
        };
        for (method, prefix) in [
            ("GET", "/api/meta/"),
            ("HEAD", "/api/meta/"),
            ("GET", "/api/download/"),
            ("HEAD", "/api/download/"),
            ("DELETE", "/api/"),
        ] {
            let want = answer(
                send(
                    &s,
                    method,
                    &format!("{prefix}{never}"),
                    Source::bytes(b""),
                    "x",
                )
                .await,
            );
            assert_eq!(want.0, StatusCode::NOT_FOUND);
            for (what, u) in [("expired", &expiring), ("used up", &used)] {
                let r = send(
                    &s,
                    method,
                    &format!("{prefix}{}", u.id),
                    Source::bytes(b""),
                    &u.owner_token,
                )
                .await;
                assert!(
                    answer(r) == want,
                    "{method} {prefix}: {what} is told apart from never issued"
                );
            }
        }
        assert!(
            blob_exists(&s, &expiring.id) && counts(&s, &expiring.id).is_some(),
            "the expired file was deleted without a sweep"
        );
        drop(in_flight);
    }

    // ---- auth ---------------------------------------------------------------

    const OTHER_ID: &str = "AgICAgICAgICAgICAgICAg";
    const OTHER_TOKEN: &str = "other-token";

    fn uploader_of(s: &Server, id: &str) -> Option<String> {
        s.app
            .db()
            .conn()
            .query_row("SELECT uploader_id FROM blobs WHERE id = ?", [id], |r| {
                r.get(0)
            })
            .unwrap()
    }

    fn ledger(s: &Server) -> i64 {
        s.app
            .db()
            .conn()
            .query_row("SELECT COUNT(*) FROM uploads", [], |r| r.get(0))
            .unwrap()
    }

    /// Bad, hashed or admin tokens are all 401 before the body is read. A removed
    /// member's token stops working, but their files stay recorded as theirs.
    #[tokio::test]
    async fn upload_requires_a_members_token() {
        let s = server();
        let hash = hex(&token_sha256(MEMBER_TOKEN));
        let refused = [
            ("no token", ""),
            ("a wrong token", "not-a-member-token"),
            ("the token's hash", hash.as_str()),
            ("an admin token", ADMIN_TOKEN),
            ("the token with a character dropped", &MEMBER_TOKEN[1..]),
        ];
        for (why, token) in refused {
            let body = Source::bytes(b"blob");
            let read = body.counter();
            let r = send(&s, "POST", &live_path(), body, token).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{why}");
            assert_eq!(read.load(Ordering::Relaxed), 0, "{why}: bytes read");
        }
        assert_eq!(
            (
                rows(&s),
                ledger(&s),
                entries(&s, "blobs"),
                entries(&s, "tmp")
            ),
            (0, 0, 0, 0),
            "rows, ledger, blobs, tmp after refused uploads"
        );

        let blob = random_blob(100);
        let u = upload(&s, &blob).await;
        assert_eq!(uploader_of(&s, &u.id).as_deref(), Some(MEMBER_ID));
        let s = restart(
            s,
            config(
                vec![member(OTHER_ID, "member", OTHER_TOKEN, NO_LIMIT)],
                |_| {},
            ),
            |_| {},
        );
        let r = send(&s, "POST", &live_path(), Source::bytes(b"x"), MEMBER_TOKEN).await;
        assert_eq!(
            r.status,
            StatusCode::UNAUTHORIZED,
            "a removed member's token"
        );
        let r = get(&s, &format!("/api/download/{}", u.id)).await;
        assert!(
            r.status == StatusCode::OK && r.body == blob,
            "a removed member's file"
        );
        assert_eq!(uploader_of(&s, &u.id).as_deref(), Some(MEMBER_ID));
    }

    /// A rename changes only the display name; files and quota stay with the id.
    #[tokio::test]
    async fn renamed_member_keeps_their_quota() {
        let two_files = [LOTS, 2, LOTS];
        let s = server_config(
            config(
                vec![member(MEMBER_ID, "Alice", MEMBER_TOKEN, two_files)],
                |_| {},
            ),
            |_| {},
        );
        let a = upload(&s, &random_blob(10)).await;
        let b = upload(&s, &random_blob(10)).await;
        let s = restart(
            s,
            config(
                vec![member(MEMBER_ID, "Alice Smith", MEMBER_TOKEN, two_files)],
                |_| {},
            ),
            |_| {},
        );
        let r = send(&s, "POST", &live_path(), Source::bytes(b"x"), MEMBER_TOKEN).await;
        assert_eq!(
            r.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "a third file after the rename"
        );
        let error = r.json()["error"].as_str().unwrap().to_owned();
        assert!(
            error.starts_with("You have 2 files stored, and your limit is 2 at once."),
            "{error}"
        );
        for u in [&a, &b] {
            assert_eq!(uploader_of(&s, &u.id).as_deref(), Some(MEMBER_ID));
        }
    }

    /// Reusing a departed member's name gives a new id, with none of their quota
    /// or files.
    #[tokio::test]
    async fn reused_name_inherits_nothing() {
        capture_logs();
        let quota = [1000, LOTS, LOTS];
        let s = server_config(
            config(vec![member(MEMBER_ID, "Sam", MEMBER_TOKEN, quota)], |_| {}),
            |_| {},
        );
        let departed = upload(&s, &random_blob(1000)).await;
        let s = restart(
            s,
            config(vec![member(OTHER_ID, "Sam", OTHER_TOKEN, quota)], |_| {}),
            |_| {},
        );
        let r = send(
            &s,
            "POST",
            &live_path(),
            Source::bytes(&random_blob(1000)),
            OTHER_TOKEN,
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::CREATED,
            "the new Sam's first 1000 bytes"
        );
        let new = r.json()["id"].as_str().unwrap().to_owned();
        let r = send(&s, "POST", &live_path(), Source::bytes(b"x"), OTHER_TOKEN).await;
        assert_eq!(
            r.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "the new Sam's own usage counts"
        );

        for (file, uploader, not) in [
            (&departed.id, MEMBER_ID, OTHER_ID),
            (&new, OTHER_ID, MEMBER_ID),
        ] {
            let r = send(
                &s,
                "DELETE",
                &format!("/api/admin/{file}"),
                Source::bytes(b""),
                ADMIN_TOKEN,
            )
            .await;
            assert_eq!(r.status, StatusCode::NO_CONTENT, "admin delete");
            let said = logged(file);
            assert_eq!(said.len(), 1, "log lines naming {file}: {said:?}");
            let (level, line) = &said[0];
            assert!(
                *level == log::Level::Warn
                    && line.starts_with("ADMIN DELETE:")
                    && line.contains(ADMIN_ID)
                    && line.contains(&format!("uploaded by member {uploader}"))
                    && !line.contains(not),
                "{line}"
            );
        }
        let (_, line) = &logged(&departed.id)[0];
        assert!(line.contains("no longer in the config"), "{line}");
    }

    /// Only an admin can delete by id, even an expired unswept file. Deletion is
    /// verified, and the log names the admin, the file and the uploader.
    #[tokio::test]
    async fn admin_delete() {
        const T0: i64 = 1_800_000_000;
        static CLOCK: AtomicI64 = AtomicI64::new(T0);
        capture_logs();
        let s = server_with(|app| app.now = || CLOCK.load(Ordering::Relaxed));
        let u = upload_with(&s, &limits_path(T0 + 60, 0), &random_blob(1000)).await;
        let other = upload_with(&s, &limits_path(T0 + 3600, 0), &random_blob(1000)).await;
        let path = format!("/api/admin/{}", u.id);
        for (why, token) in [
            ("no token", ""),
            ("a member's token", MEMBER_TOKEN),
            ("the file's owner token", u.owner_token.as_str()),
            ("a wrong token", "not-the-admin-token"),
        ] {
            let r = send(&s, "DELETE", &path, Source::bytes(b""), token).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{why}");
        }
        assert!(
            blob_exists(&s, &u.id),
            "a refused admin delete removed the file"
        );
        assert!(
            logged(&u.id).is_empty(),
            "a refused admin delete was logged as one"
        );

        CLOCK.store(T0 + 60, Ordering::Relaxed);
        let r = send(
            &s,
            "DELETE",
            &format!("/api/{}", u.id),
            Source::bytes(b""),
            &u.owner_token,
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::NOT_FOUND,
            "the owner, once it has expired"
        );
        for id in [FileId::random().to_string(), "not-an-id".into()] {
            let r = send(
                &s,
                "DELETE",
                &format!("/api/admin/{id}"),
                Source::bytes(b""),
                ADMIN_TOKEN,
            )
            .await;
            assert_eq!(r.status, StatusCode::NOT_FOUND, "admin delete of {id}");
        }
        let r = send(&s, "DELETE", &path, Source::bytes(b""), ADMIN_TOKEN).await;
        assert_eq!(
            r.status,
            StatusCode::NO_CONTENT,
            "admin delete of an expired, unswept file"
        );
        assert!(
            !blob_exists(&s, &u.id) && counts(&s, &u.id).is_none(),
            "blob or row left after the admin delete"
        );
        let said = logged(&u.id);
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(
            said[0].1,
            format!(
                "ADMIN DELETE: admin {ADMIN_ID} (the admin) deleted file {}, uploaded by member {MEMBER_ID} (member)",
                u.id
            )
        );
        let r = send(&s, "DELETE", &path, Source::bytes(b""), ADMIN_TOKEN).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "a second admin delete");
        assert_eq!(
            get(&s, &format!("/api/meta/{}", other.id)).await.status,
            StatusCode::OK,
            "another file went too"
        );
    }

    // ---- quotas -------------------------------------------------------------

    const T0: i64 = 1_800_000_000;

    fn error_of(r: &Reply) -> String {
        r.json()["error"].as_str().unwrap().to_owned()
    }

    /// Quota is freed when a file expires or is deleted, not at the next sweep.
    #[tokio::test]
    async fn active_bytes_freed_by_expiry_and_deletion() {
        static CLOCK: AtomicI64 = AtomicI64::new(T0);
        let s = server_config(
            config(
                vec![member(MEMBER_ID, "m", MEMBER_TOKEN, [1000, LOTS, LOTS])],
                |_| {},
            ),
            |app| app.now = || CLOCK.load(Ordering::Relaxed),
        );
        let first = upload_with(&s, &limits_path(T0 + 600, 0), &random_blob(800)).await;
        let path = limits_path(T0 + 3600, 0);
        let r = send(
            &s,
            "POST",
            &path,
            Source::bytes(&random_blob(800)),
            MEMBER_TOKEN,
        )
        .await;
        assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            error_of(&r),
            "Your files take 800 of your 1000 bytes stored at once. \
             Enough frees in 10 minutes as your files expire, or sooner if you delete some."
        );

        CLOCK.store(T0 + 600, Ordering::Relaxed);
        assert!(
            counts(&s, &first.id).is_some(),
            "swept: this test is about expiry alone"
        );
        let second = upload_with(&s, &path, &random_blob(800)).await;

        let r = send(
            &s,
            "POST",
            &path,
            Source::bytes(&random_blob(800)),
            MEMBER_TOKEN,
        )
        .await;
        assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE, "full again");
        let r = send(
            &s,
            "DELETE",
            &format!("/api/{}", second.id),
            Source::bytes(b""),
            &second.owner_token,
        )
        .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        upload_with(&s, &path, &random_blob(800)).await;
    }

    /// The weekly allowance comes from the upload ledger, so deleting a file
    /// doesn't refund it.
    #[tokio::test]
    async fn weekly_bytes_not_freed_by_deletion() {
        static CLOCK: AtomicI64 = AtomicI64::new(T0);
        let s = server_config(
            config(
                vec![member(MEMBER_ID, "m", MEMBER_TOKEN, [LOTS, LOTS, 1000])],
                |_| {},
            ),
            |app| app.now = || CLOCK.load(Ordering::Relaxed),
        );
        let path = || limits_path(CLOCK.load(Ordering::Relaxed) + 3600, 0);
        let u = upload_with(&s, &path(), &random_blob(800)).await;
        let r = send(
            &s,
            "DELETE",
            &format!("/api/{}", u.id),
            Source::bytes(b""),
            &u.owner_token,
        )
        .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        assert_eq!(
            (rows(&s), ledger(&s)),
            (0, 1),
            "rows, ledger after the delete"
        );

        let want = "You have uploaded 800 of your 1000 bytes allowed per 7 days. \
                    Enough frees in 7 days as your earlier uploads pass 7 days old. \
                    Deleting files does not give any back.";
        let r = send(
            &s,
            "POST",
            &path(),
            Source::bytes(&random_blob(800)),
            MEMBER_TOKEN,
        )
        .await;
        assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE, "after the delete");
        assert_eq!(error_of(&r), want);
        CLOCK.store(T0 + WEEK - 1, Ordering::Relaxed);
        let r = send(
            &s,
            "POST",
            &path(),
            Source::bytes(&random_blob(800)),
            MEMBER_TOKEN,
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "a second short of 7 days"
        );
        assert!(
            error_of(&r).contains("Enough frees in 1 second"),
            "{}",
            error_of(&r)
        );
        CLOCK.store(T0 + WEEK, Ordering::Relaxed);
        upload_with(&s, &path(), &random_blob(800)).await;

        let r = send(
            &s,
            "POST",
            &path(),
            Source::bytes(&random_blob(1001)),
            MEMBER_TOKEN,
        )
        .await;
        assert_eq!(
            error_of(&r),
            "This upload is larger than your limit of 1000 bytes uploaded per 7 days."
        );
    }

    const WEEK: i64 = crate::config::WEEK;

    /// Refused as early as possible, by whichever limit is smaller. Nothing is
    /// stored.
    #[tokio::test]
    async fn stream_cut_off_at_the_quota() {
        let s = server_config(
            config(
                vec![
                    member(MEMBER_ID, "m", MEMBER_TOKEN, [100_000, LOTS, LOTS]),
                    member(OTHER_ID, "o", OTHER_TOKEN, [LOTS, LOTS, 50_000]),
                ],
                |_| {},
            ),
            |_| {},
        );
        let s = &s;
        let endless = |token| async move {
            let body = Source::zeros(None, None);
            let read = body.counter();
            let r = send(s, "POST", &live_path(), body, token).await;
            (r, read.load(Ordering::Relaxed))
        };

        let (r, read) = endless(MEMBER_TOKEN).await;
        assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            error_of(&r),
            "This upload is larger than your limit of 100000 bytes stored at once."
        );
        assert!(
            read <= 100_000 + 64 * 1024,
            "read {read} bytes of a body over the quota"
        );

        upload(s, &random_blob(60_000)).await;
        let (r, read) = endless(MEMBER_TOKEN).await;
        assert!(
            error_of(&r).starts_with("Your files take 60000 of your 100000 bytes"),
            "{}",
            error_of(&r)
        );
        assert!(
            read <= 40_000 + 64 * 1024,
            "read {read} bytes with 40000 of room"
        );

        let (r, read) = endless(OTHER_TOKEN).await;
        assert_eq!(
            error_of(&r),
            "This upload is larger than your limit of 50000 bytes uploaded per 7 days."
        );
        assert!(
            read <= 50_000 + 64 * 1024,
            "read {read} bytes with 50000 of weekly room"
        );

        let body = Source::zeros(None, Some(40_001));
        let read = body.counter();
        let r = send(s, "POST", &live_path(), body, MEMBER_TOKEN).await;
        assert_eq!(
            r.status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "declared one byte over the room"
        );
        assert_eq!(
            read.load(Ordering::Relaxed),
            0,
            "bytes read of a body declared over the quota"
        );

        assert_eq!(
            (rows(s), ledger(s), entries(s, "blobs"), entries(s, "tmp")),
            (1, 1, 1, 0),
            "rows, ledger, blobs, tmp"
        );
    }

    /// Sixteen uploads race for a member's last bit of room; the check when
    /// saving lets exactly one through.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn parallel_uploads_race_for_the_last_room() {
        const ROUNDS: usize = 20;
        const RACERS: usize = 16;
        for round in 0..ROUNDS {
            let s = Arc::new(server_config(
                config(
                    vec![member(MEMBER_ID, "m", MEMBER_TOKEN, [1000, LOTS, LOTS])],
                    |_| {},
                ),
                |_| {},
            ));
            let racers: Vec<_> = (0..RACERS)
                .map(|_| {
                    let s = s.clone();
                    tokio::spawn(async move {
                        send(
                            &s,
                            "POST",
                            &live_path(),
                            Source::bytes(&random_blob(600)),
                            MEMBER_TOKEN,
                        )
                        .await
                    })
                })
                .collect();
            let mut landed = 0;
            for racer in racers {
                let r = racer.await.unwrap();
                match r.status {
                    StatusCode::CREATED => landed += 1,
                    StatusCode::PAYLOAD_TOO_LARGE => assert!(
                        error_of(&r).starts_with("Your files take 600 of your 1000 bytes"),
                        "round {round}: {}",
                        error_of(&r)
                    ),
                    other => panic!("round {round}: {other}"),
                }
            }
            assert_eq!(landed, 1, "round {round}: uploads landed with room for one");
            assert_eq!(
                (
                    rows(&s),
                    ledger(&s),
                    entries(&s, "blobs"),
                    entries(&s, "tmp")
                ),
                (1, 1, 1, 0),
                "round {round}: rows, ledger, blobs, tmp"
            );
        }
    }

    // ---- rate limits --------------------------------------------------------

    /// Upload rate is per member: 429 with Retry-After, before the body.
    #[tokio::test]
    async fn upload_rate_per_member() {
        let s = server_config(
            config(
                vec![
                    member(MEMBER_ID, "m", MEMBER_TOKEN, NO_LIMIT),
                    member(OTHER_ID, "o", OTHER_TOKEN, NO_LIMIT),
                ],
                |c| c["upload_rate"] = serde_json::json!({ "requests": 2, "seconds": 3600 }),
            ),
            |_| {},
        );
        upload(&s, b"a").await;
        upload(&s, b"b").await;
        let body = Source::bytes(b"c");
        let read = body.counter();
        let r = send(&s, "POST", &live_path(), body, MEMBER_TOKEN).await;
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.headers["retry-after"], "1800");
        assert_eq!(
            read.load(Ordering::Relaxed),
            0,
            "bytes read of a rate-limited upload"
        );
        let r = send(&s, "POST", &live_path(), Source::bytes(b"d"), OTHER_TOKEN).await;
        assert_eq!(r.status, StatusCode::CREATED, "another member");
        assert_eq!(rows(&s), 3);
    }

    /// The read limit can't be used to probe IDs: real, missing and malformed
    /// IDs get identical refusals at the same request.
    #[tokio::test]
    async fn read_limit_does_not_leak_existence() {
        let s = server_config(
            config(vec![member(MEMBER_ID, "m", MEMBER_TOKEN, NO_LIMIT)], |c| {
                c["read_rate"] = serde_json::json!({ "requests": 3, "seconds": 3600 })
            }),
            |_| {},
        );
        let u = upload(&s, &random_blob(100)).await;
        let ids = [
            u.id.clone(),
            FileId::random().to_string(),
            "..%2Fnot-an-id".to_owned(),
        ];
        let mut refusals = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            let peer = format!("192.0.2.{}", i + 1);
            let requests = [
                ("GET", format!("/api/meta/{id}")),
                ("HEAD", format!("/api/meta/{id}")),
                ("GET", format!("/api/download/{id}")),
            ];
            for (method, path) in &requests {
                let r = send_from(&s, &peer, &[], method, path, Source::bytes(b""), "").await;
                assert!(
                    r.status != StatusCode::TOO_MANY_REQUESTS,
                    "{method} {path}: refused early"
                );
            }
            for (method, path) in &requests {
                let r = send_from(&s, &peer, &[], method, path, Source::bytes(b""), "").await;
                assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{method} {path}");
                refusals.push((format!("{:?}", r.headers), r.body));
            }
        }
        for r in &refusals[1..] {
            assert!(*r == refusals[0], "{r:?}\nis not\n{:?}", refusals[0]);
        }
        assert!(
            refusals[0].0.contains(r#""retry-after": "1200""#),
            "{}",
            refusals[0].0
        );
        assert_eq!(
            counts(&s, &u.id),
            Some((1, 0, 0)),
            "downloads of the real file"
        );
    }

    /// Behind a trusted proxy, the read limit is per client and a forged
    /// X-Forwarded-For can't escape it. One IPv6 /64 is one client.
    #[tokio::test]
    async fn read_limit_keyed_by_the_client_address() {
        let one = serde_json::json!({ "requests": 1, "seconds": 3600 });
        let proxied = server_config(
            config(vec![], |c| {
                c["read_rate"] = one.clone();
                c["trusted_proxies"] = serde_json::json!(["10.0.0.1"]);
            }),
            |_| {},
        );
        let path = format!("/api/meta/{}", FileId::random());
        const OK: StatusCode = StatusCode::NOT_FOUND; // allowed through, to an ID never issued
        const NO: StatusCode = StatusCode::TOO_MANY_REQUESTS;
        let s = &proxied;
        assert_eq!(
            read_status(s, &path, "10.0.0.1", &["198.51.100.1"]).await,
            OK,
            "client 1 via the proxy"
        );
        assert_eq!(
            read_status(s, &path, "10.0.0.1", &["198.51.100.1"]).await,
            NO,
            "client 1 again"
        );
        assert_eq!(
            read_status(s, &path, "10.0.0.1", &["198.51.100.2"]).await,
            OK,
            "client 2, same proxy"
        );
        assert_eq!(
            read_status(s, &path, "10.0.0.1", &["1.2.3.4, 198.51.100.1"]).await,
            NO,
            "client 1 forging an entry"
        );
        assert_eq!(
            read_status(s, &path, "10.0.0.1", &["10.0.0.1", "198.51.100.1"]).await,
            NO,
            "client 1 naming the proxy"
        );
        assert_eq!(
            read_status(s, &path, "10.0.0.1", &["2001:db8:1:2::1"]).await,
            OK,
            "an IPv6 client"
        );
        assert_eq!(
            read_status(s, &path, "10.0.0.1", &["2001:db8:1:2:ffff::9"]).await,
            NO,
            "the same /64"
        );
        assert_eq!(
            read_status(s, &path, "10.0.0.1", &["2001:db8:1:3::1"]).await,
            OK,
            "the next /64"
        );
        assert_eq!(
            read_status(s, &path, "203.0.113.5", &["198.51.100.3"]).await,
            OK,
            "not through the proxy"
        );
        assert_eq!(
            read_status(s, &path, "203.0.113.5", &["198.51.100.4"]).await,
            NO,
            "its header is not believed"
        );

        let direct = direct_server();
        let s = &direct;
        assert_eq!(
            read_status(s, &path, "203.0.113.5", &["198.51.100.1"]).await,
            OK,
            "no trusted proxies"
        );
        assert_eq!(
            read_status(s, &path, "203.0.113.5", &["198.51.100.2"]).await,
            NO,
            "a spoofed header, ignored"
        );
        assert_eq!(
            read_status(s, &path, "203.0.113.6", &[]).await,
            OK,
            "another address"
        );
    }

    async fn read_status(s: &Server, path: &str, peer: &str, forwarded: &[&str]) -> StatusCode {
        send_from(s, peer, forwarded, "GET", path, Source::bytes(b""), "")
            .await
            .status
    }

    fn direct_server() -> Server {
        server_config(
            config(vec![], |c| {
                c["read_rate"] = serde_json::json!({ "requests": 1, "seconds": 3600 })
            }),
            |_| {},
        )
    }

    // ---- counters and the disk floor ------------------------------------------

    /// GET /admin/stats with the admin token, as JSON.
    async fn stats(s: &Server) -> serde_json::Value {
        let r = send(s, "GET", "/admin/stats", Source::bytes(b""), ADMIN_TOKEN).await;
        assert_eq!(r.status, StatusCode::OK, "stats");
        r.json()
    }

    const COUNTER_NAMES: [&str; 11] = [
        "uploads",
        "bytes_uploaded",
        "downloads",
        "failed_downloads",
        "failed_uploads",
        "expired_swept",
        "deletion_failures",
        "rate_limited_uploads",
        "rate_limited_reads",
        "uploads_refused_low_disk",
        "counting_since",
    ];

    /// Only an admin token opens the stats, and they contain totals only: no
    /// ids, tokens or names.
    #[tokio::test]
    async fn admin_stats_are_totals_behind_admin_auth() {
        let s = server();
        let u = upload(&s, &random_blob(1000)).await;
        assert_eq!(
            get(&s, &format!("/api/download/{}", u.id)).await.status,
            StatusCode::OK
        );
        // Counted after the body is dropped, on another thread.
        wait_until("the download is counted", || {
            s.app.counters.json()["downloads"] == 1
        })
        .await;
        let hash = hex(&token_sha256(ADMIN_TOKEN));
        for (why, token) in [
            ("no token", ""),
            ("a wrong token", "not-a-token"),
            ("a member's token", MEMBER_TOKEN),
            ("the admin token's hash", hash.as_str()),
        ] {
            for method in ["GET", "HEAD"] {
                let r = send(&s, method, "/admin/stats", Source::bytes(b""), token).await;
                assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{method}, {why}");
            }
        }

        let r = send(&s, "GET", "/admin/stats", Source::bytes(b""), ADMIN_TOKEN).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.headers["cache-control"], "no-store");
        let v = r.json();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        let mut want = COUNTER_NAMES.to_vec();
        keys.sort();
        want.sort();
        assert_eq!(keys, want, "stats keys");
        assert!(
            v.as_object().unwrap().values().all(|n| n.is_u64()),
            "a stat that is not a whole number: {v}"
        );
        let text = String::from_utf8(r.body).unwrap();
        for secret in [
            u.id.as_str(),
            u.owner_token.as_str(),
            MEMBER_ID,
            "member",
            ADMIN_ID,
        ] {
            assert!(!text.contains(secret), "stats contain {secret:?}: {text}");
        }
        assert_eq!(
            (v["uploads"].as_u64(), v["downloads"].as_u64()),
            (Some(1), Some(1))
        );
    }

    /// A fake disk: free space is CAPACITY minus what's in blobs/ and tmp/.
    static CAPACITY: AtomicU64 = AtomicU64::new(0);

    fn filling_disk(tmp: &Path) -> std::io::Result<u64> {
        let data = tmp.parent().unwrap();
        let mut used = 0;
        for sub in ["blobs", "tmp"] {
            for entry in fs::read_dir(data.join(sub))? {
                used += entry?.metadata()?.len();
            }
        }
        Ok(CAPACITY.load(Ordering::Relaxed).saturating_sub(used))
    }

    const FLOOR: u64 = 10 << 20;
    const MIB: u64 = 1 << 20;

    /// With a Content-Length the floor is exact, and refused before the body.
    /// Without one, the stream is cut off within a MiB of the floor and the
    /// partial file removed. Every refusal is counted.
    #[tokio::test]
    async fn disk_floor() {
        let s = server_config(
            config(vec![member(MEMBER_ID, "m", MEMBER_TOKEN, NO_LIMIT)], |c| {
                c["min_free_bytes"] = FLOOR.into()
            }),
            |app| app.free_space = filling_disk,
        );
        let n = 3 * MIB + 5;

        // One byte short of room for it, declared: refused unread.
        CAPACITY.store(FLOOR + n - 1, Ordering::Relaxed);
        let body = Source::zeros(Some(n), Some(n));
        let read = body.counter();
        let r = send(&s, "POST", &live_path(), body, MEMBER_TOKEN).await;
        assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE, "one byte short");
        assert_eq!(
            error_of(&r),
            "the server is low on disk space; nothing was stored"
        );
        assert_eq!(
            read.load(Ordering::Relaxed),
            0,
            "bytes read of a refused body"
        );
        assert_eq!(
            (entries(&s, "tmp"), entries(&s, "blobs"), rows(&s)),
            (0, 0, 0)
        );

        // Exactly room for it: stored, and the disk is at the floor.
        CAPACITY.store(FLOOR + n, Ordering::Relaxed);
        let r = send(
            &s,
            "POST",
            &live_path(),
            Source::zeros(Some(n), Some(n)),
            MEMBER_TOKEN,
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "exactly room");
        assert_eq!(filling_disk(&s.dir.0.join("tmp")).unwrap(), FLOOR);

        // At the floor, an empty file still fits; a byte below it, nothing does.
        let r = send(&s, "POST", &live_path(), Source::bytes(b""), MEMBER_TOKEN).await;
        assert_eq!(r.status, StatusCode::CREATED, "an empty file at the floor");
        CAPACITY.store(FLOOR + n - 1, Ordering::Relaxed);
        let r = send(&s, "POST", &live_path(), Source::bytes(b""), MEMBER_TOKEN).await;
        assert_eq!(
            r.status,
            StatusCode::INSUFFICIENT_STORAGE,
            "below the floor"
        );

        // No declared length: cut off once free space hits the floor, checked at
        // least every MiB.
        CAPACITY.store(FLOOR + n + 3 * MIB, Ordering::Relaxed);
        let body = Source::zeros(Some(8 * MIB), None);
        let read = body.counter();
        let r = send(&s, "POST", &live_path(), body, MEMBER_TOKEN).await;
        assert_eq!(
            r.status,
            StatusCode::INSUFFICIENT_STORAGE,
            "streamed past the floor"
        );
        let read = read.load(Ordering::Relaxed);
        assert!(
            read <= 4 * MIB + 64 * 1024,
            "read {read} bytes with 3 MiB of room"
        );
        assert_eq!(
            (entries(&s, "tmp"), entries(&s, "blobs"), rows(&s)),
            (0, 2, 2),
            "the partial file was left behind"
        );

        // A body that lies about its length gets no further.
        CAPACITY.store(FLOOR + n + 3 * MIB, Ordering::Relaxed);
        let body = Source::zeros(Some(8 * MIB), Some(MIB));
        let r = send(&s, "POST", &live_path(), body, MEMBER_TOKEN).await;
        assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE, "a false length");
        assert_eq!(entries(&s, "tmp"), 0);

        // Another upload takes space mid-stream; the next check refuses this one.
        CAPACITY.store(FLOOR + n + 4 * MIB, Ordering::Relaxed);
        let body = Taken {
            left: 4 * MIB,
            taken: false,
            read: Default::default(),
        };
        let read = body.read.clone();
        let req = Request::post(live_path())
            .header("Authorization", format!("Bearer {MEMBER_TOKEN}"))
            .body(body)
            .unwrap();
        let r = super::handle(s.app.clone(), PEER.parse().unwrap(), req).await;
        assert_eq!(
            r.status(),
            StatusCode::INSUFFICIENT_STORAGE,
            "room taken mid-stream"
        );
        let read = read.load(Ordering::Relaxed);
        assert!(read <= MIB + 64 * 1024, "read {read} bytes before refusing");
        assert_eq!(entries(&s, "tmp"), 0);

        let v = stats(&s).await;
        assert_eq!(
            (
                v["uploads_refused_low_disk"].as_u64(),
                v["failed_uploads"].as_u64()
            ),
            (Some(5), Some(0)),
            "refused at the floor, failed"
        );
    }

    /// `left` zero bytes in 64 KiB chunks; after the first, 2 MiB of disk is
    /// taken by someone else.
    struct Taken {
        left: u64,
        taken: bool,
        read: Arc<AtomicU64>,
    }

    impl HttpBody for Taken {
        type Data = Bytes;
        type Error = &'static str;

        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            if !this.taken && this.read.load(Ordering::Relaxed) > 0 {
                this.taken = true;
                CAPACITY.fetch_sub(2 * MIB, Ordering::Relaxed);
            }
            let n = this.left.min(64 * 1024);
            if n == 0 {
                return Poll::Ready(None);
            }
            this.left -= n;
            this.read.fetch_add(n, Ordering::Relaxed);
            Poll::Ready(Some(Ok(Frame::data(vec![0; n as usize].into()))))
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::with_exact(4 * MIB)
        }
    }

    /// A body that sends one chunk and then nothing, ever.
    struct Stall(bool);

    impl HttpBody for Stall {
        type Data = Bytes;
        type Error = &'static str;

        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let sent = std::mem::replace(&mut self.get_mut().0, true);
            match sent {
                false => Poll::Ready(Some(Ok(Frame::data(vec![0; 1000].into())))),
                true => Poll::Pending,
            }
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::with_exact(2000)
        }
    }

    /// Every counter, driven by what it counts, including forced failures.
    /// Refusals (401, 413) count nowhere.
    #[tokio::test]
    async fn counters_count() {
        use std::os::unix::fs::PermissionsExt;
        const T0: i64 = 1_800_000_000;
        static CLOCK: AtomicI64 = AtomicI64::new(T0);
        let s = server_config(
            config(
                vec![member(MEMBER_ID, "m", MEMBER_TOKEN, [LOTS, LOTS, 210_000])],
                |c| {
                    c["upload_rate"] = serde_json::json!({ "requests": 7, "seconds": 3600 });
                    c["read_rate"] = serde_json::json!({ "requests": 4, "seconds": 3600 });
                },
            ),
            |app| app.now = || CLOCK.load(Ordering::Relaxed),
        );
        let path = |max_downloads: u32| limits_path(T0 + 60, max_downloads);

        // Two stored files; `a` is long enough to stop partway.
        let a = upload_with(&s, &path(0), &random_blob(200_000)).await;
        let b = upload_with(&s, &path(1), &random_blob(2000)).await;
        // And one that expires later: deleted by the sweeper, but not expired.
        let c = upload_with(&s, &limits_path(T0 + 3600, 0), &[7; 10]).await;
        // Refusals: no token, and over the weekly quota. Neither fails.
        let refused = [
            send(&s, "POST", &path(0), Source::bytes(b"x"), "").await,
            send(
                &s,
                "POST",
                &path(0),
                Source::bytes(&random_blob(9000)),
                MEMBER_TOKEN,
            )
            .await,
        ];
        assert_eq!(
            refused.map(|r| r.status),
            [StatusCode::UNAUTHORIZED, StatusCode::PAYLOAD_TOO_LARGE]
        );
        // The client goes away mid-body.
        let gone = Source {
            fails: true,
            ..Source::zeros(Some(100), Some(1000))
        };
        let r = send(&s, "POST", &path(0), gone, MEMBER_TOKEN).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        // Cut off mid-body, as shutdown does after the grace period.
        let req = Request::post(path(0))
            .header("Authorization", format!("Bearer {MEMBER_TOKEN}"))
            .body(Stall(false))
            .unwrap();
        let cut = tokio::time::timeout(
            Duration::from_millis(200),
            super::handle(s.app.clone(), PEER.parse().unwrap(), req),
        )
        .await;
        assert!(cut.is_err(), "the stalled upload finished");
        assert_eq!(entries(&s, "tmp"), 0, "the cut-off upload's partial file");
        // Seventh upload allowed by the rate; the eighth is refused.
        upload_with(&s, &path(0), b"").await;
        let r = send(&s, "POST", &path(0), Source::bytes(b""), MEMBER_TOKEN).await;
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);

        // One download completes and uses b up; one is dropped partway.
        let r = get(&s, &format!("/api/download/{}", b.id)).await;
        assert_eq!(r.status, StatusCode::OK);
        let mut partial = start_download(&s, &a.id).await;
        partial.frame().await.unwrap().unwrap();
        drop(partial);
        wait_until("both transfers end", || {
            counts(&s, &a.id) == Some((0, 0, 0)) && counts(&s, &b.id).is_none()
        })
        .await;
        // Two more reads use up the read rate of 4; the fifth is refused.
        for want in [
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            assert_eq!(get(&s, &format!("/api/meta/{}", a.id)).await.status, want);
        }

        // The filesystem refuses deletes: one failure per file per attempt, until
        // the third sweep deletes them all.
        let blobs = s.dir.0.join("blobs");
        fs::set_permissions(&blobs, fs::Permissions::from_mode(0o500)).unwrap();
        let r = send(
            &s,
            "DELETE",
            &format!("/api/{}", c.id),
            Source::bytes(b""),
            &c.owner_token,
        )
        .await;
        CLOCK.store(T0 + 60, Ordering::Relaxed);
        let sweeps = [s.app.sweep(), s.app.sweep()];
        fs::set_permissions(&blobs, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            r.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "the refused delete"
        );
        assert_eq!(sweeps.map(|r| r.unwrap()), [(0, 3), (0, 3)]);
        assert_eq!(s.app.sweep().unwrap(), (3, 0), "the third sweep");

        let v = stats(&s).await;
        let got: Vec<(&str, u64)> = COUNTER_NAMES[..10]
            .iter()
            .map(|&k| (k, v[k].as_u64().unwrap()))
            .collect();
        assert_eq!(
            got,
            [
                ("uploads", 4),
                ("bytes_uploaded", 202_010),
                ("downloads", 1),
                ("failed_downloads", 1),
                ("failed_uploads", 2),
                ("expired_swept", 2),
                ("deletion_failures", 7),
                ("rate_limited_uploads", 1),
                ("rate_limited_reads", 1),
                ("uploads_refused_low_disk", 0),
            ]
        );
    }

    /// Saved counters carry on after reopening. Opening alone writes nothing.
    #[tokio::test]
    async fn counters_survive_a_restart() {
        let s = server();
        let u = upload(&s, &random_blob(1234)).await;
        assert_eq!(
            get(&s, &format!("/api/download/{}", u.id)).await.status,
            StatusCode::OK
        );
        wait_until("the download ends", || {
            s.app.counters.get(crate::counters::Counter::Downloads) == 1
        })
        .await;
        let before = stats(&s).await;
        let saved = |s: &Server| -> i64 {
            s.app
                .db()
                .conn()
                .query_row("SELECT COUNT(*) FROM counters", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(saved(&s), 0, "opening wrote counters");
        s.app.save_counters().unwrap();

        let s = restart(s, test_config(), |app| {
            app.free_space = |_| Ok(LOTS);
            app.now = || now() + 3600;
        });
        let after = stats(&s).await;
        assert_eq!(after, before, "counters after a restart");
        assert_eq!(
            (after["uploads"].as_u64(), after["bytes_uploaded"].as_u64()),
            (Some(1), Some(1234))
        );
        upload(&s, b"more").await;
        assert_eq!(stats(&s).await["uploads"].as_u64(), Some(2), "counting on");
    }

    /// Pruning the ledger never changes a quota answer: a pruned and an unpruned
    /// copy agree at every step.
    #[test]
    fn ledger_pruning_changes_no_quota_result() {
        use crate::db::Db;
        const T0: i64 = 1_800_000_000;
        let dirs = [TempDir::new(), TempDir::new()];
        let [mut kept, mut pruned] =
            [0, 1].map(|i| Db::open(&dirs[i].0.join("sunbird.db")).unwrap());
        let c = config(
            vec![member(MEMBER_ID, "m", MEMBER_TOKEN, [LOTS, LOTS, 10_000])],
            |_| {},
        );
        let m = &c.members[0];
        let mut times = vec![];
        for (i, at) in [
            -2 * WEEK,
            -WEEK - 1,
            -WEEK,
            -WEEK + 1,
            -1,
            0,
            1,
            3600,
            WEEK - 1,
        ]
        .into_iter()
        .enumerate()
        {
            let at = T0 + at;
            for db in [&mut kept, &mut pruned] {
                db.write(|tx| {
                    tx.execute(
                        "INSERT INTO uploads (uploader_id, size, created_at) VALUES (?, ?, ?)",
                        rusqlite::params![MEMBER_ID, 1000 + i as i64, at],
                    )?;
                    Ok(())
                })
                .unwrap();
            }
            times.extend([at - 1, at, at + 1, at + WEEK - 1, at + WEEK, at + WEEK + 1]);
        }
        times.sort();
        times.dedup();
        let mut removed = 0;
        for t in times {
            removed += pruned.prune_ledger(t).unwrap();
            let (a, b) = (
                kept.usage(&m.id, t).unwrap(),
                pruned.usage(&m.id, t).unwrap(),
            );
            assert_eq!(a.week, b.week, "at {}: the week's uploads", t - T0);
            let week: u64 = a.week.iter().map(|&(size, _)| size).sum();
            for size in [
                0,
                1,
                10_000u64.saturating_sub(week),
                10_001u64.saturating_sub(week),
            ] {
                assert_eq!(
                    m.quota.admit(&a, size, t),
                    m.quota.admit(&b, size, t),
                    "at {}: admit {size}",
                    t - T0
                );
            }
        }
        assert_eq!(removed, 9, "entries pruned");
    }

    /// The sweeper prunes the ledger as it runs.
    #[tokio::test]
    async fn sweep_prunes_the_ledger() {
        const T0: i64 = 1_800_000_000;
        static CLOCK: AtomicI64 = AtomicI64::new(T0);
        let s = server_with(|app| app.now = || CLOCK.load(Ordering::Relaxed));
        upload_with(&s, &limits_path(T0 + 60, 0), b"x").await;
        CLOCK.store(T0 + WEEK - 1, Ordering::Relaxed);
        s.app.sweep().unwrap();
        assert_eq!(ledger(&s), 1, "pruned inside the 7 days");
        CLOCK.store(T0 + WEEK, Ordering::Relaxed);
        s.app.sweep().unwrap();
        assert_eq!(ledger(&s), 0, "kept past the 7 days");
    }
}
