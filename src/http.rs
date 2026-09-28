//! Routes, handlers, and the one error type every refusal goes through. No
//! handler writes a status code; an `ApiError` variant owns each one.

use std::fmt::Display;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

use crate::app::{App, FileId, Limits, MAX_BLOB, OwnerToken, PREVIEW_LEN};

pub type Body = BoxBody<Bytes, io::Error>;

/// Every way a request is refused.
#[derive(Debug)]
pub enum ApiError {
    /// Malformed, never issued, and deleted alike: one answer, so a response
    /// never says which.
    NotFound,
    NoOwnerToken,
    WrongOwnerToken,
    BadLimits(&'static str),
    /// The body stopped before it ended: the client went away.
    Incomplete,
    TooLarge,
    /// The cause is logged where it happened; the client gets only this.
    Internal(&'static str),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::NoOwnerToken => StatusCode::UNAUTHORIZED,
            ApiError::WrongOwnerToken => StatusCode::FORBIDDEN,
            ApiError::BadLimits(_) | ApiError::Incomplete => StatusCode::BAD_REQUEST,
            ApiError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(&self) -> &'static str {
        match self {
            ApiError::NotFound => "not found",
            ApiError::NoOwnerToken => "owner token required",
            ApiError::WrongOwnerToken => "wrong owner token",
            ApiError::BadLimits(why) | ApiError::Internal(why) => why,
            ApiError::Incomplete => "upload did not complete",
            ApiError::TooLarge => "upload is larger than the server accepts",
        }
    }

    fn into_response(self) -> Response<Body> {
        json(
            self.status(),
            &serde_json::json!({ "error": self.message() }),
        )
    }
}

/// Logs the cause and refuses with a 500 carrying only `message`.
fn internal<E: Display>(message: &'static str) -> impl FnOnce(E) -> ApiError {
    move |cause| {
        log::error!("{message}: {cause}");
        ApiError::Internal(message)
    }
}

/// Lets pages run only the client's own scripts, and hash-wasm compile its
/// WebAssembly. The client renders decrypted metadata, which is hostile input,
/// as text; this is the backstop if that ever slips.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
    style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub async fn handle<B>(app: Arc<App>, req: Request<B>) -> Response<Body>
where
    B: HttpBody<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Display,
{
    let mut res = route(app, req)
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
    // Nothing between here and a client may reuse one kind of fetch of a URL
    // for another (PrivateBin's reason). A link preview fetches the page, and
    // only the page's script fetches the blob.
    headers.insert(header::VARY, HeaderValue::from_static("Accept"));
    res
}

async fn route<B>(app: Arc<App>, req: Request<B>) -> Result<Response<Body>, ApiError>
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
        _ if get && path.starts_with("/api/meta/") => {
            serve(app, &path["/api/meta/".len()..], PREVIEW_LEN).await
        }
        _ if get && path.starts_with("/api/download/") => {
            serve(app, &path["/api/download/".len()..], MAX_BLOB).await
        }
        Method::DELETE if path.starts_with("/api/") => {
            let token = bearer(&req).map(str::to_owned);
            delete(app, &path["/api/".len()..], token).await
        }
        _ if get => client_file(path).ok_or(ApiError::NotFound),
        _ => Err(ApiError::NotFound),
    }
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

/// Every refusal that can come before the body does: the limits (400), then a
/// declared length over max_blob (413). Then the body streams to tmp/ and is
/// cut off at max_blob; nothing is buffered to find its length.
async fn upload<B>(app: Arc<App>, req: Request<B>) -> Result<Response<Body>, ApiError>
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: Display,
{
    let limits = Limits::parse(req.uri().query(), (app.now)()).map_err(ApiError::BadLimits)?;
    let mut body = req.into_body();
    // hyper's size hint is the declared Content-Length, exactly.
    if body.size_hint().lower() > MAX_BLOB {
        return Err(ApiError::TooLarge);
    }

    let tmp = TempFile(app.temp_path());
    let mut file = tokio::fs::File::create_new(&tmp.0)
        .await
        .map_err(internal("could not store upload"))?;
    let mut size = 0u64;
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
    let id = blocking(&app, move |app| app.commit(&tmp.0, &owner, size, limits))
        .await
        .map_err(internal("could not store upload"))?;
    Ok(json(
        StatusCode::CREATED,
        &serde_json::json!({ "id": id.to_string(), "ownerToken": token.as_str() }),
    ))
}

/// An upload's file in tmp/, removed on every path: on success its blob has
/// been linked under its ID's name, so the temp name is not needed either.
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

/// Sends the first min(limit, size) bytes of a blob, raw. The server never
/// looks inside: the preview is a byte count, not the header (§3).
async fn serve(app: Arc<App>, id: &str, limit: u64) -> Result<Response<Body>, ApiError> {
    let id = FileId::parse(id).ok_or(ApiError::NotFound)?;
    let size = blocking(&app, {
        let id = id.clone();
        move |app| app.db().size(&id)
    })
    .await
    .map_err(internal("could not read blob"))?
    .ok_or(ApiError::NotFound)?;
    // An owner may delete the file while it streams. On POSIX that is
    // harmless: the open descriptor keeps the bytes until it is closed.
    let file = match tokio::fs::File::open(app.blob_path(&id)).await {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ApiError::NotFound), // deleted since the query
        file => file.map_err(internal("could not read blob"))?,
    };
    let len = size.min(limit);
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, len)
        .body(Blob { file, left: len }.boxed())
        .expect("valid response"))
}

/// The first `left` bytes of a blob file, read as the connection takes them.
struct Blob {
    file: tokio::fs::File,
    left: u64,
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
            // The row promised more than the file has. Ending the response
            // short, not padding it, makes the client see a failed transfer.
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
            .owner(&id)
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

// ---- client -----------------------------------------------------------------

/// The page, served at / and at /d/<anything>: the link a recipient opens.
const INDEX: &[u8] = include_bytes!("../web/index.html");

/// The files index.html loads. Nothing else in web/ is built in or served: no
/// tests, no directory listings.
const ASSETS: [(&str, &str, &[u8]); 7] = [
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
    //! The endpoints, driven straight through `handle`, with request bodies
    //! that count what the server pulled from them. The helpers are shared with
    //! the app and db tests.

    use std::fs;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll};

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use http_body_util::BodyExt;
    use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
    use hyper::{HeaderMap, Request, StatusCode};
    use sha2::{Digest, Sha256};

    use super::CONTENT_SECURITY_POLICY;
    use crate::app::{App, FileId, MAX_BLOB};

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

    pub(crate) struct Server {
        pub(crate) app: Arc<App>,
        pub(crate) dir: TempDir,
    }

    pub(crate) fn server() -> Server {
        server_with(|_| {})
    }

    pub(crate) fn server_with(setup: impl FnOnce(&mut App)) -> Server {
        let dir = TempDir::new();
        let mut app = App::open(&dir.0).unwrap();
        setup(&mut app);
        Server {
            app: Arc::new(app),
            dir,
        }
    }

    /// A request body. `len` bytes of zeros (None: endless), then the end, or an
    /// error if `fails`. `declared` is its Content-Length. `read` counts what the
    /// server pulled.
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

    pub(crate) async fn send(
        s: &Server,
        method: &str,
        path: &str,
        body: Source,
        token: &str,
    ) -> Reply {
        let mut req = Request::builder().method(method).uri(path);
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let res = super::handle(s.app.clone(), req.body(body).unwrap()).await;
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
        let r = send(s, "POST", &live_path(), Source::bytes(blob), "").await;
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

    /// Below 8 KiB the preview is the whole blob, records and all; the server does
    /// not look for where the header ends.
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
            "",
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "max_blob bytes");

        // One byte over, from an endless source: cut off, not read to the end.
        let body = Source::zeros(None, None);
        let read = body.counter();
        assert_eq!(
            send(&s, "POST", &live_path(), body, "").await.status,
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
            "",
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
            send(&s, "POST", &live_path(), body, "").await.status,
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
            send(&s, "POST", &live_path(), body, "").await.status,
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

    /// The limits are checked against the server's clock, exactly, before a byte of
    /// the body is read, and refused rather than clamped. They are stored now;
    /// expiry (session 02) enforces them.
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
            let r = send(&s, "POST", path, Source::bytes(b"blob"), "").await;
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
            let r = send(&s, "POST", path, body, "").await;
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
}
