//! Tests of the built binary, over a real socket, in a directory holding only
//! its data.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// The one member's upload token; the config holds only its hash.
const TOKEN: &str = "binary-test-token";
/// The one admin's token.
const ADMIN_TOKEN: &str = "binary-test-admin-token";

fn sha256_hex(s: &str) -> String {
    Sha256::digest(s)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn config() -> String {
    let (hash, admin) = (sha256_hex(TOKEN), sha256_hex(ADMIN_TOKEN));
    format!(
        r#"{{"members": [{{"id": "AAAAAAAAAAAAAAAAAAAAAA", "name": "m", "token_sha256": "{hash}",
             "max_active_bytes": 1000000000, "max_active_files": 1000, "max_bytes_per_week": 1000000000}}],
            "admins": [{{"id": "AQEBAQEBAQEBAQEBAQEBAQ", "name": "a", "token_sha256": "{admin}"}}],
            "trusted_proxies": [],
            "upload_rate": {{"requests": 1000, "seconds": 1}}, "read_rate": {{"requests": 1000, "seconds": 1}},
            "min_free_bytes": 0}}"#
    )
}

struct Running {
    child: Child,
    dir: PathBuf,
    addr: String,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start() -> Running {
    start_with(|_| {})
}

/// Starts the binary once `prepare` has had its data directory.
fn start_with(prepare: impl FnOnce(&Path)) -> Running {
    let dir = std::env::temp_dir().join(format!(
        "sunbird-binary-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::write(dir.join("sunbird.json"), config()).unwrap();
    prepare(&dir.join("data"));
    let (child, addr) = spawn(&dir);
    Running { child, dir, addr }
}

/// Runs the binary over `dir`'s data and config, and waits until it answers.
fn spawn(dir: &Path) -> (Child, String) {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_sunbird"))
        .args(["-addr", &addr, "-data", "data", "-config", "sunbird.json"])
        .current_dir(dir)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(&addr).is_err() {
        assert!(Instant::now() < deadline, "sunbird did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    (child, addr)
}

impl Running {
    /// Sends SIGTERM, and waits up to `within` for the process to exit.
    fn terminate(&mut self, within: Duration) -> std::process::ExitStatus {
        let sent = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success(), "kill -TERM");
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "still running {within:?} after SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The binary again, over the same data directory.
    fn restart(&mut self) {
        let (child, addr) = spawn(&self.dir);
        (self.child, self.addr) = (child, addr);
    }

    /// GET /admin/stats with the admin token.
    fn stats(&self) -> serde_json::Value {
        let response = exchange(
            &self.addr,
            &format!(
                "GET /admin/stats HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {ADMIN_TOKEN}\r\nConnection: close\r\n\r\n"
            ),
        );
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        serde_json::from_str(body).unwrap()
    }

    /// Uploads `blob`, allowing `max_downloads`, and returns its id.
    fn upload(&self, blob: &[u8], max_downloads: u32) -> String {
        let mut conn = TcpStream::connect(&self.addr).unwrap();
        conn.write_all(
            format!(
                "POST /api/upload?expires_at={}&max_downloads={max_downloads} HTTP/1.1\r\nHost: x\r\n\
                 Authorization: Bearer {TOKEN}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                unix_now() + 3600,
                blob.len()
            )
            .as_bytes(),
        )
        .unwrap();
        conn.write_all(blob).unwrap();
        let mut response = String::new();
        conn.read_to_string(&mut response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 201"), "{response}");
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        v["id"].as_str().unwrap().to_owned()
    }

    /// Starts downloading `id`: response head read, body not yet.
    fn start_download(&self, id: &str) -> TcpStream {
        let mut conn = TcpStream::connect(&self.addr).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        conn.write_all(
            format!("GET /api/download/{id} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") {
            conn.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&head)
        );
        conn
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn random_blob(n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    getrandom::fill(&mut b).unwrap();
    b
}

/// Sends `head` (and nothing else) and reads the response to its end.
fn exchange(addr: &str, head: &str) -> String {
    let mut conn = TcpStream::connect(addr).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(head.as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = conn.read_to_end(&mut response);
    String::from_utf8_lossy(&response).into_owned()
}

/// The client is built in: every page and file it loads is served byte for
/// byte, with no web/ directory present.
#[test]
fn serves_the_built_in_page() {
    let s = start();
    let beside: Vec<_> = std::fs::read_dir(&s.dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(!s.dir.join("web").exists(), "{beside:?}");
    for (path, file) in [
        ("/", "web/index.html"),
        ("/d/AAAAAAAAAAAAAAAA", "web/index.html"),
        ("/app.css", "web/app.css"),
        ("/src/app.js", "web/src/app.js"),
        ("/src/crypto.js", "web/src/crypto.js"),
        ("/src/argon2.js", "web/src/argon2.js"),
        ("/src/argon2-worker.js", "web/src/argon2-worker.js"),
        (
            "/vendor/hash-wasm/argon2.umd.min.js",
            "web/vendor/hash-wasm/argon2.umd.min.js",
        ),
    ] {
        let mut conn = TcpStream::connect(&s.addr).unwrap();
        conn.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
        let mut response = Vec::new();
        conn.read_to_end(&mut response).unwrap();
        let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"), "{path}");
        assert!(
            response[split + 4..] == std::fs::read(file).unwrap(),
            "{path}: not {file}"
        );
    }
}

/// SIGTERM: stop listening, let a download in progress finish, save the
/// counters, exit cleanly. The next start carries on counting.
#[test]
fn sigterm_finishes_transfers_and_keeps_the_counters() {
    let mut s = start();
    let blob = random_blob(32 << 20);
    let id = s.upload(&blob, 1);
    let mut download = s.start_download(&id);
    let mut got = vec![0; 1 << 20];
    download.read_exact(&mut got).unwrap();

    let pid = s.child.id().to_string();
    Command::new("kill").args(["-TERM", &pid]).status().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(&s.addr).is_ok() {
        assert!(Instant::now() < deadline, "still accepting after SIGTERM");
        std::thread::sleep(Duration::from_millis(20));
    }
    download.read_to_end(&mut got).unwrap();
    assert!(got == blob, "the download in progress: {} bytes", got.len());
    let status = s.terminate(Duration::from_secs(10));
    assert!(status.success(), "exit: {status}");

    s.restart();
    let v = s.stats();
    assert_eq!(
        (
            v["uploads"].as_u64(),
            v["bytes_uploaded"].as_u64(),
            v["downloads"].as_u64(),
            v["failed_downloads"].as_u64()
        ),
        (Some(1), Some(32 << 20), Some(1), Some(0)),
        "{v}"
    );
}

/// A transfer still running after the grace period is cut off and refunded,
/// and the process still exits cleanly.
#[test]
fn sigterm_cuts_off_a_stalled_transfer_after_the_grace_period() {
    let mut s = start();
    // Bigger than loopback's socket buffers, so the write can't finish.
    let blob = random_blob(64 << 20);
    let id = s.upload(&blob, 1);
    let stalled = s.start_download(&id);

    let started = Instant::now();
    let status = s.terminate(Duration::from_secs(45));
    let took = started.elapsed();
    assert!(status.success(), "exit: {status}");
    assert!(
        took >= Duration::from_secs(29),
        "exited after {took:?}, before the grace period"
    );
    drop(stalled);

    s.restart();
    let v = s.stats();
    assert_eq!(
        (v["downloads"].as_u64(), v["failed_downloads"].as_u64()),
        (Some(0), Some(1)),
        "{v}"
    );
    let mut again = s.start_download(&id);
    let mut got = Vec::new();
    again.read_to_end(&mut got).unwrap();
    assert!(got == blob, "the refunded download: {} bytes", got.len());
}

/// /admin/stats over the socket: 401 without the admin token.
#[test]
fn stats_need_the_admin_token() {
    let s = start();
    for auth in ["", "Authorization: Bearer binary-test-token\r\n"] {
        let response = exchange(
            &s.addr,
            &format!("GET /admin/stats HTTP/1.1\r\nHost: x\r\n{auth}Connection: close\r\n\r\n"),
        );
        assert!(response.starts_with("HTTP/1.1 401"), "{auth}: {response}");
    }
    assert_eq!(s.stats()["uploads"].as_u64(), Some(0));
}

/// A declared length over max_blob is refused before any body is sent.
#[test]
fn declared_length_over_max_blob_refused_before_the_body() {
    let s = start();
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let started = Instant::now();
    let response = exchange(
        &s.addr,
        &format!(
            "POST /api/upload?expires_at={expires}&max_downloads=0 HTTP/1.1\r\nHost: x\r\n\
             Authorization: Bearer {TOKEN}\r\nContent-Length: 104931329\r\nExpect: 100-continue\r\n\r\n"
        ),
    );
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    assert!(
        !response.contains("100 Continue"),
        "the server asked for the body it refused"
    );
    assert!(
        response.contains("upload is larger than the server accepts"),
        "{response}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the connection stayed open waiting for the body"
    );
    // A length no machine could hold is refused the same way.
    let response = exchange(
        &s.addr,
        &format!(
            "POST /api/upload?expires_at={expires}&max_downloads=0 HTTP/1.1\r\nHost: x\r\n\
             Authorization: Bearer {TOKEN}\r\nContent-Length: 9223372036854775807\r\n\r\n"
        ),
    );
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    assert!(
        std::fs::read_dir(s.dir.join("data/tmp"))
            .unwrap()
            .next()
            .is_none(),
        "tmp/ is not empty"
    );
}

/// The sweeper runs at startup, deleting files that expired while the server
/// was down.
#[test]
fn sweeps_at_startup() {
    let blob = |data: &Path| data.join("blobs/000000000000000000000000");
    let s = start_with(|data| {
        // A schema version 5 database, with one file that expired long ago.
        std::fs::copy(
            "tests/fixtures/schema-v5/sunbird.db",
            data.join("sunbird.db"),
        )
        .unwrap();
        let db = rusqlite::Connection::open(data.join("sunbird.db")).unwrap();
        db.execute(
            "INSERT INTO blobs (id, owner_token_hash, size, created_at, expires_at, max_downloads)
             VALUES ('AAAAAAAAAAAAAAAA', x'00', 1, 1, 2, 0)",
            [],
        )
        .unwrap();
        std::fs::create_dir(data.join("blobs")).unwrap();
        std::fs::write(blob(data), "x").unwrap();
    });
    let data = s.dir.join("data");
    let deadline = Instant::now() + Duration::from_secs(5);
    while blob(&data).exists() {
        assert!(
            Instant::now() < deadline,
            "the expired blob is still on disk"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let db = rusqlite::Connection::open(data.join("sunbird.db")).unwrap();
    let rows: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM blobs WHERE id = 'AAAAAAAAAAAAAAAA'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "the expired row");
}

/// No config, no start: there are no default members or limits.
#[test]
fn refuses_to_start_without_a_config() {
    let dir = std::env::temp_dir().join(format!("sunbird-binary-noconfig-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sunbird"))
        .args(["-addr", "127.0.0.1:0", "-data", "data"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!out.status.success(), "started with no config");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("sunbird.json"), "{err}");
}

/// mint-token prints a token once plus its SHA-256; mint-id prints only an id.
#[test]
fn mints_tokens_and_ids() {
    let run = |sub: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_sunbird"))
            .arg(sub)
            .output()
            .unwrap();
        assert!(out.status.success(), "{sub}");
        String::from_utf8(out.stdout).unwrap()
    };
    let out = run("mint-token");
    let field = |name: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap()
            .trim()
            .to_owned()
    };
    let (token, hash) = (field("token:"), field("token_sha256:"));
    let alphabet = |s: &str| {
        s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    };
    assert!(token.len() == 22 && alphabet(&token), "token {token}");
    let want: String = Sha256::digest(&token)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hash, want);
    assert!(field("token:") != field("token_sha256:"));
    assert!(run("mint-token") != out, "two tokens alike");

    let id = run("mint-id");
    let id = id.trim();
    assert!(id.len() == 22 && alphabet(id), "id {id}");
    assert!(!id.contains("token"));
}
