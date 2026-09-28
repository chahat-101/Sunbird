//! The built binary, run in a directory holding nothing but its data, over a
//! real socket.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// The one member's upload token; the config holds only its hash.
const TOKEN: &str = "binary-test-token";

fn config() -> String {
    let hash: String = Sha256::digest(TOKEN)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        r#"{{"members": [{{"id": "AAAAAAAAAAAAAAAAAAAAAA", "name": "m", "token_sha256": "{hash}",
             "max_active_bytes": 1000000000, "max_active_files": 1000, "max_bytes_per_week": 1000000000}}],
            "admins": [], "trusted_proxies": [],
            "upload_rate": {{"requests": 1000, "seconds": 1}}, "read_rate": {{"requests": 1000, "seconds": 1}}}}"#
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
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_sunbird"))
        .args(["-addr", &addr, "-data", "data", "-config", "sunbird.json"])
        .current_dir(&dir)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let running = Running { child, dir, addr };
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(&running.addr).is_err() {
        assert!(Instant::now() < deadline, "sunbird did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    running
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

/// The page is built into the binary: served byte for byte with no web/ beside
/// it.
#[test]
fn serves_the_built_in_page() {
    let s = start();
    assert!(!s.dir.join("web").exists());
    let response = exchange(
        &s.addr,
        "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body.as_bytes(), std::fs::read("web/index.html").unwrap());
}

/// A declared length over max_blob is answered without a byte of the body
/// sent, and the connection is not kept open to drain one.
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

/// The sweeper runs at startup, not only once its first interval has passed: a
/// file that expired while the server was down is deleted with no request for
/// it, blob and row.
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

/// Without a config the server does not start: it has no members, and no
/// limits of its own to fall back on.
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

/// mint-token prints a 128-bit base64url token once, and the SHA-256 that
/// goes in the config; mint-id prints an id, and nothing about a token.
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
