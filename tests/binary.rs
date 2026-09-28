//! The built binary, run in a directory holding nothing but its data, over a
//! real socket.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
    let dir = std::env::temp_dir().join(format!(
        "sunbird-binary-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_sunbird"))
        .args(["-addr", &addr, "-data", "data"])
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
             Content-Length: 104931329\r\nExpect: 100-continue\r\n\r\n"
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
            "POST /api/upload?expires_at={expires}&max_downloads=0 HTTP/1.1\r\nHost: x\r\nContent-Length: 9223372036854775807\r\n\r\n"
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
