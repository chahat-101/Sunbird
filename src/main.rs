//! sunbird: a file-sharing server that stores blobs it never reads and does
//! no cryptography; the browser client, built in, does all of it.
//!
//!     sunbird [-addr 127.0.0.1:8080] [-data data] [-config sunbird.json]

mod app;
mod db;
mod http;

use std::convert::Infallible;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

use crate::app::App;

struct Flags {
    addr: String,
    data: PathBuf,
    config: Option<PathBuf>,
}

impl Flags {
    /// Go's flag syntax: -name value, -name=value, or either with --.
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Flags, String> {
        let mut flags = Flags {
            addr: "127.0.0.1:8080".into(),
            data: "data".into(),
            config: None,
        };
        while let Some(arg) = args.next() {
            let name = arg
                .strip_prefix("--")
                .or_else(|| arg.strip_prefix('-'))
                .ok_or(format!("unexpected argument {arg:?}"))?;
            let (name, value) = match name.split_once('=') {
                Some((name, value)) => (name, value.to_owned()),
                None => (
                    name,
                    args.next().ok_or(format!("flag -{name} needs a value"))?,
                ),
            };
            match name {
                "addr" => flags.addr = value,
                "data" => flags.data = value.into(),
                "config" => flags.config = Some(value.into()),
                _ => return Err(format!("unknown flag -{name}")),
            }
        }
        Ok(flags)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let flags = match Flags::parse(std::env::args().skip(1)) {
        Ok(flags) => flags,
        Err(e) => {
            eprintln!(
                "{e}\nusage: sunbird [-addr 127.0.0.1:8080] [-data data] [-config sunbird.json]"
            );
            return ExitCode::from(2);
        }
    };
    let data = flags.data.clone();
    let app = match tokio::task::spawn_blocking(move || App::open(&data))
        .await
        .expect("open panicked")
    {
        Ok(app) => Arc::new(app),
        Err(e) => {
            log::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match TcpListener::bind(&flags.addr).await {
        Ok(listener) => listener,
        Err(e) => {
            log::error!("listen on {}: {e}", flags.addr);
            return ExitCode::FAILURE;
        }
    };
    if let Some(config) = &flags.config {
        log::warn!(
            "{}: not read; members, quotas and rate limits arrive in session 03",
            config.display()
        );
    }
    log::warn!(
        "uploads are not authenticated and expiry is not enforced yet; do not expose this server"
    );
    log::info!(
        "listening on {}, data in {}",
        flags.addr,
        flags.data.display()
    );

    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                // Out of file descriptors, most likely. Wait, don't spin or die.
                log::error!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let app = app.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let app = app.clone();
                async move { Ok::<_, Infallible>(http::handle(app, req).await) }
            });
            // No overall read timeout: a 100 MB upload on a slow link is
            // legitimate. The headers get 10 seconds.
            let served = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .serve_connection(TokioIo::new(stream), service)
                .await;
            if let Err(e) = served {
                log::debug!("connection: {e}");
            }
        });
    }
}
