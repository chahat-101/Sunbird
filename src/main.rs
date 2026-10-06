//! sunbird: a file-sharing server that stores blobs it never reads. The built-in
//! browser client does all the cryptography.
//!
//!     sunbird [-addr 127.0.0.1:8080] [-data data] [-config sunbird.json]
//!     sunbird mint-token
//!     sunbird mint-id

mod app;
mod config;
mod counters;
mod db;
mod google;
mod http;
mod limit;

use std::convert::Infallible;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinSet;

use crate::app::App;
use crate::config::Config;

/// How often the sweeper runs. Expired files are refused immediately; this only
/// bounds how long their bytes stay on disk.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// How often the counters are saved: a crash loses at most this much of them.
const SAVE_COUNTERS_EVERY: Duration = Duration::from_secs(60);

/// How often the counters are logged, for reading without a metrics stack.
const LOG_COUNTERS_EVERY: Duration = Duration::from_secs(3600);

/// How long transfers get to finish after SIGTERM. deploy/sunbird.service allows
/// longer than this before killing the process.
const GRACE: Duration = Duration::from_secs(30);

const USAGE: &str = "usage: sunbird [-addr 127.0.0.1:8080] [-data data] [-config sunbird.json]
       sunbird mint-token   a new upload or admin token, and the hash for the config
       sunbird mint-id      a new member or admin id, for the config";

struct Flags {
    addr: String,
    data: PathBuf,
    config: PathBuf,
}

impl Flags {
    /// Go's flag syntax: -name value, -name=value, or either with --.
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Flags, String> {
        let mut flags = Flags {
            addr: "127.0.0.1:8080".into(),
            data: "data".into(),
            config: "sunbird.json".into(),
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
                "config" => flags.config = value.into(),
                _ => return Err(format!("unknown flag -{name}")),
            }
        }
        Ok(flags)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        // Printed once and stored nowhere; the config gets only the hash. Separate
        // from mint-id, so a new token never changes who owns what.
        ["mint-token"] => {
            let token = config::mint_token();
            println!("token:        {token}");
            println!(
                "token_sha256: {}",
                config::hex(&config::token_sha256(&token))
            );
            println!();
            println!(
                "Give the token to its holder; it is not stored anywhere and cannot be shown again."
            );
            println!("Put token_sha256 in the config, in their member or admin entry.");
            return ExitCode::SUCCESS;
        }
        ["mint-id"] => {
            println!("{}", config::MemberId::mint());
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    let flags = match Flags::parse(args.into_iter()) {
        Ok(flags) => flags,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let config = match Config::read(&flags.config) {
        Ok(config) => config,
        Err(e) => {
            log::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    log::info!(
        "{} members, {} admins, trusted proxies: {:?}",
        config.members.len(),
        config.admins.len(),
        config.trusted_proxies
    );
    let data = flags.data.clone();
    let app = match tokio::task::spawn_blocking(move || App::open(&data, config))
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
    log::info!(
        "listening on {}, data in {}",
        flags.addr,
        flags.data.display()
    );

    // Registered before accepting connections, so SIGTERM always shuts down
    // cleanly and saves the counters.
    let (mut sigterm, mut sigint) = match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(term), Ok(int)) => (term, int),
        (Err(e), _) | (_, Err(e)) => {
            log::error!("cannot handle signals: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut background = JoinSet::new();
    // The first tick is immediate, so startup sweeps too. Nothing else deletes
    // expired files.
    background.spawn({
        let app = app.clone();
        async move {
            let mut every = tokio::time::interval(SWEEP_EVERY);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                every.tick().await;
                app.upload_limit.forget_idle();
                app.read_limit.forget_idle();
                let app = app.clone();
                match tokio::task::spawn_blocking(move || app.sweep()).await {
                    Ok(Ok((0, 0))) => {}
                    Ok(Ok((deleted, failed))) => {
                        log::info!("sweep: deleted {deleted} files, {failed} could not be")
                    }
                    Ok(Err(e)) => log::error!("sweep: {e}"),
                    Err(e) => log::error!("sweep panicked: {e}"),
                }
            }
        }
    });
    background.spawn({
        let app = app.clone();
        async move {
            let start = tokio::time::Instant::now();
            let mut save =
                tokio::time::interval_at(start + SAVE_COUNTERS_EVERY, SAVE_COUNTERS_EVERY);
            let mut report =
                tokio::time::interval_at(start + LOG_COUNTERS_EVERY, LOG_COUNTERS_EVERY);
            loop {
                tokio::select! {
                    _ = save.tick() => {
                        let app = app.clone();
                        match tokio::task::spawn_blocking(move || app.save_counters()).await {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => log::error!("saving the counters: {e}"),
                            Err(e) => log::error!("saving the counters panicked: {e}"),
                        }
                    }
                    _ = report.tick() => log::info!("counters: {}", app.counters.json()),
                }
            }
        }
    });

    let graceful = GracefulShutdown::new();
    let mut connections = JoinSet::new();
    let stop = loop {
        tokio::select! {
            _ = sigterm.recv() => break "SIGTERM",
            _ = sigint.recv() => break "SIGINT",
            // Reaps connections that have ended, so the set holds only live ones.
            Some(_) = connections.join_next() => {}
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        // Out of file descriptors, most likely. Wait, don't spin or die.
                        log::error!("accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let app = app.clone();
                let service = service_fn(move |req| {
                    let app = app.clone();
                    async move { Ok::<_, Infallible>(http::handle(app, peer.ip(), req).await) }
                });
                // No overall read timeout: slow 100 MB uploads are legitimate. Headers get
                // 10 seconds.
                let served = graceful.watch(
                    http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(10))
                        .serve_connection(TokioIo::new(stream), service),
                );
                connections.spawn(async move {
                    if let Err(e) = served.await {
                        log::debug!("connection: {e}");
                    }
                });
            }
        }
    };

    // Shutdown: stop accepting, let requests in progress finish, close idle
    // connections, and cut off anything still running after GRACE. Every path
    // saves the counters and closes the database.
    drop(listener);
    log::info!(
        "{stop}: no longer accepting connections; waiting up to {} s for {} to finish",
        GRACE.as_secs(),
        connections.len()
    );
    if tokio::time::timeout(GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        log::warn!(
            "cutting off {} connections still open after {} s",
            connections.len(),
            GRACE.as_secs()
        );
    }
    connections.shutdown().await;
    background.shutdown().await;
    // Cut-off downloads record their refund on a blocking thread; save after
    // those finish.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while Arc::strong_count(&app) > 1 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let saved = app.save_counters();
    log::info!("counters: {}", app.counters.json());
    match (saved, Arc::try_unwrap(app)) {
        (Ok(()), Ok(app)) => {
            drop(app); // closes the database
            log::info!("stopped");
            ExitCode::SUCCESS
        }
        (Ok(()), Err(_)) => {
            log::warn!(
                "stopped with work still holding the database; it closes as the process exits"
            );
            ExitCode::SUCCESS
        }
        (Err(e), _) => {
            log::error!("saving the counters at shutdown: {e}");
            ExitCode::FAILURE
        }
    }
}
