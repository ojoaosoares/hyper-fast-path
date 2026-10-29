//! A static file server whose requests can be answered from the kernel.

use hyper_fast_path::{
    OpenObject,
    fast_path::{self, FastPath},
    listener::BeeperListener,
    server,
};
use axum::http::{HeaderValue, header::CONTENT_TYPE};
use clap::Parser;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::{
    net::TcpSocket,
    signal::unix::{SignalKind, signal},
};
use tower_http::{
    services::ServeDir, set_header::SetResponseHeaderLayer, trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;

/// The assets served with the fast path unless told otherwise.
const DEFAULT_ROUTES: &[&str] = &[
    "/1KB.txt",
    "/8KB.txt",
    "/16KB.txt",
    "/32KB.txt",
    "/48KB.txt",
    "/64KB.txt",
    "/128KB.txt",
];

/// A static file server that can answer its smaller assets from eBPF.
#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Disable the eBPF fast path.
    #[arg(long)]
    no_fastpath: bool,

    /// The address to listen on.
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    addr: SocketAddr,

    /// The number of connections the fast path runs on at once.
    #[arg(long, default_value_t = fast_path::DEFAULT_DUMMIES)]
    dummies: usize,

    /// The directory the assets are served from. Defaults to the example's own
    /// `assets` directory.
    #[arg(long)]
    assets_dir: Option<PathBuf>,

    /// The request paths served with the fast path, comma separated. Each one
    /// names a file relative to the assets directory.
    #[arg(
        long,
        value_delimiter = ',',
        default_values_t = DEFAULT_ROUTES.iter().map(|route| route.to_string())
    )]
    routes: Vec<String>,

    /// The `Content-Type` every asset is served with, by the fast path and
    /// user space alike, instead of the one guessed from its extension.
    #[arg(long)]
    content_type: Option<HeaderValue>,

    /// The most connections the kernel queues up for the server to accept.
    /// Capped at `net.core.somaxconn`.
    #[arg(long, default_value_t = 1024)]
    backlog: u32,

    /// A file to write the fast path's stats to as `name,value` lines once the
    /// server is stopped with SIGINT or SIGTERM.
    #[arg(long)]
    stats_file: Option<PathBuf>,
}

/// All assets that are served with the fast path.
fn fastpath_routes(assets_dir: &Path, routes: &[String]) -> HashMap<String, PathBuf> {
    routes
        .iter()
        .map(|path| {
            // a request path is absolute, a file in the assets directory is not
            let file = assets_dir.join(path.trim_start_matches('/'));
            (path.to_string(), file)
        })
        .collect()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let assets_dir = args
        .assets_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/assets")));
    let serve_dir = ServeDir::new(&assets_dir);

    let app = axum::Router::new()
        .fallback_service(serve_dir)
        .layer(SetResponseHeaderLayer::overriding(
            CONTENT_TYPE,
            args.content_type.clone(),
        ))
        .layer(TraceLayer::new_for_http());

    // the fast path has to outlive the server, and nothing of it is loaded
    // unless it was asked for
    let mut open_obj = OpenObject::new();
    let fastpath = if args.no_fastpath {
        tracing::info!("Running without the eBPF fast path");
        None
    } else {
        let routes = fastpath_routes(&assets_dir, &args.routes);
        let content_type = args.content_type.as_ref().map(|value| {
            value
                .to_str()
                .expect("Content-Type is not visible ASCII")
        });
        Some(
            FastPath::attach(args.addr, &mut open_obj, routes, args.dummies, content_type)
                .expect("attach"),
        )
    };

    let socket = match args.addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .unwrap();
    // what `TcpListener::bind` would have done, but with a backlog of our own
    socket.set_reuseaddr(true).unwrap();
    socket.bind(args.addr).unwrap();
    let listener = socket.listen(args.backlog).unwrap();
    let listener = BeeperListener::new(listener);
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    let mut terminate = signal(SignalKind::terminate()).unwrap();
    tokio::select! {
        _ = server::serve(listener, app) => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }

    let Some(fastpath) = fastpath else {
        return;
    };

    let stats = fastpath.stats().expect("stats");
    tracing::info!("Fast path stats: {stats:?}");

    if let Some(stats_file) = &args.stats_file {
        let lines: String = stats
            .fields()
            .iter()
            .map(|(name, value)| format!("{name},{value}\n"))
            .collect();
        std::fs::write(stats_file, lines).expect("write stats");
    }
}
