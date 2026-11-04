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
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpSocket},
    signal::unix::{SignalKind, signal},
};
use tokio_rustls::TlsAcceptor;
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

    /// Serve HTTP/1.1 over TLS 1.2 (ECDHE-ECDSA-AES128-GCM-SHA256) with this
    /// PEM certificate, handing the session to kTLS once the handshake is done.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// The PEM private key of `--tls-cert`.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
}

/// TLS 1.2 with the one cipher suite kTLS and the benchmark's other servers
/// share, its secrets extractable for kTLS.
fn tls_acceptor(cert: &Path, key: &Path) -> TlsAcceptor {
    use rustls::crypto::aws_lc_rs;

    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert).expect("open TLS certificate"),
    ))
    .collect::<Result<Vec<_>, _>>()
    .expect("read TLS certificate");
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key).expect("open TLS key"),
    ))
    .expect("read TLS key")
    .expect("no private key in the TLS key file");

    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        ..aws_lc_rs::default_provider()
    };
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("TLS certificate and key");
    config.enable_secret_extraction = true;
    TlsAcceptor::from(Arc::new(config))
}

/// Serves `app` over TLS on `listener`: rustls does the handshake, kTLS
/// everything after it, and the connection is plain HTTP/1.1 to the server.
/// The fast path sees the connection from the moment the kernel accepted it.
async fn serve_tls(listener: TcpListener, acceptor: TlsAcceptor, app: axum::Router) {
    use axum::{body::Body, extract::Request};
    use tower::ServiceExt;

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("failed to accept a connection: {e}");
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls = match acceptor.accept(ktls::CorkStream::new(tcp)).await {
                Ok(tls) => tls,
                Err(e) => return tracing::debug!("TLS handshake with {peer} failed: {e}"),
            };
            let stream = match ktls::config_ktls_server(tls).await {
                Ok(stream) => stream,
                Err(e) => return tracing::error!("kTLS setup for {peer} failed: {e}"),
            };

            let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                let app = app.clone();
                async move { app.oneshot(req.map(Body::new)).await }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await
            {
                tracing::debug!("connection from {peer} ended: {e}");
            }
        });
    }
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
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    let mut terminate = signal(SignalKind::terminate()).unwrap();
    match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            let acceptor = tls_acceptor(cert, key);
            tokio::select! {
                _ = serve_tls(listener, acceptor, app) => {}
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
        _ => {
            let listener = BeeperListener::new(listener);
            tokio::select! {
                _ = server::serve(listener, app) => {}
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
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
