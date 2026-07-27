//! YapaYapa backend: an encrypted relay and metadata service. It stores
//! usernames, public identity keys, password hashes, ciphertext envelopes,
//! and encrypted attachment blobs — never private keys or plaintext.

pub mod auth;
pub mod http;
pub mod state;
pub mod store;
pub mod ws;

use std::net::SocketAddr;
use std::sync::Arc;

use state::AppState;
use store::mem::MemStore;
use store::pg::PgStore;
use store::Store;

pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: Option<String>,
    pub migrations_dir: String,
    pub mem_store: bool,
    pub max_attachment_bytes: u64,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let bind_addr = std::env::var("BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".into())
            .parse()?;
        Ok(Self {
            bind_addr,
            database_url: std::env::var("DATABASE_URL").ok(),
            migrations_dir: std::env::var("MIGRATIONS_DIR")
                .unwrap_or_else(|_| "./migrations".into()),
            mem_store: std::env::var("YAPAYAPA_MEM_STORE").as_deref() == Ok("1"),
            max_attachment_bytes: std::env::var("YAPAYAPA_MAX_ATTACHMENT_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(yapayapa_common::validate::DEFAULT_MAX_ATTACHMENT_BYTES),
        })
    }
}

pub async fn build_store(config: &Config) -> anyhow::Result<Box<dyn Store>> {
    if config.mem_store {
        tracing::warn!("using in-memory store: all data is lost on restart (development only)");
        return Ok(Box::new(MemStore::new()));
    }
    let url = config
        .database_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("DATABASE_URL is required (or set YAPAYAPA_MEM_STORE=1)"))?;
    let store = PgStore::connect(url, &config.migrations_dir).await?;
    tracing::info!("connected to PostgreSQL and applied migrations");
    Ok(Box::new(store))
}

/// Bind and serve. Returns the actual bound address (useful when binding
/// port 0 in tests) and a future that runs the server.
pub async fn serve(
    config: Config,
    store: Box<dyn Store>,
) -> anyhow::Result<(
    SocketAddr,
    impl std::future::Future<Output = std::io::Result<()>>,
)> {
    let state = Arc::new(AppState::new(store, config.max_attachment_bytes));
    let app = http::router(state);
    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let addr = listener.local_addr()?;
    let fut = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    );
    Ok((addr, async move { fut.await }))
}
