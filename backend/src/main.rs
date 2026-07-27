use tracing_subscriber::EnvFilter;
use yapayapa_backend::{build_store, serve, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env()?;
    let store = build_store(&config).await?;
    let (addr, server) = serve(config, store).await?;
    tracing::info!(%addr, "yapayapa backend listening");
    server.await?;
    Ok(())
}
