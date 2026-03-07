use std::path::PathBuf;
use std::sync::Arc;

use moco::audit::AuditLogger;
use moco::config::ConfigManager;
use moco::gateway::{Gateway, build_downstream_client};
use moco::security::LocalPiiProvider;
use moco::server::run_stdio_server;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cwd = std::env::current_dir()?;
    let config = ConfigManager::load_resolved(None, &cwd, None)?;

    let mut gateway = Gateway::new(config.security.clone());
    if let Some(path) = std::env::var_os("MCPS_AUDIT_LOG") {
        let max_bytes = std::env::var("MCPS_AUDIT_MAX_BYTES")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10 * 1024 * 1024);
        let max_files = std::env::var("MCPS_AUDIT_MAX_FILES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(3);
        let logger = AuditLogger::new(&PathBuf::from(path), max_bytes, max_files)?;
        gateway = gateway.with_audit_logger(Arc::new(logger));
    }

    gateway = gateway.with_pii_provider(Arc::new(LocalPiiProvider));

    for (server_name, server_cfg) in &config.mcp.servers {
        match build_downstream_client(server_name, server_cfg).await {
            Ok(client) => {
                gateway.register_downstream(server_name.clone(), client);
            }
            Err(err) => {
                eprintln!("failed to initialize downstream server '{server_name}': {err}");
            }
        }
    }

    eprintln!(
        "moco initialized: {} configured server(s), {} detector(s), mode={:?}",
        config.mcp.servers.len(),
        config.security.detectors.len(),
        config.security.mode,
    );

    run_stdio_server(gateway).await?;

    Ok(())
}
