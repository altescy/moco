use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Parser, Subcommand, ValueEnum};
use moco::audit::AuditLogger;
use moco::config::{ConfigManager, RawConfig, ServerConfig, TransportType};
use moco::gateway::{Gateway, build_downstream_client};
use moco::security::LocalPiiProvider;
use moco::server::run_stdio_server;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "moco", version, about = "MCP Observation and Control Operator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Serve(ServeCommand),
    Add(AddCommand),
}

#[derive(Args, Debug)]
struct ServeCommand {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum CliTransport {
    Stdio,
    StreamableHttp,
}

impl From<CliTransport> for TransportType {
    fn from(value: CliTransport) -> Self {
        match value {
            CliTransport::Stdio => TransportType::Stdio,
            CliTransport::StreamableHttp => TransportType::StreamableHttp,
        }
    }
}

#[derive(Args, Debug)]
#[command(
    after_help = "Examples:\n  moco add everything -- npx -y @modelcontextprotocol/server-everything\n  moco add --transport streamable-http sentry https://mcp.sentry.dev/mcp\n  moco add -e API_KEY=xxx my-server -- my-command --some-flag arg1"
)]
struct AddCommand {
    name: String,
    command_or_url: String,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = CliTransport::Stdio)]
    transport: CliTransport,
    #[arg(short = 'e', long = "env", value_parser = parse_key_value)]
    env: Vec<(String, String)>,
    #[arg(short = 'H', long = "header", value_parser = parse_header)]
    headers: Vec<(String, String)>,
    #[arg(long)]
    timeout_ms: Option<u64>,
    #[arg(long)]
    replace: bool,
}

fn parse_key_value(raw: &str) -> Result<(String, String), String> {
    let mut split = raw.splitn(2, '=');
    let key = split
        .next()
        .ok_or_else(|| "expected KEY=VALUE".to_owned())?
        .trim();
    let value = split
        .next()
        .ok_or_else(|| "expected KEY=VALUE".to_owned())?
        .trim();

    if key.is_empty() {
        return Err("KEY must not be empty".to_owned());
    }

    Ok((key.to_owned(), value.to_owned()))
}

fn parse_header(raw: &str) -> Result<(String, String), String> {
    let (key, value) = if let Some((k, v)) = raw.split_once(':') {
        (k.trim(), v.trim())
    } else if let Some((k, v)) = raw.split_once('=') {
        (k.trim(), v.trim())
    } else {
        return Err("expected HEADER:VALUE or HEADER=VALUE".to_owned());
    };

    if key.is_empty() {
        return Err("header name must not be empty".to_owned());
    }

    Ok((key.to_owned(), value.to_owned()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::Serve(command) => run_serve(command).await,
        Commands::Add(command) => run_add(command),
    }
}

async fn run_serve(command: ServeCommand) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let config = ConfigManager::load_resolved(None, &cwd, command.config.as_deref())?;

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

fn run_add(command: AddCommand) -> Result<(), Box<dyn std::error::Error>> {
    validate_add_command(&command)?;

    let cwd = std::env::current_dir()?;
    let path = resolve_project_config_path(&cwd, command.config.as_deref());

    let mut raw = if path.exists() {
        ConfigManager::load_raw(&path)?
    } else {
        RawConfig::default()
    };

    let servers = &mut raw.mcp.get_or_insert_default().servers;
    if servers.contains_key(&command.name) && !command.replace {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "server '{}' already exists in {} (use --replace to overwrite)",
                command.name,
                path.display()
            ),
        )
        .into());
    }

    servers.insert(command.name.clone(), build_server_config(&command));

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let content = toml::to_string_pretty(&raw)?;
    fs::write(&path, content)?;

    eprintln!("saved server '{}' to {}", command.name, path.display());

    Ok(())
}

fn resolve_project_config_path(cwd: &std::path::Path, explicit: Option<&std::path::Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    ConfigManager::find_project_config(cwd).unwrap_or_else(|| cwd.join(".moco.toml"))
}

fn validate_add_command(command: &AddCommand) -> Result<(), io::Error> {
    match command.transport {
        CliTransport::Stdio => {
            if !command.headers.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--header cannot be used with --transport stdio",
                ));
            }
        }
        CliTransport::StreamableHttp => {
            if !command.args.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "extra positional args cannot be used with --transport streamable-http",
                ));
            }
            if !command.env.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--env cannot be used with --transport streamable-http",
                ));
            }
        }
    }

    Ok(())
}

fn build_server_config(command: &AddCommand) -> ServerConfig {
    match command.transport {
        CliTransport::Stdio => ServerConfig {
            transport: TransportType::Stdio,
            command: Some(command.command_or_url.clone()),
            args: command.args.clone(),
            env: command.env.iter().cloned().collect::<BTreeMap<_, _>>(),
            url: None,
            headers: BTreeMap::new(),
            timeout_ms: command.timeout_ms,
        },
        CliTransport::StreamableHttp => ServerConfig {
            transport: TransportType::StreamableHttp,
            command: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            url: Some(command.command_or_url.clone()),
            headers: command.headers.iter().cloned().collect::<BTreeMap<_, _>>(),
            timeout_ms: command.timeout_ms,
        },
    }
}
