use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Args, Parser, Subcommand, ValueEnum};
use moco::audit::{AuditLogger, AuditSummary};
use moco::config::{ConfigManager, RawConfig, ServerConfig, TransportType};
use moco::gateway::{Gateway, build_downstream_client};
use moco::paths::{default_audit_db_path, default_project_config_path};
use moco::security::LocalPiiProvider;
use moco::server::run_stdio_server;
use owo_colors::OwoColorize;
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
    List(ListCommand),
    Logs(LogsCommand),
    Report(ReportCommand),
}

#[derive(Args, Debug)]
struct ServeCommand {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    audit_db: Option<PathBuf>,
    #[arg(long)]
    no_audit: bool,
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

#[derive(Args, Debug)]
struct LogsCommand {
    #[arg(long)]
    audit_db: Option<PathBuf>,
    #[arg(long, default_value_t = 50)]
    limit: usize,
}

#[derive(Args, Debug)]
struct ListCommand {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ReportCommand {
    #[arg(long)]
    audit_db: Option<PathBuf>,
    #[arg(long, default_value_t = 10)]
    top_tools: usize,
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
        Commands::List(command) => run_list(command).await,
        Commands::Logs(command) => run_logs(command),
        Commands::Report(command) => run_report(command),
    }
}

fn resolve_global_config_path() -> Option<PathBuf> {
    ConfigManager::default_global_config_path().filter(|p| p.exists())
}

async fn run_serve(command: ServeCommand) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let global_config = resolve_global_config_path();
    let config =
        ConfigManager::load_resolved(global_config.as_deref(), &cwd, command.config.as_deref())?;

    let mut gateway = Gateway::new(config.security.clone());

    if !command.no_audit {
        let audit_path = resolve_audit_db_path(&cwd, command.audit_db.as_deref());
        let logger = AuditLogger::new(&audit_path)?;
        gateway = gateway.with_audit_logger(Arc::new(logger));
        eprintln!("audit enabled: {}", audit_path.display());
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

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }

    let content = toml::to_string_pretty(&raw)?;
    fs::write(&path, content)?;

    eprintln!("saved server '{}' to {}", command.name, path.display());

    Ok(())
}

async fn run_list(command: ListCommand) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let config_path = resolve_project_config_path(&cwd, command.config.as_deref());
    let global_config = resolve_global_config_path();
    let config =
        ConfigManager::load_resolved(global_config.as_deref(), &cwd, command.config.as_deref())?;

    if config.mcp.servers.is_empty() {
        println!("{}", "Moco MCP Servers".bold().truecolor(232, 236, 241));
        println!();
        println!(
            "{:<8} {}",
            "config".bold().truecolor(125, 145, 168),
            config_path.display().to_string().truecolor(162, 176, 192)
        );
        println!(
            "{:<8} {}",
            "servers".bold().truecolor(125, 145, 168),
            "0".bold().truecolor(226, 232, 240)
        );
        return Ok(());
    }

    #[derive(Debug)]
    struct ServerRow {
        name: String,
        transport: &'static str,
        status: &'static str,
        tool_count: Option<usize>,
        detail: String,
    }

    let mut names = config.mcp.servers.keys().cloned().collect::<Vec<_>>();
    names.sort();

    let mut rows = Vec::with_capacity(names.len());

    for name in names {
        let Some(server_cfg) = config.mcp.servers.get(&name) else {
            continue;
        };

        let transport = match server_cfg.transport {
            TransportType::Stdio => "stdio",
            TransportType::StreamableHttp => "streamable-http",
        };

        match build_downstream_client(&name, server_cfg).await {
            Ok(client) => match client.list_tools().await {
                Ok(tools) => {
                    rows.push(ServerRow {
                        name,
                        transport,
                        status: "ok",
                        tool_count: Some(tools.len()),
                        detail: "ready".to_owned(),
                    });
                }
                Err(err) => {
                    rows.push(ServerRow {
                        name,
                        transport,
                        status: "fail",
                        tool_count: None,
                        detail: err.to_string(),
                    });
                }
            },
            Err(err) => {
                rows.push(ServerRow {
                    name,
                    transport,
                    status: "fail",
                    tool_count: None,
                    detail: err.to_string(),
                });
            }
        }
    }

    let ok_count = rows.iter().filter(|row| row.status == "ok").count();
    let fail_count = rows.len().saturating_sub(ok_count);
    let width = terminal_width();

    println!("{}", "Moco MCP Servers".bold().truecolor(232, 236, 241));
    println!();
    println!(
        "{:<8} {}",
        "config".bold().truecolor(125, 145, 168),
        config_path.display().to_string().truecolor(162, 176, 192)
    );
    println!(
        "{:<8} {}",
        "servers".bold().truecolor(125, 145, 168),
        rows.len().to_string().bold().truecolor(226, 232, 240)
    );
    println!(
        "{:<8} {}",
        "ok".bold().truecolor(125, 145, 168),
        ok_count.to_string().bold().green()
    );
    println!(
        "{:<8} {}",
        "fail".bold().truecolor(125, 145, 168),
        fail_count.to_string().bold().red()
    );
    println!();
    println!("{}", horizontal_rule('─', width).truecolor(88, 104, 122));
    println!();

    println!(
        "{}  {}  {}  {}  {}",
        "status".bold().truecolor(158, 187, 214),
        format!("{:<24}", "server").bold().truecolor(158, 187, 214),
        format!("{:<16}", "transport")
            .bold()
            .truecolor(158, 187, 214),
        format!("{:>5}", "tools").bold().truecolor(158, 187, 214),
        "detail".bold().truecolor(158, 187, 214),
    );

    for row in rows {
        let status_plain = format!("{:<6}", row.status);
        let status = if row.status == "ok" {
            status_plain.bold().green().to_string()
        } else {
            status_plain.bold().red().to_string()
        };
        let tools = row
            .tool_count
            .map_or_else(|| "-".to_owned(), |count| count.to_string());
        let detail_width = width.saturating_sub(56).clamp(16, 80);
        let detail = truncate_with_ellipsis(&row.detail, detail_width);
        let server_cell = format!("{:<24}", truncate_with_ellipsis(&row.name, 24));
        let transport_cell = format!("{:<16}", row.transport);
        let tools_cell = format!("{:>5}", tools);

        println!(
            "{}  {}  {}  {}  {}",
            status,
            server_cell.truecolor(210, 218, 228),
            transport_cell.truecolor(192, 204, 216),
            tools_cell.truecolor(192, 204, 216),
            if row.status == "ok" {
                detail.truecolor(122, 190, 140)
            } else {
                detail.truecolor(230, 160, 160)
            }
        );
    }

    Ok(())
}

fn run_logs(command: LogsCommand) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let path = resolve_audit_db_path(&cwd, command.audit_db.as_deref());
    let logger = AuditLogger::new(&path)?;
    let entries = logger.recent_entries(command.limit)?;

    if entries.is_empty() {
        println!("no audit events found in {}", path.display());
        return Ok(());
    }

    for entry in entries.iter().rev() {
        println!(
            "ts={} req={} phase={} status={} tool={} findings={} reasons={} reason_hashes={}",
            entry.timestamp_ms,
            entry.request_id,
            entry.phase,
            entry.status,
            entry.tool,
            entry.findings,
            entry.reasons,
            entry.reason_hashes.join(",")
        );
    }

    Ok(())
}

fn run_report(command: ReportCommand) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let path = resolve_audit_db_path(&cwd, command.audit_db.as_deref());
    let logger = AuditLogger::new(&path)?;
    let summary = logger.summarize(command.top_tools)?;

    print_summary(&summary, &path);
    Ok(())
}

fn print_summary(summary: &AuditSummary, path: &Path) {
    let width = terminal_width();
    let title = "Moco Audit Report"
        .bold()
        .truecolor(232, 236, 241)
        .to_string();
    let db_label = "db    ".bold().truecolor(125, 145, 168).to_string();
    let events_label = "events".bold().truecolor(125, 145, 168).to_string();
    let total_events = summary.total_events.to_string();

    println!("{title}");
    println!();
    println!(
        "{db_label:<8} {}",
        path.display().to_string().truecolor(162, 176, 192)
    );
    println!(
        "{events_label:<8} {}",
        total_events.bold().truecolor(226, 232, 240)
    );
    println!();
    println!("{}", horizontal_rule('─', width).truecolor(88, 104, 122));
    println!();

    print_distribution("Status", &summary.by_status, summary.total_events, width);
    println!();
    print_distribution("Phase", &summary.by_phase, summary.total_events, width);
    println!();
    print_distribution("Top Tools", &summary.top_tools, summary.total_events, width);
}

fn print_distribution(title: &str, values: &[(String, i64)], total: i64, width: usize) {
    println!("{}", title.bold().truecolor(158, 187, 214));
    if values.is_empty() {
        println!("{}", "  (none)".truecolor(122, 134, 148));
        return;
    }

    let max_key_width = width.saturating_sub(24).clamp(12, 42);
    let key_width = values
        .iter()
        .map(|(key, _)| key.chars().count().min(max_key_width))
        .max()
        .unwrap_or(12)
        .max(12);
    let bar_width = width.saturating_sub(key_width + 20).clamp(10, 50);

    for (key, count) in values {
        let plain_label = truncate_with_ellipsis(key, max_key_width);
        let label = format!("{plain_label:<key_width$}");
        let ratio = ratio_percent(*count, total);
        let bar = bar_for_ratio(ratio, bar_width);
        let count_text = format!("{:>6}", count);
        let ratio_text = format!("{:>6.1}%", ratio);
        println!(
            "{}  {}  {}  {}",
            label.truecolor(210, 218, 228),
            count_text.truecolor(192, 204, 216),
            ratio_text.truecolor(152, 170, 190),
            bar
        );
    }
}

fn ratio_percent(count: i64, total: i64) -> f64 {
    if total <= 0 {
        return 0.0;
    }
    (count as f64 / total as f64) * 100.0
}

fn bar_for_ratio(ratio_percent: f64, width: usize) -> String {
    if width == 0 {
        return String::new();
    }

    const FULL: char = '━';
    const TIP: char = '╸';

    let units = (ratio_percent / 100.0) * width as f64;
    let full = units.floor() as usize;
    let has_tip = full < width && (units - full as f64) >= 0.5;

    let filled = full.min(width);
    let tip_cells = usize::from(has_tip);
    let remainder = width.saturating_sub(filled + tip_cells);

    let complete = FULL.to_string().repeat(filled);
    let tip = if has_tip {
        TIP.to_string()
    } else {
        String::new()
    };
    let pending = FULL.to_string().repeat(remainder);

    if should_use_color() {
        let tip_colored = if tip.is_empty() {
            String::new()
        } else {
            tip.cyan().to_string()
        };
        format!(
            "{}{}{}",
            complete.cyan(),
            tip_colored,
            pending.truecolor(90, 95, 105)
        )
    } else {
        format!("{complete}{tip}{pending}")
    }
}

fn should_use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none()
}

fn truncate_with_ellipsis(value: &str, max_width: usize) -> String {
    if value.chars().count() <= max_width {
        return value.to_owned();
    }
    if max_width <= 3 {
        return ".".repeat(max_width);
    }
    let clipped: String = value.chars().take(max_width - 3).collect();
    format!("{clipped}...")
}

fn terminal_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|v| v.clamp(70, 140))
        .unwrap_or(96)
}

fn horizontal_rule(ch: char, width: usize) -> String {
    std::iter::repeat_n(ch, width).collect()
}

fn resolve_project_config_path(cwd: &Path, explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    ConfigManager::find_project_config(cwd).unwrap_or_else(|| default_project_config_path(cwd))
}

fn resolve_audit_db_path(cwd: &Path, explicit: Option<&Path>) -> PathBuf {
    explicit
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| default_audit_db_path(cwd))
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
