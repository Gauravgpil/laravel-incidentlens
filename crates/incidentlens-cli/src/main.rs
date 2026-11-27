use chrono::{Duration as ChronoDuration, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use crossterm::tty::IsTty;
use incidentlens_analyzer::{
    AnalyzerError, DatabaseAnalyzer, DependencyAnalyzer, LogAnalyzer, MigrationAnalyzer,
    PerformanceAnalyzer, ProjectAnalyzer, QueueAnalyzer, SecurityAnalyzer,
};
use incidentlens_core::{
    is_protocol_compatible, CoreError, ExitCode, ProjectMetadata, ProtocolInfo, RequestEnvelope,
    ResponseEnvelope, Severity, ENGINE_VERSION, PROTOCOL_VERSION,
};
use incidentlens_correlator::engine::CorrelationInput;
use incidentlens_correlator::CorrelationEngine;
use incidentlens_parser::{parse_runtime_jsonl, LogFilter, LogLevel};
use incidentlens_reporter::{render_html, render_markdown, render_terminal_report};
use incidentlens_storage::{compare_snapshots, load_snapshot, save_snapshot};
use incidentlens_tui::run_tui;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Markdown,
    Html,
}

#[derive(Debug, Parser)]
#[command(
    name = "incidentlens",
    version = ENGINE_VERSION,
    about = "Laravel IncidentLens — Rust-powered diagnostic engine & TUI for Laravel applications"
)]
struct Cli {
    /// Target Laravel project directory (defaults to current working directory)
    #[arg(long, global = true)]
    project: Option<PathBuf>,

    /// Output format
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Shorthand for --format=json
    #[arg(long, global = true)]
    json: bool,

    /// Disable interactive TUI/prompts and ANSI styling
    #[arg(long, global = true)]
    no_interaction: bool,

    /// Write output to a file path
    #[arg(long, short, global = true)]
    output: Option<PathBuf>,

    /// Enable verbose diagnostic logging to stderr
    #[arg(long, short, global = true)]
    verbose: bool,

    /// Suppress non-essential output
    #[arg(long, short, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Launch interactive TUI dashboard (or print status in non-TTY/CI)
    Status,
    /// Run full diagnostic scan across all modules
    Scan {
        /// Read structured RequestEnvelope JSON from stdin
        #[arg(long)]
        stdin_json: bool,
        /// Exit with code 1 if high or critical findings are detected
        #[arg(long)]
        ci: bool,
    },
    /// Analyze Laravel logs (Monolog, daily, JSONL, stack traces)
    Logs {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        level: Option<String>,
        #[arg(long)]
        search: Option<String>,
        #[arg(long)]
        fingerprint: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Analyze database query fingerprints, slow queries, and N+1 candidates
    Database {
        #[arg(long, default_value_t = 500.0)]
        slow_ms: f64,
    },
    /// Analyze queue job failures and worker exceptions
    Queue,
    /// Analyze endpoint latency (P50/P95/P99) and memory metrics
    Performance {
        #[arg(long, default_value_t = 1000.0)]
        slow_ms: f64,
    },
    /// Run read-only Laravel security configuration diagnostics
    Security,
    /// Inspect database migrations for destructive operations and rollback gaps
    Migration,
    /// Inspect Composer dependency constraints and manifest metadata
    Dependencies,
    /// Save a diagnostic snapshot for future comparison
    Snapshot {
        /// Snapshot identifier (e.g. pre-deploy)
        name: String,
    },
    /// Compare two diagnostic snapshots and detect regressions
    Compare {
        /// Baseline snapshot name or file path
        baseline: String,
        /// Current snapshot name or file path
        current: String,
    },
    /// Generate a diagnostic report (html, markdown, json, text)
    Report,
    /// Verify Rust engine, protocol compatibility, and project readiness
    Doctor,
    /// Display engine and protocol version information
    Version,
    /// Display protocol compatibility metadata
    Protocol,
}

fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        let _ = tracing_subscriber::fmt()
            .with_writer(io::stderr)
            .with_env_filter("info")
            .try_init();
    }

    let format = if cli.json {
        OutputFormat::Json
    } else {
        cli.format
    };

    let exit_code = match run(&cli, format) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::InternalError
        }
    };

    process::exit(exit_code.code());
}

fn use_color(cli: &Cli) -> bool {
    !cli.no_interaction
        && std::env::var_os("NO_COLOR").is_none()
        && io::stdout().is_tty()
}

fn run(cli: &Cli, format: OutputFormat) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match &cli.command {
        Some(Commands::Version) => {
            let info = ProtocolInfo::default();
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!(
                    "Laravel IncidentLens v{} (protocol v{})",
                    info.engine_version, info.protocol_version
                );
            }
            Ok(ExitCode::Success)
        }
        Some(Commands::Protocol) => {
            let info = ProtocolInfo::default();
            println!("{}", serde_json::to_string_pretty(&info)?);
            Ok(ExitCode::Success)
        }
        Some(Commands::Doctor) => run_doctor(cli, format),
        Some(Commands::Scan { stdin_json, ci }) => run_scan(cli, format, *stdin_json, *ci),
        Some(Commands::Logs {
            since,
            level,
            search,
            fingerprint,
            limit,
        }) => run_module_logs(cli, format, since.as_deref(), level.as_deref(), search.clone(), fingerprint.clone(), *limit),
        Some(Commands::Database { slow_ms }) => run_filtered_scan(cli, format, Some("database"), *slow_ms, 1000.0),
        Some(Commands::Queue) => run_filtered_scan(cli, format, Some("queue"), 500.0, 1000.0),
        Some(Commands::Performance { slow_ms }) => run_filtered_scan(cli, format, Some("performance"), 500.0, *slow_ms),
        Some(Commands::Security) => run_filtered_scan(cli, format, Some("security"), 500.0, 1000.0),
        Some(Commands::Migration) => run_filtered_scan(cli, format, Some("migration"), 500.0, 1000.0),
        Some(Commands::Dependencies) => run_filtered_scan(cli, format, Some("dependencies"), 500.0, 1000.0),
        Some(Commands::Snapshot { name }) => run_snapshot(cli, format, name),
        Some(Commands::Compare { baseline, current }) => run_compare(cli, format, baseline, current),
        Some(Commands::Report) => run_scan(cli, format, false, false),
        Some(Commands::Status) => run_status(cli, format, false),
        None => run_status(cli, format, true),
    }
}

fn resolve_project_path(cli: &Cli) -> Result<PathBuf, io::Error> {
    match &cli.project {
        Some(p) => Ok(p.clone()),
        None => std::env::current_dir(),
    }
}

fn build_full_response(
    project_path: &Path,
    runtime_meta: Option<&ProjectMetadata>,
    log_filter: &LogFilter,
    slow_query_ms: f64,
    slow_endpoint_ms: f64,
) -> Result<ResponseEnvelope, AnalyzerError> {
    let project_analysis = ProjectAnalyzer::analyze(project_path, runtime_meta)?;
    let (log_res, log_findings) = LogAnalyzer::analyze(project_path, log_filter);

    let runtime_jsonl = project_path
        .join("storage")
        .join("app")
        .join("incidentlens")
        .join("runtime.jsonl");
    let runtime_events = parse_runtime_jsonl(&runtime_jsonl);

    let db_analysis = DatabaseAnalyzer::analyze(&runtime_events, &log_res.groups, slow_query_ms);
    let queue_analysis = QueueAnalyzer::analyze(&runtime_events, &log_res.groups);
    let perf_analysis = PerformanceAnalyzer::analyze(&runtime_events, slow_endpoint_ms);
    let sec_findings = SecurityAnalyzer::analyze(project_path, &project_analysis.report);
    let mig_findings = MigrationAnalyzer::analyze(project_path);
    let dep_findings = DependencyAnalyzer::analyze(project_path);

    let mut findings = Vec::new();
    findings.extend(project_analysis.findings);
    findings.extend(log_findings);
    findings.extend(db_analysis.findings);
    findings.extend(queue_analysis.findings);
    findings.extend(perf_analysis.findings);
    findings.extend(sec_findings);
    findings.extend(mig_findings);
    findings.extend(dep_findings);

    let incidents = CorrelationEngine::new().correlate(&CorrelationInput {
        findings: &findings,
        runtime_events: &runtime_events,
    });

    let mut resp = ResponseEnvelope::ok(Some(project_analysis.report), findings);
    resp.incidents = incidents;
    Ok(resp)
}

fn run_status(
    cli: &Cli,
    format: OutputFormat,
    allow_tui: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let project_path = resolve_project_path(cli)?;
    match build_full_response(&project_path, None, &LogFilter::default(), 500.0, 1000.0) {
        Ok(resp) => {
            if allow_tui && format == OutputFormat::Text && !cli.no_interaction && io::stdout().is_tty() {
                let p = project_path.clone();
                run_tui(resp, move || {
                    build_full_response(&p, None, &LogFilter::default(), 500.0, 1000.0).ok()
                })?;
                return Ok(ExitCode::Success);
            }
            emit_response(cli, format, &resp)?;
            Ok(ExitCode::Success)
        }
        Err(err) => Ok(handle_analyzer_error(err, format)),
    }
}

fn run_scan(
    cli: &Cli,
    format: OutputFormat,
    stdin_json: bool,
    ci: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let (project_path, runtime_meta): (PathBuf, Option<ProjectMetadata>) = if stdin_json {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        let req: RequestEnvelope = match serde_json::from_str(&buf) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: malformed JSON request on stdin: {e}");
                return Ok(ExitCode::InvalidInput);
            }
        };
        if !req.protocol_version.is_empty() && !is_protocol_compatible(&req.protocol_version) {
            eprintln!(
                "error: incompatible protocol version '{}' (engine supports {}.x)",
                req.protocol_version,
                PROTOCOL_VERSION.split('.').next().unwrap_or("1")
            );
            return Ok(ExitCode::UnsupportedProject);
        }
        let path = req
            .project
            .as_ref()
            .filter(|p| !p.root.is_empty())
            .map(|p| PathBuf::from(&p.root))
            .unwrap_or_else(|| resolve_project_path(cli).unwrap_or_else(|_| PathBuf::from(".")));
        (path, req.project)
    } else {
        (resolve_project_path(cli)?, None)
    };

    match build_full_response(&project_path, runtime_meta.as_ref(), &LogFilter::default(), 500.0, 1000.0) {
        Ok(resp) => {
            let has_blocking = resp
                .findings
                .iter()
                .any(|f| matches!(f.severity, Severity::High | Severity::Critical));
            emit_response(cli, format, &resp)?;
            if ci && has_blocking {
                Ok(ExitCode::ThresholdExceeded)
            } else {
                Ok(ExitCode::Success)
            }
        }
        Err(err) => Ok(handle_analyzer_error(err, format)),
    }
}

fn run_filtered_scan(
    cli: &Cli,
    format: OutputFormat,
    module: Option<&str>,
    slow_query_ms: f64,
    slow_endpoint_ms: f64,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let project_path = resolve_project_path(cli)?;
    match build_full_response(&project_path, None, &LogFilter::default(), slow_query_ms, slow_endpoint_ms) {
        Ok(mut resp) => {
            if let Some(m) = module {
                resp.findings.retain(|f| f.module == m);
            }
            emit_response(cli, format, &resp)?;
            Ok(ExitCode::Success)
        }
        Err(err) => Ok(handle_analyzer_error(err, format)),
    }
}

fn run_module_logs(
    cli: &Cli,
    format: OutputFormat,
    since: Option<&str>,
    level: Option<&str>,
    search: Option<String>,
    fingerprint: Option<String>,
    limit: Option<usize>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let project_path = resolve_project_path(cli)?;
    let since_dt = since.and_then(parse_since);
    let min_level = level.and_then(LogLevel::from_str_lossy);
    let filter = LogFilter {
        min_level,
        since: since_dt,
        search,
        fingerprint,
        limit,
        max_file_size_bytes: None,
    };

    match build_full_response(&project_path, None, &filter, 500.0, 1000.0) {
        Ok(mut resp) => {
            resp.findings.retain(|f| f.module == "logs");
            emit_response(cli, format, &resp)?;
            Ok(ExitCode::Success)
        }
        Err(err) => Ok(handle_analyzer_error(err, format)),
    }
}

fn run_snapshot(
    cli: &Cli,
    format: OutputFormat,
    name: &str,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let project_path = resolve_project_path(cli)?;
    match build_full_response(&project_path, None, &LogFilter::default(), 500.0, 1000.0) {
        Ok(resp) => {
            let snap_dir = project_path.join("storage/app/incidentlens/snapshots");
            let saved = save_snapshot(&snap_dir, name, None, &resp)?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::json!({"snapshot_path": saved.display().to_string()}));
            } else {
                println!("Saved snapshot '{}' to {}", name, saved.display());
            }
            Ok(ExitCode::Success)
        }
        Err(err) => Ok(handle_analyzer_error(err, format)),
    }
}

fn run_compare(
    cli: &Cli,
    format: OutputFormat,
    baseline: &str,
    current: &str,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let project_path = resolve_project_path(cli)?;
    let snap_dir = project_path.join("storage/app/incidentlens/snapshots");
    let p1 = resolve_snapshot_path(&snap_dir, baseline);
    let p2 = resolve_snapshot_path(&snap_dir, current);

    let s1 = load_snapshot(&p1)?;
    let s2 = load_snapshot(&p2)?;
    let diff = compare_snapshots(&s1, &s2);

    let resp = ResponseEnvelope::ok(None, diff.regression_findings);
    emit_response(cli, format, &resp)?;
    Ok(ExitCode::Success)
}

fn resolve_snapshot_path(snap_dir: &Path, arg: &str) -> PathBuf {
    let direct = PathBuf::from(arg);
    if direct.is_file() {
        direct
    } else {
        snap_dir.join(format!("{arg}.json"))
    }
}

fn run_doctor(cli: &Cli, format: OutputFormat) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let project_path = resolve_project_path(cli)?;
    let info = ProtocolInfo::default();

    match ProjectAnalyzer::analyze(&project_path, None) {
        Ok(analysis) => {
            if format == OutputFormat::Json {
                let payload = serde_json::json!({
                    "protocol": info,
                    "project_detected": true,
                    "project": analysis.report,
                    "checks": {
                        "engine_ok": true,
                        "laravel_detected": true,
                        "env_present": analysis.report.has_env_file,
                        "composer_lock_present": analysis.report.has_composer_lock,
                        "logs_readable": analysis.report.log_files_count > 0 || project_path.join("storage/logs").is_dir()
                    }
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else if !cli.quiet {
                println!("IncidentLens Doctor");
                println!("  [OK] Rust Engine: v{} (Protocol v{})", info.engine_version, info.protocol_version);
                println!("  [OK] Laravel Project: {} ({})", analysis.report.name, analysis.report.root);
                println!(
                    "  [{}] .env file: {}",
                    if analysis.report.has_env_file { "OK" } else { "WARN" },
                    if analysis.report.has_env_file { "present" } else { "missing" }
                );
                println!(
                    "  [{}] composer.lock: {}",
                    if analysis.report.has_composer_lock { "OK" } else { "WARN" },
                    if analysis.report.has_composer_lock { "present" } else { "missing" }
                );
                println!("  [OK] Log files found: {}", analysis.report.log_files_count);
            }
            Ok(ExitCode::Success)
        }
        Err(err) => Ok(handle_analyzer_error(err, format)),
    }
}

fn emit_response(
    cli: &Cli,
    format: OutputFormat,
    resp: &ResponseEnvelope,
) -> Result<(), io::Error> {
    if cli.quiet && cli.output.is_none() {
        return Ok(());
    }
    let rendered = match format {
        OutputFormat::Json => serde_json::to_string_pretty(resp).unwrap_or_default(),
        OutputFormat::Markdown => render_markdown(resp),
        OutputFormat::Html => render_html(resp),
        OutputFormat::Text => render_terminal_report(resp, use_color(cli)),
    };

    if let Some(ref out_path) = cli.output {
        fs::write(out_path, rendered)?;
    } else {
        print!("{rendered}");
    }
    Ok(())
}

fn handle_analyzer_error(err: AnalyzerError, format: OutputFormat) -> ExitCode {
    let code = match &err {
        AnalyzerError::NotALaravelProject(_, _) => ExitCode::UnsupportedProject,
        AnalyzerError::Core(CoreError::InvalidPath(_, _))
        | AnalyzerError::Core(CoreError::PathTraversal(_, _)) => ExitCode::InvalidInput,
        _ => ExitCode::InternalError,
    };

    if format == OutputFormat::Json {
        let mut resp = ResponseEnvelope::ok(None, Vec::new());
        resp.status = "error".to_string();
        resp.errors.push(err.to_string());
        if let Ok(json) = serde_json::to_string_pretty(&resp) {
            println!("{json}");
        }
    } else {
        eprintln!("error: {err}");
    }
    code
}

fn parse_since(s: &str) -> Option<chrono::DateTime<Utc>> {
    let trimmed = s.trim();
    if let Some(hours) = trimmed.strip_suffix('h').and_then(|n| n.parse::<i64>().ok()) {
        return Some(Utc::now() - ChronoDuration::hours(hours));
    }
    if let Some(days) = trimmed.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
        return Some(Utc::now() - ChronoDuration::days(days));
    }
    None
}
