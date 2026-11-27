use clap::{Parser, Subcommand, ValueEnum};
use incidentlens_analyzer::{AnalyzerError, ProjectAnalysis, ProjectAnalyzer};
use incidentlens_core::{
    is_protocol_compatible, CoreError, ExitCode, ProjectMetadata, ProtocolInfo, RequestEnvelope,
    ResponseEnvelope, Severity, ENGINE_VERSION, PROTOCOL_VERSION,
};
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "incidentlens",
    version = ENGINE_VERSION,
    about = "Laravel IncidentLens — Rust-powered diagnostic engine for Laravel applications"
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

    /// Disable interactive prompts and ANSI styling
    #[arg(long, global = true)]
    no_interaction: bool,

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
    /// Show Laravel project health and summary dashboard
    Status,
    /// Run diagnostic scan on the Laravel project
    Scan {
        /// Read structured RequestEnvelope JSON from stdin
        #[arg(long)]
        stdin_json: bool,
        /// Exit with code 1 if high or critical findings are detected
        #[arg(long)]
        ci: bool,
    },
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
        Some(Commands::Status) | None => run_status(cli, format),
    }
}

fn resolve_project_path(cli: &Cli) -> Result<PathBuf, io::Error> {
    match &cli.project {
        Some(p) => Ok(p.clone()),
        None => std::env::current_dir(),
    }
}

fn run_status(cli: &Cli, format: OutputFormat) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let project_path = resolve_project_path(cli)?;
    match ProjectAnalyzer::analyze(&project_path, None) {
        Ok(analysis) => {
            if format == OutputFormat::Json {
                let resp = ResponseEnvelope::ok(Some(analysis.report), analysis.findings);
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else if !cli.quiet {
                print_dashboard(&analysis);
            }
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

    match ProjectAnalyzer::analyze(&project_path, runtime_meta.as_ref()) {
        Ok(analysis) => {
            let has_blocking = analysis
                .findings
                .iter()
                .any(|f| matches!(f.severity, Severity::High | Severity::Critical));

            if format == OutputFormat::Json {
                let resp = ResponseEnvelope::ok(Some(analysis.report), analysis.findings);
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else if !cli.quiet {
                print_scan_report(&analysis);
            }

            if ci && has_blocking {
                Ok(ExitCode::ThresholdExceeded)
            } else {
                Ok(ExitCode::Success)
            }
        }
        Err(err) => Ok(handle_analyzer_error(err, format)),
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
                println!(
                    "  [OK] Log files found: {}",
                    analysis.report.log_files_count
                );
            }
            Ok(ExitCode::Success)
        }
        Err(err) => Ok(handle_analyzer_error(err, format)),
    }
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

fn print_dashboard(analysis: &ProjectAnalysis) {
    let r = &analysis.report;
    let errors = analysis
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
        .count();
    let warnings = analysis
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Medium | Severity::Low))
        .count();

    println!("+--------------------------------------------------------------+");
    println!("|  INCIDENTLENS                                      v{:<8} |", ENGINE_VERSION);
    println!("|  Laravel Application Intelligence                            |");
    println!("+--------------------------------------------------------------+");
    println!("|  PROJECT: {:<50} |", truncate(&r.name, 50));
    println!(
        "|  Laravel: {:<14} | Env: {:<14} | Logs: {:<5} |",
        truncate(r.laravel_version.as_deref().unwrap_or("unknown"), 14),
        truncate(r.environment.as_deref().unwrap_or("unknown"), 14),
        r.log_files_count
    );
    println!("+--------------------------------------------------------------+");
    println!("|  HEALTH SUMMARY                                              |");
    println!("|  Errors (High/Crit): {:<6}   Warnings (Low/Med): {:<10} |", errors, warnings);
    println!("+--------------------------------------------------------------+");
    if analysis.findings.is_empty() {
        println!("|  No configuration issues detected in Phase 1 checks.         |");
    } else {
        println!("|  FINDINGS                                                    |");
        for f in &analysis.findings {
            println!("|  - [{:?}] {:<48} |", f.severity, truncate(&f.title, 48));
        }
    }
    println!("+--------------------------------------------------------------+");
}

fn print_scan_report(analysis: &ProjectAnalysis) {
    print_dashboard(analysis);
    if !analysis.findings.is_empty() {
        println!("\nDetailed Findings:");
        for f in &analysis.findings {
            println!(
                "  [{}] {} ({:?})\n    Component: {}\n    Next step: {}",
                f.id, f.title, f.severity, f.affected_component, f.next_step
            );
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(3)).collect();
        out.push_str("...");
        out
    }
}
