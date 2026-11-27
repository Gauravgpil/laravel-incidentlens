use incidentlens_core::{ResponseEnvelope, Severity};
use owo_colors::OwoColorize;
use std::fmt::Write as _;

/// Renders a rich, colorful enterprise CLI report (or clean plain text when `use_color` is false).
pub fn render_terminal_report(resp: &ResponseEnvelope, use_color: bool) -> String {
    let mut out = String::new();

    if use_color {
        let _ = writeln!(
            out,
            "{}",
            "╭────────────────────────────────────────────────────────────────────────────╮"
                .bright_cyan()
        );
        let _ = writeln!(
            out,
            "{}  {}                                          {} {}",
            "│".bright_cyan(),
            "LARAVEL INCIDENTLENS".bold().bright_white(),
            "Engine".dimmed(),
            format!("v{}", resp.engine_version).bright_cyan().bold()
        );
        let _ = writeln!(
            out,
            "{}  {}                                            {}",
            "│".bright_cyan(),
            "Enterprise Diagnostic Intelligence".cyan(),
            format!("Protocol v{}", resp.protocol_version).dimmed()
        );
        let _ = writeln!(
            out,
            "{}",
            "├────────────────────────────────────────────────────────────────────────────┤"
                .bright_cyan()
        );
    } else {
        let _ = writeln!(out, "+----------------------------------------------------------------------------+");
        let _ = writeln!(
            out,
            "|  LARAVEL INCIDENTLENS v{} (Protocol v{})",
            resp.engine_version, resp.protocol_version
        );
        let _ = writeln!(out, "+----------------------------------------------------------------------------+");
    }

    if let Some(ref p) = resp.project {
        let env_str = p.environment.as_deref().unwrap_or("unknown");
        let lv_str = p.laravel_version.as_deref().unwrap_or("unknown");
        if use_color {
            let _ = writeln!(
                out,
                "  {} {}   {} {}   {} {}   {} {}",
                "PROJECT:".bold().bright_blue(),
                p.name.bright_white().bold(),
                "ENV:".bold().bright_blue(),
                if env_str.eq_ignore_ascii_case("production") {
                    env_str.bright_red().bold().to_string()
                } else {
                    env_str.bright_green().bold().to_string()
                },
                "LARAVEL:".bold().bright_blue(),
                lv_str.bright_cyan(),
                "LOGS:".bold().bright_blue(),
                p.log_files_count.to_string().bright_white()
            );
        } else {
            let _ = writeln!(
                out,
                "  PROJECT: {} | ENV: {} | LARAVEL: {} | LOGS: {}",
                p.name, env_str, lv_str, p.log_files_count
            );
        }
    }

    if use_color {
        let _ = writeln!(
            out,
            "  {}  {} {}   {} {}   {} {}   {} {}",
            "HEALTH:".bold().bright_blue(),
            "Errors:".dimmed(),
            resp.summary.errors.to_string().bright_red().bold(),
            "Warnings:".dimmed(),
            resp.summary.warnings.to_string().bright_yellow().bold(),
            "Perf:".dimmed(),
            resp.summary.performance.to_string().bright_magenta().bold(),
            "Security:".dimmed(),
            resp.summary.security.to_string().bright_cyan().bold()
        );
        let _ = writeln!(
            out,
            "{}",
            "╰────────────────────────────────────────────────────────────────────────────╯"
                .bright_cyan()
        );
    } else {
        let _ = writeln!(
            out,
            "  HEALTH: Errors={} Warnings={} Perf={} Security={}",
            resp.summary.errors,
            resp.summary.warnings,
            resp.summary.performance,
            resp.summary.security
        );
        let _ = writeln!(out, "+----------------------------------------------------------------------------+");
    }

    if !resp.incidents.is_empty() {
        let _ = writeln!(out);
        if use_color {
            let _ = writeln!(out, "{}", "  CORRELATED INCIDENTS".bold().bright_magenta());
        } else {
            let _ = writeln!(out, "  CORRELATED INCIDENTS");
        }
        for inc in &resp.incidents {
            let sev = format_severity(inc.severity, use_color);
            let _ = writeln!(out, "  {} [{}] {} (Confidence: {:?})", sev, inc.id, inc.title, inc.confidence);
            let _ = writeln!(out, "     Possible cause: {}", inc.possible_root_cause);
            let _ = writeln!(out, "     Next step: {}", inc.next_step);
        }
    }

    let _ = writeln!(out);
    if resp.findings.is_empty() {
        if use_color {
            let _ = writeln!(out, "  {} {}", "✓".bright_green().bold(), "No diagnostic issues detected.".bright_green());
        } else {
            let _ = writeln!(out, "  [OK] No diagnostic issues detected.");
        }
    } else {
        if use_color {
            let _ = writeln!(out, "  {} ({})", "DIAGNOSTIC FINDINGS".bold().bright_white(), resp.findings.len());
        } else {
            let _ = writeln!(out, "  DIAGNOSTIC FINDINGS ({})", resp.findings.len());
        }
        for f in &resp.findings {
            let badge = format_severity(f.severity, use_color);
            if use_color {
                let _ = writeln!(
                    out,
                    "  {} {} {} {}",
                    badge,
                    format!("[{}]", f.id).dimmed(),
                    f.title.bold().bright_white(),
                    format!("({})", f.module).cyan()
                );
                let _ = writeln!(out, "     {} {}", "Component:".dimmed(), f.affected_component);
                let _ = writeln!(out, "     {} {}", "Next step:".dimmed(), f.next_step.bright_cyan());
            } else {
                let _ = writeln!(out, "  {} [{}] {} ({})", badge, f.id, f.title, f.module);
                let _ = writeln!(out, "     Component: {}", f.affected_component);
                let _ = writeln!(out, "     Next step: {}", f.next_step);
            }
        }
    }

    out
}

fn format_severity(sev: Severity, use_color: bool) -> String {
    match (sev, use_color) {
        (Severity::Critical, true) => " CRITICAL ".on_red().bright_white().bold().to_string(),
        (Severity::High, true) => " HIGH ".on_bright_red().bright_white().bold().to_string(),
        (Severity::Medium, true) => " MEDIUM ".on_yellow().black().bold().to_string(),
        (Severity::Low, true) => " LOW ".on_blue().bright_white().bold().to_string(),
        (Severity::Info, true) => " INFO ".on_bright_black().bright_white().to_string(),
        (Severity::Critical, false) => "[CRITICAL]".to_string(),
        (Severity::High, false) => "[HIGH]".to_string(),
        (Severity::Medium, false) => "[MEDIUM]".to_string(),
        (Severity::Low, false) => "[LOW]".to_string(),
        (Severity::Info, false) => "[INFO]".to_string(),
    }
}

pub fn render_markdown(resp: &ResponseEnvelope) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Laravel IncidentLens Report\n");
    let _ = writeln!(
        out,
        "- **Engine**: v{}\n- **Protocol**: v{}\n- **Errors**: {}\n- **Warnings**: {}\n",
        resp.engine_version, resp.protocol_version, resp.summary.errors, resp.summary.warnings
    );

    if !resp.incidents.is_empty() {
        let _ = writeln!(out, "## Correlated Incidents\n");
        for inc in &resp.incidents {
            let _ = writeln!(out, "### [{}] {} ({:?})\n", inc.id, inc.title, inc.severity);
            let _ = writeln!(out, "- **Possible Root Cause**: {}", inc.possible_root_cause);
            let _ = writeln!(out, "- **Confidence**: {:?}", inc.confidence);
            let _ = writeln!(out, "- **Next Step**: {}\n", inc.next_step);
        }
    }

    let _ = writeln!(out, "## Findings ({})\n", resp.findings.len());
    for f in &resp.findings {
        let _ = writeln!(
            out,
            "- **[{}] {}** (`{:?}`, module `{}`)\n  - Component: `{}`\n  - Next step: {}",
            f.id, f.title, f.severity, f.module, f.affected_component, f.next_step
        );
    }
    out
}

pub fn render_html(resp: &ResponseEnvelope) -> String {
    let mut rows = String::new();
    for f in &resp.findings {
        let sev_class = match f.severity {
            Severity::Critical => "crit",
            Severity::High => "high",
            Severity::Medium => "med",
            Severity::Low => "low",
            Severity::Info => "info",
        };
        let _ = writeln!(
            rows,
            "<tr><td><span class='badge {sev_class}'>{:?}</span></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            f.severity,
            escape_html(&f.id),
            escape_html(&f.module),
            escape_html(&f.title),
            escape_html(&f.affected_component),
            escape_html(&f.next_step),
        );
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Laravel IncidentLens Report</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0b1120; color: #e2e8f0; margin: 0; padding: 2rem; }}
  .card {{ background: #111827; border: 1px solid #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  h1 {{ color: #38bdf8; margin-top: 0; }}
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
  .stat {{ background: #1e293b; padding: 0.75rem 1.25rem; border-radius: 8px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
  th, td {{ text-align: left; padding: 0.75rem; border-bottom: 1px solid #1e293b; font-size: 0.9rem; }}
  th {{ color: #94a3b8; }}
  .badge {{ padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 700; font-size: 0.75rem; text-transform: uppercase; }}
  .crit {{ background: #991b1b; color: #fecaca; }}
  .high {{ background: #dc2626; color: #fff; }}
  .med {{ background: #d97706; color: #000; }}
  .low {{ background: #2563eb; color: #fff; }}
  .info {{ background: #475569; color: #fff; }}
</style>
</head>
<body>
  <div class="card">
    <h1>Laravel IncidentLens Diagnostic Report</h1>
    <div class="stats">
      <div class="stat">Engine: v{}</div>
      <div class="stat">Errors: {}</div>
      <div class="stat">Warnings: {}</div>
      <div class="stat">Performance: {}</div>
      <div class="stat">Security: {}</div>
    </div>
  </div>
  <div class="card">
    <h2>Findings ({})</h2>
    <table>
      <thead><tr><th>Severity</th><th>ID</th><th>Module</th><th>Title</th><th>Component</th><th>Next Step</th></tr></thead>
      <tbody>{}</tbody>
    </table>
  </div>
</body>
</html>"#,
        escape_html(&resp.engine_version),
        resp.summary.errors,
        resp.summary.warnings,
        resp.summary.performance,
        resp.summary.security,
        resp.findings.len(),
        rows
    )
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
