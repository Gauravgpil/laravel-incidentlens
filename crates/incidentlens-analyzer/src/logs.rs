use incidentlens_core::redaction::redact_inline_secrets;
use incidentlens_core::validation::safe_join;
use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use incidentlens_parser::{
    discover_log_files, parse_log_files_parallel, LogFilter, LogLevel, LogParseResult,
};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub struct LogAnalyzer;

impl LogAnalyzer {
    pub fn analyze(project_root: &Path, filter: &LogFilter) -> (LogParseResult, Vec<Finding>) {
        let files = discover_log_files(project_root);
        if files.is_empty() {
            return (LogParseResult::default(), Vec::new());
        }

        let Ok(parsed) = parse_log_files_parallel(&files, filter) else {
            return (LogParseResult::default(), Vec::new());
        };

        let mut findings = Vec::new();
        for (idx, grp) in parsed.groups.iter().enumerate() {
            if !grp.level.is_error_or_above() && grp.level != LogLevel::Warning {
                continue;
            }
            let severity = match grp.level {
                LogLevel::Emergency | LogLevel::Alert | LogLevel::Critical => Severity::Critical,
                LogLevel::Error => {
                    if grp.count >= 10 {
                        Severity::High
                    } else {
                        Severity::Medium
                    }
                }
                LogLevel::Warning => Severity::Low,
                _ => Severity::Info,
            };

            let title = if let Some(ref cls) = grp.exception_class {
                format!("Recurring {} ({}x)", cls, grp.count)
            } else {
                format!("Recurring {:?} log pattern ({}x)", grp.level, grp.count)
            };

            let mut evidence = vec![Evidence {
                kind: EvidenceKind::Observed,
                source: "log_analyzer".to_string(),
                detail: format!(
                    "Fingerprint {} observed {} time(s): {}",
                    grp.fingerprint, grp.count, grp.normalized_message
                ),
            }];
            if let Some(ref loc) = grp.location {
                evidence.push(Evidence {
                    kind: EvidenceKind::Observed,
                    source: "log_analyzer".to_string(),
                    detail: format!("Primary location: {loc}"),
                });
                if let Some(snippet) = extract_code_context(project_root, loc) {
                    evidence.push(Evidence {
                        kind: EvidenceKind::Observed,
                        source: "code_frame".to_string(),
                        detail: snippet,
                    });
                }
            }

            findings.push(Finding {
                id: format!("LOG-{:03}", idx + 1),
                module: "logs".to_string(),
                title,
                severity,
                confidence: Confidence::High,
                affected_component: grp
                    .location
                    .clone()
                    .unwrap_or_else(|| "storage/logs".to_string()),
                evidence,
                first_observed: grp.first_seen.map(|d| d.to_rfc3339()),
                last_observed: grp.last_seen.map(|d| d.to_rfc3339()),
                next_step: format!(
                    "Inspect occurrences with `incidentlens logs --fingerprint={}`.",
                    grp.fingerprint
                ),
            });
        }

        (parsed, findings)
    }
}

/// Safely extracts ±2 lines of PHP source context around `path/to/file.php:line` inside `project_root`.
pub fn extract_code_context(project_root: &Path, location: &str) -> Option<String> {
    let (file_part, line_part) = location.rsplit_once(':')?;
    let target_line = line_part.parse::<usize>().ok()?;
    if target_line == 0 {
        return None;
    }

    let rel = Path::new(file_part);
    let safe_path = safe_join(project_root, rel).ok()?;
    let file = File::open(safe_path).ok()?;
    let reader = BufReader::new(file);

    let start = target_line.saturating_sub(2).max(1);
    let end = target_line + 2;
    let mut lines_out = Vec::new();

    for (idx, line_res) in reader.lines().enumerate() {
        let line_no = idx + 1;
        if line_no > end {
            break;
        }
        if line_no >= start {
            if let Ok(text) = line_res {
                let marker = if line_no == target_line { ">>" } else { "  " };
                lines_out.push(format!("{marker} {line_no:>4} | {}", redact_inline_secrets(&text)));
            }
        }
    }

    if lines_out.is_empty() {
        None
    } else {
        Some(lines_out.join("\n"))
    }
}
