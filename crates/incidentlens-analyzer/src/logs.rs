use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use incidentlens_parser::{
    discover_log_files, parse_log_files_parallel, LogFilter, LogLevel, LogParseResult,
};
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
