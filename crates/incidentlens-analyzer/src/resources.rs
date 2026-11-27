use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use std::fs;
use std::path::Path;

pub struct ResourceAnalyzer;

impl ResourceAnalyzer {
    /// Checks local storage/logs disk usage and unrotated oversized log files.
    pub fn analyze(project_root: &Path) -> Vec<Finding> {
        let logs_dir = project_root.join("storage/logs");
        let Ok(entries) = fs::read_dir(&logs_dir) else {
            return Vec::new();
        };

        let mut findings = Vec::new();
        let mut total_bytes = 0u64;

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Ok(meta) = fs::metadata(&path) {
                let len = meta.len();
                total_bytes += len;
                if len >= 100 * 1024 * 1024 {
                    let mb = len as f64 / (1024.0 * 1024.0);
                    findings.push(Finding {
                        id: format!("RES-LOG-{}", findings.len() + 1),
                        module: "resources".to_string(),
                        title: format!(
                            "Oversized log file {} ({mb:.1} MB)",
                            path.file_name().and_then(|n| n.to_str()).unwrap_or("log")
                        ),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        affected_component: path.display().to_string(),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "resource_analyzer".to_string(),
                            detail: format!("Log file size is {mb:.1} MB; single-file logs can exhaust disk if unrotated."),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Switch LOG_CHANNEL to `daily` or configure logrotate.".to_string(),
                    });
                }
            }
        }

        if total_bytes >= 500 * 1024 * 1024 {
            let mb = total_bytes as f64 / (1024.0 * 1024.0);
            findings.push(Finding {
                id: "RES-DISK-001".to_string(),
                module: "resources".to_string(),
                title: format!("High storage/logs disk usage ({mb:.1} MB)"),
                severity: Severity::Medium,
                confidence: Confidence::High,
                affected_component: "storage/logs".to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "resource_analyzer".to_string(),
                    detail: format!("Total size of files in storage/logs is {mb:.1} MB."),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Review log retention days and log verbosity.".to_string(),
            });
        }

        findings
    }
}
