use crate::code::collect_php_files;
use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use incidentlens_parser::RuntimeEvent;
use std::fs;
use std::path::Path;

const HIGH_MEMORY_THRESHOLD_BYTES: u64 = 128 * 1024 * 1024; // 128 MB

pub struct ResourceAnalyzer;

impl ResourceAnalyzer {
    /// Checks local storage/logs disk usage, oversized log files, static batch memory-overflow
    /// anti-patterns in Commands/Jobs, and runtime peak memory spikes.
    pub fn analyze(project_root: &Path) -> Vec<Finding> {
        Self::analyze_with_runtime(project_root, &[])
    }

    pub fn analyze_with_runtime(project_root: &Path, events: &[RuntimeEvent]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Storage/logs disk usage
        let logs_dir = project_root.join("storage/logs");
        if let Ok(entries) = fs::read_dir(&logs_dir) {
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
        }

        // 2. Static memory-overflow anti-patterns in Console Commands & Queue Jobs
        for sub in ["app/Console/Commands", "app/Jobs"] {
            for file in collect_php_files(&project_root.join(sub)) {
                let Ok(content) = fs::read_to_string(&file) else {
                    continue;
                };
                let rel = file
                    .strip_prefix(project_root)
                    .unwrap_or(&file)
                    .display()
                    .to_string();

                let loads_all = content.contains("::all()") || content.contains("->get()");
                let uses_streaming = content.contains("chunkById(")
                    || content.contains("lazyById(")
                    || content.contains("cursor(");

                if loads_all && !uses_streaming {
                    findings.push(Finding {
                        id: format!("RES-MEM-{}", findings.len() + 1),
                        module: "resources".to_string(),
                        title: format!("Unbounded Eloquent hydration (::all()/->get()) in {rel}"),
                        severity: Severity::Medium,
                        confidence: Confidence::Medium,
                        affected_component: rel.clone(),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "resource_analyzer".to_string(),
                            detail: "Batch command/job calls `::all()` or `->get()` without `lazyById()`, `chunkById()`, or `cursor()`.".to_string(),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Use `lazyById(1000)` / `chunkById(1000)` + `DB::disableQueryLog()` + `$model->unsetRelations()` to bound memory.".to_string(),
                    });
                }

                if content.contains("->chunk(") && !content.contains("chunkById(") {
                    findings.push(Finding {
                        id: format!("RES-CHK-{}", findings.len() + 1),
                        module: "resources".to_string(),
                        title: format!("Offset-based ->chunk() used in {rel} (O(N^2) / row-skip risk)"),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        affected_component: rel,
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "resource_analyzer".to_string(),
                            detail: "`->chunk()` uses OFFSET/LIMIT which degrades on large tables and can skip rows when updating queried columns.".to_string(),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Prefer keyset pagination via `->chunkById()` or `->lazyById()`.".to_string(),
                    });
                }
            }
        }

        // 3. Runtime peak memory spikes
        for ev in events {
            if let RuntimeEvent::Request {
                method,
                route,
                memory_peak_bytes: Some(bytes),
                ..
            } = ev
            {
                if *bytes >= HIGH_MEMORY_THRESHOLD_BYTES {
                    let mb = *bytes as f64 / (1024.0 * 1024.0);
                    findings.push(Finding {
                        id: format!("RES-PEAK-{}", findings.len() + 1),
                        module: "resources".to_string(),
                        title: format!("High request memory peak on {method} {route} ({mb:.1} MB)"),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        affected_component: format!("{method} {route}"),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "resource_analyzer".to_string(),
                            detail: format!("Observed memory_get_peak_usage(true) = {mb:.1} MB (threshold 128 MB)."),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Check for large collection hydration, missing pagination, or N+1 eager-loading bloat.".to_string(),
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn detects_unbounded_get_and_chunk_in_commands() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("app/Console/Commands")).unwrap();
        fs::write(
            tmp.path().join("app/Console/Commands/ExportUsers.php"),
            "<?php\n$users = User::all();\nUser::query()->chunk(100, fn($c) => null);\n",
        )
        .unwrap();

        let findings = ResourceAnalyzer::analyze(tmp.path());
        assert!(findings.iter().any(|f| f.id.starts_with("RES-MEM-")));
        assert!(findings.iter().any(|f| f.id.starts_with("RES-CHK-")));
    }
}
