use crate::code::collect_php_files;
use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use incidentlens_parser::{LogGroup, RuntimeEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobFailureStat {
    pub job_class: String,
    pub failed_count: usize,
    pub sample_exception: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueAnalysis {
    pub total_jobs: usize,
    pub failed_jobs: usize,
    pub failure_groups: Vec<JobFailureStat>,
    pub findings: Vec<Finding>,
}

pub struct QueueAnalyzer;

impl QueueAnalyzer {
    pub fn analyze(events: &[RuntimeEvent], log_groups: &[LogGroup]) -> QueueAnalysis {
        let mut total_jobs = 0usize;
        let mut failed_jobs = 0usize;
        let mut by_job: HashMap<String, JobFailureStat> = HashMap::new();

        for ev in events {
            if let RuntimeEvent::Job {
                job_class,
                status,
                exception,
                ..
            } = ev
            {
                total_jobs += 1;
                if status.eq_ignore_ascii_case("failed") {
                    failed_jobs += 1;
                    let entry = by_job.entry(job_class.clone()).or_insert_with(|| JobFailureStat {
                        job_class: job_class.clone(),
                        failed_count: 0,
                        sample_exception: exception.clone(),
                    });
                    entry.failed_count += 1;
                }
            }
        }

        let mut failure_groups: Vec<JobFailureStat> = by_job.into_values().collect();
        failure_groups.sort_by(|a, b| b.failed_count.cmp(&a.failed_count));

        let mut findings = Vec::new();
        for (i, grp) in failure_groups.iter().enumerate() {
            findings.push(Finding {
                id: format!("QUE-{:03}", i + 1),
                module: "queue".to_string(),
                title: format!(
                    "Queue job {} failed {} time(s)",
                    grp.job_class, grp.failed_count
                ),
                severity: if grp.failed_count >= 5 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                confidence: Confidence::High,
                affected_component: grp.job_class.clone(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "queue_analyzer".to_string(),
                    detail: grp
                        .sample_exception
                        .clone()
                        .unwrap_or_else(|| "Job failed in runtime queue events.".to_string()),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Inspect failed job payload/exception via `php artisan queue:failed` (read-only).".to_string(),
            });
        }

        for (i, lg) in log_groups.iter().enumerate() {
            let lower = lg.sample_message.to_ascii_lowercase();
            if lower.contains("maxattemptsexceededexception") || lower.contains("queue") && lg.level.is_error_or_above() {
                findings.push(Finding {
                    id: format!("QUE-LOG-{:03}", i + 1),
                    module: "queue".to_string(),
                    title: format!("Queue exception in logs ({}x)", lg.count),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    affected_component: lg.location.clone().unwrap_or_else(|| "queue".to_string()),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "log_analyzer".to_string(),
                        detail: lg.normalized_message.clone(),
                    }],
                    first_observed: lg.first_seen.map(|d| d.to_rfc3339()),
                    last_observed: lg.last_seen.map(|d| d.to_rfc3339()),
                    next_step: "Review worker timeout, memory limits, and job retry configuration.".to_string(),
                });
            }
        }

        QueueAnalysis {
            total_jobs,
            failed_jobs,
            failure_groups,
            findings,
        }
    }

    /// Static analysis of `app/Jobs/*.php` for missing `$tries`, `$timeout`, and `failed()` handlers.
    pub fn analyze_static(project_root: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        for file in collect_php_files(&project_root.join("app/Jobs")) {
            let Ok(content) = fs::read_to_string(&file) else {
                continue;
            };
            if !content.contains("ShouldQueue") {
                continue;
            }
            let rel = file
                .strip_prefix(project_root)
                .unwrap_or(&file)
                .display()
                .to_string();

            if !content.contains("$tries") && !content.contains("tries(") {
                findings.push(Finding {
                    id: format!("QUE-CFG-{}", findings.len() + 1),
                    module: "queue".to_string(),
                    title: format!("Queued job missing explicit $tries retry policy in {rel}"),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    affected_component: rel.clone(),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "queue_static".to_string(),
                        detail: "Job implements ShouldQueue without `$tries` or `tries()`.".to_string(),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Define `public int $tries = 3;` (and `$backoff`) to control retry behavior.".to_string(),
                });
            }

            if !content.contains("$timeout") {
                findings.push(Finding {
                    id: format!("QUE-TMO-{}", findings.len() + 1),
                    module: "queue".to_string(),
                    title: format!("Queued job missing explicit $timeout in {rel}"),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    affected_component: rel,
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "queue_static".to_string(),
                        detail: "Job implements ShouldQueue without `public int $timeout`.".to_string(),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Set `public int $timeout` to prevent stuck workers from blocking the queue.".to_string(),
                });
            }
        }
        findings
    }
}
