use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use std::fs;
use std::path::Path;

pub struct SchedulerAnalyzer;

impl SchedulerAnalyzer {
    /// Inspects Laravel scheduler definitions for overlap protection risks.
    pub fn analyze(project_root: &Path) -> Vec<Finding> {
        let candidates = [
            project_root.join("app").join("Console").join("Kernel.php"),
            project_root.join("routes").join("console.php"),
        ];

        let mut findings = Vec::new();
        for path in candidates {
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            let rel = path
                .strip_prefix(project_root)
                .unwrap_or(&path)
                .display()
                .to_string();

            let has_frequent_schedule = content.contains("everyMinute(")
                || content.contains("everyFiveMinutes(")
                || content.contains("everyTenMinutes(");

            if has_frequent_schedule && !content.contains("withoutOverlapping(") {
                findings.push(Finding {
                    id: format!("SCHED-{}", findings.len() + 1),
                    module: "scheduler".to_string(),
                    title: format!("Frequent scheduled task without `withoutOverlapping()` in {rel}"),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    affected_component: rel,
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "scheduler_analyzer".to_string(),
                        detail: "Frequent schedule cadence detected without `withoutOverlapping()` guard.".to_string(),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Add `->withoutOverlapping()` to long-running scheduled commands/jobs to prevent concurrent runs.".to_string(),
                });
            }
        }

        findings
    }
}
