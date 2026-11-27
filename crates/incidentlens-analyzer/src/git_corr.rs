use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use std::path::Path;
use std::process::Command;

pub struct GitCorrelator;

impl GitCorrelator {
    /// Read-only correlation: checks if recently changed files overlap with finding locations.
    /// Reports candidates only; never blames commits or developers.
    pub fn correlate_recent_changes(project_root: &Path, findings: &[Finding]) -> Vec<Finding> {
        let output = Command::new("git")
            .args(["-C"])
            .arg(project_root)
            .args(["diff", "--name-only", "HEAD~1", "HEAD"])
            .output();

        let Ok(out) = output else {
            return Vec::new();
        };
        if !out.status.success() {
            return Vec::new();
        }

        let changed_files: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(ToString::to_string)
            .collect();

        if changed_files.is_empty() {
            return Vec::new();
        }

        let mut candidates = Vec::new();
        for f in findings {
            for cf in &changed_files {
                if f.affected_component.contains(cf.as_str()) {
                    candidates.push(Finding {
                        id: format!("GIT-CORR-{}", candidates.len() + 1),
                        module: "deployment".to_string(),
                        title: format!("Recently changed file '{cf}' overlaps with finding {}", f.id),
                        severity: Severity::Info,
                        confidence: Confidence::Low,
                        affected_component: cf.clone(),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Correlated,
                            source: "git_correlator".to_string(),
                            detail: format!(
                                "File '{cf}' was modified in HEAD~1..HEAD and appears in '{}' ({}).",
                                f.title, f.id
                            ),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: format!("Review `git diff HEAD~1 HEAD -- {cf}` as an investigation candidate."),
                    });
                }
            }
        }

        candidates
    }
}
