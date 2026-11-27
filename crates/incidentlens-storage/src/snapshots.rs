use chrono::Utc;
use incidentlens_core::{
    Confidence, Evidence, EvidenceKind, Finding, ResponseEnvelope, Severity, SummaryCounts,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("snapshot JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub created_at: String,
    pub git_commit: Option<String>,
    pub summary: SummaryCounts,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionDiff {
    pub baseline_id: String,
    pub current_id: String,
    pub new_findings: Vec<Finding>,
    pub resolved_findings: Vec<Finding>,
    pub regression_findings: Vec<Finding>,
}

pub fn save_snapshot(
    dir: &Path,
    id: &str,
    git_commit: Option<String>,
    response: &ResponseEnvelope,
) -> Result<PathBuf, StorageError> {
    fs::create_dir_all(dir)?;
    let safe_id: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let snap = Snapshot {
        id: safe_id.clone(),
        created_at: Utc::now().to_rfc3339(),
        git_commit,
        summary: response.summary.clone(),
        findings: response.findings.clone(),
    };
    let path = dir.join(format!("{safe_id}.json"));
    fs::write(&path, serde_json::to_string_pretty(&snap)?)?;
    Ok(path)
}

pub fn load_snapshot(path: &Path) -> Result<Snapshot, StorageError> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn compare_snapshots(baseline: &Snapshot, current: &Snapshot) -> RegressionDiff {
    let base_keys: HashSet<(&str, &str)> = baseline
        .findings
        .iter()
        .map(|f| (f.id.as_str(), f.title.as_str()))
        .collect();
    let curr_keys: HashSet<(&str, &str)> = current
        .findings
        .iter()
        .map(|f| (f.id.as_str(), f.title.as_str()))
        .collect();

    let new_findings: Vec<Finding> = current
        .findings
        .iter()
        .filter(|f| !base_keys.contains(&(f.id.as_str(), f.title.as_str())))
        .cloned()
        .collect();

    let resolved_findings: Vec<Finding> = baseline
        .findings
        .iter()
        .filter(|f| !curr_keys.contains(&(f.id.as_str(), f.title.as_str())))
        .cloned()
        .collect();

    let mut regression_findings = Vec::new();
    for (idx, nf) in new_findings.iter().enumerate() {
        regression_findings.push(Finding {
            id: format!("REG-NEW-{:03}", idx + 1),
            module: "regression".to_string(),
            title: format!("New finding since {}: {}", baseline.id, nf.title),
            severity: nf.severity,
            confidence: Confidence::High,
            affected_component: nf.affected_component.clone(),
            evidence: vec![Evidence {
                kind: EvidenceKind::Observed,
                source: "regression_engine".to_string(),
                detail: format!(
                    "Present in snapshot '{}' but absent in baseline '{}'.",
                    current.id, baseline.id
                ),
            }],
            first_observed: nf.first_observed.clone(),
            last_observed: nf.last_observed.clone(),
            next_step: nf.next_step.clone(),
        });
    }

    if current.summary.errors > baseline.summary.errors {
        regression_findings.push(Finding {
            id: "REG-ERR-SPIKE".to_string(),
            module: "regression".to_string(),
            title: format!(
                "Error count increased from {} to {}",
                baseline.summary.errors, current.summary.errors
            ),
            severity: Severity::High,
            confidence: Confidence::High,
            affected_component: "application".to_string(),
            evidence: vec![Evidence {
                kind: EvidenceKind::Observed,
                source: "regression_engine".to_string(),
                detail: format!(
                    "Baseline '{}' had {} errors; '{}' has {} errors.",
                    baseline.id, baseline.summary.errors, current.id, current.summary.errors
                ),
            }],
            first_observed: None,
            last_observed: None,
            next_step: "Inspect newly introduced findings and recent deployment changes.".to_string(),
        });
    }

    RegressionDiff {
        baseline_id: baseline.id.clone(),
        current_id: current.id.clone(),
        new_findings,
        resolved_findings,
        regression_findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn saves_loads_and_compares_snapshots() {
        let tmp = TempDir::new().unwrap();
        let base_resp = ResponseEnvelope::ok(None, vec![]);
        let mut curr_resp = ResponseEnvelope::ok(
            None,
            vec![Finding {
                id: "PRJ-001".into(),
                module: "project".into(),
                title: "Debug mode enabled".into(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                affected_component: ".env".into(),
                evidence: vec![],
                first_observed: None,
                last_observed: None,
                next_step: "Disable APP_DEBUG".into(),
            }],
        );
        curr_resp.summary.errors = 1;

        let p1 = save_snapshot(tmp.path(), "snap-a", None, &base_resp).unwrap();
        let p2 = save_snapshot(tmp.path(), "snap-b", None, &curr_resp).unwrap();

        let s1 = load_snapshot(&p1).unwrap();
        let s2 = load_snapshot(&p2).unwrap();
        let diff = compare_snapshots(&s1, &s2);

        assert_eq!(diff.new_findings.len(), 1);
        assert!(diff.resolved_findings.is_empty());
        assert!(diff.regression_findings.iter().any(|f| f.id == "REG-ERR-SPIKE"));
    }
}
