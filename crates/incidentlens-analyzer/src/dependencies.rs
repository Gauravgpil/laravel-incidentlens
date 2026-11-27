use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Default)]
struct ComposerManifest {
    #[serde(default)]
    require: BTreeMap<String, String>,
}

pub struct DependencyAnalyzer;

impl DependencyAnalyzer {
    /// Analyzes local composer.json / composer.lock metadata offline without transmitting data externally.
    pub fn analyze(project_root: &Path) -> Vec<Finding> {
        let Ok(raw) = fs::read_to_string(project_root.join("composer.json")) else {
            return Vec::new();
        };
        let Ok(manifest) = serde_json::from_str::<ComposerManifest>(&raw) else {
            return Vec::new();
        };

        let mut findings = Vec::new();
        for (pkg, constraint) in &manifest.require {
            if constraint.trim() == "*" || constraint.contains("dev-") {
                findings.push(Finding {
                    id: format!("DEP-UNPIN-{}", pkg.replace('/', "_").to_uppercase()),
                    module: "dependencies".to_string(),
                    title: format!("Unpinned or dev dependency constraint for {pkg}"),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    affected_component: format!("composer.json ({pkg}: {constraint})"),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "dependency_analyzer".to_string(),
                        detail: format!("Package '{pkg}' uses unstable/unpinned constraint '{constraint}'."),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Pin a stable semantic version constraint in composer.json.".to_string(),
                });
            }
        }

        findings
    }
}
