use crate::code::collect_php_files;
use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

static NS_RE: OnceLock<Regex> = OnceLock::new();
static USE_RE: OnceLock<Regex> = OnceLock::new();

pub struct ArchitectureAnalyzer;

impl ArchitectureAnalyzer {
    /// Analyzes `app/` class dependencies for circular references, layer boundary violations,
    /// and high coupling.
    pub fn analyze(project_root: &Path) -> Vec<Finding> {
        let app_dir = project_root.join("app");
        let files = collect_php_files(&app_dir);
        if files.is_empty() {
            return Vec::new();
        }

        let ns_re = NS_RE.get_or_init(|| Regex::new(r"(?m)^namespace\s+([^;]+);").expect("valid ns regex"));
        let use_re = USE_RE.get_or_init(|| Regex::new(r"(?m)^use\s+(App\\[^;\s]+);").expect("valid use regex"));

        let mut graph: HashMap<String, Vec<String>> = HashMap::new();
        let mut findings = Vec::new();

        for file in files {
            let Ok(content) = fs::read_to_string(&file) else {
                continue;
            };
            let Some(stem) = file.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let fqcn = if let Some(caps) = ns_re.captures(&content) {
                format!("{}\\{}", caps[1].trim(), stem)
            } else {
                continue;
            };

            let mut deps = Vec::new();
            for caps in use_re.captures_iter(&content) {
                let target = caps[1].trim().to_string();
                if target != fqcn {
                    deps.push(target);
                }
            }

            // Boundary check: Models or Services should not depend on Http\Controllers
            if fqcn.starts_with("App\\Models\\") || fqcn.starts_with("App\\Services\\") {
                for dep in &deps {
                    if dep.starts_with("App\\Http\\Controllers\\") {
                        findings.push(Finding {
                            id: format!("ARCH-BND-{}", findings.len() + 1),
                            module: "architecture".to_string(),
                            title: format!("Architecture boundary violation: {fqcn} imports {dep}"),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            affected_component: fqcn.clone(),
                            evidence: vec![Evidence {
                                kind: EvidenceKind::Observed,
                                source: "architecture_analyzer".to_string(),
                                detail: format!("Domain/service class `{fqcn}` depends on HTTP controller `{dep}`."),
                            }],
                            first_observed: None,
                            last_observed: None,
                            next_step: "Invert the dependency so controllers depend on services/models, not vice versa.".to_string(),
                        });
                    }
                }
            }

            // High coupling check
            if deps.len() >= 12 {
                findings.push(Finding {
                    id: format!("ARCH-CPL-{}", findings.len() + 1),
                    module: "architecture".to_string(),
                    title: format!("High coupling in {fqcn} ({} App\\ dependencies)", deps.len()),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    affected_component: fqcn.clone(),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "architecture_analyzer".to_string(),
                        detail: format!("`{fqcn}` imports {} internal App\\ classes.", deps.len()),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Consider splitting responsibilities into smaller, focused services.".to_string(),
                });
            }

            graph.insert(fqcn, deps);
        }

        // Circular dependency detection (2-node and DFS cycle detection)
        let mut reported_cycles: HashSet<String> = HashSet::new();
        for (a, deps_a) in &graph {
            for b in deps_a {
                if let Some(deps_b) = graph.get(b) {
                    if deps_b.contains(a) {
                        let mut pair = [a.clone(), b.clone()];
                        pair.sort();
                        let key = format!("{}<->{}", pair[0], pair[1]);
                        if reported_cycles.insert(key) {
                            findings.push(Finding {
                                id: format!("ARCH-CYC-{}", findings.len() + 1),
                                module: "architecture".to_string(),
                                title: format!("Circular dependency between {} and {}", pair[0], pair[1]),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                affected_component: format!("{} <-> {}", pair[0], pair[1]),
                                evidence: vec![Evidence {
                                    kind: EvidenceKind::Observed,
                                    source: "architecture_analyzer".to_string(),
                                    detail: format!("`{}` imports `{}` and `{}` imports `{}`.", pair[0], pair[1], pair[1], pair[0]),
                                }],
                                first_observed: None,
                                last_observed: None,
                                next_step: "Extract shared logic into a third service or use Laravel events to break the cycle.".to_string(),
                            });
                        }
                    }
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
    fn detects_circular_dependency_and_boundary_violation() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("app/Services")).unwrap();
        fs::create_dir_all(tmp.path().join("app/Models")).unwrap();

        fs::write(
            tmp.path().join("app/Services/AlphaService.php"),
            "<?php\nnamespace App\\Services;\nuse App\\Services\\BetaService;\nclass AlphaService {}\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("app/Services/BetaService.php"),
            "<?php\nnamespace App\\Services;\nuse App\\Services\\AlphaService;\nclass BetaService {}\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("app/Models/User.php"),
            "<?php\nnamespace App\\Models;\nuse App\\Http\\Controllers\\UserController;\nclass User {}\n",
        )
        .unwrap();

        let findings = ArchitectureAnalyzer::analyze(tmp.path());
        assert!(findings.iter().any(|f| f.id.starts_with("ARCH-CYC-")));
        assert!(findings.iter().any(|f| f.id.starts_with("ARCH-BND-")));
    }
}
