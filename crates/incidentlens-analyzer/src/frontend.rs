use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Default)]
struct PackageJson {
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, String>,
}

pub struct FrontendAnalyzer;

impl FrontendAnalyzer {
    /// Audits React/Inertia/Vite/Tailwind assets: production source maps, oversized bundles,
    /// and redundant frontend dependencies.
    pub fn analyze(project_root: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Check package.json for heavy/duplicate date libraries or missing build setup
        if let Ok(raw) = fs::read_to_string(project_root.join("package.json")) {
            if let Ok(pkg) = serde_json::from_str::<PackageJson>(&raw) {
                let has_moment = pkg.dependencies.contains_key("moment")
                    || pkg.dev_dependencies.contains_key("moment");
                let has_dayjs_or_datefns = pkg.dependencies.contains_key("dayjs")
                    || pkg.dependencies.contains_key("date-fns");
                if has_moment && has_dayjs_or_datefns {
                    findings.push(Finding {
                        id: "FE-DUP-001".to_string(),
                        module: "frontend".to_string(),
                        title: "Duplicate date library (moment + dayjs/date-fns) in package.json".to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        affected_component: "package.json".to_string(),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "frontend_analyzer".to_string(),
                            detail: "Both `moment` and a lighter alternative (`dayjs`/`date-fns`) are listed, inflating JS bundle size.".to_string(),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Standardize on `dayjs` or `date-fns` and remove `moment`.".to_string(),
                    });
                }
            }
        }

        // 2. Scan public/build/assets for exposed .map source maps and oversized JS bundles (> 500 KB)
        let assets_dir = project_root.join("public/build/assets");
        if let Ok(entries) = fs::read_dir(&assets_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let p = entry.path();
                if !p.is_file() {
                    continue;
                }
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.ends_with(".map") {
                    findings.push(Finding {
                        id: format!("FE-MAP-{}", findings.len() + 1),
                        module: "frontend".to_string(),
                        title: format!("Production source map exposed: public/build/assets/{name}"),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        affected_component: format!("public/build/assets/{name}"),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "frontend_analyzer".to_string(),
                            detail: "Public `.map` file exposes original TypeScript/React/Inertia source code.".to_string(),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Disable `build.sourcemap` in `vite.config.js` for production builds.".to_string(),
                    });
                } else if name.ends_with(".js") {
                    if let Ok(meta) = fs::metadata(&p) {
                        if meta.len() >= 500 * 1024 {
                            let kb = meta.len() / 1024;
                            findings.push(Finding {
                                id: format!("FE-BND-{}", findings.len() + 1),
                                module: "frontend".to_string(),
                                title: format!("Oversized JS bundle public/build/assets/{name} ({kb} KB)"),
                                severity: Severity::Low,
                                confidence: Confidence::High,
                                affected_component: format!("public/build/assets/{name}"),
                                evidence: vec![Evidence {
                                    kind: EvidenceKind::Observed,
                                    source: "frontend_analyzer".to_string(),
                                    detail: format!("Built JS bundle is {kb} KB (>= 500 KB threshold)."),
                                }],
                                first_observed: None,
                                last_observed: None,
                                next_step: "Use dynamic `import()` / React.lazy() code-splitting for heavy routes/components.".to_string(),
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
    fn detects_source_maps_and_duplicate_date_libs() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("public/build/assets")).unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"moment":"^2.30.0","dayjs":"^1.11.0"}}"#,
        )
        .unwrap();
        fs::write(tmp.path().join("public/build/assets/app.js.map"), "{}").unwrap();

        let findings = FrontendAnalyzer::analyze(tmp.path());
        assert!(findings.iter().any(|f| f.id == "FE-DUP-001"));
        assert!(findings.iter().any(|f| f.id.starts_with("FE-MAP-")));
    }
}
