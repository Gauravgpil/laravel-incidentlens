use crate::code::collect_php_files;
use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use std::fs;
use std::path::Path;

pub struct FrameworkAnalyzer;

impl FrameworkAnalyzer {
    /// Inspects Laravel ServiceProviders and ecosystem packages (Octane, Horizon, Sanctum).
    pub fn analyze(project_root: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Service Provider boot() inspection
        let providers_dir = project_root.join("app/Providers");
        for file in collect_php_files(&providers_dir) {
            let Ok(content) = fs::read_to_string(&file) else {
                continue;
            };
            let rel = file
                .strip_prefix(project_root)
                .unwrap_or(&file)
                .display()
                .to_string();
            if content.contains("public function boot") && (content.contains("DB::") || content.contains("Http::")) {
                findings.push(Finding {
                    id: format!("FW-PROV-{}", findings.len() + 1),
                    module: "framework".to_string(),
                    title: format!("External I/O (DB/HTTP) inside ServiceProvider::boot() in {rel}"),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    affected_component: rel,
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "framework_analyzer".to_string(),
                        detail: "ServiceProvider references DB:: or Http:: which can slow down Artisan/boot lifecycle or fail during package discovery.".to_string(),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Defer database/HTTP work into lazy singletons, middleware, or event listeners.".to_string(),
                });
            }
        }

        // 2. Octane compatibility check
        if let Ok(composer) = fs::read_to_string(project_root.join("composer.json")) {
            if composer.contains("laravel/octane") {
                for file in collect_php_files(&project_root.join("app")) {
                    let Ok(content) = fs::read_to_string(&file) else {
                        continue;
                    };
                    if content.contains("static $") {
                        let rel = file
                            .strip_prefix(project_root)
                            .unwrap_or(&file)
                            .display()
                            .to_string();
                        findings.push(Finding {
                            id: format!("FW-OCT-{}", findings.len() + 1),
                            module: "framework".to_string(),
                            title: format!("Mutable static state candidate under Laravel Octane in {rel}"),
                            severity: Severity::Medium,
                            confidence: Confidence::Low,
                            affected_component: rel,
                            evidence: vec![Evidence {
                                kind: EvidenceKind::Observed,
                                source: "framework_analyzer".to_string(),
                                detail: "Project uses `laravel/octane` and this file declares `static $...`, which persists across requests in long-lived workers.".to_string(),
                            }],
                            first_observed: None,
                            last_observed: None,
                            next_step: "Ensure static variables do not leak request-scoped or tenant-scoped state across Octane requests.".to_string(),
                        });
                    }
                }
            }
        }

        findings
    }
}
