use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, ProjectReport, Severity};
use incidentlens_parser::RuntimeEvent;

pub struct CacheAnalyzer;

impl CacheAnalyzer {
    /// Analyzes cache driver configuration and observed cache hit/miss telemetry.
    pub fn analyze(report: &ProjectReport, events: &[RuntimeEvent]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let is_prod = report
            .environment
            .as_deref()
            .map(|e| e.eq_ignore_ascii_case("production") || e.eq_ignore_ascii_case("prod"))
            .unwrap_or(false);

        if is_prod && matches!(report.drivers.cache.as_deref(), Some("array") | Some("null")) {
            findings.push(Finding {
                id: "CACHE-001".to_string(),
                module: "cache".to_string(),
                title: format!(
                    "Non-persistent cache driver '{}' configured in production",
                    report.drivers.cache.as_deref().unwrap_or("unknown")
                ),
                severity: Severity::High,
                confidence: Confidence::High,
                affected_component: ".env (CACHE_STORE / CACHE_DRIVER)".to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "cache_analyzer".to_string(),
                    detail: "The `array` or `null` cache driver does not persist across requests in production.".to_string(),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Configure a persistent cache store such as `redis` or `database` in production.".to_string(),
            });
        }

        let mut hits = 0usize;
        let mut misses = 0usize;
        for ev in events {
            if let RuntimeEvent::Cache { hit, .. } = ev {
                if *hit {
                    hits += 1;
                } else {
                    misses += 1;
                }
            }
        }

        let total = hits + misses;
        if total >= 10 {
            let hit_rate = (hits as f64 / total as f64) * 100.0;
            if hit_rate < 50.0 {
                findings.push(Finding {
                    id: "CACHE-002".to_string(),
                    module: "cache".to_string(),
                    title: format!("Low cache hit ratio ({hit_rate:.1}% across {total} operations)"),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    affected_component: "cache".to_string(),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "cache_analyzer".to_string(),
                        detail: format!("Observed {hits} cache hits and {misses} cache misses."),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Review cache TTLs, key naming consistency, and potential cache stampedes.".to_string(),
                });
            }
        }

        findings
    }
}
