use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, ProjectReport, Severity};

pub struct ScalabilityAnalyzer;

impl ScalabilityAnalyzer {
    /// Evaluates horizontal scaling readiness (shared session, shared cache, queue, filesystem).
    pub fn analyze(report: &ProjectReport) -> Vec<Finding> {
        let mut findings = Vec::new();
        let is_prod = report
            .environment
            .as_deref()
            .map(|e| e.eq_ignore_ascii_case("production") || e.eq_ignore_ascii_case("prod"))
            .unwrap_or(false);

        if matches!(report.drivers.session.as_deref(), Some("file") | Some("array")) {
            findings.push(Finding {
                id: "SCALE-SES-001".to_string(),
                module: "scalability".to_string(),
                title: format!(
                    "Local session driver '{}' blocks horizontal scaling",
                    report.drivers.session.as_deref().unwrap_or("file")
                ),
                severity: if is_prod { Severity::High } else { Severity::Low },
                confidence: Confidence::High,
                affected_component: ".env (SESSION_DRIVER)".to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "scalability_analyzer".to_string(),
                    detail: "File/array sessions are tied to a single container/node and fail behind a load balancer without sticky sessions.".to_string(),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Use a shared session store (`redis` or `database`) for multi-instance deployments.".to_string(),
            });
        }

        if is_prod && report.drivers.cache.as_deref() == Some("file") {
            findings.push(Finding {
                id: "SCALE-CAC-001".to_string(),
                module: "scalability".to_string(),
                title: "Local 'file' cache driver configured in production".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                affected_component: ".env (CACHE_STORE / CACHE_DRIVER)".to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "scalability_analyzer".to_string(),
                    detail: "File cache is node-local and cannot be invalidated across multiple web/queue nodes.".to_string(),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Switch CACHE_STORE to `redis` for shared, atomic cache invalidation and rate limiting.".to_string(),
            });
        }

        findings
    }
}
