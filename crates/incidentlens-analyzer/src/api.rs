use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use incidentlens_parser::RuntimeEvent;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct ApiAnalyzer;

impl ApiAnalyzer {
    /// Analyzes API route configuration and `/api/*` runtime request telemetry.
    pub fn analyze(project_root: &Path, events: &[RuntimeEvent], slow_ms: f64) -> Vec<Finding> {
        let mut findings = Vec::new();

        let api_routes_path = project_root.join("routes").join("api.php");
        if let Ok(content) = fs::read_to_string(&api_routes_path) {
            if !content.trim().is_empty() && !content.contains("throttle") {
                findings.push(Finding {
                    id: "API-001".to_string(),
                    module: "api".to_string(),
                    title: "No explicit rate-limiting (`throttle`) middleware found in routes/api.php".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::Medium,
                    affected_component: "routes/api.php".to_string(),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "api_analyzer".to_string(),
                        detail: "routes/api.php does not reference `throttle`; verify global API rate-limiter configuration in bootstrap/app.php or RouteServiceProvider.".to_string(),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Verify `throttle:api` or `RateLimiter::for('api', ...)` is active for public API endpoints.".to_string(),
                });
            }
        }

        let mut by_api_route: HashMap<String, (usize, usize, f64)> = HashMap::new();
        for ev in events {
            if let RuntimeEvent::Request {
                method,
                route,
                status,
                duration_ms,
                ..
            } = ev
            {
                if route.starts_with("/api") {
                    let entry = by_api_route
                        .entry(format!("{method} {route}"))
                        .or_insert((0, 0, 0.0));
                    entry.0 += 1;
                    if *status >= 500 {
                        entry.1 += 1;
                    }
                    if *duration_ms > entry.2 {
                        entry.2 = *duration_ms;
                    }
                }
            }
        }

        for (route, (total, errors_5xx, max_ms)) in by_api_route {
            if errors_5xx > 0 {
                let err_rate = (errors_5xx as f64 / total as f64) * 100.0;
                findings.push(Finding {
                    id: format!("API-ERR-{}", findings.len() + 1),
                    module: "api".to_string(),
                    title: format!("API 5xx errors on {route} ({errors_5xx}/{total}, {err_rate:.1}%)"),
                    severity: if err_rate >= 5.0 { Severity::High } else { Severity::Medium },
                    confidence: Confidence::High,
                    affected_component: route.clone(),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "api_analyzer".to_string(),
                        detail: format!("{errors_5xx} of {total} observed API requests returned HTTP 5xx."),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Correlate failing API requests with application error logs.".to_string(),
                });
            }
            if max_ms >= slow_ms {
                findings.push(Finding {
                    id: format!("API-SLOW-{}", findings.len() + 1),
                    module: "api".to_string(),
                    title: format!("Slow API endpoint {route} (max {max_ms:.0}ms)"),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    affected_component: route,
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "api_analyzer".to_string(),
                        detail: format!("Observed API response time reached {max_ms:.1}ms (threshold {slow_ms:.0}ms)."),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Profile database queries, JSON resource serialization, and external HTTP calls on this endpoint.".to_string(),
                });
            }
        }

        findings
    }
}
