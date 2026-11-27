use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, ProjectReport, Severity};
use std::fs;
use std::path::Path;

pub struct SecurityAnalyzer;

impl SecurityAnalyzer {
    /// Performs safe, read-only security configuration and exposure checks.
    /// Never prints secret values or performs active scanning/exploitation.
    pub fn analyze(project_root: &Path, report: &ProjectReport) -> Vec<Finding> {
        let mut findings = Vec::new();
        let is_prod = report
            .environment
            .as_deref()
            .map(|e| e.eq_ignore_ascii_case("production") || e.eq_ignore_ascii_case("prod"))
            .unwrap_or(false);

        if is_prod && report.debug == Some(true) {
            findings.push(Finding {
                id: "SEC-001".to_string(),
                module: "security".to_string(),
                title: "Debug mode exposed in production".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                affected_component: ".env (APP_DEBUG)".to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "security_analyzer".to_string(),
                    detail: "APP_DEBUG=true in production can leak stack traces and environment metadata.".to_string(),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Set APP_DEBUG=false in production.".to_string(),
            });
        }

        // Check for `.env` accidentally inside `public/`
        let public_env = project_root.join("public").join(".env");
        if public_env.exists() {
            findings.push(Finding {
                id: "SEC-002".to_string(),
                module: "security".to_string(),
                title: "Environment file present in public/ webroot".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                affected_component: "public/.env".to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "security_analyzer".to_string(),
                    detail: "A .env file was detected inside public/, which may be served directly by HTTP.".to_string(),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Remove public/.env immediately and rotate any exposed credentials.".to_string(),
            });
        }

        // Check for insecure cookie / session flags in .env (key names & non-secret booleans only)
        if let Ok(env_text) = fs::read_to_string(project_root.join(".env")) {
            for line in env_text.lines() {
                let t = line.trim();
                if let Some((k, v)) = t.split_once('=') {
                    let key = k.trim();
                    let val = v.trim().trim_matches('"').trim_matches('\'');
                    if is_prod && key == "SESSION_SECURE_COOKIE" && val.eq_ignore_ascii_case("false") {
                        findings.push(Finding {
                            id: "SEC-003".to_string(),
                            module: "security".to_string(),
                            title: "SESSION_SECURE_COOKIE disabled in production".to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::High,
                            affected_component: ".env (SESSION_SECURE_COOKIE)".to_string(),
                            evidence: vec![Evidence {
                                kind: EvidenceKind::Observed,
                                source: "security_analyzer".to_string(),
                                detail: "SESSION_SECURE_COOKIE is false while APP_ENV is production.".to_string(),
                            }],
                            first_observed: None,
                            last_observed: None,
                            next_step: "Set SESSION_SECURE_COOKIE=true when serving over HTTPS.".to_string(),
                        });
                    }
                }
            }
        }

        findings
    }
}
