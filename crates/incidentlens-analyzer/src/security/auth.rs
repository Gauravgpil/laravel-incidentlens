use crate::code::collect_php_files;
use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, ProjectReport, Severity};
use regex::Regex;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

static IDOR_RE: OnceLock<Regex> = OnceLock::new();

pub fn scan_auth_and_access_control(project_root: &Path, report: &ProjectReport) -> Vec<Finding> {
    let mut findings = Vec::new();
    let is_prod = report
        .environment
        .as_deref()
        .map(|e| e.eq_ignore_ascii_case("production") || e.eq_ignore_ascii_case("prod"))
        .unwrap_or(false);

    // 1. Session cookie security in .env & config/session.php
    if let Ok(env_text) = fs::read_to_string(project_root.join(".env")) {
        for line in env_text.lines() {
            let t = line.trim();
            if let Some((k, v)) = t.split_once('=') {
                let key = k.trim();
                let val = v.trim().trim_matches('"').trim_matches('\'');
                if is_prod && key == "SESSION_SECURE_COOKIE" && val.eq_ignore_ascii_case("false") {
                    findings.push(Finding {
                        id: "SEC-SES-001".to_string(),
                        module: "security".to_string(),
                        title: "SESSION_SECURE_COOKIE disabled in production".to_string(),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        affected_component: ".env (SESSION_SECURE_COOKIE)".to_string(),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "security_auth".to_string(),
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

    if let Ok(session_cfg) = fs::read_to_string(project_root.join("config/session.php")) {
        if session_cfg.contains("'http_only' => false") {
            findings.push(Finding {
                id: "SEC-SES-002".to_string(),
                module: "security".to_string(),
                title: "Session cookie `http_only` is disabled in config/session.php".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                affected_component: "config/session.php".to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "security_auth".to_string(),
                    detail: "http_only => false allows client-side JavaScript to read session cookies.".to_string(),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Set `'http_only' => true` in config/session.php.".to_string(),
            });
        }
    }

    // 2. CORS wildcard + credentials check
    if let Ok(cors) = fs::read_to_string(project_root.join("config/cors.php")) {
        if cors.contains("'*'") && cors.contains("'supports_credentials' => true") {
            findings.push(Finding {
                id: "SEC-CORS-001".to_string(),
                module: "security".to_string(),
                title: "Permissive CORS wildcard with supports_credentials enabled".to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                affected_component: "config/cors.php".to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "security_auth".to_string(),
                    detail: "config/cors.php contains wildcard '*' alongside supports_credentials => true.".to_string(),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Restrict `allowed_origins` to explicit trusted domains.".to_string(),
            });
        }
    }

    // 3. Filament Admin Resource authorization audit
    for file in collect_php_files(&project_root.join("app/Filament/Resources")) {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        if content.contains("extends Resource")
            && !content.contains("canViewAny")
            && !content.contains("canCreate")
            && !content.contains("canEdit")
        {
            let rel = file
                .strip_prefix(project_root)
                .unwrap_or(&file)
                .display()
                .to_string();
            findings.push(Finding {
                id: format!("SEC-FIL-{}", findings.len() + 1),
                module: "security".to_string(),
                title: format!("Filament Resource without explicit Resource authorization overrides in {rel}"),
                severity: Severity::Low,
                confidence: Confidence::Low,
                affected_component: rel,
                evidence: vec![Evidence {
                    kind: EvidenceKind::Hypothesis,
                    source: "security_auth".to_string(),
                    detail: "Filament Resource relies on Model Policy; verify a Policy is registered so non-admin panel users cannot access records.".to_string(),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Verify a Laravel Policy is registered for this Model or implement `canViewAny()` / `getEloquentQuery()` tenant scoping.".to_string(),
            });
        }
    }

    // 4. IDOR / BOLA / Tenant-ID manipulation candidates in Controllers
    let idor_re = IDOR_RE.get_or_init(|| {
        Regex::new(r"(?i)::find\s*\(\s*\$request->(?:input|get)\s*\(\s*['\x22](?:id|user_id|tenant_id|organization_id)['\x22]")
            .expect("valid idor regex")
    });
    for file in collect_php_files(&project_root.join("app/Http/Controllers")) {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        let rel = file
            .strip_prefix(project_root)
            .unwrap_or(&file)
            .display()
            .to_string();
        for (idx, line) in content.lines().enumerate() {
            if idor_re.is_match(line) {
                findings.push(Finding {
                    id: format!("SEC-IDOR-{}", findings.len() + 1),
                    module: "security".to_string(),
                    title: format!("Potential IDOR / Tenant-ID manipulation candidate in {rel}:{}", idx + 1),
                    severity: Severity::High,
                    confidence: Confidence::Medium,
                    affected_component: format!("{rel}:{}", idx + 1),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "security_auth".to_string(),
                        detail: "Controller calls `::find($request->input(...))` directly using client-supplied ID/tenant_id.".to_string(),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Scope queries by `auth()->id()` / `auth()->user()->tenant_id` and enforce `$this->authorize(...)`.".to_string(),
                });
            }
        }
    }

    findings
}
