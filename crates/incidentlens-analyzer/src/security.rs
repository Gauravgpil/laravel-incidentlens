use crate::code::collect_php_files;
use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, ProjectReport, Severity};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static SQL_INJECTION_RE: OnceLock<Regex> = OnceLock::new();
static SECRET_LITERAL_RE: OnceLock<Regex> = OnceLock::new();
static UNSAFE_EXEC_RE: OnceLock<Regex> = OnceLock::new();
static BLADE_XSS_RE: OnceLock<Regex> = OnceLock::new();

pub struct SecurityAnalyzer;

impl SecurityAnalyzer {
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
                    detail: "APP_DEBUG=true in production can leak stack traces, env keys, and internal paths.".to_string(),
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

        // Check .env for insecure cookie / session flags (non-secret booleans only)
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

        // CORS wildcard + credentials check
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
                        source: "security_analyzer".to_string(),
                        detail: "config/cors.php contains wildcard '*' alongside supports_credentials => true.".to_string(),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Restrict `allowed_origins` to explicit trusted domains.".to_string(),
                });
            }
        }

        // Static code security scan across app/ and config/
        let sql_re = SQL_INJECTION_RE.get_or_init(|| {
            Regex::new(r#"(?:DB::raw|whereRaw|selectRaw|orderByRaw)\s*\(\s*"[^"]*\$"#)
                .expect("valid sql raw regex")
        });
        let secret_re = SECRET_LITERAL_RE.get_or_init(|| {
            Regex::new(r#"(?i)(?:sk_live_[0-9a-zA-Z]{16,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)"#)
                .expect("valid secret literal regex")
        });
        let exec_re = UNSAFE_EXEC_RE.get_or_init(|| {
            Regex::new(r"\b(?:unserialize|shell_exec|exec|passthru|system)\s*\([^)]*\$")
                .expect("valid unsafe exec regex")
        });

        for dir in ["app", "config", "routes"] {
            for file in collect_php_files(&project_root.join(dir)) {
                let Ok(content) = fs::read_to_string(&file) else {
                    continue;
                };
                let rel = file
                    .strip_prefix(project_root)
                    .unwrap_or(&file)
                    .display()
                    .to_string();

                for (idx, line) in content.lines().enumerate() {
                    let line_no = idx + 1;
                    if sql_re.is_match(line) {
                        findings.push(Finding {
                            id: format!("SEC-SQL-{}", findings.len() + 1),
                            module: "security".to_string(),
                            title: format!("Dynamic raw SQL interpolation candidate in {rel}:{line_no}"),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            affected_component: format!("{rel}:{line_no}"),
                            evidence: vec![Evidence {
                                kind: EvidenceKind::Observed,
                                source: "security_analyzer".to_string(),
                                detail: "Raw SQL helper uses double-quoted string interpolation with `$variable`.".to_string(),
                            }],
                            first_observed: None,
                            last_observed: None,
                            next_step: "Use parameter bindings (`whereRaw('col = ?', [$val])`) instead of string interpolation.".to_string(),
                        });
                    }
                    if secret_re.is_match(line) {
                        findings.push(Finding {
                            id: format!("SEC-KEY-{}", findings.len() + 1),
                            module: "security".to_string(),
                            title: format!("Hardcoded secret/key candidate in {rel}:{line_no}"),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            affected_component: format!("{rel}:{line_no}"),
                            evidence: vec![Evidence {
                                kind: EvidenceKind::Observed,
                                source: "security_analyzer".to_string(),
                                detail: "Detected pattern matching a live API key, AWS access key, or private key block (value redacted).".to_string(),
                            }],
                            first_observed: None,
                            last_observed: None,
                            next_step: "Move the secret to `.env` / secrets manager and rotate the exposed credential.".to_string(),
                        });
                    }
                    if exec_re.is_match(line) {
                        findings.push(Finding {
                            id: format!("SEC-EXEC-{}", findings.len() + 1),
                            module: "security".to_string(),
                            title: format!("Unsafe deserialization or shell execution candidate in {rel}:{line_no}"),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            affected_component: format!("{rel}:{line_no}"),
                            evidence: vec![Evidence {
                                kind: EvidenceKind::Observed,
                                source: "security_analyzer".to_string(),
                                detail: "Detected `unserialize()` or shell execution function called with a variable argument.".to_string(),
                            }],
                            first_observed: None,
                            last_observed: None,
                            next_step: "Prefer JSON (`json_decode`) over `unserialize()`, and `Process::run([...])` with array args over shell strings.".to_string(),
                        });
                    }
                }
            }
        }

        // Blade unescaped XSS candidate scan
        let xss_re = BLADE_XSS_RE.get_or_init(|| Regex::new(r"\{!!\s*\$").expect("valid blade xss regex"));
        for blade in collect_blade_files(&project_root.join("resources/views")) {
            let Ok(content) = fs::read_to_string(&blade) else {
                continue;
            };
            let rel = blade
                .strip_prefix(project_root)
                .unwrap_or(&blade)
                .display()
                .to_string();
            for (idx, line) in content.lines().enumerate() {
                if xss_re.is_match(line) {
                    findings.push(Finding {
                        id: format!("SEC-XSS-{}", findings.len() + 1),
                        module: "security".to_string(),
                        title: format!("Unescaped Blade output ({{!! $... !!}}) candidate in {rel}:{}", idx + 1),
                        severity: Severity::Medium,
                        confidence: Confidence::Low,
                        affected_component: format!("{rel}:{}", idx + 1),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "security_analyzer".to_string(),
                            detail: "Unescaped `{!! ... !!}` renders raw HTML; if user-controlled, this risks XSS.".to_string(),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Use escaped `{{ ... }}` unless HTML is explicitly sanitized.".to_string(),
                    });
                    break;
                }
            }
        }

        findings
    }
}

fn collect_blade_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_dir() {
            out.extend(collect_blade_files(&p));
        } else if p
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(".blade.php"))
            .unwrap_or(false)
        {
            out.push(p);
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use incidentlens_core::ProjectDrivers;
    use tempfile::TempDir;

    #[test]
    fn detects_sql_injection_hardcoded_secret_and_xss_without_printing_secret() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("app/Services")).unwrap();
        fs::create_dir_all(tmp.path().join("resources/views")).unwrap();

        fs::write(
            tmp.path().join("app/Services/Search.php"),
            "<?php\n$k = 'AKIAIOSFODNN7EXAMPLE';\nDB::select(DB::raw(\"SELECT * FROM users WHERE name = '$q'\"));\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("resources/views/show.blade.php"),
            "<div>{!! $userBio !!}</div>\n",
        )
        .unwrap();

        let report = ProjectReport {
            root: tmp.path().display().to_string(),
            name: "test".into(),
            is_laravel_project: true,
            laravel_version: None,
            php_constraint: None,
            php_version: None,
            environment: Some("production".into()),
            debug: Some(false),
            has_env_file: false,
            has_composer_lock: true,
            has_artisan: true,
            log_files_count: 0,
            packages_count: 1,
            drivers: ProjectDrivers::default(),
        };

        let findings = SecurityAnalyzer::analyze(tmp.path(), &report);
        assert!(findings.iter().any(|f| f.id.starts_with("SEC-KEY-")));
        assert!(findings.iter().any(|f| f.id.starts_with("SEC-SQL-")));
        assert!(findings.iter().any(|f| f.id.starts_with("SEC-XSS-")));

        let json = serde_json::to_string(&findings).unwrap();
        assert!(!json.contains("AKIAIOSFODNN7EXAMPLE"));
    }
}
