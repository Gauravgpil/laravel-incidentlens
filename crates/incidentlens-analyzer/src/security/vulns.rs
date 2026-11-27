use crate::code::collect_php_files;
use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static SQL_INJECTION_RE: OnceLock<Regex> = OnceLock::new();
static UNSAFE_EXEC_RE: OnceLock<Regex> = OnceLock::new();
static SSRF_OR_REDIRECT_RE: OnceLock<Regex> = OnceLock::new();
static BLADE_XSS_RE: OnceLock<Regex> = OnceLock::new();
static WEBHOOK_ROUTE_RE: OnceLock<Regex> = OnceLock::new();

pub fn scan_vulnerabilities_uploads_and_webhooks(project_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    let sql_re = SQL_INJECTION_RE.get_or_init(|| {
        Regex::new(r#"(?:DB::raw|whereRaw|selectRaw|orderByRaw)\s*\(\s*"[^"]*\$"#)
            .expect("valid sql raw regex")
    });
    let exec_re = UNSAFE_EXEC_RE.get_or_init(|| {
        Regex::new(r"\b(?:eval|unserialize|shell_exec|exec|passthru|system|proc_open)\s*\([^)]*\$")
            .expect("valid unsafe exec regex")
    });
    let ssrf_re = SSRF_OR_REDIRECT_RE.get_or_init(|| {
        Regex::new(r"(?:Http::(?:get|post|put)|file_get_contents|redirect)\s*\(\s*\$request->")
            .expect("valid ssrf regex")
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
                            source: "security_vulns".to_string(),
                            detail: "Raw SQL helper uses double-quoted string interpolation with `$variable`.".to_string(),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Use parameter bindings (`whereRaw('col = ?', [$val])`).".to_string(),
                    });
                }
                if exec_re.is_match(line) {
                    findings.push(Finding {
                        id: format!("SEC-EXEC-{}", findings.len() + 1),
                        module: "security".to_string(),
                        title: format!("Unsafe deserialization/eval/shell execution candidate in {rel}:{line_no}"),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        affected_component: format!("{rel}:{line_no}"),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "security_vulns".to_string(),
                            detail: "Detected `eval()`, `unserialize()`, or shell execution with variable input.".to_string(),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Use `json_decode()` instead of `unserialize()` and `Process::run([...])` with array arguments.".to_string(),
                    });
                }
                if ssrf_re.is_match(line) {
                    findings.push(Finding {
                        id: format!("SEC-SSRF-{}", findings.len() + 1),
                        module: "security".to_string(),
                        title: format!("Potential SSRF / Open Redirect from $request-> in {rel}:{line_no}"),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        affected_component: format!("{rel}:{line_no}"),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "security_vulns".to_string(),
                            detail: "HTTP request, file_get_contents, or redirect directly uses `$request->...` input.".to_string(),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Validate URLs against an explicit domain allowlist before fetching or redirecting.".to_string(),
                    });
                }
            }

            // File upload validation check
            if content.contains("$request->file(") && !content.contains("mimes:") && !content.contains("mimetypes:") {
                findings.push(Finding {
                    id: format!("SEC-UPL-{}", findings.len() + 1),
                    module: "security".to_string(),
                    title: format!("File upload without MIME/extension validation in {rel}"),
                    severity: Severity::Medium,
                    confidence: Confidence::Medium,
                    affected_component: rel.clone(),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "security_storage".to_string(),
                        detail: "`$request->file(...)` detected without `mimes:` or `mimetypes:` validation rule in the same file.".to_string(),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Validate uploaded files with `['required', 'file', 'mimes:pdf,png,jpg', 'max:5120']` and store outside `public/`.".to_string(),
                });
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
                        source: "security_vulns".to_string(),
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

    // Webhook signature verification check
    let wh_re = WEBHOOK_ROUTE_RE.get_or_init(|| {
        Regex::new(r#"(?i)Route::post\s*\(\s*['"][^'"]*(?:webhook|stripe|razorpay|jvzoo|warriorplus)[^'"]*['"]"#)
            .expect("valid webhook regex")
    });
    for route_file in collect_php_files(&project_root.join("routes")) {
        let Ok(content) = fs::read_to_string(&route_file) else {
            continue;
        };
        let rel = route_file
            .strip_prefix(project_root)
            .unwrap_or(&route_file)
            .display()
            .to_string();
        for (idx, line) in content.lines().enumerate() {
            if wh_re.is_match(line) && !line.contains("middleware") {
                findings.push(Finding {
                    id: format!("SEC-WH-{}", findings.len() + 1),
                    module: "security".to_string(),
                    title: format!("Webhook POST route without explicit verification middleware in {rel}:{}", idx + 1),
                    severity: Severity::Medium,
                    confidence: Confidence::Low,
                    affected_component: format!("{rel}:{}", idx + 1),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Hypothesis,
                        source: "security_webhooks".to_string(),
                        detail: "Webhook endpoint route has no inline signature/throttle middleware; ensure signature verification runs in the controller.".to_string(),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Verify HMAC webhook signatures (`hash_equals`) and replay timestamps before processing.".to_string(),
                });
            }
        }
    }

    findings
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
