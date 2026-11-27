use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, ProjectReport, Severity};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

static SECRET_PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
static FRONTEND_ENV_RE: OnceLock<Regex> = OnceLock::new();
static INERTIA_SECRET_PROP_RE: OnceLock<Regex> = OnceLock::new();

fn secret_patterns() -> &'static Vec<(&'static str, Regex)> {
    SECRET_PATTERNS.get_or_init(|| {
        vec![
            // --- AI Providers (A-Z) ---
            ("Anthropic API Key", Regex::new(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b").unwrap()),
            ("ElevenLabs API Key", Regex::new(r#"(?i)(?:ELEVENLABS_API_KEY\s*[:=]\s*['"][^'"]{16,}['"]|\bsk_[a-f0-9]{48}\b)"#).unwrap()),
            ("Google Gemini / GCP API Key", Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap()),
            ("Groq API Key", Regex::new(r"\bgsk_[A-Za-z0-9]{20,}\b").unwrap()),
            ("Hugging Face Token", Regex::new(r"\bhf_[A-Za-z0-9]{20,}\b").unwrap()),
            ("OpenAI API Key", Regex::new(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b").unwrap()),
            ("OpenRouter API Key", Regex::new(r"\bsk-or-v1-[A-Za-z0-9]{20,}\b").unwrap()),
            ("Perplexity API Key", Regex::new(r"\bpplx-[A-Za-z0-9]{20,}\b").unwrap()),
            ("Replicate API Token", Regex::new(r"\br8_[A-Za-z0-9]{20,}\b").unwrap()),
            ("xAI / Grok API Key", Regex::new(r"\bxai-[A-Za-z0-9]{20,}\b").unwrap()),
            ("AI Provider API Key Assignment", Regex::new(r#"(?i)(?:WAVESPEED|KIE|RUNPOD|STABILITY|DEEPGRAM|COHERE|MISTRAL|DEEPSEEK|TOGETHER|FIREWORKS|FAL)_(?:API_)?KEY\s*(?:=>|=|:)\s*['"][^'"]{12,}['"]"#).unwrap()),

            // --- Payment Gateways & Marketing ---
            ("Cashfree / PayPal / GetResponse Secret", Regex::new(r#"(?i)(?:CASHFREE_SECRET|PAYPAL_SECRET|GETRESPONSE_API_KEY)\s*(?:=>|=|:)\s*['"][^'"]{12,}['"]"#).unwrap()),
            ("Razorpay Live Key", Regex::new(r"\brzp_live_[A-Za-z0-9]{14,}\b").unwrap()),
            ("Square Access/OAuth Token", Regex::new(r"\bsq0(?:atp|csp)-[A-Za-z0-9\-_]{20,}\b").unwrap()),
            ("Stripe Secret Key", Regex::new(r"\b[sr]k_live_[0-9a-zA-Z]{16,}\b").unwrap()),
            ("Stripe Webhook Signing Secret", Regex::new(r"\bwhsec_[A-Za-z0-9]{20,}\b").unwrap()),

            // --- Cloud, Infrastructure & Auth ---
            ("Alibaba Cloud Access Key", Regex::new(r"\bLTAI[A-Za-z0-9]{16,}\b").unwrap()),
            ("AWS Access Key ID", Regex::new(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b").unwrap()),
            ("AWS Bedrock API Key", Regex::new(r"\bABSK[A-Za-z0-9+/]{109,269}={0,2}\b").unwrap()),
            ("Azure AD Client Secret", Regex::new(r"[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}").unwrap()),
            ("Cloudflare / Vercel API Token", Regex::new(r#"(?i)(?:CLOUDFLARE_API_TOKEN|VERCEL_TOKEN)\s*(?:=>|=|:)\s*['"][^'"]{16,}['"]"#).unwrap()),
            ("Databricks Personal Access Token", Regex::new(r"\bdapi[a-f0-9]{32}\b").unwrap()),
            ("DigitalOcean Token", Regex::new(r"\bdo[po]_v1_[a-f0-9]{64}\b").unwrap()),
            ("Doppler API Token", Regex::new(r"\bdp\.pt\.[a-zA-Z0-9]{43}\b").unwrap()),
            ("Figma Personal Access Token", Regex::new(r"\bfigd_[A-Za-z0-9_-]{30,}\b").unwrap()),
            ("GCP Service Account JSON", Regex::new(r#""type"\s*:\s*"service_account""#).unwrap()),
            ("Grafana Cloud / Service Account Token", Regex::new(r"\b(?:glc_[A-Za-z0-9+/=]{20,}|glsa_[A-Za-z0-9_]{32}_[a-f0-9]{8})\b").unwrap()),
            ("HashiCorp Vault Token", Regex::new(r"\bhvs\.[A-Za-z0-9_-]{20,}\b").unwrap()),
            ("JWT / Supabase Token", Regex::new(r"\beyJhbGciOi[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap()),
            ("Laravel APP_KEY Hardcoded", Regex::new(r"\bbase64:[A-Za-z0-9+/=]{32,}\b").unwrap()),
            ("Linear API Key", Regex::new(r"\blin_api_[A-Za-z0-9]{40}\b").unwrap()),
            ("Notion Integration Token", Regex::new(r"\bntn_[A-Za-z0-9]{40,}\b").unwrap()),
            ("npm Access Token", Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap()),
            ("PlanetScale API Token", Regex::new(r"\bpscale_tkn_[A-Za-z0-9_=\.-]{32,64}\b").unwrap()),
            ("Postman API Key", Regex::new(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b").unwrap()),
            ("PyPI API Token", Regex::new(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{20,}\b").unwrap()),
            ("Supabase Service/Access Token", Regex::new(r"\bsbp_[a-f0-9]{40}\b").unwrap()),

            // --- VCS, Messaging, Email, Monitoring ---
            ("Discord Bot Token", Regex::new(r"\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b").unwrap()),
            ("GitHub Personal Access Token", Regex::new(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b").unwrap()),
            ("GitLab Token (PAT/OIDC/Runner)", Regex::new(r"\b(?:glpat|glrt)-[A-Za-z0-9\-_]{20,}\b|\bgloas-[0-9a-zA-Z_-]{64}\b").unwrap()),
            ("Mailgun API Key", Regex::new(r"\bkey-[0-9a-f]{32}\b").unwrap()),
            ("Resend API Key", Regex::new(r"\bre_[A-Za-z0-9]{20,}\b").unwrap()),
            ("SendGrid API Key", Regex::new(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b").unwrap()),
            ("Sentry DSN with Secret", Regex::new(r"https://[0-9a-f]{32}@[a-z0-9.-]*sentry\.io/\d+").unwrap()),
            ("Shopify Token/Secret", Regex::new(r"\bshp(?:at|ss|pa|ca)_[a-fA-F0-9]{32}\b").unwrap()),
            ("Slack Token (Bot/User/App)", Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b|\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+\b").unwrap()),
            ("Slack Incoming Webhook URL", Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+").unwrap()),
            ("Telegram Bot Token", Regex::new(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b").unwrap()),
            ("Twilio API Key / Account SID", Regex::new(r"\b(?:SK|AC)[0-9a-f]{32}\b").unwrap()),

            // --- Database DSNs, Private Keys & Hardcoded Secrets ---
            ("Database/Redis DSN with Credentials", Regex::new(r#"(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|redis|rediss|amqp)://[^:\s/'"]+:[^@\s/'"]+@[^\s/'"]+"#).unwrap()),
            ("Private Key Block", Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----").unwrap()),
            ("Hardcoded Password/Secret Assignment", Regex::new(r#"(?i)(?:db_password|redis_password|jwt_secret|webhook_secret|oauth_client_secret|smtp_password)\s*(?:=>|=|:)\s*['"][^'"]{8,}['"]"#).unwrap()),
        ]
    })
}

/// Masks a detected secret so the actual value is NEVER exposed in reports.
pub fn mask_secret(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= 8 {
        return "[REDACTED]".to_string();
    }
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}****...{suffix}")
}

pub fn scan_secrets_and_ai_keys(project_root: &Path, report: &ProjectReport) -> Vec<Finding> {
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
                source: "security_secrets".to_string(),
                detail: "APP_DEBUG=true in production exposes stack traces and internal environment details.".to_string(),
            }],
            first_observed: None,
            last_observed: None,
            next_step: "Set APP_DEBUG=false in production.".to_string(),
        });
    }

    for exposed in ["public/.env", "public/.git", "public/phpinfo.php"] {
        if project_root.join(exposed).exists() {
            findings.push(Finding {
                id: format!("SEC-PUB-{}", findings.len() + 1),
                module: "security".to_string(),
                title: format!("Sensitive path exposed in webroot: {exposed}"),
                severity: Severity::Critical,
                confidence: Confidence::High,
                affected_component: exposed.to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "security_secrets".to_string(),
                    detail: format!("'{exposed}' exists inside public/ and may be served over HTTP."),
                }],
                first_observed: None,
                last_observed: None,
                next_step: format!("Remove '{exposed}' immediately and rotate any exposed credentials."),
            });
        }
    }

    // Scan PHP, JS/TS/React, YAML, JSON, and public build files
    let scan_dirs = [
        "app",
        "config",
        "routes",
        "database",
        "resources/js",
        "public/build",
        ".github/workflows",
    ];
    let fe_env_re = FRONTEND_ENV_RE.get_or_init(|| {
        Regex::new(r"(?i)(?:VITE|NEXT_PUBLIC|REACT_APP)_[A-Z0-9_]*(?:KEY|SECRET|TOKEN|OPENAI|ANTHROPIC|GEMINI|STRIPE)")
            .expect("valid frontend env regex")
    });
    let inertia_re = INERTIA_SECRET_PROP_RE.get_or_init(|| {
        Regex::new(r#"(?i)Inertia::render\([^;]*(?:api_key|apiKey|secret|token|password|openai)"#)
            .expect("valid inertia prop regex")
    });

    for dir in scan_dirs {
        for file in collect_scannable_files(&project_root.join(dir)) {
            let Ok(content) = fs::read_to_string(&file) else {
                continue;
            };
            let rel = file
                .strip_prefix(project_root)
                .unwrap_or(&file)
                .display()
                .to_string();
            let is_frontend = rel.starts_with("resources/js") || rel.starts_with("public/build");

            for (idx, line) in content.lines().enumerate() {
                let line_no = idx + 1;
                for (label, re) in secret_patterns() {
                    if let Some(m) = re.find(line) {
                        let masked = mask_secret(m.as_str());
                        findings.push(Finding {
                            id: format!("SEC-KEY-{}", findings.len() + 1),
                            module: "security".to_string(),
                            title: format!(
                                "Hardcoded {label}{} in {rel}:{line_no}",
                                if is_frontend { " (Frontend/Browser Exposure!)" } else { "" }
                            ),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            affected_component: format!("{rel}:{line_no}"),
                            evidence: vec![Evidence {
                                kind: EvidenceKind::Observed,
                                source: "security_secrets".to_string(),
                                detail: format!("Detected {label} pattern: `{masked}` (actual value redacted)."),
                            }],
                            first_observed: None,
                            last_observed: None,
                            next_step: "Remove hardcoded credential, move to server-side `.env`, and rotate the key.".to_string(),
                        });
                    }
                }

                if is_frontend && fe_env_re.is_match(line) {
                    findings.push(Finding {
                        id: format!("SEC-FE-ENV-{}", findings.len() + 1),
                        module: "security".to_string(),
                        title: format!("Client-exposed secret env variable in {rel}:{line_no}"),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        affected_component: format!("{rel}:{line_no}"),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "security_ai".to_string(),
                            detail: "VITE_*/NEXT_PUBLIC_* secret/AI key reference is bundled into public browser JS.".to_string(),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Proxy AI/API calls through a Laravel backend controller instead of exposing keys in Vite env vars.".to_string(),
                    });
                }

                if inertia_re.is_match(line) {
                    findings.push(Finding {
                        id: format!("SEC-INERTIA-{}", findings.len() + 1),
                        module: "security".to_string(),
                        title: format!("Potential sensitive prop passed to Inertia::render() in {rel}:{line_no}"),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        affected_component: format!("{rel}:{line_no}"),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "data_flow".to_string(),
                            detail: "Inertia::render() appears to pass a key/secret/token/password prop to React frontend.".to_string(),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Strip sensitive fields using API Resources or `->only(...)` before passing props to Inertia.".to_string(),
                    });
                }
            }
        }
    }

    findings
}

/// Fast check: verifies whether `.env` was ever committed in Git history.
pub fn scan_git_env_only(project_root: &Path) -> Vec<Finding> {
    if !project_root.join(".git").exists() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    if let Ok(out) = Command::new("git")
        .args(["-C"])
        .arg(project_root)
        .args(["log", "-n", "1", "--all", "--oneline", "--", ".env"])
        .output()
    {
        if out.status.success() && !String::from_utf8_lossy(&out.stdout).trim().is_empty() {
            findings.push(Finding {
                id: "SEC-GIT-ENV".to_string(),
                module: "security".to_string(),
                title: ".env file found in Git commit history".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                affected_component: ".git history (.env)".to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "security_git".to_string(),
                    detail: "`.env` was committed in past Git history and remains recoverable even if deleted later.".to_string(),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Rotate all credentials in `.env` and purge `.env` from Git history (`git filter-repo`).".to_string(),
            });
        }
    }
    findings
}

/// Scans recent Git commit history (up to 50 commits) for committed secrets or `.env` files.
pub fn scan_git_history(project_root: &Path) -> Vec<Finding> {
    if !project_root.join(".git").exists() {
        return Vec::new();
    }

    let mut findings = scan_git_env_only(project_root);

    // Scan recent 50 commit patches for secret patterns (masked output only)
    if let Ok(out) = Command::new("git")
        .args(["-C"])
        .arg(project_root)
        .args(["log", "-n", "50", "-p", "--no-color"])
        .output()
    {
        if out.status.success() {
            let diff = String::from_utf8_lossy(&out.stdout);
            let mut current_commit = String::new();
            for line in diff.lines() {
                if let Some(rest) = line.strip_prefix("commit ") {
                    current_commit = rest.chars().take(10).collect();
                    continue;
                }
                if !line.starts_with('+') || line.starts_with("+++") {
                    continue;
                }
                for (label, re) in secret_patterns() {
                    if let Some(m) = re.find(line) {
                        let masked = mask_secret(m.as_str());
                        findings.push(Finding {
                            id: format!("SEC-GIT-KEY-{}", findings.len() + 1),
                            module: "security".to_string(),
                            title: format!("Historical {label} in Git commit {current_commit}"),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            affected_component: format!("git:{current_commit}"),
                            evidence: vec![Evidence {
                                kind: EvidenceKind::Observed,
                                source: "security_git".to_string(),
                                detail: format!("Commit {current_commit} added {label}: `{masked}`."),
                            }],
                            first_observed: None,
                            last_observed: None,
                            next_step: "Rotate the exposed credential and scrub it from Git history (e.g. Gitleaks/TruffleHog + git-filter-repo).".to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }

    findings
}

fn collect_scannable_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_dir() {
            if p.file_name().and_then(|n| n.to_str()) == Some("node_modules") {
                continue;
            }
            out.extend(collect_scannable_files(&p));
        } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "php" | "js" | "jsx" | "ts" | "tsx" | "json" | "yml" | "yaml" | "env") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}
