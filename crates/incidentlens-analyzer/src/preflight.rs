use incidentlens_core::{Finding, ProjectReport, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub overall: String,
    pub checks: Vec<PreflightCheck>,
    pub missing_env_keys: Vec<String>,
}

pub struct PreflightScanner;

impl PreflightScanner {
    pub fn evaluate(
        project_root: &Path,
        report: &ProjectReport,
        findings: &[Finding],
    ) -> PreflightReport {
        let mut checks = Vec::new();

        // 1. Laravel config & debug check
        let has_crit = findings
            .iter()
            .any(|f| f.module == "project" && f.severity == Severity::Critical);
        checks.push(PreflightCheck {
            name: "Laravel Configuration".to_string(),
            status: if has_crit { CheckStatus::Fail } else { CheckStatus::Pass },
            detail: if has_crit {
                "Critical configuration issue detected (e.g. APP_DEBUG=true in production)."
                    .to_string()
            } else {
                "Core Laravel configuration checks passed.".to_string()
            },
        });

        // 2. Composer lockfile
        checks.push(PreflightCheck {
            name: "Composer Dependencies".to_string(),
            status: if report.has_composer_lock {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            detail: if report.has_composer_lock {
                "composer.lock is present.".to_string()
            } else {
                "composer.lock is missing.".to_string()
            },
        });

        // 3. .env vs .env.example key drift (keys only, never values!)
        let missing_env_keys = detect_env_key_drift(project_root);
        checks.push(PreflightCheck {
            name: "Environment Key Drift (.env vs .env.example)".to_string(),
            status: if missing_env_keys.is_empty() {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            detail: if missing_env_keys.is_empty() {
                "All .env.example keys are present in .env.".to_string()
            } else {
                format!("Missing keys in .env: {}", missing_env_keys.join(", "))
            },
        });

        // 4. Migration risks
        let mig_count = findings.iter().filter(|f| f.module == "migration").count();
        checks.push(PreflightCheck {
            name: "Database Migrations".to_string(),
            status: if mig_count > 0 {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            },
            detail: if mig_count > 0 {
                format!("{mig_count} potentially risky migration finding(s) require review.")
            } else {
                "No risky migration patterns detected.".to_string()
            },
        });

        // 5. Security posture
        let sec_crit = findings
            .iter()
            .any(|f| f.module == "security" && matches!(f.severity, Severity::Critical | Severity::High));
        checks.push(PreflightCheck {
            name: "Security Posture".to_string(),
            status: if sec_crit {
                CheckStatus::Fail
            } else {
                CheckStatus::Pass
            },
            detail: if sec_crit {
                "High/critical security finding(s) detected.".to_string()
            } else {
                "No high/critical security misconfigurations detected.".to_string()
            },
        });

        let has_fail = checks.iter().any(|c| c.status == CheckStatus::Fail);
        let has_warn = checks.iter().any(|c| c.status == CheckStatus::Warn);
        let overall = if has_fail {
            "BLOCKED"
        } else if has_warn {
            "REVIEW_NEEDED"
        } else {
            "READY"
        }
        .to_string();

        PreflightReport {
            overall,
            checks,
            missing_env_keys,
        }
    }
}

fn detect_env_key_drift(root: &Path) -> Vec<String> {
    let example_path = root.join(".env.example");
    let env_path = root.join(".env");
    let (Ok(ex_raw), Ok(env_raw)) = (fs::read_to_string(example_path), fs::read_to_string(env_path)) else {
        return Vec::new();
    };

    let ex_keys = parse_env_keys(&ex_raw);
    let env_keys = parse_env_keys(&env_raw);
    ex_keys.difference(&env_keys).cloned().collect()
}

fn parse_env_keys(raw: &str) -> BTreeSet<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.trim().to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn detects_env_key_drift_without_exposing_values() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join(".env.example"), "APP_KEY=\nSTRIPE_WEBHOOK_SECRET=\n").unwrap();
        fs::write(tmp.path().join(".env"), "APP_KEY=base64:secret\n").unwrap();

        let missing = detect_env_key_drift(tmp.path());
        assert_eq!(missing, vec!["STRIPE_WEBHOOK_SECRET".to_string()]);
    }
}
