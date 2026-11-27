pub mod auth;
pub mod secrets;
pub mod vulns;

use incidentlens_core::{Finding, ProjectReport};
use std::path::Path;

pub struct SecurityAnalyzer;

impl SecurityAnalyzer {
    /// Runs the full read-only Laravel Security Intelligence Engine.
    /// Never prints raw secret values or modifies application files.
    pub fn analyze(project_root: &Path, report: &ProjectReport) -> Vec<Finding> {
        Self::analyze_scoped(project_root, report, "all")
    }

    pub fn analyze_scoped(
        project_root: &Path,
        report: &ProjectReport,
        scope: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let all = scope == "all" || scope.is_empty();

        if all || matches!(scope, "secrets" | "ai" | "leaks") {
            findings.extend(secrets::scan_secrets_and_ai_keys(project_root, report));
        }
        if all || scope == "git" {
            findings.extend(secrets::scan_git_history(project_root));
        }
        if all || matches!(scope, "auth" | "idor") {
            findings.extend(auth::scan_auth_and_access_control(project_root, report));
        }
        if all || matches!(scope, "vulnerabilities" | "storage" | "webhooks" | "ai") {
            findings.extend(vulns::scan_vulnerabilities_uploads_and_webhooks(project_root));
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use incidentlens_core::ProjectDrivers;
    use std::fs;
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

    #[test]
    fn detects_ai_keys_in_frontend_inertia_idor_ssrf_and_webhooks_with_masking() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("resources/js")).unwrap();
        fs::create_dir_all(tmp.path().join("app/Http/Controllers")).unwrap();
        fs::create_dir_all(tmp.path().join("routes")).unwrap();

        let fake_openai = "sk-proj-1234567890abcdefghijklmnop";
        fs::write(
            tmp.path().join("resources/js/Chat.jsx"),
            format!("const k = '{fake_openai}';\nconst e = import.meta.env.VITE_OPENAI_API_KEY;\n"),
        )
        .unwrap();
        fs::write(
            tmp.path().join("app/Http/Controllers/OrderController.php"),
            "<?php\n$o = Order::find($request->input('tenant_id'));\nHttp::get($request->input('url'));\n$request->file('doc')->store('docs');\nreturn Inertia::render('Dash', ['apiKey' => $key]);\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("routes/web.php"),
            "<?php\nRoute::post('/webhooks/stripe', [WebhookController::class, 'handle']);\n",
        )
        .unwrap();

        let report = ProjectReport {
            root: tmp.path().display().to_string(),
            name: "test".into(),
            is_laravel_project: true,
            laravel_version: None,
            php_constraint: None,
            php_version: None,
            environment: Some("local".into()),
            debug: Some(true),
            has_env_file: false,
            has_composer_lock: true,
            has_artisan: true,
            log_files_count: 0,
            packages_count: 1,
            drivers: ProjectDrivers::default(),
        };

        let findings = SecurityAnalyzer::analyze(tmp.path(), &report);
        assert!(findings.iter().any(|f| f.id.starts_with("SEC-KEY-")));
        assert!(findings.iter().any(|f| f.id.starts_with("SEC-FE-ENV-")));
        assert!(findings.iter().any(|f| f.id.starts_with("SEC-INERTIA-")));
        assert!(findings.iter().any(|f| f.id.starts_with("SEC-IDOR-")));
        assert!(findings.iter().any(|f| f.id.starts_with("SEC-SSRF-")));
        assert!(findings.iter().any(|f| f.id.starts_with("SEC-UPL-")));
        assert!(findings.iter().any(|f| f.id.starts_with("SEC-WH-")));

        let json = serde_json::to_string(&findings).unwrap();
        assert!(!json.contains(fake_openai));
        assert!(json.contains("sk-p****...mnop"));
    }

    #[test]
    fn detects_extended_a_to_z_secrets_with_masking() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("config")).unwrap();

        let fake_groq = "gsk_1234567890abcdefghijklmnop";
        let fake_rzp = "rzp_live_1234567890abcd";
        let fake_dsn = "postgres://admin:supersecretpass@db.internal:5432/prod";
        fs::write(
            tmp.path().join("config/services.php"),
            format!(
                "<?php\nreturn ['groq' => '{fake_groq}', 'rzp' => '{fake_rzp}', 'dsn' => '{fake_dsn}'];\n"
            ),
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
        assert!(findings.iter().any(|f| f.title.contains("Groq API Key")));
        assert!(findings.iter().any(|f| f.title.contains("Razorpay Live Key")));
        assert!(findings.iter().any(|f| f.title.contains("Database/Redis DSN")));

        let json = serde_json::to_string(&findings).unwrap();
        assert!(!json.contains(fake_groq));
        assert!(!json.contains(fake_rzp));
        assert!(!json.contains("supersecretpass"));
    }
}
