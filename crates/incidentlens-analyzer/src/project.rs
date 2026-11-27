use incidentlens_core::validation::validate_project_root;
use incidentlens_core::{
    Confidence, CoreError, Evidence, EvidenceKind, Finding, ProjectDrivers, ProjectMetadata,
    ProjectReport, Severity,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error(transparent)]
    Core(#[from] CoreError),

    #[error("project at '{0}' is not a valid Laravel application: {1}")]
    NotALaravelProject(String, String),

    #[error("failed to read '{0}': {1}")]
    Io(String, std::io::Error),
}

#[derive(Debug, Clone)]
pub struct ProjectAnalysis {
    pub report: ProjectReport,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Deserialize, Default)]
struct ComposerJson {
    name: Option<String>,
    #[serde(default)]
    require: BTreeMap<String, String>,
    #[serde(default, rename = "require-dev")]
    require_dev: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
struct ComposerLock {
    #[serde(default)]
    packages: Vec<ComposerLockPackage>,
}

#[derive(Debug, Deserialize, Default)]
struct ComposerLockPackage {
    name: String,
    version: String,
}

pub struct ProjectAnalyzer;

impl ProjectAnalyzer {
    /// Inspects a Laravel project directory without printing or retaining secret values.
    pub fn analyze(
        project_root: &Path,
        runtime_meta: Option<&ProjectMetadata>,
    ) -> Result<ProjectAnalysis, AnalyzerError> {
        let root = validate_project_root(project_root)?;
        let composer_path = root.join("composer.json");

        if !composer_path.is_file() {
            return Err(AnalyzerError::NotALaravelProject(
                root.display().to_string(),
                "missing composer.json".to_string(),
            ));
        }

        let composer_raw = fs::read_to_string(&composer_path)
            .map_err(|e| AnalyzerError::Io(composer_path.display().to_string(), e))?;
        let composer: ComposerJson = serde_json::from_str(&composer_raw).map_err(|e| {
            AnalyzerError::NotALaravelProject(
                root.display().to_string(),
                format!("invalid composer.json: {e}"),
            )
        })?;

        let has_laravel_framework = composer.require.contains_key("laravel/framework");
        let has_artisan = root.join("artisan").is_file();

        if !has_laravel_framework && !has_artisan {
            return Err(AnalyzerError::NotALaravelProject(
                root.display().to_string(),
                "neither laravel/framework in composer.json nor artisan file found".to_string(),
            ));
        }

        let has_composer_lock = root.join("composer.lock").is_file();
        let locked_laravel_version = if has_composer_lock {
            read_locked_laravel_version(&root.join("composer.lock"))
        } else {
            None
        };

        let laravel_version = runtime_meta
            .and_then(|m| m.laravel_version.clone())
            .or(locked_laravel_version)
            .or_else(|| composer.require.get("laravel/framework").cloned());

        let php_constraint = composer.require.get("php").cloned();
        let env_path = root.join(".env");
        let has_env_file = env_path.is_file();
        let env_flags = if has_env_file {
            inspect_env_safely(&env_path)
        } else {
            EnvInspection::default()
        };

        let environment = runtime_meta
            .and_then(|m| m.environment.clone())
            .or(env_flags.app_env.clone());

        let debug = runtime_meta
            .and_then(|m| m.debug)
            .or(env_flags.app_debug);

        let drivers = ProjectDrivers {
            cache: runtime_meta
                .and_then(|m| m.drivers.cache.clone())
                .or(env_flags.cache_driver.clone()),
            queue: runtime_meta
                .and_then(|m| m.drivers.queue.clone())
                .or(env_flags.queue_driver.clone()),
            database: runtime_meta
                .and_then(|m| m.drivers.database.clone())
                .or(env_flags.db_connection.clone()),
            session: runtime_meta
                .and_then(|m| m.drivers.session.clone())
                .or(env_flags.session_driver.clone()),
            log: runtime_meta
                .and_then(|m| m.drivers.log.clone())
                .or(env_flags.log_channel.clone()),
        };

        let logs_dir = root.join("storage").join("logs");
        let log_files_count = count_log_files(&logs_dir);

        let name = runtime_meta
            .and_then(|m| m.name.clone())
            .or(composer.name)
            .unwrap_or_else(|| {
                root.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("laravel-app")
                    .to_string()
            });

        let packages_count = composer.require.len() + composer.require_dev.len();

        let report = ProjectReport {
            root: root.display().to_string(),
            name,
            is_laravel_project: true,
            laravel_version,
            php_constraint,
            php_version: runtime_meta.and_then(|m| m.php_version.clone()),
            environment: environment.clone(),
            debug,
            has_env_file,
            has_composer_lock,
            has_artisan,
            log_files_count,
            packages_count,
            drivers: drivers.clone(),
        };

        let findings = evaluate_project_findings(&root, &report, &env_flags);

        Ok(ProjectAnalysis { report, findings })
    }
}

#[derive(Debug, Default)]
struct EnvInspection {
    app_env: Option<String>,
    app_debug: Option<bool>,
    app_key_present: bool,
    app_key_non_empty: bool,
    cache_driver: Option<String>,
    queue_driver: Option<String>,
    db_connection: Option<String>,
    session_driver: Option<String>,
    log_channel: Option<String>,
}

/// Reads `.env` only for non-secret configuration flags and key-presence checks.
/// Secret values such as `APP_KEY` or passwords are never stored or returned.
fn inspect_env_safely(env_path: &Path) -> EnvInspection {
    let Ok(content) = fs::read_to_string(env_path) else {
        return EnvInspection::default();
    };

    let mut raw: HashMap<String, String> = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            continue;
        };
        let key = k.trim().to_string();
        let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
        if key == "APP_KEY" {
            // Only record presence/non-emptiness, never store the actual key.
            raw.insert(
                "__APP_KEY_SET".to_string(),
                if val.is_empty() { "0" } else { "1" }.to_string(),
            );
            continue;
        }
        // Only retain safe non-secret operational keys.
        if matches!(
            key.as_str(),
            "APP_ENV"
                | "APP_DEBUG"
                | "CACHE_DRIVER"
                | "CACHE_STORE"
                | "QUEUE_CONNECTION"
                | "DB_CONNECTION"
                | "SESSION_DRIVER"
                | "LOG_CHANNEL"
        ) {
            raw.insert(key, val);
        }
    }

    let app_debug = raw.get("APP_DEBUG").and_then(|v| match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    });

    EnvInspection {
        app_env: raw.get("APP_ENV").cloned(),
        app_debug,
        app_key_present: raw.contains_key("__APP_KEY_SET"),
        app_key_non_empty: raw.get("__APP_KEY_SET").map(|v| v == "1").unwrap_or(false),
        cache_driver: raw
            .get("CACHE_STORE")
            .or_else(|| raw.get("CACHE_DRIVER"))
            .cloned(),
        queue_driver: raw.get("QUEUE_CONNECTION").cloned(),
        db_connection: raw.get("DB_CONNECTION").cloned(),
        session_driver: raw.get("SESSION_DRIVER").cloned(),
        log_channel: raw.get("LOG_CHANNEL").cloned(),
    }
}

fn read_locked_laravel_version(lock_path: &Path) -> Option<String> {
    let content = fs::read_to_string(lock_path).ok()?;
    let lock: ComposerLock = serde_json::from_str(&content).ok()?;
    lock.packages
        .into_iter()
        .find(|p| p.name == "laravel/framework")
        .map(|p| p.version)
}

fn count_log_files(logs_dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(logs_dir) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            let p = e.path();
            p.is_file() && p.extension().and_then(|ext| ext.to_str()) == Some("log")
        })
        .count()
}

fn evaluate_project_findings(
    root: &Path,
    report: &ProjectReport,
    env: &EnvInspection,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let is_prod = report
        .environment
        .as_deref()
        .map(|e| e.eq_ignore_ascii_case("production") || e.eq_ignore_ascii_case("prod"))
        .unwrap_or(false);

    if is_prod && report.debug == Some(true) {
        findings.push(Finding {
            id: "PRJ-001".to_string(),
            module: "project".to_string(),
            title: "Debug mode enabled in production environment".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            affected_component: ".env / config/app.php (APP_DEBUG)".to_string(),
            evidence: vec![Evidence {
                kind: EvidenceKind::Observed,
                source: "project_analyzer".to_string(),
                detail: "APP_ENV is set to production while APP_DEBUG is true.".to_string(),
            }],
            first_observed: None,
            last_observed: None,
            next_step: "Set APP_DEBUG=false in your production environment configuration."
                .to_string(),
        });
    }

    if report.has_env_file && (!env.app_key_present || !env.app_key_non_empty) {
        findings.push(Finding {
            id: "PRJ-002".to_string(),
            module: "project".to_string(),
            title: "APP_KEY is missing or empty in .env".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            affected_component: ".env (APP_KEY)".to_string(),
            evidence: vec![Evidence {
                kind: EvidenceKind::Observed,
                source: "project_analyzer".to_string(),
                detail: "APP_KEY key is absent or has an empty value in .env.".to_string(),
            }],
            first_observed: None,
            last_observed: None,
            next_step: "Run `php artisan key:generate` to configure an application encryption key."
                .to_string(),
        });
    }

    if !root.join("storage").join("logs").is_dir() {
        findings.push(Finding {
            id: "PRJ-003".to_string(),
            module: "project".to_string(),
            title: "Missing storage/logs directory".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            affected_component: "storage/logs".to_string(),
            evidence: vec![Evidence {
                kind: EvidenceKind::Observed,
                source: "project_analyzer".to_string(),
                detail: "Expected Laravel log directory storage/logs does not exist.".to_string(),
            }],
            first_observed: None,
            last_observed: None,
            next_step: "Create storage/logs and ensure the application user has write permissions."
                .to_string(),
        });
    }

    if !report.has_composer_lock {
        findings.push(Finding {
            id: "PRJ-004".to_string(),
            module: "project".to_string(),
            title: "Missing composer.lock file".to_string(),
            severity: Severity::Low,
            confidence: Confidence::High,
            affected_component: "composer.lock".to_string(),
            evidence: vec![Evidence {
                kind: EvidenceKind::Observed,
                source: "project_analyzer".to_string(),
                detail: "composer.lock was not found in the project root.".to_string(),
            }],
            first_observed: None,
            last_observed: None,
            next_step: "Run `composer install` or commit composer.lock for reproducible builds."
                .to_string(),
        });
    }

    if is_prod && report.drivers.queue.as_deref() == Some("sync") {
        findings.push(Finding {
            id: "PRJ-005".to_string(),
            module: "project".to_string(),
            title: "Synchronous queue driver configured in production".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            affected_component: ".env (QUEUE_CONNECTION)".to_string(),
            evidence: vec![Evidence {
                kind: EvidenceKind::Observed,
                source: "project_analyzer".to_string(),
                detail: "QUEUE_CONNECTION is 'sync' while APP_ENV is production.".to_string(),
            }],
            first_observed: None,
            last_observed: None,
            next_step:
                "Consider using an asynchronous queue driver (e.g., redis or database) in production."
                    .to_string(),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_sample_laravel_project(dir: &Path, env_content: &str) {
        fs::write(
            dir.join("composer.json"),
            r#"{"name":"acme/shop","require":{"php":"^8.3","laravel/framework":"^11.0"}}"#,
        )
        .unwrap();
        fs::write(dir.join("artisan"), "#!/usr/bin/env php\n").unwrap();
        fs::write(dir.join(".env"), env_content).unwrap();
        fs::create_dir_all(dir.join("storage/logs")).unwrap();
        fs::write(dir.join("storage/logs/laravel.log"), "").unwrap();
    }

    #[test]
    fn analyzes_valid_laravel_project_without_exposing_secrets() {
        let tmp = TempDir::new().unwrap();
        create_sample_laravel_project(
            tmp.path(),
            "APP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=base64:SUPERSECRETKEY123\nDB_PASSWORD=topsecret\n",
        );

        let analysis = ProjectAnalyzer::analyze(tmp.path(), None).unwrap();
        assert!(analysis.report.is_laravel_project);
        assert_eq!(analysis.report.name, "acme/shop");
        assert_eq!(analysis.report.environment.as_deref(), Some("production"));
        assert_eq!(analysis.report.debug, Some(true));
        assert_eq!(analysis.report.log_files_count, 1);

        // Critical finding for APP_DEBUG=true in production
        assert!(analysis.findings.iter().any(|f| f.id == "PRJ-001"));
        // APP_KEY is set, so PRJ-002 should NOT trigger
        assert!(!analysis.findings.iter().any(|f| f.id == "PRJ-002"));

        // Ensure secrets never appear in serialized report or findings
        let serialized = serde_json::to_string(&analysis.report).unwrap()
            + &serde_json::to_string(&analysis.findings).unwrap();
        assert!(!serialized.contains("SUPERSECRETKEY123"));
        assert!(!serialized.contains("topsecret"));
    }

    #[test]
    fn rejects_non_laravel_directory() {
        let tmp = TempDir::new().unwrap();
        let err = ProjectAnalyzer::analyze(tmp.path(), None).unwrap_err();
        assert!(matches!(err, AnalyzerError::NotALaravelProject(_, _)));
    }
}
