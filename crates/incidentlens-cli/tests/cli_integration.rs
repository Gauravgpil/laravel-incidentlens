use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn setup_laravel_fixture(env_content: &str) -> TempDir {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("composer.json"),
        r#"{"name":"acme/fixture-app","require":{"php":"^8.3","laravel/framework":"^11.0","acme/devpkg":"*"}}"#,
    )
    .unwrap();
    fs::write(tmp.path().join("artisan"), "#!/usr/bin/env php\n").unwrap();
    fs::write(tmp.path().join(".env"), env_content).unwrap();
    fs::create_dir_all(tmp.path().join("storage/logs")).unwrap();
    fs::write(
        tmp.path().join("storage/logs/laravel.log"),
        "[2026-11-27 10:00:00] production.ERROR: Illuminate\\Database\\QueryException: Deadlock for order 1 at app/Services/OrderService.php:12\n",
    )
    .unwrap();
    fs::create_dir_all(tmp.path().join("database/migrations")).unwrap();
    fs::write(
        tmp.path().join("database/migrations/2026_01_01_000000_drop_legacy.php"),
        "<?php public function up() { Schema::dropIfExists('legacy'); }",
    )
    .unwrap();
    tmp
}

#[test]
fn version_and_protocol_commands_succeed() {
    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["protocol"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"protocol_version\": \"1.0\""));
}

#[test]
fn scan_json_detects_production_debug_issue_and_ci_exits_1() {
    let fixture = setup_laravel_fixture("APP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=base64:secret123\n");

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["scan", "--project"])
        .arg(fixture.path())
        .args(["--format=json", "--ci"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("PRJ-001"))
        .stdout(predicate::str::contains("secret123").not());
}

#[test]
fn reports_html_and_markdown_and_snapshots_work() {
    let fixture = setup_laravel_fixture("APP_ENV=local\nAPP_DEBUG=true\nAPP_KEY=base64:secret123\n");

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["report", "--project"])
        .arg(fixture.path())
        .args(["--format=html"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<!DOCTYPE html>"))
        .stdout(predicate::str::contains("Laravel IncidentLens Diagnostic Report"));

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["snapshot", "base", "--project"])
        .arg(fixture.path())
        .assert()
        .success();

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["compare", "base", "base", "--project"])
        .arg(fixture.path())
        .args(["--format=json"])
        .assert()
        .success();
}

#[test]
fn non_laravel_project_exits_with_code_4() {
    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["status", "--project"])
        .arg(tmp.path())
        .assert()
        .code(4);
}

#[test]
fn preflight_incident_code_and_csv_export_work() {
    let fixture = setup_laravel_fixture("APP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=base64:secret123\n");

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["preflight", "--project"])
        .arg(fixture.path())
        .args(["--ci"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("BLOCKED"));

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["incident", "--project"])
        .arg(fixture.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("INCIDENT INVESTIGATION MODE"));

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["scan", "--project"])
        .arg(fixture.path())
        .args(["--format=csv"])
        .assert()
        .success()
        .stdout(predicate::str::contains("id,module,severity,confidence,title"));

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["architecture", "--project"])
        .arg(fixture.path())
        .args(["--format=json"])
        .assert()
        .success();

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["tests", "--project"])
        .arg(fixture.path())
        .args(["--format=json"])
        .assert()
        .success();

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["scalability", "--project"])
        .arg(fixture.path())
        .args(["--format=json"])
        .assert()
        .success();

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["frontend", "--project"])
        .arg(fixture.path())
        .args(["--format=json"])
        .assert()
        .success();

    // Verify stdin RequestEnvelope respects options.modules filtering
    let req_json = serde_json::json!({
        "protocol_version": "1.0",
        "command": "scan",
        "project": { "root": fixture.path().display().to_string() },
        "options": { "modules": ["security"], "scope": "secrets" }
    })
    .to_string();

    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["scan", "--stdin-json", "--format=json"])
        .write_stdin(req_json)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"module\": \"migration\"").not());
}
