use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn setup_laravel_fixture(env_content: &str) -> TempDir {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("composer.json"),
        r#"{"name":"acme/fixture-app","require":{"php":"^8.3","laravel/framework":"^11.0"}}"#,
    )
    .unwrap();
    fs::write(tmp.path().join("artisan"), "#!/usr/bin/env php\n").unwrap();
    fs::write(tmp.path().join(".env"), env_content).unwrap();
    fs::create_dir_all(tmp.path().join("storage/logs")).unwrap();
    fs::write(tmp.path().join("storage/logs/laravel.log"), "[2026-11-27 10:00:00] local.INFO: Booted\n").unwrap();
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
fn non_laravel_project_exits_with_code_4() {
    let tmp = TempDir::new().unwrap();
    Command::cargo_bin("incidentlens")
        .unwrap()
        .args(["status", "--project"])
        .arg(tmp.path())
        .assert()
        .code(4);
}
