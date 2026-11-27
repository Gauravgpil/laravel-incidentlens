use crate::code::collect_php_files;
use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

static TESTCASE_RE: OnceLock<Regex> = OnceLock::new();

pub struct TestingAnalyzer;

impl TestingAnalyzer {
    /// Integrates with PHPUnit/Pest JUnit XML reports and inspects test coverage gaps
    /// without replacing PHPUnit or Pest.
    pub fn analyze(project_root: &Path, junit_path: Option<&Path>) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Parse JUnit XML if provided or discovered in standard locations
        let candidate_junit = junit_path.map(Path::to_path_buf).or_else(|| {
            [
                project_root.join("build/logs/junit.xml"),
                project_root.join("storage/app/incidentlens/junit.xml"),
                project_root.join("junit.xml"),
            ]
            .into_iter()
            .find(|p| p.is_file())
        });

        if let Some(ref path) = candidate_junit {
            if let Ok(xml) = fs::read_to_string(path) {
                findings.extend(parse_junit_findings(&xml));
            }
        }

        // 2. Identify untested critical controllers
        let tests_dir = project_root.join("tests");
        let test_names: HashSet<String> = collect_php_files(&tests_dir)
            .into_iter()
            .filter_map(|p| {
                p.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_ascii_lowercase())
            })
            .collect();

        let ctrl_dir = project_root.join("app/Http/Controllers");
        for ctrl in collect_php_files(&ctrl_dir) {
            let Some(stem) = ctrl.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if stem.eq_ignore_ascii_case("Controller") {
                continue;
            }
            let expected = format!("{}test", stem.to_ascii_lowercase());
            let has_match = test_names.iter().any(|t| t.contains(&stem.to_ascii_lowercase()) || t == &expected);
            if !has_match {
                findings.push(Finding {
                    id: format!("TEST-GAP-{}", findings.len() + 1),
                    module: "tests".to_string(),
                    title: format!("Untested controller candidate: {stem}"),
                    severity: Severity::Low,
                    confidence: Confidence::Low,
                    affected_component: format!("app/Http/Controllers/{stem}.php"),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "testing_analyzer".to_string(),
                        detail: format!("No test file matching '{stem}' was found under tests/."),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: format!("Add Feature/Unit tests for {stem} if it handles critical routes."),
                });
            }
        }

        findings
    }
}

fn parse_junit_findings(xml: &str) -> Vec<Finding> {
    let tc_re = TESTCASE_RE.get_or_init(|| {
        Regex::new(r#"<testcase[^>]*name="([^"]+)"[^>]*time="([0-9.]+)"[^>]*(?:/>|>([\s\S]*?)</testcase>)"#)
            .expect("valid testcase regex")
    });

    let mut findings = Vec::new();
    for caps in tc_re.captures_iter(xml) {
        let name = &caps[1];
        let time_s: f64 = caps[2].parse().unwrap_or(0.0);
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        if body.contains("<failure") || body.contains("<error") {
            findings.push(Finding {
                id: format!("TEST-FAIL-{}", findings.len() + 1),
                module: "tests".to_string(),
                title: format!("Failing test in JUnit report: {name}"),
                severity: Severity::High,
                confidence: Confidence::High,
                affected_component: name.to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "junit_xml".to_string(),
                    detail: format!("Test '{name}' reported a <failure> or <error> in JUnit XML."),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Run `./vendor/bin/pest` or `php artisan test --filter=...` to inspect the failure.".to_string(),
            });
        } else if time_s >= 1.5 {
            findings.push(Finding {
                id: format!("TEST-SLOW-{}", findings.len() + 1),
                module: "tests".to_string(),
                title: format!("Slow test: {name} ({time_s:.2}s)"),
                severity: Severity::Low,
                confidence: Confidence::High,
                affected_component: name.to_string(),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "junit_xml".to_string(),
                    detail: format!("Test '{name}' took {time_s:.2}s in JUnit XML."),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Check for unnecessary database seeding, sleep(), or unmocked HTTP calls.".to_string(),
            });
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parses_junit_failures_and_slow_tests() {
        let tmp = TempDir::new().unwrap();
        let junit = tmp.path().join("junit.xml");
        fs::write(
            &junit,
            r#"<testsuite><testcase name="test_checkout_fails" time="0.2"><failure>Assertion failed</failure></testcase><testcase name="test_slow_export" time="2.45"/></testsuite>"#,
        )
        .unwrap();

        let findings = TestingAnalyzer::analyze(tmp.path(), Some(&junit));
        assert!(findings.iter().any(|f| f.id.starts_with("TEST-FAIL-")));
        assert!(findings.iter().any(|f| f.id.starts_with("TEST-SLOW-")));
    }
}
