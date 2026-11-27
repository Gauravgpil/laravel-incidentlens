use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static ROUTE_RE: OnceLock<Regex> = OnceLock::new();
static EMPTY_CATCH_RE: OnceLock<Regex> = OnceLock::new();

pub struct CodeAnalyzer;

impl CodeAnalyzer {
    /// Static Laravel codebase intelligence: Routes, Controllers, Models, and Exception handling.
    pub fn analyze(project_root: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(analyze_routes(project_root));
        findings.extend(analyze_controllers(project_root));
        findings.extend(analyze_models(project_root));
        findings.extend(analyze_exceptions(project_root));
        findings
    }
}

fn analyze_routes(root: &Path) -> Vec<Finding> {
    let routes_dir = root.join("routes");
    let route_re = ROUTE_RE.get_or_init(|| {
        Regex::new(r#"Route::(get|post|put|patch|delete|any)\s*\(\s*['"]([^'"]+)['"]"#)
            .expect("valid route regex")
    });

    let mut seen: HashMap<(String, String), Vec<String>> = HashMap::new();
    for file in collect_php_files(&routes_dir) {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        let rel = rel_path(root, &file);
        for (idx, line) in content.lines().enumerate() {
            if let Some(caps) = route_re.captures(line) {
                let method = caps[1].to_ascii_uppercase();
                let uri = caps[2].to_string();
                seen.entry((method, uri))
                    .or_default()
                    .push(format!("{rel}:{}", idx + 1));
            }
        }
    }

    let mut findings = Vec::new();
    for ((method, uri), locs) in seen {
        if locs.len() > 1 {
            findings.push(Finding {
                id: format!("CODE-RTE-{}", findings.len() + 1),
                module: "code".to_string(),
                title: format!("Duplicate route definition: {method} {uri} ({}x)", locs.len()),
                severity: Severity::Medium,
                confidence: Confidence::High,
                affected_component: locs.join(", "),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "code_analyzer".to_string(),
                    detail: format!("Route {method} '{uri}' appears at: {}", locs.join(", ")),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Consolidate duplicate route definitions so the intended handler is unambiguous.".to_string(),
            });
        }
    }
    findings
}

fn analyze_controllers(root: &Path) -> Vec<Finding> {
    let ctrl_dir = root.join("app").join("Http").join("Controllers");
    let mut findings = Vec::new();

    for file in collect_php_files(&ctrl_dir) {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        let lines = content.lines().count();
        let methods = content.matches("public function ").count();
        let rel = rel_path(root, &file);

        if lines > 300 || methods > 10 {
            findings.push(Finding {
                id: format!("CODE-CTL-{}", findings.len() + 1),
                module: "code".to_string(),
                title: format!("Oversized controller: {rel} ({lines} lines, {methods} public methods)"),
                severity: Severity::Low,
                confidence: Confidence::High,
                affected_component: rel,
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "code_analyzer".to_string(),
                    detail: format!("Controller has {lines} lines and {methods} public methods."),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Consider extracting business logic into dedicated Service or Action classes.".to_string(),
            });
        }
    }
    findings
}

fn analyze_models(root: &Path) -> Vec<Finding> {
    let models_dir = root.join("app").join("Models");
    let mut findings = Vec::new();

    for file in collect_php_files(&models_dir) {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        if !content.contains("extends Model") && !content.contains("extends Authenticatable") {
            continue;
        }
        let rel = rel_path(root, &file);
        if content.contains("$guarded = []") {
            findings.push(Finding {
                id: format!("CODE-MDL-{}", findings.len() + 1),
                module: "code".to_string(),
                title: format!("Unrestricted mass assignment ($guarded = []) in {rel}"),
                severity: Severity::Medium,
                confidence: Confidence::High,
                affected_component: rel,
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "code_analyzer".to_string(),
                    detail: "Model sets `protected $guarded = []`, allowing all attributes to be mass-assigned if unvalidated input is passed.".to_string(),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Define an explicit `$fillable` allowlist or ensure all callers use `$request->validated()`.".to_string(),
            });
        }
    }
    findings
}

fn analyze_exceptions(root: &Path) -> Vec<Finding> {
    let app_dir = root.join("app");
    let catch_re = EMPTY_CATCH_RE.get_or_init(|| {
        Regex::new(r"catch\s*\([^)]+\)\s*\{\s*\}").expect("valid empty catch regex")
    });
    let mut findings = Vec::new();

    for file in collect_php_files(&app_dir) {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        if catch_re.is_match(&content) {
            let rel = rel_path(root, &file);
            findings.push(Finding {
                id: format!("CODE-EXC-{}", findings.len() + 1),
                module: "code".to_string(),
                title: format!("Swallowed exception (empty catch block) in {rel}"),
                severity: Severity::Medium,
                confidence: Confidence::High,
                affected_component: rel,
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "code_analyzer".to_string(),
                    detail: "An empty `catch (...) {}` block silently discards exceptions without logging or rethrowing.".to_string(),
                }],
                first_observed: None,
                last_observed: None,
                next_step: "Log the exception with context or rethrow it so failures are observable.".to_string(),
            });
        }
    }
    findings
}

pub fn collect_php_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_dir() {
            out.extend(collect_php_files(&p));
        } else if p.extension().and_then(|e| e.to_str()) == Some("php") {
            out.push(p);
        }
    }
    out.sort();
    out
}

fn rel_path(root: &Path, full: &Path) -> String {
    full.strip_prefix(root)
        .unwrap_or(full)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn detects_duplicate_routes_unguarded_models_and_empty_catch() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("routes")).unwrap();
        fs::create_dir_all(tmp.path().join("app/Models")).unwrap();
        fs::create_dir_all(tmp.path().join("app/Services")).unwrap();

        fs::write(
            tmp.path().join("routes/web.php"),
            "<?php\nRoute::get('/orders', [OrderController::class, 'index']);\nRoute::get('/orders', [OrderController::class, 'list']);\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("app/Models/Order.php"),
            "<?php\nclass Order extends Model { protected $guarded = []; }\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("app/Services/Pay.php"),
            "<?php\ntry { work(); } catch (\\Throwable $e) { }\n",
        )
        .unwrap();

        let findings = CodeAnalyzer::analyze(tmp.path());
        assert!(findings.iter().any(|f| f.id.starts_with("CODE-RTE-")));
        assert!(findings.iter().any(|f| f.id.starts_with("CODE-MDL-")));
        assert!(findings.iter().any(|f| f.id.starts_with("CODE-EXC-")));
    }
}
