use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use std::fs;
use std::path::Path;

pub struct MigrationAnalyzer;

impl MigrationAnalyzer {
    /// Analyzes Laravel migration `up()` methods statically without executing migrations.
    /// `down()` rollback methods are intentionally excluded from destructive-op warnings.
    pub fn analyze(project_root: &Path) -> Vec<Finding> {
        let dir = project_root.join("database").join("migrations");
        let Ok(entries) = fs::read_dir(&dir) else {
            return Vec::new();
        };

        let mut findings = Vec::new();
        let mut files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("php"))
            .collect();
        files.sort();

        for (idx, path) in files.iter().enumerate() {
            let Ok(content) = fs::read_to_string(path) else {
                continue;
            };
            let fname = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("migration.php")
                .to_string();

            let up_body = extract_method_body(&content, "up");
            let scan_target = up_body.as_deref().unwrap_or(&content);

            let destructive_ops = [
                ("dropColumn", "Drops a column in up() (data loss risk)"),
                ("dropIfExists", "Drops a table in up()"),
                ("drop(", "Drops a table in up()"),
                ("renameColumn", "Renames a column in up() (zero-downtime compatibility risk)"),
            ];

            for (needle, reason) in destructive_ops {
                if scan_target.contains(needle) {
                    findings.push(Finding {
                        id: format!("MIG-DEST-{:03}", idx + 1),
                        module: "migration".to_string(),
                        title: format!("Potentially destructive operation in up(): {needle}"),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        affected_component: format!("database/migrations/{fname}"),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "migration_analyzer".to_string(),
                            detail: format!("{reason} in {fname}."),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Verify backup/rollback strategy and zero-downtime deployment ordering.".to_string(),
                    });
                    break;
                }
            }

            if content.contains("public function up") && !content.contains("public function down") {
                findings.push(Finding {
                    id: format!("MIG-DOWN-{:03}", idx + 1),
                    module: "migration".to_string(),
                    title: format!("Missing down() rollback method in {fname}"),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    affected_component: format!("database/migrations/{fname}"),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "migration_analyzer".to_string(),
                        detail: "Migration defines up() without a corresponding down() method.".to_string(),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Implement down() if rollback support is required.".to_string(),
                });
            }
        }

        findings
    }
}

/// Extracts the body of `public function <name>(...) { ... }` using brace matching.
fn extract_method_body(content: &str, method_name: &str) -> Option<String> {
    let marker = format!("function {method_name}");
    let start = content.find(&marker)?;
    let rest = &content[start..];
    let open_brace = rest.find('{')?;
    let mut depth = 0usize;
    let mut end_idx = None;

    for (i, ch) in rest[open_brace..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end_idx = Some(open_brace + i + 1);
                    break;
                }
            }
            _ => {}
        }
    }

    end_idx.map(|end| rest[open_brace..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn ignores_drop_if_exists_inside_down_method() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("database/migrations")).unwrap();
        fs::write(
            tmp.path().join("database/migrations/2026_01_01_create_orders.php"),
            "<?php\npublic function up(): void { Schema::create('orders', fn($t) => $t->id()); }\npublic function down(): void { Schema::dropIfExists('orders'); }\n",
        )
        .unwrap();

        let findings = MigrationAnalyzer::analyze(tmp.path());
        assert!(findings.is_empty(), "down() dropIfExists should not be flagged");
    }
}
