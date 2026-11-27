use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use std::fs;
use std::path::Path;

pub struct MigrationAnalyzer;

impl MigrationAnalyzer {
    /// Analyzes Laravel migration files statically without executing migrations or modifying schemas.
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

            let destructive_ops = [
                ("dropColumn", "Drops a column (data loss risk)"),
                ("dropIfExists", "Drops a table if it exists"),
                ("drop(", "Drops a table"),
                ("renameColumn", "Renames a column (potential compatibility risk)"),
            ];

            for (needle, reason) in destructive_ops {
                if content.contains(needle) {
                    findings.push(Finding {
                        id: format!("MIG-DEST-{:03}", idx + 1),
                        module: "migration".to_string(),
                        title: format!("Potentially destructive migration operation: {needle}"),
                        severity: Severity::Medium,
                        confidence: Confidence::High,
                        affected_component: format!("database/migrations/{fname}"),
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "migration_analyzer".to_string(),
                            detail: format!("{reason} detected in {fname}."),
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
