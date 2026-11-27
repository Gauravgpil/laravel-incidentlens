use crate::code::collect_php_files;
use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use incidentlens_parser::{LogGroup, RuntimeEvent};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

static LOOP_QUERY_RE: OnceLock<Regex> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryFingerprintStat {
    pub fingerprint: String,
    pub sql_normalized: String,
    pub count: usize,
    pub total_duration_ms: f64,
    pub max_duration_ms: f64,
    pub avg_duration_ms: f64,
    pub max_per_request: usize,
    #[serde(default)]
    pub call_sites: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatabaseAnalysis {
    pub total_queries: usize,
    pub slow_queries_count: usize,
    pub n_plus_one_candidates: usize,
    pub fingerprints: Vec<QueryFingerprintStat>,
    pub findings: Vec<Finding>,
}

pub struct DatabaseAnalyzer;

impl DatabaseAnalyzer {
    pub fn analyze(
        events: &[RuntimeEvent],
        log_groups: &[LogGroup],
        slow_threshold_ms: f64,
    ) -> DatabaseAnalysis {
        let mut by_fp: HashMap<String, QueryFingerprintStat> = HashMap::new();
        let mut per_request: HashMap<(String, String), usize> = HashMap::new();
        let mut lazy_violations: HashMap<(String, String), (usize, Option<String>)> = HashMap::new();
        let mut total_queries = 0usize;
        let mut slow_queries_count = 0usize;

        for ev in events {
            match ev {
                RuntimeEvent::Query {
                    duration_ms,
                    sql_normalized,
                    request_id,
                    location,
                    ..
                } => {
                    total_queries += 1;
                    if *duration_ms >= slow_threshold_ms {
                        slow_queries_count += 1;
                    }
                    let fp = fingerprint_sql(sql_normalized);
                    let stat = by_fp.entry(fp.clone()).or_insert_with(|| QueryFingerprintStat {
                        fingerprint: fp.clone(),
                        sql_normalized: sql_normalized.clone(),
                        count: 0,
                        total_duration_ms: 0.0,
                        max_duration_ms: 0.0,
                        avg_duration_ms: 0.0,
                        max_per_request: 0,
                        call_sites: Vec::new(),
                    });
                    stat.count += 1;
                    stat.total_duration_ms += *duration_ms;
                    if *duration_ms > stat.max_duration_ms {
                        stat.max_duration_ms = *duration_ms;
                    }
                    if let Some(loc) = location {
                        if stat.call_sites.len() < 5 && !stat.call_sites.contains(loc) {
                            stat.call_sites.push(loc.clone());
                        }
                    }
                    if let Some(req_id) = request_id {
                        let count = per_request
                            .entry((req_id.clone(), fp))
                            .and_modify(|c| *c += 1)
                            .or_insert(1);
                        if *count > stat.max_per_request {
                            stat.max_per_request = *count;
                        }
                    }
                }
                RuntimeEvent::LazyLoading {
                    model,
                    relation,
                    location,
                    ..
                } => {
                    let entry = lazy_violations
                        .entry((model.clone(), relation.clone()))
                        .or_insert((0, location.clone()));
                    entry.0 += 1;
                    if entry.1.is_none() {
                        entry.1 = location.clone();
                    }
                }
                _ => {}
            }
        }

        let mut fingerprints: Vec<QueryFingerprintStat> = by_fp
            .into_values()
            .map(|mut s| {
                s.avg_duration_ms = if s.count > 0 {
                    s.total_duration_ms / s.count as f64
                } else {
                    0.0
                };
                s
            })
            .collect();

        fingerprints.sort_by(|a, b| {
            b.total_duration_ms
                .partial_cmp(&a.total_duration_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut findings = Vec::new();
        let mut n_plus_one_candidates = 0usize;

        for (i, stat) in fingerprints.iter().enumerate() {
            if stat.max_duration_ms >= slow_threshold_ms {
                findings.push(Finding {
                    id: format!("DB-SLOW-{:03}", i + 1),
                    module: "database".to_string(),
                    title: format!(
                        "Slow query fingerprint ({:.1}ms max, {}x)",
                        stat.max_duration_ms, stat.count
                    ),
                    severity: if stat.max_duration_ms >= slow_threshold_ms * 3.0 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    confidence: Confidence::High,
                    affected_component: stat.sql_normalized.clone(),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "database_analyzer".to_string(),
                        detail: format!(
                            "Fingerprint {} executed {} times (avg {:.1}ms, max {:.1}ms).",
                            stat.fingerprint, stat.count, stat.avg_duration_ms, stat.max_duration_ms
                        ),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Inspect query execution plan manually (opt-in EXPLAIN) and verify table indexes.".to_string(),
                });
            }

            if stat.max_per_request >= 5 {
                n_plus_one_candidates += 1;
                let mut evidence = vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "database_analyzer".to_string(),
                    detail: format!(
                        "Query fingerprint {} repeated {} times within the same request_id.",
                        stat.fingerprint, stat.max_per_request
                    ),
                }];
                if !stat.call_sites.is_empty() {
                    evidence.push(Evidence {
                        kind: EvidenceKind::Observed,
                        source: "call_site".to_string(),
                        detail: format!("Observed PHP call-site(s): {}", stat.call_sites.join(", ")),
                    });
                }
                findings.push(Finding {
                    id: format!("DB-N1-{:03}", n_plus_one_candidates),
                    module: "database".to_string(),
                    title: format!(
                        "Potential N+1 query pattern ({}x in a single request)",
                        stat.max_per_request
                    ),
                    severity: if stat.max_per_request >= 20 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    confidence: Confidence::Medium,
                    affected_component: if let Some(first_site) = stat.call_sites.first() {
                        format!("{first_site} — {}", stat.sql_normalized)
                    } else {
                        stat.sql_normalized.clone()
                    },
                    evidence,
                    first_observed: None,
                    last_observed: None,
                    next_step: "Use Eloquent eager loading (`with(...)`) or `withCount(...)` on the relation.".to_string(),
                });
            }
        }

        // LazyLoadingViolation runtime events
        for ((model, relation), (count, loc)) in lazy_violations {
            n_plus_one_candidates += 1;
            findings.push(Finding {
                id: format!("DB-LAZY-{:03}", n_plus_one_candidates),
                module: "database".to_string(),
                title: format!("Lazy-loading violation: {model}->{relation} ({count}x)"),
                severity: Severity::High,
                confidence: Confidence::High,
                affected_component: loc.clone().unwrap_or_else(|| format!("{model}::{relation}")),
                evidence: vec![Evidence {
                    kind: EvidenceKind::Observed,
                    source: "lazy_loading_hook".to_string(),
                    detail: format!(
                        "Laravel reported {count} lazy-loading violation(s) for `{model}::{relation}`."
                    ),
                }],
                first_observed: None,
                last_observed: None,
                next_step: format!("Add `->with('{relation}')` to the {model} query."),
            });
        }

        // Correlate SQLSTATE / connection errors from logs
        for (idx, grp) in log_groups.iter().enumerate() {
            let lower = grp.sample_message.to_ascii_lowercase();
            if lower.contains("sqlstate") || lower.contains("queryexception") || lower.contains("deadlock") {
                findings.push(Finding {
                    id: format!("DB-LOG-{:03}", idx + 1),
                    module: "database".to_string(),
                    title: format!("Database error in logs ({}x)", grp.count),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    affected_component: grp.location.clone().unwrap_or_else(|| "database".to_string()),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "log_analyzer".to_string(),
                        detail: grp.normalized_message.clone(),
                    }],
                    first_observed: grp.first_seen.map(|d| d.to_rfc3339()),
                    last_observed: grp.last_seen.map(|d| d.to_rfc3339()),
                    next_step: "Check database connectivity, constraints, and transaction retry handling.".to_string(),
                });
            }
        }

        DatabaseAnalysis {
            total_queries,
            slow_queries_count,
            n_plus_one_candidates,
            fingerprints,
            findings,
        }
    }

    /// Static Laravel N+1 & Eloquent best-practice checks (works even with RuntimeCollector off).
    pub fn analyze_static(project_root: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Check AppServiceProvider for Model::preventLazyLoading()
        let app_provider = project_root.join("app/Providers/AppServiceProvider.php");
        if let Ok(content) = fs::read_to_string(&app_provider) {
            if !content.contains("preventLazyLoading") {
                findings.push(Finding {
                    id: "DB-PREV-001".to_string(),
                    module: "database".to_string(),
                    title: "Model::preventLazyLoading() is not configured in AppServiceProvider".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    affected_component: "app/Providers/AppServiceProvider.php".to_string(),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "database_static".to_string(),
                        detail: "AppServiceProvider does not call `Model::preventLazyLoading(! app()->isProduction())`.".to_string(),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Add `Model::preventLazyLoading(! app()->isProduction());` in AppServiceProvider::boot() to catch N+1s in local/CI.".to_string(),
                });
            }
        }

        // 2. Scan app/ for query-inside-foreach-loop candidates
        let loop_re = LOOP_QUERY_RE.get_or_init(|| {
            Regex::new(r"(?s)foreach\s*\([^)]+\)\s*\{[^}]{0,600}(?:::(?:find|where|first|count)|DB::)")
                .expect("valid loop query regex")
        });
        let mut flagged_files: BTreeSet<String> = BTreeSet::new();

        for file in collect_php_files(&project_root.join("app")) {
            let Ok(content) = fs::read_to_string(&file) else {
                continue;
            };
            if loop_re.is_match(&content) {
                let rel = file
                    .strip_prefix(project_root)
                    .unwrap_or(&file)
                    .display()
                    .to_string();
                if flagged_files.insert(rel.clone()) {
                    findings.push(Finding {
                        id: format!("DB-LOOP-{:03}", flagged_files.len()),
                        module: "database".to_string(),
                        title: format!("Potential database query inside foreach loop in {rel}"),
                        severity: Severity::Medium,
                        confidence: Confidence::Medium,
                        affected_component: rel,
                        evidence: vec![Evidence {
                            kind: EvidenceKind::Observed,
                            source: "database_static".to_string(),
                            detail: "Static scan detected Eloquent/DB query call inside a `foreach` block.".to_string(),
                        }],
                        first_observed: None,
                        last_observed: None,
                        next_step: "Batch load records before the loop (`whereIn(...)` or `with(...)`) to avoid N+1 queries.".to_string(),
                    });
                }
            }
        }

        findings
    }
}

fn fingerprint_sql(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.trim().to_ascii_lowercase().as_bytes());
    let d = hasher.finalize();
    format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3], d[4], d[5])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn detects_slow_and_n_plus_one_queries_with_call_sites() {
        let events: Vec<RuntimeEvent> = (0..6)
            .map(|_| RuntimeEvent::Query {
                timestamp: "2026-11-27T10:00:00Z".into(),
                duration_ms: 600.0,
                sql_normalized: "select * from items where order_id = ?".into(),
                connection: Some("mysql".into()),
                request_id: Some("req_1".into()),
                location: Some("app/Http/Controllers/OrderController.php:48".into()),
            })
            .collect();

        let analysis = DatabaseAnalyzer::analyze(&events, &[], 500.0);
        assert_eq!(analysis.total_queries, 6);
        assert_eq!(analysis.slow_queries_count, 6);
        assert_eq!(analysis.n_plus_one_candidates, 1);
        let n1 = analysis
            .findings
            .iter()
            .find(|f| f.id.starts_with("DB-N1-"))
            .unwrap();
        assert!(n1.affected_component.contains("OrderController.php:48"));
    }

    #[test]
    fn detects_static_loop_query_and_missing_prevent_lazy_loading() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("app/Providers")).unwrap();
        fs::create_dir_all(tmp.path().join("app/Services")).unwrap();

        fs::write(
            tmp.path().join("app/Providers/AppServiceProvider.php"),
            "<?php\nclass AppServiceProvider { public function boot() {} }\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("app/Services/ReportService.php"),
            "<?php\nforeach ($ids as $id) { $u = User::where('id', $id)->first(); }\n",
        )
        .unwrap();

        let findings = DatabaseAnalyzer::analyze_static(tmp.path());
        assert!(findings.iter().any(|f| f.id == "DB-PREV-001"));
        assert!(findings.iter().any(|f| f.id.starts_with("DB-LOOP-")));
    }
}
