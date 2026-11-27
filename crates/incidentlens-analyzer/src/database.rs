use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use incidentlens_parser::{LogGroup, RuntimeEvent};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryFingerprintStat {
    pub fingerprint: String,
    pub sql_normalized: String,
    pub count: usize,
    pub total_duration_ms: f64,
    pub max_duration_ms: f64,
    pub avg_duration_ms: f64,
    pub max_per_request: usize,
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
        let mut total_queries = 0usize;
        let mut slow_queries_count = 0usize;

        for ev in events {
            if let RuntimeEvent::Query {
                duration_ms,
                sql_normalized,
                request_id,
                ..
            } = ev
            {
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
                });
                stat.count += 1;
                stat.total_duration_ms += *duration_ms;
                if *duration_ms > stat.max_duration_ms {
                    stat.max_duration_ms = *duration_ms;
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
                    affected_component: stat.sql_normalized.clone(),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "database_analyzer".to_string(),
                        detail: format!(
                            "Query fingerprint {} repeated {} times within the same request_id.",
                            stat.fingerprint, stat.max_per_request
                        ),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Check Eloquent eager loading (`with(...)`) on the code path executing this query.".to_string(),
                });
            }
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

    #[test]
    fn detects_slow_and_n_plus_one_queries() {
        let events: Vec<RuntimeEvent> = (0..6)
            .map(|_| RuntimeEvent::Query {
                timestamp: "2026-11-27T10:00:00Z".into(),
                duration_ms: 600.0,
                sql_normalized: "select * from items where order_id = ?".into(),
                connection: Some("mysql".into()),
                request_id: Some("req_1".into()),
            })
            .collect();

        let analysis = DatabaseAnalyzer::analyze(&events, &[], 500.0);
        assert_eq!(analysis.total_queries, 6);
        assert_eq!(analysis.slow_queries_count, 6);
        assert_eq!(analysis.n_plus_one_candidates, 1);
        assert!(analysis.findings.iter().any(|f| f.id.starts_with("DB-N1-")));
    }
}
