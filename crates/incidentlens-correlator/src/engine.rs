use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Incident, Severity};
use incidentlens_parser::RuntimeEvent;
use std::collections::HashMap;

pub struct CorrelationInput<'a> {
    pub findings: &'a [Finding],
    pub runtime_events: &'a [RuntimeEvent],
}

pub trait CorrelationRule {
    fn evaluate(&self, input: &CorrelationInput<'_>) -> Vec<Incident>;
}

pub struct CorrelationEngine {
    rules: Vec<Box<dyn CorrelationRule>>,
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            rules: vec![
                Box::new(SlowRequestNPlusOneRule),
                Box::new(ErrorAndQueueBurstRule),
            ],
        }
    }

    pub fn correlate(&self, input: &CorrelationInput<'_>) -> Vec<Incident> {
        let mut incidents = Vec::new();
        for rule in &self.rules {
            incidents.extend(rule.evaluate(input));
        }
        incidents
    }
}

struct SlowRequestNPlusOneRule;

impl CorrelationRule for SlowRequestNPlusOneRule {
    fn evaluate(&self, input: &CorrelationInput<'_>) -> Vec<Incident> {
        let mut requests_by_id: HashMap<&str, (&str, &str, f64)> = HashMap::new();
        let mut queries_by_req_sql: HashMap<(&str, &str), (usize, f64)> = HashMap::new();

        for ev in input.runtime_events {
            match ev {
                RuntimeEvent::Request {
                    request_id: Some(req_id),
                    method,
                    route,
                    duration_ms,
                    ..
                } if *duration_ms >= 800.0 => {
                    requests_by_id.insert(req_id.as_str(), (method.as_str(), route.as_str(), *duration_ms));
                }
                RuntimeEvent::Query {
                    request_id: Some(req_id),
                    sql_normalized,
                    duration_ms,
                    ..
                } => {
                    let entry = queries_by_req_sql
                        .entry((req_id.as_str(), sql_normalized.as_str()))
                        .or_insert((0, 0.0));
                    entry.0 += 1;
                    entry.1 += *duration_ms;
                }
                _ => {}
            }
        }

        let mut incidents = Vec::new();
        let mut idx = 0usize;
        for ((req_id, sql), (count, total_q_ms)) in queries_by_req_sql {
            if count >= 5 {
                if let Some((method, route, req_ms)) = requests_by_id.get(req_id) {
                    idx += 1;
                    incidents.push(Incident {
                        id: format!("INC-N1-{:03}", idx),
                        title: format!("{method} {route} performance degradation"),
                        severity: if *req_ms >= 2000.0 || count >= 20 {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        confidence: Confidence::Medium,
                        evidence: vec![
                            Evidence {
                                kind: EvidenceKind::Observed,
                                source: "performance_analyzer".to_string(),
                                detail: format!("Request {req_id} ({method} {route}) took {req_ms:.1}ms."),
                            },
                            Evidence {
                                kind: EvidenceKind::Observed,
                                source: "database_analyzer".to_string(),
                                detail: format!(
                                    "Query `{sql}` executed {count} times in the same request ({total_q_ms:.1}ms total)."
                                ),
                            },
                            Evidence {
                                kind: EvidenceKind::Correlated,
                                source: "correlation_engine".to_string(),
                                detail: "Query repetition and endpoint latency are correlated via request_id, though exact source-code cause is not yet proven.".to_string(),
                            },
                        ],
                        possible_root_cause: "Potential N+1 query regression on Eloquent relationship loading.".to_string(),
                        next_step: "Inspect Eloquent relationship eager loading (`with(...)`) on the controller/service handling this route.".to_string(),
                    });
                }
            }
        }
        incidents
    }
}

struct ErrorAndQueueBurstRule;

impl CorrelationRule for ErrorAndQueueBurstRule {
    fn evaluate(&self, input: &CorrelationInput<'_>) -> Vec<Incident> {
        let log_errors: Vec<&Finding> = input
            .findings
            .iter()
            .filter(|f| f.module == "logs" && matches!(f.severity, Severity::High | Severity::Critical))
            .collect();
        let queue_failures: Vec<&Finding> = input
            .findings
            .iter()
            .filter(|f| f.module == "queue")
            .collect();

        if log_errors.is_empty() || queue_failures.is_empty() {
            return Vec::new();
        }

        vec![Incident {
            id: "INC-QUE-001".to_string(),
            title: "Correlated application errors and queue job failures".to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            evidence: vec![
                Evidence {
                    kind: EvidenceKind::Observed,
                    source: "log_analyzer".to_string(),
                    detail: format!("{} high/critical log error group(s) detected.", log_errors.len()),
                },
                Evidence {
                    kind: EvidenceKind::Observed,
                    source: "queue_analyzer".to_string(),
                    detail: format!("{} queue failure finding(s) detected.", queue_failures.len()),
                },
                Evidence {
                    kind: EvidenceKind::Hypothesis,
                    source: "correlation_engine".to_string(),
                    detail: "Shared downstream dependency or exception may be impacting both web and queue workers.".to_string(),
                },
            ],
            possible_root_cause: "Shared service/database failure or unhandled exception across HTTP and queue workers.".to_string(),
            next_step: "Compare timestamps between failed queue jobs and application error logs.".to_string(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlates_slow_request_with_repeated_queries() {
        let mut events = vec![RuntimeEvent::Request {
            timestamp: "2026-11-27T10:00:00Z".into(),
            method: "GET".into(),
            route: "/checkout".into(),
            status: 200,
            duration_ms: 2100.0,
            memory_peak_bytes: Some(33_554_432),
            request_id: Some("req_99".into()),
        }];
        for _ in 0..10 {
            events.push(RuntimeEvent::Query {
                timestamp: "2026-11-27T10:00:00Z".into(),
                duration_ms: 120.0,
                sql_normalized: "select * from order_items where order_id = ?".into(),
                connection: Some("mysql".into()),
                request_id: Some("req_99".into()),
                location: None,
            });
        }

        let engine = CorrelationEngine::new();
        let incidents = engine.correlate(&CorrelationInput {
            findings: &[],
            runtime_events: &events,
        });
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].confidence, Confidence::Medium);
        assert!(incidents[0].title.contains("/checkout"));
    }
}
