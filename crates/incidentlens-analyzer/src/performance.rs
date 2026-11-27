use incidentlens_core::{Confidence, Evidence, EvidenceKind, Finding, Severity};
use incidentlens_parser::RuntimeEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointStat {
    pub route: String,
    pub count: usize,
    pub avg_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub observed_requests: usize,
    pub avg_ms: Option<f64>,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub max_memory_bytes: Option<u64>,
    pub cache_hit_rate: Option<f64>,
    pub external_http_calls: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerformanceAnalysis {
    pub summary: PerformanceSummary,
    pub endpoints: Vec<EndpointStat>,
    pub findings: Vec<Finding>,
}

pub struct PerformanceAnalyzer;

impl PerformanceAnalyzer {
    pub fn analyze(events: &[RuntimeEvent], slow_endpoint_ms: f64) -> PerformanceAnalysis {
        let mut all_durations = Vec::new();
        let mut max_mem: Option<u64> = None;
        let mut by_route: HashMap<String, Vec<f64>> = HashMap::new();
        let mut cache_hits = 0usize;
        let mut cache_misses = 0usize;
        let mut external_http_calls = 0usize;
        let mut slow_http_findings = Vec::new();

        for ev in events {
            match ev {
                RuntimeEvent::Request {
                    method,
                    route,
                    duration_ms,
                    memory_peak_bytes,
                    ..
                } => {
                    all_durations.push(*duration_ms);
                    if let Some(mem) = memory_peak_bytes {
                        max_mem = Some(max_mem.map(|m| m.max(*mem)).unwrap_or(*mem));
                    }
                    by_route
                        .entry(format!("{method} {route}"))
                        .or_default()
                        .push(*duration_ms);
                }
                RuntimeEvent::Cache { hit, .. } => {
                    if *hit {
                        cache_hits += 1;
                    } else {
                        cache_misses += 1;
                    }
                }
                RuntimeEvent::HttpClient {
                    method,
                    host,
                    status,
                    duration_ms,
                    ..
                } => {
                    external_http_calls += 1;
                    if *duration_ms >= slow_endpoint_ms || *status >= 500 {
                        slow_http_findings.push(Finding {
                            id: format!("PERF-HTTP-{:03}", slow_http_findings.len() + 1),
                            module: "performance".to_string(),
                            title: format!("Slow/failing external HTTP call {method} {host} ({status}, {duration_ms:.0}ms)"),
                            severity: if *status >= 500 { Severity::High } else { Severity::Medium },
                            confidence: Confidence::High,
                            affected_component: host.clone(),
                            evidence: vec![Evidence {
                                kind: EvidenceKind::Observed,
                                source: "performance_analyzer".to_string(),
                                detail: format!("Outgoing HTTP {method} to {host} returned {status} in {duration_ms:.1}ms."),
                            }],
                            first_observed: None,
                            last_observed: None,
                            next_step: "Check third-party API latency, timeouts, and circuit-breaker/retry policies.".to_string(),
                        });
                    }
                }
                _ => {}
            }
        }

        let cache_total = cache_hits + cache_misses;
        let cache_hit_rate = if cache_total > 0 {
            Some((cache_hits as f64 / cache_total as f64) * 100.0)
        } else {
            None
        };

        if all_durations.is_empty() && cache_total == 0 && external_http_calls == 0 {
            return PerformanceAnalysis::default();
        }

        all_durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let avg = if all_durations.is_empty() {
            None
        } else {
            Some(all_durations.iter().sum::<f64>() / all_durations.len() as f64)
        };
        let summary = PerformanceSummary {
            observed_requests: all_durations.len(),
            avg_ms: avg,
            p50_ms: (!all_durations.is_empty()).then(|| percentile(&all_durations, 0.50)),
            p95_ms: (!all_durations.is_empty()).then(|| percentile(&all_durations, 0.95)),
            p99_ms: (!all_durations.is_empty()).then(|| percentile(&all_durations, 0.99)),
            max_memory_bytes: max_mem,
            cache_hit_rate,
            external_http_calls,
        };

        let mut endpoints: Vec<EndpointStat> = by_route
            .into_iter()
            .map(|(route, mut durs)| {
                durs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let count = durs.len();
                let avg_ms = durs.iter().sum::<f64>() / count as f64;
                let p95_ms = percentile(&durs, 0.95);
                let max_ms = *durs.last().unwrap_or(&0.0);
                EndpointStat {
                    route,
                    count,
                    avg_ms,
                    p95_ms,
                    max_ms,
                }
            })
            .collect();

        endpoints.sort_by(|a, b| {
            b.p95_ms
                .partial_cmp(&a.p95_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut findings = Vec::new();
        for (i, ep) in endpoints.iter().enumerate() {
            if ep.p95_ms >= slow_endpoint_ms {
                findings.push(Finding {
                    id: format!("PERF-{:03}", i + 1),
                    module: "performance".to_string(),
                    title: format!("Slow endpoint {} (P95 {:.1}ms)", ep.route, ep.p95_ms),
                    severity: if ep.p95_ms >= slow_endpoint_ms * 2.0 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    confidence: Confidence::High,
                    affected_component: ep.route.clone(),
                    evidence: vec![Evidence {
                        kind: EvidenceKind::Observed,
                        source: "performance_analyzer".to_string(),
                        detail: format!(
                            "{} request(s): avg {:.1}ms, P95 {:.1}ms, max {:.1}ms.",
                            ep.count, ep.avg_ms, ep.p95_ms, ep.max_ms
                        ),
                    }],
                    first_observed: None,
                    last_observed: None,
                    next_step: "Correlate this endpoint's request_id with database queries and external calls.".to_string(),
                });
            }
        }

        findings.extend(slow_http_findings);

        PerformanceAnalysis {
            summary,
            endpoints,
            findings,
        }
    }
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * pct).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}
