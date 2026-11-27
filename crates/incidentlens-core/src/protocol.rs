use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current PHP-to-Rust protocol version.
pub const PROTOCOL_VERSION: &str = "1.0";

/// Current Rust diagnostic engine version.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Checks whether a requested protocol version is compatible with this engine.
/// Major version must be `1`.
pub fn is_protocol_compatible(version: &str) -> bool {
    let mut parts = version.trim().split('.');
    match (parts.next(), parts.next()) {
        (Some("1"), Some(minor)) => minor.parse::<u32>().is_ok(),
        _ => false,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolInfo {
    pub protocol_version: String,
    pub engine_version: String,
    pub supported_protocols: Vec<String>,
}

impl Default for ProtocolInfo {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            engine_version: ENGINE_VERSION.to_string(),
            supported_protocols: vec![PROTOCOL_VERSION.to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RequestEnvelope {
    pub protocol_version: String,
    pub command: String,
    pub project: Option<ProjectMetadata>,
    pub options: RequestOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ProjectMetadata {
    pub root: String,
    pub name: Option<String>,
    pub laravel_version: Option<String>,
    pub php_version: Option<String>,
    pub environment: Option<String>,
    pub debug: Option<bool>,
    pub drivers: ProjectDrivers,
    pub log_paths: Vec<String>,
    pub config_flags: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct ProjectDrivers {
    pub cache: Option<String>,
    pub queue: Option<String>,
    pub database: Option<String>,
    pub session: Option<String>,
    pub log: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RequestOptions {
    pub since: Option<String>,
    pub limit: Option<usize>,
    pub modules: Vec<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TelemetrySummary {
    pub health_score: u8,
    pub log_throughput_mb_s: Option<f64>,
    pub log_timeline: Vec<u64>,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub cache_hit_rate: Option<f64>,
    pub total_queries: usize,
    pub slow_queries: usize,
    pub n_plus_one_candidates: usize,
    pub failed_jobs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub protocol_version: String,
    pub engine_version: String,
    pub status: String,
    pub summary: SummaryCounts,
    #[serde(default)]
    pub telemetry: TelemetrySummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<ProjectReport>,
    pub findings: Vec<Finding>,
    pub incidents: Vec<Incident>,
    pub errors: Vec<String>,
}

impl ResponseEnvelope {
    pub fn ok(project: Option<ProjectReport>, findings: Vec<Finding>) -> Self {
        let mut summary = SummaryCounts::default();
        let mut penalty: u32 = 0;
        for f in &findings {
            match f.severity {
                Severity::Critical => {
                    summary.errors += 1;
                    penalty += 25;
                }
                Severity::High => {
                    summary.errors += 1;
                    penalty += 15;
                }
                Severity::Medium => {
                    summary.warnings += 1;
                    penalty += 7;
                }
                Severity::Low => {
                    summary.warnings += 1;
                    penalty += 3;
                }
                Severity::Info => {}
            }
            if f.module == "performance" {
                summary.performance += 1;
            } else if f.module == "security" {
                summary.security += 1;
            }
        }

        let health_score = 100u8.saturating_sub(penalty.min(100) as u8);

        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            engine_version: ENGINE_VERSION.to_string(),
            status: "ok".to_string(),
            summary,
            telemetry: TelemetrySummary {
                health_score,
                ..Default::default()
            },
            project,
            findings,
            incidents: Vec::new(),
            errors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SummaryCounts {
    pub errors: usize,
    pub warnings: usize,
    pub performance: usize,
    pub security: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectReport {
    pub root: String,
    pub name: String,
    pub is_laravel_project: bool,
    pub laravel_version: Option<String>,
    pub php_constraint: Option<String>,
    pub php_version: Option<String>,
    pub environment: Option<String>,
    pub debug: Option<bool>,
    pub has_env_file: bool,
    pub has_composer_lock: bool,
    pub has_artisan: bool,
    pub log_files_count: usize,
    pub packages_count: usize,
    pub drivers: ProjectDrivers,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceKind {
    Observed,
    Correlated,
    Hypothesis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub module: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub affected_component: String,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_observed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_observed: Option<String>,
    pub next_step: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub possible_root_cause: String,
    pub next_step: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_compatibility_checks_major_version() {
        assert!(is_protocol_compatible("1.0"));
        assert!(is_protocol_compatible("1.2"));
        assert!(!is_protocol_compatible("2.0"));
        assert!(!is_protocol_compatible("0.9"));
        assert!(!is_protocol_compatible("invalid"));
    }

    #[test]
    fn request_envelope_ignores_unknown_fields() {
        let json = r#"{"protocol_version":"1.0","command":"scan","future_field":123}"#;
        let parsed: RequestEnvelope = serde_json::from_str(json).expect("should parse");
        assert_eq!(parsed.protocol_version, "1.0");
        assert_eq!(parsed.command, "scan");
    }
}
