use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuntimeEvent {
    Query {
        timestamp: String,
        duration_ms: f64,
        sql_normalized: String,
        connection: Option<String>,
        request_id: Option<String>,
    },
    Request {
        timestamp: String,
        method: String,
        route: String,
        status: u16,
        duration_ms: f64,
        memory_peak_bytes: Option<u64>,
        request_id: Option<String>,
    },
    Job {
        timestamp: String,
        job_class: String,
        queue: Option<String>,
        status: String,
        duration_ms: Option<f64>,
        exception: Option<String>,
        attempt: Option<u32>,
    },
}

/// Streams a bounded runtime `.jsonl` file, skipping malformed lines gracefully.
pub fn parse_runtime_jsonl(path: &Path) -> Vec<RuntimeEvent> {
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };
    let reader = BufReader::with_capacity(32 * 1024, file);
    let mut events = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<RuntimeEvent>(trimmed) {
            events.push(ev);
        }
    }

    events
}
