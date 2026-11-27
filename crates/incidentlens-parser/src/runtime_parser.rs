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
        #[serde(default)]
        location: Option<String>,
    },
    LazyLoading {
        timestamp: String,
        model: String,
        relation: String,
        #[serde(default)]
        location: Option<String>,
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
    Cache {
        timestamp: String,
        hit: bool,
        store: Option<String>,
    },
    HttpClient {
        timestamp: String,
        method: String,
        host: String,
        status: u16,
        duration_ms: f64,
        request_id: Option<String>,
    },
}

/// Streams a bounded runtime `.jsonl` file in a single pass with O(1) event memory.
pub fn stream_runtime_jsonl<F>(path: &Path, mut visitor: F)
where
    F: FnMut(RuntimeEvent),
{
    let Ok(file) = File::open(path) else {
        return;
    };
    let mut reader = BufReader::with_capacity(32 * 1024, file);
    let mut line = String::new();

    loop {
        line.clear();
        let Ok(n) = reader.read_line(&mut line) else {
            break;
        };
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<RuntimeEvent>(trimmed) {
            visitor(ev);
        }
    }
}

/// Convenience helper returning parsed events (used by tests and small datasets).
pub fn parse_runtime_jsonl(path: &Path) -> Vec<RuntimeEvent> {
    let mut events = Vec::new();
    stream_runtime_jsonl(path, |ev| events.push(ev));
    events
}
