use crate::fingerprint::fingerprint_error;
use crate::normalizer::normalize_message;
use chrono::{DateTime, NaiveDateTime, Utc};
use incidentlens_core::redaction::redact_inline_secrets;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use thiserror::Error;

const MAX_STACK_FRAMES_PER_ENTRY: usize = 32;
const MAX_LINE_BYTES: usize = 256 * 1024;
const MAX_UNIQUE_GROUPS: usize = 50_000;
const DEFAULT_SAMPLE_ENTRY_LIMIT: usize = 1_000;

#[derive(Debug, Error)]
pub enum ParserError {
    #[error("failed to read log file '{0}': {1}")]
    Io(String, std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl LogLevel {
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "notice" => Some(Self::Notice),
            "warning" | "warn" => Some(Self::Warning),
            "error" | "err" => Some(Self::Error),
            "critical" | "crit" => Some(Self::Critical),
            "alert" => Some(Self::Alert),
            "emergency" | "emerg" => Some(Self::Emergency),
            _ => None,
        }
    }

    pub fn is_error_or_above(self) -> bool {
        self >= Self::Error
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: Option<DateTime<Utc>>,
    pub raw_timestamp: Option<String>,
    pub environment: Option<String>,
    pub level: LogLevel,
    pub message: String,
    pub exception_class: Option<String>,
    pub location: Option<String>,
    pub stack_trace: Vec<String>,
    pub fingerprint: String,
    pub source_file: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogGroup {
    pub fingerprint: String,
    pub level: LogLevel,
    pub exception_class: Option<String>,
    pub normalized_message: String,
    pub sample_message: String,
    pub location: Option<String>,
    pub count: usize,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub sample_stack: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogParseStats {
    pub files_scanned: usize,
    pub total_lines: usize,
    pub parsed_entries: usize,
    pub malformed_lines: usize,
    pub unique_fingerprints: usize,
    pub bytes_processed: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogParseResult {
    pub stats: LogParseStats,
    pub groups: Vec<LogGroup>,
    pub entries: Vec<LogEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub min_level: Option<LogLevel>,
    pub since: Option<DateTime<Utc>>,
    pub search: Option<String>,
    pub fingerprint: Option<String>,
    pub limit: Option<usize>,
    pub max_file_size_bytes: Option<u64>,
}

static MONOLOG_RE: OnceLock<Regex> = OnceLock::new();
static EXCEPTION_CLASS_RE: OnceLock<Regex> = OnceLock::new();
static LOCATION_RE: OnceLock<Regex> = OnceLock::new();

fn monolog_re() -> &'static Regex {
    MONOLOG_RE.get_or_init(|| {
        Regex::new(r"^\[([^\]]+)\]\s+([A-Za-z0-9_.-]+)\.([A-Za-z]+):\s*(.*)$")
            .expect("valid monolog regex")
    })
}

fn exception_class_re() -> &'static Regex {
    EXCEPTION_CLASS_RE.get_or_init(|| {
        Regex::new(r"(?:[A-Za-z_][A-Za-z0-9_]*\\)+[A-Za-z_][A-Za-z0-9_]*Exception|[A-Za-z_][A-Za-z0-9_]*Error")
            .expect("valid exception class regex")
    })
}

fn location_re() -> &'static Regex {
    LOCATION_RE.get_or_init(|| {
        Regex::new(r"([A-Za-z0-9_./\\-]+\.php)(?::|\()(\d+)\)?").expect("valid location regex")
    })
}

/// Discovers `.log` files in `storage/logs` or a single file path.
pub fn discover_log_files(project_root: &Path) -> Vec<PathBuf> {
    let logs_dir = project_root.join("storage").join("logs");
    let Ok(entries) = fs::read_dir(&logs_dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|ext| ext.to_str()) == Some("log"))
        .collect();
    files.sort();
    files
}

/// Streams and parses a single Laravel/Monolog or JSONL log file with bounded memory.
pub fn parse_log_file(path: &Path, filter: &LogFilter) -> Result<LogParseResult, ParserError> {
    let meta = fs::metadata(path).map_err(|e| ParserError::Io(path.display().to_string(), e))?;
    if let Some(max_bytes) = filter.max_file_size_bytes {
        if meta.len() > max_bytes {
            return Ok(LogParseResult::default());
        }
    }

    let file = File::open(path).map_err(|e| ParserError::Io(path.display().to_string(), e))?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let source_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("laravel.log")
        .to_string();

    let mut stats = LogParseStats {
        files_scanned: 1,
        bytes_processed: meta.len(),
        ..Default::default()
    };

    let sample_cap = filter.limit.unwrap_or(DEFAULT_SAMPLE_ENTRY_LIMIT).max(1);
    let mut entries_ring: VecDeque<LogEntry> = VecDeque::with_capacity(sample_cap.min(4096));
    let mut groups_map: HashMap<String, LogGroup> = HashMap::new();
    let mut current: Option<LogEntry> = None;
    let mut line_buf = String::new();
    let mut line_no = 0usize;

    loop {
        line_buf.clear();
        let bytes_read = reader
            .read_line(&mut line_buf)
            .map_err(|e| ParserError::Io(path.display().to_string(), e))?;
        if bytes_read == 0 {
            break;
        }
        line_no += 1;
        stats.total_lines += 1;

        let line = if line_buf.len() > MAX_LINE_BYTES {
            &line_buf[..MAX_LINE_BYTES]
        } else {
            line_buf.trim_end_matches(&['\r', '\n'][..])
        };

        if line.is_empty() {
            continue;
        }

        // 1. Try JSON log line
        if line.starts_with('{') {
            if let Some(json_entry) = try_parse_json_line(line, &source_name, line_no) {
                if let Some(prev) = current.take() {
                    record_entry_bounded(prev, filter, &mut groups_map, &mut entries_ring, sample_cap);
                }
                stats.parsed_entries += 1;
                current = Some(json_entry);
                continue;
            }
        }

        // 2. Try Monolog header line
        if let Some(caps) = monolog_re().captures(line) {
            if let Some(prev) = current.take() {
                record_entry_bounded(prev, filter, &mut groups_map, &mut entries_ring, sample_cap);
            }
            let raw_ts = caps.get(1).map(|m| m.as_str().to_string());
            let ts = raw_ts.as_deref().and_then(parse_timestamp);
            let env = caps.get(2).map(|m| m.as_str().to_string());
            let level = caps
                .get(3)
                .and_then(|m| LogLevel::from_str_lossy(m.as_str()))
                .unwrap_or(LogLevel::Info);
            let raw_msg = caps.get(4).map(|m| m.as_str()).unwrap_or("");
            let message = redact_inline_secrets(raw_msg);
            let exc_cls = extract_exception_class(&message);
            let loc = extract_location(&message);
            let fp = fingerprint_error(exc_cls.as_deref(), &message, loc.as_deref());

            stats.parsed_entries += 1;
            current = Some(LogEntry {
                timestamp: ts,
                raw_timestamp: raw_ts,
                environment: env,
                level,
                message,
                exception_class: exc_cls,
                location: loc,
                stack_trace: Vec::new(),
                fingerprint: fp,
                source_file: source_name.clone(),
                line_number: line_no,
            });
            continue;
        }

        // 3. Multiline continuation / stack trace frame
        if let Some(entry) = current.as_mut() {
            if entry.stack_trace.len() < MAX_STACK_FRAMES_PER_ENTRY {
                let redacted = redact_inline_secrets(line);
                if entry.location.is_none() {
                    entry.location = extract_location(&redacted);
                    if entry.location.is_some() {
                        entry.fingerprint = fingerprint_error(
                            entry.exception_class.as_deref(),
                            &entry.message,
                            entry.location.as_deref(),
                        );
                    }
                }
                entry.stack_trace.push(redacted);
            }
        } else {
            stats.malformed_lines += 1;
        }
    }

    if let Some(prev) = current.take() {
        record_entry_bounded(prev, filter, &mut groups_map, &mut entries_ring, sample_cap);
    }

    let mut groups: Vec<LogGroup> = groups_map.into_values().collect();
    groups.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| b.level.cmp(&a.level)));
    stats.unique_fingerprints = groups.len();

    Ok(LogParseResult {
        stats,
        groups,
        entries: entries_ring.into_iter().collect(),
    })
}

/// Parses multiple log files in parallel using Rayon and merges grouped results with bounded memory.
pub fn parse_log_files_parallel(
    paths: &[PathBuf],
    filter: &LogFilter,
) -> Result<LogParseResult, ParserError> {
    let per_file: Vec<Result<LogParseResult, ParserError>> =
        paths.par_iter().map(|p| parse_log_file(p, filter)).collect();

    let mut combined_stats = LogParseStats::default();
    let mut merged_groups: HashMap<String, LogGroup> = HashMap::new();
    let mut all_entries = Vec::new();

    for res in per_file {
        let part = res?;
        combined_stats.files_scanned += part.stats.files_scanned;
        combined_stats.total_lines += part.stats.total_lines;
        combined_stats.parsed_entries += part.stats.parsed_entries;
        combined_stats.malformed_lines += part.stats.malformed_lines;
        combined_stats.bytes_processed += part.stats.bytes_processed;

        for g in part.groups {
            merge_log_group(&mut merged_groups, g);
        }
        all_entries.extend(part.entries);
    }

    all_entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    all_entries.truncate(filter.limit.unwrap_or(DEFAULT_SAMPLE_ENTRY_LIMIT));

    let mut groups: Vec<LogGroup> = merged_groups.into_values().collect();
    groups.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| b.level.cmp(&a.level)));
    combined_stats.unique_fingerprints = groups.len();

    Ok(LogParseResult {
        stats: combined_stats,
        groups,
        entries: all_entries,
    })
}

fn record_entry_bounded(
    entry: LogEntry,
    filter: &LogFilter,
    groups_map: &mut HashMap<String, LogGroup>,
    entries_ring: &mut VecDeque<LogEntry>,
    sample_cap: usize,
) {
    if !matches_filter(&entry, filter) {
        return;
    }

    let fp = if groups_map.contains_key(&entry.fingerprint) || groups_map.len() < MAX_UNIQUE_GROUPS {
        entry.fingerprint.clone()
    } else {
        "__overflow__".to_string()
    };

    let grp = groups_map.entry(fp.clone()).or_insert_with(|| LogGroup {
        fingerprint: fp,
        level: entry.level,
        exception_class: entry.exception_class.clone(),
        normalized_message: normalize_message(&entry.message),
        sample_message: entry.message.clone(),
        location: entry.location.clone(),
        count: 0,
        first_seen: entry.timestamp,
        last_seen: entry.timestamp,
        sample_stack: entry.stack_trace.clone(),
    });
    grp.count += 1;
    if entry.level > grp.level {
        grp.level = entry.level;
    }
    if let Some(ts) = entry.timestamp {
        grp.first_seen = Some(match grp.first_seen {
            Some(prev) => prev.min(ts),
            None => ts,
        });
        grp.last_seen = Some(match grp.last_seen {
            Some(prev) => prev.max(ts),
            None => ts,
        });
    }

    if entries_ring.len() >= sample_cap {
        entries_ring.pop_front();
    }
    entries_ring.push_back(entry);
}

fn merge_log_group(map: &mut HashMap<String, LogGroup>, g: LogGroup) {
    let key = if map.contains_key(&g.fingerprint) || map.len() < MAX_UNIQUE_GROUPS {
        g.fingerprint.clone()
    } else {
        "__overflow__".to_string()
    };
    if let Some(existing) = map.get_mut(&key) {
        existing.count += g.count;
        if g.level > existing.level {
            existing.level = g.level;
        }
        if let Some(ts) = g.first_seen {
            existing.first_seen = Some(existing.first_seen.map(|p| p.min(ts)).unwrap_or(ts));
        }
        if let Some(ts) = g.last_seen {
            existing.last_seen = Some(existing.last_seen.map(|p| p.max(ts)).unwrap_or(ts));
        }
    } else {
        map.insert(key, g);
    }
}

fn matches_filter(entry: &LogEntry, filter: &LogFilter) -> bool {
    if let Some(min_lvl) = filter.min_level {
        if entry.level < min_lvl {
            return false;
        }
    }
    if let Some(since) = filter.since {
        if let Some(ts) = entry.timestamp {
            if ts < since {
                return false;
            }
        }
    }
    if let Some(ref fp) = filter.fingerprint {
        if &entry.fingerprint != fp {
            return false;
        }
    }
    if let Some(ref needle) = filter.search {
        let needle_lower = needle.to_ascii_lowercase();
        let in_msg = entry.message.to_ascii_lowercase().contains(&needle_lower);
        let in_exc = entry
            .exception_class
            .as_deref()
            .map(|c| c.to_ascii_lowercase().contains(&needle_lower))
            .unwrap_or(false);
        if !in_msg && !in_exc {
            return false;
        }
    }
    true
}

#[derive(Deserialize)]
struct JsonLogLine {
    message: Option<String>,
    level_name: Option<String>,
    level: Option<serde_json::Value>,
    channel: Option<String>,
    datetime: Option<String>,
    timestamp: Option<String>,
}

fn try_parse_json_line(line: &str, source: &str, line_no: usize) -> Option<LogEntry> {
    let parsed: JsonLogLine = serde_json::from_str(line).ok()?;
    let raw_msg = parsed.message?;
    let message = redact_inline_secrets(&raw_msg);
    let raw_ts = parsed.datetime.or(parsed.timestamp);
    let ts = raw_ts.as_deref().and_then(parse_timestamp);
    let level = parsed
        .level_name
        .as_deref()
        .and_then(LogLevel::from_str_lossy)
        .or_else(|| {
            parsed
                .level
                .as_ref()
                .and_then(|v| v.as_str())
                .and_then(LogLevel::from_str_lossy)
        })
        .unwrap_or(LogLevel::Error);

    let exc_cls = extract_exception_class(&message);
    let loc = extract_location(&message);
    let fp = fingerprint_error(exc_cls.as_deref(), &message, loc.as_deref());

    Some(LogEntry {
        timestamp: ts,
        raw_timestamp: raw_ts,
        environment: parsed.channel,
        level,
        message,
        exception_class: exc_cls,
        location: loc,
        stack_trace: Vec::new(),
        fingerprint: fp,
        source_file: source.to_string(),
        line_number: line_no,
    })
}

fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(raw.trim(), "%Y-%m-%d %H:%M:%S") {
        return Some(naive.and_utc());
    }
    None
}

fn extract_exception_class(msg: &str) -> Option<String> {
    exception_class_re().find(msg).map(|m| m.as_str().to_string())
}

fn extract_location(text: &str) -> Option<String> {
    location_re()
        .captures(text)
        .map(|c| format!("{}:{}", &c[1], &c[2]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parses_multiline_monolog_and_groups_duplicates() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            "[2026-11-27 10:00:00] production.ERROR: Illuminate\\Database\\QueryException: Deadlock for order 123 at app/Services/OrderService.php:45\n[stacktrace]\n#0 app/Http/Controllers/OrderController.php(22): handle()\n[2026-11-27 10:01:00] production.ERROR: Illuminate\\Database\\QueryException: Deadlock for order 456 at app/Services/OrderService.php:45\nmalformed junk line without header\n{{\"message\":\"Redis connection refused\",\"level_name\":\"CRITICAL\",\"datetime\":\"2026-11-27T10:02:00Z\"}}"
        )
        .unwrap();

        let res = parse_log_file(f.path(), &LogFilter::default()).unwrap();
        assert_eq!(res.stats.parsed_entries, 3);
        assert_eq!(res.groups.len(), 2);
        assert_eq!(res.groups[0].count, 2);
    }

    #[test]
    fn bounds_sample_entries_while_aggregating_all_groups() {
        let mut f = NamedTempFile::new().unwrap();
        for i in 0..200 {
            writeln!(
                f,
                "[2026-11-27 10:00:00] production.ERROR: Deadlock for order {i} at app/Order.php:10"
            )
            .unwrap();
        }
        let filter = LogFilter {
            limit: Some(5),
            ..Default::default()
        };
        let res = parse_log_file(f.path(), &filter).unwrap();
        assert_eq!(res.stats.parsed_entries, 200);
        assert_eq!(res.entries.len(), 5);
        assert_eq!(res.groups.len(), 1);
        assert_eq!(res.groups[0].count, 200);
    }
}
