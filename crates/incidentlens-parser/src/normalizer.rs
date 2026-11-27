use regex::Regex;
use std::sync::OnceLock;

static UUID_RE: OnceLock<Regex> = OnceLock::new();
static HEX_RE: OnceLock<Regex> = OnceLock::new();
static ISO_DATE_RE: OnceLock<Regex> = OnceLock::new();
static NUM_RE: OnceLock<Regex> = OnceLock::new();
static QUOTED_RE: OnceLock<Regex> = OnceLock::new();

/// Normalizes volatile tokens (UUIDs, IDs, numbers, timestamps, quoted literals)
/// in exception messages so duplicate errors produce a stable fingerprint.
pub fn normalize_message(input: &str) -> String {
    let uuid_re = UUID_RE.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("valid uuid regex")
    });
    let hex_re = HEX_RE.get_or_init(|| Regex::new(r"\b0x[0-9a-fA-F]+\b").expect("valid hex regex"));
    let iso_re = ISO_DATE_RE.get_or_init(|| {
        Regex::new(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
            .expect("valid iso date regex")
    });
    let quoted_re = QUOTED_RE
        .get_or_init(|| Regex::new(r#"'[^']{1,120}'|"[^"]{1,120}""#).expect("valid quoted regex"));
    let num_re = NUM_RE.get_or_init(|| Regex::new(r"\b\d+\b").expect("valid num regex"));

    let s = uuid_re.replace_all(input, "<UUID>");
    let s = hex_re.replace_all(&s, "<HEX>");
    let s = iso_re.replace_all(&s, "<TIMESTAMP>");
    let s = quoted_re.replace_all(&s, "<STR>");
    let s = num_re.replace_all(&s, "<NUM>");
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ids_uuids_and_timestamps() {
        let msg = "SQLSTATE[23000]: Integrity constraint violation for user 48291 at 2026-11-27 10:15:30 request 550e8400-e29b-41d4-a716-446655440000";
        let norm = normalize_message(msg);
        assert_eq!(
            norm,
            "SQLSTATE[<NUM>]: Integrity constraint violation for user <NUM> at <TIMESTAMP> request <UUID>"
        );
    }
}
