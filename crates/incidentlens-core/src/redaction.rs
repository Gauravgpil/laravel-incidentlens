const SENSITIVE_KEY_MARKERS: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APP_KEY",
    "PRIVATE_KEY",
    "DSN",
    "CREDENTIAL",
    "AUTH",
    "STRIPE",
    "AWS_ACCESS",
    "MAIL_PASS",
    "REDIS_PASSWORD",
    "DB_PASS",
];

/// Returns true when an environment or configuration key name may hold a secret.
pub fn is_sensitive_key(key: &str) -> bool {
    let upper = key.trim().to_ascii_uppercase();
    SENSITIVE_KEY_MARKERS
        .iter()
        .any(|marker| upper.contains(marker))
}

/// Redacts a value if its key is sensitive, or applies inline secret redaction.
pub fn redact_value(key: &str, value: &str) -> String {
    if is_sensitive_key(key) {
        return "[REDACTED]".to_string();
    }
    redact_inline_secrets(value)
}

/// Redacts common inline secret patterns such as URL credentials and Bearer tokens.
pub fn redact_inline_secrets(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    // Redact `://user:pass@` URL credentials.
    while let Some(scheme_idx) = rest.find("://") {
        let after_scheme_start = scheme_idx + 3;
        out.push_str(&rest[..after_scheme_start]);
        let after_scheme = &rest[after_scheme_start..];

        if let Some(at_idx) = after_scheme.find('@') {
            let authority = &after_scheme[..at_idx];
            if !authority.contains('/') && !authority.contains(' ') && authority.contains(':') {
                out.push_str("[REDACTED]@");
                rest = &after_scheme[at_idx + 1..];
                continue;
            }
        }
        rest = after_scheme;
    }
    out.push_str(rest);

    // Redact `Bearer <token>` patterns case-insensitively.
    redact_bearer_tokens(&out)
}

fn redact_bearer_tokens(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;

    while let Some(rel_idx) = lower[cursor..].find("bearer ") {
        let match_start = cursor + rel_idx;
        let token_start = match_start + "bearer ".len();
        out.push_str(&input[cursor..token_start]);

        let token_end = input[token_start..]
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',')
            .map(|offset| token_start + offset)
            .unwrap_or(input.len());

        if token_end > token_start {
            out.push_str("[REDACTED]");
        }
        cursor = token_end;
    }

    out.push_str(&input[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sensitive_keys() {
        assert!(is_sensitive_key("APP_KEY"));
        assert!(is_sensitive_key("DB_PASSWORD"));
        assert!(is_sensitive_key("stripe_secret"));
        assert!(!is_sensitive_key("APP_ENV"));
        assert!(!is_sensitive_key("LOG_CHANNEL"));
    }

    #[test]
    fn redacts_url_credentials_and_bearer_tokens() {
        let dsn = "mysql://root:s3cr3t@127.0.0.1:3306/app";
        assert_eq!(
            redact_inline_secrets(dsn),
            "mysql://[REDACTED]@127.0.0.1:3306/app"
        );

        let header = "Authorization: Bearer super_secret_token_123";
        assert_eq!(
            redact_inline_secrets(header),
            "Authorization: Bearer [REDACTED]"
        );
    }
}
