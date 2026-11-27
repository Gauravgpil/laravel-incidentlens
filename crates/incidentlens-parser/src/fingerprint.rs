use crate::normalizer::normalize_message;
use sha2::{Digest, Sha256};

/// Generates a stable 16-char hex fingerprint from exception class, normalized message, and primary file frame.
pub fn fingerprint_error(
    exception_class: Option<&str>,
    message: &str,
    location: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    if let Some(cls) = exception_class {
        hasher.update(cls.trim().as_bytes());
    }
    hasher.update(b"|");
    hasher.update(normalize_message(message).as_bytes());
    hasher.update(b"|");
    if let Some(loc) = location {
        hasher.update(loc.trim().as_bytes());
    }
    let digest = hasher.finalize();
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_identical_fingerprint_for_same_error_with_different_ids() {
        let fp1 = fingerprint_error(
            Some("Illuminate\\Database\\QueryException"),
            "Deadlock found for order 1001",
            Some("app/Services/OrderService.php:42"),
        );
        let fp2 = fingerprint_error(
            Some("Illuminate\\Database\\QueryException"),
            "Deadlock found for order 9999",
            Some("app/Services/OrderService.php:42"),
        );
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
    }
}
