use crate::error::CoreError;
use std::path::{Path, PathBuf};

/// Validates that a project root exists and is a directory, returning its canonical path.
pub fn validate_project_root(path: &Path) -> Result<PathBuf, CoreError> {
    if !path.exists() {
        return Err(CoreError::InvalidPath(
            path.display().to_string(),
            "path does not exist".to_string(),
        ));
    }
    if !path.is_dir() {
        return Err(CoreError::InvalidPath(
            path.display().to_string(),
            "path is not a directory".to_string(),
        ));
    }
    path.canonicalize()
        .map_err(|e| CoreError::InvalidPath(path.display().to_string(), e.to_string()))
}

/// Safely joins `relative` under `base`, rejecting path traversal outside `base`.
pub fn safe_join(base: &Path, relative: &Path) -> Result<PathBuf, CoreError> {
    let canonical_base = validate_project_root(base)?;
    let candidate = canonical_base.join(relative);

    if candidate.exists() {
        let canonical_target = candidate
            .canonicalize()
            .map_err(|e| CoreError::InvalidPath(candidate.display().to_string(), e.to_string()))?;
        if !canonical_target.starts_with(&canonical_base) {
            return Err(CoreError::PathTraversal(
                relative.display().to_string(),
                canonical_base.display().to_string(),
            ));
        }
        return Ok(canonical_target);
    }

    // For non-existent paths, reject any `..` or root components.
    for component in relative.components() {
        match component {
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(CoreError::PathTraversal(
                    relative.display().to_string(),
                    canonical_base.display().to_string(),
                ));
            }
            _ => {}
        }
    }

    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_traversal() {
        let tmp = std::env::temp_dir();
        let err = safe_join(&tmp, Path::new("../etc/passwd")).unwrap_err();
        assert!(matches!(err, CoreError::PathTraversal(_, _)));
    }
}
