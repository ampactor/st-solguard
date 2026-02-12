// Re-exports security scanning pipeline.
// This module wraps the same logic as st-audit but integrated into solguard.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub title: String,
    pub severity: String,
    pub description: String,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub remediation: String,
}

/// Scan a repository for vulnerabilities.
pub async fn scan_repo(repo_path: &Path) -> Result<Vec<SecurityFinding>> {
    // TODO: Integrate st-audit scanner here
    tracing::info!(path = %repo_path.display(), "security scan: starting");

    let _ = repo_path; // will use for file traversal

    tracing::warn!("security scanner not yet wired — returning empty");
    Ok(Vec::new())
}
