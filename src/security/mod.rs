pub mod agent_review;
pub mod agent_tools;
mod ast_scan;
mod regex_scan;
pub mod validator;

use crate::config::AgentReviewConfig;
use crate::llm::LlmClient;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::info;
use walkdir::WalkDir;

// -- Public types (used by agent + output) --

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationStatus {
    #[default]
    Unvalidated,
    Confirmed,
    Disputed,
    Dismissed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub title: String,
    pub severity: String,
    pub description: String,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub remediation: String,
    #[serde(default)]
    pub validation_status: ValidationStatus,
    #[serde(default)]
    pub validation_reasoning: Option<String>,
}

// -- Internal types (used by scanners) --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Info => write!(f, "Info"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub pattern_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub code_snippet: String,
    pub remediation: String,
    pub confidence: f64,
    #[serde(default)]
    pub references: Vec<String>,
}

impl From<Finding> for SecurityFinding {
    fn from(f: Finding) -> Self {
        Self {
            title: f.title,
            severity: f.severity.to_string(),
            description: f.description,
            file_path: f.file_path,
            line_number: f.line_number,
            remediation: f.remediation,
            validation_status: ValidationStatus::Unvalidated,
            validation_reasoning: None,
        }
    }
}

/// Directories that contain test/client/build code, not on-chain programs.
const EXCLUDED_DIRS: &[&str] = &[
    "/target/",
    "/tests/",
    "/test/",
    "/client/",
    "/clients/",
    "/cli/",
    "/sdk/",
    "/scripts/",
    "/migrations/",
    "/examples/",
    "/.docs/",
    "/benches/",
    "/cpitest/",
    "/generated/",
];

/// Scan a repository for vulnerabilities.
pub async fn scan_repo(repo_path: &Path) -> Result<Vec<SecurityFinding>> {
    info!(path = %repo_path.display(), "security scan: starting");

    if !repo_path.exists() {
        anyhow::bail!("Repository path does not exist: {}", repo_path.display());
    }

    let rust_files = collect_rust_files(repo_path)?;
    info!(count = rust_files.len(), "found Rust source files");

    if rust_files.is_empty() {
        info!("no Rust files found, returning empty");
        return Ok(Vec::new());
    }

    let mut all_findings: Vec<Finding> = Vec::new();

    for file_path in &rust_files {
        let content = std::fs::read_to_string(file_path)?;

        // Regex-based pattern scan
        all_findings.extend(regex_scan::scan(&content, file_path));

        // AST-based scan
        match ast_scan::scan(&content, file_path) {
            Ok(ast_findings) => all_findings.extend(ast_findings),
            Err(e) => {
                tracing::warn!(file = %file_path.display(), error = %e, "AST parse failed, skipping");
            }
        }
    }

    // Deduplicate
    all_findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.file_path.cmp(&b.file_path))
            .then(a.line_number.cmp(&b.line_number))
    });
    all_findings.dedup_by(|a, b| {
        a.file_path == b.file_path && a.line_number == b.line_number && a.pattern_id == b.pattern_id
    });

    let findings: Vec<SecurityFinding> = all_findings
        .into_iter()
        .map(SecurityFinding::from)
        .collect();

    info!(count = findings.len(), "security scan complete");
    Ok(findings)
}

/// Run the multi-turn agent investigation on a repository.
///
/// Optionally runs the static scanner first to provide triage context.
pub async fn scan_repo_deep(
    repo_path: &Path,
    llm: &LlmClient,
    config: &AgentReviewConfig,
    scan_context: Option<&agent_review::ScanContext>,
) -> Result<Vec<SecurityFinding>> {
    // Run static scan first for triage context
    let static_findings = scan_repo(repo_path).await.unwrap_or_default();
    let triage = if static_findings.is_empty() {
        None
    } else {
        Some(agent_review::format_triage_context(&static_findings))
    };

    let (agent_findings, stats) =
        agent_review::investigate(llm, repo_path, config, triage.as_deref(), scan_context).await?;

    info!(
        agent_findings = agent_findings.len(),
        static_findings = static_findings.len(),
        turns = stats.turns,
        cost = format!("${:.4}", stats.total_cost_usd),
        "deep scan complete"
    );

    // Convert agent findings to SecurityFinding
    let mut findings: Vec<SecurityFinding> = agent_findings
        .into_iter()
        .map(|af| SecurityFinding {
            title: af.title,
            severity: af.severity,
            description: af.description,
            file_path: af
                .affected_files
                .first()
                .map(PathBuf::from)
                .unwrap_or_default(),
            line_number: 0,
            remediation: af.remediation,
            validation_status: ValidationStatus::Unvalidated,
            validation_reasoning: None,
        })
        .collect();

    // Include high-confidence static findings not covered by agent
    for sf in static_findings {
        if sf.severity == "Critical" || sf.severity == "High" {
            let dominated = findings.iter().any(|af| {
                af.title.to_lowercase().contains(&sf.title.to_lowercase())
                    || sf
                        .file_path
                        .to_string_lossy()
                        .contains(&af.file_path.to_string_lossy().to_string())
            });
            if !dominated {
                findings.push(sf);
            }
        }
    }

    Ok(findings)
}

fn collect_rust_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let path_str = path.to_string_lossy();
        if path.extension().is_some_and(|ext| ext == "rs")
            && !EXCLUDED_DIRS.iter().any(|d| path_str.contains(d))
        {
            files.push(path.to_path_buf());
        }
    }
    Ok(files)
}
