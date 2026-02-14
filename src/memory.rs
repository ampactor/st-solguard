use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

fn solguard_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".solguard")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoResult {
    pub name: String,
    pub findings_count: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunHistory {
    pub timestamp: DateTime<Utc>,
    pub signals_collected: usize,
    pub repo_results: Vec<RepoResult>,
    pub total_findings: usize,
    pub cost_estimate: f64,
    pub errors: Vec<String>,
}

impl RunHistory {
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            signals_collected: 0,
            repo_results: Vec::new(),
            total_findings: 0,
            cost_estimate: 0.0,
            errors: Vec::new(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let dir = solguard_dir().join("history");
        std::fs::create_dir_all(&dir)?;
        let filename = format!("{}.json", self.timestamp.format("%Y%m%dT%H%M%S"));
        std::fs::write(dir.join(filename), serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

/// Aggregate learning from all previous runs.
///
/// Tracks repos that consistently fail (blocklist after 3 consecutive errors),
/// error patterns, source reliability, and pattern hit rates.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunMemory {
    pub repo_blocklist: Vec<String>,
    /// Consecutive error count per repo (reset on success).
    pub error_memory: HashMap<String, u32>,
    /// (successes, total) per signal source.
    pub source_reliability: HashMap<String, (u32, u32)>,
    /// (confirmed, total) per pattern ID.
    pub pattern_hit_rates: HashMap<String, (u32, u32)>,
    pub total_runs: u32,
}

impl RunMemory {
    fn path() -> PathBuf {
        solguard_dir().join("memory.json")
    }

    pub fn load_or_default() -> Self {
        let path = Self::path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn update_from_run(&mut self, history: &RunHistory) {
        self.total_runs += 1;

        for repo in &history.repo_results {
            if !repo.errors.is_empty() && repo.findings_count == 0 {
                let count = self.error_memory.entry(repo.name.clone()).or_insert(0);
                *count += 1;
                // Blocklist after 3 consecutive failed runs
                if *count >= 3 && !self.repo_blocklist.contains(&repo.name) {
                    self.repo_blocklist.push(repo.name.clone());
                }
            } else {
                // Successful scan resets consecutive error count
                self.error_memory.remove(&repo.name);
            }
        }

        for error in &history.errors {
            let key: String = error.chars().take(100).collect();
            *self.error_memory.entry(key).or_insert(0) += 1;
        }
    }

    pub fn save(&self) -> Result<()> {
        let dir = solguard_dir();
        std::fs::create_dir_all(&dir)?;
        std::fs::write(Self::path(), serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}
