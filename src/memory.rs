// Run memory: persistent learning across pipeline executions.
//
// RunHistory captures per-run data (signals, repo results, findings).
// RunMemory aggregates across runs (blocklist, error patterns, reliability).
// Storage: ~/.solguard/history/{timestamp}.json (per-run) + ~/.solguard/memory.json (aggregate).

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::info;

/// Per-repo outcome from a single pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoResult {
    pub name: String,
    pub findings_count: usize,
    pub errors: Vec<String>,
}

/// Per-run snapshot: everything that happened in one pipeline execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunHistory {
    pub timestamp: String,
    pub signals_collected: usize,
    pub total_findings: usize,
    pub repo_results: Vec<RepoResult>,
}

impl Default for RunHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl RunHistory {
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now().format("%Y%m%d_%H%M%S").to_string(),
            signals_collected: 0,
            total_findings: 0,
            repo_results: Vec::new(),
        }
    }

    /// Save this run's history to ~/.solguard/history/{timestamp}.json
    pub fn save(&self) -> anyhow::Result<()> {
        let dir = history_dir();
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.json", self.timestamp));
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        info!(path = %path.display(), "saved run history");
        Ok(())
    }
}

/// Aggregate memory across all runs. Persisted at ~/.solguard/memory.json.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunMemory {
    pub total_runs: u32,
    /// Repos that consistently fail (clone errors, empty results) — skipped in future runs.
    pub repo_blocklist: Vec<String>,
    /// Error pattern → occurrence count. Repos hitting the same error 3+ times get blocklisted.
    pub error_memory: HashMap<String, u32>,
    /// Source → reliability score (0.0–1.0). Tracks which signal sources yield useful targets.
    pub source_reliability: HashMap<String, f64>,
    /// Pattern ID → (hits, confirmed). Tracks which vulnerability patterns produce confirmed findings.
    pub pattern_hit_rates: HashMap<String, (u32, u32)>,
}

impl RunMemory {
    /// Load aggregate memory from disk, or return defaults for first run.
    pub fn load_or_default() -> Self {
        let path = memory_file();
        match std::fs::read_to_string(&path) {
            Ok(json) => serde_json::from_str(&json).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "corrupt memory file, starting fresh");
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    /// Update aggregate memory from a completed run.
    pub fn update_from_run(&mut self, history: &RunHistory) {
        self.total_runs += 1;

        // Track repo errors — blocklist repos that fail 3+ times
        for repo in &history.repo_results {
            for error in &repo.errors {
                let key = format!("{}:{}", repo.name, error);
                let count = self.error_memory.entry(key).or_insert(0);
                *count += 1;

                if *count >= 3 && !self.repo_blocklist.contains(&repo.name) {
                    info!(
                        repo = %repo.name,
                        error = %error,
                        "blocklisting repo after 3+ failures"
                    );
                    self.repo_blocklist.push(repo.name.clone());
                }
            }
        }
    }

    /// Persist aggregate memory to disk.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = memory_file();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        info!(path = %path.display(), "saved run memory");
        Ok(())
    }
}

fn solguard_dir() -> PathBuf {
    dirs_or_home().join(".solguard")
}

fn history_dir() -> PathBuf {
    solguard_dir().join("history")
}

fn memory_file() -> PathBuf {
    solguard_dir().join("memory.json")
}

/// Home directory with fallback to /tmp.
fn dirs_or_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_history_new_has_timestamp() {
        let h = RunHistory::new();
        assert!(!h.timestamp.is_empty());
        assert_eq!(h.signals_collected, 0);
        assert_eq!(h.total_findings, 0);
        assert!(h.repo_results.is_empty());
    }

    #[test]
    fn run_memory_default() {
        let m = RunMemory::default();
        assert_eq!(m.total_runs, 0);
        assert!(m.repo_blocklist.is_empty());
        assert!(m.error_memory.is_empty());
    }

    #[test]
    fn update_from_run_increments_total() {
        let mut mem = RunMemory::default();
        let history = RunHistory::new();
        mem.update_from_run(&history);
        assert_eq!(mem.total_runs, 1);
        mem.update_from_run(&history);
        assert_eq!(mem.total_runs, 2);
    }

    #[test]
    fn blocklist_after_repeated_errors() {
        let mut mem = RunMemory::default();

        for _ in 0..3 {
            let history = RunHistory {
                timestamp: "test".into(),
                signals_collected: 0,
                total_findings: 0,
                repo_results: vec![RepoResult {
                    name: "bad-repo".into(),
                    findings_count: 0,
                    errors: vec!["clone failed".into()],
                }],
            };
            mem.update_from_run(&history);
        }

        assert!(mem.repo_blocklist.contains(&"bad-repo".to_string()));
        assert_eq!(mem.total_runs, 3);
    }

    #[test]
    fn no_blocklist_under_threshold() {
        let mut mem = RunMemory::default();

        for _ in 0..2 {
            let history = RunHistory {
                timestamp: "test".into(),
                signals_collected: 0,
                total_findings: 0,
                repo_results: vec![RepoResult {
                    name: "flaky-repo".into(),
                    findings_count: 0,
                    errors: vec!["timeout".into()],
                }],
            };
            mem.update_from_run(&history);
        }

        assert!(!mem.repo_blocklist.contains(&"flaky-repo".to_string()));
    }

    #[test]
    fn successful_repos_not_blocklisted() {
        let mut mem = RunMemory::default();
        let history = RunHistory {
            timestamp: "test".into(),
            signals_collected: 5,
            total_findings: 3,
            repo_results: vec![RepoResult {
                name: "good-repo".into(),
                findings_count: 3,
                errors: vec![],
            }],
        };
        mem.update_from_run(&history);
        assert!(mem.repo_blocklist.is_empty());
    }

    #[test]
    fn no_duplicate_blocklist_entries() {
        let mut mem = RunMemory::default();

        for _ in 0..5 {
            let history = RunHistory {
                timestamp: "test".into(),
                signals_collected: 0,
                total_findings: 0,
                repo_results: vec![RepoResult {
                    name: "bad-repo".into(),
                    findings_count: 0,
                    errors: vec!["clone failed".into()],
                }],
            };
            mem.update_from_run(&history);
        }

        assert_eq!(
            mem.repo_blocklist
                .iter()
                .filter(|r| r.as_str() == "bad-repo")
                .count(),
            1
        );
    }

    #[test]
    fn serde_roundtrip() {
        let mut mem = RunMemory::default();
        mem.total_runs = 5;
        mem.repo_blocklist.push("bad-repo".into());
        mem.error_memory.insert("bad-repo:clone failed".into(), 3);
        mem.source_reliability.insert("github".into(), 0.85);
        mem.pattern_hit_rates.insert("SOL-001".into(), (10, 7));

        let json = serde_json::to_string(&mem).unwrap();
        let restored: RunMemory = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.total_runs, 5);
        assert_eq!(restored.repo_blocklist, vec!["bad-repo"]);
        assert_eq!(restored.error_memory.get("bad-repo:clone failed"), Some(&3));
        assert_eq!(restored.source_reliability.get("github"), Some(&0.85));
        assert_eq!(restored.pattern_hit_rates.get("SOL-001"), Some(&(10, 7)));
    }
}
