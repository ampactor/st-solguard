// Re-exports narrative detection pipeline.
// This module wraps the same logic as st-narrative but integrated into solguard.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Narrative {
    pub title: String,
    pub summary: String,
    pub confidence: f64,
    pub trend: String,
    pub active_repos: Vec<String>,
}

/// Run the full narrative detection pipeline from config.
pub async fn run_narrative_pipeline(config_path: &Path) -> Result<Vec<Narrative>> {
    // TODO: Integrate st-narrative pipeline here
    // For now, returns empty — will be wired up when st-narrative is tested with live data
    tracing::info!("narrative pipeline: starting");

    let _ = config_path; // will use for config loading

    tracing::warn!("narrative pipeline not yet wired — returning empty");
    Ok(Vec::new())
}
