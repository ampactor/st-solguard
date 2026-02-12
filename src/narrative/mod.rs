mod aggregator;
mod github;
mod social;
mod solana_rpc;
mod synthesizer;
mod types;

use crate::config::Config;
use crate::http::HttpClient;
use crate::llm::LlmClient;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

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
    info!("narrative pipeline: starting");

    let config = Config::load(config_path).map_err(|e| anyhow::anyhow!("{e}"))?;
    config.validate().map_err(|e| anyhow::anyhow!("{e}"))?;

    let http = HttpClient::new("st-solguard/0.1.0").map_err(|e| anyhow::anyhow!("{e}"))?;

    // Collect signals from all sources in parallel
    let (github_result, solana_result, social_result) = tokio::join!(
        github::collect(&config.github, &http),
        solana_rpc::collect(&config.solana, &http),
        social::collect(&config.social, &http),
    );

    let mut signals = Vec::new();
    let mut repo_names = Vec::new();

    match github_result {
        Ok(data) => {
            signals.extend(data.signals);
            repo_names = data.discovered_repos;
        }
        Err(e) => tracing::warn!(error = %e, "GitHub signal collection failed"),
    }

    match solana_result {
        Ok(sigs) => signals.extend(sigs),
        Err(e) => tracing::warn!(error = %e, "Solana RPC signal collection failed"),
    }

    match social_result {
        Ok(sigs) => signals.extend(sigs),
        Err(e) => tracing::warn!(error = %e, "Social signal collection failed"),
    }

    info!(
        signals = signals.len(),
        repos = repo_names.len(),
        "signal collection complete"
    );

    if signals.is_empty() {
        tracing::warn!("no signals collected — returning empty narratives");
        return Ok(Vec::new());
    }

    // Aggregate signals
    let groups = aggregator::aggregate(&signals);
    let signals_json = aggregator::signals_to_json(&signals, &groups);

    // Synthesize narratives via LLM
    let llm = LlmClient::from_config(
        config.llm.provider,
        config.llm.model,
        config.llm.max_tokens,
        config.llm.api_key_env,
        config.llm.base_url,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let synthesized = synthesizer::identify_narratives(&llm, &signals_json)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Map to solguard Narrative type, attaching discovered repos
    let narratives = synthesized
        .into_iter()
        .map(|n| Narrative {
            title: n.title,
            summary: n.summary,
            confidence: n.confidence,
            trend: n.trend.to_string(),
            active_repos: repo_names.clone(),
        })
        .collect();

    info!("narrative pipeline complete");
    Ok(narratives)
}
