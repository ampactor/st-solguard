mod aggregator;
mod defi_llama;
mod github;
mod social;
mod solana_rpc;
mod synthesizer;
mod types;

use crate::LlmOverride;
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
    #[serde(default)]
    pub finding_count: usize,
    #[serde(default)]
    pub risk_score: f64,
    #[serde(default)]
    pub risk_level: String,
    #[serde(default)]
    pub repo_findings: Vec<(String, Vec<usize>)>,
}

/// Run the full narrative detection pipeline from config.
pub async fn run_narrative_pipeline(
    config_path: &Path,
    llm_override: Option<&LlmOverride>,
) -> Result<Vec<Narrative>> {
    info!("narrative pipeline: starting");

    let mut config = Config::load(config_path).map_err(|e| anyhow::anyhow!("{e}"))?;
    config.validate().map_err(|e| anyhow::anyhow!("{e}"))?;

    if let Some(ov) = llm_override {
        config.llm.provider = ov.provider.clone();
        config.llm.model = ov.model.clone();
    }

    let http = HttpClient::new("st-solguard/0.1.0").map_err(|e| anyhow::anyhow!("{e}"))?;

    // Collect signals from all sources in parallel
    let (github_result, solana_result, social_result, defi_llama_result) = tokio::join!(
        github::collect(&config.github, &http),
        solana_rpc::collect(&config.solana, &http),
        social::collect(&config.social, &http),
        defi_llama::collect(&config.defi_llama, &http),
    );

    let mut signals = Vec::new();
    let mut discovered_repos = Vec::new();

    match github_result {
        Ok(data) => {
            signals.extend(data.signals);
            discovered_repos = data.discovered_repos;
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

    match defi_llama_result {
        Ok(sigs) => signals.extend(sigs),
        Err(e) => tracing::warn!(error = %e, "DeFiLlama signal collection failed"),
    }

    info!(
        signals = signals.len(),
        repos = discovered_repos.len(),
        "signal collection complete"
    );

    if signals.is_empty() {
        tracing::warn!("no signals collected — returning empty narratives");
        return Ok(Vec::new());
    }

    // Aggregate signals
    let groups = aggregator::aggregate(&signals);
    let signals_json = aggregator::signals_to_json(&signals, &groups, &discovered_repos);

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

    // Map to solguard Narrative type with LLM-assigned repos
    let narratives = synthesized
        .into_iter()
        .map(|n| Narrative {
            title: n.title,
            summary: n.summary,
            confidence: n.confidence,
            trend: n.trend.to_string(),
            active_repos: n.active_repos,
            finding_count: 0,
            risk_score: 0.0,
            risk_level: String::new(),
            repo_findings: Vec::new(),
        })
        .collect();

    info!("narrative pipeline complete");
    Ok(narratives)
}
