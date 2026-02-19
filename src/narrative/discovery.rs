use super::types::{Metric, Signal, SignalSource};
use crate::config::DiscoveryConfig;
use crate::error::Result;
use crate::llm::LlmClient;
use chrono::Utc;
use serde::Deserialize;
use tracing::{info, warn};

const SYSTEM_PROMPT: &str = r#"You are a Solana ecosystem intelligence researcher.
Search the web to discover what is happening in the Solana ecosystem RIGHT NOW.

Research: breaking developments, growth trends, developer ecosystem changes,
security events, adoption news, token economics.

Strategy:
1. Search broad: "Solana ecosystem news [month/year]", "Solana DeFi trends"
2. Follow leads: find specific protocols, read announcements
3. Cross-validate: corroborate claims across sources
4. Quantify: TVL changes, user counts, transaction volumes, funding amounts

Output JSON:
{
  "signals": [{
    "title": "Specific title with names and numbers",
    "description": "What happened, why it matters, quantified impact",
    "category": "DeFi|DePIN|AI & Agents|Infrastructure|Security|Governance|NFT & Gaming|Staking|Payments|Developer Tooling",
    "url": "https://source-url",
    "metrics": [{"name": "...", "value": 0.0, "unit": "..."}],
    "relevance": 0.85
  }]
}

Rules:
- Only report things found via web search. Do NOT fabricate.
- Every signal must have a source URL.
- Recent events only (last 7-30 days).
- 8-15 signals ideal. Quality over quantity.
"#;

const USER_MESSAGE: &str = "Research the current state of the Solana ecosystem. \
Find the most significant recent developments, trends, and events. \
Focus on developments that have security implications, rapid growth sectors, \
and emerging protocol categories. Return structured JSON.";

#[derive(Deserialize)]
struct DiscoveryResponse {
    signals: Vec<DiscoveredSignal>,
}

#[derive(Deserialize)]
struct DiscoveredSignal {
    title: String,
    description: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    metrics: Vec<RawMetric>,
    #[serde(default = "default_relevance")]
    relevance: f64,
}

#[derive(Deserialize)]
struct RawMetric {
    name: String,
    value: f64,
    #[serde(default)]
    unit: String,
}

fn default_relevance() -> f64 {
    0.5
}

pub async fn discover(llm: &LlmClient, config: &DiscoveryConfig) -> Result<Vec<Signal>> {
    if !config.enabled {
        info!("discovery: disabled, skipping");
        return Ok(Vec::new());
    }

    info!(
        "discovery: starting autonomous web research via {}",
        llm.model()
    );

    let response: DiscoveryResponse = match llm.complete_json(SYSTEM_PROMPT, USER_MESSAGE).await {
        Ok(r) => r,
        Err(e) => {
            warn!("discovery failed (non-fatal): {e}");
            return Ok(Vec::new());
        }
    };

    let now = Utc::now();
    let signals: Vec<Signal> = response
        .signals
        .into_iter()
        .filter(|s| s.relevance >= 0.3)
        .take(config.max_signals)
        .map(|s| Signal {
            source: SignalSource::Discovery,
            category: if s.category.is_empty() {
                "General".into()
            } else {
                s.category
            },
            title: s.title,
            description: s.description,
            metrics: s
                .metrics
                .into_iter()
                .map(|m| Metric {
                    name: m.name,
                    value: m.value,
                    unit: m.unit,
                })
                .collect(),
            url: s.url,
            timestamp: now,
        })
        .collect();

    info!(
        count = signals.len(),
        "discovery: found signals via web research"
    );
    Ok(signals)
}
