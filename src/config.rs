use crate::error::{Error, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub github: GitHubConfig,
    pub solana: SolanaConfig,
    #[serde(default)]
    pub social: SocialConfig,
    pub llm: LlmConfig,
}

#[derive(Debug, Deserialize)]
pub struct GitHubConfig {
    #[serde(default = "default_github_token")]
    pub token: String,
    #[serde(default = "default_topics")]
    pub topics: Vec<String>,
    #[serde(default = "default_min_stars")]
    pub min_stars: u32,
    #[serde(default = "default_lookback_days")]
    pub lookback_days: u32,
    #[serde(default = "default_max_repos")]
    pub max_repos: u32,
}

#[derive(Debug, Deserialize)]
pub struct SolanaConfig {
    #[serde(default = "default_rpc_url")]
    pub rpc_url: String,
    #[serde(default = "default_programs")]
    pub tracked_programs: Vec<TrackedProgram>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrackedProgram {
    pub name: String,
    pub address: String,
    pub category: String,
}

#[derive(Debug, Deserialize)]
pub struct SocialConfig {
    #[serde(default = "default_sources")]
    pub sources: Vec<SocialSource>,
}

impl Default for SocialConfig {
    fn default() -> Self {
        Self {
            sources: default_sources(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SocialSource {
    pub name: String,
    pub url: String,
    #[serde(default = "default_source_type")]
    #[allow(dead_code)]
    pub source_type: String,
}

#[derive(Debug, Deserialize)]
pub struct LlmConfig {
    #[serde(default)]
    pub provider: crate::llm::Provider,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    pub api_key_env: Option<String>,
    pub base_url: Option<String>,
}

// Defaults
fn default_github_token() -> String {
    std::env::var("GITHUB_TOKEN").unwrap_or_default()
}
fn default_topics() -> Vec<String> {
    vec!["solana".into()]
}
fn default_min_stars() -> u32 {
    5
}
fn default_lookback_days() -> u32 {
    30
}
fn default_max_repos() -> u32 {
    30
}
fn default_rpc_url() -> String {
    std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".into())
}
fn default_programs() -> Vec<TrackedProgram> {
    vec![
        TrackedProgram {
            name: "Raydium AMM".into(),
            address: "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8".into(),
            category: "DeFi".into(),
        },
        TrackedProgram {
            name: "Jupiter Aggregator".into(),
            address: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".into(),
            category: "DeFi".into(),
        },
        TrackedProgram {
            name: "Marinade Finance".into(),
            address: "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD".into(),
            category: "Liquid Staking".into(),
        },
    ]
}
fn default_sources() -> Vec<SocialSource> {
    vec![SocialSource {
        name: "Helius Blog".into(),
        url: "https://www.helius.dev/blog".into(),
        source_type: "blog".into(),
    }]
}
fn default_source_type() -> String {
    "blog".into()
}
fn default_model() -> String {
    "arcee-ai/trinity-large-preview:free".into()
}
fn default_max_tokens() -> u32 {
    4096
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("Failed to read config {}: {e}", path.display())))?;
        toml::from_str(&content).map_err(|e| Error::config(format!("Failed to parse config: {e}")))
    }

    pub fn validate(&self) -> Result<()> {
        if self.github.token.is_empty() {
            return Err(Error::config(
                "GITHUB_TOKEN not set. Export it or set github.token in config.toml",
            ));
        }
        Ok(())
    }
}
