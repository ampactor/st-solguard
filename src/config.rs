use crate::error::{Error, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub github: GitHubConfig,
    pub solana: SolanaConfig,
    #[serde(default)]
    pub social: SocialConfig,
    #[serde(default)]
    pub defi_llama: DefiLlamaConfig,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    pub llm: LlmConfig,
    #[serde(default)]
    pub models: Option<ModelsConfig>,
    #[serde(default)]
    pub agent_review: AgentReviewConfig,
    #[serde(default)]
    pub targets: TargetsConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct TargetsConfig {
    #[serde(default)]
    pub always_scan: Vec<String>,
    #[serde(default)]
    pub repos_dir: Option<PathBuf>,
}

/// Configuration for the multi-turn agent security review.
#[derive(Debug, Deserialize)]
pub struct AgentReviewConfig {
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
    /// Max tokens per LLM response (reserved for verifier agent in Phase 2).
    #[serde(default = "default_agent_max_tokens")]
    #[allow(dead_code)]
    pub max_tokens: u32,
    #[serde(default = "default_cost_limit")]
    pub cost_limit_usd: f64,
}

impl Default for AgentReviewConfig {
    fn default() -> Self {
        Self {
            max_turns: default_max_turns(),
            max_tokens: default_agent_max_tokens(),
            cost_limit_usd: default_cost_limit(),
        }
    }
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
pub struct DefiLlamaConfig {
    #[serde(default = "default_defi_llama_enabled")]
    pub enabled: bool,
    #[serde(default = "default_top_protocols")]
    pub top_protocols: usize,
}

#[derive(Debug, Deserialize)]
pub struct DiscoveryConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_signals")]
    pub max_signals: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_signals: 15,
        }
    }
}

impl Default for DefiLlamaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            top_protocols: 10,
        }
    }
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

/// Per-task model configuration for the `[models]` config section.
#[derive(Debug, Deserialize)]
pub struct ModelConfig {
    #[serde(default)]
    pub provider: crate::llm::Provider,
    pub model: String,
    pub base_url: Option<String>,
    pub api_key_env: Option<String>,
    pub max_tokens: Option<u32>,
}

/// Task-specific model routing: overrides `[llm]` for specific pipeline stages.
#[derive(Debug, Deserialize)]
pub struct ModelsConfig {
    pub narrative: Option<ModelConfig>,
    pub discovery: Option<ModelConfig>,
    pub investigation: Option<ModelConfig>,
    pub validation: Option<ModelConfig>,
    pub cross_reference: Option<ModelConfig>,
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
fn default_defi_llama_enabled() -> bool {
    true
}
fn default_top_protocols() -> usize {
    10
}
fn default_true() -> bool {
    true
}
fn default_max_signals() -> usize {
    15
}
fn default_model() -> String {
    "arcee-ai/trinity-large-preview:free".into()
}
fn default_max_tokens() -> u32 {
    4096
}
fn default_max_turns() -> u32 {
    30
}
fn default_agent_max_tokens() -> u32 {
    8192
}
fn default_cost_limit() -> f64 {
    20.0
}

impl Default for Config {
    fn default() -> Self {
        Self {
            github: GitHubConfig {
                token: default_github_token(),
                topics: default_topics(),
                min_stars: default_min_stars(),
                lookback_days: default_lookback_days(),
                max_repos: default_max_repos(),
            },
            solana: SolanaConfig {
                rpc_url: default_rpc_url(),
                tracked_programs: default_programs(),
            },
            social: SocialConfig::default(),
            defi_llama: DefiLlamaConfig::default(),
            discovery: DiscoveryConfig::default(),
            llm: LlmConfig {
                provider: crate::llm::Provider::default(),
                model: default_model(),
                max_tokens: default_max_tokens(),
                api_key_env: None,
                base_url: None,
            },
            models: None,
            agent_review: AgentReviewConfig::default(),
            targets: TargetsConfig::default(),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_config_parses() {
        let toml = r#"
[github]
token = "ghp_test"
topics = ["solana", "anchor"]
min_stars = 10

[solana]
rpc_url = "https://api.mainnet-beta.solana.com"

[[solana.tracked_programs]]
name = "Test"
address = "11111111111111111111111111111111"
category = "DeFi"

[social]
[[social.sources]]
name = "Test Blog"
url = "https://example.com"

[defi_llama]
enabled = true
top_protocols = 5

[llm]
provider = "openrouter"
model = "test-model"
max_tokens = 2048

[agent_review]
max_turns = 15
max_tokens = 4096
cost_limit_usd = 10.0

[models]
[models.narrative]
provider = "groq"
model = "qwen3-32b"
[models.validation]
provider = "anthropic"
model = "claude-sonnet-4-5-20250929"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.github.token, "ghp_test");
        assert_eq!(config.github.topics.len(), 2);
        assert_eq!(config.agent_review.max_turns, 15);
        assert!((config.agent_review.cost_limit_usd - 10.0).abs() < f64::EPSILON);
        assert!(config.models.is_some());
        let models = config.models.unwrap();
        assert!(models.narrative.is_some());
        assert!(models.validation.is_some());
        assert!(models.investigation.is_none());
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let toml = r#"
[github]
token = "ghp_test"

[solana]
rpc_url = "https://api.mainnet-beta.solana.com"

[llm]
model = "test"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.models.is_none());
        assert_eq!(config.agent_review.max_turns, 30);
        assert_eq!(config.agent_review.max_tokens, 8192);
        assert!((config.agent_review.cost_limit_usd - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn agent_review_config_defaults() {
        let arc = AgentReviewConfig::default();
        assert_eq!(arc.max_turns, 30);
        assert_eq!(arc.max_tokens, 8192);
        assert!((arc.cost_limit_usd - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn validate_rejects_empty_token() {
        let mut config = Config::default();
        config.github.token = String::new();
        assert!(config.validate().is_err());
    }
}
