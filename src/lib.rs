pub mod agent;
pub mod config;
pub mod error;
pub mod http;
pub mod llm;
pub mod memory;
pub mod narrative;
pub mod output;
pub mod security;

/// CLI override for LLM provider/model.
pub struct LlmOverride {
    pub provider: llm::Provider,
    pub model: String,
}
