use crate::error::{Error, Result};
use crate::http::HttpClient;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// LLM provider — determines API format and endpoint.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Anthropic,
    #[default]
    OpenRouter,
    /// Any OpenAI-compatible API (together.ai, local ollama, etc.)
    #[serde(rename = "openai")]
    OpenAi,
}

impl Provider {
    fn default_base_url(&self) -> &'static str {
        match self {
            Self::Anthropic => "https://api.anthropic.com/v1",
            Self::OpenRouter => "https://openrouter.ai/api/v1",
            Self::OpenAi => "http://localhost:11434/v1",
        }
    }

    fn default_api_key_env(&self) -> &'static str {
        match self {
            Self::Anthropic => "ANTHROPIC_API_KEY",
            Self::OpenRouter => "OPENROUTER_API_KEY",
            Self::OpenAi => "OPENAI_API_KEY",
        }
    }
}

pub struct LlmClient {
    provider: Provider,
    api_key: String,
    model: String,
    max_tokens: u32,
    base_url: String,
    http: HttpClient,
}

// -- Anthropic format --

#[derive(Serialize)]
struct AnthropicRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<Msg<'a>>,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicBlock>,
}

#[derive(Deserialize)]
struct AnthropicBlock {
    text: Option<String>,
}

// -- OpenAI-compatible format --

#[derive(Serialize)]
struct OpenAiRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<Msg<'a>>,
}

#[derive(Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
}

#[derive(Deserialize)]
struct OpenAiMessage {
    content: String,
}

// -- Shared --

#[derive(Serialize)]
struct Msg<'a> {
    role: &'a str,
    content: &'a str,
}

impl LlmClient {
    pub fn new(
        provider: Provider,
        api_key: String,
        model: String,
        max_tokens: u32,
        base_url: Option<String>,
    ) -> Result<Self> {
        let http = HttpClient::new("st-solguard/0.1.0")?;
        let base_url = base_url.unwrap_or_else(|| provider.default_base_url().into());
        Ok(Self {
            provider,
            api_key,
            model,
            max_tokens,
            base_url,
            http,
        })
    }

    /// Build from config, reading the API key from the specified env var.
    pub fn from_config(
        provider: Provider,
        model: String,
        max_tokens: u32,
        api_key_env: Option<String>,
        base_url: Option<String>,
    ) -> Result<Self> {
        let env_var = api_key_env.unwrap_or_else(|| provider.default_api_key_env().into());
        let api_key = std::env::var(&env_var).unwrap_or_default();
        Self::new(provider, api_key, model, max_tokens, base_url)
    }

    pub async fn complete(&self, system: &str, user_message: &str) -> Result<String> {
        debug!(provider = ?self.provider, model = %self.model, "sending LLM request");

        match self.provider {
            Provider::Anthropic => self.complete_anthropic(system, user_message).await,
            Provider::OpenRouter | Provider::OpenAi => {
                self.complete_openai(system, user_message).await
            }
        }
    }

    /// Send a prompt and parse the response as JSON, stripping markdown fences if present.
    pub async fn complete_json<T: serde::de::DeserializeOwned>(
        &self,
        system: &str,
        user_message: &str,
    ) -> Result<T> {
        let text = self.complete(system, user_message).await?;
        let json_str = extract_json(&text);
        serde_json::from_str(json_str)
            .map_err(|e| Error::parse(format!("parse LLM JSON: {e}\nraw: {text}")))
    }

    async fn complete_anthropic(&self, system: &str, user_message: &str) -> Result<String> {
        let request = AnthropicRequest {
            model: &self.model,
            max_tokens: self.max_tokens,
            system,
            messages: vec![Msg {
                role: "user",
                content: user_message,
            }],
        };

        let body = serde_json::to_string(&request)
            .map_err(|e| Error::parse(format!("serialize request: {e}")))?;

        let url = format!("{}/messages", self.base_url);
        let response_text = self
            .http
            .post_json_raw(
                &url,
                &body,
                &[
                    ("x-api-key", &self.api_key),
                    ("anthropic-version", "2023-06-01"),
                ],
            )
            .await
            .map_err(|e| {
                warn!("Anthropic API error: {e}");
                e
            })?;

        let resp: AnthropicResponse = serde_json::from_str(&response_text)
            .map_err(|e| Error::parse(format!("parse Anthropic response: {e}")))?;

        Ok(resp
            .content
            .into_iter()
            .filter_map(|b| b.text)
            .collect::<Vec<_>>()
            .join("\n"))
    }

    async fn complete_openai(&self, system: &str, user_message: &str) -> Result<String> {
        let request = OpenAiRequest {
            model: &self.model,
            max_tokens: self.max_tokens,
            messages: vec![
                Msg {
                    role: "system",
                    content: system,
                },
                Msg {
                    role: "user",
                    content: user_message,
                },
            ],
        };

        let body = serde_json::to_string(&request)
            .map_err(|e| Error::parse(format!("serialize request: {e}")))?;

        let url = format!("{}/chat/completions", self.base_url);
        let response_text = self
            .http
            .post_json_raw(
                &url,
                &body,
                &[("Authorization", &format!("Bearer {}", self.api_key))],
            )
            .await
            .map_err(|e| {
                warn!("LLM API error: {e}");
                e
            })?;

        let resp: OpenAiResponse = serde_json::from_str(&response_text)
            .map_err(|e| Error::parse(format!("parse LLM response: {e}")))?;

        resp.choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| Error::parse("empty response from LLM"))
    }
}

/// Extract JSON from a response that might be wrapped in markdown code fences.
fn extract_json(text: &str) -> &str {
    if let Some(start) = text.find("```json") {
        let content = &text[start + 7..];
        if let Some(end) = content.find("```") {
            return content[..end].trim();
        }
    }
    if let Some(start) = text.find("```") {
        let content = &text[start + 3..];
        if let Some(end) = content.find("```") {
            let inner = content[..end].trim();
            if inner.starts_with('{') || inner.starts_with('[') {
                return inner;
            }
        }
    }
    if let Some(start) = text.find('{')
        && let Some(end) = text.rfind('}')
    {
        return &text[start..=end];
    }
    text
}
