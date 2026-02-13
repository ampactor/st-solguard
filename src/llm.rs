use crate::error::{Error, Result};
use crate::http::HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
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
    Groq,
}

impl Provider {
    fn default_base_url(&self) -> &'static str {
        match self {
            Self::Anthropic => "https://api.anthropic.com/v1",
            Self::OpenRouter => "https://openrouter.ai/api/v1",
            Self::OpenAi => "http://localhost:11434/v1",
            Self::Groq => "https://api.groq.com/openai/v1",
        }
    }

    fn default_api_key_env(&self) -> &'static str {
        match self {
            Self::Anthropic => "ANTHROPIC_API_KEY",
            Self::OpenRouter => "OPENROUTER_API_KEY",
            Self::OpenAi => "OPENAI_API_KEY",
            Self::Groq => "GROQ_API_KEY",
        }
    }
}

// -- Shared conversation types for multi-turn tool use --

/// Tool definition passed to the LLM.
#[derive(Debug, Clone, Serialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Content block in a conversation message.
#[derive(Debug, Clone)]
pub enum ContentBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
}

/// Role in a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
}

/// A message in a multi-turn conversation.
#[derive(Debug, Clone)]
pub struct ConversationMessage {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

/// Why the LLM stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
}

/// Token usage from a single API call.
#[derive(Debug, Clone, Default)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

/// Response from a multi-turn conversation call.
#[derive(Debug)]
pub struct ConversationResponse {
    pub content: Vec<ContentBlock>,
    pub stop_reason: StopReason,
    pub usage: Usage,
}

pub struct LlmClient {
    provider: Provider,
    api_key: String,
    model: String,
    max_tokens: u32,
    base_url: String,
    http: HttpClient,
}

// -- Anthropic simple completion wire types --

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

// -- Anthropic conversation wire types --

#[derive(Deserialize)]
struct AnthropicConvResponse {
    content: Vec<Value>,
    stop_reason: Option<String>,
    #[serde(default)]
    usage: AnthropicUsage,
}

#[derive(Deserialize, Default)]
struct AnthropicUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
}

// -- OpenAI-compatible simple completion wire types --

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

// -- OpenAI conversation wire types --

#[derive(Deserialize)]
struct OpenAiConvResponse {
    choices: Vec<OpenAiConvChoice>,
    usage: Option<OpenAiConvUsage>,
}

#[derive(Deserialize)]
struct OpenAiConvChoice {
    message: OpenAiConvMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct OpenAiConvMessage {
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<OpenAiToolCall>>,
}

#[derive(Deserialize)]
struct OpenAiToolCall {
    id: String,
    function: OpenAiToolCallFn,
}

#[derive(Deserialize)]
struct OpenAiToolCallFn {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct OpenAiConvUsage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
}

// -- Shared simple message --

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

    pub fn model(&self) -> &str {
        &self.model
    }

    // -- Simple single-turn completion (used by narrative synthesis) --

    pub async fn complete(&self, system: &str, user_message: &str) -> Result<String> {
        debug!(provider = ?self.provider, model = %self.model, "sending LLM request");

        match self.provider {
            Provider::Anthropic => self.complete_anthropic(system, user_message).await,
            Provider::OpenRouter | Provider::OpenAi | Provider::Groq => {
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

    // -- Multi-turn conversation with tool use --

    /// Send a multi-turn conversation to the LLM with tool definitions.
    ///
    /// The caller manages conversation history and tool dispatch. This method
    /// handles wire format translation for both Anthropic and OpenAI providers.
    pub async fn converse(
        &self,
        system: &str,
        messages: &[ConversationMessage],
        tools: &[ToolDef],
    ) -> Result<ConversationResponse> {
        debug!(
            provider = ?self.provider,
            model = %self.model,
            turns = messages.len(),
            "converse"
        );
        match self.provider {
            Provider::Anthropic => self.converse_anthropic(system, messages, tools).await,
            Provider::OpenRouter | Provider::OpenAi | Provider::Groq => {
                self.converse_openai(system, messages, tools).await
            }
        }
    }

    async fn converse_anthropic(
        &self,
        system: &str,
        messages: &[ConversationMessage],
        tools: &[ToolDef],
    ) -> Result<ConversationResponse> {
        let wire_messages = Self::messages_to_anthropic(messages);
        let wire_tools: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "name": &t.name,
                    "description": &t.description,
                    "input_schema": &t.input_schema,
                })
            })
            .collect();

        let mut body = json!({
            "model": &self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": wire_messages,
        });
        if !wire_tools.is_empty() {
            body["tools"] = json!(wire_tools);
        }

        let body_str = serde_json::to_string(&body)
            .map_err(|e| Error::parse(format!("serialize converse request: {e}")))?;

        let url = format!("{}/messages", self.base_url);
        let response_text = self
            .http
            .post_json_raw(
                &url,
                &body_str,
                &[
                    ("x-api-key", &self.api_key),
                    ("anthropic-version", "2023-06-01"),
                ],
            )
            .await
            .map_err(|e| {
                warn!("Anthropic converse error: {e}");
                e
            })?;

        let resp: AnthropicConvResponse = serde_json::from_str(&response_text).map_err(|e| {
            Error::parse(format!(
                "parse Anthropic converse response: {e}\nraw: {response_text}"
            ))
        })?;

        let content = resp
            .content
            .into_iter()
            .filter_map(Self::parse_anthropic_content_block)
            .collect();
        let stop_reason = match resp.stop_reason.as_deref() {
            Some("tool_use") => StopReason::ToolUse,
            Some("max_tokens") => StopReason::MaxTokens,
            _ => StopReason::EndTurn,
        };
        let usage = Usage {
            input_tokens: resp.usage.input_tokens,
            output_tokens: resp.usage.output_tokens,
        };

        Ok(ConversationResponse {
            content,
            stop_reason,
            usage,
        })
    }

    fn messages_to_anthropic(messages: &[ConversationMessage]) -> Vec<Value> {
        messages
            .iter()
            .map(|msg| {
                let role = match msg.role {
                    Role::User => "user",
                    Role::Assistant => "assistant",
                };
                let content: Vec<Value> = msg
                    .content
                    .iter()
                    .map(|block| match block {
                        ContentBlock::Text { text } => {
                            json!({"type": "text", "text": text})
                        }
                        ContentBlock::ToolUse { id, name, input } => {
                            json!({"type": "tool_use", "id": id, "name": name, "input": input})
                        }
                        ContentBlock::ToolResult {
                            tool_use_id,
                            content,
                            is_error,
                        } => {
                            let mut v = json!({
                                "type": "tool_result",
                                "tool_use_id": tool_use_id,
                                "content": content,
                            });
                            if *is_error {
                                v["is_error"] = json!(true);
                            }
                            v
                        }
                    })
                    .collect();
                json!({"role": role, "content": content})
            })
            .collect()
    }

    fn parse_anthropic_content_block(v: Value) -> Option<ContentBlock> {
        let typ = v.get("type")?.as_str()?;
        match typ {
            "text" => Some(ContentBlock::Text {
                text: v.get("text")?.as_str()?.to_string(),
            }),
            "tool_use" => Some(ContentBlock::ToolUse {
                id: v.get("id")?.as_str()?.to_string(),
                name: v.get("name")?.as_str()?.to_string(),
                input: v.get("input")?.clone(),
            }),
            _ => None,
        }
    }

    async fn converse_openai(
        &self,
        system: &str,
        messages: &[ConversationMessage],
        tools: &[ToolDef],
    ) -> Result<ConversationResponse> {
        let wire_messages = Self::messages_to_openai(system, messages);
        let wire_tools: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": &t.name,
                        "description": &t.description,
                        "parameters": &t.input_schema,
                    }
                })
            })
            .collect();

        let mut body = json!({
            "model": &self.model,
            "max_tokens": self.max_tokens,
            "messages": wire_messages,
        });
        if !wire_tools.is_empty() {
            body["tools"] = json!(wire_tools);
        }

        let body_str = serde_json::to_string(&body)
            .map_err(|e| Error::parse(format!("serialize converse request: {e}")))?;

        let url = format!("{}/chat/completions", self.base_url);
        let response_text = self
            .http
            .post_json_raw(
                &url,
                &body_str,
                &[("Authorization", &format!("Bearer {}", self.api_key))],
            )
            .await
            .map_err(|e| {
                warn!("OpenAI converse error: {e}");
                e
            })?;

        let resp: OpenAiConvResponse = serde_json::from_str(&response_text).map_err(|e| {
            Error::parse(format!(
                "parse OpenAI converse response: {e}\nraw: {response_text}"
            ))
        })?;

        let choice = resp
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| Error::parse("empty choices in converse response"))?;

        let mut content = Vec::new();
        if let Some(text) = choice.message.content
            && !text.is_empty()
        {
            content.push(ContentBlock::Text { text });
        }
        if let Some(tool_calls) = choice.message.tool_calls {
            for tc in tool_calls {
                let input: Value = serde_json::from_str(&tc.function.arguments)
                    .unwrap_or_else(|_| json!({"_raw": tc.function.arguments}));
                content.push(ContentBlock::ToolUse {
                    id: tc.id,
                    name: tc.function.name,
                    input,
                });
            }
        }

        let stop_reason = match choice.finish_reason.as_deref() {
            Some("tool_calls") => StopReason::ToolUse,
            Some("length") => StopReason::MaxTokens,
            _ => StopReason::EndTurn,
        };
        let usage = resp
            .usage
            .map(|u| Usage {
                input_tokens: u.prompt_tokens,
                output_tokens: u.completion_tokens,
            })
            .unwrap_or_default();

        Ok(ConversationResponse {
            content,
            stop_reason,
            usage,
        })
    }

    fn messages_to_openai(system: &str, messages: &[ConversationMessage]) -> Vec<Value> {
        let mut wire = vec![json!({"role": "system", "content": system})];

        for msg in messages {
            match msg.role {
                Role::User => {
                    // Tool results → separate "tool" role messages
                    let tool_results: Vec<_> = msg
                        .content
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::ToolResult {
                                tool_use_id,
                                content,
                                ..
                            } => Some((tool_use_id, content)),
                            _ => None,
                        })
                        .collect();

                    if !tool_results.is_empty() {
                        for (tool_use_id, content) in tool_results {
                            wire.push(json!({
                                "role": "tool",
                                "tool_call_id": tool_use_id,
                                "content": content,
                            }));
                        }
                    } else {
                        let text: String = msg
                            .content
                            .iter()
                            .filter_map(|b| match b {
                                ContentBlock::Text { text } => Some(text.as_str()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        wire.push(json!({"role": "user", "content": text}));
                    }
                }
                Role::Assistant => {
                    let text: String = msg
                        .content
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::Text { text } => Some(text.clone()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("\n");

                    let tool_calls: Vec<Value> = msg
                        .content
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::ToolUse { id, name, input } => Some(json!({
                                "id": id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": input.to_string(),
                                },
                            })),
                            _ => None,
                        })
                        .collect();

                    let mut message = json!({"role": "assistant"});
                    if !text.is_empty() {
                        message["content"] = json!(text);
                    } else {
                        message["content"] = Value::Null;
                    }
                    if !tool_calls.is_empty() {
                        message["tool_calls"] = json!(tool_calls);
                    }
                    wire.push(message);
                }
            }
        }

        wire
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

// -- Task-based model routing --

/// What kind of LLM task is being performed — determines which model to use.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum TaskKind {
    /// Narrative synthesis: fast, structured JSON output.
    NarrativeSynthesis,
    /// Deep security investigation: best reasoning, code analysis.
    DeepInvestigation,
    /// Adversarial finding validation.
    Validation,
    /// Cross-reference analysis between narratives and findings.
    CrossReference,
}

/// Routes LLM requests to different models based on task kind.
pub struct ModelRouter {
    clients: HashMap<TaskKind, LlmClient>,
    default: LlmClient,
}

impl ModelRouter {
    pub fn new(default: LlmClient) -> Self {
        Self {
            clients: HashMap::new(),
            default,
        }
    }

    pub fn with_client(mut self, kind: TaskKind, client: LlmClient) -> Self {
        self.clients.insert(kind, client);
        self
    }

    /// Get the LLM client for a specific task kind. Falls back to the default.
    pub fn client_for(&self, kind: TaskKind) -> &LlmClient {
        self.clients.get(&kind).unwrap_or(&self.default)
    }

    /// Get the default LLM client.
    #[allow(dead_code)]
    pub fn default_client(&self) -> &LlmClient {
        &self.default
    }
}

/// Estimate cost in USD for a single API call based on token usage and model.
///
/// Rates are approximate — verify against provider pricing pages.
pub fn estimate_cost_usd(usage: &Usage, model: &str) -> f64 {
    // Per-million-token rates (input, output)
    let (input_per_m, output_per_m) = match model {
        m if m.contains("opus") => (15.0, 75.0),
        m if m.contains("sonnet") => (3.0, 15.0),
        m if m.contains("haiku") => (0.25, 1.25),
        m if m.contains("gpt-4o") => (2.50, 10.0),
        m if m.contains("gpt-4") => (10.0, 30.0),
        m if m.contains(":free") => (0.0, 0.0),
        _ => (1.0, 2.0), // conservative default for unknown models
    };
    (usage.input_tokens as f64 * input_per_m + usage.output_tokens as f64 * output_per_m)
        / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_strips_json_fences() {
        assert_eq!(extract_json("```json\n{\"a\":1}\n```"), "{\"a\":1}");
    }

    #[test]
    fn extract_json_strips_bare_fences_with_json() {
        assert_eq!(extract_json("```\n{\"a\":1}\n```"), "{\"a\":1}");
    }

    #[test]
    fn extract_json_embedded_object() {
        let input = "some text {\"a\":1} more text";
        assert_eq!(extract_json(input), "{\"a\":1}");
    }

    #[test]
    fn extract_json_no_json_returns_input() {
        assert_eq!(extract_json("no json here"), "no json here");
    }

    #[test]
    fn extract_json_array_in_fences() {
        assert_eq!(extract_json("```json\n[1,2,3]\n```"), "[1,2,3]");
    }

    #[test]
    fn estimate_cost_opus() {
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
        };
        let cost = estimate_cost_usd(&usage, "claude-opus-4-20250514");
        assert!((cost - 0.0525).abs() < f64::EPSILON);
    }

    #[test]
    fn estimate_cost_free_model() {
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
        };
        let cost = estimate_cost_usd(&usage, "arcee-ai/trinity:free");
        assert!((cost - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn estimate_cost_unknown_model() {
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
        };
        let cost = estimate_cost_usd(&usage, "some-unknown-model");
        assert!((cost - 0.002).abs() < f64::EPSILON);
    }

    #[test]
    fn estimate_cost_sonnet() {
        let usage = Usage {
            input_tokens: 1000,
            output_tokens: 500,
        };
        let cost = estimate_cost_usd(&usage, "claude-sonnet-4-20250514");
        assert!((cost - 0.0105).abs() < f64::EPSILON);
    }

    #[test]
    fn estimate_cost_zero_tokens() {
        let zero = Usage {
            input_tokens: 0,
            output_tokens: 0,
        };
        assert!((estimate_cost_usd(&zero, "opus") - 0.0).abs() < f64::EPSILON);
    }
}
