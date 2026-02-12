//! Multi-turn agent review: an LLM investigates a repository using tools,
//! following call chains and reasoning about trust models to find real
//! vulnerabilities.
//!
//! The agent loop sends the conversation to the LLM, executes tool calls,
//! appends results, and repeats until the LLM produces a final answer or
//! a hard stop is hit (max turns, cost limit).

use crate::config::AgentReviewConfig;
use crate::llm::{
    ContentBlock, ConversationMessage, LlmClient, Role, StopReason, Usage, estimate_cost_usd,
};
use crate::security::agent_tools;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info, warn};

/// A verified finding from the agent review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFinding {
    pub title: String,
    pub severity: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub attack_scenario: String,
    pub remediation: String,
    pub confidence: f64,
    pub affected_files: Vec<String>,
}

/// Cumulative cost and usage stats for an agent review session.
#[derive(Debug, Default)]
pub struct ReviewStats {
    pub turns: u32,
    pub total_input_tokens: u32,
    pub total_output_tokens: u32,
    pub total_cost_usd: f64,
    pub tool_calls: u32,
}

impl ReviewStats {
    fn accumulate(&mut self, usage: &Usage, model: &str) {
        self.turns += 1;
        self.total_input_tokens += usage.input_tokens;
        self.total_output_tokens += usage.output_tokens;
        self.total_cost_usd += estimate_cost_usd(usage, model);
    }
}

const SYSTEM_PROMPT: &str = r#"You are an expert Solana smart contract security auditor. You have access to tools that let you read and search the repository's source code.

## Investigation Methodology

You are looking for REAL, EXPLOITABLE vulnerabilities — not style issues or theoretical concerns. Your investigation must follow this methodology:

### 1. Understand the Program's Trust Model
- Read the program's entry points (processor, instruction handlers)
- Identify which accounts are trusted (signers, PDAs, program-owned) vs untrusted (user-provided)
- Map the authority/ownership hierarchy: who can do what?

### 2. Trace Fund Flows
- Find all token transfers, SOL transfers, and account closures
- For each: who authorizes it? What checks gate it? Can any check be bypassed?
- Follow the FULL call chain from instruction handler to CPI call

### 3. Look for Trust Boundary Violations
- Accounts passed to CPI calls: are they validated before use?
- PDA derivation: are all seeds verified? Can an attacker supply a different PDA?
- Account reinitialization: can closed accounts be reopened?
- Remaining accounts: are they validated or used blindly?

### 4. Check Arithmetic Safety
- Token amount calculations: overflow/underflow possible?
- Fee calculations: rounding that benefits attacker?
- Division before multiplication causing precision loss?

### 5. Verify State Transitions
- Can instructions be called in unexpected order?
- Are state flags checked before sensitive operations?
- Can an attacker front-run or sandwich transactions?

## CRITICAL Rules

- Only report findings you can trace through actual code. NO hypothetical vulnerabilities.
- For each finding, you MUST identify the specific file(s) and line(s) where the vulnerability exists.
- Start by reading the top-level structure (Cargo.toml, lib.rs or main entry point) to understand the program architecture.
- Follow cross-file references — most real vulnerabilities span multiple files.
- Read complete functions, not just signatures. The vulnerability is usually in the implementation details.
- If scanner triage results are provided, investigate each one but be skeptical — most are false positives. Verify by reading the actual code context.

## Output Format

When you have completed your investigation, output your findings as a JSON array. Each finding must have this structure:

```json
[
  {
    "title": "Short descriptive title",
    "severity": "Critical|High|Medium|Low|Info",
    "description": "What the vulnerability is and why it matters",
    "evidence": ["file.rs:42 — the unchecked transfer", "other_file.rs:100 — missing validation"],
    "attack_scenario": "Step-by-step how an attacker exploits this",
    "remediation": "Specific code change to fix it",
    "confidence": 0.95,
    "affected_files": ["programs/vault/src/processor.rs", "programs/vault/src/state.rs"]
  }
]
```

If you find NO real vulnerabilities, output an empty array: `[]`

Confidence scale:
- 0.9-1.0: Definite vulnerability, clear exploit path
- 0.7-0.9: Very likely vulnerable, minor uncertainty about exploitability
- 0.5-0.7: Possible vulnerability, needs more context to confirm
- Below 0.5: Don't report it
"#;

/// Run a multi-turn agent investigation of a repository.
///
/// Returns the extracted findings and cumulative session stats.
pub async fn investigate(
    llm: &LlmClient,
    repo_path: &Path,
    config: &AgentReviewConfig,
    triage_context: Option<&str>,
) -> Result<(Vec<AgentFinding>, ReviewStats)> {
    let tools = agent_tools::tool_definitions();
    let mut messages: Vec<ConversationMessage> = Vec::new();
    let mut stats = ReviewStats::default();

    // Build initial user message
    let repo_name = repo_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());

    let mut initial_msg = format!(
        "Investigate the repository '{repo_name}' for security vulnerabilities.\n\n\
         Start by understanding the project structure, then systematically trace \
         trust boundaries and fund flows. Focus on finding REAL, exploitable \
         vulnerabilities with clear evidence.\n\n\
         Begin by listing the top-level files and reading the main entry point."
    );

    if let Some(triage) = triage_context {
        initial_msg.push_str(&format!(
            "\n\n## Scanner Triage Results (verify each — most are false positives)\n\n{triage}"
        ));
    }

    messages.push(ConversationMessage {
        role: Role::User,
        content: vec![ContentBlock::Text { text: initial_msg }],
    });

    info!(
        repo = %repo_name,
        max_turns = config.max_turns,
        cost_limit = config.cost_limit_usd,
        "starting agent investigation"
    );

    // Agent loop
    loop {
        // Hard stop: max turns
        if stats.turns >= config.max_turns {
            warn!(
                turns = stats.turns,
                "hit max turns limit, extracting findings"
            );
            break;
        }

        // Hard stop: cost limit
        if stats.total_cost_usd >= config.cost_limit_usd {
            warn!(
                cost = stats.total_cost_usd,
                limit = config.cost_limit_usd,
                "hit cost limit, extracting findings"
            );
            break;
        }

        // Send conversation to LLM
        let response = match llm.converse(SYSTEM_PROMPT, &messages, &tools).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "LLM converse failed");
                // If we already have some conversation, try to extract findings
                if stats.turns > 0 {
                    break;
                }
                return Err(e.into());
            }
        };

        stats.accumulate(&response.usage, llm.model());

        debug!(
            turn = stats.turns,
            stop = ?response.stop_reason,
            cost = format!("${:.4}", stats.total_cost_usd),
            "agent turn"
        );

        // Check if the response contains tool use calls
        let tool_uses: Vec<_> = response
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::ToolUse { id, name, input } => {
                    Some((id.clone(), name.clone(), input.clone()))
                }
                _ => None,
            })
            .collect();

        // Add assistant message to history
        messages.push(ConversationMessage {
            role: Role::Assistant,
            content: response.content,
        });

        if response.stop_reason == StopReason::EndTurn || tool_uses.is_empty() {
            // LLM is done — extract findings from the last text block
            debug!("agent finished (end_turn), extracting findings");
            break;
        }

        // Execute tools and collect results
        let mut tool_results = Vec::new();
        for (id, name, input) in &tool_uses {
            stats.tool_calls += 1;
            debug!(tool = %name, "executing tool");

            let (result, is_error) = agent_tools::dispatch(repo_path, name, input);
            tool_results.push(ContentBlock::ToolResult {
                tool_use_id: id.clone(),
                content: result,
                is_error,
            });
        }

        // Add tool results as user message
        messages.push(ConversationMessage {
            role: Role::User,
            content: tool_results,
        });
    }

    // Extract findings from the conversation
    let findings = extract_findings(&messages);

    info!(
        findings = findings.len(),
        turns = stats.turns,
        tool_calls = stats.tool_calls,
        cost = format!("${:.4}", stats.total_cost_usd),
        "agent investigation complete"
    );

    Ok((findings, stats))
}

/// Extract structured findings from the agent's conversation.
///
/// Looks for JSON arrays in the last assistant text block, falling back
/// to scanning earlier messages if the final message doesn't contain findings.
fn extract_findings(messages: &[ConversationMessage]) -> Vec<AgentFinding> {
    // Search assistant messages in reverse order for a JSON findings array
    for msg in messages.iter().rev() {
        if msg.role != Role::Assistant {
            continue;
        }
        for block in &msg.content {
            if let ContentBlock::Text { text } = block
                && let Some(findings) = try_parse_findings(text)
            {
                return findings;
            }
        }
    }

    warn!("could not extract structured findings from agent conversation");
    Vec::new()
}

/// Try to parse a JSON findings array from text, handling markdown fences.
fn try_parse_findings(text: &str) -> Option<Vec<AgentFinding>> {
    // Try extracting from ```json ... ``` fences first
    if let Some(start) = text.find("```json") {
        let content = &text[start + 7..];
        if let Some(end) = content.find("```") {
            let json_str = content[..end].trim();
            if let Ok(findings) = serde_json::from_str::<Vec<AgentFinding>>(json_str) {
                return Some(findings);
            }
        }
    }

    // Try bare ``` fences
    if let Some(start) = text.find("```") {
        let content = &text[start + 3..];
        if let Some(end) = content.find("```") {
            let inner = content[..end].trim();
            if inner.starts_with('[')
                && let Ok(findings) = serde_json::from_str::<Vec<AgentFinding>>(inner)
            {
                return Some(findings);
            }
        }
    }

    // Try to find a bare JSON array
    if let Some(start) = text.find('[')
        && let Some(end) = text.rfind(']')
    {
        let json_str = &text[start..=end];
        if let Ok(findings) = serde_json::from_str::<Vec<AgentFinding>>(json_str) {
            return Some(findings);
        }
    }

    None
}

/// Convert scanner findings into triage context text for the agent.
pub fn format_triage_context(findings: &[super::SecurityFinding]) -> String {
    if findings.is_empty() {
        return "No scanner findings to verify.".into();
    }

    let mut out = String::new();
    for (i, f) in findings.iter().enumerate() {
        out.push_str(&format!(
            "{}. [{}] {} — {}\n   File: {}:{}\n   Remediation: {}\n\n",
            i + 1,
            f.severity,
            f.title,
            f.description,
            f.file_path.display(),
            f.line_number,
            f.remediation,
        ));
    }
    out
}
