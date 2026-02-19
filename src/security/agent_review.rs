//! Multi-turn agent review: an LLM investigates a repository using tools,
//! following call chains and reasoning about trust models to find real
//! vulnerabilities.
//!
//! The agent loop sends the conversation to the LLM, executes tool calls,
//! appends results, and repeats until the LLM produces a final answer or
//! a hard stop is hit (max turns, cost limit).

use crate::config::AgentReviewConfig;
use crate::llm::{
    ContentBlock, ConversationMessage, ConverseContext, LlmClient, Role, StopReason, Usage,
    estimate_cost_usd,
};
use crate::security::agent_tools;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::Path;
use tracing::{info, warn};

/// Context from narrative detection to focus the security scan.
pub struct ScanContext {
    pub protocol_category: Option<String>,
    pub narrative_summary: Option<String>,
    pub sibling_findings: Vec<String>,
}

/// Compute investigation budget based on narrative confidence and target count.
pub fn compute_budget(confidence: f64, repo_count: usize) -> (u32, f64) {
    let depth = confidence * (1.0 / (repo_count as f64).sqrt());
    (
        (30.0 * depth).clamp(5.0, 40.0) as u32, // max_turns
        (20.0 * depth).clamp(2.0, 30.0),        // cost_limit_usd
    )
}

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
    scan_context: Option<&ScanContext>,
) -> Result<(Vec<AgentFinding>, ReviewStats)> {
    let tools = agent_tools::tool_definitions();
    let mut messages: Vec<ConversationMessage> = Vec::new();
    let mut stats = ReviewStats::default();

    // Build initial user message
    let repo_name = repo_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());

    let repo_abs = repo_path
        .canonicalize()
        .unwrap_or_else(|_| repo_path.to_path_buf());
    let mut initial_msg = format!(
        "Investigate the Solana program repository at `{}`.\n\
         The code is on your local filesystem. Use Read, Grep, and Glob tools to explore it.\n\n\
         Start by understanding the project structure, then systematically trace \
         trust boundaries and fund flows. Focus on finding REAL, exploitable \
         vulnerabilities with clear evidence.\n\n\
         Begin by listing the top-level files and reading the main entry point.",
        repo_abs.display()
    );

    if let Some(triage) = triage_context {
        initial_msg.push_str(&format!(
            "\n\n## Scanner Leads (automated pattern matches — verify by reading actual code)\n\
             These are surface-level regex hits. Most are false positives. For each:\n\
             READ the cited file to determine if the pattern indicates a real vulnerability.\n\
             Then investigate BEYOND these leads for architectural issues patterns can't detect.\n\n\
             {triage}"
        ));
    }

    if let Some(ctx) = scan_context {
        if let Some(ref category) = ctx.protocol_category {
            let focus = match category.to_lowercase().as_str() {
                cat if cat.contains("dex") || cat.contains("amm") || cat.contains("swap") => {
                    "Focus areas: sandwich attack vectors, LP manipulation, price oracle dependencies, slippage calculations, front-running opportunities"
                }
                cat if cat.contains("lend") || cat.contains("borrow") => {
                    "Focus areas: liquidation logic correctness, interest rate manipulation, collateral valuation, bad debt scenarios, flash loan interactions"
                }
                cat if cat.contains("privacy") || cat.contains("mixer") => {
                    "Focus areas: Merkle root commitment integrity, cryptographic proof verification, nullifier handling, deposit/withdrawal privacy guarantees"
                }
                cat if cat.contains("stak") || cat.contains("liquid") => {
                    "Focus areas: reward distribution fairness, unstake timing attacks, slashing condition handling, validator selection manipulation"
                }
                cat if cat.contains("nft") || cat.contains("market") => {
                    "Focus areas: royalty bypass, listing/delisting race conditions, bid manipulation, metadata integrity"
                }
                _ => {
                    "Focus areas: access control, fund flow authorization, state transition integrity"
                }
            };
            initial_msg.push_str(&format!(
                "\n\n## Protocol Context\nCategory: {category}\n{focus}"
            ));
        }
        if let Some(ref summary) = ctx.narrative_summary {
            initial_msg.push_str(&format!("\n\nNarrative context: {summary}"));
        }
        if !ctx.sibling_findings.is_empty() {
            initial_msg.push_str("\n\n## Findings from sibling repos in this narrative:");
            for sf in &ctx.sibling_findings {
                initial_msg.push_str(&format!("\n- {sf}"));
            }
        }
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

    // History for stuck-loop detection: (tool_name, hash_of_input)
    let mut recent_calls: Vec<(String, u64)> = Vec::new();

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
        let ctx = ConverseContext { repo_path };
        let response = match llm
            .converse(SYSTEM_PROMPT, &messages, &tools, Some(&ctx))
            .await
        {
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

        info!(
            cost = format!("${:.4}", stats.total_cost_usd),
            "turn {}/{}: {:?}", stats.turns, config.max_turns, response.stop_reason,
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
            info!("agent finished (end_turn), extracting findings");
            break;
        }

        // Stuck-loop detection: check if any (name, input_hash) appears 3+ times
        let mut stuck = false;
        for (_, name, input) in &tool_uses {
            let mut hasher = DefaultHasher::new();
            input.to_string().hash(&mut hasher);
            let input_hash = hasher.finish();
            recent_calls.push((name.clone(), input_hash));
            let count = recent_calls
                .iter()
                .filter(|(n, h)| n == name && *h == input_hash)
                .count();
            if count >= 3 {
                stuck = true;
                break;
            }
        }

        if stuck {
            info!("stuck loop detected — injecting nudge");
            let mut tool_results = Vec::new();
            for (id, _, _) in &tool_uses {
                tool_results.push(ContentBlock::ToolResult {
                    tool_use_id: id.clone(),
                    content: "You have called the same tool with the same arguments multiple times. Try a different approach or provide your final findings.".into(),
                    is_error: false,
                });
            }
            messages.push(ConversationMessage {
                role: Role::User,
                content: tool_results,
            });
            continue;
        }

        // Execute tools and collect results
        let mut tool_results = Vec::new();
        for (id, name, input) in &tool_uses {
            stats.tool_calls += 1;

            // Guard: malformed tool input
            if !input.is_object() {
                info!(tool = %name, "malformed tool input (not a JSON object)");
                tool_results.push(ContentBlock::ToolResult {
                    tool_use_id: id.clone(),
                    content: "Invalid tool input: expected a JSON object with named parameters"
                        .into(),
                    is_error: true,
                });
                continue;
            }

            info!(tool = %name, "executing tool");

            let (result, is_error) = agent_tools::dispatch(repo_path, name, input);

            // Summarize result for logging
            let summary = summarize_tool_result(name, &result);
            info!(tool = %name, "{summary}");

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
    let mut findings = extract_findings(&messages);

    // If no findings extracted and the model was still investigating (never EndTurned),
    // force one final turn asking for the summary — call converse() without tools so
    // the model MUST produce text.
    if findings.is_empty() {
        info!("no findings extracted, forcing summary turn");
        messages.push(ConversationMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "You have run out of investigation turns. Based on everything you have \
                       read so far, produce your final security findings NOW as a JSON array. \
                       Each finding must have: title, severity, description, evidence, \
                       attack_scenario, remediation, confidence, affected_files."
                    .into(),
            }],
        });
        let ctx = ConverseContext { repo_path };
        if let Ok(response) = llm
            .converse(SYSTEM_PROMPT, &messages, &[], Some(&ctx))
            .await
        {
            stats.accumulate(&response.usage, llm.model());
            // Log what the model actually said for debugging
            for block in &response.content {
                if let ContentBlock::Text { text } = block {
                    let preview: String = text.chars().take(500).collect();
                    info!(len = text.len(), "forced summary response: {preview}");
                }
            }
            messages.push(ConversationMessage {
                role: Role::Assistant,
                content: response.content,
            });
            findings = extract_findings(&messages);
            info!(findings = findings.len(), "forced summary extracted");
        }
    }

    info!(
        findings = findings.len(),
        turns = stats.turns,
        tool_calls = stats.tool_calls,
        cost = format!("${:.4}", stats.total_cost_usd),
        "agent investigation complete"
    );

    Ok((findings, stats))
}

/// Produce a brief log-friendly summary of a tool result.
fn summarize_tool_result(tool: &str, result: &str) -> String {
    match tool {
        "list_files" => {
            let n = result.lines().count();
            format!("listed {n} entries")
        }
        "read_file" => {
            let n = result.lines().count();
            format!("read {n} lines")
        }
        "search_code" => {
            let n = result.lines().count();
            format!("{n} match lines")
        }
        "get_file_structure" => {
            let n = result.lines().count();
            format!("{n} structure items")
        }
        _ => {
            let len = result.len();
            format!("{len} bytes")
        }
    }
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
pub fn try_parse_findings(text: &str) -> Option<Vec<AgentFinding>> {
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
///
/// Caps at top 20 findings sorted by severity to prevent token bloat
/// when static scanners produce hundreds of hits.
pub fn format_triage_context(findings: &[super::SecurityFinding]) -> String {
    if findings.is_empty() {
        return "No scanner findings to verify.".into();
    }

    const MAX_TRIAGE_LEADS: usize = 20;

    let mut ranked: Vec<_> = findings.iter().collect();
    ranked.sort_by(|a, b| {
        super::severity_weight(&b.severity)
            .cmp(&super::severity_weight(&a.severity))
            .then(a.line_number.cmp(&b.line_number))
    });
    let total = ranked.len();
    ranked.truncate(MAX_TRIAGE_LEADS);

    let mut out = String::new();
    for (i, f) in ranked.iter().enumerate() {
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
    if total > MAX_TRIAGE_LEADS {
        out.push_str(&format!(
            "({} additional lower-priority findings omitted)\n",
            total - MAX_TRIAGE_LEADS,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{SecurityFinding, ValidationStatus};
    use std::path::PathBuf;

    // -- compute_budget --

    #[test]
    fn compute_budget_full_confidence_single_repo() {
        let (turns, cost) = compute_budget(1.0, 1);
        // depth = 1.0 * (1.0 / sqrt(1)) = 1.0
        assert_eq!(turns, 30);
        assert!((cost - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_budget_half_confidence_four_repos() {
        let (turns, cost) = compute_budget(0.5, 4);
        // depth = 0.5 * (1.0 / sqrt(4)) = 0.5 * 0.5 = 0.25
        // turns = (30 * 0.25) = 7.5 → 7
        // cost = (20 * 0.25) = 5.0
        assert_eq!(turns, 7);
        assert!((cost - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_budget_clamps_low() {
        let (turns, cost) = compute_budget(1.0, 100);
        // depth = 1.0 / sqrt(100) = 0.1
        // turns = 3.0 → clamped to 5
        // cost = 2.0
        assert_eq!(turns, 5);
        assert!((cost - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_budget_zero_confidence() {
        let (turns, cost) = compute_budget(0.0, 1);
        // depth = 0.0
        // turns = 0 → clamped to 5
        // cost = 0 → clamped to 2.0
        assert_eq!(turns, 5);
        assert!((cost - 2.0).abs() < f64::EPSILON);
    }

    // -- try_parse_findings --

    const SAMPLE_FINDING_JSON: &str = r#"[{"title":"Test","severity":"High","description":"desc","evidence":["file.rs:1"],"attack_scenario":"attacker does X","remediation":"fix Y","confidence":0.9,"affected_files":["src/lib.rs"]}]"#;

    #[test]
    fn parse_findings_json_fence() {
        let text = format!("```json\n{}\n```", SAMPLE_FINDING_JSON);
        let findings = try_parse_findings(&text).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Test");
        assert_eq!(findings[0].severity, "High");
        assert!((findings[0].confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_findings_bare_fence() {
        let text = format!("```\n{}\n```", SAMPLE_FINDING_JSON);
        let findings = try_parse_findings(&text).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Test");
    }

    #[test]
    fn parse_findings_bare_json() {
        let findings = try_parse_findings(SAMPLE_FINDING_JSON).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Test");
    }

    #[test]
    fn parse_findings_prose_then_json() {
        let text = format!("Here are my findings:\n{}", SAMPLE_FINDING_JSON);
        let findings = try_parse_findings(&text).unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn parse_findings_empty_array() {
        let findings = try_parse_findings("[]").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_findings_no_json() {
        assert!(try_parse_findings("I found nothing noteworthy.").is_none());
    }

    #[test]
    fn parse_findings_malformed() {
        assert!(try_parse_findings("[{broken").is_none());
    }

    #[test]
    fn parse_findings_object_not_array() {
        assert!(try_parse_findings(r#"{"title":"Test"}"#).is_none());
    }

    // -- format_triage_context --

    #[test]
    fn triage_context_empty() {
        assert_eq!(format_triage_context(&[]), "No scanner findings to verify.");
    }

    #[test]
    fn triage_context_with_findings() {
        let findings = vec![SecurityFinding {
            title: "Missing Signer".into(),
            severity: "High".into(),
            description: "desc".into(),
            file_path: PathBuf::from("src/lib.rs"),
            line_number: 10,
            remediation: "add check".into(),
            validation_status: ValidationStatus::Unvalidated,
            validation_reasoning: None,
        }];
        let text = format_triage_context(&findings);
        assert!(text.contains("[High]"));
        assert!(text.contains("Missing Signer"));
    }
}
