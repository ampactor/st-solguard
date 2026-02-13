//! Second-pass finding verification: an LLM attempts to DISPROVE each finding
//! from the initial investigation, producing a verdict (Confirmed / Disputed /
//! Dismissed) with reasoning.

use super::SecurityFinding;
use super::ValidationStatus;
use super::agent_review::AgentFinding;
use crate::config::AgentReviewConfig;
use crate::llm::{
    ContentBlock, ConversationMessage, LlmClient, ModelRouter, Role, StopReason, TaskKind,
    estimate_cost_usd,
};
use crate::security::agent_tools;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Verdict {
    Confirmed,
    Disputed,
    Dismissed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedFinding {
    pub finding: AgentFinding,
    pub verdict: Verdict,
    pub reasoning: String,
}

/// Intermediate deserialization target for the LLM's JSON output.
#[derive(Deserialize)]
struct VerdictEntry {
    title: String,
    verdict: String,
    reasoning: String,
}

const VALIDATOR_PROMPT: &str = r#"You are a security auditor reviewing another auditor's findings against a Solana program repository. Your job is adversarial: for each finding below, use the provided tools to read the cited code and try to DISPROVE it.

For each finding, check:
- Is there a check elsewhere in the codebase that prevents the described attack?
- Is the severity overstated given the actual code context?
- Can you construct a concrete defense or mitigation that already exists?
- Is the cited code actually reachable from an instruction handler?
- Are the assumptions about account ownership / signing correct?

For each finding, determine a verdict:
- **Confirmed**: The vulnerability is real. You found supporting evidence or could not find any mitigation.
- **Disputed**: The vulnerability might be real but you found partial mitigations, the attack scenario is unlikely, or the severity is overstated.
- **Dismissed**: The vulnerability is a false positive. You found concrete evidence that disproves it (e.g. a check in a parent function, unreachable code, incorrect assumptions about account types).

After investigating with the tools, respond with a JSON array:
```json
[{"title": "<finding title>", "verdict": "Confirmed|Disputed|Dismissed", "reasoning": "<your analysis>"}]
```

Be thorough. Read the actual code paths. Do not rubber-stamp findings — your value is in catching false positives and overstated severity."#;

/// Validate a set of findings by running an adversarial second-pass LLM review.
///
/// Returns one `ValidatedFinding` per input finding. Findings the validator
/// does not mention get `Verdict::Disputed` with a default reasoning string.
pub async fn validate(
    llm: &LlmClient,
    repo_path: &Path,
    findings: &[AgentFinding],
    config: &AgentReviewConfig,
) -> Result<Vec<ValidatedFinding>> {
    if findings.is_empty() {
        return Ok(Vec::new());
    }

    let tools = agent_tools::tool_definitions();
    let mut messages: Vec<ConversationMessage> = Vec::new();
    let mut turns: u32 = 0;
    let mut total_cost_usd: f64 = 0.0;
    let max_turns = config.max_turns.min(15);

    // Build initial user message with the findings as JSON.
    let findings_json =
        serde_json::to_string_pretty(findings).unwrap_or_else(|_| format!("{findings:?}"));
    let initial_msg = format!(
        "Review the following {} security finding(s) against the repository at '{}'.\n\n\
         For each finding, use the tools to read the cited code and determine whether \
         the vulnerability is real, overstated, or a false positive.\n\n\
         Findings:\n```json\n{}\n```",
        findings.len(),
        repo_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into()),
        findings_json,
    );

    messages.push(ConversationMessage {
        role: Role::User,
        content: vec![ContentBlock::Text { text: initial_msg }],
    });

    info!(
        findings = findings.len(),
        max_turns,
        cost_limit = config.cost_limit_usd,
        "starting validator pass"
    );

    // Conversation loop — mirrors investigate() in agent_review.rs.
    loop {
        if turns >= max_turns {
            warn!(turns, "validator hit max turns, extracting verdicts");
            break;
        }
        if total_cost_usd >= config.cost_limit_usd {
            warn!(cost = total_cost_usd, "validator hit cost limit");
            break;
        }

        let response = match llm.converse(VALIDATOR_PROMPT, &messages, &tools).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "validator converse failed");
                if turns > 0 {
                    break;
                }
                return Err(e.into());
            }
        };

        turns += 1;
        let cost = estimate_cost_usd(&response.usage, llm.model());
        total_cost_usd += cost;

        debug!(
            turn = turns,
            stop = ?response.stop_reason,
            cost = format!("${:.4}", total_cost_usd),
            "validator turn"
        );

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

        messages.push(ConversationMessage {
            role: Role::Assistant,
            content: response.content,
        });

        if response.stop_reason == StopReason::EndTurn || tool_uses.is_empty() {
            debug!("validator finished, extracting verdicts");
            break;
        }

        // Execute tools.
        let mut tool_results = Vec::new();
        for (id, name, input) in &tool_uses {
            debug!(tool = %name, "validator executing tool");
            let (result, is_error) = agent_tools::dispatch(repo_path, name, input);
            tool_results.push(ContentBlock::ToolResult {
                tool_use_id: id.clone(),
                content: result,
                is_error,
            });
        }

        messages.push(ConversationMessage {
            role: Role::User,
            content: tool_results,
        });
    }

    // Extract verdicts from the last assistant text block.
    let mut verdicts = extract_verdicts(&messages);

    // If no verdicts extracted, force one final turn without tools.
    if verdicts.is_empty() {
        info!("no verdicts extracted, forcing summary turn");
        messages.push(ConversationMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "You have run out of investigation turns. Based on everything you have \
                       read so far, produce your final verdicts NOW as a JSON array. \
                       Each entry must have: title, verdict (Confirmed|Disputed|Dismissed), reasoning."
                    .into(),
            }],
        });
        if let Ok(response) = llm.converse(VALIDATOR_PROMPT, &messages, &[]).await {
            let cost = estimate_cost_usd(&response.usage, llm.model());
            total_cost_usd += cost;
            turns += 1;
            for block in &response.content {
                if let ContentBlock::Text { text } = block {
                    let preview: String = text.chars().take(500).collect();
                    info!(len = text.len(), "forced validator response: {preview}");
                }
            }
            messages.push(ConversationMessage {
                role: Role::Assistant,
                content: response.content,
            });
            verdicts = extract_verdicts(&messages);
            info!(
                verdicts = verdicts.len(),
                "forced validator summary extracted"
            );
        }
    }

    // Match verdicts to input findings.
    let validated: Vec<ValidatedFinding> = findings
        .iter()
        .map(|f| {
            let matched = verdicts.iter().find(|v| {
                let vt = v.title.to_lowercase();
                let ft = f.title.to_lowercase();
                ft.contains(&vt) || vt.contains(&ft)
            });

            match matched {
                Some(v) => ValidatedFinding {
                    finding: f.clone(),
                    verdict: parse_verdict(&v.verdict),
                    reasoning: v.reasoning.clone(),
                },
                None => ValidatedFinding {
                    finding: f.clone(),
                    verdict: Verdict::Disputed,
                    reasoning: "No verdict provided by validator".into(),
                },
            }
        })
        .collect();

    info!(
        validated = validated.len(),
        turns,
        cost = format!("${:.4}", total_cost_usd),
        "validator pass complete"
    );

    Ok(validated)
}

/// Validate findings in-place using the ModelRouter, then filter/downgrade.
///
/// - Annotates each `SecurityFinding` with `ValidationStatus` and `validation_reasoning`
/// - Removes findings with `Dismissed` status
/// - Downgrades severity by one level for `Disputed` findings
pub async fn validate_findings(
    findings: &mut Vec<SecurityFinding>,
    router: &ModelRouter,
    repo_path: &Path,
    config: &AgentReviewConfig,
) -> Result<()> {
    if findings.is_empty() {
        return Ok(());
    }

    let llm = router.client_for(TaskKind::Validation);
    let tools = agent_tools::tool_definitions();
    let mut messages: Vec<ConversationMessage> = Vec::new();
    let mut turns: u32 = 0;
    let mut total_cost_usd: f64 = 0.0;
    let max_turns = config.max_turns.min(15);

    // Build initial user message with findings JSON.
    let findings_json =
        serde_json::to_string_pretty(&*findings).unwrap_or_else(|_| format!("{findings:?}"));
    let initial_msg = format!(
        "Review the following {} security finding(s) against the repository at '{}'.\n\n\
         For each finding, use the tools to read the cited code and determine whether \
         the vulnerability is real, overstated, or a false positive.\n\n\
         Findings:\n```json\n{}\n```",
        findings.len(),
        repo_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into()),
        findings_json,
    );

    messages.push(ConversationMessage {
        role: Role::User,
        content: vec![ContentBlock::Text { text: initial_msg }],
    });

    info!(
        findings = findings.len(),
        max_turns,
        cost_limit = config.cost_limit_usd,
        "starting validate_findings pass"
    );

    // Conversation loop — mirrors the existing validate() logic.
    loop {
        if turns >= max_turns {
            warn!(turns, "validate_findings hit max turns");
            break;
        }
        if total_cost_usd >= config.cost_limit_usd {
            warn!(cost = total_cost_usd, "validate_findings hit cost limit");
            break;
        }

        let response = match llm.converse(VALIDATOR_PROMPT, &messages, &tools).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "validate_findings converse failed");
                if turns > 0 {
                    break;
                }
                return Err(e.into());
            }
        };

        turns += 1;
        let cost = estimate_cost_usd(&response.usage, llm.model());
        total_cost_usd += cost;

        debug!(
            turn = turns,
            stop = ?response.stop_reason,
            cost = format!("${:.4}", total_cost_usd),
            "validate_findings turn"
        );

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

        messages.push(ConversationMessage {
            role: Role::Assistant,
            content: response.content,
        });

        if response.stop_reason == StopReason::EndTurn || tool_uses.is_empty() {
            debug!("validate_findings finished, extracting verdicts");
            break;
        }

        let mut tool_results = Vec::new();
        for (id, name, input) in &tool_uses {
            debug!(tool = %name, "validate_findings executing tool");
            let (result, is_error) = agent_tools::dispatch(repo_path, name, input);
            tool_results.push(ContentBlock::ToolResult {
                tool_use_id: id.clone(),
                content: result,
                is_error,
            });
        }

        messages.push(ConversationMessage {
            role: Role::User,
            content: tool_results,
        });
    }

    let mut verdicts = extract_verdicts(&messages);

    // Force a summary turn if no verdicts extracted.
    if verdicts.is_empty() {
        info!("no verdicts extracted in validate_findings, forcing summary turn");
        messages.push(ConversationMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "You have run out of investigation turns. Based on everything you have \
                       read so far, produce your final verdicts NOW as a JSON array. \
                       Each entry must have: title, verdict (Confirmed|Disputed|Dismissed), reasoning."
                    .into(),
            }],
        });
        if let Ok(response) = llm.converse(VALIDATOR_PROMPT, &messages, &[]).await {
            let cost = estimate_cost_usd(&response.usage, llm.model());
            total_cost_usd += cost;
            turns += 1;
            messages.push(ConversationMessage {
                role: Role::Assistant,
                content: response.content,
            });
            verdicts = extract_verdicts(&messages);
        }
    }

    // Annotate findings in-place.
    for finding in findings.iter_mut() {
        let matched = verdicts.iter().find(|v| {
            let vt = v.title.to_lowercase();
            let ft = finding.title.to_lowercase();
            ft.contains(&vt) || vt.contains(&ft)
        });

        match matched {
            Some(v) => {
                finding.validation_status = match parse_verdict(&v.verdict) {
                    Verdict::Confirmed => ValidationStatus::Confirmed,
                    Verdict::Disputed => ValidationStatus::Disputed,
                    Verdict::Dismissed => ValidationStatus::Dismissed,
                };
                finding.validation_reasoning = Some(v.reasoning.clone());
            }
            None => {
                finding.validation_status = ValidationStatus::Disputed;
                finding.validation_reasoning = Some("No verdict provided by validator".into());
            }
        }
    }

    // Remove Dismissed findings.
    findings.retain(|f| f.validation_status != ValidationStatus::Dismissed);

    // Downgrade severity for Disputed findings.
    for finding in findings.iter_mut() {
        if finding.validation_status == ValidationStatus::Disputed {
            finding.severity = downgrade_severity(&finding.severity);
        }
    }

    info!(
        remaining = findings.len(),
        turns,
        cost = format!("${:.4}", total_cost_usd),
        "validate_findings pass complete"
    );

    Ok(())
}

fn downgrade_severity(severity: &str) -> String {
    match severity {
        "Critical" => "High".into(),
        "High" => "Medium".into(),
        "Medium" => "Low".into(),
        _ => "Info".into(),
    }
}

fn parse_verdict(s: &str) -> Verdict {
    match s.to_lowercase().as_str() {
        "confirmed" => Verdict::Confirmed,
        "dismissed" => Verdict::Dismissed,
        _ => Verdict::Disputed,
    }
}

/// Search assistant messages in reverse for a JSON verdicts array.
fn extract_verdicts(messages: &[ConversationMessage]) -> Vec<VerdictEntry> {
    for msg in messages.iter().rev() {
        if msg.role != Role::Assistant {
            continue;
        }
        for block in &msg.content {
            if let ContentBlock::Text { text } = block
                && let Some(entries) = try_parse_verdicts(text)
            {
                return entries;
            }
        }
    }

    warn!("could not extract structured verdicts from validator conversation");
    Vec::new()
}

/// Try to parse a JSON array of VerdictEntry from text, handling markdown fences.
fn try_parse_verdicts(text: &str) -> Option<Vec<VerdictEntry>> {
    // ```json ... ```
    if let Some(start) = text.find("```json") {
        let content = &text[start + 7..];
        if let Some(end) = content.find("```") {
            let json_str = content[..end].trim();
            if let Ok(entries) = serde_json::from_str::<Vec<VerdictEntry>>(json_str) {
                return Some(entries);
            }
        }
    }

    // Bare ``` fences
    if let Some(start) = text.find("```") {
        let content = &text[start + 3..];
        if let Some(end) = content.find("```") {
            let inner = content[..end].trim();
            if inner.starts_with('[')
                && let Ok(entries) = serde_json::from_str::<Vec<VerdictEntry>>(inner)
            {
                return Some(entries);
            }
        }
    }

    // Bare JSON array
    if let Some(start) = text.find('[')
        && let Some(end) = text.rfind(']')
    {
        let json_str = &text[start..=end];
        if let Ok(entries) = serde_json::from_str::<Vec<VerdictEntry>>(json_str) {
            return Some(entries);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_verdict --

    #[test]
    fn verdict_confirmed_lowercase() {
        assert!(matches!(parse_verdict("confirmed"), Verdict::Confirmed));
    }

    #[test]
    fn verdict_confirmed_mixed_case() {
        assert!(matches!(parse_verdict("Confirmed"), Verdict::Confirmed));
    }

    #[test]
    fn verdict_dismissed_lowercase() {
        assert!(matches!(parse_verdict("dismissed"), Verdict::Dismissed));
    }

    #[test]
    fn verdict_dismissed_mixed_case() {
        assert!(matches!(parse_verdict("Dismissed"), Verdict::Dismissed));
    }

    #[test]
    fn verdict_disputed() {
        assert!(matches!(parse_verdict("disputed"), Verdict::Disputed));
    }

    #[test]
    fn verdict_unknown_falls_back_to_disputed() {
        assert!(matches!(parse_verdict("unknown"), Verdict::Disputed));
    }

    #[test]
    fn verdict_empty_falls_back_to_disputed() {
        assert!(matches!(parse_verdict(""), Verdict::Disputed));
    }

    // -- downgrade_severity --

    #[test]
    fn downgrade_critical() {
        assert_eq!(downgrade_severity("Critical"), "High");
    }

    #[test]
    fn downgrade_high() {
        assert_eq!(downgrade_severity("High"), "Medium");
    }

    #[test]
    fn downgrade_medium() {
        assert_eq!(downgrade_severity("Medium"), "Low");
    }

    #[test]
    fn downgrade_low() {
        assert_eq!(downgrade_severity("Low"), "Info");
    }

    #[test]
    fn downgrade_info() {
        assert_eq!(downgrade_severity("Info"), "Info");
    }

    // -- try_parse_verdicts --

    const SAMPLE_VERDICT_JSON: &str = r#"[{"title":"Missing Signer","verdict":"Confirmed","reasoning":"The check is indeed missing"}]"#;

    #[test]
    fn parse_verdicts_json_fence() {
        let text = format!("```json\n{}\n```", SAMPLE_VERDICT_JSON);
        let entries = try_parse_verdicts(&text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Missing Signer");
        assert_eq!(entries[0].verdict, "Confirmed");
    }

    #[test]
    fn parse_verdicts_bare_fence() {
        let text = format!("```\n{}\n```", SAMPLE_VERDICT_JSON);
        let entries = try_parse_verdicts(&text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Missing Signer");
    }

    #[test]
    fn parse_verdicts_bare_json() {
        let entries = try_parse_verdicts(SAMPLE_VERDICT_JSON).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].verdict, "Confirmed");
    }

    #[test]
    fn parse_verdicts_empty_array() {
        let entries = try_parse_verdicts("[]").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_verdicts_no_json() {
        assert!(try_parse_verdicts("No issues found.").is_none());
    }

    #[test]
    fn parse_verdicts_malformed() {
        assert!(try_parse_verdicts("[{broken").is_none());
    }
}
