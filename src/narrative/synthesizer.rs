use super::types::{Metric, TrendDirection};
use crate::error::Result;
use crate::llm::LlmClient;
use serde::Deserialize;
use tracing::info;

const SYSTEM_PROMPT: &str = r#"You are a Solana ecosystem analyst for SolGuard, identifying emerging narratives that connect growth trends with security posture.

A "narrative" is a thematic trend backed by multiple data points across different sources (GitHub developer activity, onchain metrics, social/blog signals). A narrative must appear in 2+ signal sources to be credible.

For each narrative you identify, provide:
1. A clear, specific title — name the protocols, tools, or repos involved (not generic like "DeFi growth" — be specific: "Concentrated Liquidity Migration on Orca and Raydium")
2. A 2-3 sentence summary covering:
   - WHAT is happening (the trend, with numbers)
   - WHY it matters (structural implications — what does this enable or threaten?)
   - SECURITY ANGLE: What does this trend mean for ecosystem security? (e.g., rapid growth in new DeFi protocols = more unaudited code = higher attack surface; validator concentration = centralization risk; new token standards = integration bugs)
3. Confidence score (0.0-1.0) based on signal strength and source diversity
4. Which signal indices support this narrative (from the input data)
5. Trend direction: "Accelerating" (growing faster), "Stable" (steady), "Decelerating" (slowing), "Emerging" (too early to tell, but signals present)
6. Key quantitative metrics that back the narrative
7. Active repositories — pick ONLY from the "discovered_repos" list in the input. Associate each repo with the narrative it most relates to. A repo can appear in multiple narratives if relevant, but don't assign repos to narratives they're unrelated to. If no discovered repos relate to a narrative, use an empty list.

Analysis framework — apply these lenses to each narrative:
- **Historical context:** Is this trend new, or a continuation/acceleration of something established? Reference prior ecosystem state where the data allows.
- **Structural implications:** What does this trend enable or threaten? How does it reshape the ecosystem's architecture?
- **Cross-signal validation:** Do GitHub activity, onchain metrics, and social signals agree? Disagreements are themselves a signal — flag them.
- **Security implications:** Every growth vector has a security shadow. New protocols mean unaudited code. TVL concentration means high-value targets. Developer tooling changes mean new classes of bugs. Name the specific risk.

Respond in JSON:
{
  "narratives": [
    {
      "title": "...",
      "summary": "...",
      "confidence": 0.85,
      "supporting_signals": [0, 3, 7],
      "trend": "Accelerating",
      "key_metrics": [{"name": "...", "value": 123.4, "unit": "..."}],
      "active_repos": ["owner/repo-name", "owner/other-repo"]
    }
  ]
}

Rules:
- Only report narratives you're confident about. Quality over quantity.
- Every claim must be backed by specific signals from the input data.
- Quantify everything. "Growing" is weak; "42% increase in new repos" is strong.
- Name specific protocols, repos, and tools — never hide behind category labels.
- 5-8 narratives is ideal. Fewer if the data doesn't support more.
- Don't invent data. Only use what's in the signals.
- When signals conflict (e.g., GitHub activity up but onchain usage flat), say so explicitly — contradictions reveal more than confirmations."#;

#[derive(Deserialize)]
struct SynthesisResponse {
    narratives: Vec<RawNarrative>,
}

#[derive(Deserialize)]
struct RawNarrative {
    title: String,
    summary: String,
    confidence: f64,
    #[allow(dead_code)]
    supporting_signals: Vec<usize>,
    trend: String,
    #[serde(default)]
    key_metrics: Vec<RawMetric>,
    #[serde(default)]
    active_repos: Vec<String>,
}

#[derive(Deserialize)]
struct RawMetric {
    name: String,
    value: f64,
    #[serde(default)]
    unit: String,
}

pub struct SynthesizedNarrative {
    pub title: String,
    pub summary: String,
    pub confidence: f64,
    pub trend: TrendDirection,
    #[allow(dead_code)]
    pub key_metrics: Vec<Metric>,
    pub active_repos: Vec<String>,
}

pub async fn identify_narratives(
    llm: &LlmClient,
    signals_json: &str,
) -> Result<Vec<SynthesizedNarrative>> {
    info!("sending signals to LLM for narrative identification");

    let user_message = format!(
        "Analyze these aggregated signals from the Solana ecosystem and identify emerging narratives:\n\n{signals_json}"
    );

    let response: SynthesisResponse = llm.complete_json(SYSTEM_PROMPT, &user_message).await?;

    let count = response.narratives.len();
    let narratives = response
        .narratives
        .into_iter()
        .map(|n| SynthesizedNarrative {
            title: n.title,
            summary: n.summary,
            confidence: n.confidence.clamp(0.0, 1.0),
            trend: parse_trend(&n.trend),
            key_metrics: n
                .key_metrics
                .into_iter()
                .map(|m| Metric {
                    name: m.name,
                    value: m.value,
                    unit: m.unit,
                })
                .collect(),
            active_repos: n.active_repos,
        })
        .collect();

    info!(count, "identified narratives");
    Ok(narratives)
}

fn parse_trend(s: &str) -> TrendDirection {
    match s.to_lowercase().as_str() {
        "accelerating" => TrendDirection::Accelerating,
        "stable" | "steady" => TrendDirection::Stable,
        "decelerating" | "declining" => TrendDirection::Decelerating,
        "emerging" | "nascent" | "early" => TrendDirection::Emerging,
        _ => TrendDirection::Emerging,
    }
}
