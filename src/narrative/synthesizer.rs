use super::types::{Metric, TrendDirection};
use crate::error::Result;
use crate::llm::LlmClient;
use serde::Deserialize;
use tracing::info;

const SYSTEM_PROMPT: &str = r#"You are a Solana ecosystem analyst identifying emerging narratives.

A "narrative" is a thematic trend backed by multiple data points across different sources (GitHub developer activity, onchain metrics, social/blog signals). A narrative must appear in 2+ signal sources to be credible.

For each narrative you identify, provide:
1. A clear, specific title (not generic like "DeFi growth" — be specific: "Concentrated Liquidity Migration on Solana DEXs")
2. A 2-3 sentence summary explaining what's happening and why it matters
3. Confidence score (0.0-1.0) based on signal strength and source diversity
4. Which signal indices support this narrative (from the input data)
5. Trend direction: "Accelerating" (growing faster), "Stable" (steady), "Decelerating" (slowing), "Emerging" (too early to tell, but signals present)
6. Key quantitative metrics that back the narrative

Respond in JSON:
{
  "narratives": [
    {
      "title": "...",
      "summary": "...",
      "confidence": 0.85,
      "supporting_signals": [0, 3, 7],
      "trend": "Accelerating",
      "key_metrics": [{"name": "...", "value": 123.4, "unit": "..."}]
    }
  ]
}

Rules:
- Only report narratives you're confident about. Quality over quantity.
- Every claim must be backed by specific signals from the input data.
- Quantify everything. "Growing" is weak; "42% increase in new repos" is strong.
- 5-8 narratives is ideal. Fewer if the data doesn't support more.
- Don't invent data. Only use what's in the signals."#;

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
