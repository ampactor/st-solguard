use super::github::DiscoveredRepo;
use super::types::{Metric, Signal, SignalSource};
use std::collections::HashMap;

pub struct SignalGroup {
    pub category: String,
    pub signals: Vec<usize>,
    pub source_diversity: usize,
    pub total_signals: usize,
    #[allow(dead_code)]
    pub key_metrics: Vec<Metric>,
}

/// Normalize source-specific categories to canonical forms for grouping.
fn normalize_category(raw: &str) -> String {
    match raw {
        "DeFi TVL" | "Dexes" | "DEX" | "Lending" | "Yield" | "Yield Aggregator" => "DeFi".into(),
        "Liquid Staking" | "Staking" => "Staking".into(),
        "NFT" | "NFT Marketplace" | "NFT Lending" => "NFT & Gaming".into(),
        other => other.to_string(),
    }
}

pub fn aggregate(signals: &[Signal]) -> Vec<SignalGroup> {
    let mut by_category: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, signal) in signals.iter().enumerate() {
        let category = normalize_category(&signal.category);
        by_category.entry(category).or_default().push(i);
    }

    let mut groups: Vec<SignalGroup> = by_category
        .into_iter()
        .map(|(category, indices)| {
            let sources: std::collections::HashSet<SignalSource> =
                indices.iter().map(|&i| signals[i].source).collect();

            let mut metric_sums: HashMap<String, (f64, String)> = HashMap::new();
            for &i in &indices {
                for m in &signals[i].metrics {
                    let entry = metric_sums
                        .entry(m.name.clone())
                        .or_insert((0.0, m.unit.clone()));
                    entry.0 += m.value;
                }
            }
            let key_metrics: Vec<Metric> = metric_sums
                .into_iter()
                .map(|(name, (value, unit))| Metric { name, value, unit })
                .collect();

            SignalGroup {
                category,
                total_signals: indices.len(),
                source_diversity: sources.len(),
                signals: indices,
                key_metrics,
            }
        })
        .collect();

    groups.sort_by(|a, b| {
        b.source_diversity
            .cmp(&a.source_diversity)
            .then(b.total_signals.cmp(&a.total_signals))
    });

    groups
}

pub fn signals_to_json(
    signals: &[Signal],
    groups: &[SignalGroup],
    discovered_repos: &[DiscoveredRepo],
) -> String {
    let summary: Vec<serde_json::Value> = groups
        .iter()
        .map(|g| {
            let signal_details: Vec<serde_json::Value> = g
                .signals
                .iter()
                .map(|&i| {
                    let s = &signals[i];
                    serde_json::json!({
                        "source": s.source.to_string(),
                        "title": s.title,
                        "description": s.description,
                        "metrics": s.metrics.iter().map(|m| {
                            serde_json::json!({
                                "name": m.name,
                                "value": m.value,
                                "unit": m.unit,
                            })
                        }).collect::<Vec<_>>(),
                        "url": s.url,
                        "timestamp": s.timestamp.to_rfc3339(),
                    })
                })
                .collect();

            serde_json::json!({
                "category": g.category,
                "signal_count": g.total_signals,
                "source_diversity": g.source_diversity,
                "signals": signal_details,
            })
        })
        .collect();

    let output = serde_json::json!({
        "signal_groups": summary,
        "discovered_repos": discovered_repos,
    });
    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".into())
}
