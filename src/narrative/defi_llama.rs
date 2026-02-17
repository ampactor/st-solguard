use super::types::{Metric, Signal, SignalSource};
use crate::config::DefiLlamaConfig;
use crate::error::Result;
use crate::http::HttpClient;
use chrono::Utc;
use serde::Deserialize;
use tracing::info;

#[derive(Deserialize)]
struct Chain {
    name: String,
    tvl: Option<f64>,
}

#[derive(Deserialize)]
struct Protocol {
    name: String,
    #[serde(default)]
    chains: Vec<String>,
    #[serde(default)]
    chain: Option<String>,
    tvl: Option<f64>,
    category: Option<String>,
}

pub async fn collect(config: &DefiLlamaConfig, http: &HttpClient) -> Result<Vec<Signal>> {
    if !config.enabled {
        return Ok(Vec::new());
    }

    let mut signals = Vec::new();

    // Fetch chain TVL
    let chains: Vec<Chain> = http.get_json("https://api.llama.fi/v2/chains").await?;

    if let Some(solana) = chains.iter().find(|c| c.name == "Solana") {
        let tvl = solana.tvl.unwrap_or(0.0);
        let tvl_billions = tvl / 1_000_000_000.0;

        // Find Solana's rank
        let mut chain_tvls: Vec<f64> = chains.iter().filter_map(|c| c.tvl).collect();
        chain_tvls.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        let rank = chain_tvls
            .iter()
            .position(|&t| (t - tvl).abs() < 1.0)
            .map(|r| r + 1);

        signals.push(Signal {
            source: SignalSource::DeFiLlama,
            category: "DeFi TVL".into(),
            title: format!(
                "Solana Chain TVL: ${tvl_billions:.2}B{}",
                rank.map(|r| format!(" (#{r} overall)")).unwrap_or_default()
            ),
            description: format!(
                "Total value locked across all Solana DeFi protocols. {}",
                rank.map(|r| format!("Ranked #{r} among all chains by TVL."))
                    .unwrap_or_default()
            ),
            metrics: vec![
                Metric {
                    name: "solana_tvl".into(),
                    value: tvl,
                    unit: "USD".into(),
                },
                Metric {
                    name: "solana_tvl_billions".into(),
                    value: tvl_billions,
                    unit: "B USD".into(),
                },
            ],
            url: Some("https://defillama.com/chain/Solana".into()),
            timestamp: Utc::now(),
        });
    }

    // Fetch protocol data — filter for Solana protocols
    let protocols: Vec<Protocol> = http.get_json("https://api.llama.fi/protocols").await?;

    let mut solana_protocols: Vec<&Protocol> = protocols
        .iter()
        .filter(|p| p.chains.iter().any(|c| c == "Solana") || p.chain.as_deref() == Some("Solana"))
        .filter(|p| p.tvl.unwrap_or(0.0) > 0.0)
        .collect();

    solana_protocols.sort_by(|a, b| {
        b.tvl
            .unwrap_or(0.0)
            .partial_cmp(&a.tvl.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let top_n = config.top_protocols.min(solana_protocols.len());
    let top_protocols = &solana_protocols[..top_n];

    if !top_protocols.is_empty() {
        let protocol_list: Vec<String> = top_protocols
            .iter()
            .map(|p| format!("{}: ${:.0}M", p.name, p.tvl.unwrap_or(0.0) / 1_000_000.0))
            .collect();

        let total_solana_tvl: f64 = solana_protocols.iter().filter_map(|p| p.tvl).sum();

        signals.push(Signal {
            source: SignalSource::DeFiLlama,
            category: "DeFi TVL".into(),
            title: format!(
                "Top {} Solana DeFi Protocols by TVL ({} total Solana protocols tracked)",
                top_n,
                solana_protocols.len()
            ),
            description: format!("Leading protocols: {}", protocol_list.join(", ")),
            metrics: vec![
                Metric {
                    name: "solana_protocol_count".into(),
                    value: solana_protocols.len() as f64,
                    unit: "protocols".into(),
                },
                Metric {
                    name: "total_solana_defi_tvl".into(),
                    value: total_solana_tvl,
                    unit: "USD".into(),
                },
                Metric {
                    name: "top_protocol_tvl".into(),
                    value: top_protocols[0].tvl.unwrap_or(0.0),
                    unit: "USD".into(),
                },
            ],
            url: Some("https://defillama.com/chain/Solana".into()),
            timestamp: Utc::now(),
        });

        // Category breakdown
        let mut categories: std::collections::HashMap<String, (f64, usize)> =
            std::collections::HashMap::new();
        for p in &solana_protocols {
            let cat = p.category.as_deref().unwrap_or("Other").to_string();
            let entry = categories.entry(cat).or_insert((0.0, 0));
            entry.0 += p.tvl.unwrap_or(0.0);
            entry.1 += 1;
        }
        let mut cat_list: Vec<(String, f64, usize)> = categories
            .into_iter()
            .map(|(k, (v, c))| (k, v, c))
            .collect();
        cat_list.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let cat_desc: Vec<String> = cat_list
            .iter()
            .take(5)
            .map(|(cat, tvl, count)| {
                format!("{cat}: ${:.0}M ({count} protocols)", tvl / 1_000_000.0)
            })
            .collect();

        signals.push(Signal {
            source: SignalSource::DeFiLlama,
            category: "DeFi TVL".into(),
            title: format!(
                "Solana DeFi Category Breakdown ({} categories)",
                cat_list.len()
            ),
            description: format!("Top categories: {}", cat_desc.join(", ")),
            metrics: cat_list
                .iter()
                .take(5)
                .map(|(cat, tvl, _)| Metric {
                    name: format!("tvl_{}", cat.to_lowercase().replace(' ', "_")),
                    value: *tvl,
                    unit: "USD".into(),
                })
                .collect(),
            url: Some("https://defillama.com/chain/Solana".into()),
            timestamp: Utc::now(),
        });
    }

    info!(
        signal_count = signals.len(),
        "collected DeFiLlama TVL signals"
    );
    Ok(signals)
}
