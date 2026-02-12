use super::types::{Metric, Signal, SignalSource};
use crate::config::SolanaConfig;
use crate::error::{Error, Result};
use crate::http::HttpClient;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    message: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct PerformanceSample {
    #[serde(rename = "numTransactions")]
    num_transactions: u64,
    #[serde(rename = "numNonVoteTransactions")]
    num_non_vote_transactions: Option<u64>,
    #[serde(rename = "numSlots")]
    num_slots: u64,
    #[serde(rename = "samplePeriodSecs")]
    sample_period_secs: u64,
}

#[derive(Deserialize)]
struct EpochInfo {
    epoch: u64,
    #[serde(rename = "slotIndex")]
    slot_index: u64,
    #[serde(rename = "slotsInEpoch")]
    slots_in_epoch: u64,
    #[serde(rename = "absoluteSlot")]
    absolute_slot: u64,
    #[serde(rename = "transactionCount")]
    transaction_count: Option<u64>,
}

#[derive(Deserialize)]
struct Supply {
    value: SupplyValue,
}

#[derive(Deserialize)]
struct SupplyValue {
    total: u64,
    circulating: u64,
    #[serde(rename = "nonCirculating")]
    non_circulating: u64,
}

pub async fn collect(config: &SolanaConfig, http: &HttpClient) -> Result<Vec<Signal>> {
    let mut signals = Vec::new();

    // Recent performance samples (TPS)
    let perf_samples = rpc_call::<Vec<PerformanceSample>>(
        &config.rpc_url,
        http,
        "getRecentPerformanceSamples",
        serde_json::json!([10]),
    )
    .await?;

    if !perf_samples.is_empty() {
        let avg_tps: f64 = perf_samples
            .iter()
            .map(|s| s.num_transactions as f64 / s.sample_period_secs as f64)
            .sum::<f64>()
            / perf_samples.len() as f64;

        let avg_non_vote_tps: f64 = perf_samples
            .iter()
            .filter_map(|s| {
                s.num_non_vote_transactions
                    .map(|nv| nv as f64 / s.sample_period_secs as f64)
            })
            .sum::<f64>()
            / perf_samples.len() as f64;

        signals.push(Signal {
            source: SignalSource::SolanaOnchain,
            category: "Network Performance".into(),
            title: format!("Solana TPS: {avg_tps:.0} total, {avg_non_vote_tps:.0} non-vote"),
            description: format!(
                "Average over {} recent samples. Non-vote TPS indicates real user activity.",
                perf_samples.len()
            ),
            metrics: vec![
                Metric {
                    name: "avg_tps".into(),
                    value: avg_tps,
                    unit: "tx/s".into(),
                },
                Metric {
                    name: "avg_non_vote_tps".into(),
                    value: avg_non_vote_tps,
                    unit: "tx/s".into(),
                },
            ],
            url: Some("https://explorer.solana.com/".into()),
            timestamp: Utc::now(),
        });
    }

    // Epoch info
    let epoch: EpochInfo =
        rpc_call(&config.rpc_url, http, "getEpochInfo", serde_json::json!([])).await?;
    let epoch_progress = epoch.slot_index as f64 / epoch.slots_in_epoch as f64 * 100.0;

    signals.push(Signal {
        source: SignalSource::SolanaOnchain,
        category: "Network State".into(),
        title: format!("Epoch {} — {epoch_progress:.1}% complete", epoch.epoch),
        description: format!(
            "Slot {}/{}, absolute slot {}. {}",
            epoch.slot_index,
            epoch.slots_in_epoch,
            epoch.absolute_slot,
            epoch
                .transaction_count
                .map(|tc| format!("Total transactions: {tc}"))
                .unwrap_or_default()
        ),
        metrics: vec![
            Metric {
                name: "epoch".into(),
                value: epoch.epoch as f64,
                unit: String::new(),
            },
            Metric {
                name: "epoch_progress".into(),
                value: epoch_progress,
                unit: "%".into(),
            },
        ],
        url: Some("https://explorer.solana.com/".into()),
        timestamp: Utc::now(),
    });

    // SOL supply
    let supply: Supply =
        rpc_call(&config.rpc_url, http, "getSupply", serde_json::json!([])).await?;
    let circulating_pct = supply.value.circulating as f64 / supply.value.total as f64 * 100.0;

    signals.push(Signal {
        source: SignalSource::SolanaOnchain,
        category: "Token Economics".into(),
        title: format!(
            "SOL Supply: {:.1}M circulating ({circulating_pct:.1}%)",
            supply.value.circulating as f64 / 1_000_000_000.0 / 1_000_000.0,
        ),
        description: format!(
            "Total: {:.1}M SOL, Circulating: {:.1}M SOL, Non-circulating: {:.1}M SOL",
            supply.value.total as f64 / 1e15,
            supply.value.circulating as f64 / 1e15,
            supply.value.non_circulating as f64 / 1e15,
        ),
        metrics: vec![
            Metric {
                name: "circulating_sol".into(),
                value: supply.value.circulating as f64 / 1e9,
                unit: "SOL".into(),
            },
            Metric {
                name: "circulating_pct".into(),
                value: circulating_pct,
                unit: "%".into(),
            },
        ],
        url: None,
        timestamp: Utc::now(),
    });

    // Tracked program activity (paginated for real counts)
    for program in &config.tracked_programs {
        match get_program_activity(&config.rpc_url, http, &program.address).await {
            Ok(activity) => {
                let title = if activity.tx_per_hour > 0.0 {
                    let time_str = if activity.time_span_hours < 1.0 {
                        format!("{:.0}m", activity.time_span_hours * 60.0)
                    } else {
                        format!("{:.1}h", activity.time_span_hours)
                    };
                    format!(
                        "{}: {:.0} tx/hr ({} txs over {})",
                        program.name, activity.tx_per_hour, activity.tx_count, time_str
                    )
                } else {
                    format!(
                        "{}: {} recent transactions",
                        program.name, activity.tx_count
                    )
                };
                let mut metrics = vec![Metric {
                    name: "recent_tx_count".into(),
                    value: activity.tx_count as f64,
                    unit: "txs".into(),
                }];
                if activity.tx_per_hour > 0.0 {
                    metrics.push(Metric {
                        name: "tx_per_hour".into(),
                        value: activity.tx_per_hour,
                        unit: "tx/hr".into(),
                    });
                }
                signals.push(Signal {
                    source: SignalSource::SolanaOnchain,
                    category: program.category.clone(),
                    title,
                    description: format!(
                        "Program {} ({}) — {} transactions sampled.",
                        program.name, program.address, activity.tx_count
                    ),
                    metrics,
                    url: Some(format!(
                        "https://explorer.solana.com/address/{}",
                        program.address
                    )),
                    timestamp: Utc::now(),
                });
            }
            Err(e) => {
                tracing::warn!(program = %program.name, error = %e, "failed to get program activity");
            }
        }
    }

    info!(
        signal_count = signals.len(),
        "collected Solana onchain signals"
    );
    Ok(signals)
}

struct ProgramActivity {
    tx_count: usize,
    tx_per_hour: f64,
    time_span_hours: f64,
}

async fn get_program_activity(
    rpc_url: &str,
    http: &HttpClient,
    address: &str,
) -> Result<ProgramActivity> {
    #[derive(Deserialize)]
    struct SigInfo {
        signature: String,
        #[serde(rename = "blockTime")]
        block_time: Option<i64>,
    }

    let mut all_sigs = Vec::new();
    let mut before: Option<String> = None;

    for _ in 0..10 {
        let params = if let Some(ref cursor) = before {
            serde_json::json!([address, {"limit": 100, "before": cursor}])
        } else {
            serde_json::json!([address, {"limit": 100}])
        };

        let sigs: Vec<SigInfo> = rpc_call(rpc_url, http, "getSignaturesForAddress", params).await?;
        let batch_len = sigs.len();
        if let Some(last) = sigs.last() {
            before = Some(last.signature.clone());
        }
        all_sigs.extend(sigs);
        if batch_len < 100 {
            break;
        }
    }

    let tx_count = all_sigs.len();
    let timestamps: Vec<i64> = all_sigs.iter().filter_map(|s| s.block_time).collect();
    let (tx_per_hour, time_span_hours) = if timestamps.len() >= 2 {
        let newest = timestamps[0];
        let oldest = timestamps[timestamps.len() - 1];
        let span_secs = (newest - oldest).max(1) as f64;
        let span_hours = span_secs / 3600.0;
        (tx_count as f64 / span_hours, span_hours)
    } else {
        (0.0, 0.0)
    };

    Ok(ProgramActivity {
        tx_count,
        tx_per_hour,
        time_span_hours,
    })
}

async fn rpc_call<T: serde::de::DeserializeOwned>(
    rpc_url: &str,
    http: &HttpClient,
    method: &str,
    params: serde_json::Value,
) -> Result<T> {
    let request = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method,
        params,
    };
    let body =
        serde_json::to_string(&request).map_err(|e| Error::parse(format!("serialize: {e}")))?;
    let resp_text = http.post_json_raw(rpc_url, &body, &[]).await?;
    let resp: RpcResponse<T> =
        serde_json::from_str(&resp_text).map_err(|e| Error::parse(format!("parse RPC: {e}")))?;

    if let Some(err) = resp.error {
        return Err(Error::api("solana-rpc", err.message));
    }
    resp.result
        .ok_or_else(|| Error::parse("RPC response missing result"))
}
