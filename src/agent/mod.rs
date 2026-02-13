// Autonomous orchestration: narrative → target selection → scan → validate → cross-ref → report

pub mod cross_ref;

use crate::LlmOverride;
use crate::config::Config;
use crate::llm::{ModelRouter, TaskKind};
use crate::narrative::{self, Narrative};
use crate::output;
use crate::security::{self, agent_review::ScanContext};
use anyhow::Result;
use std::path::PathBuf;
use tracing::info;

/// Run the full autonomous pipeline.
///
/// 1. Detect narratives (what's growing in the Solana ecosystem)
/// 2. Identify active repos from narratives
/// 3. Clone + scan with narrative context + validate per-repo
/// 4. Cross-reference: narratives × findings with risk scoring
/// 5. Generate narrative-centric intelligence report
pub async fn run_full_pipeline(
    config_path: PathBuf,
    output_path: PathBuf,
    repos_dir: PathBuf,
    llm_override: Option<LlmOverride>,
    router: ModelRouter,
    deep: bool,
) -> Result<()> {
    info!("SolGuard autonomous pipeline starting");

    // Phase 1: Narrative detection
    info!("Phase 1: Detecting narratives...");
    let mut narratives =
        narrative::run_narrative_pipeline(&config_path, llm_override.as_ref()).await?;
    info!(count = narratives.len(), "narratives detected");

    // Phase 2: Target selection from narratives
    info!("Phase 2: Selecting scan targets...");
    let targets: Vec<String> = narratives
        .iter()
        .flat_map(|n| n.active_repos.iter().cloned())
        .collect();
    info!(count = targets.len(), "scan targets identified");

    // Phase 3: Clone + scan + validate per-repo
    info!(
        "Phase 3: Scanning targets{}...",
        if deep { " (deep agent review)" } else { "" }
    );
    std::fs::create_dir_all(&repos_dir)?;

    let default_agent_config = if deep {
        Config::load(&config_path)
            .map(|c| c.agent_review)
            .unwrap_or_default()
    } else {
        crate::config::AgentReviewConfig::default()
    };

    let mut all_findings = Vec::new();
    for target in &targets {
        let repo_name = target.split('/').next_back().unwrap_or(target);
        let repo_path = repos_dir.join(repo_name);

        if !repo_path.exists() {
            info!(repo = %target, "cloning repository");
            let status = tokio::process::Command::new("git")
                .args([
                    "clone",
                    "--depth",
                    "1",
                    &format!("https://github.com/{target}"),
                    &repo_path.to_string_lossy(),
                ])
                .status()
                .await?;

            if !status.success() {
                tracing::warn!(repo = %target, "failed to clone, skipping");
                continue;
            }
        }

        // Build narrative-informed scan context + dynamic budget
        let (scan_ctx, repo_agent_config) = if deep {
            let narrative = narratives.iter().find(|n| {
                n.active_repos
                    .iter()
                    .any(|ar| ar.split('/').next_back() == Some(repo_name))
            });
            match narrative {
                Some(n) => {
                    let (budget_turns, budget_cost) =
                        security::agent_review::compute_budget(n.confidence, targets.len());

                    let siblings: Vec<String> = all_findings
                        .iter()
                        .take(10)
                        .map(|f: &security::SecurityFinding| {
                            format!("[{}] {}", f.severity, f.title)
                        })
                        .collect();

                    let ctx = ScanContext {
                        protocol_category: infer_protocol_category(n),
                        narrative_summary: Some(n.summary.clone()),
                        sibling_findings: siblings,
                    };

                    let cfg = crate::config::AgentReviewConfig {
                        max_turns: budget_turns,
                        max_tokens: default_agent_config.max_tokens,
                        cost_limit_usd: budget_cost,
                    };
                    (Some(ctx), cfg)
                }
                None => (
                    None,
                    crate::config::AgentReviewConfig {
                        max_turns: default_agent_config.max_turns,
                        max_tokens: default_agent_config.max_tokens,
                        cost_limit_usd: default_agent_config.cost_limit_usd,
                    },
                ),
            }
        } else {
            (
                None,
                crate::config::AgentReviewConfig {
                    max_turns: default_agent_config.max_turns,
                    max_tokens: default_agent_config.max_tokens,
                    cost_limit_usd: default_agent_config.cost_limit_usd,
                },
            )
        };

        let result = if deep {
            let llm = router.client_for(TaskKind::DeepInvestigation);
            security::scan_repo_deep(&repo_path, llm, &repo_agent_config, scan_ctx.as_ref()).await
        } else {
            security::scan_repo(&repo_path).await
        };

        match result {
            Ok(mut findings) => {
                // Validate findings for this repo
                if deep && !findings.is_empty() {
                    info!(repo = %target, count = findings.len(), "validating findings");
                    if let Err(e) = security::validator::validate_findings(
                        &mut findings,
                        &router,
                        &repo_path,
                        &repo_agent_config,
                    )
                    .await
                    {
                        tracing::warn!(
                            repo = %target, error = %e,
                            "validation failed, keeping unvalidated"
                        );
                    }
                }
                info!(repo = %target, findings = findings.len(), "scan complete");
                all_findings.extend(findings);
            }
            Err(e) => {
                tracing::warn!(repo = %target, error = %e, "scan failed");
            }
        }
    }

    // Phase 4: Cross-reference narratives with security findings
    info!("Phase 4: Cross-referencing narratives with security findings...");
    let _links = cross_ref::analyze(&mut narratives, &all_findings, &router).await?;

    // Sort narratives by risk_score descending for the report
    narratives.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Phase 5: Generate combined report
    info!("Phase 5: Generating combined report...");
    let html = output::render_combined_report(&narratives, &all_findings)?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output_path, &html)?;

    info!(path = %output_path.display(), "combined report written");
    println!("SolGuard report: {}", output_path.display());
    println!(
        "  {} narratives, {} security findings",
        narratives.len(),
        all_findings.len()
    );

    Ok(())
}

/// Infer protocol category from narrative content for scan context.
pub fn infer_protocol_category(narrative: &Narrative) -> Option<String> {
    let text = format!("{} {}", narrative.title, narrative.summary).to_lowercase();
    if text.contains("dex")
        || text.contains("amm")
        || text.contains("swap")
        || text.contains("exchange")
    {
        Some("DEX".into())
    } else if text.contains("lend") || text.contains("borrow") || text.contains("loan") {
        Some("Lending".into())
    } else if text.contains("stak") || text.contains("liquid") {
        Some("Staking".into())
    } else if text.contains("nft") || text.contains("marketplace") || text.contains("collectible") {
        Some("NFT/Marketplace".into())
    } else if text.contains("privacy") || text.contains("mixer") || text.contains("anon") {
        Some("Privacy".into())
    } else if text.contains("bridge") || text.contains("cross-chain") {
        Some("Bridge".into())
    } else {
        None
    }
}
