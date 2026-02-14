// Autonomous orchestration: narrative → target selection → scan → validate → cross-ref → report

pub mod cross_ref;

use crate::LlmOverride;
use crate::config::Config;
use crate::llm::{ModelRouter, TaskKind};
use crate::memory::{RepoResult, RunHistory, RunMemory};
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

    // Load run memory from previous runs
    let run_memory = RunMemory::load_or_default();
    if run_memory.total_runs > 0 {
        info!(
            runs = run_memory.total_runs,
            blocklisted = run_memory.repo_blocklist.len(),
            "Loaded memory from {} previous runs. Blocklisted {} repos.",
            run_memory.total_runs,
            run_memory.repo_blocklist.len()
        );
    }
    let mut run_history = RunHistory::new();

    // Phase 1: Narrative detection
    info!("Phase 1: Detecting narratives...");
    let mut narratives =
        narrative::run_narrative_pipeline(&config_path, llm_override.as_ref()).await?;
    info!(count = narratives.len(), "narratives detected");

    // Phase 2: Target selection from narratives
    info!("Phase 2: Selecting scan targets...");
    let mut targets: Vec<String> = narratives
        .iter()
        .flat_map(|n| n.active_repos.iter().cloned())
        .collect();
    targets.sort();
    targets.dedup();

    // Load config once for targets + agent_review
    let cfg = Config::load(&config_path).unwrap_or_default();

    // Inject known-good targets from config
    if let Some(ref cfg_repos_dir) = cfg.targets.repos_dir {
        let base = config_path
            .parent()
            .map(|p| p.join(cfg_repos_dir))
            .unwrap_or_else(|| cfg_repos_dir.clone());
        for name in &cfg.targets.always_scan {
            if base.join(name).is_dir()
                && !targets
                    .iter()
                    .any(|t| t.split('/').next_back() == Some(name))
            {
                targets.push(name.clone());
            }
        }
    }
    // Filter out blocklisted repos (consistently failing in previous runs)
    let pre_filter = targets.len();
    targets.retain(|t| {
        let name = t.split('/').next_back().unwrap_or(t);
        !run_memory.repo_blocklist.iter().any(|b| b == name)
    });
    if targets.len() < pre_filter {
        info!(
            removed = pre_filter - targets.len(),
            "filtered blocklisted repos from memory"
        );
    }

    run_history.signals_collected = narratives.len();
    info!(
        count = targets.len(),
        "scan targets identified (deduped + known-good, blocklist filtered)"
    );

    // Phase 3: Clone + scan + validate per-repo
    info!(
        "Phase 3: Scanning targets{}...",
        if deep { " (deep agent review)" } else { "" }
    );
    std::fs::create_dir_all(&repos_dir)?;

    // Resolve config repos_dir relative to config file for known-good target lookup
    let known_good_base = cfg.targets.repos_dir.as_ref().map(|rd| {
        config_path
            .parent()
            .map(|p| p.join(rd))
            .unwrap_or_else(|| rd.clone())
    });

    let default_agent_config = if deep {
        cfg.agent_review
    } else {
        crate::config::AgentReviewConfig::default()
    };

    let mut all_findings = Vec::new();
    for target in &targets {
        let repo_name = target.split('/').next_back().unwrap_or(target);

        // Known-good targets (bare names) resolve from config repos_dir
        let repo_path = if !target.contains('/') {
            if let Some(ref base) = known_good_base {
                let p = base.join(repo_name);
                if p.is_dir() {
                    p
                } else {
                    repos_dir.join(repo_name)
                }
            } else {
                repos_dir.join(repo_name)
            }
        } else {
            repos_dir.join(repo_name)
        };

        if !repo_path.exists() {
            if !target.contains('/') {
                tracing::warn!(repo = %target, "known-good target not found locally, skipping");
                run_history.repo_results.push(RepoResult {
                    name: repo_name.to_string(),
                    findings_count: 0,
                    errors: vec!["not found locally".into()],
                });
                continue;
            }
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
                run_history.repo_results.push(RepoResult {
                    name: repo_name.to_string(),
                    findings_count: 0,
                    errors: vec!["clone failed".into()],
                });
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
                let mut repo_errors = Vec::new();
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
                        repo_errors.push(format!("validation: {e}"));
                        tracing::warn!(
                            repo = %target, error = %e,
                            "validation failed, keeping unvalidated"
                        );
                    }
                }
                let count = findings.len();
                info!(repo = %target, findings = count, "scan complete");
                all_findings.extend(findings);
                run_history.repo_results.push(RepoResult {
                    name: repo_name.to_string(),
                    findings_count: count,
                    errors: repo_errors,
                });
            }
            Err(e) => {
                tracing::warn!(repo = %target, error = %e, "scan failed");
                run_history.repo_results.push(RepoResult {
                    name: repo_name.to_string(),
                    findings_count: 0,
                    errors: vec![e.to_string()],
                });
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
    let html = output::render_combined_report(&narratives, &all_findings, Some(&run_memory))?;

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

    // Save run history and update memory for future runs
    run_history.total_findings = all_findings.len();
    if let Err(e) = run_history.save() {
        tracing::warn!(error = %e, "failed to save run history");
    }
    let mut run_memory = run_memory;
    run_memory.update_from_run(&run_history);
    if let Err(e) = run_memory.save() {
        tracing::warn!(error = %e, "failed to save run memory");
    }

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
