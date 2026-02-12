// Autonomous orchestration: narrative → target selection → scan → combined report

use crate::LlmOverride;
use crate::config::Config;
use crate::llm::LlmClient;
use crate::narrative;
use crate::output;
use crate::security;
use anyhow::Result;
use std::path::PathBuf;
use tracing::info;

/// Run the full autonomous pipeline.
///
/// 1. Detect narratives (what's growing in the Solana ecosystem)
/// 2. Identify active repos from narratives
/// 3. Select scan targets (unaudited, in emerging sectors)
/// 4. Scan each target for vulnerabilities (static or deep agent review)
/// 5. Cross-reference: which narratives have security risks
/// 6. Generate combined intelligence report
pub async fn run_full_pipeline(
    config_path: PathBuf,
    output_path: PathBuf,
    repos_dir: PathBuf,
    llm_override: Option<LlmOverride>,
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

    // Phase 3: Clone and scan targets
    info!(
        "Phase 3: Scanning targets{}...",
        if deep { " (deep agent review)" } else { "" }
    );
    std::fs::create_dir_all(&repos_dir)?;

    // Build LLM client for deep scanning if needed
    let (llm, agent_config) = if deep {
        let cfg = Config::load(&config_path).unwrap_or_default();
        let provider = llm_override
            .as_ref()
            .map(|o| o.provider.clone())
            .unwrap_or_else(|| cfg.llm.provider.clone());
        let model = llm_override
            .as_ref()
            .map(|o| o.model.clone())
            .unwrap_or_else(|| cfg.llm.model.clone());
        let client = LlmClient::from_config(
            provider,
            model,
            cfg.llm.max_tokens,
            cfg.llm.api_key_env.clone(),
            cfg.llm.base_url.clone(),
        )?;
        (Some(client), cfg.agent_review)
    } else {
        (None, crate::config::AgentReviewConfig::default())
    };

    let mut all_findings = Vec::new();
    for target in &targets {
        // Clone repo if needed
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

        // Scan: deep agent review or static-only
        let result = if let Some(ref llm) = llm {
            security::scan_repo_deep(&repo_path, llm, &agent_config).await
        } else {
            security::scan_repo(&repo_path).await
        };

        match result {
            Ok(findings) => {
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
    for narrative in &mut narratives {
        narrative.finding_count = all_findings
            .iter()
            .filter(|f| {
                let path = f.file_path.to_string_lossy();
                let repo = if let Some(idx) = path.find("repos/") {
                    let after = &path[idx + 6..];
                    after.split('/').next().unwrap_or(after).to_string()
                } else {
                    f.file_path
                        .components()
                        .find_map(|c| {
                            let s = c.as_os_str().to_string_lossy();
                            if s != "." && s != ".." && s != "repos" {
                                Some(s.into_owned())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| "unknown".into())
                };
                narrative
                    .active_repos
                    .iter()
                    .any(|ar| ar.split('/').next_back().is_some_and(|tail| tail == repo))
            })
            .count();
        if narrative.finding_count > 0 {
            info!(
                "  {} -> {} findings",
                narrative.title, narrative.finding_count
            );
        }
    }

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
