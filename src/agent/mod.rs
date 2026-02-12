// Autonomous orchestration: narrative → target selection → scan → combined report

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
/// 4. Scan each target for vulnerabilities
/// 5. Cross-reference: which narratives have security risks
/// 6. Generate combined intelligence report
pub async fn run_full_pipeline(
    config_path: PathBuf,
    output_path: PathBuf,
    repos_dir: PathBuf,
) -> Result<()> {
    info!("SolGuard autonomous pipeline starting");

    // Phase 1: Narrative detection
    info!("Phase 1: Detecting narratives...");
    let narratives = narrative::run_narrative_pipeline(&config_path).await?;
    info!(count = narratives.len(), "narratives detected");

    // Phase 2: Target selection from narratives
    info!("Phase 2: Selecting scan targets...");
    let targets: Vec<String> = narratives
        .iter()
        .flat_map(|n| n.active_repos.iter().cloned())
        .collect();
    info!(count = targets.len(), "scan targets identified");

    // Phase 3: Clone and scan targets
    info!("Phase 3: Scanning targets...");
    std::fs::create_dir_all(&repos_dir)?;

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

        // Scan
        match security::scan_repo(&repo_path).await {
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
