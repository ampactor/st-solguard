use crate::llm::{ModelRouter, TaskKind};
use crate::narrative::Narrative;
use crate::security::{SecurityFinding, ValidationStatus};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::info;

#[allow(dead_code)] // available for downstream consumers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeRiskProfile {
    pub narrative_idx: usize,
    pub risk_score: f64,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub confirmed_count: usize,
    pub repo_findings: Vec<(String, Vec<usize>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeFindingLink {
    pub narrative_idx: usize,
    pub finding_idx: usize,
    pub repo: String,
    pub relevance: String,
}

/// Cross-reference narratives with security findings, computing risk scores
/// and linking findings to the narratives whose repos they belong to.
pub async fn analyze(
    narratives: &mut [Narrative],
    findings: &[SecurityFinding],
    router: &ModelRouter,
) -> Result<Vec<NarrativeFindingLink>> {
    info!(
        narratives = narratives.len(),
        findings = findings.len(),
        "cross-reference: starting"
    );

    let mut all_links = Vec::new();

    for (ni, narrative) in narratives.iter_mut().enumerate() {
        // Tail repo names from active_repos (e.g. "owner/repo" -> "repo")
        let repo_tails: Vec<&str> = narrative
            .active_repos
            .iter()
            .filter_map(|ar| ar.split('/').next_back())
            .collect();

        // Match findings to this narrative by repo name
        let mut matched: Vec<(usize, String)> = Vec::new(); // (finding_idx, repo_name)
        for (fi, finding) in findings.iter().enumerate() {
            let repo = repo_name_from_path(&finding.file_path);
            if repo_tails.iter().any(|tail| *tail == repo) {
                matched.push((fi, repo));
            }
        }

        // Risk score computation
        let mut risk_score = 0.0f64;

        // Aggregate per-repo finding indices
        let mut repo_finding_map: HashMap<String, Vec<usize>> = HashMap::new();

        for &(fi, ref repo) in &matched {
            let finding = &findings[fi];

            let severity_weight = match finding.severity.as_str() {
                "Critical" => 10.0,
                "High" => 5.0,
                "Medium" => 2.0,
                "Low" => 0.5,
                _ => 0.0,
            };

            let vm = validation_multiplier(&finding.validation_status);
            risk_score += severity_weight * vm * narrative.confidence;

            repo_finding_map.entry(repo.clone()).or_default().push(fi);
        }

        let risk_level = if risk_score >= 20.0 {
            "Critical"
        } else if risk_score >= 10.0 {
            "High"
        } else if risk_score >= 5.0 {
            "Medium"
        } else if risk_score >= 1.0 {
            "Low"
        } else {
            "None"
        };

        let repo_findings: Vec<(String, Vec<usize>)> = repo_finding_map.into_iter().collect();

        // Update narrative fields
        narrative.finding_count = matched.len();
        narrative.risk_score = risk_score;
        narrative.risk_level = risk_level.to_string();
        narrative.repo_findings = repo_findings.clone();

        // Try LLM relevance summary if CrossReference client is configured
        let llm_summary = if !matched.is_empty() {
            try_llm_relevance(narrative, &matched, findings, router).await
        } else {
            None
        };

        // Build links
        for (fi, repo) in &matched {
            let relevance = llm_summary.clone().unwrap_or_else(|| {
                format!(
                    "Finding in repo {} linked to narrative via active_repos",
                    repo
                )
            });
            all_links.push(NarrativeFindingLink {
                narrative_idx: ni,
                finding_idx: *fi,
                repo: repo.clone(),
                relevance,
            });
        }

        if !matched.is_empty() {
            info!(
                narrative = %narrative.title,
                findings = matched.len(),
                risk_score = format!("{:.1}", risk_score),
                risk_level,
                "cross-reference: narrative scored"
            );
        }
    }

    info!(links = all_links.len(), "cross-reference: complete");
    Ok(all_links)
}

/// Attempt a single LLM call per narrative for relevance summary.
/// Returns None if no CrossReference client is configured or the call fails.
async fn try_llm_relevance(
    narrative: &Narrative,
    matched: &[(usize, String)],
    findings: &[SecurityFinding],
    router: &ModelRouter,
) -> Option<String> {
    let client = router.client_for(TaskKind::CrossReference);
    // If it falls back to default, that's fine — still make the call

    let finding_summaries: Vec<String> = matched
        .iter()
        .take(10) // cap to avoid huge prompts
        .map(|(fi, repo)| {
            let f = &findings[*fi];
            format!(
                "- [{}] {} in {}: {}",
                f.severity, f.title, repo, f.description
            )
        })
        .collect();

    let prompt = format!(
        "Narrative: \"{}\"\nSummary: {}\n\nLinked security findings:\n{}\n\n\
         In 1-2 sentences, explain the security relevance of these findings to this ecosystem narrative. Be specific about risk implications.",
        narrative.title,
        narrative.summary,
        finding_summaries.join("\n")
    );

    match client
        .complete(
            "You are a Solana security analyst. Produce concise risk summaries.",
            &prompt,
        )
        .await
    {
        Ok(text) if !text.is_empty() => Some(text.trim().to_string()),
        Ok(_) => None,
        Err(e) => {
            tracing::debug!(error = %e, "cross-reference LLM call failed, using deterministic fallback");
            None
        }
    }
}

fn validation_multiplier(status: &ValidationStatus) -> f64 {
    match status {
        ValidationStatus::Confirmed => 1.0,
        ValidationStatus::Disputed => 0.5,
        ValidationStatus::Unvalidated => 0.7,
        ValidationStatus::Dismissed => 0.0,
    }
}

/// Extract repo name from a finding's file path — same logic as output/mod.rs.
fn repo_name_from_path(path: &Path) -> String {
    let path_str = path.to_string_lossy();
    // Look for "repos/<name>/..." pattern
    if let Some(idx) = path_str.find("repos/") {
        let after = &path_str[idx + 6..];
        if let Some(slash) = after.find('/') {
            return after[..slash].to_string();
        }
        return after.to_string();
    }
    // Fallback: first meaningful path component
    path.components()
        .find_map(|c| {
            let s = c.as_os_str().to_string_lossy();
            if s != "." && s != ".." && s != "repos" {
                Some(s.to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_multiplier_values() {
        assert!((validation_multiplier(&ValidationStatus::Confirmed) - 1.0).abs() < f64::EPSILON);
        assert!((validation_multiplier(&ValidationStatus::Disputed) - 0.5).abs() < f64::EPSILON);
        assert!((validation_multiplier(&ValidationStatus::Unvalidated) - 0.7).abs() < f64::EPSILON);
        assert!((validation_multiplier(&ValidationStatus::Dismissed) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn repo_name_from_repos_prefix() {
        assert_eq!(
            repo_name_from_path(Path::new("repos/my-repo/src/lib.rs")),
            "my-repo"
        );
        assert_eq!(
            repo_name_from_path(Path::new("repos/other-repo/programs/vault.rs")),
            "other-repo"
        );
    }

    #[test]
    fn repo_name_fallback_no_repos_prefix() {
        assert_eq!(repo_name_from_path(Path::new("src/lib.rs")), "src");
    }

    #[test]
    fn repo_name_just_filename() {
        assert_eq!(repo_name_from_path(Path::new("lib.rs")), "lib.rs");
    }
}
