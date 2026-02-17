use crate::memory::RunMemory;
use crate::narrative::Narrative;
use crate::security::{SecurityFinding, ValidationStatus};
use askama::Template;
use chrono::Utc;
use std::collections::BTreeMap;

#[derive(Template)]
#[template(path = "solguard_report.html")]
struct SolGuardReport {
    generated_at: String,
    narrative_count: usize,
    finding_count: usize,
    repo_count: usize,
    critical_count: usize,
    severity_critical: usize,
    severity_high: usize,
    severity_medium: usize,
    severity_low: usize,
    severity_info: usize,
    confirmed_count: usize,
    disputed_count: usize,
    has_validation: bool,
    narratives: Vec<NarrativeView>,
    repo_summaries: Vec<RepoSummary>,
    orphan_groups: Vec<GroupedFinding>,
    orphan_count: usize,
    learning_total_runs: u32,
    learning_repos_blocklisted: usize,
    learning_errors_learned: usize,
}

#[allow(dead_code)] // fields used by Askama template
struct NarrativeView {
    title: String,
    summary: String,
    confidence_pct: u32,
    trend: String,
    repo_count: usize,
    finding_count: usize,
    risk_score_fmt: String,
    risk_level: String,
    risk_class: String,
    grouped_findings: Vec<GroupedFinding>,
    repo_context: String,
}

#[allow(dead_code)] // fields used by Askama template
struct FindingView {
    title: String,
    severity: String,
    severity_class: String,
    description: String,
    remediation: String,
    file_location: String,
    repo: String,
    validation_badge: String,
    validation_class: String,
    validation_reasoning: String,
    provenance: String,
}

#[allow(dead_code)] // fields used by Askama template
struct GroupedFinding {
    title: String,
    severity: String,
    severity_class: String,
    repo: String,
    count: usize,
    example: FindingView,
}

#[allow(dead_code)] // fields used by Askama template
struct RepoSummary {
    name: String,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    total: usize,
}

fn severity_class(severity: &str) -> String {
    match severity {
        "Critical" => "text-red-500".into(),
        "High" => "text-orange-400".into(),
        "Medium" => "text-yellow-400".into(),
        "Low" => "text-blue-400".into(),
        _ => "text-gray-400".into(),
    }
}

fn risk_class(level: &str) -> String {
    match level {
        "Critical" => "bg-red-900/30 text-red-400 border-red-800/50".into(),
        "High" => "bg-orange-900/30 text-orange-400 border-orange-800/50".into(),
        "Medium" => "bg-yellow-900/30 text-yellow-400 border-yellow-800/50".into(),
        "Low" => "bg-blue-900/30 text-blue-400 border-blue-800/50".into(),
        _ => "bg-gray-800 text-gray-400 border-gray-700".into(),
    }
}

fn validation_class(status: &ValidationStatus) -> String {
    match status {
        ValidationStatus::Confirmed => "bg-green-900/30 text-green-400".into(),
        ValidationStatus::Disputed => "bg-yellow-900/30 text-yellow-400".into(),
        ValidationStatus::Unvalidated => "bg-gray-800 text-gray-400".into(),
        ValidationStatus::Dismissed => "bg-red-900/30 text-red-400".into(),
    }
}

fn validation_badge(status: &ValidationStatus) -> String {
    match status {
        ValidationStatus::Confirmed => "Confirmed".into(),
        ValidationStatus::Disputed => "Disputed".into(),
        ValidationStatus::Unvalidated => "Unvalidated".into(),
        ValidationStatus::Dismissed => "Dismissed".into(),
    }
}

/// Extract repo name from a finding's file path (first component under repos/).
fn repo_name(f: &SecurityFinding) -> String {
    let path = f.file_path.to_string_lossy();
    if let Some(idx) = path.find("repos/") {
        let after = &path[idx + 6..];
        if let Some(slash) = after.find('/') {
            return after[..slash].to_string();
        }
        return after.to_string();
    }
    f.file_path
        .components()
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

fn finding_to_view(f: &SecurityFinding, provenance: String) -> FindingView {
    FindingView {
        title: f.title.clone(),
        severity_class: severity_class(&f.severity),
        description: f.description.clone(),
        remediation: f.remediation.clone(),
        file_location: format!("{}:{}", f.file_path.display(), f.line_number),
        repo: repo_name(f),
        validation_badge: validation_badge(&f.validation_status),
        validation_class: validation_class(&f.validation_status),
        validation_reasoning: f.validation_reasoning.clone().unwrap_or_default(),
        severity: f.severity.clone(),
        provenance,
    }
}

fn group_findings(findings: Vec<FindingView>) -> Vec<GroupedFinding> {
    let mut map: BTreeMap<(String, String), Vec<FindingView>> = BTreeMap::new();
    for f in findings {
        map.entry((f.title.clone(), f.repo.clone()))
            .or_default()
            .push(f);
    }
    let mut groups: Vec<GroupedFinding> = map
        .into_iter()
        .map(|((title, repo), mut members)| {
            members.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));
            let count = members.len();
            let severity = members[0].severity.clone();
            let severity_class = members[0].severity_class.clone();
            let example = members.into_iter().next().unwrap();
            GroupedFinding {
                title,
                severity,
                severity_class,
                repo,
                count,
                example,
            }
        })
        .collect();
    groups.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));
    groups
}

pub fn render_combined_report(
    narratives: &[Narrative],
    findings: &[SecurityFinding],
    run_memory: Option<&RunMemory>,
) -> anyhow::Result<String> {
    // Build narrative views with linked findings
    let narrative_views: Vec<NarrativeView> = narratives
        .iter()
        .map(|n| {
            let mut linked = Vec::new();
            for (_, indices) in &n.repo_findings {
                for &idx in indices {
                    if let Some(f) = findings.get(idx) {
                        let scan_type = if f.line_number == 0 {
                            "deep agent review"
                        } else {
                            "static scan"
                        };
                        let provenance = format!(
                            "Source: {} ({}%) \u{2192} target selection \u{2192} {} \u{2192} {}",
                            n.title,
                            (n.confidence * 100.0) as u32,
                            scan_type,
                            validation_badge(&f.validation_status),
                        );
                        linked.push(finding_to_view(f, provenance));
                    }
                }
            }

            let rl = if n.risk_level.is_empty() {
                "None"
            } else {
                &n.risk_level
            };
            let repos_display = if n.active_repos.is_empty() {
                "none yet".to_string()
            } else if n.active_repos.len() <= 3 {
                n.active_repos.join(", ")
            } else {
                format!(
                    "{} + {} more",
                    n.active_repos[..3].join(", "),
                    n.active_repos.len() - 3
                )
            };
            let repo_context = format!(
                "Repos selected from \"{}\" narrative ({}% confidence, {} trend): {}",
                n.title,
                (n.confidence * 100.0) as u32,
                n.trend,
                repos_display,
            );
            NarrativeView {
                title: n.title.clone(),
                summary: n.summary.clone(),
                confidence_pct: (n.confidence * 100.0) as u32,
                trend: n.trend.clone(),
                repo_count: n.active_repos.len(),
                finding_count: n.finding_count,
                risk_score_fmt: format!("{:.1}", n.risk_score),
                risk_level: rl.to_string(),
                risk_class: risk_class(rl),
                grouped_findings: group_findings(linked),
                repo_context,
            }
        })
        .collect();

    // Orphan findings: not linked to any narrative — render under "Additional Findings"
    let linked_indices: std::collections::HashSet<usize> = narratives
        .iter()
        .flat_map(|n| n.repo_findings.iter().flat_map(|(_, v)| v.iter().copied()))
        .collect();
    let orphan_views: Vec<FindingView> = findings
        .iter()
        .enumerate()
        .filter(|(i, _)| !linked_indices.contains(i))
        .map(|(_, f)| {
            let scan_type = if f.line_number == 0 {
                "deep agent review"
            } else {
                "static scan"
            };
            let provenance = format!(
                "Source: {} \u{2192} {}",
                scan_type,
                validation_badge(&f.validation_status),
            );
            finding_to_view(f, provenance)
        })
        .collect();
    let orphan_count = orphan_views.len();
    let orphan_groups = group_findings(orphan_views);

    // Severity counts
    let severity_critical = findings.iter().filter(|f| f.severity == "Critical").count();
    let severity_high = findings.iter().filter(|f| f.severity == "High").count();
    let severity_medium = findings.iter().filter(|f| f.severity == "Medium").count();
    let severity_low = findings.iter().filter(|f| f.severity == "Low").count();
    let severity_info = findings.iter().filter(|f| f.severity == "Info").count();
    let critical_count = severity_critical + severity_high;

    // Validation counts
    let confirmed_count = findings
        .iter()
        .filter(|f| f.validation_status == ValidationStatus::Confirmed)
        .count();
    let disputed_count = findings
        .iter()
        .filter(|f| f.validation_status == ValidationStatus::Disputed)
        .count();
    let has_validation = findings
        .iter()
        .any(|f| f.validation_status != ValidationStatus::Unvalidated);

    // Per-repo summaries
    let mut repo_map: BTreeMap<String, [usize; 5]> = BTreeMap::new();
    for f in findings {
        let name = repo_name(f);
        let counts = repo_map.entry(name).or_insert([0; 5]);
        match f.severity.as_str() {
            "Critical" => counts[0] += 1,
            "High" => counts[1] += 1,
            "Medium" => counts[2] += 1,
            "Low" => counts[3] += 1,
            _ => counts[4] += 1,
        }
    }
    let mut repo_summaries: Vec<RepoSummary> = repo_map
        .into_iter()
        .map(|(name, c)| RepoSummary {
            name,
            critical: c[0],
            high: c[1],
            medium: c[2],
            low: c[3],
            total: c.iter().sum(),
        })
        .collect();
    repo_summaries.sort_by(|a, b| b.total.cmp(&a.total));

    let repo_count = repo_summaries.len();

    let (learning_total_runs, learning_repos_blocklisted, learning_errors_learned) =
        match run_memory {
            Some(mem) => (
                mem.total_runs,
                mem.repo_blocklist.len(),
                mem.error_memory.len(),
            ),
            None => (0, 0, 0),
        };

    let report = SolGuardReport {
        generated_at: Utc::now().format("%Y-%m-%d %H:%M UTC").to_string(),
        narrative_count: narratives.len(),
        finding_count: findings.len(),
        repo_count,
        critical_count,
        severity_critical,
        severity_high,
        severity_medium,
        severity_low,
        severity_info,
        confirmed_count,
        disputed_count,
        has_validation,
        narratives: narrative_views,
        repo_summaries,
        orphan_groups,
        orphan_count,
        learning_total_runs,
        learning_repos_blocklisted,
        learning_errors_learned,
    };

    report
        .render()
        .map_err(|e| anyhow::anyhow!("template render: {e}"))
}

fn severity_order(severity: &str) -> u8 {
    match severity {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        "Low" => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_test_finding() -> SecurityFinding {
        SecurityFinding {
            title: "Test".into(),
            severity: "Medium".into(),
            description: "desc".into(),
            file_path: PathBuf::from("repos/test-repo/src/lib.rs"),
            line_number: 1,
            remediation: "fix it".into(),
            validation_status: ValidationStatus::Unvalidated,
            validation_reasoning: None,
        }
    }

    #[test]
    fn severity_class_values() {
        assert!(severity_class("Critical").contains("red"));
        assert!(severity_class("High").contains("orange"));
        assert!(severity_class("Medium").contains("yellow"));
        assert!(severity_class("Low").contains("blue"));
        assert!(severity_class("Info").contains("gray"));
    }

    #[test]
    fn risk_class_values() {
        assert!(risk_class("Critical").contains("red"));
        assert!(risk_class("High").contains("orange"));
        assert!(risk_class("Medium").contains("yellow"));
        assert!(risk_class("Low").contains("blue"));
        assert!(risk_class("None").contains("gray"));
    }

    #[test]
    fn validation_badge_values() {
        assert_eq!(validation_badge(&ValidationStatus::Confirmed), "Confirmed");
        assert_eq!(validation_badge(&ValidationStatus::Disputed), "Disputed");
        assert_eq!(
            validation_badge(&ValidationStatus::Unvalidated),
            "Unvalidated"
        );
        assert_eq!(validation_badge(&ValidationStatus::Dismissed), "Dismissed");
    }

    #[test]
    fn severity_order_values() {
        assert_eq!(severity_order("Critical"), 0);
        assert_eq!(severity_order("High"), 1);
        assert_eq!(severity_order("Medium"), 2);
        assert_eq!(severity_order("Low"), 3);
        assert_eq!(severity_order("Info"), 4);
        assert!(severity_order("Critical") < severity_order("High"));
    }

    #[test]
    fn repo_name_from_repos_path() {
        let f = SecurityFinding {
            file_path: PathBuf::from("repos/my-repo/src/lib.rs"),
            ..make_test_finding()
        };
        assert_eq!(repo_name(&f), "my-repo");
    }

    #[test]
    fn repo_name_fallback() {
        let f = SecurityFinding {
            file_path: PathBuf::from("src/lib.rs"),
            ..make_test_finding()
        };
        assert_eq!(repo_name(&f), "src");
    }
}
