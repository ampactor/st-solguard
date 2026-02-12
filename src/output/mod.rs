use crate::narrative::Narrative;
use crate::security::SecurityFinding;
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
    narratives: Vec<NarrativeView>,
    repo_summaries: Vec<RepoSummary>,
    top_findings: Vec<FindingView>,
    remaining_findings: Vec<FindingView>,
    remaining_count: usize,
}

#[allow(dead_code)] // fields used by Askama template
struct NarrativeView {
    title: String,
    summary: String,
    confidence_pct: u32,
    trend: String,
    repo_count: usize,
}

#[allow(dead_code)] // fields used by Askama template
struct FindingView {
    title: String,
    severity: String,
    severity_class: String,
    description: String,
    file_path: String,
    line_number: usize,
    remediation: String,
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

fn to_finding_view(f: &SecurityFinding) -> FindingView {
    FindingView {
        title: f.title.clone(),
        severity: f.severity.clone(),
        severity_class: severity_class(&f.severity),
        description: f.description.clone(),
        file_path: f.file_path.display().to_string(),
        line_number: f.line_number,
        remediation: f.remediation.clone(),
    }
}

/// Extract repo name from a finding's file path (first component under repos/).
fn repo_name(f: &SecurityFinding) -> String {
    let path = f.file_path.to_string_lossy();
    // Look for "repos/<name>/..." pattern
    if let Some(idx) = path.find("repos/") {
        let after = &path[idx + 6..];
        if let Some(slash) = after.find('/') {
            return after[..slash].to_string();
        }
        return after.to_string();
    }
    // Fallback: use first meaningful path component
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

pub fn render_combined_report(
    narratives: &[Narrative],
    findings: &[SecurityFinding],
) -> anyhow::Result<String> {
    let narrative_views: Vec<NarrativeView> = narratives
        .iter()
        .map(|n| NarrativeView {
            title: n.title.clone(),
            summary: n.summary.clone(),
            confidence_pct: (n.confidence * 100.0) as u32,
            trend: n.trend.clone(),
            repo_count: n.active_repos.len(),
        })
        .collect();

    // Severity counts
    let severity_critical = findings.iter().filter(|f| f.severity == "Critical").count();
    let severity_high = findings.iter().filter(|f| f.severity == "High").count();
    let severity_medium = findings.iter().filter(|f| f.severity == "Medium").count();
    let severity_low = findings.iter().filter(|f| f.severity == "Low").count();
    let severity_info = findings.iter().filter(|f| f.severity == "Info").count();
    let critical_count = severity_critical + severity_high;

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
    // Sort by total findings descending
    repo_summaries.sort_by(|a, b| b.total.cmp(&a.total));

    let repo_count = repo_summaries.len();

    // Split findings: top (Critical/High) vs remaining
    let top_findings: Vec<FindingView> = findings
        .iter()
        .filter(|f| f.severity == "Critical" || f.severity == "High")
        .map(to_finding_view)
        .collect();

    let remaining_findings: Vec<FindingView> = findings
        .iter()
        .filter(|f| f.severity != "Critical" && f.severity != "High")
        .map(to_finding_view)
        .collect();

    let remaining_count = remaining_findings.len();

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
        narratives: narrative_views,
        repo_summaries,
        top_findings,
        remaining_findings,
        remaining_count,
    };

    report
        .render()
        .map_err(|e| anyhow::anyhow!("template render: {e}"))
}
