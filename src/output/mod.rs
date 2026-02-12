use crate::narrative::Narrative;
use crate::security::SecurityFinding;
use askama::Template;
use chrono::Utc;

#[derive(Template)]
#[template(path = "solguard_report.html")]
struct SolGuardReport {
    generated_at: String,
    narrative_count: usize,
    finding_count: usize,
    narratives: Vec<NarrativeView>,
    findings: Vec<FindingView>,
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
    remediation: String,
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

    let finding_views: Vec<FindingView> = findings
        .iter()
        .map(|f| FindingView {
            title: f.title.clone(),
            severity: f.severity.clone(),
            severity_class: match f.severity.as_str() {
                "Critical" => "text-red-500".into(),
                "High" => "text-orange-400".into(),
                "Medium" => "text-yellow-400".into(),
                _ => "text-blue-400".into(),
            },
            description: f.description.clone(),
            file_path: f.file_path.display().to_string(),
            remediation: f.remediation.clone(),
        })
        .collect();

    let report = SolGuardReport {
        generated_at: Utc::now().format("%Y-%m-%d %H:%M UTC").to_string(),
        narrative_count: narratives.len(),
        finding_count: findings.len(),
        narratives: narrative_views,
        findings: finding_views,
    };

    report
        .render()
        .map_err(|e| anyhow::anyhow!("template render: {e}"))
}
