use st_solguard::narrative::Narrative;
use st_solguard::output;
use st_solguard::security::{SecurityFinding, ValidationStatus};
use std::path::PathBuf;

fn make_narrative(title: &str, repos: Vec<&str>, risk_score: f64, risk_level: &str) -> Narrative {
    Narrative {
        title: title.into(),
        summary: format!("Summary of {title}"),
        confidence: 0.8,
        trend: "Accelerating".into(),
        active_repos: repos.into_iter().map(String::from).collect(),
        finding_count: 0,
        risk_score,
        risk_level: risk_level.into(),
        repo_findings: vec![],
    }
}

fn make_finding(
    title: &str,
    severity: &str,
    repo_path: &str,
    validation: ValidationStatus,
) -> SecurityFinding {
    SecurityFinding {
        title: title.into(),
        severity: severity.into(),
        description: format!("Description of {title}"),
        file_path: PathBuf::from(repo_path),
        line_number: 42,
        remediation: "Fix it".into(),
        validation_status: validation,
        validation_reasoning: Some("test reasoning".into()),
    }
}

#[test]
fn report_contains_narrative_titles() {
    let narratives = vec![make_narrative(
        "DeFi Growth",
        vec!["owner/repo1"],
        15.0,
        "High",
    )];
    let findings = vec![];
    let html = output::render_combined_report(&narratives, &findings).unwrap();
    assert!(html.contains("DeFi Growth"));
}

#[test]
fn report_contains_finding_titles() {
    let narratives = vec![];
    let findings = vec![make_finding(
        "Missing Signer",
        "High",
        "repos/test/src/lib.rs",
        ValidationStatus::Unvalidated,
    )];
    let html = output::render_combined_report(&narratives, &findings).unwrap();
    assert!(html.contains("Missing Signer"));
}

#[test]
fn report_contains_validation_badges() {
    let mut n = make_narrative("Test", vec!["owner/test"], 5.0, "Medium");
    n.repo_findings = vec![("test".into(), vec![0])];
    n.finding_count = 1;
    let narratives = vec![n];
    let findings = vec![make_finding(
        "Confirmed Bug",
        "Critical",
        "repos/test/src/lib.rs",
        ValidationStatus::Confirmed,
    )];
    let html = output::render_combined_report(&narratives, &findings).unwrap();
    assert!(html.contains("Confirmed"));
}

#[test]
fn report_has_orphan_findings() {
    let narratives = vec![make_narrative(
        "Unrelated",
        vec!["owner/other"],
        0.0,
        "None",
    )];
    let findings = vec![make_finding(
        "Orphan Bug",
        "Medium",
        "repos/orphan-repo/src/lib.rs",
        ValidationStatus::Unvalidated,
    )];
    let html = output::render_combined_report(&narratives, &findings).unwrap();
    assert!(html.contains("Orphan Bug"));
}

#[test]
fn empty_narratives_and_findings_produce_valid_html() {
    let html = output::render_combined_report(&[], &[]).unwrap();
    assert!(
        html.contains("html") || html.contains("<!DOCTYPE") || html.contains("<html"),
        "should produce valid HTML"
    );
}
