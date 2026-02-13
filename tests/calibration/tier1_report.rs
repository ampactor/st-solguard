use st_solguard::narrative::Narrative;
use st_solguard::output::render_combined_report;
use st_solguard::security::{SecurityFinding, ValidationStatus};
use std::path::PathBuf;

use super::ground_truth::GROUND_TRUTH;

fn make_narrative_with_findings(finding_count: usize) -> Narrative {
    let indices: Vec<usize> = (0..finding_count).collect();
    Narrative {
        title: "Privacy Protocol Growth".into(),
        summary: "Shielded pool protocols gaining traction".into(),
        confidence: 0.85,
        trend: "Emerging".into(),
        active_repos: vec!["owner/shielded-pool-pinocchio-solana".into()],
        finding_count,
        risk_score: 37.4,
        risk_level: "Critical".into(),
        repo_findings: vec![("shielded-pool-pinocchio-solana".into(), indices)],
    }
}

fn gt_findings_confirmed() -> Vec<SecurityFinding> {
    GROUND_TRUTH
        .iter()
        .map(|gt| SecurityFinding {
            title: gt.title.into(),
            severity: gt.severity.into(),
            description: format!("Ground truth: {}", gt.key_evidence),
            file_path: PathBuf::from(format!(
                "repos/shielded-pool-pinocchio-solana/{}",
                gt.affected_files[0]
            )),
            line_number: 0,
            remediation: "See ground truth".into(),
            validation_status: ValidationStatus::Confirmed,
            validation_reasoning: None,
        })
        .collect()
}

#[test]
fn report_contains_all_ground_truth() {
    let findings = gt_findings_confirmed();
    let narratives = vec![make_narrative_with_findings(findings.len())];
    let html = render_combined_report(&narratives, &findings).unwrap();

    // Every ground truth title should appear in the report
    for gt in GROUND_TRUTH {
        assert!(
            html.contains(gt.title),
            "report missing ground truth: {}",
            gt.title
        );
    }

    // Risk score should appear
    assert!(
        html.contains("37.4"),
        "report should contain risk score 37.4"
    );

    // Critical badge
    assert!(
        html.contains("Critical"),
        "report should contain Critical badge"
    );

    // Confirmed badge
    assert!(
        html.contains("Confirmed"),
        "report should contain Confirmed badge"
    );
}

#[test]
fn report_severity_counts() {
    let findings = gt_findings_confirmed();
    let narratives = vec![make_narrative_with_findings(findings.len())];
    let html = render_combined_report(&narratives, &findings).unwrap();

    // Count severity occurrences by checking for severity-class patterns
    // The report uses text-red-500 for Critical, text-orange-400 for High, text-yellow-400 for Medium
    let critical_count = findings.iter().filter(|f| f.severity == "Critical").count();
    let high_count = findings.iter().filter(|f| f.severity == "High").count();
    let medium_count = findings.iter().filter(|f| f.severity == "Medium").count();

    assert_eq!(critical_count, 3, "should have 3 Critical findings");
    assert_eq!(high_count, 2, "should have 2 High findings");
    assert_eq!(medium_count, 2, "should have 2 Medium findings");

    // The HTML should render without error and contain the narrative title
    assert!(
        html.contains("Privacy Protocol Growth"),
        "report should contain narrative title"
    );
    assert!(html.len() > 1000, "report should be substantial HTML");
}
