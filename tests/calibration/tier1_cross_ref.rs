use st_solguard::agent::cross_ref;
use st_solguard::llm::{LlmClient, ModelRouter, Provider};
use st_solguard::narrative::Narrative;
use st_solguard::security::{SecurityFinding, ValidationStatus};
use std::path::PathBuf;

use super::ground_truth::GROUND_TRUTH;

fn make_router() -> ModelRouter {
    let client = LlmClient::new(
        Provider::OpenRouter,
        "dummy".into(),
        "test:free".into(),
        100,
        Some("http://localhost:1".into()),
    )
    .unwrap();
    ModelRouter::new(client)
}

fn make_narrative_for_pool(confidence: f64) -> Narrative {
    Narrative {
        title: "Privacy Protocol Growth".into(),
        summary: "Shielded pool protocols gaining traction".into(),
        confidence,
        trend: "Emerging".into(),
        active_repos: vec!["owner/shielded-pool-pinocchio-solana".into()],
        finding_count: 0,
        risk_score: 0.0,
        risk_level: String::new(),
        repo_findings: vec![],
    }
}

fn gt_to_security_finding(
    gt: &super::ground_truth::GroundTruthVuln,
    validation: ValidationStatus,
) -> SecurityFinding {
    SecurityFinding {
        title: gt.title.into(),
        severity: gt.severity.into(),
        description: format!("Ground truth: {}", gt.key_evidence),
        file_path: PathBuf::from(format!(
            "repos/shielded-pool-pinocchio-solana/{}",
            gt.affected_files[0]
        )),
        line_number: 0,
        remediation: "See ground truth".into(),
        validation_status: validation,
        validation_reasoning: None,
    }
}

#[tokio::test]
async fn risk_score_all_confirmed() {
    let router = make_router();
    let mut narratives = vec![make_narrative_for_pool(0.85)];

    let findings: Vec<SecurityFinding> = GROUND_TRUTH
        .iter()
        .map(|gt| gt_to_security_finding(gt, ValidationStatus::Confirmed))
        .collect();

    let links = cross_ref::analyze(&mut narratives, &findings, &router)
        .await
        .unwrap();

    // Expected: 3*Critical(10) + 2*High(5) + 2*Medium(2) = 30+10+4 = 44
    // All Confirmed(1.0) * confidence(0.85) = 44 * 0.85 = 37.4
    let score = narratives[0].risk_score;
    assert!(
        (score - 37.4).abs() < 0.1,
        "risk_score should be 37.4, got {score:.1}"
    );
    assert_eq!(
        narratives[0].risk_level, "Critical",
        "score 37.4 → Critical"
    );
    assert_eq!(links.len(), 7, "all 7 findings should link");
}

#[tokio::test]
async fn risk_score_disputed_findings() {
    let router = make_router();
    let mut narratives = vec![make_narrative_for_pool(0.85)];

    // Only the 2 Medium findings, both Disputed
    let findings: Vec<SecurityFinding> = GROUND_TRUTH
        .iter()
        .filter(|gt| gt.severity == "Medium")
        .map(|gt| gt_to_security_finding(gt, ValidationStatus::Disputed))
        .collect();
    assert_eq!(findings.len(), 2, "should have 2 medium findings");

    cross_ref::analyze(&mut narratives, &findings, &router)
        .await
        .unwrap();

    // Expected: 2*Medium(2) * Disputed(0.5) * confidence(0.85) = 4 * 0.5 * 0.85 = 1.7
    let score = narratives[0].risk_score;
    assert!(
        (score - 1.7).abs() < 0.1,
        "disputed medium → score 1.7, got {score:.1}"
    );
    assert_eq!(narratives[0].risk_level, "Low", "score 1.7 → Low");
}
