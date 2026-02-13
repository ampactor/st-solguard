use st_solguard::agent::cross_ref;
use st_solguard::llm::{LlmClient, ModelRouter, Provider};
use st_solguard::narrative::Narrative;
use st_solguard::security::{SecurityFinding, ValidationStatus};
use std::path::PathBuf;

fn make_narrative(title: &str, repos: Vec<&str>, confidence: f64) -> Narrative {
    Narrative {
        title: title.into(),
        summary: format!("Summary of {title}"),
        confidence,
        trend: "Emerging".into(),
        active_repos: repos.into_iter().map(String::from).collect(),
        finding_count: 0,
        risk_score: 0.0,
        risk_level: String::new(),
        repo_findings: vec![],
    }
}

fn make_finding(
    title: &str,
    severity: &str,
    file_path: &str,
    validation: ValidationStatus,
) -> SecurityFinding {
    SecurityFinding {
        title: title.into(),
        severity: severity.into(),
        description: "desc".into(),
        file_path: PathBuf::from(file_path),
        line_number: 1,
        remediation: "fix".into(),
        validation_status: validation,
        validation_reasoning: None,
    }
}

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

#[tokio::test]
async fn finding_links_to_narrative_by_repo() {
    let router = make_router();
    let mut narratives = vec![make_narrative("DeFi Growth", vec!["owner/my-repo"], 0.8)];
    let findings = vec![make_finding(
        "Bug",
        "Critical",
        "repos/my-repo/src/lib.rs",
        ValidationStatus::Confirmed,
    )];

    let links = cross_ref::analyze(&mut narratives, &findings, &router)
        .await
        .unwrap();
    assert!(!links.is_empty(), "should link finding to narrative");
    assert_eq!(links[0].narrative_idx, 0);
    assert_eq!(links[0].finding_idx, 0);
    assert_eq!(links[0].repo, "my-repo");
}

#[tokio::test]
async fn finding_does_not_link_to_wrong_narrative() {
    let router = make_router();
    let mut narratives = vec![make_narrative("DeFi Growth", vec!["owner/other-repo"], 0.8)];
    let findings = vec![make_finding(
        "Bug",
        "High",
        "repos/my-repo/src/lib.rs",
        ValidationStatus::Unvalidated,
    )];

    let links = cross_ref::analyze(&mut narratives, &findings, &router)
        .await
        .unwrap();
    assert!(
        links.is_empty(),
        "should not link finding to unrelated narrative"
    );
}

#[tokio::test]
async fn risk_score_computation() {
    let router = make_router();
    let mut narratives = vec![make_narrative("Test", vec!["owner/my-repo"], 0.8)];
    let findings = vec![make_finding(
        "Bug",
        "Critical",
        "repos/my-repo/src/lib.rs",
        ValidationStatus::Confirmed,
    )];

    cross_ref::analyze(&mut narratives, &findings, &router)
        .await
        .unwrap();
    // Risk = severity_weight(Critical=10) * validation_multiplier(Confirmed=1.0) * confidence(0.8) = 8.0
    assert!(
        (narratives[0].risk_score - 8.0).abs() < 0.01,
        "risk_score should be 8.0, got {}",
        narratives[0].risk_score
    );
    assert_eq!(narratives[0].risk_level, "Medium"); // 5 <= 8 < 10
}

#[tokio::test]
async fn risk_level_thresholds() {
    let router = make_router();
    // Multiple findings to push score above 20
    let mut narratives = vec![make_narrative("Big Risk", vec!["owner/my-repo"], 1.0)];
    let findings = vec![
        make_finding(
            "Bug1",
            "Critical",
            "repos/my-repo/src/a.rs",
            ValidationStatus::Confirmed,
        ),
        make_finding(
            "Bug2",
            "Critical",
            "repos/my-repo/src/b.rs",
            ValidationStatus::Confirmed,
        ),
        make_finding(
            "Bug3",
            "Critical",
            "repos/my-repo/src/c.rs",
            ValidationStatus::Confirmed,
        ),
    ];

    cross_ref::analyze(&mut narratives, &findings, &router)
        .await
        .unwrap();
    // 3 * 10.0 * 1.0 * 1.0 = 30.0 -> Critical
    assert_eq!(narratives[0].risk_level, "Critical");
}
