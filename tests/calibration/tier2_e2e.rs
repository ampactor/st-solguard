use st_solguard::agent::cross_ref;
use st_solguard::llm::{LlmClient, ModelRouter, Provider};
use st_solguard::narrative::Narrative;
use st_solguard::output::render_combined_report;
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

/// Full pipeline data flow: narrative → findings → cross-ref → report.
/// No LLM calls — uses ground truth data and dummy router (LLM calls fail gracefully).
#[tokio::test]
async fn full_pipeline_data_flow() {
    let router = make_router();

    // Phase 1: Synthetic narrative (simulates narrative detection output)
    let mut narratives = vec![Narrative {
        title: "Privacy Protocol Growth on Solana".into(),
        summary: "Shielded pool and mixer protocols gaining developer traction".into(),
        confidence: 0.85,
        trend: "Emerging".into(),
        active_repos: vec!["owner/shielded-pool-pinocchio-solana".into()],
        finding_count: 0,
        risk_score: 0.0,
        risk_level: String::new(),
        repo_findings: vec![],
    }];

    // Phase 2-3: Ground truth as SecurityFindings (simulates scanner + agent output)
    let findings: Vec<SecurityFinding> = GROUND_TRUTH
        .iter()
        .map(|gt| SecurityFinding {
            title: gt.title.into(),
            severity: gt.severity.into(),
            description: format!("{}: {}", gt.id, gt.key_evidence),
            file_path: PathBuf::from(format!(
                "repos/shielded-pool-pinocchio-solana/{}",
                gt.affected_files[0]
            )),
            line_number: 0,
            remediation: "See ground truth".into(),
            validation_status: ValidationStatus::Confirmed,
            validation_reasoning: Some("Manually verified in T32 clean-room analysis".into()),
        })
        .collect();

    // Phase 4: Cross-reference
    let links = cross_ref::analyze(&mut narratives, &findings, &router)
        .await
        .unwrap();

    assert_eq!(links.len(), 7, "all 7 findings should link to narrative");
    assert!(
        narratives[0].risk_score > 30.0,
        "risk score should be > 30 for 7 confirmed findings"
    );
    assert_eq!(narratives[0].risk_level, "Critical");

    // Phase 5: Report generation
    let html = render_combined_report(&narratives, &findings, None).unwrap();

    // Verify all data flows through to the report
    for gt in GROUND_TRUTH {
        assert!(
            html.contains(gt.title),
            "report missing finding: {}",
            gt.title
        );
    }
    assert!(
        html.contains("Privacy Protocol Growth"),
        "report missing narrative title"
    );
    assert!(
        html.contains("Critical"),
        "report missing Critical risk badge"
    );
    assert!(
        html.contains("Confirmed"),
        "report missing Confirmed validation badge"
    );
    assert!(
        html.contains(&format!("{:.1}", narratives[0].risk_score)),
        "report missing risk score"
    );
}

/// Compare severity distributions across model outputs.
/// T32 (opus): 7 findings, 3C/2H/2M
/// T33 (trinity): 6 findings
/// T33 (deepseek): 5 findings
#[test]
fn model_comparison_severity_distributions() {
    let t32: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../../test-results/T32-opus-clean-room.json")).unwrap();
    let t33_trinity: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../../test-results/T33-trinity-fixed.json")).unwrap();
    let t33_deepseek: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../../test-results/T33-deepseek-fixed.json")).unwrap();

    // Total finding counts
    assert_eq!(t32.len(), 7, "T32 opus should have 7 findings");
    assert_eq!(t33_trinity.len(), 6, "T33 trinity should have 6 findings");
    assert_eq!(t33_deepseek.len(), 5, "T33 deepseek should have 5 findings");

    // T32 severity breakdown
    let t32_critical = t32
        .iter()
        .filter(|v| v["severity"].as_str() == Some("Critical"))
        .count();
    let trinity_critical = t33_trinity
        .iter()
        .filter(|v| v["severity"].as_str() == Some("Critical"))
        .count();

    assert_eq!(t32_critical, 3, "T32 should have 3 Critical");

    // Opus should find at least as many criticals as free models
    assert!(
        t32_critical >= trinity_critical,
        "opus criticals ({t32_critical}) should be >= trinity criticals ({trinity_critical})"
    );

    eprintln!("Model comparison:");
    eprintln!(
        "  T32 opus:    {} findings ({} Critical)",
        t32.len(),
        t32_critical
    );
    eprintln!(
        "  T33 trinity: {} findings ({} Critical)",
        t33_trinity.len(),
        trinity_critical
    );
    eprintln!(
        "  T33 deepseek: {} findings ({} Critical)",
        t33_deepseek.len(),
        t33_deepseek
            .iter()
            .filter(|v| v["severity"].as_str() == Some("Critical"))
            .count()
    );
}
