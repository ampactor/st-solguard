use st_solguard::agent::infer_protocol_category;
use st_solguard::narrative::Narrative;
use st_solguard::security::agent_review::compute_budget;

fn make_narrative(title: &str, summary: &str) -> Narrative {
    Narrative {
        title: title.into(),
        summary: summary.into(),
        confidence: 0.8,
        trend: "Emerging".into(),
        active_repos: vec![],
        finding_count: 0,
        risk_score: 0.0,
        risk_level: String::new(),
        repo_findings: vec![],
    }
}

#[test]
fn privacy_narrative_infers_privacy() {
    let n = make_narrative(
        "Shielded Pool Privacy Protocol Emerges",
        "New privacy-preserving transaction protocol gains traction on Solana",
    );
    assert_eq!(
        infer_protocol_category(&n),
        Some("Privacy".into()),
        "privacy/shielded keywords should map to Privacy category"
    );
}

#[test]
fn dex_narrative_infers_dex() {
    let n = make_narrative("New DEX Protocol Launches", "AMM with novel swap mechanism");
    assert_eq!(infer_protocol_category(&n), Some("DEX".into()));
}

#[test]
fn lending_narrative_infers_lending() {
    let n = make_narrative("Lending Platform Growth", "Borrow rates attract users");
    assert_eq!(infer_protocol_category(&n), Some("Lending".into()));
}

#[test]
fn generic_narrative_infers_none() {
    let n = make_narrative(
        "Miscellaneous Protocol Update",
        "Some protocol released a new version with various improvements",
    );
    assert_eq!(
        infer_protocol_category(&n),
        None,
        "generic narrative should not match any category"
    );
}

#[test]
fn budget_high_confidence_single_repo() {
    let (turns, cost) = compute_budget(0.85, 1);
    // depth = 0.85 * 1/sqrt(1) = 0.85
    // turns = (30 * 0.85).clamp(5,40) = 25
    // cost  = (20 * 0.85).clamp(2,30) = 17.0
    assert_eq!(turns, 25, "high confidence single repo → 25 turns");
    assert!(
        (cost - 17.0).abs() < 0.01,
        "high confidence single repo → $17.00, got ${cost:.2}"
    );
}

#[test]
fn budget_low_confidence_many_repos() {
    let (turns, cost) = compute_budget(0.6, 3);
    // depth = 0.6 * 1/sqrt(3) = 0.6 * 0.57735 = 0.34641
    // turns = (30 * 0.34641).clamp(5,40) = 10.39 → 10
    // cost  = (20 * 0.34641).clamp(2,30) = 6.928
    assert_eq!(turns, 10, "low confidence many repos → 10 turns");
    assert!(
        (cost - 6.93).abs() < 0.1,
        "low confidence many repos → ~$6.93, got ${cost:.2}"
    );
}
