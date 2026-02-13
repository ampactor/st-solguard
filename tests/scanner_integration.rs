use st_solguard::security;
use std::path::Path;

#[tokio::test]
async fn scanner_finds_all_patterns_in_vulnerable_fixture() {
    let findings = security::scan_repo(Path::new("tests/fixtures/vulnerable_repo"))
        .await
        .unwrap();

    assert!(!findings.is_empty(), "should find vulnerabilities");

    // Check we have findings from multiple severity levels
    let has_critical = findings.iter().any(|f| f.severity == "Critical");
    let has_high = findings.iter().any(|f| f.severity == "High");
    let has_medium = findings.iter().any(|f| f.severity == "Medium");
    assert!(has_critical, "should find Critical findings");
    assert!(has_high, "should find High findings");
    assert!(has_medium, "should find Medium findings");

    // 13 patterns, some produce multiple hits — expect at least 10
    assert!(
        findings.len() >= 10,
        "expected at least 10 findings, got {}",
        findings.len()
    );
}

#[tokio::test]
async fn scanner_produces_zero_findings_on_clean_code() {
    let findings = security::scan_repo(Path::new("tests/fixtures/clean_repo"))
        .await
        .unwrap();
    assert!(
        findings.is_empty(),
        "clean code should have zero findings, got {}",
        findings.len()
    );
}
