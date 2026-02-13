use st_solguard::security::agent_review::try_parse_findings;

use super::ground_truth::GROUND_TRUTH;

const T32_FIXTURE: &str = include_str!("../fixtures/t32_opus_findings.txt");

#[test]
fn t32_findings_parse_correctly() {
    let findings =
        try_parse_findings(T32_FIXTURE).expect("T32 fixture should parse as AgentFinding array");
    assert_eq!(findings.len(), 7, "T32 should have exactly 7 findings");
}

#[test]
fn t32_titles_match_ground_truth() {
    let findings = try_parse_findings(T32_FIXTURE).unwrap();
    for gt in GROUND_TRUTH {
        let matched = findings
            .iter()
            .any(|f| f.title.contains(gt.title) || gt.title.contains(&f.title));
        assert!(
            matched,
            "ground truth '{}' should match a parsed finding",
            gt.title
        );
    }
}

#[test]
fn t32_severity_distribution() {
    let findings = try_parse_findings(T32_FIXTURE).unwrap();
    let critical = findings.iter().filter(|f| f.severity == "Critical").count();
    let high = findings.iter().filter(|f| f.severity == "High").count();
    let medium = findings.iter().filter(|f| f.severity == "Medium").count();

    assert_eq!(critical, 3, "T32 should have 3 Critical");
    assert_eq!(high, 2, "T32 should have 2 High");
    assert_eq!(medium, 2, "T32 should have 2 Medium");
}

#[test]
fn t32_findings_have_required_fields() {
    let findings = try_parse_findings(T32_FIXTURE).unwrap();
    for (i, f) in findings.iter().enumerate() {
        assert!(!f.title.is_empty(), "finding {i} has empty title");
        assert!(
            !f.description.is_empty(),
            "finding {i} has empty description"
        );
        assert!(
            !f.evidence.is_empty(),
            "finding {i} '{}' has no evidence",
            f.title
        );
        assert!(
            !f.remediation.is_empty(),
            "finding {i} '{}' has no remediation",
            f.title
        );
        assert!(
            f.confidence >= 0.5,
            "finding {i} '{}' confidence {:.2} < 0.5",
            f.title,
            f.confidence
        );
    }
}

#[test]
fn t32_affected_files_are_valid() {
    let findings = try_parse_findings(T32_FIXTURE).unwrap();
    for f in &findings {
        assert!(
            !f.affected_files.is_empty(),
            "'{}' has no affected files",
            f.title
        );
        for af in &f.affected_files {
            assert!(
                af.ends_with(".rs") || af.ends_with(".nr"),
                "'{}' has invalid affected file: {}",
                f.title,
                af
            );
            assert!(
                af.contains("shielded_pool_program") || af.contains("noir_circuit"),
                "'{}' affected file not in expected crate: {}",
                f.title,
                af
            );
        }
    }
}
