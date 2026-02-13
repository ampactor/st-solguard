use super::ground_truth::{EXPECTED_STATIC_HITS, GROUND_TRUTH};
use st_solguard::security;
use std::path::PathBuf;

fn shielded_pool_path() -> Option<PathBuf> {
    let from_env = std::env::var("SHIELDED_POOL_PATH").ok().map(PathBuf::from);
    let default = std::env::var("HOME").ok().map(|h| {
        PathBuf::from(h).join("Documents/superteam/st-audit/repos/shielded-pool-pinocchio-solana")
    });
    let path = from_env.or(default)?;
    if path.exists() { Some(path) } else { None }
}

#[tokio::test]
async fn static_scanner_runs_without_error() {
    let Some(repo) = shielded_pool_path() else {
        eprintln!("SKIP: shielded-pool repo not found");
        return;
    };
    let findings = security::scan_repo(&repo).await.unwrap();
    // Should produce SOME findings (at minimum SOL-005 on find_program_address)
    assert!(
        !findings.is_empty(),
        "scanner should produce findings on shielded-pool, got 0"
    );
}

#[tokio::test]
async fn expected_patterns_fire() {
    let Some(repo) = shielded_pool_path() else {
        eprintln!("SKIP: shielded-pool repo not found");
        return;
    };
    let findings = security::scan_repo(&repo).await.unwrap();

    // Check patterns that SHOULD fire (match on title substring since pattern_id
    // is not preserved in SecurityFinding)
    for expected in EXPECTED_STATIC_HITS.iter().filter(|e| e.should_fire) {
        let fired = findings
            .iter()
            .any(|f| f.title.contains(expected.title_match));
        assert!(
            fired,
            "{} ({}) should fire on shielded-pool: {}",
            expected.pattern_id, expected.title_match, expected.reason
        );
    }

    // Check patterns that should NOT fire (Anchor-specific)
    for expected in EXPECTED_STATIC_HITS.iter().filter(|e| !e.should_fire) {
        let fired = findings
            .iter()
            .any(|f| f.title.contains(expected.title_match));
        if fired {
            eprintln!(
                "INFO: {} ({}) unexpectedly fired ({}). May be a partial match.",
                expected.pattern_id, expected.title_match, expected.reason
            );
        }
    }
}

#[tokio::test]
async fn static_scanner_deterministic() {
    let Some(repo) = shielded_pool_path() else {
        eprintln!("SKIP: shielded-pool repo not found");
        return;
    };
    let run1 = security::scan_repo(&repo).await.unwrap();
    let run2 = security::scan_repo(&repo).await.unwrap();

    assert_eq!(run1.len(), run2.len(), "two runs should produce same count");
    for (a, b) in run1.iter().zip(run2.iter()) {
        assert_eq!(a.title, b.title, "titles must match between runs");
        assert_eq!(a.severity, b.severity, "severities must match");
        assert_eq!(a.file_path, b.file_path, "file paths must match");
        assert_eq!(a.line_number, b.line_number, "line numbers must match");
    }
}

#[tokio::test]
async fn static_coverage_vs_ground_truth() {
    let Some(repo) = shielded_pool_path() else {
        eprintln!("SKIP: shielded-pool repo not found");
        return;
    };
    let findings = security::scan_repo(&repo).await.unwrap();

    let mut covered = 0usize;
    for gt in GROUND_TRUTH {
        let touches = gt.affected_files.iter().any(|af| {
            findings.iter().any(|f| {
                f.file_path
                    .to_string_lossy()
                    .contains(af.rsplit('/').next().unwrap_or(af))
            })
        });
        if touches {
            eprintln!("COVERED: {} ({})", gt.id, gt.title);
            covered += 1;
        } else {
            eprintln!("GAP:     {} ({})", gt.id, gt.title);
        }
    }

    // At minimum, deposit.rs and withdraw.rs should be touched via SOL-005/SOL-008
    assert!(
        covered >= 2,
        "static scanner should cover at least 2 ground truth files, covered {covered}"
    );

    // Document the gap — this is the POINT of calibration
    let gap = GROUND_TRUTH.len() - covered;
    eprintln!(
        "\nStatic coverage: {covered}/{} ground truth vulns have file overlap",
        GROUND_TRUTH.len()
    );
    eprintln!("Gap: {gap} vulns require LLM agent to detect (logic flaws, not pattern matches)");
}
