/// A manually-verified vulnerability from the T32-opus-clean-room analysis.
#[allow(dead_code)]
pub struct GroundTruthVuln {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: &'static str,
    pub confidence: f64,
    pub primary_file: &'static str,
    pub affected_files: &'static [&'static str],
    pub key_evidence: &'static str,
}

/// All 7 ground truth findings from T32-opus-clean-room.json.
pub const GROUND_TRUTH: &[GroundTruthVuln] = &[
    GroundTruthVuln {
        id: "GT-01",
        title: "Depositor can supply arbitrary Merkle root — no on-chain tree verification",
        severity: "Critical",
        confidence: 0.97,
        primary_file: "deposit.rs",
        affected_files: &[
            "shielded_pool_program/src/instructions/deposit.rs",
            "shielded_pool_program/src/state.rs",
            "shielded_pool_program/src/instructions/withdraw.rs",
        ],
        key_evidence: "new_root parsed directly from user data, stored without validation",
    },
    GroundTruthVuln {
        id: "GT-02",
        title: "ZK circuit does not bind recipient to the commitment — recipient is unconstrained",
        severity: "Critical",
        confidence: 0.85,
        primary_file: "main.nr",
        affected_files: &[
            "noir_circuit/src/main.nr",
            "shielded_pool_program/src/instructions/withdraw.rs",
        ],
        key_evidence: "assert(recipient != 0) is the ONLY constraint on recipient",
    },
    GroundTruthVuln {
        id: "GT-03",
        title: "Deposit commitment is never verified or stored — no on-chain commitment tracking",
        severity: "Critical",
        confidence: 0.97,
        primary_file: "deposit.rs",
        affected_files: &["shielded_pool_program/src/instructions/deposit.rs"],
        key_evidence: "_commitment: intentionally unused variable",
    },
    GroundTruthVuln {
        id: "GT-04",
        title: "Zero-amount deposits allow free Merkle root manipulation",
        severity: "High",
        confidence: 0.92,
        primary_file: "deposit.rs",
        affected_files: &[
            "shielded_pool_program/src/instructions/deposit.rs",
            "shielded_pool_program/src/state.rs",
        ],
        key_evidence: "amount parsed but never checked for > 0",
    },
    GroundTruthVuln {
        id: "GT-05",
        title: "Nullifier double-spend check relies on lamports instead of account existence flag",
        severity: "High",
        confidence: 0.75,
        primary_file: "withdraw.rs",
        affected_files: &["shielded_pool_program/src/instructions/withdraw.rs"],
        key_evidence: "nullifier_account.lamports() > 0 as double-spend guard",
    },
    GroundTruthVuln {
        id: "GT-06",
        title: "Vault SOL withdrawal uses direct lamport manipulation instead of system program CPI",
        severity: "Medium",
        confidence: 0.6,
        primary_file: "withdraw.rs",
        affected_files: &["shielded_pool_program/src/instructions/withdraw.rs"],
        key_evidence: "vault lamports decremented directly via set_lamports()",
    },
    GroundTruthVuln {
        id: "GT-07",
        title: "State PDA not validated in withdraw instruction",
        severity: "Medium",
        confidence: 0.7,
        primary_file: "withdraw.rs",
        affected_files: &["shielded_pool_program/src/instructions/withdraw.rs"],
        key_evidence: "only checks owned_by, not PDA derivation",
    },
];

/// Static scanner patterns expected to fire on shielded-pool (Pinocchio, not Anchor).
pub struct ExpectedStaticHit {
    pub pattern_id: &'static str,
    /// Substring of the SecurityFinding title (pattern_id is not preserved in SecurityFinding).
    pub title_match: &'static str,
    pub should_fire: bool,
    pub reason: &'static str,
}

pub const EXPECTED_STATIC_HITS: &[ExpectedStaticHit] = &[
    ExpectedStaticHit {
        pattern_id: "SOL-001",
        title_match: "Missing Signer",
        should_fire: false,
        reason: "Anchor-specific: #[account] signer check — Pinocchio doesn't use Anchor",
    },
    ExpectedStaticHit {
        pattern_id: "SOL-002",
        title_match: "Missing Owner",
        should_fire: false,
        reason: "Anchor-specific: owner validation — Pinocchio doesn't use Account<>",
    },
    ExpectedStaticHit {
        pattern_id: "SOL-003",
        title_match: "Unchecked Arithmetic",
        should_fire: false,
        reason: "Anchor-specific: unchecked arithmetic pattern not in Pinocchio",
    },
    ExpectedStaticHit {
        pattern_id: "SOL-004",
        title_match: "remaining_accounts",
        should_fire: false,
        reason: "Anchor-specific: remaining_accounts — not used in Pinocchio",
    },
    ExpectedStaticHit {
        pattern_id: "SOL-005",
        title_match: "PDA Bump Seed",
        should_fire: true,
        reason: "find_program_address used in initialize, deposit, withdraw",
    },
    ExpectedStaticHit {
        pattern_id: "SOL-006",
        title_match: "Account Closed",
        should_fire: false,
        reason: "Anchor-specific: close account — not used in Pinocchio",
    },
    ExpectedStaticHit {
        pattern_id: "SOL-007",
        title_match: "Arbitrary CPI",
        should_fire: false,
        reason: "Anchor-specific: CPI authority — different pattern in Pinocchio",
    },
    ExpectedStaticHit {
        pattern_id: "SOL-008",
        title_match: "Type Cosplay",
        should_fire: false,
        reason: "from_bytes_mut used (not from_bytes) — regex gap: SOL-008 pattern misses _mut variant",
    },
    ExpectedStaticHit {
        pattern_id: "SOL-009",
        title_match: "Division Before",
        should_fire: false,
        reason: "Division before multiplication — not present in shielded-pool",
    },
    ExpectedStaticHit {
        pattern_id: "SOL-010",
        title_match: "Token-2022",
        should_fire: false,
        reason: "Token-2022 — not used in shielded-pool",
    },
];
