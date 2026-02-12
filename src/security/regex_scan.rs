use super::{Finding, Severity};
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

struct Pattern {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    severity: Severity,
    regex: &'static str,
    remediation: &'static str,
    references: &'static [&'static str],
}

static PATTERNS: &[Pattern] = &[
    Pattern {
        id: "SOL-001",
        title: "Missing Signer Constraint",
        description: "Account used in privileged operation without #[account(signer)] or Signer<> type. \
                      An attacker could call this instruction with any account, bypassing authorization.",
        severity: Severity::High,
        regex: r"(?m)^[^/]*pub\s+(\w+)\s*:\s*(?:Account|AccountInfo|UncheckedAccount)(?!.*(?:has_one|constraint|signer))",
        remediation: "Add `Signer<'info>` type or `#[account(signer)]` constraint to enforce authorization.",
        references: &["https://www.soldev.app/course/signer-auth"],
    },
    Pattern {
        id: "SOL-002",
        title: "Missing Owner Validation",
        description: "Account deserialized without owner = program_id constraint. \
                      An attacker could pass an account owned by a different program with crafted data.",
        severity: Severity::High,
        regex: r"(?m)#\[account\([^)]*\)\]\s*pub\s+\w+\s*:\s*Account<[^>]+>(?!.*owner\s*=)",
        remediation: "Add `owner = crate::ID` or equivalent constraint. For Anchor, `Account<>` checks owner by default — verify the program ID matches.",
        references: &["https://www.soldev.app/course/owner-checks"],
    },
    Pattern {
        id: "SOL-003",
        title: "Unchecked Arithmetic on Token Amounts",
        description: "Arithmetic operation (+, -, *) on potential token amounts without checked_* or saturating_*. \
                      Could overflow/underflow, leading to incorrect balances.",
        severity: Severity::Medium,
        regex: r"(?m)(?:amount|balance|supply|lamports|quantity|total|reserve)\s*(?:\+|-|\*)\s*(?:amount|balance|supply|lamports|quantity|total|reserve|[0-9])",
        remediation: "Use `checked_add()`, `checked_sub()`, `checked_mul()` or `saturating_*` variants.",
        references: &["CWE-190"],
    },
    Pattern {
        id: "SOL-004",
        title: "Unvalidated remaining_accounts Usage",
        description: "Iterating over ctx.remaining_accounts without validation. \
                      Attacker can pass arbitrary accounts, potentially bypassing security checks.",
        severity: Severity::High,
        regex: r"remaining_accounts(?:\s*\.|\s*\[)",
        remediation: "Validate each account in remaining_accounts: check owner, check key against expected PDA, verify signer status.",
        references: &[],
    },
    Pattern {
        id: "SOL-005",
        title: "PDA Bump Seed Not Stored/Verified",
        description: "PDA created with find_program_address but bump not stored in account data. \
                      Without bump verification, account can be re-derived with wrong bump.",
        severity: Severity::Medium,
        regex: r"find_program_address\s*\(",
        remediation: "Store the canonical bump in account data and verify it in subsequent instructions using `seeds` + `bump = stored_bump`.",
        references: &["https://www.soldev.app/course/bump-seed-canonicalization"],
    },
    Pattern {
        id: "SOL-006",
        title: "Account Closed Without Zeroing Data",
        description: "Account closed by transferring lamports but data not zeroed. \
                      Revival attack: within the same transaction, account can be re-opened with stale data.",
        severity: Severity::Critical,
        regex: r"(?m)(?:close|lamports\.borrow_mut|sub_lamports)(?:(?!assign|realloc|data\.borrow_mut\(\)\.fill\(0\)).)*$",
        remediation: "After transferring lamports, zero the account data: `account.data.borrow_mut().fill(0)`. Or use Anchor's `#[account(close = destination)]`.",
        references: &["https://www.soldev.app/course/closing-accounts"],
    },
    Pattern {
        id: "SOL-007",
        title: "Potential Arbitrary CPI Target",
        description: "Cross-program invocation where the target program ID may come from user input. \
                      Attacker could redirect the CPI to a malicious program.",
        severity: Severity::Critical,
        regex: r"invoke(?:_signed)?\s*\(\s*&[^,]*(?:program_id|program_key|target_program)",
        remediation: "Hardcode the target program ID or validate it against a known constant.",
        references: &["https://www.soldev.app/course/arbitrary-cpi"],
    },
    Pattern {
        id: "SOL-008",
        title: "Potential Type Cosplay (Missing Discriminator)",
        description: "Account deserialized with try_from_slice or manual deserialization without discriminator check. \
                      An attacker could pass a different account type with same data layout.",
        severity: Severity::High,
        regex: r"(?:try_from_slice|deserialize|from_bytes)\s*\(",
        remediation: "Use Anchor's Account<> type (auto-checks discriminator) or manually verify the 8-byte discriminator.",
        references: &["https://www.soldev.app/course/type-cosplay"],
    },
    Pattern {
        id: "SOL-009",
        title: "Division Before Multiplication (Precision Loss)",
        description: "Division followed by multiplication on the result. In integer math, this loses precision. \
                      For financial calculations, always multiply first, then divide.",
        severity: Severity::Medium,
        regex: r"/\s*\w+\s*\)\s*(?:\.\s*)?(?:checked_mul|saturating_mul|\*)",
        remediation: "Reorder: multiply first, then divide. Or use u128 intermediate precision.",
        references: &["CWE-682"],
    },
    Pattern {
        id: "SOL-010",
        title: "Missing Token-2022 Extension Handling",
        description: "Token transfer using spl_token but not handling Token-2022 extensions \
                      (transfer fees, confidential transfers).",
        severity: Severity::Medium,
        regex: r"spl_token::instruction::transfer(?!_checked)",
        remediation: "Use `transfer_checked` instead of `transfer`. Check for Token-2022 extensions.",
        references: &["https://spl.solana.com/token-2022"],
    },
];

pub fn scan(content: &str, file_path: &Path) -> Vec<Finding> {
    static COMPILED: LazyLock<Vec<(Regex, usize)>> = LazyLock::new(|| {
        PATTERNS
            .iter()
            .enumerate()
            .filter_map(|(i, p)| Regex::new(p.regex).ok().map(|r| (r, i)))
            .collect()
    });

    let mut findings = Vec::new();

    for (regex, pattern_idx) in COMPILED.iter() {
        let pattern = &PATTERNS[*pattern_idx];

        for mat in regex.find_iter(content) {
            let line_number = content[..mat.start()].matches('\n').count() + 1;

            let lines: Vec<&str> = content.lines().collect();

            // Skip matches on comment lines
            if line_number > 0 && line_number <= lines.len() {
                let line = lines[line_number - 1].trim_start();
                if line.starts_with("//") || line.starts_with("///") || line.starts_with("*") {
                    continue;
                }
            }
            let start = line_number.saturating_sub(3);
            let end = (line_number + 3).min(lines.len());
            let snippet: String = lines[start..end]
                .iter()
                .enumerate()
                .map(|(i, line)| format!("{:>4} | {line}", start + i + 1))
                .collect::<Vec<_>>()
                .join("\n");

            findings.push(Finding {
                pattern_id: pattern.id.to_string(),
                title: pattern.title.to_string(),
                description: pattern.description.to_string(),
                severity: pattern.severity.clone(),
                file_path: file_path.to_path_buf(),
                line_number,
                code_snippet: snippet,
                remediation: pattern.remediation.to_string(),
                confidence: 0.6,
                references: pattern.references.iter().map(|s| s.to_string()).collect(),
            });
        }
    }

    findings
}
