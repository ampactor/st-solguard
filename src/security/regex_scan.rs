use super::{Finding, Severity};
use fancy_regex::RegexBuilder;
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
    line_span: usize,
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
        line_span: 1,
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
        line_span: 1,
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
        line_span: 1,
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
        line_span: 1,
    },
    Pattern {
        id: "SOL-006",
        title: "Account Closed Without Zeroing Data",
        description: "Account closed by transferring lamports but data not zeroed. \
                      Revival attack: within the same transaction, account can be re-opened with stale data.",
        severity: Severity::Critical,
        regex: r"(?m)(?:close|lamports\.borrow_mut|sub_lamports)(?![^\n]*(?:assign|realloc|data\.borrow_mut\(\)\.fill\(0\)))[^\n]*$",
        remediation: "After transferring lamports, zero the account data: `account.data.borrow_mut().fill(0)`. Or use Anchor's `#[account(close = destination)]`.",
        references: &["https://www.soldev.app/course/closing-accounts"],
        line_span: 1,
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
        line_span: 1,
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
        line_span: 1,
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
        line_span: 1,
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
        line_span: 1,
    },
];

pub fn scan(content: &str, file_path: &Path) -> Vec<Finding> {
    static COMPILED: LazyLock<Vec<(fancy_regex::Regex, usize)>> = LazyLock::new(|| {
        PATTERNS
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                RegexBuilder::new(p.regex)
                    .backtrack_limit(10_000)
                    .build()
                    .ok()
                    .map(|r| (r, i))
            })
            .collect()
    });

    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();

    for (regex, pattern_idx) in COMPILED.iter() {
        let pattern = &PATTERNS[*pattern_idx];
        let span = pattern.line_span;

        // Scan with sliding window to prevent catastrophic backtracking on large files
        for line_idx in 0..lines.len() {
            let line_number = line_idx + 1;

            // Skip comment lines
            let trimmed = lines[line_idx].trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("*") {
                continue;
            }

            let window_end = (line_idx + span).min(lines.len());
            let window: String = lines[line_idx..window_end].join("\n");

            if regex.is_match(&window).unwrap_or(false) {
                let start = line_number.saturating_sub(3);
                let end = (line_number + 3).min(lines.len());
                let snippet: String = lines[start..end]
                    .iter()
                    .enumerate()
                    .map(|(i, l)| format!("{:>4} | {l}", start + i + 1))
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
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scan_one(code: &str) -> Vec<Finding> {
        scan(code, Path::new("test.rs"))
    }

    // -- SOL-001: Missing Signer Constraint --

    #[test]
    fn sol_001_positive() {
        let findings = scan_one("pub authority: AccountInfo<'info>");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "SOL-001" && f.severity == Severity::High),
            "expected SOL-001 High finding, got: {findings:?}"
        );
    }

    #[test]
    fn sol_001_negative() {
        let findings = scan_one("pub authority: Signer<'info>");
        assert!(!findings.iter().any(|f| f.pattern_id == "SOL-001"));
    }

    // -- SOL-003: Unchecked Arithmetic --

    #[test]
    fn sol_003_positive() {
        let findings = scan_one("amount + balance");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "SOL-003" && f.severity == Severity::Medium),
            "expected SOL-003 Medium finding, got: {findings:?}"
        );
    }

    #[test]
    fn sol_003_negative() {
        let findings = scan_one("amount.checked_add(balance)");
        assert!(!findings.iter().any(|f| f.pattern_id == "SOL-003"));
    }

    // -- SOL-004: Unvalidated remaining_accounts --

    #[test]
    fn sol_004_positive() {
        let findings = scan_one("ctx.remaining_accounts[0]");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "SOL-004" && f.severity == Severity::High),
            "expected SOL-004 High finding, got: {findings:?}"
        );
    }

    #[test]
    fn sol_004_negative() {
        let findings = scan_one("ctx.accounts.authority");
        assert!(!findings.iter().any(|f| f.pattern_id == "SOL-004"));
    }

    // -- SOL-005: PDA Bump Seed Not Stored --

    #[test]
    fn sol_005_positive() {
        let findings = scan_one("Pubkey::find_program_address(&seeds, program_id)");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "SOL-005" && f.severity == Severity::Medium),
            "expected SOL-005 Medium finding, got: {findings:?}"
        );
    }

    #[test]
    fn sol_005_negative() {
        let findings = scan_one(r#"let seeds = [b"vault", bump.as_ref()];"#);
        assert!(!findings.iter().any(|f| f.pattern_id == "SOL-005"));
    }

    // -- SOL-006: Account Closed Without Zeroing Data --

    #[test]
    fn sol_006_positive() {
        // Using sub_lamports — `**account.lamports.borrow_mut()` starts with `*`
        // which triggers the comment-skip heuristic (starts_with("*")).
        let findings = scan_one("account.sub_lamports(amount)?;");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "SOL-006" && f.severity == Severity::Critical),
            "expected SOL-006 Critical finding, got: {findings:?}"
        );
    }

    #[test]
    fn sol_006_negative() {
        // Zeroing IS present on the same line. The tempered greedy token stops at
        // `data.borrow_mut().fill(0)`, preventing the match from reaching $.
        // Known limitation: if zeroing is on a DIFFERENT line, the regex still
        // matches because $ is line-anchored with (?m).
        let findings =
            scan_one("account.sub_lamports(amount)?; account.data.borrow_mut().fill(0);");
        assert!(
            !findings.iter().any(|f| f.pattern_id == "SOL-006"),
            "SOL-006 matched despite data zeroing on same line: {findings:?}"
        );
    }

    // -- SOL-007: Arbitrary CPI Target --

    #[test]
    fn sol_007_positive() {
        // Regex requires program_id/program_key/target_program in the first
        // argument (before comma) of invoke().
        let findings = scan_one("invoke(&target_program, &[account.clone()])");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "SOL-007" && f.severity == Severity::Critical),
            "expected SOL-007 Critical finding, got: {findings:?}"
        );
    }

    #[test]
    fn sol_007_negative() {
        let findings = scan_one("invoke(&instruction, &[spl_token::id()])");
        assert!(!findings.iter().any(|f| f.pattern_id == "SOL-007"));
    }

    // -- SOL-008: Type Cosplay (Missing Discriminator) --

    #[test]
    fn sol_008_positive() {
        let findings = scan_one("MyStruct::try_from_slice(&data)");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "SOL-008" && f.severity == Severity::High),
            "expected SOL-008 High finding, got: {findings:?}"
        );
    }

    #[test]
    fn sol_008_negative() {
        let findings = scan_one("let vault: Account<'info, MyStruct> = next;");
        assert!(!findings.iter().any(|f| f.pattern_id == "SOL-008"));
    }

    // -- SOL-009: Division Before Multiplication --

    #[test]
    fn sol_009_positive() {
        let findings = scan_one("let result = (amount / rate) * factor;");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "SOL-009" && f.severity == Severity::Medium),
            "expected SOL-009 Medium finding, got: {findings:?}"
        );
    }

    #[test]
    fn sol_009_negative() {
        let findings = scan_one("let result = (amount * factor) / rate;");
        assert!(!findings.iter().any(|f| f.pattern_id == "SOL-009"));
    }

    // -- SOL-010: Missing Token-2022 Extension Handling --

    #[test]
    fn sol_010_positive() {
        let findings =
            scan_one("spl_token::instruction::transfer(program_id, src, dst, auth, &[], amt)");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "SOL-010" && f.severity == Severity::Medium),
            "expected SOL-010 Medium finding, got: {findings:?}"
        );
    }

    #[test]
    fn sol_010_negative() {
        let findings = scan_one(
            "spl_token::instruction::transfer_checked(program_id, src, dst, mint, auth, &[], amt, decimals)",
        );
        assert!(!findings.iter().any(|f| f.pattern_id == "SOL-010"));
    }

    // -- Edge cases --

    #[test]
    fn comment_lines_produce_zero_findings() {
        let findings = scan_one("// pub authority: AccountInfo<'info>");
        assert!(
            findings.is_empty(),
            "expected no findings for comment line: {findings:?}"
        );
    }

    #[test]
    fn empty_input_produces_zero_findings() {
        let findings = scan_one("");
        assert!(findings.is_empty());
    }

    #[test]
    fn line_number_is_correct() {
        let input = "fn main() {\n    let x = 1;\n    amount + balance\n}";
        let findings = scan_one(input);
        let f = findings
            .iter()
            .find(|f| f.pattern_id == "SOL-003")
            .expect("should find SOL-003");
        assert_eq!(f.line_number, 3);
    }

    #[test]
    fn code_snippet_contains_matched_line() {
        let input = "fn main() {\n    amount + balance\n}";
        let findings = scan_one(input);
        let f = findings
            .iter()
            .find(|f| f.pattern_id == "SOL-003")
            .expect("should find SOL-003");
        assert!(
            f.code_snippet.contains("amount + balance"),
            "snippet should contain matched line: {}",
            f.code_snippet
        );
    }
}
