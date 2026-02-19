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
    /// Lines to include in the forward match window. Extend for patterns where
    /// the dangerous construct and its remediation span multiple lines.
    line_span: usize,
    /// Per-pattern confidence score. Reflects historical false-positive rate.
    confidence: f64,
    /// If this regex matches in the ±3-line context window, suppress the finding.
    /// Used to eliminate known false-positive cases without breaking the base pattern.
    suppress_if: Option<&'static str>,
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
        confidence: 0.65,
        // Suppress when Anchor account attributes or CHECK doc comments appear nearby.
        suppress_if: Some(r"#\[account|has_one\s*=|///\s*CHECK:|Signer\s*<"),
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
        // Low confidence — pattern is too broad (any `amount + x`) to be actionable via static scan.
        // Filtered by MIN_CONFIDENCE in the pipeline; agent catches real cases in context.
        confidence: 0.45,
        suppress_if: None,
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
        confidence: 0.75,
        suppress_if: None,
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
        // Low confidence — find_program_address is ubiquitous; whether bump is stored
        // requires dataflow analysis. Filtered by MIN_CONFIDENCE; agent investigates.
        confidence: 0.45,
        suppress_if: None,
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
        confidence: 0.72,
        // Suppress when zeroing appears on a nearby line (the regex only catches same-line).
        suppress_if: Some(
            r"fill\s*\(\s*0\s*\)|borrow_mut\s*\(\s*\)\s*\.\s*fill|assign\s*\(|realloc\s*\(|#\[account[^\]]*close",
        ),
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
        confidence: 0.65,
        // Suppress when target resolves to a well-known program constant.
        suppress_if: Some(
            r"TOKEN_PROGRAM_ID|spl_token::id\(\)|spl_associated_token_account::id\(\)|system_program::id\(\)|System(?:Program)?::id\(\)|::ID\b",
        ),
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
        confidence: 0.62,
        // Suppress when Anchor's Account<> wrapper is used nearby — it handles discriminators automatically.
        suppress_if: Some(r"Account\s*<'info\s*,|AccountLoader\s*<'info"),
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
        confidence: 0.68,
        suppress_if: None,
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
        confidence: 0.78,
        suppress_if: None,
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

    static SUPPRESS_RE: LazyLock<Vec<Option<fancy_regex::Regex>>> = LazyLock::new(|| {
        PATTERNS
            .iter()
            .map(|p| {
                p.suppress_if
                    .and_then(|s| RegexBuilder::new(s).backtrack_limit(10_000).build().ok())
            })
            .collect()
    });

    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();

    for (regex, pattern_idx) in COMPILED.iter() {
        let pattern = &PATTERNS[*pattern_idx];
        let span = pattern.line_span;

        for line_idx in 0..lines.len() {
            let line_number = line_idx + 1;

            // Skip comment lines
            let trimmed = lines[line_idx].trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("*") {
                continue;
            }

            let window_end = (line_idx + span).min(lines.len());
            let window: String = lines[line_idx..window_end].join("\n");

            if !regex.is_match(&window).unwrap_or(false) {
                continue;
            }

            // Check suppress context in a ±3-line window around the match
            if let Some(Some(suppress_re)) = SUPPRESS_RE.get(*pattern_idx) {
                let ctx_start = line_idx.saturating_sub(3);
                let ctx_end = (line_idx + 4).min(lines.len());
                let ctx_window = lines[ctx_start..ctx_end].join("\n");
                if suppress_re.is_match(&ctx_window).unwrap_or(false) {
                    continue;
                }
            }

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
                confidence: pattern.confidence,
                references: pattern.references.iter().map(|s| s.to_string()).collect(),
            });
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

    #[test]
    fn sol_001_suppressed_by_anchor_attribute_above() {
        let code = "#[account(signer)]\npub authority: AccountInfo<'info>";
        let findings = scan_one(code);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "SOL-001"),
            "SOL-001 should be suppressed when #[account] is nearby: {findings:?}"
        );
    }

    #[test]
    fn sol_001_suppressed_by_check_doc_comment() {
        let code =
            "/// CHECK: validated by the instruction handler\npub authority: AccountInfo<'info>";
        let findings = scan_one(code);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "SOL-001"),
            "SOL-001 should be suppressed when CHECK doc comment is present: {findings:?}"
        );
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

    #[test]
    fn sol_003_has_low_confidence() {
        let findings = scan_one("amount + balance");
        let f = findings
            .iter()
            .find(|f| f.pattern_id == "SOL-003")
            .expect("SOL-003 should be present in scan output");
        assert!(
            (f.confidence - 0.45).abs() < f64::EPSILON,
            "expected confidence 0.45, got {}",
            f.confidence
        );
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

    #[test]
    fn sol_005_has_low_confidence() {
        let findings = scan_one("Pubkey::find_program_address(&seeds, program_id)");
        let f = findings
            .iter()
            .find(|f| f.pattern_id == "SOL-005")
            .expect("SOL-005 should be present in scan output");
        assert!(
            (f.confidence - 0.45).abs() < f64::EPSILON,
            "expected confidence 0.45, got {}",
            f.confidence
        );
    }

    // -- SOL-006: Account Closed Without Zeroing Data --

    #[test]
    fn sol_006_positive() {
        let findings = scan_one("account.sub_lamports(amount)?;");
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "SOL-006" && f.severity == Severity::Critical),
            "expected SOL-006 Critical finding, got: {findings:?}"
        );
    }

    #[test]
    fn sol_006_negative_same_line() {
        // Zeroing IS present on the same line — regex's own negative lookahead handles this.
        let findings =
            scan_one("account.sub_lamports(amount)?; account.data.borrow_mut().fill(0);");
        assert!(
            !findings.iter().any(|f| f.pattern_id == "SOL-006"),
            "SOL-006 matched despite data zeroing on same line: {findings:?}"
        );
    }

    #[test]
    fn sol_006_suppressed_by_zeroing_next_line() {
        // Zeroing on the NEXT line — suppress_if catches what the inline regex cannot.
        let code = "account.sub_lamports(amount)?;\naccount.data.borrow_mut().fill(0);";
        let findings = scan_one(code);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "SOL-006"),
            "SOL-006 should be suppressed when zeroing is on next line: {findings:?}"
        );
    }

    #[test]
    fn sol_006_suppressed_by_anchor_close() {
        let code = "account.sub_lamports(amount)?;\n#[account(close = recipient)]";
        let findings = scan_one(code);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "SOL-006"),
            "SOL-006 should be suppressed when Anchor close attribute is nearby: {findings:?}"
        );
    }

    // -- SOL-007: Arbitrary CPI Target --

    #[test]
    fn sol_007_positive() {
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

    #[test]
    fn sol_007_suppressed_by_known_program_id() {
        let code = "let program_id = TOKEN_PROGRAM_ID;\ninvoke(&program_id, &accounts)";
        let findings = scan_one(code);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "SOL-007"),
            "SOL-007 should be suppressed when TOKEN_PROGRAM_ID is in context: {findings:?}"
        );
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
