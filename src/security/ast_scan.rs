use super::{Finding, Severity};
use quote::ToTokens;
use std::path::Path;
use syn::visit::Visit;
use syn::{Attribute, File, Item, ItemFn, ItemStruct};

pub fn scan(content: &str, file_path: &Path) -> anyhow::Result<Vec<Finding>> {
    let ast: File = syn::parse_str(content)?;
    let mut visitor = SolanaVisitor {
        findings: Vec::new(),
        file_path: file_path.to_path_buf(),
        source: content.to_string(),
    };
    visitor.visit_file(&ast);
    Ok(visitor.findings)
}

struct SolanaVisitor {
    findings: Vec<Finding>,
    file_path: std::path::PathBuf,
    source: String,
}

impl SolanaVisitor {
    fn line_of(&self, span: proc_macro2::Span) -> usize {
        span.start().line
    }

    fn snippet_at(&self, line: usize) -> String {
        let lines: Vec<&str> = self.source.lines().collect();
        let start = line.saturating_sub(3);
        let end = (line + 3).min(lines.len());
        lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, l)| format!("{:>4} | {l}", start + i + 1))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn has_anchor_attribute(attrs: &[Attribute], name: &str) -> bool {
        attrs
            .iter()
            .any(|attr| attr.path().segments.iter().any(|seg| seg.ident == name))
    }

    fn check_account_struct(&mut self, item: &ItemStruct) {
        if !Self::has_anchor_attribute(&item.attrs, "derive") {
            return;
        }

        let is_accounts_struct = item.attrs.iter().any(|attr| {
            let tokens = attr.to_token_stream().to_string();
            tokens.contains("Accounts")
        });

        if !is_accounts_struct {
            return;
        }

        if let syn::Fields::Named(fields) = &item.fields {
            for field in &fields.named {
                let field_str = quote::quote!(#field).to_string();

                if field_str.contains("AccountInfo") && !field_str.contains("CHECK") {
                    let line = self.line_of(
                        field
                            .ident
                            .as_ref()
                            .map_or(proc_macro2::Span::call_site(), |i| i.span()),
                    );
                    self.findings.push(Finding {
                        pattern_id: "AST-001".into(),
                        title: "Unchecked AccountInfo in Accounts Struct".into(),
                        description: format!(
                            "AccountInfo field '{}' lacks a CHECK doc comment.",
                            field
                                .ident
                                .as_ref()
                                .map(|i| i.to_string())
                                .unwrap_or_default()
                        ),
                        severity: Severity::Medium,
                        file_path: self.file_path.clone(),
                        line_number: line,
                        code_snippet: self.snippet_at(line),
                        remediation: "Add `/// CHECK: <reason>` or use a validated account type."
                            .into(),
                        confidence: 0.7,
                        references: vec![],
                    });
                }
            }
        }
    }

    fn check_function_body(&mut self, func: &ItemFn) {
        let body_str = quote::quote!(#func).to_string();

        if body_str.contains("msg !") && body_str.contains("key ()") {
            let line = self.line_of(func.sig.ident.span());
            self.findings.push(Finding {
                pattern_id: "AST-002".into(),
                title: "Verbose Error Logging May Leak Account Keys".into(),
                description:
                    "Function logs account keys via msg!(). This may leak sensitive information."
                        .into(),
                severity: Severity::Low,
                file_path: self.file_path.clone(),
                line_number: line,
                code_snippet: self.snippet_at(line),
                remediation: "Use error codes instead of logging raw keys.".into(),
                confidence: 0.5,
                references: vec![],
            });
        }

        if body_str.contains("unsafe") {
            let line = self.line_of(func.sig.ident.span());
            self.findings.push(Finding {
                pattern_id: "AST-003".into(),
                title: "Unsafe Block in Solana Program".into(),
                description:
                    "Function contains an unsafe block. Requires careful review for memory safety."
                        .into(),
                severity: Severity::High,
                file_path: self.file_path.clone(),
                line_number: line,
                code_snippet: self.snippet_at(line),
                remediation: "Review unsafe block for soundness. Consider safe alternatives."
                    .into(),
                confidence: 0.8,
                references: vec!["CWE-119".into()],
            });
        }
    }
}

impl<'ast> Visit<'ast> for SolanaVisitor {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        self.check_account_struct(node);
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item(&mut self, node: &'ast Item) {
        if let Item::Fn(func) = node {
            self.check_function_body(func);
        }
        syn::visit::visit_item(self, node);
    }
}
