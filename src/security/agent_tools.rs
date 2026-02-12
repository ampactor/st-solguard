//! Tools for the security review agent to investigate repositories.
//!
//! Four tools operate on a cloned repo directory: `list_files`, `read_file`,
//! `search_code`, and `get_file_structure`. All paths are resolved relative
//! to the repo root with traversal protection.

use crate::llm::ToolDef;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use tracing::debug;
use walkdir::WalkDir;

/// Max chars returned from any single tool invocation.
const MAX_RESULT_CHARS: usize = 5000;

/// Build the tool definitions sent to the LLM.
pub fn tool_definitions() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "list_files".into(),
            description: "List files in a directory within the repository. Returns file paths \
                          relative to the repo root. Use to discover project structure before \
                          reading specific files."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path relative to repo root. Use '.' for root."
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Optional glob pattern to filter files (e.g. '*.rs'). Omit to list all."
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "read_file".into(),
            description: "Read the contents of a file in the repository. Returns the file text \
                          with line numbers. Use to examine specific source files, configs, or \
                          Cargo.toml. Large files are truncated."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path relative to repo root."
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Start line (1-indexed). Omit to read from beginning."
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "End line (inclusive). Omit to read to end (or truncation limit)."
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "search_code".into(),
            description: "Search for a pattern across repository files. Returns matching lines \
                          with file paths and line numbers. Use to find function definitions, \
                          cross-references, or specific patterns like 'invoke_signed' or \
                          'transfer_checked'."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Text pattern to search for (substring match, case-sensitive)."
                    },
                    "file_pattern": {
                        "type": "string",
                        "description": "Optional file extension filter (e.g. 'rs', 'toml'). Omit to search all files."
                    }
                },
                "required": ["pattern"]
            }),
        },
        ToolDef {
            name: "get_file_structure".into(),
            description: "Get the structural outline of a Rust source file: function signatures, \
                          struct definitions, impl blocks, trait definitions, and public items. \
                          Use to understand a file's API surface without reading every line."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Rust source file path relative to repo root."
                    }
                },
                "required": ["path"]
            }),
        },
    ]
}

/// Dispatch a tool call by name. Returns `(result_text, is_error)`.
pub fn dispatch(repo_root: &Path, tool_name: &str, input: &Value) -> (String, bool) {
    match tool_name {
        "list_files" => handle_list_files(repo_root, input),
        "read_file" => handle_read_file(repo_root, input),
        "search_code" => handle_search_code(repo_root, input),
        "get_file_structure" => handle_get_file_structure(repo_root, input),
        _ => (format!("Unknown tool: {tool_name}"), true),
    }
}

/// Resolve a user-provided path relative to repo root, rejecting traversal.
fn safe_resolve(repo_root: &Path, user_path: &str) -> Result<PathBuf, String> {
    let cleaned = user_path.replace('\\', "/");
    let cleaned = cleaned.trim_start_matches('/');

    // Reject explicit traversal
    if cleaned.contains("..") {
        return Err("Path traversal (..) is not allowed".into());
    }

    let resolved = repo_root.join(cleaned);
    let canonical_root = repo_root
        .canonicalize()
        .map_err(|e| format!("Cannot resolve repo root: {e}"))?;
    let canonical = resolved
        .canonicalize()
        .map_err(|e| format!("Cannot resolve path '{}': {e}", user_path))?;

    if !canonical.starts_with(&canonical_root) {
        return Err("Path resolves outside repository".into());
    }

    Ok(canonical)
}

fn truncate(s: String) -> String {
    if s.len() <= MAX_RESULT_CHARS {
        s
    } else {
        let mut out = s[..MAX_RESULT_CHARS].to_string();
        out.push_str("\n... [truncated]");
        out
    }
}

fn handle_list_files(repo_root: &Path, input: &Value) -> (String, bool) {
    let path = input["path"].as_str().unwrap_or(".");
    let pattern = input["pattern"].as_str();

    let dir = match safe_resolve(repo_root, path) {
        Ok(d) => d,
        Err(e) => return (e, true),
    };

    if !dir.is_dir() {
        return (format!("Not a directory: {path}"), true);
    }

    debug!(dir = %dir.display(), "list_files");

    let mut entries = Vec::new();
    for entry in WalkDir::new(&dir)
        .max_depth(2)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let ep = entry.path();
        // Skip hidden dirs and target/
        let name = ep.file_name().map(|n| n.to_string_lossy());
        if name
            .as_deref()
            .is_some_and(|n| n.starts_with('.') || n == "target")
            && ep != dir
        {
            continue;
        }

        if let Ok(rel) = ep.strip_prefix(repo_root) {
            let rel_str = rel.to_string_lossy();
            if let Some(pat) = pattern
                && !rel_str.ends_with(pat.trim_start_matches('*'))
            {
                continue;
            }
            let suffix = if ep.is_dir() { "/" } else { "" };
            entries.push(format!("{rel_str}{suffix}"));
        }
    }

    entries.sort();
    if entries.is_empty() {
        ("No files found".into(), false)
    } else {
        (truncate(entries.join("\n")), false)
    }
}

fn handle_read_file(repo_root: &Path, input: &Value) -> (String, bool) {
    let path = match input["path"].as_str() {
        Some(p) => p,
        None => return ("Missing 'path' parameter".into(), true),
    };
    let start = input["start_line"].as_u64().map(|n| n as usize);
    let end = input["end_line"].as_u64().map(|n| n as usize);

    let file = match safe_resolve(repo_root, path) {
        Ok(f) => f,
        Err(e) => return (e, true),
    };

    if !file.is_file() {
        return (format!("Not a file: {path}"), true);
    }

    debug!(file = %file.display(), "read_file");

    let content = match std::fs::read_to_string(&file) {
        Ok(c) => c,
        Err(e) => return (format!("Cannot read file: {e}"), true),
    };

    let lines: Vec<&str> = content.lines().collect();
    let start_idx = start.unwrap_or(1).saturating_sub(1);
    let end_idx = end.unwrap_or(lines.len()).min(lines.len());

    if start_idx >= lines.len() {
        return (
            format!("Start line {start_idx} exceeds file length {}", lines.len()),
            true,
        );
    }

    let numbered: String = lines[start_idx..end_idx]
        .iter()
        .enumerate()
        .map(|(i, line)| format!("{:>4} | {}", start_idx + i + 1, line))
        .collect::<Vec<_>>()
        .join("\n");

    (truncate(numbered), false)
}

fn handle_search_code(repo_root: &Path, input: &Value) -> (String, bool) {
    let pattern = match input["pattern"].as_str() {
        Some(p) => p,
        None => return ("Missing 'pattern' parameter".into(), true),
    };
    let file_ext = input["file_pattern"].as_str();

    debug!(pattern, "search_code");

    let mut results = Vec::new();
    let mut total_matches = 0usize;
    let max_matches = 50;

    for entry in WalkDir::new(repo_root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let ep = entry.path();
        if !ep.is_file() {
            continue;
        }

        // Skip hidden, target, test dirs
        let path_str = ep.to_string_lossy();
        if path_str.contains("/target/")
            || path_str.contains("/.git/")
            || path_str.contains("/node_modules/")
        {
            continue;
        }

        if let Some(ext) = file_ext
            && ep.extension().is_none_or(|e| e != ext)
        {
            continue;
        }

        // Only search text files
        let content = match std::fs::read_to_string(ep) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let rel = ep.strip_prefix(repo_root).unwrap_or(ep);
        for (line_num, line) in content.lines().enumerate() {
            if line.contains(pattern) {
                total_matches += 1;
                if results.len() < max_matches {
                    results.push(format!(
                        "{}:{}: {}",
                        rel.display(),
                        line_num + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    if results.is_empty() {
        (format!("No matches for '{pattern}'"), false)
    } else {
        let header = if total_matches > max_matches {
            format!("Found {total_matches} matches (showing first {max_matches}):\n")
        } else {
            format!("Found {total_matches} matches:\n")
        };
        (truncate(format!("{header}{}", results.join("\n"))), false)
    }
}

fn handle_get_file_structure(repo_root: &Path, input: &Value) -> (String, bool) {
    let path = match input["path"].as_str() {
        Some(p) => p,
        None => return ("Missing 'path' parameter".into(), true),
    };

    let file = match safe_resolve(repo_root, path) {
        Ok(f) => f,
        Err(e) => return (e, true),
    };

    if !file.is_file() {
        return (format!("Not a file: {path}"), true);
    }

    debug!(file = %file.display(), "get_file_structure");

    let content = match std::fs::read_to_string(&file) {
        Ok(c) => c,
        Err(e) => return (format!("Cannot read file: {e}"), true),
    };

    // Line-based structural extraction (no syn dependency here — fast and robust)
    let mut outline = Vec::new();
    let mut in_doc_comment = false;

    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        let line_num = i + 1;

        // Track doc comments for context
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            in_doc_comment = true;
            continue;
        }

        let is_structural = trimmed.starts_with("pub fn ")
            || trimmed.starts_with("fn ")
            || trimmed.starts_with("pub struct ")
            || trimmed.starts_with("struct ")
            || trimmed.starts_with("pub enum ")
            || trimmed.starts_with("enum ")
            || trimmed.starts_with("pub trait ")
            || trimmed.starts_with("trait ")
            || trimmed.starts_with("impl ")
            || trimmed.starts_with("pub mod ")
            || trimmed.starts_with("mod ")
            || trimmed.starts_with("pub type ")
            || trimmed.starts_with("type ")
            || trimmed.starts_with("pub const ")
            || trimmed.starts_with("const ")
            || trimmed.starts_with("pub static ")
            || trimmed.starts_with("static ")
            || trimmed.starts_with("#[derive")
            || trimmed.starts_with("pub use ")
            || trimmed.starts_with("use ");

        if is_structural {
            // Include one-line doc summary if preceding line was a doc comment
            let doc_hint = if in_doc_comment { " [documented]" } else { "" };
            outline.push(format!("{line_num:>4} | {trimmed}{doc_hint}"));
        }

        if !trimmed.is_empty() && !trimmed.starts_with("//") {
            in_doc_comment = false;
        }
    }

    if outline.is_empty() {
        ("No structural items found".into(), false)
    } else {
        (truncate(outline.join("\n")), false)
    }
}
