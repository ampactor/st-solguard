use serde_json::json;
use st_solguard::security::agent_tools;
use std::path::Path;

#[test]
fn list_files_root() {
    let repo = Path::new("tests/fixtures/vulnerable_repo");
    let (result, is_error) = agent_tools::dispatch(repo, "list_files", &json!({"path": "."}));
    assert!(!is_error, "list_files root failed: {result}");
    assert!(result.contains("src/"), "should list src/ directory");
}

#[test]
fn list_files_src() {
    let repo = Path::new("tests/fixtures/vulnerable_repo");
    let (result, is_error) = agent_tools::dispatch(repo, "list_files", &json!({"path": "src"}));
    assert!(!is_error, "list_files src failed: {result}");
    assert!(result.contains("lib.rs"), "should list lib.rs");
}

#[test]
fn read_file_full() {
    let repo = Path::new("tests/fixtures/vulnerable_repo");
    let (result, is_error) =
        agent_tools::dispatch(repo, "read_file", &json!({"path": "src/lib.rs"}));
    assert!(!is_error, "read_file failed: {result}");
    assert!(
        result.contains("authority"),
        "should contain the vulnerable code"
    );
}

#[test]
fn read_file_line_range() {
    let repo = Path::new("tests/fixtures/vulnerable_repo");
    let (result, is_error) = agent_tools::dispatch(
        repo,
        "read_file",
        &json!({"path": "src/lib.rs", "start_line": 1, "end_line": 5}),
    );
    assert!(!is_error, "read_file line range failed: {result}");
    let lines: Vec<&str> = result.lines().collect();
    assert!(lines.len() <= 5, "should return at most 5 lines");
}

#[test]
fn search_code_finds_matches() {
    let repo = Path::new("tests/fixtures/vulnerable_repo");
    let (result, is_error) =
        agent_tools::dispatch(repo, "search_code", &json!({"pattern": "unsafe"}));
    assert!(!is_error, "search_code failed: {result}");
    assert!(result.contains("unsafe"), "should find 'unsafe' in code");
}

#[test]
fn get_file_structure() {
    let repo = Path::new("tests/fixtures/vulnerable_repo");
    let (result, is_error) =
        agent_tools::dispatch(repo, "get_file_structure", &json!({"path": "src/lib.rs"}));
    assert!(!is_error, "get_file_structure failed: {result}");
    assert!(
        result.contains("fn") || result.contains("struct"),
        "should contain fn or struct definitions"
    );
}

#[test]
fn safe_resolve_blocks_traversal() {
    let repo = Path::new("tests/fixtures/vulnerable_repo");
    let (result, is_error) =
        agent_tools::dispatch(repo, "read_file", &json!({"path": "../../etc/passwd"}));
    assert!(is_error, "traversal should be blocked");
    assert!(
        result.contains("traversal")
            || result.contains("not allowed")
            || result.contains("outside"),
        "error should mention traversal: {result}"
    );
}

#[test]
fn unknown_tool_returns_error() {
    let repo = Path::new("tests/fixtures/vulnerable_repo");
    let (result, is_error) = agent_tools::dispatch(repo, "nonexistent_tool", &json!({}));
    assert!(is_error, "unknown tool should return error");
    assert!(
        result.contains("Unknown tool"),
        "error should mention unknown tool: {result}"
    );
}
