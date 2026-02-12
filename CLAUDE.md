# st-solguard

Autonomous Solana ecosystem intelligence agent — combines narrative detection + security scanning.

## Build & Test

```bash
cargo build
cargo test
cargo clippy -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

## Run

```bash
# Full autonomous pipeline (static scanning)
cargo run -- run -c config.toml -o solguard-report.html

# Full pipeline with deep agent review
cargo run -- run -c config.toml -o solguard-report.html --deep --provider openrouter --model <model>

# Narrative detection only
cargo run -- narratives -c config.toml

# Static scan a specific repo (stdout)
cargo run -- scan path/to/repo

# Static scan with output to file
cargo run -- scan path/to/repo --output findings.json

# Deep agent scan (static + multi-turn LLM investigation)
cargo run -- scan path/to/repo --deep --provider openrouter --model <model> --output findings.json

# Investigate a repo (agent-only, with CLI overrides)
cargo run -- investigate path/to/repo --provider anthropic --model claude-sonnet-4-5-20250929 --max-turns 10 --cost-limit 5.0 --output findings.json
```

## Environment Variables

```bash
GITHUB_TOKEN=          # GitHub API (required for narrative detection)
OPENROUTER_API_KEY=    # Default LLM provider for narrative synthesis
ANTHROPIC_API_KEY=     # When using provider = "anthropic" in config.toml
SOLANA_RPC_URL=        # Solana RPC endpoint (default: public mainnet)
```

Shared .env at `~/Documents/.env` — loaded automatically.

## Architecture

```
CLI → Agent Orchestrator
  Phase 1: Narrative Detection (GitHub + Solana RPC + Social signals → LLM synthesis)
  Phase 2: Target Selection (repos from narratives)
  Phase 3: Clone + Security Scanning
           Static: regex (SOL-001..010) + AST (AST-001..003) patterns
           Deep (--deep): multi-turn LLM agent investigates repo with tools
  Phase 4: Cross-Reference (findings ↔ narratives)
  Phase 5: Combined HTML Report (Askama template)
```

### The Triple-Dip Value

This isn't "two tools side by side." The cross-functional insight is:
- **"what's growing" + "what's risky" = "where are the ecosystem landmines"**
- Narrative-informed targeting: scan repos in EMERGING sectors, not random repos
- Combined report tells a STORY: growth vectors + risk hotspots

### Narrative Pipeline

Signal collection from 3 sources (parallel):
- `narrative/github.rs` — GitHub Search API: new Solana repos, star velocity, trending
- `narrative/solana_rpc.rs` — Solana RPC: TPS, epoch info, program activity (paginated)
- `narrative/social.rs` — Blog scraping: article extraction, Solana relevance filtering

Analysis:
- `narrative/aggregator.rs` — Group by category, compute cross-source validation
- `narrative/synthesizer.rs` — LLM narrative identification from aggregated signals

### Security Pipeline

**Static scanner:** 10 regex patterns (SOL-001..010) + 3 AST patterns (AST-001..003):
- Missing signer/owner checks, unchecked arithmetic, remaining_accounts
- PDA bump issues, account revival, arbitrary CPI, type cosplay
- Division before multiplication, Token-2022 handling
- Unchecked AccountInfo, key logging, unsafe blocks

**Deep agent review (`--deep`):** Multi-turn LLM investigation using 4 tools:
- `list_files`, `read_file`, `search_code`, `get_file_structure`
- Agent follows trust models, call chains, fund flows — investigates like a human auditor
- Static scanner runs first for triage context, then agent verifies/discovers
- Hard stops: max_turns (30), cost_limit_usd ($20) — configurable via `[agent_review]` in config.toml
- Supports Anthropic, OpenRouter, OpenAI wire formats for tool_use

## Key Files

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry (5 subcommands: run, narratives, scan, investigate, render) |
| `src/config.rs` | TOML + env var config loading, `AgentReviewConfig` |
| `src/error.rs` | Error types |
| `src/http.rs` | HTTP client with retry/backoff |
| `src/llm.rs` | LLM client: single-turn `complete()` + multi-turn `converse()` with tool_use |
| `src/agent/mod.rs` | Autonomous orchestration (5 phases, optional deep scan) |
| `src/narrative/mod.rs` | Narrative pipeline orchestrator |
| `src/narrative/github.rs` | GitHub signal collection |
| `src/narrative/solana_rpc.rs` | Solana RPC signal collection |
| `src/narrative/social.rs` | Blog scraping |
| `src/narrative/synthesizer.rs` | LLM narrative synthesis |
| `src/security/mod.rs` | Security scanner orchestrator + `scan_repo_deep()` |
| `src/security/regex_scan.rs` | 10 vulnerability regex patterns |
| `src/security/ast_scan.rs` | 3 syn-based AST patterns |
| `src/security/agent_tools.rs` | 4 repo investigation tools for deep agent review |
| `src/security/agent_review.rs` | Multi-turn agent loop: conversation → tool dispatch → finding extraction |
| `src/output/mod.rs` | Combined report rendering |
| `config.toml` | Default configuration (including `[agent_review]`) |
| `templates/solguard_report.html` | HTML report template |

## Sprint Context

Part of SuperTeam bounty sprint (Feb 11-15, 2026).
Open Innovation track — judged on autonomy, originality, Solana usage, reproducibility.
Durable state: `~/.claude/projects/-home-suds-Documents/memory/superteam-sprint.md`

## Doc-to-Code Mapping

| Source File(s) | Documentation Target(s) | What to Update |
|---|---|---|
| `src/agent/mod.rs` | CLAUDE.md (Architecture), README.md | Pipeline phases, deep flag |
| `src/narrative/*.rs` | CLAUDE.md (Narrative Pipeline) | Signal sources, synthesis |
| `src/security/mod.rs` | CLAUDE.md (Security Pipeline) | Scanner orchestration, scan_repo_deep |
| `src/security/regex_scan.rs`, `ast_scan.rs` | CLAUDE.md (Security Pipeline) | Pattern IDs, scan logic |
| `src/security/agent_review.rs` | CLAUDE.md (Security Pipeline) | Agent loop, system prompt, finding extraction |
| `src/security/agent_tools.rs` | CLAUDE.md (Security Pipeline) | Tool definitions, dispatch |
| `src/config.rs`, `config.toml` | CLAUDE.md (Environment Variables) | Config options, agent_review section |
| `src/llm.rs` | CLAUDE.md (Key Files) | Provider support, converse() wire formats |
| `src/main.rs` | CLAUDE.md (Run) | CLI subcommands, flags |
| `src/output/mod.rs`, templates | CLAUDE.md (Key Files) | Report structure |
