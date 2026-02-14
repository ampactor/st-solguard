# st-solguard

Autonomous Solana ecosystem intelligence agent — combines narrative detection + security scanning.

## IMPORTANT: Build/Test/Release Ownership

**Morgan manually runs all builds, tests, and releases.** Claude writes code and stages changes only. Never run `cargo build`, `cargo test`, `cargo run`, `cargo clippy`, or any release command unless Morgan explicitly asks.

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

# Test pipeline: investigate → validate → summary (development/calibration)
cargo run -- test path/to/repo --provider openrouter --model <model> --max-turns 10 --output results.json
```

## Environment Variables

```bash
GITHUB_TOKEN=          # GitHub API (required for narrative detection)
OPENROUTER_API_KEY=    # Default LLM provider for narrative synthesis
GROQ_API_KEY=          # Groq provider (fast structured tasks via [models] routing)
ANTHROPIC_API_KEY=     # When using provider = "anthropic" in config.toml
SOLANA_RPC_URL=        # Solana RPC endpoint (default: public mainnet)
```

Shared .env at `~/Documents/superteam/.env` — loaded automatically.

## Architecture

```
CLI → ModelRouter → Agent Orchestrator
  Phase 1: Narrative Detection (GitHub + Solana RPC + Social + DeFiLlama → LLM synthesis)
  Phase 2: Target Selection (repos from narratives)
  Phase 3: Clone + Security Scanning (per repo)
           - Build ScanContext from narrative (protocol category, sibling findings)
           - compute_budget() → dynamic max_turns/cost_limit from confidence
           Static: regex (SOL-001..010) + AST (AST-001..003) patterns
           Deep (--deep): multi-turn LLM agent with protocol-specific focus areas
           → validate_findings() in-place: remove Dismissed, downgrade Disputed
  Phase 4: Cross-Reference (deterministic risk scoring + optional LLM relevance)
  Phase 5: Narrative-centric HTML Report (sorted by risk_score desc)
```

**Model routing:** `ModelRouter` maps `TaskKind` → `LlmClient`. Four task kinds: `NarrativeSynthesis`, `DeepInvestigation`, `Validation`, `CrossReference`. Config `[models]` section overrides per-task; falls back to `[llm]`. CLI `--model` overrides all uniformly.

### The Triple-Dip Value

This isn't "two tools side by side." The cross-functional insight is:
- **"what's growing" + "what's risky" = "where are the ecosystem landmines"**
- Narrative-informed targeting: scan repos in EMERGING sectors, not random repos
- Combined report tells a STORY: growth vectors + risk hotspots

### Narrative Pipeline

Signal collection from 4 sources (parallel):
- `narrative/github.rs` — GitHub Search API: new Solana repos, star velocity, trending
- `narrative/solana_rpc.rs` — Solana RPC: TPS, epoch info, program activity (paginated)
- `narrative/defi_llama.rs` — DeFiLlama API: TVL, protocol metrics, chain activity
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
- Hardening: progress logging (info-level), stuck-loop detection (3x same call → nudge), malformed input guard, forced summary turn (converse with empty tools when max_turns hit with no findings)
- **Narrative-informed scanning:** `ScanContext` carries protocol category, narrative summary, and sibling findings into the agent prompt. Protocol-specific focus areas: DEX (sandwich/LP/oracles), Lending (liquidation/interest/collateral), Privacy (Merkle proofs/nullifiers), Staking (reward distribution/slashing), NFT (royalty bypass/listing races).
- **Dynamic budget:** `compute_budget(confidence, repo_count)` → depth = confidence / sqrt(repo_count), clamped to turns [5,40] and cost [$2,$30].

**Adversarial validator:** Two modes:
1. `test` subcommand: standalone investigate → validate pipeline (development/calibration)
2. `validate_findings()`: in-place adapter for the full pipeline — annotates `SecurityFinding` vec with `ValidationStatus` + reasoning, removes Dismissed, downgrades Disputed severity by one level
- Uses `ModelRouter::client_for(TaskKind::Validation)` for model selection
- Same tool access as investigator, adversarial system prompt
- Forced summary fallback for verdict extraction

**Cross-reference engine** (`src/agent/cross_ref.rs`):
- Links findings to narratives by matching repo names from file paths to narrative `active_repos`
- Deterministic risk scoring: `sum(severity_weight * validation_multiplier * narrative_confidence)` per narrative. Severity weights: Critical=10, High=5, Medium=2, Low=0.5. Validation multipliers: Confirmed=1.0, Disputed=0.5, Unvalidated=0.7.
- Optional LLM relevance pass (one fast call per narrative via `TaskKind::CrossReference`)
- Populates `Narrative.{risk_score, risk_level, repo_findings}` for the report

## Key Files

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry (6 subcommands: run, narratives, scan, investigate, test, render) |
| `src/config.rs` | TOML + env var config loading, `AgentReviewConfig`, `ModelsConfig` |
| `src/error.rs` | Error types |
| `src/http.rs` | HTTP client with retry/backoff |
| `src/llm.rs` | LLM client (`complete`/`converse`), `ModelRouter`, `TaskKind` routing |
| `src/agent/mod.rs` | Autonomous orchestration (5 phases, narrative-informed scanning, per-repo validation) |
| `src/agent/cross_ref.rs` | Cross-reference engine: risk scoring, narrative↔finding linking |
| `src/narrative/mod.rs` | Narrative pipeline orchestrator |
| `src/narrative/github.rs` | GitHub signal collection |
| `src/narrative/solana_rpc.rs` | Solana RPC signal collection |
| `src/narrative/social.rs` | Blog scraping |
| `src/narrative/synthesizer.rs` | LLM narrative synthesis |
| `src/security/mod.rs` | Security scanner orchestrator + `scan_repo_deep()` |
| `src/security/regex_scan.rs` | 10 vulnerability regex patterns |
| `src/security/ast_scan.rs` | 3 syn-based AST patterns |
| `src/security/agent_tools.rs` | 4 repo investigation tools for deep agent review |
| `src/security/agent_review.rs` | Multi-turn agent loop, `ScanContext`, `compute_budget()`, protocol focus areas |
| `src/security/validator.rs` | Adversarial validation: `validate()` (standalone) + `validate_findings()` (pipeline) |
| `src/output/mod.rs` | Narrative-centric report: risk badges, linked findings, orphans, methodology |
| `config.toml` | Default configuration (`[agent_review]`, optional `[models]` for per-task routing) |
| `templates/solguard_report.html` | HTML report template |

## Sprint Context

Part of SuperTeam bounty sprint (Feb 11-15, 2026).
Open Innovation track — judged on autonomy, originality, Solana usage, reproducibility.
Durable state: `~/.claude/projects/-home-suds-Documents-superteam/memory/superteam-sprint.md`

## Doc-to-Code Mapping

| Source File(s) | Documentation Target(s) | What to Update |
|---|---|---|
| `src/agent/mod.rs` | CLAUDE.md (Architecture), README.md | Pipeline phases, deep flag, per-repo validation |
| `src/agent/cross_ref.rs` | CLAUDE.md (Security Pipeline) | Risk scoring formula, linking logic |
| `src/narrative/*.rs` | CLAUDE.md (Narrative Pipeline) | Signal sources, synthesis |
| `src/security/mod.rs` | CLAUDE.md (Security Pipeline) | Scanner orchestration, scan_repo_deep |
| `src/security/regex_scan.rs`, `ast_scan.rs` | CLAUDE.md (Security Pipeline) | Pattern IDs, scan logic |
| `src/security/agent_review.rs` | CLAUDE.md (Security Pipeline) | Agent loop, system prompt, finding extraction, hardening |
| `src/security/validator.rs` | CLAUDE.md (Security Pipeline) | Validator module, verdicts, test subcommand |
| `src/security/agent_tools.rs` | CLAUDE.md (Security Pipeline) | Tool definitions, dispatch, path canonicalization |
| `src/config.rs`, `config.toml` | CLAUDE.md (Environment Variables) | Config options, agent_review section, [models] routing |
| `src/llm.rs` | CLAUDE.md (Key Files, Architecture) | Provider support, ModelRouter, TaskKind routing |
| `src/main.rs` | CLAUDE.md (Run) | CLI subcommands, flags |
| `src/output/mod.rs`, templates | CLAUDE.md (Key Files) | Report structure |
