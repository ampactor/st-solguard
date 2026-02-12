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
# Full autonomous pipeline
cargo run -- run -c config.toml -o solguard-report.html

# Narrative detection only
cargo run -- narratives -c config.toml

# Scan a specific repo
cargo run -- scan path/to/repo
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
  Phase 3: Clone + Security Scanning (regex + AST patterns)
  Phase 4: Cross-Reference (narratives × findings)
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

10 regex patterns (SOL-001 through SOL-010) + 3 AST patterns (AST-001 through AST-003):
- Missing signer/owner checks, unchecked arithmetic, remaining_accounts
- PDA bump issues, account revival, arbitrary CPI, type cosplay
- Division before multiplication, Token-2022 handling
- Unchecked AccountInfo, key logging, unsafe blocks

## Key Files

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry (3 subcommands) |
| `src/config.rs` | TOML + env var config loading |
| `src/error.rs` | Error types |
| `src/http.rs` | HTTP client with retry/backoff |
| `src/llm.rs` | Provider-swappable LLM client (Anthropic/OpenRouter/OpenAI) |
| `src/agent/mod.rs` | Autonomous orchestration (5 phases) |
| `src/narrative/mod.rs` | Narrative pipeline orchestrator |
| `src/narrative/github.rs` | GitHub signal collection |
| `src/narrative/solana_rpc.rs` | Solana RPC signal collection |
| `src/narrative/social.rs` | Blog scraping |
| `src/narrative/synthesizer.rs` | LLM narrative synthesis |
| `src/security/mod.rs` | Security scanner orchestrator |
| `src/security/regex_scan.rs` | 10 vulnerability regex patterns |
| `src/security/ast_scan.rs` | 3 syn-based AST patterns |
| `src/output/mod.rs` | Combined report rendering |
| `config.toml` | Default configuration |
| `templates/solguard_report.html` | HTML report template |

## Sprint Context

Part of SuperTeam bounty sprint (Feb 11-15, 2026).
Open Innovation track — judged on autonomy, originality, Solana usage, reproducibility.
Durable state: `~/.claude/projects/-home-suds-Documents/memory/superteam-sprint.md`

## Doc-to-Code Mapping

| Source File(s) | Documentation Target(s) | What to Update |
|---|---|---|
| `src/agent/mod.rs` | CLAUDE.md (Architecture), README.md | Pipeline phases |
| `src/narrative/*.rs` | CLAUDE.md (Narrative Pipeline) | Signal sources, synthesis |
| `src/security/*.rs` | CLAUDE.md (Security Pipeline) | Pattern IDs, scan logic |
| `src/config.rs`, `config.toml` | CLAUDE.md (Environment Variables) | Config options |
| `src/llm.rs` | CLAUDE.md (Key Files) | Provider support |
| `src/output/mod.rs`, templates | CLAUDE.md (Key Files) | Report structure |
