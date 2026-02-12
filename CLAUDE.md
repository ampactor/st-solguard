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
GITHUB_TOKEN=          # GitHub API
ANTHROPIC_API_KEY=     # Claude API
HELIUS_API_KEY=        # Helius RPC (optional)
SOLANA_RPC_URL=        # Solana RPC endpoint
```

## Architecture

```
CLI → Agent Orchestrator
  Phase 1: Narrative Detection (what's growing)
  Phase 2: Target Selection (which repos to scan)
  Phase 3: Security Scanning (what's risky)
  Phase 4: Cross-Reference (where are the landmines)
  Phase 5: Combined HTML Report
```

### The Triple-Dip Value

This isn't "two tools side by side." The cross-functional insight is:
- **"what's growing" + "what's risky" = "where are the ecosystem landmines"**
- Narrative-informed targeting: scan repos in EMERGING sectors, not random repos
- Combined report tells a STORY: growth vectors + risk hotspots

## Key Files

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry |
| `src/agent/mod.rs` | Autonomous orchestration pipeline |
| `src/narrative/mod.rs` | Narrative detection (wraps st-narrative logic) |
| `src/security/mod.rs` | Security scanning (wraps st-audit logic) |
| `src/output/mod.rs` | Combined report rendering |
| `templates/solguard_report.html` | HTML report template |

## Sprint Context

Part of SuperTeam bounty sprint (Feb 11-15, 2026).
Open Innovation track — judged on autonomy, originality, Solana usage, reproducibility.
Durable state: `~/.claude/projects/-home-suds-Documents/memory/superteam-sprint.md`

## Doc-to-Code Mapping

| Source File(s) | Documentation Target(s) | What to Update |
|---|---|---|
| `src/agent/mod.rs` | CLAUDE.md (Architecture), README.md | Pipeline phases |
| `src/narrative/mod.rs` | CLAUDE.md (Architecture) | Narrative integration |
| `src/security/mod.rs` | CLAUDE.md (Architecture) | Security integration |
| `src/output/mod.rs`, templates | CLAUDE.md (Key Files) | Report structure |
