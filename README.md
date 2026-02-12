# SolGuard

Autonomous Solana ecosystem intelligence agent that combines narrative detection with security scanning to answer: **"where are the ecosystem landmines?"**

## The Insight

Most security tools scan code. Most analytics tools track metrics. SolGuard does both and cross-references them:

- **What's growing** (narrative detection) + **what's risky** (vulnerability scanning) = **where the landmines are**
- Narrative-informed targeting: scan repos in *emerging* sectors, not random repos
- Combined report tells a story: growth vectors alongside risk hotspots

## How It Works

```
Phase 1: Narrative Detection
  ├── GitHub API → new repos, trending, categorized by sector
  ├── Solana RPC → TPS, program activity rates (paginated)
  └── Blog scraping → Helius, Solana, Jito, Marinade
  └── LLM synthesis → 5-8 narratives with confidence scores

Phase 2: Target Selection
  └── Extract active repos from narrative signals

Phase 3: Security Scanning
  ├── Clone targets (--depth 1)
  ├── 10 regex vulnerability patterns (SOL-001 to SOL-010)
  └── 3 AST patterns via syn (AST-001 to AST-003)

Phase 4: Cross-Reference
  └── Map findings to narrative contexts

Phase 5: Combined HTML Report
  └── Askama template with narratives + findings
```

## Quick Start

```bash
# Set environment
export GITHUB_TOKEN=...
export OPENROUTER_API_KEY=...
export SOLANA_RPC_URL=...           # optional

# Full autonomous pipeline
cargo run -- run -c config.toml -o solguard-report.html

# Narrative detection only
cargo run -- narratives -c config.toml

# Security scan a specific repo
cargo run -- scan path/to/repo
```

## Architecture

Three CLI subcommands that can run independently or together:

| Module | Source | Capability |
|--------|--------|------------|
| `narrative/` | GitHub + Solana RPC + Social | Signal collection, aggregation, LLM synthesis |
| `security/` | Local Rust files | 13 vulnerability patterns (regex + AST) |
| `agent/` | Orchestrator | Narrative → target selection → scan → report |
| `output/` | Askama | Combined HTML report rendering |

## Tech Stack

Rust (edition 2024), reqwest, tokio, syn, regex, walkdir, scraper, askama, clap.
