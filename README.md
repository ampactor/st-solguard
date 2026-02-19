# SolGuard

**Autonomous agent that finds ecosystem landmines: growing Solana projects with critical security gaps.**

Built on narrative intelligence from [SolScout](https://github.com/ampactor/st-narrative) and scanning methodology from [SolScout Scanner](https://github.com/ampactor/st-audit). SolGuard is the autonomous orchestrator that combines both into a narrative-informed security intelligence pipeline.

## What It Found

SolGuard's narrative detection identified a Privacy trend on Solana — a new ZK shielded pool marked "NOT AUDITED." The agent autonomously cloned the repo, scanned it, and discovered a **complete vault-drain exploit chain** (3 Critical + 2 High + 2 Medium findings). Full proof-of-concept and exploit walkthrough: **[shielded-pool-vault-drain.md](https://github.com/ampactor/st-audit/blob/main/pocs/shielded-pool-vault-drain.md)**.

The key insight: no regex or AST pattern can detect this — it's an architectural vulnerability found because narrative signals pointed at unaudited code in an emerging sector. That's narrative-informed targeting in action.

**For comparison:** Round 1 scanned 4 mature, audited repos (Raydium, Switchboard, Tensor) — 155 static findings, zero real vulnerabilities. Round 2 used narrative-informed targeting on unaudited repos — 7 confirmed vulnerabilities including the vault drain.

## Live Report

**[ampactor.github.io/st-solguard](https://ampactor.github.io/st-solguard)** — 9 detected narratives, 7 confirmed findings, all cross-referenced.

## How It Works

```
Signal Collection ──► Narrative Synthesis ──► Target Selection ──► Security Scanning ──► Cross-Reference
  GitHub API              LLM analysis          audit status ×        static + deep         narrative ×
  Solana RPC              confidence scores      narrative signal      agent review          risk scoring
  Blog scraping           trend detection
  DeFiLlama TVL
```

Five phases, fully autonomous after `cargo run`. Each phase's output drives the next:

1. **Signal Collection** — parallel queries to GitHub API (new repos, star velocity), Solana RPC (TPS, program activity, SOL supply), blog scraping (Helius, Jito, Marinade), and DeFiLlama (TVL, protocol rankings)
2. **Narrative Synthesis** — LLM identifies 5-9 emerging trends from cross-validated signals with confidence scores
3. **Target Selection** — cross-references narrative repos with audit status to find high-value, under-examined code
4. **Security Scanning** — 13 static patterns (10 regex + 3 AST via `syn`) plus optional deep multi-turn LLM agent review with protocol-specific focus areas
5. **Cross-Reference** — maps findings back to narratives with risk scoring. The report says "here are bugs in the protocols growing fastest"

## Autonomy

SolGuard is designed to run without human intervention. One command produces a complete intelligence report:

```bash
cargo run -- run -c config.toml -o report.html --deep
```

No human-curated target lists. No manual triage. No hand-picked repos. The agent:

- **Discovers its own targets** — narrative synthesis identifies what's trending, target selection filters by audit status and risk signals
- **Decides where to look** — protocol-specific focus areas are chosen by matching narrative context (DeFi → sandwich/oracle/LP patterns, Privacy → Merkle proof/nullifier patterns, etc.)
- **Allocates its own budget** — `compute_budget()` dynamically scales investigation depth based on narrative confidence and repo count. High-confidence narratives get deeper scans
- **Challenges its own findings** — adversarial validator reviews each finding with a skeptical prompt, dismissing false positives and downgrading disputed severity
- **Handles failures gracefully** — API rate limits, unreachable blogs, repos with no Rust code, malformed LLM responses — the pipeline continues through all of them
- **Cross-references autonomously** — maps findings back to narratives with deterministic risk scoring, producing a narrative-centric report that tells a story, not a list of bugs

The vault-drain exploit chain (3 Critical findings composing a complete attack path) was discovered by the pipeline running exactly this command. A human pointed it at a config file. The agent did the rest.

**98 tests** verify scanner accuracy, agent orchestration, report generation, and cross-reference logic. The pipeline is reproducible: same config → same signal sources → deterministic scoring.

## Why This Matters

Security scanners find bugs. Analytics tools track metrics. No existing tool does both and cross-references them.

The insight is the intersection: **narrative-informed targeting** means the agent scans what's emerging, not what's popular. The vault-drain wasn't found by scanning random repos — it was found because the Privacy narrative signal led to an unaudited program handling SOL custody. That's the ecosystem landmine: growth vector + security gap.

## Quick Start

```bash
cp .env.example .env  # fill in API keys
cargo run -- run -c config.toml -o solguard-report.html
```

Individual phases:
```bash
cargo run -- narratives -c config.toml          # narrative detection only
cargo run -- scan path/to/repo                  # security scan only
cargo run -- scan path/to/repo --deep           # + multi-turn LLM agent review
cargo run -- render -n narratives.json -f findings.json -o report.html  # offline render
```

## Required API Keys

| Subcommand | Keys Needed |
|------------|-------------|
| `scan` | None (static analysis only) |
| `narratives` | `GITHUB_TOKEN` + `GROQ_API_KEY` (or configured LLM provider) |
| `run` | `GITHUB_TOKEN` + `GROQ_API_KEY` + `OPENROUTER_API_KEY` |

## Reproduction Notes

- The [live report](https://ampactor.github.io/st-solguard) was generated with the `claudecode` provider (Claude Opus via local `claude` CLI) for all LLM tasks — narrative synthesis, deep investigation, validation, and cross-reference
- `claudecode` provider: subscription-based, no per-token cost. Requires `claude` CLI installed and authenticated. Each deep scan spawns a `claude -p` subprocess
- Alternative: switch `config.toml` to `provider = "groq"` / `"openrouter"` / `"anthropic"` for API-based inference. Uncomment `[models]` section for per-task routing
- `scan` subcommand without `--deep` runs deterministic static analysis only (no LLM, no API key)

## Tech Stack

| Component | Crate | Purpose |
|-----------|-------|---------|
| Runtime | `tokio` | Async runtime, parallel signal collection |
| HTTP | `reqwest` | GitHub API, Solana RPC, blog scraping, DeFiLlama |
| Security | `syn`, `regex` | AST + regex vulnerability pattern scanning |
| Templates | `askama` | Type-safe HTML report generation |
| CLI | `clap` | 6 subcommands: run, narratives, scan, investigate, test, render |
| Config | `toml`, `dotenvy` | TOML config + `.env` loading |

Rust edition 2024. No Python, no JavaScript, no external binaries.

## License

MIT
