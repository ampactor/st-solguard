# SolGuard

**Autonomous agent that finds ecosystem landmines: growing Solana projects with critical security gaps.**

## What It Found

SolGuard's narrative detection identified a Privacy trend on Solana — a new ZK shielded pool (`shielded-pool-pinocchio-solana`) built with raw Pinocchio, Groth16/Noir circuits, and explicitly marked "NOT AUDITED." The agent autonomously cloned the repo, scanned it, and triggered deep code review.

The result: a **complete vault-drain exploit chain**. The program accepts Merkle roots directly from instruction data without verification — there is no on-chain Merkle tree. Combined with zero-amount deposits (Solana allows 0-lamport transfers), an attacker can:

1. Deposit 0 SOL with a fabricated Merkle root containing a commitment for the full vault balance
2. Generate a valid ZK proof against their own root (it's genuinely valid — the attacker built the tree)
3. Withdraw every lamport in the vault in a single transaction

**Cost:** ~10,000 lamports (two transaction fees). **Impact:** Total loss of all deposited funds.

Three Critical findings compose the chain: client-supplied root acceptance (C-01), no on-chain commitment storage (C-02), and zero-amount deposits (C-03). Plus 2 High and 2 Medium findings in the same program.

No regex or AST pattern can detect this. It's an architectural vulnerability — the program's trust model is fundamentally broken. SolGuard found it because narrative signals pointed at unaudited code in an emerging sector.

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
