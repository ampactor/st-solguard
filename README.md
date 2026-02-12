# SolGuard

**Autonomous Solana ecosystem intelligence agent that answers one question: "where are the ecosystem landmines?"**

Growing projects with security gaps are where the ecosystem is most vulnerable -- that's where users and capital are flowing toward unaudited code. SolGuard finds those intersections autonomously.

## Autonomous Decision Chain

SolGuard runs a 5-phase pipeline where each phase's output drives the next. No human input after `cargo run`. Every decision -- what to monitor, what to scan, what to report -- emerges from data collected in prior phases.

```
Signal Collection ──► Narrative Synthesis ──► Target Selection ──► Security Scanning ──► Cross-Reference
   (4 sources)           (LLM analysis)        (data-driven)      (13 patterns)        (narrative x findings)
```

### Phase 1: Signal Collection

Four data sources queried in parallel via `tokio::join!`:

| Source | What it collects | Implementation |
|--------|-----------------|----------------|
| **GitHub API** | New Solana repos, star velocity, trending projects | `src/narrative/github.rs` |
| **Solana RPC** | TPS, epoch state, SOL supply, per-program tx rates | `src/narrative/solana_rpc.rs` |
| **Social/Blogs** | Article extraction from Helius, Solana, Jito, Marinade blogs | `src/narrative/social.rs` |
| **DeFiLlama** | Chain TVL, protocol TVL rankings, category breakdown | `src/narrative/defi_llama.rs` |

Signals are collected with metrics (tx/hr, TVL in USD, star counts) and cross-source timestamps. The agent doesn't just scrape -- it computes rates, ranks, and relative positions.

**Solana on-chain data specifically monitored:**
- Network performance: TPS (total + non-vote), recent performance samples
- Network state: epoch number, slot progress, cumulative transaction count
- Token economics: SOL supply (total, circulating, non-circulating), circulating percentage
- Program activity (paginated, up to 1000 tx per program): Jupiter Aggregator v6, Raydium AMM, Jito Stake Pool, Marinade Finance, Metaplex Token Metadata, Tensor

### Phase 2: Narrative Synthesis

Aggregated signals are grouped by category, cross-validated across sources, and fed to an LLM that identifies 5-8 emerging narratives with confidence scores (0.0-1.0). Each narrative includes:
- Title and summary explaining the trend
- Confidence score based on signal convergence
- Trend direction (accelerating/stable/emerging)
- Active repositories associated with the narrative

The LLM doesn't generate fiction -- it synthesizes structured signals into named trends. The `aggregator` pre-groups signals so the LLM's job is pattern naming, not data processing.

### Phase 3: Target Selection

Repositories discovered during signal collection are attached to their narratives. The agent selects scan targets based on what's *emerging*, not what's popular. This is the key autonomous decision: narrative context determines what gets scanned.

A random scanner finds bugs in random code. SolGuard finds bugs in the code that *matters right now* -- the protocols where capital and users are flowing.

### Phase 4: Security Scanning

13 Solana-specific vulnerability patterns applied to every Rust file in cloned repos:

**10 regex patterns (SOL-001 through SOL-010):**

| ID | Pattern | Severity |
|----|---------|----------|
| SOL-001 | Missing signer constraint on privileged accounts | High |
| SOL-002 | Missing owner validation on deserialized accounts | High |
| SOL-003 | Unchecked arithmetic on token amounts (overflow/underflow) | Medium |
| SOL-004 | Unvalidated `remaining_accounts` iteration | High |
| SOL-005 | PDA bump seed not stored or verified | Medium |
| SOL-006 | Account closed without zeroing data (revival attack) | Critical |
| SOL-007 | Arbitrary CPI target from user input | Critical |
| SOL-008 | Type cosplay -- missing discriminator check | High |
| SOL-009 | Division before multiplication (precision loss) | Medium |
| SOL-010 | Missing Token-2022 extension handling | Medium |

**3 AST patterns via `syn` (AST-001 through AST-003):**

| ID | Pattern | Severity |
|----|---------|----------|
| AST-001 | Unchecked `AccountInfo` in Anchor Accounts struct (no `/// CHECK:`) | Medium |
| AST-002 | Verbose error logging leaking account keys via `msg!()` | Low |
| AST-003 | `unsafe` block in Solana program code | High |

The scanner excludes test/client/SDK directories -- only on-chain program code is analyzed. Findings are deduplicated and sorted by severity.

### Phase 5: Cross-Reference

The final output maps security findings back to narrative contexts. The report doesn't just say "here are bugs" -- it says "here are bugs in the protocols that are growing fastest." This is where the insight lives: the intersection of growth vectors and risk hotspots.

## Worked Example: Real Vulnerability Found via Narrative Targeting

Signal collection detected a "Privacy" category signal: `shielded-pool-pinocchio-solana`, a new ZK privacy pool for SOL using Pinocchio (raw Solana, no Anchor safety net) with Groth16/Noir circuits. The repo explicitly declared "NOT AUDITED." Simultaneously, Jito Stake Pool was processing 380 tx/hr (40:1 vs Marinade), and Metaplex Token Metadata was at 4,176 tx/hr. Narrative synthesis identified three emerging narratives with high confidence.

Target selection cross-referenced narrative signals with audit status. Four previously-scanned repos (Raydium CLMM, Raydium CP-Swap, Switchboard, Tensor) were mature and heavily-audited -- they yielded zero real vulnerabilities across 155 scanner findings. The three narrative-informed targets had **no formal audits**.

Security scanning found 90 static findings across the three repos -- all false positives. But deep manual review of shielded-pool discovered a **complete vault-drain exploit chain**:

> **C-01: Client-Supplied Merkle Root.** The deposit instruction accepts the new Merkle root directly from instruction data and writes it to state without verification. The `_commitment` field is literally unused (underscore prefix = Rust convention for intentionally discarded). An attacker can deposit 0 SOL with a crafted Merkle root, then withdraw the entire vault balance with a valid ZK proof against their own root. Cost: one transaction fee (~5000 lamports).
>
> **C-02: No On-Chain Commitment Storage.** `ShieldedPoolState` stores only 33 roots (1 current + 32 history), zero leaves. There is no on-chain Merkle tree -- the architectural root cause of C-01.
>
> **C-03: Zero-Amount Deposit.** No minimum deposit check. Solana allows 0-lamport system transfers. Combined with C-01, the vault drain is free.

Cross-reference: The privacy narrative signal led to an unaudited Pinocchio program where the program's entire trust model is broken -- it trusts client-supplied Merkle roots. This is an **architectural** vulnerability that no regex or AST scanner can detect. It requires understanding the system's invariants and how they compose. That's the ecosystem landmine: a growing privacy narrative attracting deposits into a vault that can be drained in a single transaction.

**Result:** Round 1 (mature targets, no narrative) = 0 real vulnerabilities. Round 2 (narrative-informed, unaudited targets) = 3 CRITICAL + 3 HIGH + 7 MEDIUM + 17 LOW across 3 repos. Narrative-informed targeting dramatically outperformed manual target selection.

## Why This Combination Is Unique

Security scanners find bugs. Analytics tools track metrics. No existing tool does both and cross-references them.

The cross-functional insight matters because:
- **Narrative-informed targeting** means scanning repos in *emerging* sectors, not random repos. The agent's scan list is a function of what's growing.
- **Security-contextualized narratives** mean growth stories come with risk assessments. "This sector is booming" becomes "this sector is booming and has 40 critical findings."
- **Ecosystem landmines** are the specific intersection: high growth + unaudited code = where the next exploit will hit.

## Reproducibility

Everything runs from a single command:

```bash
# Set environment (see .env.example)
export GITHUB_TOKEN=...
export OPENROUTER_API_KEY=...
export SOLANA_RPC_URL=...           # optional, defaults to public mainnet

# Full autonomous pipeline -- produces everything from scratch
cargo run -- run -c config.toml -o solguard-report.html
```

Individual phases can also run independently:

```bash
# Narrative detection only (signals + LLM synthesis)
cargo run -- narratives -c config.toml

# Security scan a specific local repo
cargo run -- scan path/to/repo

# Re-render report from cached data
cargo run -- render -n narratives.json -f findings.json -o report.html
```

The output is a self-contained HTML report with:
- Narrative cards with confidence scores and trend indicators
- Security findings grouped by repo with severity breakdown
- Cross-referenced ecosystem intelligence view
- Stats dashboard: narratives detected, repos scanned, critical/high findings

**Live report:** deployed automatically via GitHub Pages on every push to `main`.

## Commit History as Autonomy Evidence

The git log shows the autonomous development arc:

```
c94ab54 feat(solguard): init project with CLI skeleton
cc581cf feat(solguard): add narrative detection module
187e4c4 feat(solguard): add security scanning module
b283ac5 feat(solguard): add combined intelligence report with Tailwind template
2607cd2 feat(solguard): add autonomous agent orchestrator
3f3d5a9 feat(solguard): wire CLI to autonomous pipeline
3064d31 feat(solguard): wire narrative and security modules with real implementations
0372b41 feat(solguard): add DeFiLlama TVL data source
354cf93 feat(solguard): add render subcommand for offline report generation
86fdbdc feat(solguard): regenerate report with Opus analysis and security scans
```

Each commit is a working increment. The agent designed the architecture (5-phase pipeline), implemented each module, wired them together, iterated on the report quality, and regenerated with production-grade LLM analysis.

## Tech Stack

| Component | Crate | Purpose |
|-----------|-------|---------|
| Runtime | `tokio` | Async runtime, parallel signal collection |
| HTTP | `reqwest` | GitHub API, Solana RPC, blog scraping, DeFiLlama |
| Parsing | `syn`, `proc-macro2`, `quote` | Rust AST analysis for security patterns |
| Patterns | `regex` | 10 vulnerability regex patterns |
| Scraping | `scraper` | HTML article extraction from blogs |
| Templates | `askama` | Type-safe HTML report generation |
| CLI | `clap` | Subcommand routing (`run`, `narratives`, `scan`, `render`) |
| Filesystem | `walkdir` | Recursive Rust file discovery |
| Config | `toml`, `dotenvy` | TOML config + `.env` loading |
| Serialization | `serde`, `serde_json` | Signal/finding data interchange |
| Diagnostics | `tracing` | Structured logging across all phases |

Rust edition 2024. No Python, no JavaScript runtime, no external binaries. Pure Rust from signal collection to HTML output.

## License

MIT
