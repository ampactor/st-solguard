use st_solguard::*;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

/// Build an LlmClient from config + optional CLI override.
fn build_llm_client(
    llm_config: &config::LlmConfig,
    llm_override: Option<&LlmOverride>,
) -> Result<llm::LlmClient> {
    let provider = llm_override
        .map(|o| o.provider.clone())
        .unwrap_or_else(|| llm_config.provider.clone());
    let model = llm_override
        .map(|o| o.model.clone())
        .unwrap_or_else(|| llm_config.model.clone());
    let client = llm::LlmClient::from_config(
        provider,
        model,
        llm_config.max_tokens,
        llm_config.api_key_env.clone(),
        llm_config.base_url.clone(),
    )?;
    Ok(client)
}

/// Build a ModelRouter from config, with optional CLI override.
///
/// If `--model` is set, all task kinds use the override. Otherwise, per-task
/// models from `[models]` override the default `[llm]` client.
fn build_model_router(
    cfg: &config::Config,
    llm_override: Option<&LlmOverride>,
) -> Result<llm::ModelRouter> {
    let default = build_llm_client(&cfg.llm, llm_override)?;

    // CLI override applies uniformly — no per-task routing
    if llm_override.is_some() {
        return Ok(llm::ModelRouter::new(default));
    }

    let mut router = llm::ModelRouter::new(default);

    if let Some(ref models) = cfg.models {
        let pairs: [(&Option<config::ModelConfig>, llm::TaskKind); 4] = [
            (&models.narrative, llm::TaskKind::NarrativeSynthesis),
            (&models.investigation, llm::TaskKind::DeepInvestigation),
            (&models.validation, llm::TaskKind::Validation),
            (&models.cross_reference, llm::TaskKind::CrossReference),
        ];
        for (model_cfg, kind) in pairs {
            if let Some(mc) = model_cfg {
                let client = llm::LlmClient::from_config(
                    mc.provider.clone(),
                    mc.model.clone(),
                    mc.max_tokens.unwrap_or(cfg.llm.max_tokens),
                    mc.api_key_env.clone(),
                    mc.base_url.clone(),
                )?;
                router = router.with_client(kind, client);
            }
        }
    }

    Ok(router)
}

fn make_llm_override(provider: Option<String>, model: Option<String>) -> Option<LlmOverride> {
    if provider.is_none() && model.is_none() {
        return None;
    }
    let provider = provider
        .map(|p| match p.as_str() {
            "anthropic" => llm::Provider::Anthropic,
            "openai" => llm::Provider::OpenAi,
            "groq" => llm::Provider::Groq,
            _ => llm::Provider::OpenRouter,
        })
        .unwrap_or_default();
    let model = model.unwrap_or_else(|| match &provider {
        llm::Provider::Anthropic => "claude-opus-4-6".into(),
        _ => "arcee-ai/trinity-large-preview:free".into(),
    });
    Some(LlmOverride { provider, model })
}

#[derive(Parser)]
#[command(
    name = "solguard",
    about = "Autonomous Solana ecosystem intelligence — narrative detection + security scanning"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Run the full autonomous pipeline: narratives → target selection → security scan → combined report
    Run {
        /// Path to config file
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,

        /// Output path for the combined HTML report
        #[arg(short, long, default_value = "solguard-report.html")]
        output: PathBuf,

        /// Directory to clone repos into for scanning
        #[arg(long, default_value = "repos")]
        repos_dir: PathBuf,

        /// LLM provider override: anthropic, openrouter, openai
        #[arg(long)]
        provider: Option<String>,

        /// LLM model override
        #[arg(long)]
        model: Option<String>,

        /// Use multi-turn agent investigation instead of static-only scanning
        #[arg(long)]
        deep: bool,
    },

    /// Run narrative detection only
    Narratives {
        /// Path to config file
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,

        /// LLM provider override: anthropic, openrouter, openai
        #[arg(long)]
        provider: Option<String>,

        /// LLM model override
        #[arg(long)]
        model: Option<String>,
    },

    /// Scan a specific repo for vulnerabilities
    Scan {
        /// Path to the repository
        repo_path: PathBuf,

        /// Use multi-turn agent investigation (LLM-powered deep review)
        #[arg(long)]
        deep: bool,

        /// LLM provider override: anthropic, openrouter, openai
        #[arg(long)]
        provider: Option<String>,

        /// LLM model override
        #[arg(long)]
        model: Option<String>,

        /// Path to config file (for agent_review settings)
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,

        /// Write findings to file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Investigate a repo with the multi-turn security agent (deep review only)
    Investigate {
        /// Path to the repository
        repo_path: PathBuf,

        /// LLM provider override: anthropic, openrouter, openai
        #[arg(long)]
        provider: Option<String>,

        /// LLM model override
        #[arg(long)]
        model: Option<String>,

        /// Maximum conversation turns
        #[arg(long)]
        max_turns: Option<u32>,

        /// Maximum cost in USD
        #[arg(long)]
        cost_limit: Option<f64>,

        /// Path to config file
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,

        /// Write findings to file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Test a repo: investigate → validate findings → summary (development/calibration)
    Test {
        /// Path to the repository
        repo_path: PathBuf,

        /// LLM provider override: anthropic, openrouter, openai
        #[arg(long)]
        provider: Option<String>,

        /// LLM model override
        #[arg(long)]
        model: Option<String>,

        /// Maximum conversation turns (per phase)
        #[arg(long)]
        max_turns: Option<u32>,

        /// Maximum cost in USD (per phase)
        #[arg(long)]
        cost_limit: Option<f64>,

        /// Path to config file
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,

        /// Write results to file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Render a report from pre-computed analysis files (no LLM calls)
    Render {
        /// Path to narratives JSON file
        #[arg(long)]
        narratives: PathBuf,

        /// Path to security findings JSON file
        #[arg(long)]
        findings: PathBuf,

        /// Output path for the combined HTML report
        #[arg(short, long, default_value = "solguard-report.html")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "st_solguard=info".parse().unwrap()),
        )
        .init();

    dotenvy::from_path("../.env").ok();
    dotenvy::dotenv().ok();

    let cli = Cli::parse();

    match cli.command {
        Command::Run {
            config,
            output,
            repos_dir,
            provider,
            model,
            deep,
        } => {
            let llm_override = make_llm_override(provider, model);
            let cfg = config::Config::load(&config).unwrap_or_default();
            let router = build_model_router(&cfg, llm_override.as_ref())?;
            agent::run_full_pipeline(config, output, repos_dir, llm_override, router, deep).await
        }
        Command::Narratives {
            config,
            provider,
            model,
        } => {
            let llm_override = make_llm_override(provider, model);
            let narratives =
                narrative::run_narrative_pipeline(&config, llm_override.as_ref()).await?;
            let json = serde_json::to_string_pretty(&narratives)?;
            println!("{json}");
            Ok(())
        }
        Command::Scan {
            repo_path,
            deep,
            provider,
            model,
            config,
            output,
        } => {
            let findings = if deep {
                let cfg = config::Config::load(&config).unwrap_or_default();
                let llm_override = make_llm_override(provider, model);
                let llm = build_llm_client(&cfg.llm, llm_override.as_ref())?;
                security::scan_repo_deep(&repo_path, &llm, &cfg.agent_review, None).await?
            } else {
                security::scan_repo(&repo_path).await?
            };
            let json = serde_json::to_string_pretty(&findings)?;
            write_or_print(&json, output.as_deref())?;
            Ok(())
        }
        Command::Investigate {
            repo_path,
            provider,
            model,
            max_turns,
            cost_limit,
            config,
            output,
        } => {
            let cfg = config::Config::load(&config).unwrap_or_default();
            let llm_override = make_llm_override(provider, model);
            let llm = build_llm_client(&cfg.llm, llm_override.as_ref())?;
            let mut agent_config = cfg.agent_review;
            if let Some(turns) = max_turns {
                agent_config.max_turns = turns;
            }
            if let Some(limit) = cost_limit {
                agent_config.cost_limit_usd = limit;
            }
            let findings = security::scan_repo_deep(&repo_path, &llm, &agent_config, None).await?;
            let json = serde_json::to_string_pretty(&findings)?;
            write_or_print(&json, output.as_deref())?;
            Ok(())
        }
        Command::Test {
            repo_path,
            provider,
            model,
            max_turns,
            cost_limit,
            config,
            output,
        } => {
            let cfg = config::Config::load(&config).unwrap_or_default();
            let llm_override = make_llm_override(provider, model);
            let llm = build_llm_client(&cfg.llm, llm_override.as_ref())?;
            let mut agent_config = cfg.agent_review;
            if let Some(turns) = max_turns {
                agent_config.max_turns = turns;
            }
            if let Some(limit) = cost_limit {
                agent_config.cost_limit_usd = limit;
            }

            // Phase 1: Investigate
            info!("phase 1: investigating repository");
            let (findings, inv_stats) =
                security::agent_review::investigate(&llm, &repo_path, &agent_config, None, None)
                    .await?;
            info!(
                findings = findings.len(),
                turns = inv_stats.turns,
                cost = format!("${:.4}", inv_stats.total_cost_usd),
                "investigation complete"
            );

            // Phase 2: Validate
            info!("phase 2: validating findings");
            let validated =
                security::validator::validate(&llm, &repo_path, &findings, &agent_config).await?;
            let confirmed = validated
                .iter()
                .filter(|v| matches!(v.verdict, security::validator::Verdict::Confirmed))
                .count();
            let disputed = validated
                .iter()
                .filter(|v| matches!(v.verdict, security::validator::Verdict::Disputed))
                .count();
            let dismissed = validated
                .iter()
                .filter(|v| matches!(v.verdict, security::validator::Verdict::Dismissed))
                .count();
            info!(confirmed, disputed, dismissed, "validation complete");

            let json = serde_json::to_string_pretty(&validated)?;
            write_or_print(&json, output.as_deref())?;
            Ok(())
        }
        Command::Render {
            narratives,
            findings,
            output,
        } => render_from_files(narratives, findings, output),
    }
}

fn write_or_print(json: &str, output: Option<&std::path::Path>) -> Result<()> {
    match output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, json)?;
            eprintln!("Findings written to {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn render_from_files(
    narratives_path: PathBuf,
    findings_path: PathBuf,
    output_path: PathBuf,
) -> Result<()> {
    let narratives: Vec<narrative::Narrative> =
        serde_json::from_str(&std::fs::read_to_string(&narratives_path)?)?;
    let findings: Vec<security::SecurityFinding> =
        serde_json::from_str(&std::fs::read_to_string(&findings_path)?)?;

    let html = output::render_combined_report(&narratives, &findings)?;
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output_path, &html)?;

    println!(
        "Report rendered: {} ({} narratives, {} findings)",
        output_path.display(),
        narratives.len(),
        findings.len()
    );
    Ok(())
}
