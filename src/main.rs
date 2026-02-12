mod agent;
mod config;
mod error;
mod http;
mod llm;
mod narrative;
mod output;
mod security;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

/// CLI override for LLM provider/model.
pub struct LlmOverride {
    pub provider: llm::Provider,
    pub model: String,
}

fn make_llm_override(provider: Option<String>, model: Option<String>) -> Option<LlmOverride> {
    if provider.is_none() && model.is_none() {
        return None;
    }
    let provider = provider
        .map(|p| match p.as_str() {
            "anthropic" => llm::Provider::Anthropic,
            "openai" => llm::Provider::OpenAi,
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
        } => {
            let llm_override = make_llm_override(provider, model);
            agent::run_full_pipeline(config, output, repos_dir, llm_override).await
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
        Command::Scan { repo_path } => {
            let findings = security::scan_repo(&repo_path).await?;
            let json = serde_json::to_string_pretty(&findings)?;
            println!("{json}");
            Ok(())
        }
    }
}
