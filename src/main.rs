mod agent;
mod narrative;
mod output;
mod security;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

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
    },

    /// Run narrative detection only
    Narratives {
        /// Path to config file
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,
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
        } => agent::run_full_pipeline(config, output, repos_dir).await,
        Command::Narratives { config } => {
            let narratives = narrative::run_narrative_pipeline(&config).await?;
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
