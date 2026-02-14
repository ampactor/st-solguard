use super::types::{Metric, Signal, SignalSource};
use crate::config::GitHubConfig;
use crate::error::Result;
use crate::http::HttpClient;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

const GITHUB_API: &str = "https://api.github.com";

#[derive(Deserialize)]
struct SearchResponse {
    total_count: u64,
    items: Vec<RepoItem>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RepoItem {
    full_name: String,
    description: Option<String>,
    html_url: String,
    stargazers_count: u64,
    forks_count: u64,
    open_issues_count: u64,
    language: Option<String>,
    topics: Option<Vec<String>>,
    created_at: DateTime<Utc>,
    pushed_at: DateTime<Utc>,
    #[serde(default)]
    watchers_count: u64,
}

#[derive(Clone, Serialize)]
pub struct DiscoveredRepo {
    pub name: String,
    pub language: String,
    pub stars: u64,
    pub description: String,
}

pub struct GitHubData {
    pub signals: Vec<Signal>,
    pub discovered_repos: Vec<DiscoveredRepo>,
}

pub async fn collect(config: &GitHubConfig, http: &HttpClient) -> Result<GitHubData> {
    let mut signals = Vec::new();
    let mut discovered_repos = Vec::new();

    let cutoff = Utc::now() - chrono::Duration::days(config.lookback_days as i64);
    let cutoff_str = cutoff.format("%Y-%m-%d").to_string();

    for topic in &config.topics {
        let url = format!(
            "{GITHUB_API}/search/repositories?q=topic:{topic}+created:>{cutoff_str}+stars:>={min_stars}&sort=stars&order=desc&per_page={max}",
            min_stars = config.min_stars,
            max = config.max_repos,
        );

        info!(topic, "searching GitHub for new repos");
        let resp: SearchResponse = http.get_json_authed(&url, &config.token).await?;

        // Collect Rust repos for target selection
        for repo in &resp.items {
            if repo.language.as_deref() == Some("Rust") {
                discovered_repos.push(DiscoveredRepo {
                    name: repo.full_name.clone(),
                    language: "Rust".into(),
                    stars: repo.stargazers_count,
                    description: repo.description.clone().unwrap_or_default(),
                });
            }
        }

        signals.push(Signal {
            source: SignalSource::GitHub,
            category: format!("New {topic} Repositories"),
            title: format!(
                "{} new repos with topic '{topic}' in last {} days",
                resp.total_count, config.lookback_days
            ),
            description: format!(
                "GitHub search found {} repositories created since {cutoff_str} with topic '{topic}' and {}+ stars.",
                resp.total_count, config.min_stars
            ),
            metrics: vec![Metric {
                name: "total_new_repos".into(),
                value: resp.total_count as f64,
                unit: "repos".into(),
            }],
            url: Some(format!("https://github.com/topics/{topic}?o=desc&s=stars")),
            timestamp: Utc::now(),
        });

        // Per-repo signals grouped by category
        let mut categories: std::collections::HashMap<String, Vec<&RepoItem>> =
            std::collections::HashMap::new();
        for repo in &resp.items {
            let cat = categorize_repo(repo);
            categories.entry(cat).or_default().push(repo);
        }

        for (category, repos) in &categories {
            let total_stars: u64 = repos.iter().map(|r| r.stargazers_count).sum();
            let total_forks: u64 = repos.iter().map(|r| r.forks_count).sum();
            let top_repos: Vec<String> = repos
                .iter()
                .take(5)
                .map(|r| format!("{} ({}*)", r.full_name, r.stargazers_count))
                .collect();

            signals.push(Signal {
                source: SignalSource::GitHub,
                category: category.clone(),
                title: format!(
                    "{category}: {} new repos, {total_stars} total stars",
                    repos.len()
                ),
                description: format!("Top repos: {}", top_repos.join(", ")),
                metrics: vec![
                    Metric {
                        name: "repo_count".into(),
                        value: repos.len() as f64,
                        unit: "repos".into(),
                    },
                    Metric {
                        name: "total_stars".into(),
                        value: total_stars as f64,
                        unit: "stars".into(),
                    },
                    Metric {
                        name: "total_forks".into(),
                        value: total_forks as f64,
                        unit: "forks".into(),
                    },
                ],
                url: None,
                timestamp: Utc::now(),
            });
        }
    }

    // Trending Solana repos (recently active)
    let trending_url = format!(
        "{GITHUB_API}/search/repositories?q=topic:solana+pushed:>{cutoff_str}&sort=updated&order=desc&per_page=10",
        cutoff_str = (Utc::now() - chrono::Duration::days(7)).format("%Y-%m-%d"),
    );
    let trending: SearchResponse = http.get_json_authed(&trending_url, &config.token).await?;

    for repo in &trending.items {
        if repo.language.as_deref() == Some("Rust")
            && !discovered_repos.iter().any(|r| r.name == repo.full_name)
        {
            discovered_repos.push(DiscoveredRepo {
                name: repo.full_name.clone(),
                language: "Rust".into(),
                stars: repo.stargazers_count,
                description: repo.description.clone().unwrap_or_default(),
            });
        }
    }

    if !trending.items.is_empty() {
        let top: Vec<String> = trending
            .items
            .iter()
            .take(10)
            .map(|r| {
                format!(
                    "{} ({}*) - {}",
                    r.full_name,
                    r.stargazers_count,
                    r.description.as_deref().unwrap_or("no description")
                )
            })
            .collect();

        signals.push(Signal {
            source: SignalSource::GitHub,
            category: "Trending Solana Repos".into(),
            title: format!(
                "Top {} most active Solana repos this week",
                trending.items.len()
            ),
            description: top.join("\n"),
            metrics: vec![Metric {
                name: "trending_count".into(),
                value: trending.items.len() as f64,
                unit: "repos".into(),
            }],
            url: Some("https://github.com/topics/solana?o=desc&s=updated".into()),
            timestamp: Utc::now(),
        });
    }

    info!(
        signal_count = signals.len(),
        repos = discovered_repos.len(),
        "collected GitHub signals"
    );
    Ok(GitHubData {
        signals,
        discovered_repos,
    })
}

fn categorize_repo(repo: &RepoItem) -> String {
    let topics = repo.topics.as_deref().unwrap_or(&[]);
    let desc = repo.description.as_deref().unwrap_or("").to_lowercase();
    let name = repo.full_name.to_lowercase();

    if topics.iter().any(|t| {
        matches!(
            t.as_str(),
            "defi" | "dex" | "amm" | "swap" | "lending" | "yield"
        )
    }) || desc.contains("defi")
        || desc.contains("swap")
        || desc.contains("amm")
        || desc.contains("lending")
    {
        return "DeFi".into();
    }

    if topics
        .iter()
        .any(|t| matches!(t.as_str(), "depin" | "iot" | "helium" | "hivemapper"))
        || desc.contains("depin")
        || desc.contains("physical infrastructure")
    {
        return "DePIN".into();
    }

    if topics
        .iter()
        .any(|t| matches!(t.as_str(), "ai" | "agent" | "llm" | "machine-learning"))
        || desc.contains("ai agent")
        || desc.contains("autonomous")
        || desc.contains("llm")
    {
        return "AI & Agents".into();
    }

    if topics
        .iter()
        .any(|t| matches!(t.as_str(), "nft" | "gaming" | "metaplex" | "metaverse"))
        || desc.contains("nft")
        || desc.contains("gaming")
    {
        return "NFT & Gaming".into();
    }

    if topics
        .iter()
        .any(|t| matches!(t.as_str(), "payments" | "payfi" | "stablecoin"))
        || desc.contains("payment")
        || desc.contains("payfi")
    {
        return "PayFi".into();
    }

    if topics.iter().any(|t| {
        matches!(
            t.as_str(),
            "sdk" | "toolkit" | "framework" | "rpc" | "validator"
        )
    }) || desc.contains("sdk")
        || desc.contains("framework")
        || desc.contains("toolkit")
        || name.contains("sdk")
    {
        return "Infrastructure".into();
    }

    if topics
        .iter()
        .any(|t| matches!(t.as_str(), "privacy" | "zk" | "zero-knowledge"))
        || desc.contains("privacy")
        || desc.contains("zero knowledge")
        || desc.contains("zk-")
    {
        return "Privacy".into();
    }

    "General Solana".into()
}
