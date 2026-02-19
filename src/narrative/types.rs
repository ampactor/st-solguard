use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub source: SignalSource,
    pub category: String,
    pub title: String,
    pub description: String,
    pub metrics: Vec<Metric>,
    pub url: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalSource {
    GitHub,
    SolanaOnchain,
    Social,
    DeFiLlama,
    Discovery,
}

impl std::fmt::Display for SignalSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GitHub => write!(f, "GitHub"),
            Self::SolanaOnchain => write!(f, "Solana Onchain"),
            Self::Social => write!(f, "Social"),
            Self::DeFiLlama => write!(f, "DeFiLlama"),
            Self::Discovery => write!(f, "Discovery"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub value: f64,
    pub unit: String,
}

impl std::fmt::Display for Metric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.unit.is_empty() {
            write!(f, "{}: {:.1}", self.name, self.value)
        } else {
            write!(f, "{}: {:.1} {}", self.name, self.value, self.unit)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrendDirection {
    Accelerating,
    Stable,
    Decelerating,
    Emerging,
}

impl std::fmt::Display for TrendDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accelerating => write!(f, "Accelerating"),
            Self::Stable => write!(f, "Stable"),
            Self::Decelerating => write!(f, "Decelerating"),
            Self::Emerging => write!(f, "Emerging"),
        }
    }
}
