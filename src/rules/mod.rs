mod encoding;
mod heuristics;
mod signatures;

pub use encoding::EncodingDetector;
pub use heuristics::HeuristicAnalyzer;
pub use signatures::SignatureMatcher;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub signatures: Vec<SignatureRule>,
    #[serde(default)]
    pub heuristics: Vec<HeuristicRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignatureRule {
    pub id: String,
    pub pattern: String,
    pub severity: Severity,
    pub description: String,
    pub category: String,
    #[serde(default)]
    pub cwe: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeuristicRule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub min_length: Option<usize>,
    #[serde(default)]
    pub decode_keywords: Vec<String>,
    #[serde(default)]
    pub unicode_ratio_threshold: Option<f64>,
    #[serde(default)]
    pub tag_density_threshold: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub line: Option<usize>,
    pub matched_text: Option<String>,
    pub cwe: Option<String>,
}

pub fn load_rules(path: &std::path::Path) -> Result<RuleFile, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let rules: RuleFile = toml::from_str(&content)?;
    Ok(rules)
}

pub fn load_default_rules() -> RuleFile {
    let default_toml = include_str!("../../rules/default.toml");
    toml::from_str(default_toml).expect("built-in rules must be valid")
}

pub fn load_secrets_rules() -> RuleFile {
    let toml = include_str!("../../rules/secrets.toml");
    toml::from_str(toml).expect("built-in secrets rules must be valid")
}

pub fn load_code_injection_rules() -> RuleFile {
    let toml = include_str!("../../rules/code_injection.toml");
    toml::from_str(toml).expect("built-in code injection rules must be valid")
}

pub fn load_web_injection_rules() -> RuleFile {
    let toml = include_str!("../../rules/web_injection.toml");
    toml::from_str(toml).expect("built-in web injection rules must be valid")
}
