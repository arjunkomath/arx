use serde::Deserialize;
use std::path::Path;

use crate::rules::RuleFile;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub scan: Option<ScanConfig>,
    #[serde(default)]
    pub hook: Option<HookConfig>,
    #[serde(default)]
    pub signatures: Vec<crate::rules::SignatureRule>,
    #[serde(default)]
    pub heuristics: Vec<crate::rules::HeuristicRule>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ScanConfig {
    pub severity: Option<String>,
    pub no_secrets: Option<bool>,
    pub no_code_injection: Option<bool>,
    pub no_web_injection: Option<bool>,
    pub allow_rules: Option<Vec<String>>,
    pub ignore_paths: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct HookConfig {
    pub threshold: Option<String>,
    pub fail_open: Option<bool>,
    pub no_secrets: Option<bool>,
    pub no_code_injection: Option<bool>,
    pub no_web_injection: Option<bool>,
    pub allow_rules: Option<Vec<String>>,
}

impl Config {
    pub fn custom_rules(&self) -> RuleFile {
        RuleFile {
            signatures: self.signatures.clone(),
            heuristics: self.heuristics.clone(),
        }
    }
}

pub fn load_config() -> Option<Config> {
    let path = Path::new("arx.toml");
    if !path.exists() {
        return None;
    }

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("arx: warning: failed to read arx.toml: {e}");
            return None;
        }
    };

    match toml::from_str(&content) {
        Ok(config) => Some(config),
        Err(e) => {
            eprintln!("arx: warning: failed to parse arx.toml: {e}");
            None
        }
    }
}
