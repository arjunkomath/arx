#![deny(clippy::all)]

mod allowlist;
mod config;
mod hook;
mod output;
mod rules;
mod scanner;

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand, ValueEnum};

use allowlist::Allowlist;
use rules::{
    Severity, load_code_injection_rules, load_default_rules, load_rules, load_secrets_rules,
    load_web_injection_rules,
};
use scanner::Scanner;

#[derive(Parser)]
#[command(
    name = "arx",
    version,
    about = "Protect AI agents from prompt injection"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        path: PathBuf,

        #[arg(long)]
        rules: Option<PathBuf>,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        no_secrets: bool,

        #[arg(long)]
        no_code_injection: bool,

        #[arg(long)]
        no_web_injection: bool,

        #[arg(long, value_enum)]
        severity: Option<ThresholdLevel>,

        #[arg(long, value_delimiter = ',')]
        allow_rules: Vec<String>,

        #[arg(long, value_delimiter = ',')]
        ignore_path: Vec<String>,
    },

    Hook {
        #[arg(long)]
        rules: Option<PathBuf>,

        #[arg(long)]
        no_secrets: bool,

        #[arg(long)]
        no_code_injection: bool,

        #[arg(long)]
        no_web_injection: bool,

        #[arg(long, value_enum)]
        threshold: Option<ThresholdLevel>,

        #[arg(long)]
        json: bool,

        #[arg(long, value_delimiter = ',')]
        allow_rules: Vec<String>,

        #[arg(long)]
        fail_open: bool,
    },
}

#[derive(Clone, ValueEnum)]
enum ThresholdLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl From<ThresholdLevel> for Severity {
    fn from(level: ThresholdLevel) -> Self {
        match level {
            ThresholdLevel::Low => Severity::Low,
            ThresholdLevel::Medium => Severity::Medium,
            ThresholdLevel::High => Severity::High,
            ThresholdLevel::Critical => Severity::Critical,
        }
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn main() {
    let cli = Cli::parse();
    let config = config::load_config().unwrap_or_default();

    match cli.command {
        Commands::Scan {
            path,
            rules,
            json,
            no_secrets,
            no_code_injection,
            no_web_injection,
            severity,
            allow_rules,
            ignore_path,
        } => {
            let scan_cfg = config.scan.as_ref();

            // CLI flags override config (CLI bool flags are false when not passed)
            let eff_no_secrets = no_secrets || scan_cfg.and_then(|s| s.no_secrets).unwrap_or(false);
            let eff_no_code_injection =
                no_code_injection || scan_cfg.and_then(|s| s.no_code_injection).unwrap_or(false);
            let eff_no_web_injection =
                no_web_injection || scan_cfg.and_then(|s| s.no_web_injection).unwrap_or(false);

            let mut rule_file = build_rules(
                rules,
                eff_no_secrets,
                eff_no_code_injection,
                eff_no_web_injection,
            );

            // Merge custom rules from arx.toml
            let custom = config.custom_rules();
            rule_file.signatures.extend(custom.signatures);
            rule_file.heuristics.extend(custom.heuristics);

            // Merge allow_rules: CLI + config
            let mut merged_allow_rules = allow_rules;
            if let Some(cfg_allow) = scan_cfg.and_then(|s| s.allow_rules.as_ref()) {
                for rule in cfg_allow {
                    if !merged_allow_rules.contains(rule) {
                        merged_allow_rules.push(rule.clone());
                    }
                }
            }

            // Merge ignore_paths: CLI + config
            let mut merged_ignore_paths = ignore_path;
            if let Some(cfg_ignore) = scan_cfg.and_then(|s| s.ignore_paths.as_ref()) {
                for p in cfg_ignore {
                    if !merged_ignore_paths.contains(p) {
                        merged_ignore_paths.push(p.clone());
                    }
                }
            }

            let allowlist = Allowlist::new(&merged_allow_rules, &merged_ignore_paths);
            let scanner = Scanner::with_allowlist(&rule_file, allowlist);

            // CLI severity overrides config severity
            let min_severity = if let Some(sev) = severity {
                sev.into()
            } else if let Some(sev_str) = scan_cfg.and_then(|s| s.severity.as_deref()) {
                parse_severity(sev_str).unwrap_or_else(|| {
                    eprintln!(
                        "arx: warning: invalid severity '{}' in arx.toml, using low",
                        sev_str
                    );
                    Severity::Low
                })
            } else {
                Severity::Low
            };

            let all_results = match scanner.scan_path(&path) {
                Ok(results) => results,
                Err(e) => {
                    eprintln!("arx: error: {e}");
                    process::exit(1);
                }
            };

            let has_threats = all_results
                .iter()
                .flat_map(|r| &r.findings)
                .any(|f| f.severity >= Severity::High);

            let display_results: Vec<_> = all_results
                .into_iter()
                .map(|mut r| {
                    r.findings.retain(|f| f.severity >= min_severity);
                    r
                })
                .collect();

            output::print_results(&display_results, json);

            if has_threats {
                process::exit(1);
            }
        }

        Commands::Hook {
            rules,
            no_secrets,
            no_code_injection,
            no_web_injection,
            threshold,
            json,
            allow_rules,
            fail_open,
        } => {
            let hook_cfg = config.hook.as_ref();

            let eff_no_secrets = no_secrets || hook_cfg.and_then(|h| h.no_secrets).unwrap_or(false);
            let eff_no_code_injection =
                no_code_injection || hook_cfg.and_then(|h| h.no_code_injection).unwrap_or(false);
            let eff_no_web_injection =
                no_web_injection || hook_cfg.and_then(|h| h.no_web_injection).unwrap_or(false);

            let mut rule_file = build_rules(
                rules,
                eff_no_secrets,
                eff_no_code_injection,
                eff_no_web_injection,
            );

            let custom = config.custom_rules();
            rule_file.signatures.extend(custom.signatures);
            rule_file.heuristics.extend(custom.heuristics);

            let mut merged_allow_rules = allow_rules;
            if let Some(cfg_allow) = hook_cfg.and_then(|h| h.allow_rules.as_ref()) {
                for rule in cfg_allow {
                    if !merged_allow_rules.contains(rule) {
                        merged_allow_rules.push(rule.clone());
                    }
                }
            }

            let allowlist = Allowlist::new(&merged_allow_rules, &[]);
            let scanner = Scanner::with_allowlist(&rule_file, allowlist);

            let eff_fail_open = fail_open || hook_cfg.and_then(|h| h.fail_open).unwrap_or(false);

            // CLI threshold overrides config, default to high
            let eff_threshold: Severity = if let Some(t) = threshold {
                t.into()
            } else if let Some(t_str) = hook_cfg.and_then(|h| h.threshold.as_deref()) {
                parse_severity(t_str).unwrap_or_else(|| {
                    eprintln!(
                        "arx: warning: invalid threshold '{}' in arx.toml, using high",
                        t_str
                    );
                    Severity::High
                })
            } else {
                Severity::High
            };

            match hook::run_hook(&scanner, eff_threshold, json) {
                Ok(true) => process::exit(0),
                Ok(false) => process::exit(2),
                Err(e) => {
                    eprintln!("arx: hook error: {e}");
                    if eff_fail_open {
                        process::exit(0)
                    } else {
                        process::exit(2)
                    }
                }
            }
        }
    }
}

fn build_rules(
    extra: Option<PathBuf>,
    no_secrets: bool,
    no_code_injection: bool,
    no_web_injection: bool,
) -> rules::RuleFile {
    let mut rules = load_default_rules();

    if !no_secrets {
        let secrets = load_secrets_rules();
        rules.signatures.extend(secrets.signatures);
        rules.heuristics.extend(secrets.heuristics);
    }

    if !no_code_injection {
        let ci = load_code_injection_rules();
        rules.signatures.extend(ci.signatures);
        rules.heuristics.extend(ci.heuristics);
    }

    if !no_web_injection {
        let wi = load_web_injection_rules();
        rules.signatures.extend(wi.signatures);
        rules.heuristics.extend(wi.heuristics);
    }

    if let Some(path) = extra {
        match load_rules(&path) {
            Ok(extra_rules) => {
                rules.signatures.extend(extra_rules.signatures);
                rules.heuristics.extend(extra_rules.heuristics);
            }
            Err(e) => {
                eprintln!(
                    "arx: warning: failed to load rules from {}: {e}",
                    path.display()
                );
            }
        }
    }

    rules
}
