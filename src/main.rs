#![deny(clippy::all)]

mod allowlist;
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

        #[arg(long, value_enum, default_value = "high")]
        threshold: ThresholdLevel,

        #[arg(long)]
        json: bool,

        #[arg(long, value_delimiter = ',')]
        allow_rules: Vec<String>,
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

fn main() {
    let cli = Cli::parse();

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
            let rule_file = build_rules(rules, no_secrets, no_code_injection, no_web_injection);
            let allowlist = Allowlist::new(&allow_rules, &ignore_path);
            let scanner = Scanner::with_allowlist(&rule_file, allowlist);
            let min_severity: Severity = severity.map(Into::into).unwrap_or(Severity::Low);

            let results: Vec<_> = scanner
                .scan_path(&path)
                .into_iter()
                .map(|mut r| {
                    r.findings.retain(|f| f.severity >= min_severity);
                    r
                })
                .collect();

            let has_threats = results
                .iter()
                .flat_map(|r| &r.findings)
                .any(|f| f.severity >= Severity::High);

            output::print_results(&results, json);

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
        } => {
            let rule_file = build_rules(rules, no_secrets, no_code_injection, no_web_injection);
            let allowlist = Allowlist::new(&allow_rules, &[]);
            let scanner = Scanner::with_allowlist(&rule_file, allowlist);

            match hook::run_hook(&scanner, threshold.into(), json) {
                Ok(true) => process::exit(0),
                Ok(false) => process::exit(2),
                Err(e) => {
                    eprintln!("arx: hook error: {e}");
                    process::exit(0);
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
