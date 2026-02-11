use crate::rules::{Finding, Severity};
use crate::scanner::ScanResult;

const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

pub fn print_results(results: &[ScanResult], json_output: bool) {
    if json_output {
        print_json(results);
        return;
    }

    let total_files = results.len();
    let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();

    if total_findings == 0 {
        eprintln!(
            "\n  {BOLD}arx{RESET} scanned {total_files} files — {BOLD}no threats found{RESET}\n"
        );
        return;
    }

    let critical = count_severity(results, Severity::Critical);
    let high = count_severity(results, Severity::High);
    let medium = count_severity(results, Severity::Medium);
    let low = count_severity(results, Severity::Low);

    eprintln!();
    for result in results {
        if result.findings.is_empty() {
            continue;
        }
        let path = result.path.display();
        for finding in &result.findings {
            print_finding(&path.to_string(), finding);
        }
    }

    let mut parts = Vec::new();
    if critical > 0 {
        parts.push(format!("{RED}{critical} critical{RESET}"));
    }
    if high > 0 {
        parts.push(format!("{RED}{high} high{RESET}"));
    }
    if medium > 0 {
        parts.push(format!("{YELLOW}{medium} medium{RESET}"));
    }
    if low > 0 {
        parts.push(format!("{DIM}{low} low{RESET}"));
    }

    eprintln!(
        "  {BOLD}{total_findings} issues{RESET} found in {total_files} files ({})\n",
        parts.join(", ")
    );
}

fn print_finding(path: &str, finding: &Finding) {
    let severity_label = match finding.severity {
        Severity::Critical => format!("{RED}{BOLD}THREAT{RESET}"),
        Severity::High => format!("{RED}HIGH{RESET}  "),
        Severity::Medium => format!("{YELLOW}WARN{RESET}  "),
        Severity::Low => format!("{DIM}INFO{RESET}  "),
    };

    let location = match finding.line {
        Some(line) => format!("{path}:{line}"),
        None => path.to_string(),
    };

    eprintln!("  {severity_label} {CYAN}{location}{RESET}");
    eprintln!(
        "          {DIM}{}/{}{RESET} — {}",
        finding.category, finding.rule_id, finding.description
    );
    if let Some(ref text) = finding.matched_text {
        eprintln!("          {DIM}\"{text}\"{RESET}");
    }
    eprintln!();
}

fn print_json(results: &[ScanResult]) {
    let output: Vec<serde_json::Value> = results
        .iter()
        .flat_map(|r| {
            r.findings.iter().map(move |f| {
                serde_json::json!({
                    "path": r.path.display().to_string(),
                    "rule_id": f.rule_id,
                    "description": f.description,
                    "severity": f.severity.to_string(),
                    "category": f.category,
                    "line": f.line,
                    "matched_text": f.matched_text,
                    "cwe": f.cwe,
                })
            })
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn count_severity(results: &[ScanResult], severity: Severity) -> usize {
    results
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| f.severity == severity)
        .count()
}
