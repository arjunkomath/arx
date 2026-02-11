use serde::Deserialize;
use std::io::Read;

use crate::rules::Severity;
use crate::scanner::Scanner;

const HIGH_RISK_TOOLS: &[&str] = &[
    "Bash",
    "bash",
    "Write",
    "write",
    "execute",
    "Execute",
    "shell",
    "Shell",
    "run_command",
    "terminal",
];

#[derive(Debug, Deserialize)]
pub struct HookEvent {
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<serde_json::Value>,
    #[serde(default, alias = "tool_response")]
    pub tool_result: Option<serde_json::Value>,
    #[serde(default)]
    pub message: Option<String>,
}

pub fn run_hook(
    scanner: &Scanner,
    threshold: Severity,
    json_output: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    if input.trim().is_empty() {
        return Ok(true);
    }

    let event: HookEvent = serde_json::from_str(&input)?;
    let is_high_risk = event
        .tool_name
        .as_deref()
        .map(|t| HIGH_RISK_TOOLS.contains(&t))
        .unwrap_or(false);

    let effective_threshold = if is_high_risk {
        std::cmp::min(threshold, Severity::Medium)
    } else {
        threshold
    };

    let texts = extract_scannable_text(&event);

    let mut all_findings = Vec::new();
    let mut has_blocked = false;

    for text in &texts {
        let findings = scanner.scan_content(text);
        for finding in &findings {
            if finding.severity >= effective_threshold {
                if !json_output {
                    eprintln!(
                        "arx: BLOCKED — {} ({}/{})",
                        finding.description, finding.category, finding.rule_id
                    );
                    if let Some(ref matched) = finding.matched_text {
                        eprintln!("arx: matched: \"{}\"", matched);
                    }
                }
                has_blocked = true;
            }
        }
        all_findings.extend(findings);
    }

    if json_output {
        let output: Vec<serde_json::Value> = all_findings
            .iter()
            .filter(|f| f.severity >= effective_threshold)
            .map(|f| {
                serde_json::json!({
                    "rule_id": f.rule_id,
                    "description": f.description,
                    "severity": f.severity.to_string(),
                    "category": f.category,
                    "line": f.line,
                    "matched_text": f.matched_text,
                    "cwe": f.cwe,
                    "blocked": f.severity >= effective_threshold,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    }

    Ok(!has_blocked)
}

fn extract_scannable_text(event: &HookEvent) -> Vec<String> {
    let mut texts = Vec::new();

    if let Some(ref input) = event.tool_input {
        collect_string_values(input, &mut texts);
    }

    if let Some(ref result) = event.tool_result {
        collect_string_values(result, &mut texts);
    }

    if let Some(ref message) = event.message
        && message.len() > 10
    {
        texts.push(message.clone());
    }

    texts
}

fn collect_string_values(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            if s.len() > 10 {
                out.push(s.clone());
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_string_values(v, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_string_values(v, out);
            }
        }
        _ => {}
    }
}
