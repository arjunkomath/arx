use serde::Deserialize;
use std::io::Read;
use std::path::PathBuf;

use crate::rules::Severity;
use crate::scanner::Scanner;

const PROJECT_SKILL_DIRS: &[&str] = &[
    ".agents/skills",
    ".agent/skills",
    ".augment/skills",
    ".claude/skills",
    "skills",
    ".cline/skills",
    ".codebuddy/skills",
    ".commandcode/skills",
    ".continue/skills",
    ".crush/skills",
    ".cursor/skills",
    ".factory/skills",
    ".goose/skills",
    ".junie/skills",
    ".iflow/skills",
    ".kilocode/skills",
    ".kiro/skills",
    ".kode/skills",
    ".mcpjam/skills",
    ".vibe/skills",
    ".mux/skills",
    ".openhands/skills",
    ".pi/skills",
    ".qoder/skills",
    ".qwen/skills",
    ".roo/skills",
    ".trae/skills",
    ".windsurf/skills",
    ".zencoder/skills",
    ".neovate/skills",
    ".pochi/skills",
    ".adal/skills",
];

const GLOBAL_SKILL_DIRS: &[&str] = &[
    ".config/agents/skills",
    ".gemini/antigravity/skills",
    ".augment/skills",
    ".claude/skills",
    ".moltbot/skills",
    ".cline/skills",
    ".codebuddy/skills",
    ".codex/skills",
    ".commandcode/skills",
    ".continue/skills",
    ".config/crush/skills",
    ".cursor/skills",
    ".factory/skills",
    ".gemini/skills",
    ".copilot/skills",
    ".config/goose/skills",
    ".junie/skills",
    ".iflow/skills",
    ".kilocode/skills",
    ".kiro/skills",
    ".kode/skills",
    ".mcpjam/skills",
    ".vibe/skills",
    ".mux/skills",
    ".config/opencode/skills",
    ".openhands/skills",
    ".pi/agent/skills",
    ".qoder/skills",
    ".qwen/skills",
    ".roo/skills",
    ".trae/skills",
    ".trae-cn/skills",
    ".codeium/windsurf/skills",
    ".zencoder/skills",
    ".neovate/skills",
    ".pochi/skills",
    ".adal/skills",
];

const HIGH_RISK_TOOLS: &[&str] = &[
    "bash",
    "write",
    "execute",
    "shell",
    "run_command",
    "terminal",
    "skill",
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

fn resolve_skill_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    let cwd = std::env::current_dir().unwrap_or_default();
    for rel in PROJECT_SKILL_DIRS {
        let path = cwd.join(rel);
        if std::fs::metadata(&path).is_ok() {
            dirs.push(path);
        }
    }

    if let Some(home) = dirs::home_dir() {
        for rel in GLOBAL_SKILL_DIRS {
            let path = home.join(rel);
            if std::fs::metadata(&path).is_ok() {
                dirs.push(path);
            }
        }
    }

    dirs
}

const SKILL_SCAN_CATEGORIES: &[&str] = &["prompt_injection", "jailbreak", "delimiter_attack"];

fn scan_skill_dirs(
    scanner: &Scanner,
    threshold: Severity,
    json_output: bool,
    dry_run: bool,
) -> (Vec<crate::rules::Finding>, bool) {
    let skill_threshold = std::cmp::max(threshold, Severity::High);
    let mut all_findings = Vec::new();
    let mut has_blocked = false;

    for dir in resolve_skill_dirs() {
        if let Ok(results) = scanner.scan_path(&dir) {
            for result in results {
                for finding in &result.findings {
                    if finding.severity >= skill_threshold
                        && SKILL_SCAN_CATEGORIES.contains(&finding.category.as_str())
                    {
                        if !json_output {
                            let label = if dry_run { "FOUND" } else { "BLOCKED" };
                            eprintln!(
                                "arx: {} — {} ({}/{}) in {}",
                                label,
                                finding.description,
                                finding.category,
                                finding.rule_id,
                                result.path.display()
                            );
                            if let Some(ref matched) = finding.matched_text {
                                eprintln!("arx: matched: \"{}\"", matched);
                            }
                        }
                        has_blocked = true;
                    }
                }
                all_findings.extend(result.findings);
            }
        }
    }

    (all_findings, has_blocked)
}

pub fn run_hook(
    scanner: &Scanner,
    threshold: Severity,
    json_output: bool,
    dry_run: bool,
    no_skill_scan: bool,
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
        .map(|t| HIGH_RISK_TOOLS.contains(&t.to_lowercase().as_str()))
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
                    let label = if dry_run { "FOUND" } else { "BLOCKED" };
                    eprintln!(
                        "arx: {} — {} ({}/{})",
                        label, finding.description, finding.category, finding.rule_id
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

    if !no_skill_scan {
        let (skill_findings, skill_blocked) =
            scan_skill_dirs(scanner, effective_threshold, json_output, dry_run);
        all_findings.extend(skill_findings);
        if skill_blocked {
            has_blocked = true;
        }
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
        && !message.is_empty()
    {
        texts.push(message.clone());
    }

    texts
}

fn collect_string_values(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            if !s.is_empty() {
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
