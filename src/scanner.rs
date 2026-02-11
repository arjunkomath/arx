use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use crate::allowlist::Allowlist;
use crate::rules::{EncodingDetector, Finding, HeuristicAnalyzer, RuleFile, SignatureMatcher};

pub struct Scanner {
    signatures: SignatureMatcher,
    heuristics: HeuristicAnalyzer,
    encoding: EncodingDetector,
    allowlist: Allowlist,
}

#[derive(Debug)]
pub struct ScanResult {
    pub path: PathBuf,
    pub findings: Vec<Finding>,
}

impl Scanner {
    #[allow(dead_code)]
    pub fn new(rules: &RuleFile) -> Self {
        Self {
            signatures: SignatureMatcher::new(&rules.signatures),
            heuristics: HeuristicAnalyzer::new(&rules.heuristics),
            encoding: EncodingDetector::new(&rules.heuristics),
            allowlist: Allowlist::empty(),
        }
    }

    pub fn with_allowlist(rules: &RuleFile, allowlist: Allowlist) -> Self {
        Self {
            signatures: SignatureMatcher::new(&rules.signatures),
            heuristics: HeuristicAnalyzer::new(&rules.heuristics),
            encoding: EncodingDetector::new(&rules.heuristics),
            allowlist,
        }
    }

    pub fn scan_content(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(self.signatures.scan(content));
        findings.extend(self.heuristics.scan(content));
        findings.extend(self.encoding.scan(content));

        let lines: Vec<&str> = content.lines().collect();

        findings.retain(|f| {
            if self.allowlist.is_rule_allowed(&f.rule_id) {
                return false;
            }

            if let Some(line_num) = f.line
                && line_num > 0
                && line_num <= lines.len()
                && Allowlist::has_inline_allow(lines[line_num - 1])
            {
                return false;
            }

            true
        });

        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }

    pub fn scan_file(&self, path: &Path) -> ScanResult {
        let findings = match std::fs::read_to_string(path) {
            Ok(content) => self.scan_content(&content),
            Err(_) => Vec::new(),
        };
        ScanResult {
            path: path.to_path_buf(),
            findings,
        }
    }

    pub fn scan_path(&self, path: &Path) -> Vec<ScanResult> {
        if path.is_file() {
            if self.allowlist.is_path_ignored(path) {
                return vec![ScanResult {
                    path: path.to_path_buf(),
                    findings: Vec::new(),
                }];
            }
            return vec![self.scan_file(path)];
        }

        WalkBuilder::new(path)
            .follow_links(true)
            .hidden(false)
            .build()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_some_and(|ft| ft.is_file()))
            .filter(|e| is_scannable(e.path()))
            .filter(|e| !self.allowlist.is_path_ignored(e.path()))
            .map(|e| self.scan_file(e.path()))
            .collect()
    }
}

const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", ".venv", "__pycache__"];

fn is_scannable(path: &Path) -> bool {
    for component in path.components() {
        if let std::path::Component::Normal(name) = component
            && let Some(name_str) = name.to_str()
            && SKIP_DIRS.contains(&name_str)
        {
            return false;
        }
    }

    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => matches!(
            ext,
            "md" | "txt"
                | "toml"
                | "yaml"
                | "yml"
                | "json"
                | "jsonl"
                | "xml"
                | "html"
                | "py"
                | "js"
                | "ts"
                | "tsx"
                | "jsx"
                | "rs"
                | "go"
                | "rb"
                | "sh"
                | "bash"
                | "zsh"
                | "fish"
                | "prompt"
                | "template"
                | "jinja"
                | "j2"
                | "hbs"
                | "env"
                | "cfg"
                | "ini"
                | "conf"
                | "csv"
        ),
        None => false,
    }
}
