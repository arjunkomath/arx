use regex::Regex;

use super::{Finding, SignatureRule};

pub struct SignatureMatcher {
    compiled: Vec<CompiledSignature>,
}

struct CompiledSignature {
    rule: SignatureRule,
    regex: Regex,
}

impl SignatureMatcher {
    pub fn new(rules: &[SignatureRule]) -> Self {
        let compiled = rules
            .iter()
            .filter_map(|rule| match Regex::new(&rule.pattern) {
                Ok(regex) => Some(CompiledSignature {
                    rule: rule.clone(),
                    regex,
                }),
                Err(e) => {
                    eprintln!("arx: warning: invalid regex in rule {}: {e}", rule.id);
                    None
                }
            })
            .collect();
        Self { compiled }
    }

    pub fn scan(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for sig in &self.compiled {
            for mat in sig.regex.find_iter(content) {
                let line = content[..mat.start()].matches('\n').count() + 1;
                let matched = mat.as_str();
                let truncated = if matched.len() > 100 {
                    let boundary = matched
                        .char_indices()
                        .map(|(i, _)| i)
                        .take_while(|&i| i <= 100)
                        .last()
                        .unwrap_or(0);
                    format!("{}...", &matched[..boundary])
                } else {
                    matched.to_string()
                };

                findings.push(Finding {
                    rule_id: sig.rule.id.clone(),
                    description: sig.rule.description.clone(),
                    severity: sig.rule.severity,
                    category: sig.rule.category.clone(),
                    line: Some(line),
                    matched_text: Some(truncated),
                    cwe: sig.rule.cwe.clone(),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Severity;

    #[test]
    fn bad_regex_is_skipped_with_warning() {
        let rules = vec![SignatureRule {
            id: "bad-rule".to_string(),
            pattern: "[invalid(regex".to_string(),
            severity: Severity::High,
            description: "test".to_string(),
            category: "test".to_string(),
            cwe: None,
        }];

        let matcher = SignatureMatcher::new(&rules);
        assert!(matcher.compiled.is_empty());
    }

    #[test]
    fn truncation_safe_on_multibyte() {
        let rules = vec![SignatureRule {
            id: "test-rule".to_string(),
            pattern: r".{50,}".to_string(),
            severity: Severity::Low,
            description: "test".to_string(),
            category: "test".to_string(),
            cwe: None,
        }];

        let matcher = SignatureMatcher::new(&rules);
        let content = "é".repeat(200);
        let findings = matcher.scan(&content);
        assert!(!findings.is_empty());
        if let Some(ref text) = findings[0].matched_text {
            assert!(text.ends_with("..."));
        }
    }
}
