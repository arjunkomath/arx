use std::sync::LazyLock;

use base64::Engine;
use regex::Regex;
use unicode_normalization::UnicodeNormalization;

use super::{Finding, HeuristicRule, Severity};

static HEX_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\\x[0-9a-fA-F]{2}){8,}").unwrap());

static URL_ENCODED_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:%[0-9a-fA-F]{2}){5,}").unwrap());

const DEFAULT_DECODE_KEYWORDS: &[&str] = &[
    "ignore",
    "instruction",
    "system",
    "override",
    "secret",
    "password",
    "token",
    "execute",
    "forget",
    "disregard",
];

pub struct EncodingDetector {
    base64_pattern: Regex,
    rules: Vec<HeuristicRule>,
}

impl EncodingDetector {
    pub fn new(rules: &[HeuristicRule]) -> Self {
        Self {
            base64_pattern: Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").unwrap(),
            rules: rules.to_vec(),
        }
    }

    pub fn scan(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        findings.extend(self.check_base64(content));
        findings.extend(self.check_hex(content));
        findings.extend(self.check_url_encoded(content));
        findings.extend(self.check_rot13(content));
        findings.extend(self.check_normalization_tricks(content));

        findings
    }

    fn get_keywords(&self, rule_id: &str) -> Vec<String> {
        self.rules
            .iter()
            .find(|r| r.id == rule_id)
            .map(|r| r.decode_keywords.clone())
            .unwrap_or_else(|| {
                DEFAULT_DECODE_KEYWORDS
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            })
    }

    fn get_severity(&self, rule_id: &str) -> Severity {
        self.rules
            .iter()
            .find(|r| r.id == rule_id)
            .map(|r| r.severity)
            .unwrap_or(Severity::Medium)
    }

    fn check_base64(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let keywords = self.get_keywords("heur-base64-block");

        for mat in self.base64_pattern.find_iter(content) {
            let encoded = mat.as_str();
            if let Some(decoded) = try_base64_decode(encoded) {
                let matched = check_keywords(&decoded, &keywords);
                if !matched.is_empty() {
                    let line = content[..mat.start()].matches('\n').count() + 1;
                    findings.push(Finding {
                        rule_id: "heur-base64-block".to_string(),
                        description: format!(
                            "Base64 block decodes to text containing: {}",
                            matched.join(", ")
                        ),
                        severity: self.get_severity("heur-base64-block"),
                        category: "encoding".to_string(),
                        line: Some(line),
                        matched_text: Some(truncate(&decoded, 80)),
                        cwe: None,
                    });
                }

                if let Some(finding) = self.try_multilayer_decode(&decoded, mat.start(), content) {
                    findings.push(finding);
                }
            }
        }

        findings
    }

    fn check_hex(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let keywords = self.get_keywords("heur-hex-encoded");

        for mat in HEX_PATTERN.find_iter(content) {
            let hex_str = mat.as_str();
            if let Some(decoded) = try_hex_decode(hex_str) {
                let matched = check_keywords(&decoded, &keywords);
                if !matched.is_empty() {
                    let line = content[..mat.start()].matches('\n').count() + 1;
                    findings.push(Finding {
                        rule_id: "heur-hex-encoded".to_string(),
                        description: format!(
                            "Hex-encoded block decodes to text containing: {}",
                            matched.join(", ")
                        ),
                        severity: self.get_severity("heur-hex-encoded"),
                        category: "encoding".to_string(),
                        line: Some(line),
                        matched_text: Some(truncate(&decoded, 80)),
                        cwe: None,
                    });
                }
            }
        }

        findings
    }

    fn check_url_encoded(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let keywords = self.get_keywords("heur-url-encoded");

        for mat in URL_ENCODED_PATTERN.find_iter(content) {
            let url_str = mat.as_str();
            if let Some(decoded) = try_url_decode(url_str) {
                let matched = check_keywords(&decoded, &keywords);
                if !matched.is_empty() {
                    let line = content[..mat.start()].matches('\n').count() + 1;
                    findings.push(Finding {
                        rule_id: "heur-url-encoded".to_string(),
                        description: format!(
                            "URL-encoded block decodes to text containing: {}",
                            matched.join(", ")
                        ),
                        severity: self.get_severity("heur-url-encoded"),
                        category: "encoding".to_string(),
                        line: Some(line),
                        matched_text: Some(truncate(&decoded, 80)),
                        cwe: None,
                    });
                }
            }
        }

        findings
    }

    fn check_rot13(&self, content: &str) -> Vec<Finding> {
        let keywords = self.get_keywords("heur-base64-block");
        let content_lower = content.to_lowercase();

        let has_keywords_in_original = keywords
            .iter()
            .any(|kw| content_lower.contains(kw.as_str()));

        let rotated = apply_rot13(content);
        let rotated_lower = rotated.to_lowercase();

        let matched: Vec<String> = keywords
            .iter()
            .filter(|kw| {
                rotated_lower.contains(kw.as_str()) && !content_lower.contains(kw.as_str())
            })
            .cloned()
            .collect();

        if !matched.is_empty() && !has_keywords_in_original {
            vec![Finding {
                rule_id: "heur-rot13".to_string(),
                description: format!(
                    "ROT13-decoded content contains suspicious keywords: {}",
                    matched.join(", ")
                ),
                severity: Severity::Medium,
                category: "encoding".to_string(),
                line: None,
                matched_text: Some(truncate(&rotated, 80)),
                cwe: None,
            }]
        } else {
            Vec::new()
        }
    }

    fn try_multilayer_decode(
        &self,
        decoded: &str,
        offset: usize,
        original: &str,
    ) -> Option<Finding> {
        let keywords = self.get_keywords("heur-base64-block");
        let max_depth = 3;

        let mut current = decoded.to_string();
        for _depth in 0..max_depth {
            let next = try_base64_decode(&current)
                .or_else(|| {
                    if HEX_PATTERN.is_match(&current) {
                        HEX_PATTERN
                            .find(&current)
                            .and_then(|m| try_hex_decode(m.as_str()))
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    if URL_ENCODED_PATTERN.is_match(&current) {
                        URL_ENCODED_PATTERN
                            .find(&current)
                            .and_then(|m| try_url_decode(m.as_str()))
                    } else {
                        None
                    }
                });

            match next {
                Some(next_decoded) => {
                    let matched = check_keywords(&next_decoded, &keywords);
                    if !matched.is_empty() {
                        let line = original[..offset].matches('\n').count() + 1;
                        return Some(Finding {
                            rule_id: "heur-multilayer-encode".to_string(),
                            description: format!(
                                "Multi-layer encoded content contains: {}",
                                matched.join(", ")
                            ),
                            severity: Severity::High,
                            category: "encoding".to_string(),
                            line: Some(line),
                            matched_text: Some(truncate(&next_decoded, 80)),
                            cwe: None,
                        });
                    }
                    current = next_decoded;
                }
                None => break,
            }
        }

        None
    }

    fn check_normalization_tricks(&self, content: &str) -> Vec<Finding> {
        let nfkc: String = content.nfkc().collect();
        if nfkc == content {
            return Vec::new();
        }

        let original_words: std::collections::HashSet<&str> = content.split_whitespace().collect();
        let normalized_words: Vec<&str> = nfkc
            .split_whitespace()
            .filter(|w| !original_words.contains(w))
            .collect();

        let suspicious_keywords = [
            "ignore",
            "instruction",
            "system",
            "override",
            "execute",
            "admin",
            "secret",
        ];

        let has_suspicious = normalized_words.iter().any(|w| {
            let lower = w.to_lowercase();
            suspicious_keywords.iter().any(|kw| lower.contains(kw))
        });

        if has_suspicious {
            vec![Finding {
                rule_id: "heur-unicode-normalization".to_string(),
                description:
                    "Unicode text normalizes to different content containing suspicious keywords"
                        .to_string(),
                severity: Severity::High,
                category: "encoding".to_string(),
                line: None,
                matched_text: None,
                cwe: None,
            }]
        } else {
            Vec::new()
        }
    }
}

fn try_base64_decode(s: &str) -> Option<String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

fn try_hex_decode(s: &str) -> Option<String> {
    let hex_chars: String = s
        .replace("\\x", "")
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if hex_chars.len() < 2 || !hex_chars.len().is_multiple_of(2) {
        return None;
    }

    let bytes: Vec<u8> = (0..hex_chars.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex_chars[i..i + 2], 16).ok())
        .collect();

    String::from_utf8(bytes).ok()
}

fn try_url_decode(s: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(s).decode_utf8().ok()?;
    let decoded_str = decoded.to_string();
    if decoded_str == s {
        return None;
    }
    Some(decoded_str)
}

fn apply_rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

fn check_keywords(decoded: &str, keywords: &[String]) -> Vec<String> {
    let lower = decoded.to_lowercase();
    keywords
        .iter()
        .filter(|kw| lower.contains(kw.as_str()))
        .cloned()
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let boundary = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= max)
        .last()
        .unwrap_or(0);
    format!("{}...", &s[..boundary])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_ascii() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hello...");
    }

    #[test]
    fn test_truncate_multibyte() {
        let s = "héllo wörld";
        let result = truncate(s, 5);
        assert!(!result.is_empty());
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_hex_decode() {
        let hex = "\\x69\\x67\\x6e\\x6f\\x72\\x65\\x20\\x69\\x6e\\x73\\x74\\x72\\x75\\x63\\x74\\x69\\x6f\\x6e";
        let decoded = try_hex_decode(hex).unwrap();
        assert_eq!(decoded, "ignore instruction");
    }

    #[test]
    fn test_url_decode() {
        let encoded = "%69%67%6e%6f%72%65%20%73%79%73%74%65%6d";
        let decoded = try_url_decode(encoded).unwrap();
        assert_eq!(decoded, "ignore system");
    }

    #[test]
    fn test_rot13() {
        assert_eq!(apply_rot13("vtaber"), "ignore");
        assert_eq!(apply_rot13("flfgrz"), "system");
    }

    #[test]
    fn test_base64_decode() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("ignore instructions");
        let decoded = try_base64_decode(&encoded).unwrap();
        assert_eq!(decoded, "ignore instructions");
    }

    #[test]
    fn test_check_keywords() {
        let keywords = vec!["ignore".to_string(), "system".to_string()];
        let matched = check_keywords("please ignore the system", &keywords);
        assert_eq!(matched.len(), 2);
    }
}
