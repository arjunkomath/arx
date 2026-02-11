use std::collections::HashSet;
use std::path::Path;

pub struct Allowlist {
    allowed_rule_ids: HashSet<String>,
    ignored_paths: Vec<glob::Pattern>,
}

impl Allowlist {
    pub fn new(allowed_rules: &[String], ignored_paths: &[String]) -> Self {
        let allowed_rule_ids = allowed_rules.iter().cloned().collect();
        let ignored_paths = ignored_paths
            .iter()
            .filter_map(|p| match glob::Pattern::new(p) {
                Ok(pat) => Some(pat),
                Err(e) => {
                    eprintln!("arx: warning: invalid glob pattern '{}': {e}", p);
                    None
                }
            })
            .collect();

        Self {
            allowed_rule_ids,
            ignored_paths,
        }
    }

    #[allow(dead_code)]
    pub fn empty() -> Self {
        Self {
            allowed_rule_ids: HashSet::new(),
            ignored_paths: Vec::new(),
        }
    }

    pub fn is_rule_allowed(&self, rule_id: &str) -> bool {
        self.allowed_rule_ids.contains(rule_id)
    }

    pub fn is_path_ignored(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.ignored_paths.iter().any(|p| p.matches(&path_str))
    }

    pub fn has_inline_allow(line: &str) -> bool {
        line.contains("arx:allow")
    }
}
