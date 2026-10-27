use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: String,
    pub severity: Severity,
    pub pattern_name: String,
    pub match_excerpt: String,
}

struct PatternDef {
    name: &'static str,
    category: &'static str,
    severity: Severity,
    regex: Regex,
}

pub struct PromptInjectScanner {
    patterns: Vec<PatternDef>,
}

impl Default for PromptInjectScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptInjectScanner {
    pub fn new() -> Self {
        let pattern_specs: Vec<(&str, &str, Severity, &str)> = vec![
            (
                "ignore_previous",
                "instruction_override",
                Severity::High,
                r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(the above|previous|prior|earlier)\s+(instructions?|prompts?|rules?|directives?)\b",
            ),
            (
                "ignore_above_broad",
                "instruction_override",
                Severity::High,
                r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(the above|previous|prior|earlier)\b",
            ),
            (
                "new_task",
                "instruction_override",
                Severity::Medium,
                r"(?i)\b(your\s+new\s+task\s+is|you\s+must\s+now|disregard\s+everything)\b",
            ),
            (
                "role_confusion",
                "role_confusion",
                Severity::High,
                r"(?i)\b(you\s+are\s+now|pretend\s+to\s+be|from\s+now\s+on\s+respond\s+as)\s+[A-Za-z0-9_-]+\b",
            ),
            (
                "dan_jailbreak",
                "capability_jailbreak",
                Severity::High,
                r"(?i)\b(DAN\s+mode|jailbreak|developer\s+mode|unrestricted\s+AI|no\s+restrictions)\b",
            ),
            (
                "exfil_credentials",
                "exfiltration",
                Severity::High,
                r"(?i)\b(exfiltrate|id_rsa|\.env|dump\s+credentials|system\s+prompt|send\s+to\s+evil)\b",
            ),
            (
                "tool_misuse",
                "tool_misuse",
                Severity::High,
                r"(?i)\b(curl\s+-X|curl\s+.*http|wget\s+.*http|rm\s+-rf\s+/)\b",
            ),
        ];

        let mut compiled = Vec::new();
        for (name, category, severity, pat) in pattern_specs {
            if let Ok(re) = Regex::new(pat) {
                compiled.push(PatternDef {
                    name,
                    category,
                    severity,
                    regex: re,
                });
            }
        }

        Self { patterns: compiled }
    }

    pub fn scan(&self, text: &str) -> Vec<Finding> {
        // Homoglyph-fold before matching: Cyrillic/Greek lookalikes
        // (і→i, о→o, …) and zero-width characters are a classic evasion of
        // ASCII regexes — the synthetic dataset itself ships homoglyph
        // attacks, so the scanner must fold them.
        let folded = fold_lookalikes(text);
        let mut findings = Vec::new();

        for p in &self.patterns {
            if let Some(mat) = p.regex.find(&folded) {
                findings.push(Finding {
                    category: p.category.to_string(),
                    severity: p.severity,
                    pattern_name: p.name.to_string(),
                    match_excerpt: mat.as_str().to_string(),
                });
            }
        }

        findings
    }

    /// LLM-safe findings digest: pattern names and categories only. Never
    /// embed `match_excerpt` into agent-facing context — the raw excerpt is
    /// attacker text and re-delivering it verbatim is itself an injection
    /// channel (RT-13).
    pub fn summarize_findings(findings: &[Finding]) -> String {
        findings
            .iter()
            .map(|f| format!("{}[{}]", f.pattern_name, f.category))
            .collect::<Vec<_>>()
            .join(", ")
    }
    
    /// Rule catalogue `(pattern_name, category, severity)` for every active
    /// pattern. Used by the SARIF exporter to describe the tool's rules.
    pub fn rules(&self) -> Vec<(&'static str, &'static str, Severity)> {
        self.patterns
            .iter()
            .map(|p| (p.name, p.category, p.severity))
            .collect()
    }

    /// Like `scan`, but reports every match with its 1-indexed line number.
    /// Folding only drops zero-width chars, never newlines, so line numbers
    /// computed on the folded text match the original file.
    pub fn scan_located(&self, text: &str) -> Vec<(usize, Finding)> {
        let folded = fold_lookalikes(text);
        let line_starts: Vec<usize> = std::iter::once(0)
            .chain(folded.match_indices('\n').map(|(i, _)| i + 1))
            .collect();
        let line_of = |offset: usize| line_starts.partition_point(|&s| s <= offset);

        let mut out = Vec::new();
        for p in &self.patterns {
            for mat in p.regex.find_iter(&folded) {
                out.push((
                    line_of(mat.start()),
                    Finding {
                        category: p.category.to_string(),
                        severity: p.severity,
                        pattern_name: p.name.to_string(),
                        match_excerpt: mat.as_str().to_string(),
                    },
                ));
            }
        }
        out.sort_by_key(|(line, _)| *line);
        out
    }
}

/// Folds Unicode confusables to their ASCII lookalikes and strips
/// zero-width characters, so `іgnore` (Cyrillic і) matches `ignore`-style
/// patterns. Non-confusable text passes through unchanged.
fn fold_lookalikes(text: &str) -> String {
    text.chars()
        .filter_map(|c| match c {
            // Zero-width / BOM: invisible payload stitching.
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' => None,
            // Cyrillic lookalikes.
            'а' => Some('a'), 'е' => Some('e'), 'о' => Some('o'),
            'р' => Some('p'), 'с' => Some('c'), 'у' => Some('y'),
            'х' => Some('x'), 'і' => Some('i'), 'ѕ' => Some('s'),
            'ј' => Some('j'), 'һ' => Some('h'), 'ԛ' => Some('q'),
            'ԝ' => Some('w'), 'Ь' => Some('b'), 'І' => Some('I'),
            'А' => Some('A'), 'Е' => Some('E'), 'О' => Some('O'),
            'Р' => Some('P'), 'С' => Some('C'), 'Х' => Some('X'),
            'В' => Some('B'), 'М' => Some('M'), 'Т' => Some('T'),
            // Greek lookalikes.
            'ο' => Some('o'), 'α' => Some('a'), 'ε' => Some('e'),
            'ρ' => Some('p'), 'ν' => Some('v'), 'ι' => Some('i'),
            'Ο' => Some('O'), 'Α' => Some('A'), 'Ε' => Some('E'),
            'Ρ' => Some('P'), 'Ι' => Some('I'), 'Τ' => Some('T'),
            other => Some(other),
        })
        .collect()
}
