//! SARIF 2.1.0 export for Ethos containment-wall findings.
//! RT-13: `match_excerpt` is attacker-controlled text and is never written
//! into SARIF output. Only rule ids and categories are emitted.

use super::promptinject::{Finding, PromptInjectScanner, Severity};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", "dist", ".ethos", ".ethos_snapshots"];

#[derive(Debug, Clone)]
pub struct ScanHit {
    pub path: String, // relative to scan root, '/'-separated
    pub line: usize,  // 1-indexed
    pub finding: Finding,
}

pub fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

// GitHub uses this 0-10 score to label alerts Critical/High/Medium/Low.
fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "8.0",
        Severity::Medium => "5.0",
        Severity::Low => "2.0",
    }
}

pub fn to_sarif(scanner: &PromptInjectScanner, hits: &[ScanHit]) -> Value {
    let rules: Vec<Value> = scanner
        .rules()
        .into_iter()
        .map(|(name, category, severity)| {
            json!({
                "id": name,
                "name": name,
                "shortDescription": { "text": format!("Prompt-injection pattern '{}' ({})", name, category) },
                "fullDescription": { "text": format!(
                    "Text matching the '{}' pattern in the '{}' family. Content like this can hijack \
                     an AI coding agent that reads the file (indirect prompt injection).",
                    name, category) },
                "defaultConfiguration": { "level": sarif_level(severity) },
                "properties": {
                    "category": category,
                    "security-severity": security_severity(severity),
                    "tags": ["security", "prompt-injection", category]
                }
            })
        })
        .collect();

    let results: Vec<Value> = hits
        .iter()
        .map(|h| {
            let f = &h.finding;
            json!({
                "ruleId": f.pattern_name,
                "level": sarif_level(f.severity),
                "message": { "text": format!(
                    "Possible prompt injection: matched '{}' ({}). An agent reading this file could be hijacked.",
                    f.pattern_name, f.category) },
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": h.path },
                    "region": { "startLine": h.line }
                }}],
                "properties": { "category": f.category }
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "Ethos PromptInjectScanner",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/xyzmr114/ds440-ethos",
                "rules": rules
            }},
            "results": results
        }]
    })
}

/// Recursively scans `root`, skipping build/VCS dirs, `excludes` (relative
/// to root), symlinks, files over 1 MB, and binary files.
pub fn scan_directory(
    scanner: &PromptInjectScanner,
    root: &Path,
    excludes: &[PathBuf],
) -> std::io::Result<Vec<ScanHit>> {
    let mut hits = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            if excludes.iter().any(|ex| rel.starts_with(ex)) {
                continue;
            }
            let ftype = entry.file_type()?;
            if ftype.is_symlink() {
                continue;
            }
            if ftype.is_dir() {
                if !SKIP_DIRS.iter().any(|s| entry.file_name() == *s) {
                    stack.push(path);
                }
                continue;
            }
            if !ftype.is_file() || entry.metadata()?.len() > MAX_FILE_BYTES {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let rel_str = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            for (line, finding) in scanner.scan_located(&text) {
                hits.push(ScanHit { path: rel_str.clone(), line, finding });
            }
        }
    }
    hits.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));
    Ok(hits)
}
