//! SARIF 2.1.0 and plain-JSON export for Ethos containment-wall findings.
//! RT-13: attacker-controlled text is never written into SARIF or JSON output
//! in readable form. By default only rule ids and categories are emitted;
//! `--excerpt hash|encrypt` adds a keyed fingerprint and, for `encrypt`, an
//! AES-256-GCM ciphertext of the source line (see `ExcerptProtector`).

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

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

/// Plain JSON report: a flat, scriptable alternative to SARIF for notebooks,
/// `jq` and the paper's analysis scripts. Same RT-13 rule as SARIF — rule ids,
/// categories and locations only, never the matched attacker text.
pub fn to_json(hits: &[ScanHit]) -> Value {
    let count = |s: Severity| hits.iter().filter(|h| h.finding.severity == s).count();
    let files: std::collections::BTreeSet<&str> = hits.iter().map(|h| h.path.as_str()).collect();

    let findings: Vec<Value> = hits
        .iter()
        .map(|h| {
            json!({
                "path": h.path,
                "line": h.line,
                "rule_id": h.finding.pattern_name,
                "category": h.finding.category,
                "severity": severity_name(h.finding.severity),
            })
        })
        .collect();

    json!({
        "tool": "ethos-scan",
        "version": env!("CARGO_PKG_VERSION"),
        "summary": {
            "total": hits.len(),
            "files_with_findings": files.len(),
            "high": count(Severity::High),
            "medium": count(Severity::Medium),
            "low": count(Severity::Low),
        },
        "findings": findings,
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

// ---------------------------------------------------------------------------
// Protected excerpts (--excerpt hash | encrypt)
// ---------------------------------------------------------------------------

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Env var holding the secret used to fingerprint and encrypt excerpts.
pub const EXCERPT_KEY_ENV: &str = "ETHOS_SCAN_KEY";
/// Minimum secret length; short secrets make the HMAC guessable.
pub const MIN_KEY_LEN: usize = 16;
/// Longest source line kept per finding (minified files can be one 1 MB line).
pub const MAX_EXCERPT_CHARS: usize = 2000;
const CIPHERTEXT_PREFIX: &str = "v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExcerptMode {
    /// No excerpt data at all (default; RT-13 original behaviour).
    None,
    /// Keyed HMAC-SHA256 fingerprint only. Irreversible.
    Hash,
    /// Fingerprint plus AES-256-GCM ciphertext of the source line.
    Encrypt,
}

/// Holds keys derived from the operator secret. The secret itself is never
/// written to any report; two independent keys are derived so the
/// fingerprint and the ciphertext never share key material.
pub struct ExcerptProtector {
    mac_key: [u8; 32],
    enc_key: [u8; 32],
}

impl ExcerptProtector {
    pub fn from_secret(secret: &str) -> anyhow::Result<Self> {
        if secret.chars().count() < MIN_KEY_LEN {
            anyhow::bail!(
                "{} must be at least {} characters (got {})",
                EXCERPT_KEY_ENV,
                MIN_KEY_LEN,
                secret.chars().count()
            );
        }
        let derive = |label: &[u8]| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(b"ethos-scan-excerpt/v1/");
            h.update(label);
            h.update(secret.as_bytes());
            h.finalize().into()
        };
        Ok(Self { mac_key: derive(b"mac"), enc_key: derive(b"enc") })
    }

    /// Reads the secret from `ETHOS_SCAN_KEY`.
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var(EXCERPT_KEY_ENV) {
            Ok(v) if !v.is_empty() => Self::from_secret(&v),
            _ => anyhow::bail!(
                "--excerpt hash/encrypt needs a secret in the {} environment variable \
                 (refusing to write excerpts without one)",
                EXCERPT_KEY_ENV
            ),
        }
    }

    /// Keyed fingerprint (hex HMAC-SHA256). Stable for the same text and key,
    /// so duplicates can be matched across files and runs.
    ///
    /// The fingerprint depends on `ETHOS_SCAN_KEY`. It is also written to SARIF
    /// `partialFingerprints`, which GitHub Code Scanning uses to track alerts,
    /// so ROTATING THE KEY closes and reopens every alert once. Keep the CI key
    /// stable, and expect one round of alert churn if it is ever changed.
    pub fn fingerprint(&self, text: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.mac_key)
            .expect("HMAC accepts any key length");
        mac.update(text.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// AES-256-GCM with a fresh random 96-bit nonce. Output: `v1:` + hex(nonce || ciphertext+tag).
    pub fn encrypt(&self, text: &str) -> String {
        let cipher = Aes256Gcm::new_from_slice(&self.enc_key).expect("32-byte key");
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, text.as_bytes())
            .expect("AES-GCM encryption of an in-memory buffer cannot fail");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        format!("{}{}", CIPHERTEXT_PREFIX, hex::encode(out))
    }

    /// Reverses `encrypt`. Fails on a wrong key or any tampering (GCM tag check).
    pub fn decrypt(&self, token: &str) -> anyhow::Result<String> {
        let body = token
            .strip_prefix(CIPHERTEXT_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("unknown ciphertext format"))?;
        let bytes = hex::decode(body)?;
        if bytes.len() < 12 + 16 {
            anyhow::bail!("ciphertext too short");
        }
        let (nonce, ct) = bytes.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&self.enc_key).expect("32-byte key");
        let plain = cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| anyhow::anyhow!("decryption failed: wrong {} or tampered report", EXCERPT_KEY_ENV))?;
        Ok(String::from_utf8(plain)?)
    }
}

/// Original (un-folded) source line for each hit, so homoglyphs and
/// zero-width characters survive as evidence. Files are read once each.
pub fn source_lines(root: &Path, hits: &[ScanHit]) -> Vec<String> {
    let mut cache: std::collections::HashMap<&str, Vec<String>> = std::collections::HashMap::new();
    hits.iter()
        .map(|h| {
            let lines = cache.entry(h.path.as_str()).or_insert_with(|| {
                std::fs::read_to_string(root.join(&h.path))
                    .map(|t| t.lines().map(str::to_string).collect())
                    .unwrap_or_default()
            });
            lines.get(h.line.saturating_sub(1)).cloned().unwrap_or_default()
        })
        .collect()
}

/// Builds the excerpt object for one finding. Never contains readable text.
fn excerpt_value(mode: ExcerptMode, p: &ExcerptProtector, line: &str) -> Value {
    let truncated = line.chars().count() > MAX_EXCERPT_CHARS;
    let kept: String = line.chars().take(MAX_EXCERPT_CHARS).collect();
    let mut v = json!({
        "scheme": "hmac-sha256",
        "fingerprint": p.fingerprint(&kept),
        "truncated": truncated,
    });
    if mode == ExcerptMode::Encrypt {
        v["scheme"] = json!("hmac-sha256+aes-256-gcm");
        v["ciphertext"] = json!(p.encrypt(&kept));
    }
    v
}

/// Adds protected excerpts to a report produced by `to_sarif` or `to_json`.
/// `lines[i]` must be the source line for `hits[i]` (see `source_lines`).
/// SARIF: `result.properties.ethosExcerpt` plus `partialFingerprints`
/// (which GitHub uses to de-duplicate alerts). JSON: `finding.excerpt`.
/// Nothing is placed in `message.text`, so no UI ever renders it.
pub fn add_excerpts(report: &mut Value, mode: ExcerptMode, p: &ExcerptProtector, lines: &[String]) {
    if mode == ExcerptMode::None {
        return;
    }
    // pointer_mut, not indexing: IndexMut panics on a missing path, and a
    // JSON-format report has no "runs".
    if let Some(results) = report.pointer_mut("/runs/0/results").and_then(Value::as_array_mut) {
        for (r, line) in results.iter_mut().zip(lines) {
            let ex = excerpt_value(mode, p, line);
            r["partialFingerprints"] = json!({ "ethosExcerpt/v1": ex["fingerprint"].clone() });
            r["properties"]["ethosExcerpt"] = ex;
        }
    } else if let Some(findings) = report.pointer_mut("/findings").and_then(Value::as_array_mut) {
        for (f, line) in findings.iter_mut().zip(lines) {
            f["excerpt"] = excerpt_value(mode, p, line);
        }
    }
}

/// One excerpt from a report. `text` is `Err` when that single entry could
/// not be decrypted (wrong key, tampering, corruption); the others are still
/// returned, so one bad entry does not hide the rest.
#[derive(Debug, Clone)]
pub struct RevealedExcerpt {
    pub path: String,
    pub line: u64,
    pub rule_id: String,
    pub text: Result<String, String>,
}

/// Decrypts every excerpt in a SARIF or JSON report produced with `--excerpt encrypt`.
/// Fails only if the document is not an Ethos report; per-entry decryption
/// failures are reported in `RevealedExcerpt::text`.
pub fn reveal_excerpts(report: &Value, p: &ExcerptProtector) -> anyhow::Result<Vec<RevealedExcerpt>> {
    let mut out = Vec::new();
    if let Some(results) = report["runs"][0]["results"].as_array() {
        for r in results {
            if let Some(ct) = r["properties"]["ethosExcerpt"]["ciphertext"].as_str() {
                let loc = &r["locations"][0]["physicalLocation"];
                out.push(RevealedExcerpt {
                    path: loc["artifactLocation"]["uri"].as_str().unwrap_or("?").to_string(),
                    line: loc["region"]["startLine"].as_u64().unwrap_or(0),
                    rule_id: r["ruleId"].as_str().unwrap_or("?").to_string(),
                    text: p.decrypt(ct).map_err(|e| e.to_string()),
                });
            }
        }
    } else if let Some(findings) = report["findings"].as_array() {
        for f in findings {
            if let Some(ct) = f["excerpt"]["ciphertext"].as_str() {
                out.push(RevealedExcerpt {
                    path: f["path"].as_str().unwrap_or("?").to_string(),
                    line: f["line"].as_u64().unwrap_or(0),
                    rule_id: f["rule_id"].as_str().unwrap_or("?").to_string(),
                    text: p.decrypt(ct).map_err(|e| e.to_string()),
                });
            }
        }
    } else {
        anyhow::bail!("not an Ethos SARIF or JSON scan report");
    }
    Ok(out)
}

/// True for characters that render as nothing (or reorder text) in a
/// terminal, so a reader cannot see them: zero-width and joiner characters,
/// all bidi controls (embeddings, overrides AND isolates), invisible math
/// operators, Unicode tag characters (used to smuggle hidden ASCII
/// instructions), variation selectors and similar fillers.
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}'                    // soft hyphen
        | '\u{034F}'                  // combining grapheme joiner
        | '\u{061C}'                  // Arabic letter mark (bidi)
        | '\u{115F}' | '\u{1160}'     // Hangul fillers
        | '\u{17B4}' | '\u{17B5}'     // Khmer inherent vowels
        | '\u{180B}'..='\u{180F}'     // Mongolian variation selectors / vowel separator
        | '\u{200B}'..='\u{200F}'     // zero-width space/joiners, LRM, RLM
        | '\u{202A}'..='\u{202E}'     // bidi embeddings and overrides
        | '\u{2060}'..='\u{2064}'     // word joiner, invisible math operators
        | '\u{2066}'..='\u{2069}'     // bidi isolates (LRI, RLI, FSI, PDI)
        | '\u{206A}'..='\u{206F}'     // deprecated format characters
        | '\u{3164}'                  // Hangul filler
        | '\u{FE00}'..='\u{FE0F}'     // variation selectors
        | '\u{FEFF}'                  // zero-width no-break space / BOM
        | '\u{FFA0}'                  // halfwidth Hangul filler
        | '\u{FFF9}'..='\u{FFFB}'     // interlinear annotation controls
        | '\u{1D173}'..='\u{1D17A}'   // musical format characters
        | '\u{E0000}'..='\u{E007F}'   // Unicode tag characters (hidden ASCII)
        | '\u{E0100}'..='\u{E01EF}'   // variation selectors supplement
    )
}

/// Makes untrusted text safe to print: control characters (terminal escape
/// sequences) and invisible characters are shown as `\u{..}` instead of being
/// interpreted, so a payload cannot drive the terminal and hidden zero-width,
/// bidi or tag-character smuggling stays visible as evidence. Use it for every
/// attacker-influenced field, including file paths.
pub fn escape_for_terminal(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\t' => "\\t".to_string(),
            c if c.is_control() || is_invisible(c) => format!("\\u{{{:04x}}}", c as u32),
            c => c.to_string(),
        })
        .collect()
}
