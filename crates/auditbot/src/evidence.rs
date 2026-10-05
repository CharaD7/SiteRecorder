//! Capturing the source and graph context behind a hotspot.
//!
//! A report without evidence is an essay. Everything here carries provenance —
//! where each fact came from — so a reviewer can open the same file and see the
//! same thing the bot saw.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// What kind of artifact an [`Evidence`] item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Source of the function under review.
    Source,
    /// A compiled artifact or bytecode blob.
    Bytecode,
    /// A compiler or analyser diagnostic.
    Diagnostic,
    /// Published text from a prior audit or the program's own docs.
    PublishedDisclosure,
}

impl EvidenceKind {
    /// Published disclosures cannot support a novel finding — they are how
    /// [`crate::dedupe`] learns the bug is already known.
    pub fn is_prior_disclosure(self) -> bool {
        matches!(self, EvidenceKind::PublishedDisclosure)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::Source => "source",
            EvidenceKind::Bytecode => "bytecode",
            EvidenceKind::Diagnostic => "diagnostic",
            EvidenceKind::PublishedDisclosure => "published_disclosure",
        }
    }
}

/// One piece of evidence, with its origin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Evidence {
    pub kind: EvidenceKind,
    /// Where this came from: a path, a command, or a URL.
    pub source: String,
    /// Optional line range within `source`.
    pub start_line: Option<u64>,
    pub end_line: Option<u64>,
    pub content: String,
}

impl Evidence {
    pub fn source(source: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            kind: EvidenceKind::Source,
            source: source.into(),
            start_line: None,
            end_line: None,
            content: content.into(),
        }
    }

    pub fn disclosure(source: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            kind: EvidenceKind::PublishedDisclosure,
            source: source.into(),
            start_line: None,
            end_line: None,
            content: content.into(),
        }
    }

    pub fn with_lines(mut self, start: u64, end: u64) -> Self {
        self.start_line = Some(start);
        self.end_line = Some(end);
        self
    }

    pub fn with_kind(mut self, kind: EvidenceKind) -> Self {
        self.kind = kind;
        self
    }

    /// One-line provenance for a report appendix.
    pub fn cite(&self) -> String {
        match (self.start_line, self.end_line) {
            (Some(s), Some(e)) if s != e => format!("{}:{}-{}", self.source, s, e),
            (Some(s), _) => format!("{}:{}", self.source, s),
            _ => self.source.clone(),
        }
    }
}

/// What to capture for a target.
#[derive(Debug, Clone)]
pub struct SnapshotRequest {
    pub target: crate::HuntTarget,
    /// Root of the fetched source tree (ChainScope writes `.chainsource/`).
    pub source_root: PathBuf,
    /// Lines of context either side of the hotspot.
    pub context_lines: usize,
}

impl SnapshotRequest {
    pub fn new(target: crate::HuntTarget, source_root: impl Into<PathBuf>) -> Self {
        Self {
            target,
            source_root: source_root.into(),
            context_lines: 40,
        }
    }
}

/// Capture the source surrounding a hotspot.
///
/// ChainScope's `file` is a composite path like `1/0x4d73.../Address.sol`, so
/// the reader matches on the trailing filename rather than trusting an exact
/// path — the address segment is volatile between runs.
pub fn capture(req: &SnapshotRequest) -> Result<Vec<Evidence>, SnapshotError> {
    if req.target.function.is_empty() {
        return Err(SnapshotError::NoFunction);
    }

    let path = resolve_source(&req.source_root, &req.target.file)
        .ok_or_else(|| SnapshotError::NotFound(req.target.file.clone().into()))?;

    let text = std::fs::read_to_string(&path).map_err(|source| SnapshotError::Read {
        path: path.clone(),
        source,
    })?;

    let lines: Vec<&str> = text.lines().collect();
    let needle = req.target.function.as_str();

    let Some(start) = find_function(&lines, needle, req.target.line) else {
        // No declaration found: hand back the file whole rather than nothing,
        // so the reviewer can see the whole context instead of an empty claim.
        return Ok(vec![Evidence::source(path.display().to_string(), text)]);
    };

    let ctx = req.context_lines;
    let from = start.saturating_sub(ctx);
    let to = (start + ctx).min(lines.len());
    let snippet = lines[from..to].join("\n");

    Ok(vec![Evidence {
        kind: EvidenceKind::Source,
        source: path.display().to_string(),
        start_line: Some(from as u64 + 1),
        end_line: Some(to as u64),
        content: snippet,
    }])
}

/// Find a path under `root` whose tail matches `wanted`.
fn resolve_source(root: &Path, wanted: &str) -> Option<PathBuf> {
    let direct = root.join(wanted);
    if direct.exists() {
        return Some(direct);
    }
    let leaf = wanted.rsplit('/').next()?;
    walk(root, 0).into_iter().find(|p| p.ends_with(leaf))
}

fn walk(dir: &Path, depth: usize) -> Vec<PathBuf> {
    if depth > 8 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p, depth + 1));
        } else if p.extension().is_some_and(|x| x == "sol") {
            out.push(p);
        }
    }
    out
}

/// Index of the line declaring `needle`, nearest to `hint` when given.
#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let nested = d.path().join("1/0xabc");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("Ownable.sol"),
            "pragma solidity ^0.8.13;\n\
             contract Ownable {\n\
             \n  \
                 address owner;\n\
             \n  \
                 function owner() public view returns (address) { return owner; }\n\
             }\n",
        )
        .unwrap();
        d
    }

    #[test]
    fn captures_the_function_with_context() {
        let d = tree();
        let mut target = crate::HuntTarget::new("layerzero", "owner", "1/0xabc/Ownable.sol");
        target.line = Some(6);
        let mut req = SnapshotRequest::new(target, d.path());
        req.context_lines = 3;
        let got = capture(&req).expect("should capture");
        assert_eq!(got.len(), 1);
        assert!(
            got[0].content.contains("function owner()"),
            "{}",
            got[0].content
        );
        assert!(got[0].start_line.is_some());
        assert!(got[0].cite().contains("Ownable.sol:"));
    }

    #[test]
    fn volatile_address_segment_still_resolves() {
        let d = tree();
        let target = crate::HuntTarget::new("layerzero", "owner", "1/0xdeadbeef/Ownable.sol");
        let got = capture(&SnapshotRequest::new(target, d.path())).expect("should resolve by leaf");
        assert!(got[0].content.contains("function owner()"));
    }

    #[test]
    fn missing_file_is_an_error_not_empty_evidence() {
        let d = tree();
        let target = crate::HuntTarget::new("layerzero", "owner", "Nope.sol");
        let err = capture(&SnapshotRequest::new(target, d.path())).unwrap_err();
        assert!(matches!(err, SnapshotError::NotFound(_)));
    }

    #[test]
    fn absent_function_returns_the_whole_file_rather_than_nothing() {
        let d = tree();
        let target = crate::HuntTarget::new("layerzero", "notHere", "1/0xabc/Ownable.sol");
        let got = capture(&SnapshotRequest::new(target, d.path())).expect("returns file");
        assert_eq!(got.len(), 1);
        assert!(got[0].content.contains("contract Ownable"));
    }

    #[test]
    fn disclosure_evidence_is_marked_as_prior() {
        let e = Evidence::disclosure("Halborn 2024", "previously reported");
        assert!(e.kind.is_prior_disclosure());
        assert!(!Evidence::source("a.sol", "x").kind.is_prior_disclosure());
    }
}
fn find_function(lines: &[&str], needle: &str, hint: Option<u64>) -> Option<usize> {
    let decls: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| {
            let l = l.trim();
            l.contains(needle)
                && (l.contains("function")
                    || l.contains("modifier")
                    || l.contains("contract")
                    || l.contains("error"))
        })
        .map(|(i, _)| i)
        .collect();

    if decls.is_empty() {
        return None;
    }
    match hint {
        None => decls.first().copied(),
        Some(h) => decls
            .into_iter()
            .min_by_key(|i| (*i as u64).abs_diff(h.saturating_sub(1))),
    }
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("source file not found: {0}")]
    NotFound(PathBuf),
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the target names no function to locate")]
    NoFunction,
}
