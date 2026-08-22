//! #7233: no comment in the dataplane may claim the shim passes transit to the
//! kernel when a heartbeat (or ctrl) is absent. It DROPS.
//!
//! Two comment blocks asserted the opposite and both were stale:
//!
//!   * `userspace-dp/src/afxdp/mod.rs` documented `HEARTBEAT_GRACE_PERIOD_NS`
//!     with "the XDP shim sees no heartbeat -> XDP_PASS -> kernel forwards
//!     packets". The constant was `#[allow(dead_code)]` with exactly one grep
//!     hit — its own declaration — so it documented a design that was never
//!     wired.
//!   * `userspace-dp/src/server/helpers/status.rs` said queues awaiting XSK RQ
//!     bootstrap "get XDP_PASS until they bootstrap naturally", and described
//!     the old deadlock as "ctrl=0 -> XDP_PASS".
//!
//! At HEAD every one of those paths reaches `drop_degraded_transit`, which
//! returns `XDP_DROP`; only `pass_local_control` admits proven local/control
//! traffic. A comment that points the other way is worse than no comment: it
//! tells a reader the box fails OPEN when it fails CLOSED, which invites either
//! a compensating control that is not needed or — the dangerous one — treating
//! a genuine fail-open report as expected behaviour.
//!
//! FAIL-ON-REVERT: reintroduce `HEARTBEAT_GRACE_PERIOD_NS`, or write a comment
//! pairing heartbeat/ctrl-disabled with XDP_PASS, and this test goes RED.
//!
//! GRANULARITY, and what it costs — measured, not assumed. Judgement is per
//! contiguous comment BLOCK, so an unrelated `XDP_PASS` sentence FUSED into a
//! block that also mentions the heartbeat trips the guard. Separated by a blank
//! line, or by any code, it does not (both verified by mutation). That is the
//! over-strict direction — it can only deny, never admit a fail-open claim —
//! and the escape hatch below covers the fused case deliberately.
//!
//! ESCAPE HATCH, deliberately narrow: a comment that needs to mention both may
//! phrase the verdict as a denial (`not XDP_PASS`, `rather than XDP_PASS`,
//! `instead of XDP_PASS`), or carry the literal marker `#7233-ok`. The guard is
//! intentionally over-strict rather than clever — it never has to decide
//! whether a sentence is asserting or correcting, and a maintainer who really
//! means it has a greppable way to say so.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("userspace-dp should live directly under the repo root")
        .to_path_buf()
}

/// Every `.rs` file under `dir`, recursively.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read source root {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

/// The two crates whose comments describe shim behaviour.
fn source_roots(root: &Path) -> Vec<PathBuf> {
    vec![
        root.join("userspace-dp/src"),
        root.join("userspace-xdp/src"),
    ]
}

fn comment_body(line: &str) -> Option<&str> {
    let t = line.trim_start();
    for prefix in ["//!", "///", "//"] {
        if let Some(rest) = t.strip_prefix(prefix) {
            return Some(rest);
        }
    }
    None
}

/// One contiguous run of comment lines, with the 1-based line number it starts
/// at.
///
/// Blocks, not lines, are the unit of judgement — and that distinction is the
/// whole point rather than a refinement. The status.rs defect this guard exists
/// to catch spelled the claim across TWO lines:
///
///   // populated). The per-queue xsk_rx_confirmed heartbeat gating handles
///   // queues whose XSK RQ hasn't been bootstrapped yet — those get XDP_PASS
///
/// "heartbeat" on one line, "XDP_PASS" on the next. A per-line guard passes
/// that cleanly, which means the first version of this test was satisfiable by
/// the very bug it was written for. It was caught by mutating the ORIGINAL
/// comment back in and watching the guard stay green.
fn comment_blocks(body: &str) -> Vec<(usize, String)> {
    let mut blocks = Vec::new();
    let mut current: Option<(usize, String)> = None;
    for (i, line) in body.lines().enumerate() {
        match comment_body(line) {
            Some(text) => match current {
                Some((_, ref mut acc)) => {
                    acc.push(' ');
                    acc.push_str(text);
                }
                None => current = Some((i + 1, text.to_string())),
            },
            None => {
                if let Some(block) = current.take() {
                    blocks.push(block);
                }
            }
        }
    }
    if let Some(block) = current.take() {
        blocks.push(block);
    }
    blocks
}

#[test]
fn no_comment_claims_the_shim_passes_transit_when_the_heartbeat_is_absent() {
    let root = repo_root();
    let mut blocks_scanned = 0usize;
    let mut offenders = Vec::new();

    for source_root in source_roots(&root) {
        let files = rust_sources(&source_root);
        // Non-vacuous: an empty or moved source root must FAIL, not silently
        // certify nothing. This is the property that keeps a guard from going
        // quiet when the thing it reads is refactored away.
        assert!(
            !files.is_empty(),
            "{} yielded no .rs files — the enumeration source moved and this \
             guard would pass vacuously",
            source_root.display()
        );
        for file in files {
            // Skip this guard's own text, which necessarily quotes the pattern.
            if file
                .file_name()
                .is_some_and(|n| n == "heartbeat_failclosed_doc_guard.rs")
            {
                continue;
            }
            let body = fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
            for (start, block) in comment_blocks(&body) {
                blocks_scanned += 1;
                if !block.contains("XDP_PASS") {
                    continue;
                }
                let lower = block.to_ascii_lowercase();
                let mentions_gate = lower.contains("heartbeat")
                    || lower.contains("ctrl=0")
                    || lower.contains("ctrl = 0")
                    || lower.contains("ctrl disabled")
                    || lower.contains("ctrl_disabled");
                if !mentions_gate {
                    continue;
                }
                let excused = block.contains("#7233-ok")
                    || lower.contains("not xdp_pass")
                    || lower.contains("rather than xdp_pass")
                    || lower.contains("instead of xdp_pass");
                if !excused {
                    offenders.push(format!(
                        "{}:{}",
                        file.strip_prefix(&root).unwrap_or(&file).display(),
                        start
                    ));
                }
            }
        }
    }

    assert!(blocks_scanned > 0, "scanned no comment blocks at all");
    assert!(
        offenders.is_empty(),
        "comment block(s) pair a heartbeat/ctrl-disabled condition with XDP_PASS. The \
         shim DROPS transit in every one of those states (drop_degraded_transit -> \
         XDP_DROP); only pass_local_control admits proven local/control traffic. Saying \
         otherwise tells a reader the dataplane fails OPEN when it fails CLOSED (#7233).\n\
         If the comment genuinely means to DENY the pass-through, phrase it as \
         `not XDP_PASS` / `rather than XDP_PASS` / `instead of XDP_PASS`, or mark it \
         `#7233-ok`.\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_never_wired_heartbeat_grace_period_constant_stays_deleted() {
    let root = repo_root();
    let mut hits = Vec::new();
    let mut files_seen = 0usize;

    for source_root in source_roots(&root) {
        let files = rust_sources(&source_root);
        assert!(
            !files.is_empty(),
            "{} yielded no .rs files — enumeration source moved",
            source_root.display()
        );
        for file in files {
            if file.file_name().is_some_and(|n| n == "heartbeat_failclosed_doc_guard.rs") {
                continue;
            }
            files_seen += 1;
            let body = fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
            for (i, line) in body.lines().enumerate() {
                if line.contains("HEARTBEAT_GRACE_PERIOD") {
                    hits.push(format!(
                        "{}:{}",
                        file.strip_prefix(&root).unwrap_or(&file).display(),
                        i + 1
                    ));
                }
            }
        }
    }

    assert!(files_seen > 0, "scanned no files");
    assert!(
        hits.is_empty(),
        "HEARTBEAT_GRACE_PERIOD_NS documented a post-bind pass-through window that was \
         never wired — it had one grep hit, its own declaration, behind #[allow(dead_code)]. \
         Reintroducing it re-lays the #7233 trap. Sites: {}",
        hits.join(", ")
    );
}
