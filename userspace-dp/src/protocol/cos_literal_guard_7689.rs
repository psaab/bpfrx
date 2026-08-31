//! #7689: keep `CoSSchedulerSnapshot` struct literals non-exhaustive.
//!
//! An ADDITIVE wire field — one carrying `#[serde(default)]`, designed to be
//! invisible to older peers — is a compile break at every **exhaustive** struct
//! literal, i.e. every literal with no `..Default::default()` tail. Those
//! literals do not care about the new field; they break only because they
//! enumerate.
//!
//! `CoSSchedulerSnapshot` was the tree's outlier: 72 of 74 literals enumerated
//! (97%), against 1 of 402 for `InterfaceSnapshot` and 12 of 330 for
//! `FirewallTermSnapshot`. #6846 paid that toll — two new fields broke 71
//! literals across five files — and #7689 converted them. This is the second
//! half of #7689's acceptance: the cell that stops the pattern coming back,
//! because the habit is what regrows it.
//!
//! Deliberately NOT `#[non_exhaustive]`. That would force the tail at compile
//! time, but it also blocks exhaustive construction outside the defining crate
//! and changes the type's public contract to solve a test-hygiene problem.

use crate::afxdp::worker_queue::tests::{afxdp_rs_files, blank_comments_and_strings};

/// Split a struct-literal body on its DEPTH-0 commas.
///
/// The struct-update tail is `..expr` occupying the position a field name would
/// occupy, so it is the segment test that identifies it — not a substring
/// search for `..`, which also matches a range inside a field value
/// (`foo: 0..3`) and would score an exhaustive literal as guarded.
fn depth0_segments(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for ch in body.chars() {
        match ch {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth -= 1,
            _ => {}
        }
        if ch == ',' && depth == 0 {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    out.push(cur);
    out
}

/// True when the literal body carries a `..` struct-update tail.
fn has_update_tail(body: &str) -> bool {
    depth0_segments(body)
        .iter()
        .any(|s| s.trim_start().starts_with(".."))
}

#[test]
fn cos_scheduler_snapshot_literals_carry_an_update_tail_7689() {
    // The whole crate source, not just `src/afxdp`: `src/protocol/` holds 15 of
    // these literals, and a scan rooted at the afxdp subtree would report a
    // clean tree while never reading them. (`afxdp_rs_files` is a generic
    // recursive `.rs` walker despite its name.)
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    afxdp_rs_files(&root, &mut files);

    let mut literals = 0usize;
    let mut skipped_non_literal = 0usize;
    let mut exhaustive: Vec<String> = Vec::new();

    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        let raw = std::fs::read_to_string(path).expect("read source");

        // Comments and string bodies are blanked BEFORE any brace or comma
        // arithmetic. This is not defensive dressing: a literal whose tail is
        // written `field: 1, // note\n ..Default::default()` puts the comment
        // at the head of the final depth-0 segment, so an unblanked scan reads
        // that segment as starting with `//` and reports a guarded literal as
        // exhaustive. Measured on this tree — it produced a false positive at
        // forwarding_build/tests.rs before blanking was added. The shared
        // helper is reused rather than re-implemented for exactly the reason
        // `afxdp/worker_queue.rs` gives where it widens the visibility: "a
        // second copy of comment-blanking is exactly where a source-scanning
        // gate quietly stops seeing what it is meant to."
        let src = blank_comments_and_strings(&raw);

        let mut from = 0usize;
        while let Some(hit) = src[from..].find("CoSSchedulerSnapshot") {
            let start = from + hit;
            from = start + "CoSSchedulerSnapshot".len();

            // Require the identifier to be whole, then an optional run of
            // whitespace, then `{`. Anything else is a mention, not a literal.
            let after = src[from..].trim_start();
            if !after.starts_with('{') {
                continue;
            }
            let brace = from + src[from..].find('{').expect("checked above");

            // `struct X {`, `impl ... for X {` and `-> X {` all match the
            // identifier-then-brace shape and are NOT literals. The return-type
            // case is the one that bites: a constructor helper
            // `fn f(..) -> CoSSchedulerSnapshot {` would otherwise have its
            // whole FUNCTION BODY brace-matched as a literal body, which
            // contains no depth-0 `..` segment and so scores as exhaustive.
            // Measured: 4 such helpers in this tree, all false positives
            // before this guard was added.
            let pre = src[..start].trim_end();
            if pre.ends_with("->")
                || pre.ends_with("struct")
                || pre.ends_with("impl")
                || pre.ends_with("for")
            {
                skipped_non_literal += 1;
                continue;
            }

            // Brace-match the literal body.
            let bytes = src.as_bytes();
            let mut i = brace + 1;
            let mut depth = 1i32;
            while i < bytes.len() && depth > 0 {
                match bytes[i] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                i += 1;
            }
            if depth != 0 {
                continue; // unbalanced: not a literal we can judge
            }
            let body = &src[brace + 1..i - 1];

            literals += 1;
            if !has_update_tail(body) {
                let line = src[..start].matches('\n').count() + 1;
                exhaustive.push(format!("{rel}:{line}"));
            }
        }
    }

    // NON-VACUITY. The assertion below is an ABSENCE, so it passes for two very
    // different reasons: the literals all carry a tail, or the scan found no
    // literals at all. A rename of the struct, a move of these files, or a
    // regression in the match shape would each silently produce a clean report.
    // Both populations are floored so a scan that reached nothing FAILS instead.
    assert!(
        files.len() >= 200,
        "scan read only {} .rs files under src — the walk is broken, so the \
         exhaustive-literal assertion below would pass vacuously",
        files.len()
    );
    assert!(
        literals >= 70,
        "found only {literals} CoSSchedulerSnapshot literals (expected ~83). \
         Either the struct was renamed or the match shape stopped matching — \
         either way this cell is no longer measuring what it names, and a \
         green result here would mean nothing"
    );

    assert!(
        exhaustive.is_empty(),
        "{} CoSSchedulerSnapshot literal(s) enumerate every field with no \
         `..Default::default()` tail, so the next additive wire field breaks \
         them:\n  {}\n\nAdd `..Default::default()` and keep only the fields the \
         test asserts on. If a literal must enumerate DELIBERATELY (to force a \
         compile break when a field is added), say so at the site and raise \
         this ceiling with the reason — do not delete the assertion.",
        exhaustive.len(),
        exhaustive.join("\n  ")
    );
}
