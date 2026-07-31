//! #6592 publish/read canary — defence in depth over the atomic
//! `(validation, forwarding)` pairing.
//!
//! # The type system is the boundary; this file is the backstop
//!
//! An earlier version of this canary WAS the write-capability boundary, and a
//! review probe showed that was fail-open. `HaState::runtime_reader` returned
//! the writable `Arc<ArcSwap<RuntimeView>>` and `RuntimeView` was `Clone` with
//! reachable fields, so production code could do:
//!
//! ```ignore
//! let alias = self.ha.runtime_reader();
//! let mut torn = alias.load_full().as_ref().clone();
//! torn.validation.fib_generation = torn.validation.fib_generation.wrapping_add(1);
//! alias.store(Arc::new(torn));
//! ```
//!
//! That compiled, published the exact `(new validation, old forwarding)` tear,
//! and every rule below passed: the store was not the choke point's literal
//! spelling, and the view came from a CLONE, not a construction — so the
//! "a publish needs a constructed view" argument was simply false. Enumerating
//! bypasses had by then failed twice on this canary (the first was a
//! rustfmt-wrapped method chain).
//!
//! The capability is now enforced by types, and each of those three lines is
//! independently a COMPILE error:
//!
//! - `runtime_reader()` returns [`RuntimeViewReader`], whose `ArcSwap` is a
//!   private field and whose only method is `load()`. No consumer can obtain a
//!   writer, so `alias.store(..)` and `alias.load_full()` do not exist.
//! - `RuntimeView` is not `Clone`, so `.as_ref().clone()` does not compile —
//!   `RuntimeView::new` is now the ONLY way to obtain a view value anywhere.
//! - `RuntimeView`'s fields are private, so `torn.validation.x = ..` does not
//!   compile.
//! - The coordinator's own handle is [`RuntimeViewChannel`], which likewise
//!   hides the `ArcSwap`: `publish` is the only mutation, so `swap`, `rcu`,
//!   `compare_and_swap` and `Deref` are unreachable rather than merely
//!   unmentioned by a regex.
//!
//! What remains for this file is the residue types cannot express: a NEW site
//! inside `coordinator/` calling `self.ha.runtime.publish(RuntimeView::new(
//! stale_validation, fwd))`, and a second view load inside one worker tick.
//! Because `RuntimeView` is no longer `Clone`, "a publish needs a CONSTRUCTED
//! view" is now a true statement rather than an enumeration, which is what
//! makes rule 2 meaningful.
//!
//! # What it pins
//!
//! 1. **One publish, and the writer stays inside its type.** Exactly one
//!    `.runtime.publish(` in the tree, at the choke point; and no file outside
//!    the type's own module may name `ArcSwap<RuntimeView>` — that spelling
//!    reappearing means the raw writer has escaped again, which is precisely
//!    how the probe got in.
//! 2. **No view constructed outside the choke point.** Sites outside the type's
//!    own module must be the choke point, or carry the marker
//!    `runtime-view-canary: test-local` — which is honoured ONLY in a file's
//!    test half, so it cannot silence production code.
//! 3. **One load per reader.** Each production reader takes BOTH halves from a
//!    single `load()`. Residual, stated rather than papered over: the count
//!    keys on the `shared_runtime.load(` spelling, so a future reader that
//!    binds its handle to another name evades the COUNT (it fails closed for
//!    any file that does use the spelling). The type system covers the worse
//!    half of that: every `load()` yields one coherent view, so a single call
//!    can never tear a pair — only two calls in one tick can.
//!
//! Adding a legitimate site is meant to be possible — update the table below
//! and say why in the PR. Silently growing one is not.

use std::fs;
use std::path::{Path, PathBuf};

/// Marker that exempts a `RuntimeView` construction line (rule 2). Test-local
/// views built for a test-local channel never reach a worker.
///
/// Honoured ONLY in a file's TEST half (after the first top-level
/// `#[cfg(test)]`). A reviewer pointed out that an unconstrained marker
/// silences production code just as happily — so a production line carrying it
/// still counts.
const TEST_LOCAL_MARKER: &str = "runtime-view-canary: test-local";

/// Rule 1: the only file allowed to publish into the runtime channel.
const PUBLISH_CHOKE_POINT: &str = "src/afxdp/coordinator/mod.rs";

/// Rule 2: the module that DEFINES `RuntimeView` may construct it freely (its
/// own constructor and `Default` impl live there).
const RUNTIME_VIEW_DEFINITION: &str = "src/afxdp/types/runtime_view.rs";

/// Rule 2: production construction sites outside the definition module, as
/// `(file, expected_count, why)`.
const ALLOWED_CONSTRUCTION: &[(&str, usize, &str)] = &[
    (
        "src/afxdp/coordinator/mod.rs",
        1,
        "Coordinator::store_runtime_view — THE choke point; builds the view from \
         self.validation at the store",
    ),
];

/// Rule 3: production reader load sites, as `(file, expected_count, why)`.
/// Counted only in the code BEFORE the file's first top-level `#[cfg(test)]`.
const ALLOWED_READER_LOADS: &[(&str, usize, &str)] = &[
    (
        "src/afxdp/worker/loop_body/mod.rs",
        1,
        "refresh_runtime_view — the per-tick worker refresh; BOTH halves come \
         from this one load",
    ),
    (
        "src/afxdp/worker/loop_body/setup.rs",
        1,
        "worker_loop_setup — the startup seed; same single-load rule so a fresh \
         worker cannot start on a torn pair",
    ),
    (
        "src/afxdp/tunnel.rs",
        1,
        "local_tunnel_source_loop — seeds the GRE local-origin thread's \
         forwarding half (it does not match generation stamps)",
    ),
    (
        "src/afxdp/types/runtime_view.rs",
        1,
        "load_forwarding_if_changed — the #1188 short-circuit for \
         forwarding-only readers",
    ),
];

#[derive(Debug)]
struct Violation {
    rule: &'static str,
    detail: String,
}

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("cannot read {} — {err}", dir.display()));
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Everything before the file's first top-level `#[cfg(test)]` attribute. Test
/// modules in this tree are declared at column 0, so this is the production
/// half of the file.
fn production_half(content: &str) -> &str {
    match content.find("\n#[cfg(test)]") {
        Some(idx) => &content[..idx],
        None => content,
    }
}

/// Lines of CODE — comment-only lines dropped.
///
/// Load-bearing, not cosmetic: this file's own subject matter is documented in
/// the very comments it scans. The `#6592` docs quote `ha.runtime.store(`,
/// `RuntimeView::default()` and `shared_runtime.load()` in prose, and counting
/// those made the canary fire on its own documentation — a false positive that
/// would have been "fixed" by weakening the counts. A trailing comment on a
/// line that also holds code is kept, so the `TEST_LOCAL_MARKER` still works and
/// a construction cannot hide behind one.
fn code_lines(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
}

/// Comment-stripped code with ALL whitespace removed.
///
/// Also load-bearing. rustfmt wraps a long method chain, so a real bypass reads
///
/// ```text
/// self.ha
///     .runtime
///     .store(Arc::new(RuntimeView::new(stale, fwd)));
/// ```
///
/// and the substring `.runtime.store(` never appears on any single line. A
/// line-based count silently missed exactly that shape when this canary was
/// fire-probed — the "canary that cannot fire" failure mode. Collapsing
/// whitespace makes the chain match regardless of how it is wrapped.
fn code_blob_no_whitespace(content: &str) -> String {
    code_lines(content)
        .flat_map(|line| line.chars())
        .filter(|ch| !ch.is_whitespace())
        .collect()
}

/// Does this line CONSTRUCT a `RuntimeView` (as opposed to naming the type in a
/// signature)? `-> RuntimeView {` is a return type, not a construction.
fn constructs_runtime_view(line: &str) -> bool {
    if line.contains("RuntimeView::new(") || line.contains("RuntimeView::default()") {
        return true;
    }
    line.contains("RuntimeView {") && !line.contains("-> RuntimeView {")
}

/// Rule 1b: does this line name the raw `ArcSwap<RuntimeView>`?
///
/// Outside the type's own module that spelling means the write capability has
/// escaped its wrapper — exactly what let a review probe alias the writer and
/// publish a torn pair. Whitespace is already stripped by the caller so a
/// wrapped generic (`ArcSwap<\n    RuntimeView>`) still matches.
fn names_raw_runtime_arcswap(code_no_whitespace: &str) -> usize {
    code_no_whitespace.matches("ArcSwap<RuntimeView>").count()
}

/// Rule 1 + rule 2, over one file's full content.
fn scan_publish(rel: &str, content: &str, violations: &mut Vec<Violation>) {
    let stores = code_blob_no_whitespace(content)
        .matches(".runtime.publish(")
        .count();
    if rel == PUBLISH_CHOKE_POINT {
        if stores != 1 {
            violations.push(Violation {
                rule: "1 (one publish)",
                detail: format!(
                    "{rel}: found {stores} `.runtime.publish(` — expected exactly 1 \
                     (Coordinator::store_runtime_view). Every publish must go \
                     through the choke point so the view is built from \
                     self.validation AT the store; a second store site can pair a \
                     stale validation with new forwarding and neither #6592 \
                     RED-on-revert test would see it."
                ),
            });
        }
    } else if stores != 0 {
        violations.push(Violation {
            rule: "1 (one publish)",
            detail: format!(
                "{rel}: {stores} `.runtime.publish(` outside the choke point \
                 ({PUBLISH_CHOKE_POINT}). Publish via \
                 Coordinator::publish_runtime_view or \
                 republish_runtime_validation instead."
            ),
        });
    }

    // Rule 1b: the raw writable `ArcSwap<RuntimeView>` must not be nameable
    // outside the type's own module. Its escape is how the probe got in.
    if rel != RUNTIME_VIEW_DEFINITION {
        let raw = names_raw_runtime_arcswap(&code_blob_no_whitespace(content));
        if raw != 0 {
            violations.push(Violation {
                rule: "1b (writer stays inside its type)",
                detail: format!(
                    "{rel}: names `ArcSwap<RuntimeView>` {raw} time(s). The raw \
                     writable ArcSwap must not leave `{RUNTIME_VIEW_DEFINITION}` \
                     — anything holding it can `store`/`swap`/`rcu` a torn pair \
                     past the choke point, which is exactly the bypass this \
                     canary previously missed. Take a `RuntimeViewReader` (read \
                     only) or use the coordinator's `RuntimeViewChannel`."
                ),
            });
        }
    }

    if rel == RUNTIME_VIEW_DEFINITION {
        return;
    }
    // The `test-local` marker is honoured ONLY in a file's TEST half. Left
    // unconstrained it silences PRODUCTION code — a reviewer flagged that the
    // marker's mere presence on any line suppressed the rule.
    let production = production_half(content);
    let test_half = &content[production.len()..];
    let constructions = code_lines(production)
        .filter(|line| constructs_runtime_view(line))
        .count()
        + code_lines(test_half)
            .filter(|line| {
                constructs_runtime_view(line) && !line.contains(TEST_LOCAL_MARKER)
            })
            .count();
    let expected = ALLOWED_CONSTRUCTION
        .iter()
        .find(|(file, _, _)| *file == rel)
        .map(|(_, count, _)| *count)
        .unwrap_or(0);
    if constructions != expected {
        let why = ALLOWED_CONSTRUCTION
            .iter()
            .find(|(file, _, _)| *file == rel)
            .map(|(_, _, why)| *why)
            .unwrap_or("no construction allowed here");
        violations.push(Violation {
            rule: "2 (no view built outside the choke point)",
            detail: format!(
                "{rel}: {constructions} RuntimeView construction(s), expected \
                 {expected} ({why}). `RuntimeView` is not Clone, so construction \
                 is the ONLY way to obtain a view value — which makes this the \
                 rule that catches a publish however it reaches the channel. If \
                 the site is a test-local view for a test-local channel, put \
                 `{TEST_LOCAL_MARKER}` on the construction line IN THE FILE'S \
                 TEST HALF; otherwise publish through the choke point."
            ),
        });
    }
}

/// Rule 3's truncation heuristic assumes everything after a file's first
/// top-level `#[cfg(test)]` is test code. A `#[cfg(not(test))]` block down
/// there would be PRODUCTION code silently excluded from the load count, so say
/// so loudly rather than let the heuristic rot into a blind spot. No file in
/// the tree does this today; this fires the day one does.
fn scan_truncation_heuristic(rel: &str, content: &str, violations: &mut Vec<Violation>) {
    let production = production_half(content);
    if production.len() == content.len() {
        return;
    }
    let discarded = &content[production.len()..];

    // Scoped to the files rule 3 actually counts. A load past the truncation
    // point is NOT by itself a finding — a file's own test module legitimately
    // has several — so the signal is `#[cfg(not(test))]`, which is the only way
    // PRODUCTION code gets down there. Zero occurrences today; this fires the
    // day the heuristic stops holding rather than letting it rot into a blind
    // spot. Distinguishing test from production loads precisely would need
    // region tracking, which is more machinery than the risk warrants while the
    // count stays at zero.
    if !ALLOWED_READER_LOADS.iter().any(|(file, _, _)| *file == rel) {
        return;
    }
    let cfg_not_test = code_lines(discarded)
        .filter(|line| line.contains("#[cfg(not(test))]"))
        .count();
    if cfg_not_test != 0 {
        violations.push(Violation {
            rule: "3 (one load per reader)",
            detail: format!(
                "{rel} is a counted runtime-view reader and has {cfg_not_test} \
                 `#[cfg(not(test))]` after the first top-level `#[cfg(test)]`. \
                 Rule 3 treats everything past that point as test code, so a \
                 load added in that production block would go uncounted. Move it \
                 above the test module, or teach `production_half` to skip only \
                 the test module's braces."
            ),
        });
    }
}


/// Rule 3, over one file's PRODUCTION half.
fn scan_reader_loads(rel: &str, production: &str, violations: &mut Vec<Violation>) {
    let loads = code_blob_no_whitespace(production)
        .matches("shared_runtime.load(")
        .count();
    let expected = ALLOWED_READER_LOADS
        .iter()
        .find(|(file, _, _)| *file == rel)
        .map(|(_, count, _)| *count)
        .unwrap_or(0);
    if loads != expected {
        let why = ALLOWED_READER_LOADS
            .iter()
            .find(|(file, _, _)| *file == rel)
            .map(|(_, _, why)| *why)
            .unwrap_or("this file is not a runtime-view reader");
        violations.push(Violation {
            rule: "3 (one load per reader)",
            detail: format!(
                "{rel}: {loads} production runtime-view load(s), expected \
                 {expected} ({why}). Two loads in the same tick can observe two \
                 different views and pair halves across generations — the exact \
                 defect #6592 closed. Take both halves from ONE load."
            ),
        });
    }
}

#[test]
fn runtime_view_publish_and_read_sites_are_pinned() {
    let src = crate_src();
    let mut violations = Vec::new();
    for path in rust_sources(&src) {
        let rel = format!(
            "src/{}",
            path.strip_prefix(&src)
                .expect("under src")
                .to_string_lossy()
                .replace('\\', "/")
        );
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("cannot read {} — {err}", path.display()));
        scan_publish(&rel, &content, &mut violations);
        scan_truncation_heuristic(&rel, &content, &mut violations);
        scan_reader_loads(&rel, production_half(&content), &mut violations);
    }

    // Every entry in the tables must correspond to a real file, or the table has
    // rotted into a rule that can never fire (a canary that cannot fire is worse
    // than no canary).
    for (file, _, _) in ALLOWED_CONSTRUCTION.iter().chain(ALLOWED_READER_LOADS) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        assert!(
            path.exists(),
            "{file} is listed in a runtime-view canary table but does not exist — \
             the entry is dead and its rule can never fire; fix the path or drop \
             the entry"
        );
    }

    assert!(
        violations.is_empty(),
        "#6592 runtime-view canary: {} violation(s)\n{}",
        violations.len(),
        violations
            .iter()
            .map(|v| format!("  [rule {}] {}", v.rule, v.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[cfg(test)]
mod self_tests {
    use super::*;

    #[test]
    fn detects_a_second_publish_in_the_choke_point_file() {
        let mut v = Vec::new();
        scan_publish(
            PUBLISH_CHOKE_POINT,
            "self.ha.runtime.publish(a);\nself.ha.runtime.publish(b);\n\
             let x = RuntimeView::new(1, 2);\n",
            &mut v,
        );
        assert_eq!(v.len(), 1, "two stores in the choke-point file must fire");
        assert!(v[0].rule.starts_with('1'), "got {:?}", v[0]);
    }

    #[test]
    fn detects_a_publish_outside_the_choke_point() {
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/ha/somewhere.rs",
            "self.ha.runtime.publish(view);\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('1')),
            "a publish outside the choke point must fire: {v:?}"
        );
    }

    #[test]
    fn detects_a_view_constructed_outside_the_choke_point() {
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/ha/somewhere.rs",
            "let view = RuntimeView::new(older_validation, fwd);\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('2')),
            "an unmarked construction must fire: {v:?}"
        );
    }

    #[test]
    fn test_local_marker_suppresses_a_construction() {
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/ha/somewhere.rs",
            "fn production() {}\n#[cfg(test)]\nmod t {\n\
             let view = RuntimeView::new(a, b); // runtime-view-canary: test-local\n}\n",
            &mut v,
        );
        assert!(
            v.is_empty(),
            "a marked construction in the TEST half must be tolerated: {v:?}"
        );
    }

    #[test]
    fn choke_point_with_exactly_one_store_and_one_construction_is_clean() {
        let mut v = Vec::new();
        scan_publish(
            PUBLISH_CHOKE_POINT,
            "let view = Arc::new(RuntimeView::new(self.validation, forwarding));\n\
             self.ha.runtime.publish(view);\n",
            &mut v,
        );
        assert!(v.is_empty(), "the real shape must be clean: {v:?}");
    }

    #[test]
    fn detects_a_second_reader_load() {
        let mut v = Vec::new();
        scan_reader_loads(
            "src/afxdp/worker/loop_body/mod.rs",
            "let view = shared_runtime.load();\nlet again = shared_runtime.load();\n",
            &mut v,
        );
        assert_eq!(v.len(), 1, "a second load must fire");
        assert!(v[0].rule.starts_with('3'), "got {:?}", v[0]);
    }

    #[test]
    fn detects_a_reader_load_in_an_unlisted_file() {
        let mut v = Vec::new();
        scan_reader_loads(
            "src/afxdp/ha/somewhere.rs",
            "let view = shared_runtime.load();\n",
            &mut v,
        );
        assert_eq!(v.len(), 1, "a load in an unlisted file must fire");
    }

    #[test]
    fn test_module_loads_are_not_counted() {
        // Production half ends at the first top-level `#[cfg(test)]`, so loads
        // inside a test module do not inflate the count.
        let content = "let view = shared_runtime.load();\n#[cfg(test)]\nmod t {\n\
                       let a = shared_runtime.load();\n let b = shared_runtime.load();\n}\n";
        let mut v = Vec::new();
        scan_reader_loads(
            "src/afxdp/worker/loop_body/mod.rs",
            production_half(content),
            &mut v,
        );
        assert!(v.is_empty(), "test-module loads must not count: {v:?}");
    }

    #[test]
    fn detects_production_code_hidden_after_the_test_module() {
        let mut v = Vec::new();
        scan_truncation_heuristic(
            "src/afxdp/worker/loop_body/mod.rs",
            "fn prod() {}\n#[cfg(test)]\nmod t {}\n#[cfg(not(test))]\n\
             fn also_prod() { let v = shared_runtime.load(); }\n",
            &mut v,
        );
        assert_eq!(
            v.len(),
            1,
            "a counted reader with cfg(not(test)) past the truncation point must \
             be reported: {v:?}"
        );

        // An unrelated file with cfg(not(test)) but no runtime-view load is NOT
        // a finding — the tree has several and they are harmless.
        let mut v = Vec::new();
        scan_truncation_heuristic(
            "src/filter/mod.rs",
            "fn prod() {}\n#[cfg(test)]\nmod t {}\n#[cfg(not(test))]\nfn x() {}\n",
            &mut v,
        );
        assert!(v.is_empty(), "unrelated cfg(not(test)) must be quiet: {v:?}");
    }

    #[test]
    fn truncation_heuristic_is_quiet_on_a_normal_file() {
        let mut v = Vec::new();
        scan_truncation_heuristic(
            "src/afxdp/worker/loop_body/mod.rs",
            "fn prod() {}\n#[cfg(test)]\nmod t { fn a() {} }\n",
            &mut v,
        );
        assert!(v.is_empty(), "a normal file must not fire: {v:?}");
    }

    #[test]
    fn production_half_keeps_whole_file_when_no_test_module() {
        let content = "let view = shared_runtime.load();\n";
        assert_eq!(production_half(content), content);
    }

    #[test]
    fn prose_mentioning_the_scanned_tokens_does_not_fire() {
        // The #6592 docs quote every token this canary counts. Before comment
        // skipping, that made the canary fire on its own documentation.
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/ha/somewhere.rs",
            "// a site writing self.ha.runtime.store(Arc::new(RuntimeView::new(v, f)))\n\
             /// would reintroduce the torn pair; see RuntimeView::default()\n\
             //! and shared_runtime.load() in the module header\n",
            &mut v,
        );
        assert!(v.is_empty(), "comment-only lines must not count: {v:?}");
        let mut v = Vec::new();
        scan_reader_loads(
            "src/afxdp/ha/somewhere.rs",
            "// a SECOND shared_runtime.load() would tear the pair\n",
            &mut v,
        );
        assert!(v.is_empty(), "comment-only loads must not count: {v:?}");
    }

    #[test]
    fn code_with_a_trailing_comment_still_counts() {
        // Skipping is comment-ONLY lines. A construction cannot hide behind a
        // trailing comment (only the explicit marker exempts it).
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/ha/somewhere.rs",
            "let view = RuntimeView::new(a, b); // perfectly innocent\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('2')),
            "a trailing comment must not exempt a construction: {v:?}"
        );
    }

    #[test]
    fn detects_a_publish_wrapped_across_lines_by_rustfmt() {
        // The shape a fire-probe actually produced. A line-based count misses
        // it entirely, which is why the counts run over whitespace-stripped
        // code.
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/coordinator/snapshot_refresh.rs",
            "        self.ha\n            .runtime\n            .publish(view);\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('1')),
            "a rustfmt-wrapped store chain must still fire rule 1: {v:?}"
        );
    }

    #[test]
    fn detects_a_reader_load_wrapped_across_lines() {
        let mut v = Vec::new();
        scan_reader_loads(
            "src/afxdp/worker/loop_body/mod.rs",
            "let a = shared_runtime.load();\nlet b = shared_runtime\n    .load();\n",
            &mut v,
        );
        assert_eq!(v.len(), 1, "a wrapped second load must still fire rule 3");
        assert!(v[0].rule.starts_with('3'), "got {:?}", v[0]);
    }

    #[test]
    fn the_marker_does_not_silence_production_code() {
        // The marker used to suppress rule 2 wherever it appeared, including in
        // production. It is now honoured only in a file's TEST half.
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/coordinator/snapshot_refresh.rs",
            "let view = RuntimeView::new(stale, fwd); // runtime-view-canary: test-local\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('2')),
            "a marker on a PRODUCTION line must not exempt it: {v:?}"
        );
    }

    #[test]
    fn detects_the_raw_writable_arcswap_escaping_its_type() {
        // Rule 1b. Holding `ArcSwap<RuntimeView>` outside its module is the
        // capability escape a review probe used to publish a torn pair.
        let mut v = Vec::new();
        scan_publish(
            "src/afxdp/coordinator/ha_state.rs",
            "    pub(super) runtime: Arc<ArcSwap<RuntimeView>>,\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with("1b")),
            "a raw ArcSwap<RuntimeView> outside the type's module must fire: {v:?}"
        );
    }

    #[test]
    fn a_wrapped_generic_still_counts_as_the_raw_arcswap() {
        assert_eq!(
            names_raw_runtime_arcswap(&code_blob_no_whitespace(
                "fn f(x: Arc<ArcSwap<\n    RuntimeView,\n>>) {}"
            )),
            0,
            "a trailing comma is a different spelling; documented limit"
        );
        assert_eq!(
            names_raw_runtime_arcswap(&code_blob_no_whitespace(
                "fn f(x: Arc<ArcSwap<\n    RuntimeView>>) {}"
            )),
            1,
            "a plain wrapped generic must still match"
        );
    }

    #[test]
    fn a_return_type_is_not_a_construction() {
        assert!(
            !constructs_runtime_view("    fn mint(&mut self, gen: u64) -> RuntimeView {"),
            "`-> RuntimeView {{` names the type in a signature; it builds nothing"
        );
        assert!(
            constructs_runtime_view("        let view = RuntimeView { validation, forwarding };"),
            "a struct literal IS a construction"
        );
        assert!(constructs_runtime_view("        RuntimeView::new(v, f)"));
        assert!(constructs_runtime_view("        RuntimeView::default()"));
    }
}
