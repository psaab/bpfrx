//! #6592 publish/read canary — source-scanning guard over the atomic
//! `(validation, forwarding)` pairing.
//!
//! # Why a source canary and not only types
//!
//! #6592 made validation and forwarding travel in ONE `Arc` (`RuntimeView`), so
//! a reader can never pair them across generations. Two RED-on-revert tests
//! guard that: `snapshot_refresh_runtime_view_pair_is_atomic_6592` (consumer)
//! and `refresh_runtime_snapshot_publishes_a_coherent_view_pair` (producer).
//!
//! Neither can see a NEW site that bypasses the choke point. The producer test
//! drives `refresh_runtime_snapshot`, which publishes through
//! `Coordinator::store_runtime_view`; a future HA or fabric path writing
//! `self.ha.runtime.store(Arc::new(RuntimeView::new(older_validation, fwd)))`
//! directly would reintroduce the torn pair on the WRITER side with the whole
//! suite green. Likewise the consumer test drives `refresh_runtime_view` rather
//! than the real `worker_loop`, so a SECOND `shared_runtime.load()` added
//! elsewhere in the tick would pair halves across generations untested.
//!
//! Field visibility narrows the first hole — `HaState::runtime` is `pub(super)`,
//! so nothing outside the `coordinator` module tree can reach the `ArcSwap` at
//! all — but it cannot close it, because a new site inside `coordinator/` still
//! compiles, and a holder of the reader handle (`HaState::runtime_reader`) has
//! a storable `Arc<ArcSwap<..>>` by construction. This canary is what makes the
//! remaining paths mechanical rather than conventional.
//!
//! # What it pins
//!
//! 1. **One publish.** Exactly one `.runtime.store(` in the tree, at the choke
//!    point. Test fixtures publish through `seed_published_validation`, which
//!    routes to `republish_runtime_validation` — so there is no cfg(test)
//!    exemption to reason about here.
//! 2. **No view built outside the choke point.** Any publish needs a
//!    `RuntimeView` VALUE, so pinning CONSTRUCTION catches a bypass even if it
//!    stores through a cloned handle the textual rule (1) cannot see. Sites
//!    outside the type's own module must be the choke point, or carry the
//!    marker `runtime-view-canary: test-local` on the construction line.
//! 3. **One load per reader.** Each production reader takes BOTH halves from a
//!    single `ArcSwap` load. The expected count per file is listed explicitly;
//!    adding a load anywhere fires this with the reason.
//!
//! Adding a legitimate site is meant to be possible — update the table below
//! and say why in the PR. Silently growing one is not.

use std::fs;
use std::path::{Path, PathBuf};

/// Marker that exempts a `RuntimeView` construction line (rule 2). Test-local
/// views built for a test-local `ArcSwap` never reach a worker.
const TEST_LOCAL_MARKER: &str = "runtime-view-canary: test-local";

/// Rule 1: the only file+substring allowed to store into the runtime `ArcSwap`.
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
    (
        "src/afxdp/coordinator/ha_state.rs",
        1,
        "HaState::new — the initial default view the ArcSwap is created from",
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
    if line.contains(TEST_LOCAL_MARKER) {
        return false;
    }
    if line.contains("RuntimeView::new(") || line.contains("RuntimeView::default()") {
        return true;
    }
    line.contains("RuntimeView {") && !line.contains("-> RuntimeView {")
}

/// Rule 1 + rule 2, over one file's full content.
fn scan_publish(rel: &str, content: &str, violations: &mut Vec<Violation>) {
    let stores = code_blob_no_whitespace(content)
        .matches(".runtime.store(")
        .count();
    if rel == PUBLISH_CHOKE_POINT {
        if stores != 1 {
            violations.push(Violation {
                rule: "1 (one publish)",
                detail: format!(
                    "{rel}: found {stores} `.runtime.store(` — expected exactly 1 \
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
                "{rel}: {stores} `.runtime.store(` outside the choke point \
                 ({PUBLISH_CHOKE_POINT}). Publish via \
                 Coordinator::publish_runtime_view or \
                 republish_runtime_validation instead."
            ),
        });
    }

    if rel == RUNTIME_VIEW_DEFINITION {
        return;
    }
    let constructions = code_lines(content).filter(|line| constructs_runtime_view(line)).count();
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
                 {expected} ({why}). A publish needs a view VALUE, so this rule \
                 catches a bypass that stores through a cloned handle too. If the \
                 site is a test-local view for a test-local ArcSwap, put \
                 `{TEST_LOCAL_MARKER}` on the construction line; otherwise \
                 publish through the choke point."
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
            "self.ha.runtime.store(a);\nself.ha.runtime.store(b);\n\
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
            "self.ha.runtime.store(Arc::new(view));\n",
            &mut v,
        );
        assert!(
            v.iter().any(|x| x.rule.starts_with('1')),
            "a store outside the choke point must fire: {v:?}"
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
            "let view = RuntimeView::new(a, b); // runtime-view-canary: test-local\n",
            &mut v,
        );
        assert!(v.is_empty(), "marked construction must be tolerated: {v:?}");
    }

    #[test]
    fn choke_point_with_exactly_one_store_and_one_construction_is_clean() {
        let mut v = Vec::new();
        scan_publish(
            PUBLISH_CHOKE_POINT,
            "let view = RuntimeView::new(self.validation, forwarding);\n\
             self.ha.runtime.store(Arc::new(view));\n",
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
            "        self.ha\n            .runtime\n            .store(Arc::new(view));\n",
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
