//! #8945: a `#[path]`-included file that lives inside a `mod` block in its
//! parent is DESTROYED by rustfmt, and nothing else notices.
//!
//! `neighbor_dispatch_mirror_tests.rs` is included into `neighbor_dispatch.rs`
//! inside a `mod mirror_tests { … }`, so its contents are indented four spaces
//! by convention while the braces live in the parent. rustfmt sees a
//! standalone module, concludes the whole file is over-indented, and
//! **de-indents every line** — ~48KB rewritten end to end, with whatever edit
//! prompted the format invisible inside it.
//!
//! The file still COMPILES either way, which is why this needs a guard rather
//! than a rule: nothing in the build objects, the diff is enormous but
//! uniform, and a reviewer skimming it sees whitespace. The damage is that the
//! actual change becomes unreviewable, and that master then carries a file
//! whose style contradicts every sibling in its own module.
//!
//! `docs/engineering-style.md` says not to run a formatter in `userspace-dp`.
//! This is that rule as a mechanism, because the rule is one you read AFTER
//! reaching for the formatter.

use std::fs;
use std::path::Path;

/// Files that are `#[path]`-included INSIDE a `mod` block and therefore carry
/// their parent's indentation.
///
/// Enumerated rather than discovered: a discovery pass would have to model
/// which includes sit inside a `mod` and which are bare, and a model of the
/// include graph is exactly the kind of second implementation that drifts from
/// the thing it models. If a new file joins this shape, add it here — the
/// addition is part of creating one.
const INDENTED_INCLUDES_8945: &[&str] = &["src/afxdp/neighbor_dispatch_mirror_tests.rs"];

#[test]
fn path_included_files_keep_their_parents_indentation_8945() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        !INDENTED_INCLUDES_8945.is_empty(),
        "NON-VACUITY: the file list is empty, so this guard checks nothing"
    );

    for rel in INDENTED_INCLUDES_8945 {
        let path = root.join(rel);
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

        // Top-level items at column 0 are the signature of a de-indent: this
        // file's items all sit at four spaces because the `mod` braces are in
        // the parent.
        let flush: Vec<&str> = src
            .lines()
            .filter(|l| {
                l.starts_with("fn ")
                    || l.starts_with("const ")
                    || l.starts_with("pub(super) fn ")
                    || l.starts_with("pub(crate) fn ")
            })
            .take(4)
            .collect();

        let indented = src
            .lines()
            .filter(|l| {
                l.starts_with("    fn ")
                    || l.starts_with("    const ")
                    || l.starts_with("    pub(super) fn ")
            })
            .count();

        assert!(
            indented > 0,
            "NON-VACUITY: {rel} has no four-space-indented items at all, so the \
             flush-left check below cannot distinguish a de-indented file from \
             one that never had this shape. Either the file changed shape \
             deliberately — in which case remove it from INDENTED_INCLUDES_8945 \
             and say why — or it has already been flattened."
        );

        assert!(
            flush.is_empty(),
            "#8945: {rel} has top-level items at column 0, which means a \
             formatter has DE-INDENTED it.\n\
             \n\
             This file is `#[path]`-included inside a `mod` block in its \
             parent, so its items belong at four spaces; the braces are in the \
             parent. rustfmt does not know that, treats the file as a \
             standalone module, and rewrites all of it. It still compiles, \
             which is why nothing else catches this — but the change that \
             prompted the format is now invisible inside a whole-file diff.\n\
             \n\
             Recover with `git checkout HEAD -- {rel}` and re-apply your edit \
             by hand. Do not run `cargo fmt` or `rustfmt` anywhere in \
             userspace-dp (docs/engineering-style.md).\n\
             \n\
             First offending lines: {flush:?}"
        );
    }
}
