//! #6898 (A1-b5-F1): the binding snapshot must observe `bind_mode` ONCE.
//!
//! `xsk_bind_mode` and `zero_copy` are two spellings of one value — the mode's
//! name, and whether that mode is zero-copy. Reading the atomic twice lets a
//! concurrent rebind land between the reads and publish a snapshot whose two
//! fields describe DIFFERENT modes.
//!
//! That is not merely a stale value: it is a snapshot that **disagrees with
//! itself**, on an operator-facing status surface. `show` would report a
//! copy-mode bind as zero-copy or the reverse, and because the inconsistency is
//! internal to a single snapshot, nothing downstream can detect it — every
//! consumer sees a well-formed record.
//!
//! A torn read is a race, so no behavioural test can reliably observe it. The
//! two guards below cover the two ways it can come back:
//!   * the SOURCE guard catches a reintroduced second load (the original bug);
//!   * the AGREEMENT test catches a wrong derivation, where one field is
//!     computed from something other than the single observation.

/// The original defect, and the one a future edit is most likely to reintroduce
/// by "inlining" the local back into both fields.
///
/// Comments are stripped BEFORE matching, so this file's own prose — which
/// necessarily spells the banned expression — cannot satisfy the scan, and
/// neither can the explanatory comment at the fix site.
#[test]
fn snapshot_observes_bind_mode_exactly_once_6898() {
    let src = include_str!("snapshot.rs");
    let code: String = src
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");

    let loads = code.matches("bind_mode.load(").count();
    assert_eq!(
        loads, 1,
        "#6898: `snapshot.rs` performs {loads} `bind_mode.load(...)` calls in CODE \
         (comments stripped); it must perform exactly ONE. Two observations let a \
         concurrent rebind tear `xsk_bind_mode` against `zero_copy` within a single \
         snapshot. Load once into a local and derive both fields from it."
    );
}

/// Guards the derivation itself: for every mode, the rendered name and the
/// zero-copy flag must describe the same mode. This is what a source guard
/// cannot see — a single load whose two derivations disagree.
#[test]
fn bind_mode_name_and_zero_copy_flag_agree_6898() {
    use crate::afxdp::binding_state::XskBindMode;

    for raw in 0u8..=8 {
        let mode = XskBindMode::from_u8(raw);
        let name = mode.as_str();
        let zc = mode.is_zerocopy();
        // The two spellings must not disagree about zero-copy-ness. Keyed on the
        // rendered name rather than on the enum, because the name is what the
        // operator reads and what the snapshot actually carries.
        let name_says_zc = name.contains("zerocopy") || name.contains("zero-copy");
        assert_eq!(
            name_says_zc, zc,
            "#6898: mode {raw} renders as {name:?} but is_zerocopy()={zc}; the \
             snapshot's two fields would describe different modes"
        );
    }
}
