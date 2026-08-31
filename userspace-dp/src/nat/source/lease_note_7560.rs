//! #7560: the operator-facing note for persistent-NAT leases that a
//! partial-overlap pool change dropped.
//!
//! WHY THIS IS A SEPARATE NOTE, not a field on the #6765 line. That line
//! accounts for live TRANSLATIONS — carried, out of range, address-only,
//! refused — and the SHAPE of a carried/skipped accounting implies it is
//! complete. Persistent leases appeared in neither column, so an operator who
//! added one address to a pool read a reassuring "carried N live
//! translation(s)" and was told nothing about every subscriber binding being
//! dropped. A true message whose shape implies more than it says was the
//! defect, not a missing log.
//!
//! WHY TWO COUNTS. Only one of them is a surprise. A lease on a REMOVED address
//! cannot be honoured — the address is gone. A lease on a RETAINED address was
//! dropped only because carry-over is keyed on the whole address list, so an
//! operator who changed a DIFFERENT address loses it anyway. Reporting one
//! number would bury the actionable half inside the expected one.
//!
//! WHY ITS OWN FILE. nat/source/mod.rs was at 1493 LOC and this change crossed
//! the 1500 [WATCH] floor the refactoraudit gate enforces. Moving the note into
//! allocator.rs would have dodged that gate rather than answered it — that file
//! is already 3686 LOC, so it crosses no NEW threshold — which is the wrong
//! instinct. A new concern gets a small file.

//! THE RENAME SITE (#7560 residual). This note is emitted at every
//! `reseed_retained_from` call site, not only the pool-change one, and the
//! #6979 rename path is the reason that matters. A rename builds its index map
//! as an IDENTITY over every address — same addresses, same range, which is
//! what makes it a rename — so EVERY dropped lease lands in
//! `dropped_persistent_on_retained`: 100% of the pool's leases, in the bucket
//! this note calls the actual operator surprise. That site reported carried
//! translations, refusals and range misses and said nothing about any of them,
//! which is the same implied-completeness shape described above, at a site the
//! first fix did not reach.
//!
//! The nat64 site is wired too and is LATENT: nothing in nat64.rs allocates
//! through the persistent-lease path, so the note should always be `None`
//! there. Wired anyway — "the counter exists but nobody prints it" is the
//! defect, and leaving one site unwired preserves it.

use super::super::allocator::ReseedOutcome;

/// The note, or `None` when no lease was dropped.
///
/// EXTRACTED from the eprintln so the message is bindable. The counters are
/// only half the fix — the defect was that the operator was never TOLD — and a
/// message that lives inside a macro call in a config-apply path is asserted by
/// nothing. A guard on an inline format string is not a guard.
///
/// Silent when there is nothing to say: a note on every ordinary pool change is
/// noise an operator learns to skip, which would reintroduce the invisibility
/// by a different route.
pub(crate) fn dropped_persistent_lease_note(
    pool_name: &str,
    outcome: &ReseedOutcome,
) -> Option<String> {
    if outcome.dropped_persistent_on_retained == 0 && outcome.dropped_persistent_on_removed == 0 {
        return None;
    }
    Some(format!(
        "xpf-dp: source-nat pool {pool_name:?} changed: DROPPED {} persistent-NAT lease(s) \
         on RETAINED addresses and {} on removed addresses — a source pinned to an address \
         that is still in the pool will be re-mapped to a new address on its next new flow \
         (#7560)",
        outcome.dropped_persistent_on_retained, outcome.dropped_persistent_on_removed,
    ))
}

/// Emit the note if there is one. Every `reseed_retained_from` call site calls
/// exactly this, so "which sites report dropped leases" is one line of code
/// rather than a convention three callers have to remember — the convention is
/// what produced the gap this file's header describes.
pub(crate) fn report_dropped_leases(pool_name: &str, outcome: &ReseedOutcome) {
    if let Some(note) = dropped_persistent_lease_note(pool_name, outcome) {
        eprintln!("{note}");
    }
}
