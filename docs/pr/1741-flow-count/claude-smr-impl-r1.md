# PR #1860 — Claude SMR hostile implementation review (round 1)

Head reviewed: d199d1767c34. Stance: hostile, line-level.

## Attacks

1. **In-window behavior parity vs master.** The rewritten loop's
   predicate chain (`None` slot skip → `last_used_epoch == 0` skip →
   `wrapping_sub` age → `age < ACTIVE_WINDOW_EPOCHS` to count) is the
   exact De Morgan expansion of master's `active_entry_age` filter;
   rows/limit/truncated/cos_counts logic is untouched. For any entry
   with age in [0, 10) the function's outputs are byte-identical to
   master. The only behavioral delta is the new store for age >= 10
   entries, which master already excluded from every output.
   **No regression found.**

2. **Boundary.** Counted iff `age < 10`; clamped iff `age >= 10`. An
   entry hit at epoch E is counted for current_epoch in [E, E+9] (ages
   0..9 — 10 epochs ≈ 650 ms) exactly as on master, and cleared at the
   first scan where age = 10 — the same scan that already excluded it.
   Pinned by `issue_1741_window_boundary_counts_age_9_clamps_age_10`,
   which also asserts the in-window stamp is NOT mutated. **Holds.**

3. **Wrap safety of the clamp itself.** Could a stamp survive from age
   10 up through the wrap because scans stopped running? No: the only
   way `current_epoch` advances is `tick_advance_epoch`, whose single
   production call site is immediately followed by this scan
   (`umem/debug_state.rs:230/234`). No tick, no wrap; tick implies
   clamp scan. **Airtight.**

4. **&mut fan-out.** Callers: `umem/debug_state.rs:234` (method call on
   `binding.flow.flow_cache`, `binding: &mut BindingWorker` — auto-ref
   &mut, compiles) and test code. Full suite compiled and ran: 1943/0.
   `active_entry_age` is now `#[cfg(test)]`; its only remaining caller
   `count_active_flows` is already `#[cfg(test)]`. Release warning
   count == base 138 (checked before/after). **Clean.**

5. **Hot-path discipline.** `lookup`/`insert`/packet path untouched.
   The clamp adds one compare + conditional u16 store per expired entry
   in the existing O(4096) debug-cadence scan. No new allocations
   (rows/cos_counts allocations are master's). **Zero per-packet cost.**

6. **Tests pin the bug.** Mutation check run: with the flow_cache.rs
   fix reverted (tests kept), `issue_1741_epoch_wrap_dead_entry_never_
   resurrects`, `issue_1741_clean_close_choreography_never_ghosts`, and
   the boundary test FAIL (resurrections / missing clamp); the
   recoverable-by-hit test passes both ways by design (pins the
   no-eviction + observed_bytes-preservation semantics). The
   choreography test asserts the FIN re-insert sentinel-clear and the
   final-ACK re-stamp individually before the wrap loop — faithful to
   the production close path established in the research round
   (packet_eligible gate at poll_descriptor/mod.rs:209; slow-path
   insert at poll_descriptor/mod.rs:1992-2016). **Adequate.**

7. **Docs.** fairness-regimes.md states the restored invariant plus the
   two honest caveats (elastic window, slower-than-window flows drop
   out) — no over-claim; matches what #1746 needs. Module comments
   updated on the field, the helper, and the scan. **Adequate.**

## Verdict

**MERGE-READY.** No findings of any severity.
