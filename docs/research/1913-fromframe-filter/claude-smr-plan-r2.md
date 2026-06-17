# Claude SMR hostile plan review — #1913 r2

Reviewer: Claude (domain SMR + CPU-arch/design + SW-design-patterns), HOSTILE.

## Re-verification of r2 corrections (against source @ d23d55022)

1. **§2.1 table** now states `ForwardCandidate`/`FabricRedirect` are consumed
   at mod.rs:1794-1798 and never reach :2814; the lead-in paragraph makes this
   explicit. Re-checked source: `:1794 if matches!(disposition, ForwardCandidate
   | FabricRedirect)` is the FORWARD branch; the `else` containing the :2156
   match + :2814 call is only reached for the non-forward dispositions.
   CORRECT.
2. **MissingNeighbor SNAT-failure continues** at :2533/:2564 are now in the
   table. Re-checked: both are `scratch_recycle.push(desc.addr); continue;`
   inside the MissingNeighbor SNAT-allocation-failure handling. CORRECT.
3. **§2.6** now correctly describes the :238 desc branch as the FILTERED
   wrapper that DROPS FabricRedirect (asymmetry, pre-existing, out of scope),
   and adds the `slow_path.rs:61` ForwardCandidate build-failure fallback as a
   second load-bearing unfiltered caller. Path B cons updated to "breaks BOTH."
   CORRECT.
4. **Altitude** — Path A step 3 + §6 now require a raw/unchecked-primitive doc
   comment on `_from_frame`. CORRECT.
5. **F1/F2** folded (DiscardRoute cleanest-proof in §2.4; Q3 deferral in §2.5).
   CORRECT.

## Hostile re-attack (looking for NEW defects)

- **Does Path A's wrapper refactor change wrapper behavior?** The wrapper at
  slow_path.rs:90 currently inlines `matches!(disposition, LocalDelivery |
  NoRoute | MissingNeighbor | NextTableUnsupported)`. Replacing it with a
  shared predicate of the IDENTICAL set is a pure refactor — no behavior
  change. The plan's T2 test pins this. OK.
- **Could gating :2814 drop a frame that SHOULD have been reinjected?** The
  only dispositions reaching :2814 are LocalDelivery/NoRoute/MissingNeighbor/
  NextTableUnsupported (eligible → still reinjected) and PolicyDenied/
  HAInactive/DiscardRoute (the leak → now dropped). No eligible disposition is
  newly excluded. OK.
- **Telemetry regression?** `record_forwarding_disposition` (:2802) runs
  BEFORE the gate and is unchanged, so per-disposition counts are unaffected.
  `record_slow_path_accept` never had a counter for the three dropped
  dispositions (`_ => {}`), so nothing goes missing. OK (matches my r1 F4).
- **Recycle interaction?** PolicyDenied/HAInactive/DiscardRoute keep
  `recycle_now = true`; with the reinject gated, the frame is simply recycled
  at :2852 — the correct drop behavior. No leak, no double-free. OK.
- **Scope creep risk:** the plan now explicitly fences off the :238
  FabricRedirect asymmetry and Q3 as out-of-scope follow-ups. Good — prevents
  the fix from ballooning.

## Verdict

**PLAN-READY.** All r1 findings are correctly addressed and re-verified
against source; no new defects. The diagnosis is sound, Path A is the right
altitude with the raw-primitive doc comment closing the footgun, and the two
out-of-scope items (FabricRedirect :238 asymmetry, Q3 duplicate) are explicitly
fenced. Ready for /engineer.
