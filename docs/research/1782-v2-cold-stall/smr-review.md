# Claude SMR pass — #1782 v2 plan (self-adversarial, r1)

Verdict on own draft v1: **PLAN-NEEDS-MINOR → folded** (all findings
below are already incorporated into plan.md v1 as committed).

1. **(HIGH, folded)** The draft initially over-claimed the v8 lease
   ladder as THE mechanism on the strength of rep I's +14 parks. The
   parks delta spans the post-release shaped handshake bytes, so it
   is not clean stall evidence; meanwhile the timer-wheel O(lag)
   catch-up (`advance_cos_timer_wheel`) quantitatively predicts the
   magnitudes (~5-10 ns/tick × lag/50 µs: 7-13 min → 60-190 ms,
   hours → ~1-2 s) AND the per-worker variance (rep C fast/slow
   split, the 53 ms@60 s control where the worker's true lag exceeds
   60 s). The only counter-evidence (rep H no-CPU-burst) inherits
   ±1-2 s cross-VM clock-mapping uncertainty. → Plan now presents
   (i)/(ii) as candidate sub-mechanisms with a 2-atomic Step-1
   disambiguator.
2. **(MED, folded)** Rep H negatives must carry the clock-skew
   caveat (fw1 runs 51.2 s behind the client; three earlier perf
   windows silently missed their stalls because of it). → §3.6
   caveat + the measurement-gotcha note in §3.
3. **(MED, open as Q3)** Rep C's BE-queue 127 ms stalls are not
   explained by the exact-queue lease story (BE is non-exact,
   transparent queue tokens; root parks were 0 in rep I but rep I
   only exercised :5201). The wheel theory covers them naturally
   (per-worker, class-independent). Q3 + root-lease counters in
   Step 1 keep this falsifiable.
4. **(LOW)** "≥33.5 ms top bucket +1 per rep" is clipped evidence —
   the actual per-call durations are unknown (could be 40 ms or the
   full stall). Step-1 raises the bucket ceiling; severity table
   uses connect wall times, which are direct measurements.
5. **(LOW)** The neighbor-side PLAN-KILL is scoped to "as the #1782
   fix" — H5 remains real (operator's induced rep) and the Option-B
   design notes are retained for a future neighbor-loss issue. This
   is deliberate: killing the artifact, not the knowledge.
