# Claude SMR r2 — #1752 remaining-paths plan v3

**Verdict: PLAN-READY-pending-r3.** v3 folds Codex r2 (B wording softened to
"verified participant / fraction TBD"; TX-vs-RX per-site attribution as Path B
step 1) and recasts E-followup after AGY's self-reversal.

On AGY's E-followup flip (r1 "necessary" → r2 "corrupts"): I did NOT adopt either
verdict. Both are conditional on collision reachability, which neither AGY round
proved. v3 correctly makes reachability the gating question and notes the behavior
is PRE-EXISTING (Path E #1753 preserved the old re-assert byte-identically; the 4
reviewers verified parity, so if it's a bug it's a latent pre-existing one, not a
#1753 regression). The honest output: a correctness-first investigation, not a
perf opt — do not pre-commit to kill or fix.

Residual: Path C is likely a net loss (16.7% worker-capacity cut vs GC jitter) —
v3 states the high bar + kill exit. Path B may recover less than the headline if
RX-wake (not TX-interval-gated) dominates — v3's step-1 attribution gates that.
No path here ships code except the D docs PR; all real levers spin to their own
gated research. Sound.
