# Claude SMR plan-review r2 — #1746

I drove the r2 revision to address my own r1 findings plus Codex's and
AGY's. Re-checking the four required revisions from claude-smr-plan-r1.md:

1. Naming knot resolved — default "" ≡ `slowest` (current `min`),
   `mean` = Σ/Σ, `ideal-share` = literal share. No ""-vs-named
   divergence (§1, §5.2, §9 Q1). DONE.
2. §10 replaced by the corrected observed-band 10-flow model in §4
   (12.42G/27.7% baseline; mean 10.93G/16.7%; slowest 8.70G/~0%); both
   Codex and AGY independently recomputed the identical numbers. DONE.
3. F1 live-measurement ship-gate added (§8.2/§9 Q3): `mean` ships only
   on a measured material CoV win, else PLAN-KILL at /engineer time —
   the explicit mitigation for the sample-set-collapse no-op risk and
   for AGY's footgun objection. DONE.
4. Committed to the sibling info-metric (§5.3, no gauge relabel); added
   the F3 lease-rebuild coordinator test (§8.1). DONE.

Codex r2 caught one residual: the plan referenced a nonexistent field
`rate_bytes_per_epoch`. Fixed post-review — IdealShare now derives the
nominal cap from `new_cap`/`rate_bytes`×EPOCH + `total_flows` with a
call-order note (the cap/total_flows are computed AFTER the current
publish call site, so the implementation threads them or reorders).

No remaining structural objection. The design is a one-match change in
`publish_equal_flow_epoch_v8` over data the rotation already collects
(confirmed by all three reviewers), default byte-unchanged, opt-in
policies gated on a measured win. AGY's correct structural point (the
cap cannot lift the 0.87G floor; #1748 is the work-conserving fix) is
documented honestly in §4 and §6 Path C and does not block the cheap
opt-in partial win.

VERDICT: PLAN-READY.
