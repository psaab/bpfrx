# Claude SMR hostile plan-review — #1800 r2 (`48d1a023c`)

**Verdict: PLAN-READY**

v2 folds all r1 findings; re-checked hostilely:

- My r1 F1 (U2 failover gate), F2 (§5.5 premise stated + implementer
  re-verification step), F3 (U6 interactions resolved in-plan via the split
  semantics, not deferred) — all addressed.
- Codex F1-F8: U6 split matches Codex's per-path prescription AND absorbs
  AGY's two counter-arguments (sync divergence → B-for-SyncApply; rollback
  hole → B-for-auto-rollback). U10 resequenced + monotonic-ns + KVM claim
  withdrawn + pause simulation required. U5a reshaped to FormatSet-generation
  with the fidelity caveat I'd want (a buggy generator would chase phantoms —
  the sanity check is in). U8 keeps the Background-root invariant. U11 flipped
  to Option B on the verified no-pair-reader evidence with A as recorded
  fallback. Parallelism is now an explicit two-lane scheme with the smoke
  cluster named as the global serializer.
- AGY A/B/F: companion wall-clock sites enumerated in §5.6; RestartHeartbeat
  grace gap in scope with the widen-vs-suppress decision delegated to r2 Q2;
  U7 validation moved to the strict path only with a Load()-boots regression
  test — the boot-safety constraint is now load-bearing in §7.

Remaining items are r2 questions by design (window default, FormatSet
fidelity depth, RELEASE semantics) — none blocks the triage structure. No new
findings. Ready.
