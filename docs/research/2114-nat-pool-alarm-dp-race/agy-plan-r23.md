# AGY adversarial plan-review — round 23 (plan v23 @ d1b64a4f1)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY. Raw output follows verbatim. NOTE (claude-smr-plan-r23.md): AGY's attack-2 rationale cites plan.md:2100,3077 for the transient-retain pin, but those lines are the R-kind table's x4d/x4e legs — the D-kind (d-i) boundary was genuinely unpinned (SMR m1 / Codex M1).

---

(A) Verification of each fold 1-4:

1. FOLD1: FOLDED
- File:line evidence: docs/research/2114-nat-pool-alarm-dp-race/plan.md:1580,1617,2110,3071
- Explanation: The (w-b) bullet in all locations (summary, Work Item H2, summary of changes, and acceptance criteria) has been rewritten to D2 (restore-as-supersession, subsuming the dead record's R-kind debt once the restore's directory barrier lands). No R-first language remains in the body for the W-kind retry path.

2. FOLD2: FOLDED
- File:line evidence: docs/research/2114-nat-pool-alarm-dp-race/plan.md:1835-1853,2100,3077; pkg/configstore/store_persist.go:405-460
- Explanation: The D-kind retry explicitly re-reads confirm.json and re-classifies into (d-i) still unreadable (permanent) → synthesized tombstone → delete; (d-ii) ABSENT → DeleteConfirm re-drive → clear; (d-iii) READABLE → clear as moot (the superseded unreadable record was replaced) and follow normal readable recovery path. An arm-C landing before retry creates a readable live record, causing branch (d-iii) to clear D as moot without touching C. The entire re-read and write/delete sequence executes inside one `s.mu` critical section per pass (pkg/configstore/store_persist.go:405-460). Transient read errors at retry time retain debt without tombstoning (plan.md:2100,3077).

3. FOLD3: FOLDED
- File:line evidence: docs/research/2114-nat-pool-alarm-dp-race/plan.md:648,1854-1868,3535
- Explanation: The D-kind debt is explicitly process-local (abandoned on exit with no boot auto-recreation). A pre-tombstone crash reconstructs the boot latch and relies on operator-mediated runbook remediation. The residual is strictly bounded to the admitted tombstone-write-failure ∧ crash-before-heal class with an operator-paced heal. All claims of self-reconstruction at boot have been removed.

4. FOLD4: FOLDED
- File:line evidence: docs/research/2114-nat-pool-alarm-dp-race/plan.md:1666-1675,1813-1833,1997-1999,2118,2183,2240,2461,3083,3136,3198,3540
- Explanation: All three x12/x19 copies specify the two-step synthesized tombstone + D-kind debt (lines 2183, 2240, 3136, 3198). All four "ONLY tombstone producer" copies are scoped to distinguish the read-back producer from the synthesized producer (lines 2118, 2461, 3083, 3540). The recordless guarantee is scoped to restore-first ordering, with restore failures returning to D1 and the admitted arm-persistence residual (lines 1666-1675). The synthetic record is pinned (`FirstCommit=false` preventing Work Item H false-reverts, `Deadline = now + 60s`, `PrevTree = active.Clone()`, `GuardedHash = canonicalConfigHash(s.active)`, `HashBasis = "canonical-v1"`, `ArmID = fresh crypto/rand`) with documented downgrade behavior and shape regression (lines 1813-1833). Health state gains `SLOT_DELETE` in `ConfirmDebtKindMask`, and the aggregate is defined as the OR of `persistDegraded`, confirm debt kinds, and the latch (lines 1997-1999).


(B) Fresh attacks with outcomes:

1. Attack: Synthetic record field inventory mismatch or reader corruption
- Outcome: FAILED
- Rationale: Inspecting `confirmRecord` in pkg/configstore/db.go:169-191 and its reader validation in pkg/configstore/db.go:275-280:
  - `Deadline = now + 60s` (non-zero) passes `rec.Deadline.IsZero()` at db.go:275.
  - `PrevTree = s.active.Clone()` (non-nil) passes `rec.PrevTree == nil` at db.go:278.
  - `FirstCommit = false` avoids tripping Work Item H's `rec.FirstCommit && s.compiled != nil && s.compiled.Chassis.Cluster != nil` guard at store_persist.go:113.
  - `GuardedHash = canonicalConfigHash(s.active)` with `HashBasis = "canonical-v1"` ensures dual-basis consistency.
  - `Resolved = true` causes all updated readers to drop/delete the record immediately without re-arming or rolling back.
  - On downgrade to an old reader (which ignores unknown JSON fields `Resolved`, `HashBasis`, `ArmID`), the record is seen as a live pending window with `PrevTree` matching `s.active.Clone()`. If rolled back, reverting to `PrevTree` is a no-op revert to the identical running config.

2. Attack: Transient vs Permanent read error boundary at D-retry time
- Outcome: FAILED
- Rationale: The permanent vs transient error classification uses a mechanical `errors.As` check for `ConfirmRecordPermanentError` (wrapping malformed JSON, zero deadline, nil target, and crypto/envelope/auth/PRF failures). At retry time for a D-kind debt, a transient IO error retains the debt without writing a synthetic tombstone (plan.md:2100,3077). A permanent error proceeds with writing the synthetic tombstone over the unreadable file and unlinking it under `s.mu.Lock()`. If a transient failure occurs during the synthetic `WriteConfirm` write itself, the D-kind debt remains retained for subsequent passes.

3. Attack: Interleaving race between D-kind retry and a concurrent live arm (arm-C)
- Outcome: FAILED
- Rationale: All mutations and reads of confirm.json are serialized by `s.mu` (pkg/configstore/store_persist.go:405-460). If `arm-C` lands before D-retry executes, `arm-C` overwrites `confirm.json` with C's record under `s.mu.Lock()`. When D-retry subsequently acquires `s.mu.Lock()` and re-reads `confirm.json`, it successfully parses C's record (READABLE) and hits branch (d-iii), which clears D as moot without modifying C. If D-retry runs first under `s.mu.Lock()`, it writes the synthetic tombstone and unlinks `confirm.json`, after which `arm-C` acquires `s.mu.Lock()` and installs C as a fresh live record. In both ordering permutations, C is preserved and D is cleared.


Verdict:
PLAN-READY
