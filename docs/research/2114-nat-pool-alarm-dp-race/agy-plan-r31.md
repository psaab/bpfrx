# AGY adversarial plan-review — round 31 (plan v31 @ 445cbd2b1)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (5/5 folds FOLDED; 3 fresh attacks FAILED). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED — `store_persist.go:414-428` retry loop and `crypto.go:262-270,457-465` key loading structurally prevent split-key re-encryption by blocking encrypted writes during key-class failures until confirm-side re-reads heal under restored key K.
2. FOLDED — `ConfirmDebtKindMask != 0` explicitly gates the process-local debt state in `plan.md:1093-1100`, routing any live W debt + BOOT latch scenario to running/wait instead of stopped-restore.
3. FOLDED — Clear-time re-read taxonomy explicitly maps byte mismatch to key-class state, invalid-length to `ErrMasterKeyLength` (`crypto.go:451-454`), and EACCES/ENOENT to key-state-UNVERIFIABLE across x23/x24 legs (`plan.md:1115-1122`).
4. FOLDED — Arm-supersession barrier pins `fsatomic.WriteFileDurable` (`fsatomic.go:45-79`) directory fsync completion as the deferred barrier so D clears atomically with W upon successful (w-a) completion.
5. FOLDED — Residual copies swept; both x23 copies list (w-u), both x24 copies carry re-read taxonomy, W table is four-legged, §9 partition correctly tags items 3-5 as [FOLLOW-UP], and source comments point to the follow-up unit (`plan.md:1128-1134,4137`).

(B) Fresh attacks:
1. Refusing bootstrap commits during outstanding key-class: FAILED — On a day-0 box, no prior `confirm.json` exists, so a key-class corrupt confirm record cannot exist prior to the first commit; if a key-class corrupt confirm record exists from a prior commit, refusing subsequent commits until key remediation occurs is the intended invariant (`crypto.go:457-465`, `store_persist.go:414-428`).
2. One-pass-lag shutdown hazard: FAILED — If shutdown occurs during pass N before active write execution in N+1, the process exit abandons the retry loop (`store_persist.go:397-401`), leaving the last durable `active.json` on disk intact; this preserves pre-existing active-side degraded persistence behavior without state corruption.
3. Orphaned D debt on W stale-clear during window resolution: FAILED — Window resolution finalized via `clearConfirmResolutionPendingLocked` (`store_persist.go:428`) issues a tombstone/deletion of `confirm.json`, which subsumes the slot and eliminates any orphaned D debt state without an underlying live window.

(C) Structure confirmation:
The §4.7 delivery structure (G+H+H2 in follow-up unit, r28 (A) dissent recorded) stands unchanged.

PLAN-READY
