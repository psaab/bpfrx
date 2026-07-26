# AGY adversarial plan-review — round 36 (plan v36 @ c0cf0b687)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (3/3 folds FOLDED; 2 fresh attacks FAILED). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. Item 1 (Mandatory mask==0 precondition explicit): FOLDED — `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1305-1318,3307-3325` explicitly require `ConfirmDebtKindMask == 0` before stopped-repair filesystem remediation, citing `pkg/configstore/store_persist.go:397-401` (process-local debts die on process exit) and `pkg/configstore/store_persist.go:149-165,171-255` (repaired pending record hash-matches into expired-revert or re-arm at next boot, rolling back confirmed config with H able to Load-revert FirstCommit+cluster); live debts use the running probe/removal path, and the operator is warned that a successful-active `Load` runs full total order recovery while absent/compile-failed `Load` seeds an orphan.
2. Item 2 (Re-verify mechanism pinned): FOLDED — `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1318-1329,3333-3351,4119-4125` pin `fsatomic.WriteFileDurableStaged(path, data, perm, preRename func() error)` with temp+write+fsync+close, pre-rename hook, and rename, running classification re-verify inside the hook under `s.mu`, hook error temp cleanup & re-classification, test seam, explicit rejection of post-write read-back, §5.1 entry, and untouched monolithic `WriteFileDurable`, verified against `pkg/configstore/db.go:207-218` and `pkg/fsatomic/fsatomic.go:310-355`.
3. Item 3 (Stale three-cause copies swept): FOLDED — `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1330-1333,4237-4238,4420-4427` sweep all three stale copies (`pkg/api/README.md:30-36`, `pkg/api/health.go:10-16`, and descriptor/wiring comments) to name all causes including `ConfigWriteUnverified`.

(B) Fresh attacks:
1. Hypothesis: A pre-rename hook error in `WriteFileDurableStaged` might leave an un-linked temp file in `.configdb/` that accumulates over time or interferes with boot recovery classification.
   Outcome: FAILED — `pkg/fsatomic/fsatomic.go:316-321,357` initializes `cleanup = true` and only clears `cleanup = false` after a successful `renameFile`; any hook error prior to rename causes `defer` to run `os.Remove(tmpName)`, unlinking `.confirm.json.tmp-*`. Furthermore, boot recovery in `pkg/configstore/store_persist.go:149-170` and `pkg/configstore/db.go:194-197` reads strictly fixed paths (`confirm.json`), so stray temp files would be completely inert on read paths.
2. Hypothesis: A process debt raised concurrently between the operator's mask check and `xpfd` stop could leave a record removal incomplete during stop, causing boot total order to mishandle the record.
   Outcome: FAILED — `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1095-1102,3307-3325` and `pkg/configstore/store_persist.go:130-165` dictate that on restart, the boot total order evaluates durable disk state (`confirm.json` present/absent/hash-matched) cleanly regardless of prior process-local debts (which die on exit per `store_persist.go:397-401`). If a removal completed before exit, `confirm.json` is absent; if it failed, `confirm.json` remains and is classified by `GuardedHash`/`ArmID`. Guidance specifies immediate post-boot health re-check.

(C) Structure confirmation:
`docs/research/2114-nat-pool-alarm-dp-race/plan.md:4035-4079` (§4.7) 2-unit delivery structure stands (PR-1 core deliverable + G+H+H2 follow-up unit; AGY r28 (A) CONVERGE dissent remains recorded).

PLAN-READY
