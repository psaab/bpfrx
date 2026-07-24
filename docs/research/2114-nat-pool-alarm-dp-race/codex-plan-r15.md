# Codex hostile plan-review — round 15 (plan v15 @ `4b3546bac`)

Reviewer: Codex (companion task `task-mryp8l35-fwtat6`, session
`019f9350-cf2a-7b60-9793-8dd39dd8fc7b`; dispatched from the worktree,
read-only). Verbatim output below; fold adjudications recorded in plan v16.

---

Fold verification:
1. NOT-FOLDED — Plain commit is correctly routed through `clearPendingConfirmLocked` to `resolveConfirmRemovalLocked`; under `s.mu`, the planned tombstone can precede timer cancellation even though active was already persisted/promoted, and the extra write occurs only with a pending window (`pkg/configstore/store_commit.go:160-246,678-702`). But the class-(ii) idempotence premise is false: timeout replay re-runs the full daemon apply, while failed-then-durable SyncApply can revert a newer durable config (`pkg/daemon/daemon_apply_commit.go:640-706`; `pkg/configstore/store.go:738-760`; `pkg/configstore/store_persist.go:149-253,414-428`).
2. NOT-FOLDED — ABSENT correctly requires another `DeleteConfirm` to finish directory fsync (`pkg/configstore/db.go:297-315`), but different-B→clear is unsafe when B's rename was visible but not durable (`pkg/fsatomic/fsatomic.go:45-55,358-366`), and degenerate records enter a permanent read-error loop (`pkg/configstore/db.go:226-281`).
3. PARTIAL — A random persisted ArmID is the right identity, and timer callbacks need only `confirmGen` (`pkg/configstore/store_commit.go:503-510,717-726,856-864`). Recovery need not compare ArmID, but must retain it: current pending state and recovery restore no disk identity (`pkg/configstore/store.go:168-179`; `pkg/configstore/store_persist.go:231-253`), so an ArmID-keyed debt cannot be created after a resolution-time read error.
4. PARTIAL — The after-deadline immediate-revert wording is honest (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:990-995`; `pkg/configstore/store_persist.go:171-228`), but "resolves at the NEXT BOOT" is still false when that boot occurs before the deadline: recovery merely re-arms the stale window (`pkg/configstore/store_persist.go:231-253`).
5. FOLDED — `active.json` and `confirm.json` share the DB directory (`pkg/configstore/db.go:73-76,194-197`), which factory reset removes wholesale (`pkg/configstore/factory_reset.go:252-268`) under the terminal reset generation (`pkg/daemon/daemon_apply_reset.go:20-29,59-89`).
6. FOLDED — The current warning categorically attributes mismatch to supersession (`pkg/configstore/store_persist.go:149-164`), and v15 explicitly scopes changing the actual diagnostic to "superseded OR basis-incompatible" (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1285-1286,1445-1448`).

New findings:

MAJOR — Repeated non-FirstCommit timeout rollback is not observably idempotent. In the admitted same-content/legacy-hash case with a backward wall-clock adjustment, recovery re-arms the lingering record (`pkg/configstore/store_persist.go:231-253`). Boot already applies rollback target A (`pkg/daemon/daemon_run_bringup.go:516-520`); expiry then promotes A→A and executes the entire apply again (`pkg/daemon/daemon_apply_commit.go:640-706`). Userspace performs a fresh compile/generation and publish with no identical-config gate (`pkg/dataplane/userspace/manager_compile.go:162-199,325-355`), invalidating generation-keyed flow-cache and NAT64 fragment associations (`userspace-dp/src/afxdp/flow_cache.rs:972-999`; `userspace-dp/src/nat64.rs:522-553`). The same apply unconditionally reloads FRR and may restart heartbeat (`pkg/daemon/daemon_apply_routing.go:203-226`; `pkg/frr/manager.go:545-570`; `pkg/daemon/daemon_apply_dataplane.go:425-436`). No-tombstone is safe only before the replacement is durable; afterward tombstone-before-delete is necessary.

MAJOR — Failed SyncApply becomes non-idempotent once its retry lands. SyncApply promotes B and cancels the original C→A window before persistence, retaining A's record on failure (`pkg/configstore/store.go:681-746`). The retry then makes B durable before invoking record removal (`pkg/configstore/store_persist.go:414-428`). A crash between those operations—or removal failure—leaves durable B plus A's pending-shaped record. For B==C or legacy empty `GuardedHash`, recovery binds and reverts B to A or re-arms A (`pkg/configstore/store_persist.go:149-253`). The cited test covers only B never persisting (`pkg/configstore/confirm_rollback_durable_5473_test.go:248-290`). Moreover, v15 normatively tombstones successful SyncApply but x7 says unqualified SyncApply writes no tombstone (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:935-960,1086-1089,1743-1745`). The design must split pre-durability retention from post-durability tombstone→delete and reorder successful SyncApply's early cancellation.

MAJOR — Different-B mismatch does not durably discharge A's removal debt. V15 explicitly includes post-rename B in mismatch→clear (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1011-1014`), but `WriteFileDurable` documents that a post-rename error leaves B merely visible; power loss may replay the old namespace state A (`pkg/fsatomic/fsatomic.go:45-55,66-79,358-366`). `WriteConfirm` preserves that error, while `writeConfirmState` only logs it and creates no B durability debt (`pkg/configstore/db.go:216-218`; `pkg/configstore/store_commit.go:530-553`). The retry must durably fsync/rewrite B while preserving it before clearing A's debt.

MAJOR — ArmID alone does not make the proposed debt constructible. `ReadConfirm` returns no record—and therefore no ArmID—on read, decrypt, parse, or semantic-validation errors (`pkg/configstore/db.go:242-281`), yet v15 requires resolution to proceed and retain keyed retry debt (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:978-1014`). Direct class-(ii) deletion can likewise unlink before dir-fsync fails, leaving no record from which to recover identity (`pkg/configstore/db.go:297-315`). Additionally, every matching debt is instructed to tombstone, contradicting the categorical class-(ii) tombstone prohibition (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:951-962,1004-1010`). Persist/propagate a `pendingArmID` through arm and recovery, and either carry a debt action mode or redefine the rule as "no tombstone until replacement durability lands."

MINOR — Degenerate-present is not a fifth `ReadConfirm` result, but it is a distinct permanent subtype of read error. The #5637 gates return ordinary errors for malformed JSON, zero deadline, or nil rollback target (`pkg/configstore/db.go:226-281`); retain+retry therefore loops forever at capped backoff (`pkg/configstore/store_persist.go:402-465`). Document terminal degraded/manual-remediation behavior or add typed permanent-error handling; x4e currently promises only generic retry (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1069-1070`).

MINOR — The implementation inventory and introductory rationale were not updated consistently. H2 still says every confirm path removes the record without changing active content (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:916-923`), contradicted by plain commit and SyncApply (`pkg/configstore/store_commit.go:220-246`; `pkg/configstore/store.go:687-755`). Section 5.1 also omits `pkg/configstore/store.go` (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1271-1286`), although successful SyncApply must be reordered there.

NEEDS-REVISION

---

## Orchestrator fold adjudication (into v16)

All 4 MAJOR + 2 MINOR code-verified before folding; M1 is accepted OVER
the r15 AGY/SMR sign-off on the idempotence premise:

- M1 (runtime non-idempotence) VERIFIED — the compile path deletes XDP
  link pins and re-attaches AF_XDP (`manager_compile.go:162-172`,
  "fresh attach triggers mlx5 to initialize XSK buffer pool from fill
  ring"); the flow cache keys on `config_generation`
  (`flow_cache.rs:122-139`); the apply reloads FRR
  (`daemon_apply_routing.go:203-226`) and touches heartbeat-relevant
  dataplane state (`daemon_apply_dataplane.go:425-436`). A replayed
  revert is config-state idempotent but runtime-CHURNING. Folded:
  retention-without-tombstone is safe only PRE-durability; the rule is
  now UNIFORM — every `resolveConfirmRemovalLocked` tombstones first.
- M2 (failed SyncApply) VERIFIED — SyncApply supersedes the window
  (`store.go:697-700`); the finalize removes the record only after the
  replacement is durable (`store_persist.go:414-428`). Folded: the
  post-durability finalize tombstones before deleting; "no tombstone on
  replacement paths" means exactly "no tombstone UNTIL durable"; the
  x7 contradiction fixed with the qualifier + divergence regression.
- M3 (B-durability precondition) VERIFIED — master's own code treats
  post-rename as visible-not-durable (`store_commit.go:443-451`);
  `writeConfirmState` only logs (`store_commit.go:530-553`). Folded:
  mismatch → durably rewrite B via `WriteConfirm` first → then clear;
  B-rewrite failure retains A's debt; `writeConfirmState` post-rename
  failure raises a B-rewrite debt.
- M4 (pendingArmID) VERIFIED — the in-memory pending state carries no
  disk identity (`store.go:168-179`). Folded: arm stores
  `s.pendingArmID`; recovery restores it from the record when readable
  (`store_persist.go:231-253`); the debt keys from memory, so
  resolution-time read errors still construct the keyed debt (x2c).
- m1 (permanent read-error loop) VERIFIED — #5637 semantic gate errors
  are permanent; folded as typed errors (transient → retry; semantic →
  TERMINAL degraded, loop stops, health 503, loud journal, documented
  manual remediation).
- m2 (consistency) VERIFIED — H2 intro rewritten (plain commit /
  SyncApply DO change content); §5.1 adds `pkg/configstore/store.go` +
  `store_persist.go`.

Verdict recorded: **NEEDS-REVISION (4 MAJOR, 2 MINOR)**.
