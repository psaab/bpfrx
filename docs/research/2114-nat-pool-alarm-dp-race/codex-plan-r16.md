# Codex hostile plan-review — round 16 (plan v16 @ 0b8e7cc97)

Task: task-mryq552r-semyw3 (session 019f9367-fc8e-7423-93b4-c002c7b90293).
Verdict: NEEDS-REVISION (4 MAJOR, 3 MINOR). Raw companion output follows verbatim.

---

Fold verification

1. PARTIAL — The runtime premise is corrected: every userspace compile removes XDP pins and bumps generation (`pkg/dataplane/userspace/manager_compile.go:162-175,199`), and stale flow entries are evicted on generation mismatch (`userspace-dp/src/afxdp/flow_cache.rs:992-999`). Normal replacement failures retain confirm.json (`pkg/configstore/store.go:738-746`, `store_commit.go:917-937`, `store_persist.go:196-220`). But the claim that removal is reached only post-durability is false: `PostRenameSyncError` explicitly means not yet durable (`store_commit.go:15-25`, `pkg/fsatomic/fsatomic.go:45-55`), yet plain and confirmed commits immediately finalize deferred removal (`store_commit.go:180-200,437-452,641-649`). Stale-drop tombstoning itself is sound (`store_persist.go:159-165`; Resolved-first recovery at `plan.md:1125-1128`).

2. FOLDED — SyncApply cancels the timer before writing, retains A on every failed write, resolves directly only after success, and the retry finalizes only after successfully rewriting active state (`pkg/configstore/store.go:697-760`, `store_persist.go:414-428`, `store_commit.go:631-649`). With v16’s tombstone-first finalize, durable B plus lingering A recovers through the Resolved check and cannot revert B (`plan.md:1162-1172`).

3. PARTIAL — `WriteConfirm` does establish full durability through temp-write, file-fsync, rename, and directory-fsync (`pkg/configstore/db.go:207-218`, `pkg/fsatomic/fsatomic.go:310-369`). Repeated B-rewrite failure intentionally retains A’s debt and degraded health (`plan.md:1074-1088`), but the new B-rewrite debt has no transition rules for later arms or the other two debts.

4. NOT-FOLDED — The sole live arm reaches `writeConfirmState` (`pkg/configstore/store_commit.go:503-553`), and readable recovery re-arms the same record coherently (`store_persist.go:231-253`). However, v16 clears `pendingArmID` at resolution while replacement finalization occurs later (`plan.md:1061-1069`; `store.go:738-746`), and boot stale/expired removals precede the claimed restore point (`store_persist.go:159-228`). Thus several removal-error paths cannot key debt from memory as promised. An unreadable boot record returns before re-arm (`store_persist.go:140-144`); a readable legacy empty ArmID should instead be defined as a matchable legacy sentinel.

5. PARTIAL — v16 requests permanent typed subtypes for #5637 errors (`plan.md:1082-1088`), but the present `ReadConfirm` path does not uniformly distinguish them: malformed JSON is wrapped, while zero deadline and nil target are plain generic errors (`pkg/configstore/db.go:243-280`). The proposed table also omits permanent decrypt/envelope corruption and mixed master-key failures (`pkg/configstore/crypto.go:307-356,366-395,409-453`).

6. PARTIAL — Section 5.1 now includes both `store.go` and `store_persist.go` (`plan.md:1356-1376`), but H2 still calls HA-sync supersession confirm-type at `plan.md:957-962` and replacement-class at `plan.md:1002-1018`; the documentation sweep likewise still says “confirm-type-scoped tombstone-first” (`plan.md:1532-1534`) despite the uniform rule.

New findings

MAJOR 1 — The durability proof fails on the real post-rename call graph. Both commit paths treat a directory-fsync failure as visible-but-nondurable and immediately invoke deferred removal (`pkg/configstore/store_commit.go:180-200,437-452,641-649`). A successful tombstone `WriteConfirm` may incidentally fsync both same-directory renames, but if that write also fails post-rename there is no transactional guarantee that active B and A’s tombstone survive power loss together (`pkg/fsatomic/fsatomic.go:345-369`). Existing tests cannot expose this: their “post-rename” seam first completes a successful durable `WriteActive` and only then fabricates the typed error (`pkg/configstore/confirm_rollback_durable_5473_test.go:334-349,354-368,433-440`). The plan must defer finalization until the active retry succeeds or specify and test a real durability barrier.

MAJOR 2 — `pendingArmID` is an attempted timer-arm identity, not a reliable on-disk-record identity. V16 says it is cleared at resolution and removal debt copies it from memory, never from a fresh read (`plan.md:1061-1069`), while `confirmResolvePendingPersist` is currently only a boolean surviving until a later finalize (`pkg/configstore/store.go:138-150`). Moreover, a nested arm B updates memory before its best-effort `WriteConfirm` outcome; a pre-rename failure leaves record A on disk (`store_commit.go:503-553`, `pkg/fsatomic/fsatomic.go:310-345`). A subsequent B resolution read failure therefore creates B-keyed debt, whose retry sees A as a “newer mismatch” and preserves or rewrites it; same-content or legacy-hash A can then bind after restart. The design needs a retained resolved ArmID and a separate known-on-disk identity updated according to the actual write phase.

MAJOR 3 — The B-rewrite debt has no A/B/C state machine. Nested arms are legal (`pkg/configstore/store_commit.go:470-524`), while the singleton retry sleeps outside the store lock (`store_persist.go:402-405`), so arm C can supersede B before B’s rewrite debt runs. V16 does not say whether retrying captured B may overwrite C, when a durable C clears B’s debt, how post-rename C transfers the debt, or how B-rewrite ordering composes with `persistDegraded` and A’s removal debt (`plan.md:1074-1089,1368-1375`). “Rewrite B, then clear A” is insufficient without identity checks and supersession transitions for the rewrite debt itself.

MAJOR 4 — Terminal degradation is neither exhaustive, restart-stable, nor debt-scoped. `ReadConfirm` can fail through parse validation, corrupt encryption envelopes, authentication failure, unsupported PRF, invalid key length, and master-key I/O (`pkg/configstore/db.go:243-280`, `crypto.go:307-356,366-395,409-453`), but v16 terminalizes only #5637 parse-gate errors. Recovery currently logs and returns without setting any degraded latch (`store_persist.go:140-144`), while health derives solely from in-memory debt flags (`store_persist.go:342-353`), so restart launders a corrupt terminal record from 503 to healthy. Finally, “stop the retry loop” is unsafe because that singleton also heals active-config persistence (`store_persist.go:402-465`). The plan needs a total typed taxonomy, boot reconstruction, per-debt terminal state, and an exact remediation/clear transition.

MINOR 1 — H2’s classification remains contradictory and can send implementation down two orderings: HA SyncApply is called immediate confirm-type at `plan.md:957-1001`, then replacement/rollback at `plan.md:1002-1018`; the actual code is unequivocally replacement-class (`pkg/configstore/store.go:697-760`). The stale “confirm-type-scoped” documentation instruction at `plan.md:1532-1534` compounds the ambiguity.

MINOR 2 — The NAT64 churn citation is wrong. `flow_cache.rs:122-139` only defines/captures a stamp, and ordinary flow caching explicitly excludes NAT64 (`userspace-dp/src/afxdp/flow_cache.rs:385-393`). Ordinary eviction is at `flow_cache.rs:992-999`; NAT64 fragment loss follows its separate generation guard (`userspace-dp/src/nat64.rs:244-263,528-553`). The premise holds, but the plan must cite the correct mechanism.

MINOR 3 — Permanent HTTP 503 does not gate internal HA promotion. Config persistence degradation is wired to REST health (`pkg/daemon/daemon_run_servers.go:370-374`, `pkg/api/health.go:65-71`), while cluster health annotations are election-neutral and crash takeover bypasses readiness (`pkg/cluster/readiness.go:20-24`, `election.go:427-432`). V16 should state that policy explicitly; additionally, its “pkg/api untouched” declaration (`plan.md:1382`) leaves the misleading “active configuration failed to persist” response for terminal confirm-record corruption.

NEEDS-REVISION

Codex session ID: 019f9367-fc8e-7423-93b4-c002c7b90293
Resume in Codex: codex resume 019f9367-fc8e-7423-93b4-c002c7b90293
