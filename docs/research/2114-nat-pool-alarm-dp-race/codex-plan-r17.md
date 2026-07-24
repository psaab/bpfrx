# Codex hostile plan-review — round 17 (plan v17 @ 3d3b3e8af)

Task: task-mrz6e3hp-k8sknb (session 019f9508-6dfb-7842-9a71-75c434058a2a).
Verdict: NEEDS-REVISION (6 MAJOR, 3 MINOR). Raw companion output follows verbatim.

---

Fold verification

1. PARTIAL — The same-directory barrier and program order hold: both paths use `db.dir` (`pkg/configstore/db.go:73-76,194-218`), `WriteFileDurable` performs rename then directory fsync (`pkg/fsatomic/fsatomic.go:310-369`), and active writes precede finalize on plain commit, confirmed commit, and retry (`pkg/configstore/store_commit.go:180-200,437-452`; `pkg/configstore/store_persist.go:419-428`). Immediate finalize is therefore valid. x8 is implementable through the existing real seam (`pkg/fsatomic/test_seams.go:9-32`; `pkg/configstore/postrename_dbboundary_5234_test.go:80-124`). SyncApply nevertheless bypasses that barrier on a post-rename failure.

2. PARTIAL — The A/B nested-arm counterexample is closed by the two-field rules (`plan.md:1111-1153`), and a tombstone post-rename failure correctly leaves `onDiskArmID` equal to the tombstoned record’s preserved ArmID while retaining rewrite debt. However, early `Load` exits never seed the supposedly exact disk identity (`pkg/configstore/store_persist.go:26-42,81-113`).

3. PARTIAL — The individual A/B/C rewrite transitions are sound (`plan.md:1170-1189`), and active persistence is serialized before finalize (`pkg/configstore/store_persist.go:405-428`). If active retry succeeds and tombstoning fails pre-rename, active debt clears while the matching removal debt remains, which is safe. The claimed “≤1 removal + 1 rewrite” bound is false (`plan.md:1193-1198`).

4. PARTIAL — The fixed-record parse and crypto classes are enumerated (`pkg/configstore/db.go:242-281`; `pkg/configstore/crypto.go:307-356,366-395,409-453`), and per-debt terminal latching is conceptually correct. Master-key I/O is misclassified, terminal remediation lacks an observer, and transient boot failures violate the recovery total order.

5. FOLDED — SyncApply is replacement-class only and uniform tombstone-first removal is explicit in the body (`plan.md:1006-1014,1030-1078`; `pkg/configstore/store.go:697-760`). No stale confirm-type-scoped or HA-sync-auto-confirm claim remains in the plan body.

6. FOLDED — The citations are accurate: generation stamp (`userspace-dp/src/afxdp/flow_cache.rs:120-139`), lookup eviction (`:992-999`), NAT64 exclusion (`:385-393`), and NAT64 generation guarding (`userspace-dp/src/nat64.rs:244-263,528-553`).

7. PARTIAL — Election-neutrality is verified (`pkg/daemon/daemon_run_servers.go:370-374`; `pkg/cluster/readiness.go:20-24`; `pkg/cluster/election.go:427-432`). The distinct terminal response is not implementable through the specified aggregate boolean API (`pkg/api/server.go:132-140,338,424`; `pkg/api/health.go:65-71`).

New findings

MAJOR 1 — SyncApply has a single-failure restart hole. It cancels the window before writing active and treats every write error, including `PostRenameSyncError`, as non-durable without attempting the tombstone (`pkg/configstore/store.go:697-717,738-746`). Post-rename means B is already namespace-visible to readers and restart (`pkg/fsatomic/fsatomic.go:66-72,354-366`). Restart before retry can therefore load B plus pending-shaped A; equal guarded content or a legacy empty hash binds A and re-arms/reverts it (`pkg/configstore/store_persist.go:149-171`). This contradicts the claimed failed-SyncApply closure (`plan.md:1066-1071,1361-1366,1860-1876`). SyncApply must classify post-rename and immediately attempt the tombstone barrier; success proves B durable, while failure retains both debts.

MAJOR 2 — `onDiskArmID` conflates “not observed” with the legacy empty-ID sentinel. `Load` returns without reading confirm.json when active is absent or compilation fails (`pkg/configstore/store_persist.go:26-42,81-113`), despite v17 claiming exact identity after recovery (`plan.md:1127-1147`). An admitted replay can leave orphan A with no active (`plan.md:1217-1222`); bootstrap then performs a plain commit (`pkg/daemon/daemon_run_bringup.go:308-333`; `pkg/daemon/daemon_apply_commit.go:23-60`), but no timer means the orphan is not resolved (`pkg/configstore/store_commit.go:678-702`). A later B arm failing pre-rename, followed by a resolution read error, constructs an empty-key debt; retry treats nonempty A as a newer mismatch and durably preserves it (`plan.md:1154-1166`). The model needs an explicit unknown state or a confirm read on every `Load` outcome.

MAJOR 3 — A third confirm-side debt can coexist. Let A’s resolution leave removal debt R_A; arm B and fail its confirm write post-rename, creating W_B; before the sleeping retry reacquires the lock, resolve B and fail its tombstone post-rename, creating R_B (`pkg/configstore/store_persist.go:402-405`; `pkg/configstore/store_commit.go:397-425,470-524`). The result is R_A + W_B + R_B. V17’s proof says the second tombstone clears W_B (`plan.md:1193-1198`), but a post-rename failure establishes visibility, not durability (`pkg/fsatomic/fsatomic.go:358-367`). Specify a proven removal-slot transfer/coalescing rule or support multiple keyed removal debts.

MAJOR 4 — The terminal machine has both an incorrect entry class and no in-process exit. V17 classifies all master-key I/O as permanent (`plan.md:1235-1241`), but the decrypt path merely calls `os.ReadFile`; a missing key mount, repaired permissions, or transient I/O can recover, while only invalid observed key length is deterministic (`pkg/configstore/crypto.go:443-453`). Once terminalized, v17 stops that debt but says a later clean `ReadConfirm` or absence clears it (`plan.md:1240-1259`). The only production `ReadConfirm` call is boot recovery (`pkg/configstore/store_persist.go:140`), and the singleton exits without actionable debt (`:402-412,455-465`). Pin a probe/new-arm transition or state explicitly that remediation requires restart.

MAJOR 5 — Transient boot `ReadConfirm` failure permanently loses the rollback hatch for that process. V17 preserves log-and-return (`plan.md:1252-1255,1375-1380,2095-2099`); current recovery then returns without a timer, debt, or retry while `Load` succeeds (`pkg/configstore/store_persist.go:140-145`). An unconfirmed active configuration can consequently stand indefinitely, violating both the documented recovery purpose (`:117-125`) and v17’s “must NEVER stand” invariant (`plan.md:1846-1848`). Boot recovery must retry to a bounded decision or fail `Load` before manager construction.

MAJOR 6 — The distinct terminal 503 has no cause-bearing channel. V17 folds `confirmRecordTerminal` into `ConfigPersistDegraded` while requiring different response text (`plan.md:1246-1248,1273-1279,1597-1600`). The API receives and stores only `func() bool` (`pkg/api/server.go:132-140,338,424`), and health sees only that boolean (`pkg/api/health.go:65-71`). Add a typed snapshot, terminal callback, or equivalent state accessor and specify precedence when multiple degradation causes coexist.

MINOR 1 — The residual is broader than “both writes fail post-rename.” V17 makes that exact claim (`plan.md:1217-1224,1870-1876`), but active POST plus tombstone PRE leaves B visible and A intact; restart before healing can still observe B+A (`pkg/fsatomic/fsatomic.go:45-55,66-72,310-366`). The precise residual is active POST plus tombstone failure in any phase, followed by restart/power loss before a successful directory barrier.

MINOR 2 — “Wired ONLY to REST health” is false (`plan.md:1262-1266`): the same callback drives Prometheus (`pkg/api/metrics.go:948-957`). Moreover, the metric and wiring comments describe only active-config persistence (`pkg/api/metrics_descriptors.go:625-630`; `pkg/daemon/daemon_run_servers.go:370-374`), which becomes false when terminal confirm corruption sets the aggregate flag. Update those surfaces or expose separate causes.

MINOR 3 — The documentation sweep misses replacement-class terminology still present in source documentation. SyncApply is described as “confirmation” in `pkg/configstore/store.go:697-719` and `pkg/configstore/README.md:663-672`, while the planned sweep lists neither (`plan.md:1741-1766`).

NEEDS-REVISION

Codex session ID: 019f9508-6dfb-7842-9a71-75c434058a2a
Resume in Codex: codex resume 019f9508-6dfb-7842-9a71-75c434058a2a
