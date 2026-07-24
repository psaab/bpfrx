# Codex hostile plan-review — round 18 (plan v18 @ df04e2598)

Task: task-mrz8pf3q-wm7p94 (session 019f9543-bf13-7791-8cce-3a26b0f817fc).
Verdict: NEEDS-REVISION (7 MAJOR, 5 MINOR). Raw companion output follows verbatim.

---

Fold verification

1. FOLDED — The three replacement paths receive the same pre/post-rename classification and immediate post-rename tombstone barrier (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1123-1201`). `errors.As` preserves the phase through wrapping (`pkg/configstore/store_commit.go:15-25`), and `s.mu` serialization prevents a nested arm from replacing A during SyncApply (`pkg/configstore/store.go:634-643`; `pkg/configstore/store_commit.go:856-858`; `pkg/configstore/store_persist.go:21-24`). The read therefore sees A, not B; byte-identical/no-op confirmation is covered because durability classification is content-independent (`pkg/fsatomic/fsatomic.go:45-95,342-369`). A failed tombstone plus restart remains the explicitly admitted two-failure residual, not the original single-failure hole.

2. PARTIAL — The exact A-orphan/B-pre-rename/read-error chain is now keyed to A, every Load outcome seeds Present/Absent/terminal, and successful arm explicitly transitions Absent to Present (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1218-1265,1490-1497`). A shorter orphan path remains through a superseding plain commit, described below.

3. PARTIAL — The single rewrite slot is valid because `writeConfirmState` is the sole serialized arm and newer outcomes re-key that slot (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1282-1301`; `pkg/configstore/store_commit.go:503-553`). Multiple removal debts are representable, but they are unbounded over time, “strict per-pass convergence” is false under concurrent additions or retained failures, and same-key rewrite/removal ordering is unspecified (`plan.md:1266-1318`).

4. PARTIAL — The permanent sentinel can survive `ReadConfirm`’s `%w` wrapper, and transient master-key reads are correctly separated from invalid observed key material (`pkg/configstore/db.go:250-280`; `pkg/configstore/crypto.go:443-461`; `plan.md:1358-1422`). Probe continuation, identity refresh, and confirmed-absence handling are not safe or fully specified.

5. NOT-FOLDED — The proposed bounded transient failure exists in the plan (`plan.md:1405-1410,1585-1589`), but the only production Load caller still treats every non-`ErrConfigDBUnreadable` error as warning-and-proceed (`pkg/daemon/bootstrap.go:45-62`; `pkg/daemon/daemon_run_bringup.go:277-305`). If made fatal, Load occurs before interface naming, managers, and dataplane construction, so it would not strand fxp0 (`pkg/daemon/daemon_run.go:157-177`); the required caller classification is simply absent.

6. PARTIAL — The typed accessor is mechanically addable to `api.Config`, copied into `Server`, and usable by health (`pkg/api/server.go:93-140,324-340,408-425`; `pkg/api/health.go:65-71`). Both callbacks must be wired because the gauge still consumes the aggregate bool (`pkg/api/metrics.go:948-958`); the state accessor does not subsume it. More importantly, the proposed snapshot omits nonterminal confirm persistence debt.

7. PARTIAL — The residual is now accurately broadened (`plan.md:1337-1351,2113-2119`), and the named metric/store documentation surfaces were added. Stale body claims and documentation surfaces remain, including `pkg/configstore/README.md:476-540`, `pkg/api/README.md:30-36`, and the “preserved exactly” claim at `plan.md:2005-2028`.

New findings

MAJOR 1 — The debt-set convergence claim is untenable. The plan creates one removal entry per unresolved resolution and forbids eager clearing (`plan.md:1266-1281,1305-1318`), while the retry loop sleeps outside `s.mu` (`pkg/configstore/store_persist.go:396-405`) and mutation is not gated by degraded persistence (`pkg/configstore/store_lock.go:9-28`). Arms and failed resolutions can therefore add debts indefinitely between passes. A transient or terminal result also retains an entry (`plan.md:1277-1278,1361-1399`), so a pass need not reduce the set at all. The guarantee must be conditional on no new work and successful I/O, or the design needs coalescing, a cap, and bounded per-pass work.

MAJOR 2 — Same-key removal must dominate rewrite. The plan permits rewrite W_B and removal R_B to coexist (`plan.md:1223-1227,1285-1318`) without specifying their order. If B’s tombstone fails pre-rename, disk still contains pending B; executing W_B first durably restores that pending record, and a crash before R_B makes recovery re-arm the already-resolved window (`pkg/configstore/store_persist.go:149-165,231-253`). R_B must run first or subsume W_B, with a crash-between-debts test.

MAJOR 3 — The orphan lifecycle still has a shorter unsafe path. On absent-DB Load with Present(A), the plan leaves A for a later stale drop or keyed resolution (`plan.md:1234-1251`). A real bootstrap/plain commit can supersede it (`pkg/daemon/daemon_apply_commit.go:23-60`), but clearing confirmation returns immediately when no in-memory timer exists (`pkg/configstore/store_commit.go:678-682`). On restart, legacy empty `GuardedHash` or byte-identical content bypasses mismatch rejection (`pkg/configstore/store_persist.go:149-165`; `plan.md:1085-1089`) and can rollback or re-arm A (`pkg/configstore/store_persist.go:171-253`). A known Present(A) must be resolved by every superseding plain replacement, even without an in-memory timer.

MAJOR 4 — Probe-confirmed absence launders an unproven unlink. The four-state machine correctly requires an absent removal retry to call `DeleteConfirm` for the directory-fsync barrier (`plan.md:1266-1271`; `pkg/configstore/db.go:297-315`). Probe-only mode instead says a read-only ENOENT clears the latch and drops the debt (`plan.md:1392-1399,1581-1585`). An external unlink followed by ENOENT and power loss can replay after reboot if the directory entry was never durable. Confirmed absence must reactivate the debt’s absent-state `DeleteConfirm`, not drop it.

MAJOR 5 — Terminal-probe continuation lacks an origin and disposition. A runtime removal debt must resume tombstoning, but a boot-time permanent read failure occurs before the record is classified as resolved, stale, expired-H, expired-non-H, or pending (`pkg/configstore/store_persist.go:136-145`; `plan.md:1490-1497`). The generic “clean read → re-arm retry” rule (`plan.md:1392-1420`) can tombstone a still-pending window, re-arm a resolved record, or discover an H rollback only after managers have started. It also never states that `onDiskArmID` becomes Present(record.ArmID), despite identity updates otherwise being restricted to Load and writes (`plan.md:1218-1227`). The latch needs an explicit continuation kind; repaired boot reads should likely force a restart through normal recovery.

MAJOR 6 — Transient confirm failure still boots open. `ErrConfigDBUnreadable` is explicitly active.json-specific (`pkg/configstore/envelope.go:11-19`), and the daemon’s fatal diagnostic likewise assumes active.json (`pkg/daemon/daemon_run_bringup.go:279-286`). A new confirm-read failure returned by Load therefore falls into the existing warn/proceed branch (`pkg/daemon/bootstrap.go:45-62`). The plan needs a distinct fatal Load error class, daemon classification changes, and updates to `pkg/daemon/bootstrap_test.go:10-36`.

MAJOR 7 — The cause-bearing health snapshot loses an existing degraded cause. The proposed state has only `ActivePersistDegraded` and `ConfirmRecordTerminal` (`plan.md:1423-1457`), while today’s aggregate explicitly includes nonterminal confirmation-removal persistence failure (`pkg/configstore/store_persist.go:342-353`; `pkg/configstore/store.go:152-166`). H2 expands that category to removal and rewrite debts (`plan.md:1305-1322`). Consequently health could report healthy while the aggregate gauge is 1, or “active persistence” would have to misleadingly absorb confirm debt. Add a distinct confirm-persistence-degraded field/cause and define precedence terminal > confirm persistence > active persistence.

MINOR 1 — The staged barrier result is underspecified. A successful tombstone write already establishes the replacement barrier even if the following unlink fails, while the current helper exposes only one aggregate error (`pkg/configstore/store_commit.go:575-590`; `plan.md:1166-1201`). Retaining redundant debt is safe, but it contradicts “retention only when the barrier attempt also fails.” Specify a staged outcome or correct the expectation. The absent no-op must still call `DeleteConfirm`, whose directory fsync supplies the barrier (`pkg/configstore/db.go:297-315`).

MINOR 2 — “Bounded retry” is not implementable reproducibly: no attempt count, total deadline, delay/backoff, jitter policy, cancellation behavior, or test seam is pinned (`plan.md:1405-1410,1585-1589,1816`). Startup cancellation is checked only between phases (`pkg/daemon/daemon_run.go:782-805`), so sleeping inside Load can also delay shutdown.

MINOR 3 — The no-close claim becomes weaker once a terminal latch can keep the observer alive indefinitely. The retry worker is an unjoined plain goroutine with no close signal (`pkg/configstore/store_persist.go:389-405`; `plan.md:1392-1399`). Process exit masks this in production, but repeated Store/daemon lifecycles and tests can leak workers.

MINOR 4 — The documentation sweep remains incomplete. Besides the stale README sections (`pkg/configstore/README.md:476-540`; `pkg/api/README.md:30-36`), existing comments still describe a single unkeyed delete retry (`pkg/configstore/store_commit.go:556-570,667-695,732-735`), and the health contract header remains active-write-only (`pkg/api/health.go:10-16`). These are outside the sweep listed at `plan.md:1968-2002`.

MINOR 5 — The API change is described as a “functional option,” but this server uses fields on `api.Config` (`pkg/api/server.go:93-140`), and existing health/metric tests inject private callbacks directly (`pkg/api/health_test.go:220-275`; `pkg/api/metrics_persist_degraded_test.go:25-27`). Pin a `Config -> NewServer` plumbing test plus daemon wiring of both callbacks at `pkg/daemon/daemon_run_servers.go:370-374`.

NEEDS-REVISION

Codex session ID: 019f9543-bf13-7791-8cce-3a26b0f817fc
Resume in Codex: codex resume 019f9543-bf13-7791-8cce-3a26b0f817fc
