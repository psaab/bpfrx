# Codex hostile plan-review — round 61 (plan v61 @ d79c01d40)

Task: task-msaeqb8e-po29bx (session 019fbd83-32f6-7e11-8c7e-337a148da036).
Verdict: NEEDS-REVISION (5 MAJOR, 3 MINOR; fold verification 2 FOLDED / 3 PARTIAL / 2 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:

1. PARTIAL — The four-term topology holds: local show chassis cluster data-plane statistics exposes ProcessStatus.HAGroups[].Active as rg<ID> active=<bool> (pkg/grpcapi/server_show_cluster_text.go:138-147; pkg/dataplane/userspace/format/status_sections.go:329-335), and show security vrrp exposes VRRPInstanceInfo.State (pkg/grpcapi/server_nat.go:341-367; cmd/cli/show_security.go:601-625). Exactly-one rg_active plus explicit loser inactivity rejects ACTIVE+BACKUP/ACTIVE+MASTER. But formal acceptance drops these terms (plan.md:5477-5483 versus 8280-8302).

2. NOT-FOLDED — plan.md:6914-6924 asserts a callback JOIN SET without specifying its tracker, admission-close linearization, or timeout disposition. The callback remains conceptually detached from shutdown’s join machinery (pkg/dataplane/userspace/maps_sync.go:451-456; pkg/daemon/daemon_run.go:115-119), and the five-second drain followed by teardown cannot guarantee a non-contextual callback has stopped (pkg/daemon/daemon_run_shutdown.go:50-64,214-230).

3. PARTIAL — Distinct reservation entries let B and C migrate independently, and exact-entry cancellation needs no tombstone (plan.md:6593-6617). However, reservation sequences and admission tokens “never alias,” leaving “lower identity” undefined across their namespaces, while neither the runbook predicate nor formal acceptance requires the queued set empty or renders it (plan.md:5441-5444,6593-6617,6851-6857,8254-8258). The fieldwise merge therefore remains incomplete.

4. NOT-FOLDED — plan.md:6691-6699 defines only old-token→new-token aliases. Successive supersessions are explicitly possible while manager debt remains live (plan.md:6654-6664; pkg/dataplane/userspace/process_status.go:188-198), but no chain walk, path compression, or old→current rebasing closes A→B→C.

5. NOT-FOLDED — plan.md:6543-6554 still requires registration atomic with the launch decision under m.mu, while plan.md:6673-6684 requires all registration through a separate ledger with m.mu never nested. Today the decision and debt state are m.mu-coupled (pkg/dataplane/userspace/maps_sync.go:353,451-456; pkg/dataplane/userspace/manager_ha.go:78-112,139-150); no relocation or post-unlock canonicalizing handoff is specified.

6. FOLDED — plan.md:6931-6940 requires concrete type plus IPVLAN_MODE_L2 and replacement on either mismatch, matching the desired construction at pkg/daemon/daemon_ha_fabric.go:56-62 rather than today’s parent-only acceptance at :41-53.

7. FOLDED — All four requested textual folds exist: pendingHAStateClear at plan.md:6530-6535, callback legs at :8403-8412, residual alignment at :8285-8288, and daemon_apply.go inventory at :6862-6865. Current corresponding paths are pkg/dataplane/userspace/manager_ha.go:98-151 and pkg/daemon/daemon_apply.go:49-86.

New findings — MAJOR:

MAJOR 1 — Formal acceptance can still false-green the r60 loser construction. Normative text requires exactly one RG0 rg_active, conditional VRRP mastership co-located on the intended node, and explicit loser inactivity both before completion and after reactivation (plan.md:5477-5483). Formal acceptance instead requires only one election primary at plan.md:8280-8284 and later uses an undefined generic “authority check” at :8296-8302. Election can settle while demotion has resigned VRRP but SetRGActive(false) keeps failing (pkg/daemon/daemon_ha.go:340-371,809-848; pkg/daemon/rg_state.go:250-263).

MAJOR 2 — The callback join has no implementable lifecycle protocol. A WaitGroup Add from the detached firing path can race shutdown’s Wait unless a closed/admission gate atomically reserves in-flight work before launch (pkg/dataplane/userspace/maps_sync.go:451-456; pkg/daemon/daemon_run.go:115-119). Moreover, putting callbacks on the existing WaitGroup makes the wait unbounded, while timing the join out after five seconds permits the callback’s non-contextual Link*/Addr* operations to overlap dataplane teardown (pkg/daemon/daemon_ha_fabric.go:23-93,102-148; pkg/daemon/daemon_run_shutdown.go:50-64,214-230). Section 9 tests only teardown between guard and mutation, not admission-versus-close or timeout behavior (plan.md:8403-8412).

MAJOR 3 — QUEUED remains outside the executable convergence predicate. A waiting apply is real before applySem admission (pkg/daemon/daemon_apply.go:49-51,83-86; pkg/daemon/daemon_apply_commit.go:172-175), but plan.md:5441-5444 and :8254-8258 test only failure count, pending arms, and last outcome. Since enqueue sequence and attempt token are separate namespaces (plan.md:6593-6601), no defined generation comparison prevents A’s terminal success from projecting green while B/C remain queued, nor defines restoration after the highest waiter cancels. Require enqueue-reservations==∅ in the predicate/status and B→C migration, cancellation, and A-success/B-queued tests; current §9 lacks them (plan.md:8376-8390,8453-8461).

MAJOR 4 — Alias transitivity is unspecified. After A→B and B→C, a completion carrying A reaches an alias whose B registration has already moved to C. plan.md:6691-6699 promises only that “the aliased old identity” retires the carried registration; it requires neither recursive resolution nor direct rebasing of all historical aliases to C. Because retry debt can remain live indefinitely (pkg/dataplane/userspace/manager_worker_arm_5134.go:38-96), this can strand the current registration forever and an unbounded chain also lacks cleanup bounds.

MAJOR 5 — The separate-ledger fold preserves an atomicity contradiction. OnXSKBound’s readiness decision, one-shot flag, and launch currently occur while m.mu is held (pkg/dataplane/userspace/maps_sync.go:353,451-456; pkg/dataplane/userspace/process_status.go:160-173), while pendingHAStateClear registration/retirement depends on m.mu-protected cluster state and IPC outcome (pkg/dataplane/userspace/manager_ha.go:78-112,139-150). plan.md:6543-6554 requires atomic registration with those decisions, but :6673-6684 forbids nesting the required ledger lock. A specified ownership move or canonicalizing two-phase handoff is mandatory.

New findings — MINOR:

MINOR 1 — Type/mode replacement validation is ambiguous and omits deletion failure. Normative text requires successful replacement (plan.md:6934-6939), but §9 lists “the type+mode mismatch” itself among failures retiring the arm FAILED (:8409-8412), which does not prove successful delete-and-L2-recreate. The supposedly complete aggregation list also omits LinkDel, whose error is discarded today (pkg/daemon/daemon_ha_fabric.go:52-53), and the inventory summary still says KIND only (plan.md:6866-6873).

MINOR 2 — pendingHAStateClear lacks token/ledger acceptance coverage. It is now declared tokened at plan.md:6530-6535, but the mechanism and token tests at :8413-8423 and :8453-8457 omit it. Existing tests cover only boolean debt/retry behavior (pkg/dataplane/userspace/hastate_clear_debt_5487_test.go:15-112; manager_ha_clear_debt_5873_test.go:32-112), not registration, supersession, alias completion, or ledger serialization.

MINOR 3 — The cited 120-second status-poll block is inaccurate. plan.md:6677-6680 and :6881-6884 attribute 120 seconds to the status request, but small requests use a three-second deadline (pkg/dataplane/userspace/process_control.go:34-40,85-103,129-142). Even a maximum 64-MiB apply_snapshot computes to roughly 67 seconds under the current cap/formula (:31,41-56,92-103); the status loop can reach that longer path at pkg/dataplane/userspace/process_status.go:183-186, so the locking concern remains but its evidence must be corrected.

Structure confirmation: §4.7 stands unchanged as core A1 followed by G+H+H2 (plan.md:6353-6396).

NEEDS-REVISION

Codex session ID: 019fbd83-32f6-7e11-8c7e-337a148da036
Resume in Codex: codex resume 019fbd83-32f6-7e11-8c7e-337a148da036
