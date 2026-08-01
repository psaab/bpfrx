# Codex hostile plan-review — round 60 (plan v60 @ e8e8beabd)

Task: task-msadgfd5-g7ntju (session 019fbd62-89bd-7a33-8d3f-f9319bfd146b).
Verdict: NEEDS-REVISION (7 MAJOR, 4 MINOR; fold verification 1 FOLDED / 3 PARTIAL / 1 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. NOT-FOLDED — The actuated wording landed at docs/research/2114-nat-pool-alarm-dp-race/plan.md:5390-5404, but §9 still requires only election state at plan.md:8138-8141. RG0 normally has no VRRP instance (pkg/vrrp/manager.go:929-936; pkg/vrrp/vrrp.go:128-142,170-173), while rg_active and VRRP are exposed through separate local surfaces (pkg/dataplane/userspace/format/status_sections.go:329-335; pkg/grpcapi/server_nat.go:341-367). Even for a VRRP-backed RG, old-node ACTIVE+BACKUP plus new-node ACTIVE+MASTER satisfies “exactly one ACTIVE AND MASTER,” so failed deactivation remains a false green (pkg/daemon/daemon_ha.go:340-371,809-848).

2. PARTIAL — The full runCtx-or-stopping checks and deep errors.Join/FAILED requirements are normative at docs/research/2114-nat-pool-alarm-dp-race/plan.md:6771-6800. runCtx closes the signal-before-stopping window, but check-before-mutation is not atomic with teardown and cannot cover teardown beginning during a netlink operation; shutdown proceeds after its bounded drain (pkg/daemon/daemon_run_shutdown.go:50-64,214-230). §9 also tests only stopping and generic reconciliation failure at plan.md:8260-8264.

3. PARTIAL — QUEUED is genuinely normative in §5.1 at docs/research/2114-nat-pool-alarm-dp-race/plan.md:6492-6515. It remains absent from the formal predicate, rendered status inventory, and §9 tests (plan.md:5366-5374,6726-6734,8112-8116,8305-8313), while its required generation cannot be the token minted only after admission (plan.md:6480-6507).

4. PARTIAL — TOTAL transfer is now normative at docs/research/2114-nat-pool-alarm-dp-race/plan.md:5459-5468,6556-6576. Registration-before-launch plus m.mu serialization makes a registered-but-not-yet-launched arm enumerable, but transfer changes its registration from token A to B while its captured A completion is subsequently ignored (plan.md:6459-6473,6542-6545,6556-6559).

5. FOLDED — Both missing callback files are now inventoried at docs/research/2114-nat-pool-alarm-dp-race/plan.md:6739-6746, and the formal post-reactivation predicate now includes no-pending-outstanding at plan.md:8153-8158.

New findings:

MAJOR 1 — The actuated predicate is both topology-invalid and logically insufficient. Cluster-owned RETH VRRP exists only for RGs greater than zero, and standalone VRRP events are explicitly excluded from cluster ownership (pkg/vrrp/vrrp.go:128-142,170-173; pkg/daemon/daemon_ha.go:478-501), so “RG0 ... VRRP MASTER” is not generally observable. If interpreted as a VRRP-backed RG instead, demotion resigns VRRP before clearing rg_active; a failed SetRGActive leaves the loser ACTIVE+BACKUP while the winner becomes ACTIVE+MASTER (pkg/daemon/rg_state.go:250-263; pkg/daemon/daemon_ha.go:340-371,809-848). Exactly one conjunction is then true despite dual rg_active, for arbitrarily many failed retries. The required predicate is separate exact-one rg_active, exact-one MASTER where applicable, same intended node, and an explicitly inactive loser.

MAJOR 2 — The callback fence remains check-then-act, not lifecycle-total. The plan checks runCtx/stopping immediately before each mutation (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6781-6787), but the netlink mutations are non-contextual calls (pkg/daemon/daemon_ha_fabric.go:29-93,102-148). A signal can arrive after the check; if the call exceeds the five-second drain, dataplane teardown proceeds concurrently (pkg/daemon/daemon_run_shutdown.go:50-64,214-230). A teardown-serialized callback lease/join is required; repeated atomic loads cannot establish the claimed “never mutating” invariant.

MAJOR 3 — The generation model is internally impossible. The attempt generation is minted after applySem admission (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6480-6491), yet QUEUED is published before admission tagged with “its attempt generation” (plan.md:6492-6507). Reserving that token early reintroduces waiter-before-runner supersession and permits enqueue/admission inversion; retaining the admission mint requires a distinct queue-reservation sequence. The seqlock version is necessarily another counter because it double-bumps every snapshot write, not every attempt (plan.md:6346-6373). The plan must define all three identities and their mapping.

MAJOR 4 — The lower-generation guard has no safe whole-snapshot semantics. The plan promises one coherent snapshot, then says a lower-generation publication never overwrites a higher-generation state (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6346-6373,6505-6512). If running A’s terminal FAILURE arrives after B publishes QUEUED, dropping A wholesale loses the process-lifetime failure-count increment; applying A wholesale can erase B’s queued reservation. Fieldwise monotonic merging is required. Formal acceptance and observability compound the hole by containing no queued set/count at plan.md:5366-5374,6726-6734,8112-8116.

MAJOR 5 — Debt transfer retokens registration but not completion. Arms complete using their captured `(token, arm-ID)`, and unregistered completions are ignored (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6459-6473,6542-6545); the public manager calls explicitly gain token parameters (plan.md:7153-7156). If B mints after arm A is registered but before its goroutine executes, transfer creates `(B,id)`, while completion `(A,id)` is ignored and `(B,id)` remains permanently pending. Serialization prevents omission, not this identity mismatch; transfer needs a stable debt handle or explicit completion alias.

MAJOR 6 — The locking requirements contradict each other. Supersession, registration, and completion must serialize through manager m.mu at docs/research/2114-nat-pool-alarm-dp-race/plan.md:6569-6572, while the mint query must use a short-held ledger and never block behind control IPC at plan.md:6752-6757,8270-8275. Today the status loop holds m.mu across requestLocked (pkg/dataplane/userspace/process_status.go:160-167), whose round trip may block for 120 seconds (pkg/dataplane/userspace/process_control.go:52-56,129-142). The plan must specify a separate ledger lock and lock order, or explicitly design the IPC/m.mu refactor.

MAJOR 7 — “KIND” does not close wrong-IPVLAN acceptance. The desired link is specifically IPVLAN_MODE_L2 (pkg/daemon/daemon_ha_fabric.go:56-62), whereas v60 requires only a KIND check (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6794-6800). A same-parent IPVLAN in L3/L3S mode has the correct kind but wrong forwarding semantics and can still be reconciled and retired SUCCESS. Acceptance must validate both netlink type and mode, replacing a mismatched link.

MINOR 1 — The claimed complete manager-debt inventory is literally incomplete. pendingHAStateClear is explicit asynchronous retry debt (pkg/dataplane/userspace/manager.go:227-236; pkg/dataplane/userspace/manager_ha.go:98-151; pkg/dataplane/userspace/process_status.go:200-207) but is absent from the six-arm list at docs/research/2114-nat-pool-alarm-dp-race/plan.md:6432-6451. Its originating apply fails terminally, so this is not independently false-green; narrow “every live manager debt” or include it.

MINOR 2 — §9 does not verify v60’s full callback fold. It checks mismatch, stopping, and generic creation/reconciliation failure (docs/research/2114-nat-pool-alarm-dp-race/plan.md:8260-8264), omitting the early runCtx fence, a teardown beginning between guard and mutation, and operation-by-operation error aggregation required at plan.md:6781-6799.

MINOR 3 — Formal acceptance still says residuals “(iv)-(vi)” remain (docs/research/2114-nat-pool-alarm-dp-race/plan.md:8143-8145), contradicting the explicit withdrawal of residual (vi) at plan.md:5459-5468.

MINOR 4 — The changed-file inventory remains incomplete for QUEUED: both direct semaphore-entry wrappers in pkg/daemon/daemon_apply.go:49-86 require pre-wait publication and admission transition, but §5.1 has no corresponding changed-file entry; it only cites that file while describing token entry points at docs/research/2114-nat-pool-alarm-dp-race/plan.md:6480-6498.

Structure confirmation: CONFIRMED — §4.7 still ships A1 as PR-1 and keeps G+H+H2 together in the follow-up at docs/research/2114-nat-pool-alarm-dp-race/plan.md:6284-6309; §9 JOIN-COHERENCE remains intact at plan.md:8172-8221.

NEEDS-REVISION

Codex session ID: 019fbd62-89bd-7a33-8d3f-f9319bfd146b
Resume in Codex: codex resume 019fbd62-89bd-7a33-8d3f-f9319bfd146b
