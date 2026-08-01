# AGY adversarial plan-review — round 61 (plan v61 @ d79c01d40)

Direct agy print-mode invocation from the trusted workspace with --add-dir at a 12m timeout (see reviewer-ids.md infra notes). Verdict: PLAN-READY (7/7 folds FOLDED; 3 fresh attacks FAILED — including its alias-collapse analysis matching the pin; no new findings). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED — The multi-term actuated predicate (RG0 rg_active=1 on winner, VRRP MASTER=1 on winner for VRRP-backed RGs, both on intended node, loser explicitly inactive) closes the ACTIVE+BACKUP-loser construction; per-node actuated state is observable today on each node's surface via gRPC `GetVRRPStatus` (`pkg/grpcapi/server_nat.go:341-374`, `pb.VRRPInstanceInfo.State`), CLI `show chassis cluster status` (`pkg/cli/cli_show_cluster.go:220-263`), `cluster.Manager.FormatStatus` (`pkg/cluster/status.go:12-25`), and `userspace.ProcessStatus.HAGroups` (`pkg/dataplane/userspace/process_status.go:208`).
2. FOLDED — In-flight fabric callbacks are included in the shutdown's join set via WaitGroup lifecycle tracking before dataplane teardown, with the 5s drain timeout (`applyCloseoutDrainTimeout = 5s`) serving as safety net; consistent and implementable (`pkg/daemon/daemon_ha_fabric.go:29-93`, `pkg/daemon/daemon_run_shutdown.go:50-64,214-230`).
3. FOLDED — The three identities (enqueue-reservation sequence, admission attempt token, seqlock version) are non-aliasing and distinct; queued entries migrate atomically at admission under `applySem`, and fieldwise merge accumulates `failureCount` monotonically across terminal failures while per-attempt state fields are generation-guarded (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:6593-6638`, `pkg/daemon/daemon_apply_commit.go:102-175`).
4. FOLDED — Carried-forward registrations record the alias `(old-token, arm-ID) -> (new-token, arm-ID)` so completions for in-flight arms carrying old tokens retire the aliased registration without stranding (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:2737-2742,6691-6700`).
5. FOLDED — A dedicated short-held debt-ledger lock serializes registration/completion/supersession without nesting with `m.mu` or holding across control-socket IPC (`requestLocked`), obeying lock order `applySem -> ledger lock` (`pkg/dataplane/userspace/process_status.go:160-167`, `pkg/dataplane/userspace/process_control.go:52-56,129-142`).
6. FOLDED — Acceptance validates both link type ("ipvlan") and mode (`IPVLAN_MODE_L2`) and replaces any mismatched link (`pkg/daemon/daemon_ha_fabric.go:56-62`, `docs/research/2114-nat-pool-alarm-dp-race/plan.md:6934-6942`).
7. FOLDED — `pendingHAStateClear` added to arm inventory (`pkg/dataplane/userspace/manager.go:227-236`, `manager_ha.go:98-151`), §9 callback legs updated, acceptance aligned to (vi) withdrawal, and `daemon_apply.go` added to §5.1 inventory (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:2757-2764,6862-6865`).

(B) Fresh attacks:
- Queued-entry migration: FAILED — Enqueue sequences $S_k$ are strictly ordered and admission is serialized under `applySem`; migrating $S_B \to T_B$ then $S_C \to T_C$ preserves order and identity, while cancellation before admission simply removes $S_k$ from `queuedSet` without minting an attempt token or leaving a tombstone.
- Alias chain: FAILED — Re-registering carried-forward debts under the new token $T_{new}$ at supersession (or updating the alias mapping `alias[oldToken] = currentToken`) under `ledger.mu` collapses alias lookups to $O(1)$, ensuring completions carrying oldest tokens retire carried registrations across multiple supersessions ($A \to B \to C$).
- Delta regressions / earlier rounds: FAILED — All locking, lifecycle, and identity invariants in v61 are consistent with codebase implementation constraints.

(C) New findings:
NONE

(D) Structure confirmation:
The §4.7 two-unit delivery structure stands (core PR + G+H+H2 follow-up unit; r28 (A) dissent remains recorded).

(E) Verdict:
PLAN-READY
