# AGY adversarial plan-review — round 59 (plan v59 @ 5a0df2b2c)

Direct agy print-mode invocation from the trusted workspace with --add-dir at a 12m timeout (see reviewer-ids.md infra notes). Verdict: NEEDS-REVISION (1 MAJOR — the running attempt's trailing SUCCESS publication overwrites the waiter's QUEUED publication, IS part of Codex M4; folds 5/5 FOLDED; 2 fresh attacks FAILED). Structure confirmed. Raw output follows verbatim (file:/// link markup as emitted).

---

(A) Fold verification:
1. FOLDED: `docs/research/2114-nat-pool-alarm-dp-race/plan.md:5331-5333,8019-8022`; cluster status surface in `pkg/cluster/status.go:51-107,196-202` exposes per-RG states via `GroupStates()`, and requiring RG0 election SETTLED with EXACTLY ONE primary matching intended mastership on both nodes eliminates the dual-primary false-green window.
2. FOLDED: `docs/research/2114-nat-pool-alarm-dp-race/plan.md:6668-6681`; the stopping fence re-check is placed under `applySem` at callback entry, and outcome reporting in `pkg/daemon/daemon_ha_fabric.go:29-97` marks the arm FAILED on parent-up, MTU, or address reconciliation failures.
3. PARTIAL: `docs/research/2114-nat-pool-alarm-dp-race/plan.md:2616-2624`; publishing QUEUED before `applySem.Acquire()` in `pkg/daemon/daemon_dhcp.go:73-90` is un-sequenced against a running apply Attempt A's trailing `publish(SUCCESS)`, allowing Attempt A to overwrite QUEUED while Attempt B is still waiting.
4. FOLDED: `docs/research/2114-nat-pool-alarm-dp-race/plan.md:6470-6474`; registration, completion, and mint-boundary supersession all serialize under manager `m.mu` (`pkg/daemon/process_status.go:150-198`, `maps_sync.go:451-456`), and residual (vi) scope remains strictly fail-closed.
5. FOLDED: `docs/research/2114-nat-pool-alarm-dp-race/plan.md:8019-8025,8136-8144`; §9 and acceptance copy gain hybrid-closure legs (h2k), residual enumeration (iv)-(vi), and authority check.

(B) Fresh attacks:
- QUEUED publication vs done predicate timing (stale QUEUED leak across restart): FAILED — process restart re-initializes in-memory daemon state from disk (`pkg/configstore/store_persist.go:26-113`), clearing in-memory QUEUED status so it cannot leak into the new incarnation.
- Authority check timing (pre-settlement read): FAILED — pre-settlement state reads as `StateSecondaryHold` or `StateInit` in `pkg/cluster/status.go:94,200`, which fails the "RG0 election SETTLED with EXACTLY ONE primary" requirement and thus fails closed.

(C) New findings:
MAJOR:
1. `docs/research/2114-nat-pool-alarm-dp-race/plan.md:2616-2624` (referencing `pkg/daemon/daemon_dhcp.go:73-90` + `pkg/daemon/daemon_apply.go`): Running apply's trailing SUCCESS publication overwrites waiter's QUEUED publication. When Attempt B enqueues and writes QUEUED before blocking on `applySem`, an already-running Attempt A finishing its execution writes `SUCCESS` upon completion. Attempt A's `SUCCESS` write overwrites Attempt B's `QUEUED` state while Attempt B is still waiting in the queue, causing the predicate to read green (`SUCCESS`) over stale enforcement until Attempt B executes. Fix: publish status updates using a monotonic apply sequence generation or queue-depth guard so a completing attempt cannot overwrite a higher-generation `QUEUED` state.

MINOR:
None.

(D) Structure confirmation:
The §4.7 delivery structure stands (two units: PR-1 with core `d.dp` accessor + follow-up with G+H+H2; r28 dissent remains recorded).

(E) Verdict line:
NEEDS-REVISION
