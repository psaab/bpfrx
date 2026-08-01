# AGY adversarial plan-review — round 62 (plan v62 @ fbe9369a8)

Direct agy print-mode invocation from the trusted workspace with --add-dir at a 12m timeout (see reviewer-ids.md infra notes). Verdict: PLAN-READY-WITH-NITS (0 MAJOR, 1 MINOR — the rg_active actuated-state rendering entry, IS Codex m2's territory; folds 6/6 FOLDED; 1 fresh attack FAILED, 1 SUCCEEDED as the MINOR). Structure confirmed. Raw output follows verbatim (file:/// link markup as emitted).

---

(A) Fold verification:
1. FOLDED: docs/research/2114-nat-pool-alarm-dp-race/plan.md:5527-5533,8369-8378 (formal acceptance and §5.1 runbook carry the identical multi-term actuated predicate).
2. FOLDED: docs/research/2114-nat-pool-alarm-dp-race/plan.md:6997-7008 (admission gate closes under debt-ledger lock prior to WaitGroup join; post-join 5s bound disposition abandons at fence checks).
3. FOLDED: docs/research/2114-nat-pool-alarm-dp-race/plan.md:2790-2794,6643-6647 (queued-empty term added; admission token inherits enqueue-reservation monotonic sequence position for total ordering).
4. FOLDED: docs/research/2114-nat-pool-alarm-dp-race/plan.md:6765-6768 (all outstanding aliases are rewritten directly to the new current token at each supersession).
5. FOLDED: docs/research/2114-nat-pool-alarm-dp-race/plan.md:6736-6746 (decision, flag, registration, and launch form one section taken as `m.mu` then ledger lock; reverse order forbidden).
6. FOLDED: docs/research/2114-nat-pool-alarm-dp-race/plan.md:6729-6731,6942,7022,8548 (m1 LinkDel added to error aggregation; m2 pendingHAStateClear added to §9; m3 deadline figures corrected to 3s/67s).

(B) Fresh attacks:
- Admission gate placement: FAILED (The decision, gate check, reservation, and launch execute inside a single atomic section under `m.mu` with `ledger lock` nested inside, preventing any launch interleaving).
- Per-node actuated reads: SUCCEEDED (`rg_active` BPF map state is unrendered on any CLI/health surface, making the acceptance check un-executable without a §5.1 inventory rendering entry).

(C) New findings:
MAJOR:
None.

MINOR:
- docs/research/2114-nat-pool-alarm-dp-race/plan.md:5527-5533,8370-8378 (vs pkg/cluster/status.go:91-105, pkg/cli/cli_show_cluster.go:215): `rg_active` actuated state is unrendered on status surfaces; §5.1 inventory missing rendering entry. The normative runbook (§5.1) and formal acceptance (§9) require operator verification of `rg_active` per-node on each node's own status surface (`show chassis cluster status` or `/health`). However, `rg_active` is internal kernel/BPF state (`pkg/daemon/daemon_ha.go:273`) not exposed in `m.FormatStatus()` (`pkg/cluster/status.go:91-105`) or `/health` (`pkg/api`). §5.1 requires an explicit inventory entry to render `rg_active` on the status/health surface to render the acceptance predicate executable.

(D) Structure confirmation:
The §4.7 delivery structure stands (two-unit split: #2114 PR-1 accessor core + follow-up recovery integrity issue; r28 dissent recorded).

(E) Verdict line:
PLAN-READY-WITH-NITS
