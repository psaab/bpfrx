# AGY adversarial plan-review — round 56 (plan v56 @ 269b4c70c)

Direct agy print-mode invocation from the trusted workspace with --add-dir at a 12m timeout (see reviewer-ids.md infra notes). Verdict: NEEDS-REVISION (1 MAJOR — the mint-boundary debt query stalls on control-socket IPC under m.mu, process_status.go:160-167, IS Codex M6's territory; folds 8/8 FOLDED; 1 fresh attack FAILED, 1 SUCCEEDED as the MAJOR). Structure confirmed. Raw output follows verbatim (file:/// link markup as emitted).

---

Ask user permission? No, tools are read_file / view_file / grep_search / run_command (if needed for git grep).
Let's check read-only rules: "Read-only — do NOT edit any files."
Let's view plan lines 5000 to 5080.
(A) Fold verification:
1. r55 M1 (provider coherence + success semantics): FOLDED — plan.md:2441-2450,5004-5026 revalidates captured `ss` matching current `getSessionSync()` pointer-wise and requires `QueueConfig` success return (`pkg/cluster/sync_conn_config.go:234-250`) before marker publication under `configSyncMu`.
2. r55 M2 (authority generation): FOLDED — plan.md:2452-2456,5013-5015 adds authority generation to marker claim state, invalidated on RG0 transitions in `pkg/daemon/daemon_ha.go:438-475`.
3. r55 M3 (lock discipline): FOLDED — plan.md:2457-2460,5027-5032 establishes single locked-send owner and lock-assuming marker helper (`pkg/daemon/daemon_ha_sync.go:407-415`), eliminating re-entrant locking on `configSyncMu`.
4. r55 M4 (outer mint enumeration & ordering): FOLDED — plan.md:2466-2476 enumerates all apply paths (`pkg/daemon/daemon_apply_commit.go:331-402,527-575,697`, `pkg/daemon/daemon_apply.go:50-86`), ordering mint after `applySem` admission and before preflight/promotion with terminal outer classification.
5. r55 M5 (OnXSKBound self-registration): FOLDED — plan.md:2477-2483, manager registers arm atomically with launch decision under `m.mu` (`pkg/dataplane/userspace/manager.go:424-434`, `pkg/daemon/daemon_apply_interfaces.go:61,98-100`).
6. r55 M6 (next-mint supersession & debt query): FOLDED — plan.md:2484-2490, new mint atomically supersedes old token's registration set and re-registers outstanding manager debts queried at the mint boundary.
7. r55 M7 (seventh arm terminal failure): FOLDED — plan.md:2491-2497, detach failures in `syncInterfaceAttachments` (`pkg/dataplane/userspace/manager_compile.go:211-214,567-591`) return a terminal pipeline failure in `ApplyConfig` (`pkg/dataplane/userspace/manager.go:348-357`).
8. r55 M8 + M9 + m1 + m2: FOLDED — plan.md:2498-2505,6141-6152 carries no-pending in done predicate across runbook/acceptance/inventory, aligns tri-state to terminal-only, documents 2s `syncWriteDeadline` (`pkg/cluster/sync.go:88`), and adds §9 send-boundary legs.

(B) Fresh attacks:
- Authority generation vs marker lifetime across restart: FAILED — daemon process restart constructs a new `Daemon` instance with `configSyncHasPushed=false` and a fresh `syncPeerConnEpoch` (`pkg/daemon/daemon_ha_sync.go:51-57`), preventing pre-restart claim collisions.
- Debt query blocking on statusLoop socket I/O: SUCCEEDED — `statusLoop` holds `m.mu` across synchronous socket IPC (`m.requestLocked`, `pkg/dataplane/userspace/process_status.go:160-167`), causing debt queries at the mint boundary to stall behind control socket I/O during status polls.

(C) New findings:
MAJOR:
- Debt query at mint boundary stalls on control-socket IPC under `m.mu` (`pkg/dataplane/userspace/process_status.go:160-167`): `statusLoop` holds `m.mu` for the entire duration of `m.requestLocked(ControlRequest{Type: "status"}, &status)`. If the daemon queries manager outstanding debt at the mint boundary by acquiring `m.mu`, the mint boundary must block on socket I/O whenever `statusLoop` is mid-poll. This introduces control-socket IPC latency directly into `applySem`-held apply execution. The plan must specify that manager debt state is read without holding `m.mu` across socket IPC (e.g., via an independent atomic debt mask or releasing `m.mu` during `requestLocked`).

(D) Structure confirmation:
- The §4.7 delivery structure stands (G+H+H2 move together in follow-up unit; r28 dissent recorded).

(E) Verdict line:
NEEDS-REVISION
