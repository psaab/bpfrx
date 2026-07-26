# Codex hostile plan-review — round 38 (plan v38 @ 95866d9c3)

Task: task-ms23q2tu-8exsvf (session 019f9f93-feb3-71f2-ab29-9405df34aaf1).
Verdict: NEEDS-REVISION (4 MAJOR, 1 MINOR; fold verification 1 FOLDED / 2 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. NOT-FOLDED — D records only process-local logical supersession, not durable resolution (`plan.md:3113-3124,3256-3268`). If tombstone creation fails and D is abandoned at shutdown, sanctioned repair can expose the original pending record; successful Load may re-arm or revert it (`plan.md:3383-3407`; `pkg/configstore/store_persist.go:149-165,171-255`).
2. NOT-FOLDED — Original-remaining re-arm and bare-commit mechanics are correct (`pkg/configstore/store_persist.go:231-253`; `pkg/cli/cli_config.go:257-271`), but the named deadline-fired residual has already expired and reverts before re-arm (`store_persist.go:171-228`), while H’s FirstCommit+cluster state cannot be live re-committed (`plan.md:1925-1929`; `pkg/daemon/cluster_topology_preflight.go:59-97`).
3. FOLDED — Both stale two-writer claims exist at `pkg/fsatomic/fsatomic.go:1-4` and `pkg/fsatomic/README.md:3-12`; both updates are explicitly inventoried at `plan.md:4272-4285`.

New findings:

MAJOR — The mandatory cluster-sync quiescence step is neither operator-observable nor an ingress fence (`plan.md:3422-3436`). The actual apply flag and queue are private (`pkg/cluster/sync.go:594-616`), while public statistics and status expose only cumulative/history data (`pkg/cluster/sync.go:191-228`; `pkg/cluster/status.go:340-356`). Reconnect, promotion, and the reconciler remain active producers (`pkg/daemon/daemon_ha_sync.go:417-430,500-522,926-956`). “Peer stable” therefore does not prevent a later SyncApply, and no surface proves completion of the requested retry pass. An enforceable disconnect/barrier or an explicit observable join protocol is required because the residual is not benign.

MAJOR — The benign-D proof conflates a persisted tombstone with a repaired original record (`plan.md:3437-3449`). Tombstone-success/delete-failure is safe because the readable record is `Resolved`; tombstone failure instead leaves the original unreadable pending record. After D disappears on stop and the operator performs the sanctioned repair-to-valid (`plan.md:3383-3407`), successful Load runs the recovery total order, not seeded-orphan handling (`plan.md:3700-3707`). Legacy-empty or same-content hashes can then bind and replay the resolved window (`plan.md:2059-2067`; `pkg/configstore/store_persist.go:149-165,171-255`).

MAJOR — The mid-fence deadline recovery instruction is false in both normative and acceptance copies (`plan.md:3437-3459,5311-5317`). A deadline that fired before shutdown is already past at restart, so Load immediately reverts and never re-arms (`pkg/configstore/store_persist.go:171-253`). Bare confirmation then returns “no pending confirmed commit” (`pkg/configstore/store_commit.go:729-746`). The runbook must distinguish future/still-pending records from expired/already-reverted records and restore the intended configuration in the latter case.

MAJOR — H’s instruction to “RE-COMMIT after the revert” is not a supported live recovery path (`plan.md:3460-3464`). H leaves compiled configuration nil and constructs no cluster manager (`plan.md:1925-1929`; `pkg/daemon/daemon_run_bringup.go:161-165`). A subsequent clustered commit is rejected because the runtime is absent (`pkg/daemon/daemon_apply_commit.go:194-205`; `pkg/daemon/cluster_topology_preflight.go:59-97`). The plan must name the existing `xpf.conf` boot import or an offline seed-and-restart workflow (`plan.md:4032-4056`).

MINOR — “Read the deadline from the record/journal” lacks a pinned operator surface (`plan.md:3451-3455`). Audit journal entries have no deadline (`pkg/configstore/journal/journal.go:59-80`; `pkg/configstore/store_commit.go:495-499`), and `confirm.json` may be encrypted (`pkg/configstore/db.go:199-216`). Only the startup log exposes the remaining interval (`pkg/configstore/store_persist.go:254-255`); the runbook should name journald explicitly.

Structure confirmation: CONFIRMED — PR-1 remains the synchronized-accessor core, with G+H+H2 together in the follow-up (`plan.md:4188-4231,5368-5377`); v38 is documentation-only.

NEEDS-REVISION

Codex session ID: 019f9f93-feb3-71f2-ab29-9405df34aaf1
Resume in Codex: codex resume 019f9f93-feb3-71f2-ab29-9405df34aaf1
