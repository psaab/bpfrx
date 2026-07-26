# AGY adversarial plan-review — round 39 (plan v39 @ 801c9dd3e)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY-WITH-NITS (5/5 folds FOLDED; 3 fresh attacks FAILED — attack 2 carries the prefer-removal recommendation, IS SMR m1). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. Enforceable peer-stop barrier (Codex r38 M1): FOLDED — peer receiver handles incoming sync via `daemon_ha_sync.go:534-578,909-912`; sync apply queue and in-flight flag are unexported private state in `cluster/sync.go:594-616`; public status surfaces report cumulative history metrics only in `cluster/sync.go:191-228` and `cluster/status.go:340-356`.
2. Abandoned-D repair shape (Codex r38 M2): FOLDED — boot recovery guarded-hash check (`store_persist.go:149-165`) skips stale drops on empty/matching hashes and executes the unexpired re-arm or expired revert (`store_persist.go:171-255`), proving pending-shaped dead records re-arm or revert if present.
3. Deadline-split recovery (Codex r38 M3): FOLDED — expired records revert inside boot `Load()` (`store_persist.go:171-228`) and subsequent `ConfirmCommitAs` returns "no pending confirmed commit" (`store_commit.go:729-746`); unexpired records re-arm for the exact remaining duration (`store_persist.go:237-254`) and confirm away cleanly.
4. H-class recovery (Codex r38 M4): FOLDED — `commitWithGenBinding` invokes `clusterTopologyCommitPreflight` (`daemon_apply_commit.go:194-205`), which checks `runtimeClusterActive` (`d.cluster != nil`) and rejects live `chassis cluster` commits (`cluster_topology_preflight.go:59-97`) with `errClusterTopologyRequiresRestart` when the HA runtime is uninitialized.
5. Deadline surface (Codex r38 m1): FOLDED — startup logs remaining interval to journald (`store_persist.go:254-255`); audit `Entry` struct carries no deadline field (`pkg/configstore/journal/journal.go:59-80`); `WriteConfirm` encrypts `confirm.json` via `maybeEncryptTreeJSON` (`pkg/configstore/db.go:199-216`).

(B) Fresh attacks:
1. Peer stop blast radius & restart order:
   - Hypothesis: Stopping the peer `xpfd` process abandons its memory-only retry debts symmetrically, and restarting the peer before local repair classification completes could inject a peer SyncApply mid-repair.
   - Outcome: FAILED. Peer stop is symmetrically benign because process restart cleanly re-derives `confirm.json` state from disk during `Load()` (`store_persist.go:26-255`). Furthermore, gRPC/cluster sync servers are constructed and started only after local `Load()` finishes (`daemon_run.go:586-589,1868`), preventing incoming `handleConfigSync` (`daemon_ha_sync.go:534-578`) until local boot classification completes.
2. Hand-authored `Resolved: true` tombstone burden vs removal:
   - Hypothesis: Hand-authoring a `Resolved: true` record requires schema fields (`Resolved`, `FirstCommit`, `HashBasis`, `Deadline`, `PrevTree`) to satisfy `#5637` validation (`pkg/configstore/db.go:275-281`) and cross-version compatibility, whereas file deletion (`rm confirm.json`) is zero-risk.
   - Outcome: FAILED (attack closed; minor runbook recommendation). The plan explicitly permits removal (`plan.md` lines 3503-3506: "the operator either REMOVES the record (always live-safe, offline too) or writes..."). The runbook should explicitly prefer file removal (`rm confirm.json`) in all manual repair scenarios to eliminate hand-authoring error.
3. H-class recovery interaction with file bootstrap:
   - Hypothesis: H-class recovery's `FirstCommit` revert at `Load()` might fail to trigger day-0 import when `xpf.conf` exists.
   - Outcome: FAILED. Reverting a `FirstCommit` record clears `s.compiled` and sets `s.everCommitted = false` (`store_persist.go:177-184`), which directly satisfies `shouldBootstrapFromFile` (`bootstrap.go:321-334`) and cleanly re-imports `xpf.conf` on startup.

(C) Structure confirmation:
The §4.7 delivery structure stands (2-of-3 majority: PR-1 core accessor, follow-up issue for G+H+H2; r28 (A) dissent remains recorded).

Verdict: PLAN-READY-WITH-NITS
