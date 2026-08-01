# AGY adversarial plan-review — round 47 (plan v47 @ b677e3a74)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (6/6 folds FOLDED; 2 fresh attacks FAILED; no new findings). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED: Node-lifetime monotonic dispatch epoch is pinned at `pkg/cluster/sync_conn_config.go:281` and `sync_conn_gen.go:340-367` (where `lastAppliedConfigGen` resets) and `sync_conn_read.go:299` (where `ConfigsReceived` increments before disposition), preventing ABA across provider swaps (`pkg/daemon/daemon_apply_tail.go:253-254`); counter==0 AND epoch-unchanged forms a complete quiescence predicate.
2. FOLDED: Done predicate exposes `ActiveApplied` (`pkg/grpcapi/server_show_cluster_text.go:66-74`) and requires `IsConfirmPending() == false` (`pkg/configstore/store_commit.go:796-800`, `pkg/grpcapi/server_config.go:102`) AND `IsDirty() == false` (`pkg/configstore/store_lock.go:334-338`, `pkg/configstore/store_command.go:304-334`); rebuttal holds as failed same-text reapplies leave prior converged enforcement live (`pkg/daemon/daemon_apply.go:56-71`, `pkg/daemon/daemon_apply_dataplane.go:147-159`).
3. FOLDED: Capture surface covers canonical digest and intended text with `.configdb/active.json` fallback, correctly stating JSON envelope limitations (`pkg/configstore/store_command.go:306-309`), encryption behavior (`pkg/configstore/crypto.go:262-285`), and stopped-daemon restore semantics (`pkg/configstore/db.go:105-130`).
4. FOLDED: JOIN-COHERENCE teardown legs (g1) READER-WINS and (g2) STOP-WINS explicitly cover ordering without relying on in-section freezing (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:6628-6640`).
5. FOLDED: `load replace` is dropped; CLI modes strictly enforce `override`, `merge`, or `set` (`cmd/cli/main.go:556-558`).
6. FOLDED: Unscoped claims are qualified to registered readers / dispatched frames (`docs/research/2114-nat-pool-alarm-dp-race/plan.md:1707,6454`), and §5.1 package touch set is consistent (`pkg/configstore`, `pkg/daemon`, `pkg/cluster` touched; `pkg/grpcapi` and `pkg/cli` untouched as relays, `pkg/grpcapi/server_show_cluster_text.go:66-74`).

(B) Fresh attacks:
- Peer-side preflight epoch requirement: FAILED — The peer is stopped immediately following preflight (2a); once stopped, no further dispatches occur on the peer, making peer epoch delta tracking across preflight unnecessary.
- Capture ordering against commit refrain: FAILED — Step (2) explicitly orders "refrain from commits" before fencing/stopping the peer; because the operator controls commit issuance and refrains from commits throughout the runbook, capturing intended digest/text before fencing is sound.

(C) New findings:
None.

(D) Structure confirmation:
The §4.7 delivery structure stands (PR-1 = work item A1 + site conversions + canaries + sampler; follow-up unit = G + H + H2; r28 dissent recorded).

(E) Verdict line:
PLAN-READY
