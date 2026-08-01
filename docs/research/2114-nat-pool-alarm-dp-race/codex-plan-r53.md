# Codex hostile plan-review — round 53 (plan v53 @ f3f651145)

Task: task-msa556gu-w89iif (session 019fbc8d-7fb1-79c3-9763-8a699152b837).
Verdict: NEEDS-REVISION (4 MAJOR, 1 MINOR; fold verification 1 FOLDED / 4 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — The one-snapshot invariant and regression exist at plan.md:5842-5852,7465-7470, but §5.1 never names the accessor, return type, fields, or replacement call; plan.md:6038-6040 merely says “canonical accessor.” Current reads remain separate at pkg/daemon/daemon_ha_sync.go:550,563 through pkg/configstore/store_format.go:31-36 and pkg/configstore/store.go:797-809. Repository-wide production grep finds no other `ShowActive`/`ActiveApplied` composite reader.
2. PARTIAL — The current-token rule is stated at plan.md:5877-5898,7471-7479, but catch-up and content-dedup completions can occur without an apply in flight at pkg/dataplane/userspace/process_status.go:19-38,73-81,150-186, and the plan never assigns those paths an originating token. Existing APIs are tokenless at pkg/dataplane/apply.go:37-40,130-134, while deferred-MAC debt is an unkeyed boolean at pkg/dataplane/userspace/manager.go:213-225.
3. PARTIAL — XSK liveness and link-cycle rebind are named at plan.md:5883-5890,7471-7475, but the arm inventory is incomplete. `PrepareLinkCycle()` is another commandful void apply-time call at pkg/daemon/daemon_apply_dataplane.go:289-296; it suppresses the control-disable error and only logs `stop_workers` failure at pkg/dataplane/userspace/process_linkcycle.go:145-162. The asynchronous `SetOnXSKBound` callback likewise logs its terminal failure only at pkg/daemon/daemon_apply_interfaces.go:98-109 and pkg/dataplane/userspace/maps_sync.go:451-457.
4. FOLDED — The operative runbook withdraws both old witnesses and names the digest check as the only join at plan.md:4777-4782; formal acceptance and §9 reject tick waiting at plan.md:7244-7260,7462-7464. Remaining tick/no-op mentions are rejection/history, not gates.
5. PARTIAL — Tri-state language landed at plan.md:5893-5899,7475-7479, but runbook and acceptance still omit the no-pending term at plan.md:4913-4919,7331-7350. Surviving text still records NOT-converged as count-incrementing and says every non-converged return increments at plan.md:5862-5876,5900-5909; §9 still makes pending-XSK rejection `count++` at plan.md:7453-7456.

New findings:

MAJOR — The replacement outbound join is not a join. The plan circularly requires the re-convergence commit after the digest observation at plan.md:4777-4782, then defines both observations after re-convergence at plan.md:4801-4808. More fundamentally, the reconciler claims its marker and unlocks before `QueueConfig` at pkg/daemon/daemon_ha_sync.go:462-497; subsequent passes no-op at :479-484 while that claimant may remain paused without a completion handle or time bound. It can resume after both digest reads and obtain a fresh wire generation at pkg/cluster/sync_conn_config.go:230-243. The §9 leg at plan.md:7457-7464 catches only release during the interval, not release after the second read.

MAJOR — The attempt token has no implementable lifecycle. Plan.md:5888-5898 specifies only “monotonic per-apply generation”: it does not define the mint point, owner, type/overflow behavior, expected-arm set, storage, transport, manager/helper-restart inheritance, or process-restart namespace. The tokenless interfaces at pkg/dataplane/apply.go:37-40,130-134 and completion-without-live-apply paths at pkg/dataplane/userspace/process_status.go:19-38,73-81 make stale-completion rejection impossible to audit from the inventory.

MAJOR — Pending state is neither inventoried nor observable. The predicate requires “no pending arm outstanding” at plan.md:5893-5899, but §5.1 inventories only `applyFailureCount` and `lastApplyOK` at plan.md:5812-5822, and the status surface exposes only ActiveApplied, last outcome, and failure count at plan.md:6032-6041. No pending mask/counter, per-arm state, current token, or accessor exists, so the operator cannot evaluate the stated predicate.

MAJOR — Rehabilitation is mathematically incompatible with the sticky counter. The count is process-lifetime and monotonic at plan.md:5812-5815,6034-6038; pending-XSK rejection increments it at plan.md:7453-7456; yet later success allegedly rehabilitates at plan.md:5894-5899,7475-7479 while acceptance requires count zero at plan.md:4918-4919,7331-7334. No decrement or reset exists. The analogous HA-clear retry is asynchronous/log-only at pkg/dataplane/userspace/manager_ha.go:139-150 and pkg/dataplane/userspace/process_status.go:200-207, leaving the same unresolved choice between sticky failure and tokened rehabilitation.

MINOR — v53 claims the publication-method name and seqlock writer double-bump were folded at plan.md:2258-2261, but normative §5.1 specifies only the reader’s version/read/re-read sequence at plan.md:5834-5842. It names neither the outcome-publication method nor the odd-before/even-after writer protocol; plan.md:6038-6040 again says only “canonical accessor.”

Structure confirmation: §4.7 still cleanly assigns A1/core to PR-1 and G+H+H2 together to the follow-up at plan.md:5757-5792.

NEEDS-REVISION

Codex session ID: 019fbc8d-7fb1-79c3-9763-8a699152b837
Resume in Codex: codex resume 019fbc8d-7fb1-79c3-9763-8a699152b837
