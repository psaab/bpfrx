# Codex hostile plan-review — round 57 RULING (plan v57 @ a4094634c)

Task: task-msa9tymi-t2gw2w (session 019fbd05-a7e8-75b0-a313-3f8dcd345406).
Verdict: NEEDS-REVISION — ruling (A), with the decisive safety argument against (B)-pure: M5 (the stale OnXSKBound closure mutates live fabric kernel state the digest bracket cannot see, daemon_apply_interfaces.go:98-109 + maps_sync.go:451-456 + daemon_ha_fabric.go:41-54,99-148) and M4 (a rollback session-clear failure leaves stale-authorization forwarding, daemon_policy_invalidate.go:242-280 + daemon_apply_commit.go:645-708, while text digests read green). Fold verification 3/3 FOLDED (the v57 consistency folds). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. FOLDED — the acceptance contract includes lock-held single ownership, provider revalidation, success-only publication, and authority generation at docs/research/2114-nat-pool-alarm-dp-race/plan.md:7714-7730; §5.1 inventories daemon state at :6121-6127 and token/debt/detach changes at :6476-6490; §6 records the signature changes at :6841-6846, matching pkg/daemon/daemon.go:420-424, pkg/daemon/daemon_ha.go:438-475, pkg/dataplane/apply.go:37-40,130-134, and pkg/dataplane/userspace/manager_compile.go:211-214,567-591.
2. FOLDED — h2j contains every requested v56-mechanism leg at docs/research/2114-nat-pool-alarm-dp-race/plan.md:7939-7954, and h2i names the contention leg at :7955-7972.
3. FOLDED — the post-reactivation predicate includes no-pending at docs/research/2114-nat-pool-alarm-dp-race/plan.md:5242-5249, and the rendering inventory exposes the token/pending set at :6463-6475.

Ruling: (A). M1-M3 alone could be admitted as digest-visible, re-driveable residuals because the runbook brackets both-node digests and retains the recovery artifact (plan.md:5107-5115,5149-5164), but M5 defeats B’s safe-direction premise: an old OnXSKBound closure captures configuration A, runs outside applySem, and can resume after apply B to restore A’s fabric parent/addresses (pkg/daemon/daemon_apply_interfaces.go:98-109; pkg/dataplane/userspace/maps_sync.go:451-456; pkg/daemon/daemon_ha_fabric.go:41-54,99-148). The predicate hashes configuration text, not that live kernel state (pkg/configstore/store.go:772-829), while the plan has only one per-arm-ID registration (plan.md:6251-6265); therefore a newer callback can retire B’s arm while A remains live. Next round must fold: M1’s bounded generation-correlated receiver-apply ACK—currently only local write success exists and no config ACK wire type exists (pkg/cluster/sync_conn_config.go:234-250,325-395; pkg/cluster/sync.go:38-76); M2’s provider-generation compare/send/publish transaction (pkg/daemon/daemon_ha_sync.go:594-607,658-667,1405-1415); M3’s authority-invalidation/publication transaction (pkg/daemon/daemon_ha.go:438-475); M4’s explicit rollback branch/result accumulator; M5’s unique callback-launch identity plus applySem serialization and post-admission current-payload validation; and M6’s single short-held debt creation/snapshot/retoken/completion transaction (plan.md:6310-6313,6479-6486).

Any construction your ruling does not make safe: current v57 leaves M5 unsafe as described above—successful stale mutation is invisible to the digest bracket and can disrupt the fabric used for heartbeat/VRRP (pkg/daemon/daemon_apply_interfaces.go:17-19). M4 is independently under-specified: rollback has no-op, bootstrap-teardown, apply-failure, and session-clear-failure forks whose errors are only logged (pkg/daemon/daemon_apply_commit.go:645-708); a clear failure can leave traffic forwarding under stale authorization (pkg/daemon/daemon_policy_invalidate.go:242-280) while text digest and applied state are green. Both require the A folds above.

Structure confirmation: CONFIRMED — §4.7 retains PR-1 at docs/research/2114-nat-pool-alarm-dp-race/plan.md:6076-6086, G+H+H2 together in the follow-up at :6087-6101, and the dissent at :6102-6108.

NEEDS-REVISION

Codex session ID: 019fbd05-a7e8-75b0-a313-3f8dcd345406
Resume in Codex: codex resume 019fbd05-a7e8-75b0-a313-3f8dcd345406
