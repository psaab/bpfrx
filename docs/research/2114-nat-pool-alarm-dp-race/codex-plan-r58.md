# Codex hostile plan-review — round 58 (plan v58 @ 77720748d)

Task: task-msab180x-ai3rrk (session 019fbd24-7763-74d0-9173-3bb499a5de2f).
Verdict: NEEDS-REVISION (4 MAJOR, 1 MINOR; fold verification 2 PARTIAL / 2 NOT-FOLDED / 1 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — Holding applySem continuously from the CURRENT-config read through ensureFabricIPVLAN closes the A→B apply race (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6352-6361,6592-6598), but the detached callback can acquire after shutdown’s one-shot drain releases applySem and mutate live fabric state during teardown (pkg/dataplane/userspace/maps_sync.go:451-456; pkg/daemon/daemon_run_shutdown.go:50-64,214-230).
2. PARTIAL — The stale, teardown-failure, apply-failure, and session-clear-failure classifications are directionally correct (pkg/daemon/daemon_apply_commit.go:645-708; pkg/daemon/daemon_policy_invalidate.go:242-280), but NEUTRAL has no transition in the still-three-state model, and the reset return is neither classified nor explicitly ordered before mint (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6351-6364,6406-6416; pkg/daemon/daemon_apply_commit.go:636-638).
3. NOT-FOLDED — Receiver-primary rejection can occur while both nodes already hold fully applied intended text; both digests and all apply-health fields remain green while both primary transitions enable live forwarding (pkg/daemon/daemon_ha_sync.go:545-548; pkg/daemon/daemon_ha.go:273-325), and the terminal predicate never rechecks complementary authority (docs/research/2114-nat-pool-alarm-dp-race/plan.md:5152-5160,5287-5295).
4. PARTIAL — A differing stale accepted push is digest-visible, but a provider drop or authority rejection can leave an already text-equal yet unapplied peer without digest divergence (pkg/configstore/store.go:687-689,797-829; pkg/daemon/daemon_apply_commit.go:464-475); ActiveApplied catches it, but v58’s stated digest-triggered re-drive does not (docs/research/2114-nat-pool-alarm-dp-race/plan.md:5152-5158,5329-5332).
5. NOT-FOLDED — With the single-retoken transaction deferred, a background arm can self-register after the manager snapshot but before old-set supersession; its registration is discarded and its old-token completion ignored, leaving count==0, no pending, and lastOK true while work remains live (docs/research/2114-nat-pool-alarm-dp-race/plan.md:5333-5338,6331-6343,6388-6405; pkg/dataplane/userspace/process_status.go:150-198; pkg/dataplane/userspace/maps_sync.go:451-456).

New findings:

MAJOR 1 — M1 is a live-state false green, not a config-text residual. Sender-primary validation plus receiver-primary rejection means both nodes believe they own RG0; promotion sets rg_active and can force VRRP mastership outside the full-apply health publisher (pkg/daemon/daemon_ha.go:273-325). The plan checks election state only before reconvergence, then brackets digests and apply health—not stable complementary authority—so equal intended text can be blessed during dual-active forwarding (docs/research/2114-nat-pool-alarm-dp-race/plan.md:5042-5052,5152-5160,5287-5295).

MAJOR 2 — The M5 callback is neither lifecycle-total nor outcome-truthful. Shutdown can release applySem before the detached callback runs, and ensureFabricIPVLAN itself ignores parent-up failure, returns nil after void address reconciliation, and only logs several address/MTU/up failures (pkg/daemon/daemon_run_shutdown.go:50-64; pkg/daemon/daemon_ha_fabric.go:29-50,78-88,115-147). Consequently the arm can publish success with missing/stale CURRENT addresses or mutate after teardown starts, both invisible to the digest.

MAJOR 3 — A queued local apply remains invisible before semaphore admission. V58 mints only after applySem acquisition while claiming parked DHCP/feed applies read non-success (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6351-6361,6422-6427). A DHCP lease is already changed before applyConfig blocks at the semaphore, and that reapply is required to rebuild address-scoped host-inbound enforcement (pkg/daemon/daemon_dhcp.go:73-90,231-260; pkg/daemon/daemon_apply.go:49-56); after the holder publishes SUCCESS but before the waiter acquires, every predicate field can read green over stale enforcement.

MAJOR 4 — V58 both defers and requires M6’s transaction. The residual calls the single-retoken transaction a precision follow-up, while normative §5.1 still promises atomic supersession/re-registration and §9 requires completion-versus-mint non-stranding (docs/research/2114-nat-pool-alarm-dp-race/plan.md:5333-5338,6402-6405,8052-8054). Without creation/snapshot/retoken/completion ordering, the creation-side interleave above is false green; with it, M6 is not an admitted residual.

MINOR 1 — The new test references are dangling. V58 claims rollback-fork and stale-callback legs (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6375-6378,6597-6598), but §9’s actual mechanism legs cover only callback registration, debt transfer, detach, and authority mechanics—not current-config/applySem/shutdown ordering or rollback NEUTRAL/FAILURE publication (docs/research/2114-nat-pool-alarm-dp-race/plan.md:8047-8062).

Structure confirmation: CONFIRMED — §4.7 still keeps PR-1 as the accessor core and G+H+H2 together in the follow-up (docs/research/2114-nat-pool-alarm-dp-race/plan.md:6144-6187).

NEEDS-REVISION

Codex session ID: 019fbd24-7763-74d0-9173-3bb499a5de2f
Resume in Codex: codex resume 019fbd24-7763-74d0-9173-3bb499a5de2f
