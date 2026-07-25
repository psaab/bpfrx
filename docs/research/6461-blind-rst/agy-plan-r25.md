# Verdict: PLAN YES

### Design Verification of v9.9.9 Additions

1. **Stable Logical Rule ID Disambiguation ([policies_ids.go](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/dataplane/userspace/policies_ids.go#L101-L110))**:
   - `StablePolicyRuleID` (`<from>-><to>/<name>`) is position-independent as it derives strictly from zone pairs and the rule name, unaffected by positional index shifts.
   - When G2 inserts P1 ahead of P2 with identical content $C$, P1 is assigned `<from>-><to>/P1` and P2 retains `<from>-><to>/P2`. The distinct rule names ensure P1 never cross-selects or invalidates P2's existing entries.

2. **Legacy Peer Suppression via Handshake Capability ([sync_auth.go](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go#L314-L370))**:
   - `pkg/cluster/sync_auth.go` (`performSyncHandshake`) and `sync.go` (`syncMsgAuthHello`) provide a capability handshake exchanging version and feature flags prior to streaming sync frames.
   - Hanging the identity-enforcement capability bit on this handshake allows new senders to reliably detect legacy peers and suppress identity-dependent invalidation/conditional deletes.

3. **Durable Coordinator-Owned `NatHoldEscrow` Boundedness ([mod.rs](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/mod.rs#L403))**:
   - In the event of a permanent operator stop without dataplane re-bringup, the escrow drains on the declared permanent stop signal (full helper teardown).
   - If the daemon process exits, OS memory reclamation cleans up the state; while running, the escrow state is strictly bounded by max concurrent NAT holding allocations. No unbounded leak path exists.
