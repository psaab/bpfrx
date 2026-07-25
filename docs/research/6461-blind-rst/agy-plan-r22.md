### Defensive Firewall DoS-Hardening Design Review (#6461 v9.9.5.1)

1. **Rule Identity Invalidation Predicate ([policies_ids.go](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/policies_ids.go))**:
   - `policies_ids.go` currently defines `StablePolicyRuleID` (`fmt.Sprintf("%s->%s/%s", ...)` string) and positional numeric IDs (`PolicySetID*MaxRulesPerPolicy + RuleIndex`).
   - A content-addressed rule hash does **not** exist in `policies_ids.go` or the policy compiler today and **must be added** to compiler snapshot generation.
   - Existing aliases (`PolicyIDsByStableKey`, `RuntimePolicyIndex`) still carry positional numeric IDs; the invalidation predicate must consult the content-addressed rule hash + snapshot forwarding generation rather than these positional IDs.

2. **Per-Entry Owner-Gated Invalidation Delete Sync**:
   - In a dual-active window (both nodes claiming RG2 during failover), both nodes invalidating E1 is correct because E1's admitting rule is stale/invalidated on both nodes.
   - However, Node A's deletion sync for E1 can kill Node B's live E2 sharing the key if delete sync messages match purely on 5-tuple lookup without validating a unique session cookie/generation ID.

3. **Single-Winner Terminal Transition & Worker Crash Lifecycle**:
   - When a worker claims a pending entry, retains a token, and dies before the `claim_state` recheck, both RAII token drop and keeper permit expiration trigger.
   - If RAII drop does not disarm the permit expiration timer (or vice versa), keeper slot cleanup causes a **double-release** of the pending map slot, creating a race condition against subsequent worker allocations.

**Verdict: PLAN YES**

*Findings:*
1. **Rule Hash Required**: `pkg/dataplane/userspace/policies_ids.go` lacks a content-addressed rule hash and must be extended to compute and store rule hashes alongside forwarding generations.
2. **Session Cookie Guard in Sync**: Invalidation delete sync messages must carry unique session cookies to prevent cross-node deletion of aliased live sessions ($E2$) during dual-active failover windows.
3. **Timer Disarm on RAII Drop**: Token RAII drop must disarm the keeper permit expiration timer to prevent double-releasing pending map entries.
