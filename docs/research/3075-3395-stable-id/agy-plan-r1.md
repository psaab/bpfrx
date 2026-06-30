# AGY adversarial plan review r1 (verbatim)

AGY job `rescue-mr0w8dqr-1ut9yh` (succeeded, exit 0), reviewing
`docs/research/3075-3395-stable-id/plan.md` @ v1 (`027e7c6f7`).

Note: a sibling AGY job (`adversarial-review-mr0wcll0-pk94mc`) mis-targeted a
DIFFERENT worktree (#2387 VRF SessionKey) via the MCP git-diff default and was
discarded. The review below was produced by reading this plan's file content
directly (not a git diff) and verified against the 3075-3395 source files; it is
the canonical AGY r1 verdict.

---

**Verdict: NEEDS-REVISION**

While the overall thesis of the plan—treating zone IDs and policy IDs as two
separate schemes sharing one pattern rather than a unified allocator—is
architecturally sound and correct, the plan contains a critical correctness gap
in the fallback logic, a missing implementation detail regarding the rule
identity handle, and a minor Go constant declaration omission.

## 1. Specific Blocking Items

### Objection 1: Incorrect Fallback Logic for Deleted Rules Causes Misattribution
Plan §5.2/§9 asserts "Deleted-rule fallback: delete the admitting rule; assert
the session falls back to the frozen positional id (today's behavior), never a
wrong rule." This is incorrect and contradicts "never a wrong rule." If a rule is
deleted and the session falls back to its frozen positional ID (e.g. index 5),
and a subsequent reorder shifts another active rule into index 5, the established
session's traffic resolves to and is logged under the NEW rule's name. To
guarantee correct attribution, a deleted rule (stable ID not found in current
PolicyState) must resolve policy_id to 0/unattributed, not the frozen positional
ID. Evidence: policies.go:L1210-1215, entry.rs:L58.

### Objection 2: Missing Rule ID Storage in PolicyRuleCounter
PolicyCounterStore maps rule_id → Arc<PolicyRuleCounter>, but PolicyRuleCounter
itself does not contain the rule_id string. Without storing it (e.g. Arc<str>),
the worker cannot extract the stable rule ID from the bound policy_counter handle
to query current_policy_id_for_rule_id. To avoid a new SessionMetadata field
(per-session memory), modify PolicyRuleCounter to store its rule_id at creation
in rule_hit_counter. Evidence: policy.rs:L1010-1023, policy.rs:L1108-1118,
entry.rs:L125.

### Objection 3: Omission of Go Constant Declarations
ZoneIDReservedMin is referenced in the proposed Go hashing function but does not
exist in the Go codebase; only the Rust ZONE_ID_RESERVED_MIN (policy.rs:L609) is
defined. The plan must explicitly state it needs declaration in pkg/config.

## 2. Pressure-Test Analysis & Findings

1. **Two Schemes vs. One Allocator** — rejection of a single persistent
   allocator is fully justified. Zones: once widened to u16, name-hashing is
   stateless (mirrors #1873); an allocator would force sync/persist/ISSU/rollback
   for zero gain. Policies: the #3063 positional Index contract means policy_id
   on the wire must match the live positional index, so an allocator would not
   make the wire ID content-stable without breaking the contract or requiring
   local re-resolution anyway.
2. **Event-Stream Wire Widening (Same-Host IPC)** — the claim is TRUE. Local Unix
   socket (eventstream.go:L30-35); upgrades STOP→FLIP→START (in-place-upgrade.md
   L93-102) stop the old daemon (killing the helper) before starting the new one;
   socket unlinked+recreated on restart (process.go:L53-61). Stale in-flight
   frames cannot straddle the width change. Clarify the record version is managed
   via ProcessStatus.ConfigSnapshotProtocolVersion over the control socket on
   startup.
3. **Birthday Math + Collision Gate** — folding FNV-1a into [1,65533] yields
   collision ≈0.007% for 10 zones, ≈7% for 100. The pre-expansion group-scoped
   checking holds; mirror validateTunnelEndpointIDCollisionAST (tunnelid.go:L239)
   with View 1 + node0/node1-expanded Views 2/3 for HA symmetry.
4. **Close-Path PolicyState Plumbing** — the plan's estimate was CONSERVATIVE.
   ForwardingState (carrying policy: PolicyState) is ALREADY passed to
   flush_session_deltas (session_delta.rs:L74-75). Accessing current policy IDs at
   close-emit requires NO new structural plumbing.
5. **Migration & Cutover** — accepting the one-time transient is defensible. On a
   standalone node, upgrading the daemon restarts the helper, clearing BPF
   conntrack/SessionTable anyway. On a clustered node, rolling upgrade syncs
   sessions from the peer by name → cleanly mapped to new stable IDs.

## 3. Citation Spot-Check (verified against 49765c603)
All Appendix citations 100% accurate: compiler.go:L183-194,
daemon_ha_userspace.go:L24-30 (sorted 1..N); codec.rs:L338-360,
eventstream.go:L932-933, zones.rs:L40 (u8 chokepoints); policies.go:L194-196,
L243-302 (walkPolicyRuleSlots); policies.go:L198-227, L1201-1215 (#3063).
