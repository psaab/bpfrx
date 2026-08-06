### QUESTION 1: Rescoring the Cost & Verdict on PLAN-KILL

**My PLAN-KILL verdict does NOT hold under v6-r4.**

In Round 3, PLAN-KILL was heavily weighted by the cost of an auto-mutating, stateful interner carried in Junos configuration text — a design that created split-brain risks during HA config sync, broken `rollback` semantics, and complex lifecycle state management. 

By replacing the interner with `StableRoutingInstanceTableID(name)` (a pure FNV-1a hash function of the routing-instance name) and extending `validateRoutingInstanceTableIDCollisionAST` at `pkg/config/compiler.go:229` to reject collisions at compile time, v6-r4 deleted the stateful interner, the config-carried table, the never-reissue rule, the flush-on-delete path, restart persistence, and rollback coherence handling.

With those cost items removed, the remaining work consists of:
- ~297 mechanical `SessionKey` struct-literal updates (primarily in test fixtures).
- A pure-function `u32` domain derivation.
- A rolling-compatible bump to `CurrentHAProtocolVersion` (2) paired with `MinCompatHAProtocolVersion` (1).
- A flush of legacy peer-imported sessions on the enforcement transition.
- Updating `parseHAProtocolCompatible` to respect the declared `MinCompatHAProtocolVersion` floor.

Given that #2387 represents a **live cross-tenant session hijacking vulnerability** under overlapping subnets with PBR (which I verified first-hand in §4.1–4.2), and that the implementation cost is now clean, bounded, and state-free, the cost/benefit trade-off flips. PLAN-KILL is no longer justified.

---

### QUESTION 2: The `parseHAProtocolCompatible` Objection

**§3a accurately characterizes the argument, but it is NOT decisive on its own.**

The argument against changing `parseHAProtocolCompatible` (`pkg/upgrade/cluster_cli.go:253`) is that moving from strict version equality (`local == peer`) to a range check (`peer >= MinCompatHAProtocolVersion`) modifies the gate deciding whether releases can undergo rolling upgrades. 

However, this objection is not decisive because:
1. `MinCompatHAProtocolVersion` was **already designed into the codebase** (`pkg/cluster/heartbeat.go:46`) specifically to declare backward compatibility for rolling upgrades across version bumps, but `parseHAProtocolCompatible` previously left it vestigial.
2. Updating `parseHAProtocolCompatible` to evaluate `peer >= MinCompatHAProtocolVersion` does not blindly relax the gate for future releases; it completes the protocol versioning contract as originally intended. Future authors making breaking wire changes will simply set `MinCompatHAProtocolVersion = CurrentHAProtocolVersion`.

---

### QUESTION 3: Verification of §4.3c (Transition Management & FLUSH vs. MARK)

**§4.3c successfully closes the transition hole identified in R2(b).**

1. **Unknown Peer Version Default:** Defaulting to NOT-ENFORCING on startup or heartbeat gaps correctly avoids false mismatches against legacy peers.
2. **FLUSH vs. MARK:** **FLUSH is the superior choice.** Peer-imported sessions are standby replicas on the receiving node (or backup entries in an active-standby cluster). FLUSHing peer-synced entries (`SessionOrigin::is_peer_synced()`, `userspace-dp/src/session/entry.rs:245`) upon the peer upgrading to v2 forces a standard HA bulk resync where sessions are re-imported with valid `routing_domain` IDs. In contrast, the MARK approach would add per-session metadata flags (`is_authoritative_domain`) and branch logic to every fast-path conntrack lookup, leaving legacy non-authoritative entries unisolated in memory until natural expiration.
3. **Resync Storm / Gap Risks:** FLUSHing peer-imported sessions on the standby node does **not** interrupt active traffic on the primary node. Once the peer advertises v2, it immediately streams its active sessions with their new wire fields.
4. **Flapping Protection:** Applying a transition dampener (mirroring the project's existing GARP dampener pattern) prevents flapping heartbeats from causing repeated flush storms.

---

### QUESTION 4: Verification of Shipped A.1 Warning Text & Obligation

**Verified.** In `pkg/config/compiler_validate_vrf_overlap.go:215-224`, the shipped Track A.1 warning explicitly states:

```go
"routing-instance %q (%s) and %q (%s) both carry %s: overlapping L3 across routing-instances is forwarded via PBR but is NOT session-isolated (#2387) — colliding 5-tuples may cross-forward until the session identity is VRF-aware"
```

The commitment that colliding 5-tuples may cross-forward *"until the session identity is VRF-aware"* is an explicit promise in the operator contract. If #2387 were closed via PLAN-KILL, this text would become permanently misleading and would obligate rewriting the warning into a statement of permanent non-support (e.g., hard-rejecting the config or documenting permanent non-isolation).

---

### QUESTION 5: Auditing Revision v6-r4 for New Errors

**No new technical defects were found in v6-r4.**

- **Domain 0 Disjointness:** Non-default routing instances derive their `routing_domain` via `StableRoutingInstanceTableID(name)`, which returns numbers in the reserved kernel table range `[100000, 999999]` (`pkg/config/routinginstanceid.go:22`). Reserving `0` for the default routing instance creates no collision risk with `StableRoutingInstanceTableID`, making domain `0` mathematically disjoint from all configured VRF domain IDs.
- **Existing Infrastructure Alignment:** `userspace-dp/src/session/entry.rs:245` already exports `SessionOrigin::is_peer_synced()`, which directly supports the transition flush logic required by §4.3c without needing new tracking flags.

---

VERDICT: PLAN-READY
The v6-r4 revision successfully eliminates the unworkable stateful interner by leveraging existing compile-time collision machinery (`StableRoutingInstanceTableID`), closes the HA upgrade transition hole via §4.3c, and establishes a clean, rolling-compatible PR series for Track B. Because #2387 addresses a live cross-tenant session hijack vulnerability, this state-free, bounded design is ready for implementation.
