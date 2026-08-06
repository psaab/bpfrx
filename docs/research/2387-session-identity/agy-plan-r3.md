### R1. Deterministic Interning vs. Config-Carried Allocation
* **Rejection of FNV-1a Hash:** **INCORRECT.** The plan's rejection of FNV-1a hashing on the grounds of a "silent $2^{-32}$ hash collision mapping two tenants to one domain ID" is factually wrong. Inspection of [`pkg/config/routinginstanceid.go`](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/pkg/config/routinginstanceid.go#L48-L193) shows that `xpf` already uses `StableRoutingInstanceTableID(name)` (FNV-1a string hashing) for kernel VRF table IDs and enforces `validateRoutingInstanceTableIDCollisionAST` at compile time to **REJECT** any commit where two routing-instances hash to the same ID. Hash collisions are caught deterministically before commit without carrying persistent allocation state.
* **Workability of Config-Carried Allocation:** **UNWORKABLE.** Human-edited Junos configuration text does not carry internal daemon allocation tables. Auto-mutating the config file to persist an allocation table breaks out-of-order local/remote commits, causes split-brain state during HA config sync, and corrupts domain IDs on `rollback` (which restores older configuration text lacking the allocated IDs or carrying stale mappings).

---

### R2. Attack on Version-Gating Fix (§4.3b)
* **(a) Pre-heartbeat / Startup posture:** Defaulting peer version to v1 before receiving a heartbeat turns domain enforcement OFF, leaving VRF traffic unisolated during boot/failover windows. Defaulting to v2 causes false mismatches against legacy peers.
* **(b) Session table contamination across upgrade transition:** Active sessions synced from a v1 peer land in the table carrying `domain 0`. When the peer upgrades to v2 and heartbeats arrive, enforcement flips ON. Existing v1-synced VRF sessions STILL carry `domain 0` in the session table. Domain-0 packets hitting those sessions **MATCH** (fail-OPEN cross-forwarding/hijack), while domain-N packets **FAIL** (dropping legitimate VRF traffic). The plan provides no mechanism to flush or re-tag sessions synced prior to the version flip.
* **(c) Peer flapping / regression:** Flapping heartbeats cause enforcement to toggle dynamically on live session tables, producing unpredictable fast-path lookup behavior.

---

### R3. Ingress-Producer Inventory (§7a)
* **VERIFIED FACTUALLY CORRECT.** Code inspection of [`userspace-dp/src`](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/userspace-dp/src) confirms there is no VXLAN decapsulation engine (the only grep hit is a test filename) and no IP-in-IP decapsulation path ([`PROTO_IPIP`](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/userspace-dp/src/policy.rs) exists only as a policy match protocol and in tunnel config validation). My r2 suggestion of VXLAN and IP-in-IP decap producers was incorrect, and the plan's explicit rejection in §7a is correct.

---

### R4. Rust key.rs Signature Changes
* **VERIFIED IMPLEMENTABLE.** C-P2 and §5 explicitly detail the 4 function signature updates (`reverse_wire_key`, `reverse_canonical_key`, `translated_session_key`, `forward_wire_key`) and the required `egress_domain: u32` parameter threading in [`userspace-dp/src/session/key.rs`](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/userspace-dp/src/session/key.rs#L19-L157).

---

VERDICT: PLAN-KILL

The trigger configuration (overlapping L3 subnets across VRFs with PBR `then routing-instance`) is a niche edge case already mitigated by shipped commit warnings (Track A.1) and logical interface keying in the flow cache (Track A.2). The accumulated cost of Track B — widening `SessionKey` across ~297 literal sites, introducing an unworkable stateful interner, bumping `CurrentHAProtocolVersion`, and altering the core `parseHAProtocolCompatible` upgrade gate predicate — far outweighs the security benefit. Closing #2387 as PLAN-KILL formalizes the shipped Track A.1 commit warning as the permanent operator contract.
