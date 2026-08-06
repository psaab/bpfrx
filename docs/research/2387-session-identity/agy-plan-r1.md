# Hostile Adversarial Plan Review: `#2387` Session Identity (`docs/research/2387-session-identity/plan.md`)

**Verified against:** `origin/master` @ `e80db2eae`  
**Repository State:** READ-ONLY inspection verified.

---

### 1. REACHABILITY (Plan §4.1 / §4.2)
**CONFIRMED.**
* **Ordering Proof:** In [userspace-dp/src/afxdp/poll_descriptor/mod.rs:432](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L432), `resolve_flow_session_decision` is called on the established-session fast path and short-circuits immediately on a session hit. PBR evaluation via `ingress_route_table_override` occurs at [poll_descriptor/mod.rs:1327](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1327) on the session-MISS path (as explicitly documented at line 1242 and line 461: *"resolve_flow_session_decision never runs policy evaluation"*).
* **Accepted Config:** In [pkg/config/compiler_validate_vrf_overlap.go:69-239](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/pkg/config/compiler_validate_vrf_overlap.go#L69-L239), `validateVRFOverlap` detects overlapping L3 address space across distinct routing-instances (from member interfaces or PBR filter terms) and emits a commit **WARNING** (lines 211-225), **NOT** a hard reject. The configuration commits successfully.
* **Conclusion:** Two simultaneous flows with an identical 5-tuple across two routing-instances in PBR mode will reach the dataplane, match the bare 5-tuple session table, and inherit the first flow's cached forwarding/NAT/policy decision without ever reaching PBR evaluation. The collision is live.

---

### 2. THE WIRE CLAIM (Plan §4.3)
**CONFIRMED (with strict implementation constraints).**
* **Wire Verification:** In [pkg/cluster/sync_protocol.go:374-498](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/pkg/cluster/sync_protocol.go#L374-L498) (`decodeSessionV4Payload`) and lines 500-630 (`decodeSessionV6Payload`), optional trailing fields are length-gated using `if off+N <= len(payload)` (e.g., lines 440, 452, 458, 471, 477, 481, 487, 493). Unread trailing fields default to 0 without failing payload decoding (`ok = true`).
* **Fixed `ReverseKey` Caveat:** In `sync_protocol.go:440-451`, `ReverseKey` is serialized as a fixed 16-byte block (40 bytes for V6). Widening `ReverseKey` in place would shift offsets for all subsequent fields (`ALGType`, `Generation`, `ConfigEpoch`, `RTFlowSessionID`) and cause wire decoding failures for legacy peers. Carried as two trailing `u32` VALUE fields (`IngressRoutingDomain` and `EgressRoutingDomain`) at the payload end, `CurrentHAProtocolVersion` ([pkg/cluster/heartbeat.go:35](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/pkg/cluster/heartbeat.go#L35)) does **not** move and the ISSU rolling upgrade path remains open.
* **Mixed-Version Window:** Interning the default routing-instance as `domain 0` ensures legacy peers' omitted fields decode as `domain 0`. Non-VRF clusters remain bit-identical. In VRF clusters, peer-synced sessions for non-default VRFs land in `domain 0`, resulting in a fast-path session miss on the upgraded node for domain-N packets, which safely re-establishes the flow via PBR rather than cross-forwarding or blackholing.

---

### 3. THE "NO VIABLE MIDDLE" CLAIM (Plan §5)
**CONFIRMED.**
* **Verification:** [userspace-dp/src/session/install.rs:139](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/userspace-dp/src/session/install.rs#L139) opens unconditionally with `let _previous = self.remove_entry(&key);`.
* **Attack Analysis:** Simply bailing on a cross-domain hit during fast-path lookup forces the packet onto the session-miss path, which executes `install_with_protocol_with_origin`. Because `SessionKey` is the bare 5-tuple, installation unconditionally evicts the incumbent VRF's entry. Colliding flows in different VRFs would evict each other on **every packet**, tearing down SNAT allocations, generating RT_FLOW churn, and swamping HA session sync.

---

### 4. THE DISCRIMINATOR CHOICE (Plan §7)
**CONFIRMED.**
* **Verification:** In [userspace-dp/src/session/key.rs:94-140](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/userspace-dp/src/session/key.rs#L94-L140) (`reverse_wire_key`), conntrack reply matching relies on key symmetry.
* **Symmetry Analysis:** `ingress_ifindex` and `ingress_zone` ([userspace-dp/src/session/entry.rs:25-26](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/userspace-dp/src/session/entry.rs#L25-L26)) are asymmetric across forward and reply directions because reply packets ingress on the egress interface/zone. Placing either in `SessionKey` breaks reply matching. Only `routing_domain` (VRF ID) is symmetric for intra-VRF flows, and swap-derivable (`egress_domain`) for inter-VRF route-leaked flows.

---

### 5. COST ACCOUNTING (Plan §2 / §4.4)
**CONFIRMED.**
* **Count Verification:** `SessionKey` ([userspace-dp/src/session/key.rs:9-17](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/userspace-dp/src/session/key.rs#L9-L17)) is 40 bytes (`size_of::<SessionKey>() = 40`). Adding `routing_domain: u32` grows it to 44 bytes (+10%), staying within a single 64-byte cache line. Rust `SessionKey` references total 743 across `userspace-dp/src/**/*.rs`, and struct literals `SessionKey {` total 291 in source/tests.
* **Mirror Isolation:** Go's `dataplane.SessionKey` ([pkg/dataplane/types.go:6-13](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/pkg/dataplane/types.go#L6-L13)) stays at 16 bytes when the domain is carried in `SessionValue`. Striking the unbacked "~1-3%" perf claim is correct; isolated lookup benchmarks and scale tests are mandatory before commit.

---

### 6. THE FOUR PATHS (Plan §5)
**REFUTED REGARDING PATH D'S STABILITY.**
* **Attack on Path D:** Path D proposes assigning non-zero `routing_domain` IDs only when the compiler detects overlapping subnets. This creates a severe **live-session state hazard**: committing a configuration change mid-flight (e.g., adding or removing a PBR term or interface) alters the compiler's overlap detection, causing routing-domain IDs for active VRFs to change or reset to 0. Active in-memory sessions keyed under old domain IDs will mismatch new packets, dropping established production traffic. Path D must be rejected in favor of static, deterministic domain interning across all routing instances (Path C).

---

### 7. COST/BENEFIT CASE FOR PATH A (PLAN-KILL ANALYSIS)
* **Path A Case:** The bug trigger requires a niche topology (overlapping L3 subnets + PBR `then routing-instance` + simultaneous identical 5-tuples). The firewall already ships Track A.1 commit warnings ([pkg/config/compiler_validate_vrf_overlap.go](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/pkg/config/compiler_validate_vrf_overlap.go)) and Track A.2 logical-ifindex flow-cache keying. Modifying `SessionKey` across 300+ sites touches the core conntrack engine for 100% of production traffic to fix an edge-case configuration. 
* **Evaluation:** Path A is pragmatically strong for single-tenant firewalls. However, because it leaves a genuine cross-tenant session hijack vector in a CLI-accepted config, Path C remains necessary if multi-tenant VRF isolation is a product requirement.

---

VERDICT: PLAN-NEEDS-REVISION

The plan's factual findings regarding PBR ordering, HA wire length-gating, and key symmetry are accurate, but Path D's rollout strategy introduces a severe live-session instability hazard on mid-flight config changes. Furthermore, the plan lacks precise specification for static routing-domain interning and `UserspaceDpMeta` slot population across non-PBR dataplane paths.

1. **Reject Path D Explicitly:** Remove Path D as a rollout option in §5 due to the live-session state instability hazard caused by dynamic config-analysis domain assignment, and mandate pure Path C with static, deterministic dense domain interning across all routing-instances.
2. **Specify Metadata & Dataplane Plumbing Details:** Detail how `routing_domain` is assigned and populated into the dead `UserspaceDpMeta.routing_table` slot (offset 24) across native interface ingress, local delivery, GRE tunnel decap ([userspace-dp/src/afxdp/gre.rs:760](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/userspace-dp/src/afxdp/gre.rs#L760)), and fabric cross-chassis ingress ([poll_descriptor/mod.rs:448](file:///home/ps/git/bpfrx/.claude/worktrees/2387res/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L448)).
3. **Formalize Wire & Reconstruct Logic:** Document the explicit Go wire encoding/decoding for `IngressRoutingDomain` and `EgressRoutingDomain` in `pkg/cluster/sync_protocol.go` alongside the reverse-key domain reconstruction rules in `userspace-dp/src/session/key.rs`.
