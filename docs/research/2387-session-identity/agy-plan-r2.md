# Hostile Adversarial Plan Review (Round 2): `#2387` Session Identity

**Plan Under Review:** `docs/research/2387-session-identity/plan.md` (v6-r2)  
**Target Repository:** `/home/ps/git/bpfrx/.claude/worktrees/2387res` (git worktree `@ origin/master e80db2eae`)  
**Mode:** READ-ONLY code and doc verification pass.

---

## 1. Analysis of Changes in v6-r2 (Items 1–3)

### Item 1: Refutation of Path D & Verification of "Static Deterministic Interning"
* **Finding: FLAWED — MOVES THE HAZARD & CREATES AN HA DESYNCHRONIZATION BUG.**
* **Analysis:** Withdrawing Path D (dynamic overlap-based interning) was necessary due to live-session drops during config commits. However, replacing it with generic "static deterministic interning" without mandating a **global string hash** (e.g., 32-bit FNV-1a of the routing-instance name, reserving `0` for `default`) creates two severe vulnerabilities:
  1. **Config Commit ID Shifting / Recycling:** If dense IDs ($1, 2, 3\dots$) are assigned sequentially per `ConfigSnapshot` compile, adding or deleting a routing-instance re-indexes all RIs. Active sessions in memory carrying old dense IDs will fail fast-path lookups for existing traffic (self-DoS). Furthermore, if a deleted RI’s dense ID is recycled for a new RI, packets in the new RI will match leftover sessions from the deleted RI (cross-tenant session hijack across config commits).
  2. **HA Peer Divergence:** Nodes in a cluster process config commits independently or reboot at different times. If node $A$ builds its interner map sequentially over time as RIs are created/deleted, while node $B$ reboots and builds its interner map from a fresh snapshot, node $A$ and node $B$ will assign **different dense IDs to the same routing instance string**. When node $A$ syncs a session to node $B$ carrying `routing_domain = 2`, node $B$ will match it against a completely different local VRF.
* **Requirement:** The plan must explicitly mandate **cluster-wide string hashing** (e.g., `hash(ri_name) -> u32`, with `0` fixed for `default`), rather than positional sequential indexing per snapshot.

### Item 2: Verification of Ingress Producers Inventory (§7a)
* **Finding: INCOMPLETE INVENTORY.**
* **Analysis:** §7a lists native interface ingress, PBR overrides, GRE decap, fabric ingress, local delivery, transient installs, and peer-synced sessions. It omits the following session-instantiating ingress producers:
  1. **VXLAN Decap & IP-in-IP Tunnel Decap:** Tunnel logical interfaces assigned to non-default routing-instances must derive their domain from `ifindex_to_routing_instance[endpoint.logical_ifindex]`.
  2. **Host-Generated Error/Control Sessions:** Control-plane/dataplane generated flows (such as ICMP Unreachable, ICMP Time Exceeded, or TCP RST generators that instantiate reverse session state) must inherit the domain of the triggering packet's context rather than falling back to `0`.
  3. **Synthetic Translation Flows:** Forward translation session instantiations in NAT64 / NPTv6 pipelines when operating across VRF boundaries.
* **Impact:** Any session admitted by an omitted producer receives `domain 0`, resulting in a fast-path session miss for non-default VRF traffic (a silent self-DoS).

### Item 3: Wire Encoding & Reverse-Key Reconstruction Specification (§4.3 / §4.3a / C-P3)
* **Finding: INCOMPLETE SPECIFICATION.**
* **Analysis:** The plan correctly identifies that `ReverseKey` in `pkg/cluster/sync_protocol.go:440` is a fixed 16-byte block (40 bytes for V6) and that `IngressRoutingDomain` and `EgressRoutingDomain` must be appended as trailing `u32` fields. However:
  1. **Missing Method Signatures in `userspace-dp/src/session/key.rs`:** In Rust, `SessionKey` only contains `routing_domain: u32` (which stores the ingress domain). Key transformation methods such as `reverse_canonical_key(&self)`, `reverse_wire_key(&self)`, and `translated_session_key(&self)` cannot derive the reverse key’s `routing_domain` (which must equal `egress_domain`) without receiving `egress_domain: u32` as a parameter. The plan does not specify the method signature updates required in `key.rs`.
  2. **Wire Offset Formalization:** The plan omits the explicit Go struct wire definitions and byte-offset guards for `encodeSessionV4Payload` / `decodeSessionV4Payload` in `pkg/cluster/sync_protocol.go`.

---

## 2. Analysis of New Material in v6-r2 (Items 4–8)

### Item 4: Verification of Chain Position Claims (#4983 $\rightarrow$ #2387 $\rightarrow$ #5804)
* **Finding: VERIFIED.**
* **Analysis:** Code inspection confirms #2387 imports no symbols, struct fields, or wire protocol constants from #4983. Issue #4983 (true ingress-interface identity) is purely a display/filtering refinement. The claim in §2.5 that #4983 is a sequencing preference rather than a hard technical blocker is factually correct.

### Item 5: Verification of Fail-Closed vs. Fail-Open Mixed-Version Posture (§4.3a)
* **Finding: REFUTED FOR DOMAIN 0 (DEFAULT VRF) OVERLAPPING FLOWS.**
* **Analysis:** §4.3a claims that an omitted trailing field on a peer-synced session decodes to `0` (default VRF) and "never cross-forwards." **This claim is false for overlapping subnets involving `domain 0`**:
  - Suppose an upgraded node receives a synced session $S_{legacy}$ from an un-upgraded peer for a flow in `tenant-a` (VRF $N$). Because the legacy peer omitted the field, the upgraded node decodes `routing_domain = 0` and installs $S_{legacy}$ under `domain 0`.
  - Now, a new flow $F_{default}$ arrives in the **Default VRF (`domain 0`)** with an identical 5-tuple.
  - The upgraded node performs a fast-path lookup for `(5-tuple, domain 0)`.
  - **Result:** $F_{default}$ **MATCHES** $S_{legacy}$! Traffic in the Default VRF cross-forwards using `tenant-a`'s cached egress/NAT/policy decision.
* **Conclusion:** The mechanism is fail-closed for non-default VRFs (`domain N` packets miss `domain 0` sessions), but **fail-OPEN for packets originating in `domain 0`**.

### Item 6: Verification of `performSyncHandshake` Source Code (§4.3a)
* **Finding: VERIFIED.**
* **Analysis:** Inspection of `pkg/cluster/sync_auth.go:330-334` confirms:
  ```go
  key := s.authKey()
  if len(key) == 0 {
      // No local key ⇒ no handshake; legacy behavior (dual-accept).
      return syncAuthUnauthenticated, nil, nil, nil
  }
  ```
  When no local PSK (`authentication-key`) is configured, `performSyncHandshake` returns early without transmitting a `syncMsgAuthHello` frame. An unkeyed cluster executes no connection-setup capability exchange.

### Item 7: Verification of the 1:1 `key_to_handle` Map Constraint (§5)
* **Finding: VERIFIED.**
* **Analysis:** In `userspace-dp/src/session/mod.rs:548`, `key_to_handle` is defined as `SeededKeyMap<u32>` (`HashMap<SessionKey, u32, FxSeededState>`), which is strictly 1:1. In `userspace-dp/src/session/install.rs:139`, `install_with_protocol_with_origin` executes `self.remove_entry(&key)` unconditionally. Without widening `SessionKey`, holding two handles under one 5-tuple forces either a cross-tenant DoS (dropping the second flow) or eviction thrashing (evicting the first flow on every packet). Path B (DENY) is indeed structurally forced into a cross-tenant fault.

### Item 8: Verification of Chain-Wide Byte Budget Arithmetic (§4.4)
* **Finding: VERIFIED.**
* **Analysis:** `SessionKey` field sizes (`addr_family: u8`, `protocol: u8`, `src_ip: IpAddr` [17B], `dst_ip: IpAddr` [17B], `src_port: u16`, `dst_port: u16`) total 40 bytes. Adding `routing_domain: u32` (+4B) grows the struct to 44 bytes (align 4). Adding a second plain `u32` for #5804 (+4B) yields 48 bytes. In Rust, a typed `enum` discriminant requires a tag byte plus alignment padding (4 bytes) and payload (4 bytes), costing 8 bytes total and pushing struct size to 52 bytes. The 40 $\rightarrow$ 44 $\rightarrow$ 48 budget and the 8-byte enum penalty are mathematically and structurally accurate.

---

## Terminal Verdict & Summary

VERDICT: PLAN-NEEDS-REVISION

The plan’s core reachability findings, 1:1 map structural proof, and HA wire length-gating analysis are accurate, but the replacement for Path D lacks a deterministic string-hashing specification to prevent HA sync desynchronization and config-reload ID shifting. Additionally, the mixed-version safety claim in §4.3a is false for Default VRF traffic, the ingress producer inventory in §7a is incomplete, and the key transformation signature updates in Rust remain underspecified.

1. **Mandate Cluster-Wide Deterministic String Hashing for Domain Interning:** Update §5 (C-P0) to explicitly mandate a deterministic string hash (e.g., 32-bit FNV-1a hash of the routing-instance name string, with `0` hardcoded for `default`) rather than positional sequential indexing per snapshot, preventing HA peer interner divergence and ID shifting across config reloads.
2. **Correct the Mixed-Version Safety Posture in §4.3a:** Update §4.3a to acknowledge that legacy-peer synced sessions decoding missing fields to `domain 0` are fail-OPEN against Default VRF traffic sharing the 5-tuple in overlapping subnets, and document the required operational mitigation (e.g., requiring PSK capability negotiation or keying non-default VRFs during mixed-version rolling upgrades).
3. **Complete the Ingress Producer Inventory (§7a):** Add VXLAN/IP-in-IP tunnel decap (`endpoint.logical_ifindex`), host-generated ICMP error/TCP RST session instantiations, and NAT64/NPTv6 forward translation flow generators to the §7a table.
4. **Specify Rust Key Transformation Method Signatures:** Update §4.3 and C-P2 to document signature changes in `userspace-dp/src/session/key.rs` for `reverse_canonical_key(&self, egress_domain: u32)`, `reverse_wire_key(&self, egress_domain: u32)`, and `translated_session_key(&self, egress_domain: u32)` to enable reverse-key reconstruction.
