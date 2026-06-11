# Hostile Plan Review (Round 2) — Verdict: **PLAN-READY**

We have completed the adversarial review of the Transactional Session Install Plan (v3, commit `9fae7bfd8451`). Below is the verification of the v3 deltas and details on the six requested points with quoted file:line evidence.

---

### 1. §5.4 Cache-Eligibility Gate: Soundness, Minimality, and Sessionless Caching

The cache-eligibility gate in §5.4 is **sound and minimal**. It successfully prevents caching of decisions whose backing session installs were refused at capacity, without breaking any legitimate sessionless flows.

*   **No sessionless caching leak (`install_failed` vs. backing sessions):**
    *   **Tracked Flows (Hit Path):** In [session_glue/mod.rs:1006](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/session_glue/mod.rs#L1006), if a session already exists (`lookup_session_across_scopes` matches), a `ResolvedFlowSessionDecision` is returned with `created: false` and `install_failed: false`. A session is guaranteed to back this decision.
    *   **Tracked Flows (Repair Path):** In [session_glue/mod.rs:1081](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/session_glue/mod.rs#L1081), `install_failed` propagates `!installed` from `install_reverse_session_from_forward_match`. If the install succeeds, `install_failed` is `false` and a session backs it. If the install fails, `install_failed` is `true` and the decision is excluded from the cache.
*   **Legitimate Sessionless/Untracked Caching is Unbroken:**
    *   **`dns_fastpath_admit`:** When `dns_fastpath_admit` is `true`, `track_in_userspace` is `false` ([poll_descriptor/mod.rs:1258-1260](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1258-L1260)). No userspace session is installed. In Path A, the preflight check is skipped (`needed == 0`). `resolve_flow_session_decision` is never hit because no session lookup matches, meaning `install_failed` is never set to `true`. Thus, the flow cache is populated normally at [poll_descriptor/mod.rs:2016](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2016) based on `should_cache`, keeping the fast path active.
    *   **`LocalDelivery`:** `ForwardingDisposition::LocalDelivery` is explicitly excluded from the flow cache by `is_cacheable()` in [types/forwarding.rs:274-279](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/types/forwarding.rs#L274-L279). It never populates the flow cache regardless of this gate.
    *   **`fabric-return`:** When a fabric-return session install fails at capacity, the code hits `continue` at [poll_descriptor/mod.rs:508](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L508), skipping the flow cache population at line 2016. If it succeeds, subsequent packets hit the session lookup and get cached normally (`install_failed = false`).

---

### 2. I4/I5 "PARTIAL Self-Heal" Rewrite Accuracy

The rewrite of the **I4/I5 self-heal** mechanics is **accurate**. 
*   **Today's Bug (v1/v2):** When a reverse session install fails at capacity (either on the new-flow reverse arm or during reply repair), `resolve_flow_session_decision` returned `created: true` unconditionally and forwarded the packet. The reply decision was immediately cached at [poll_descriptor/mod.rs:2016](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2016). Subsequent replies matched in the flow cache (Step 1 fast-path) and never hit `resolve_flow_session_decision` again. Thus, the reverse session was **never** installed even if the table later freed up capacity.
*   **Correction in v3:** Gating the cache entry on `!decision_install_failed` guarantees that a failed repair install leaves the reply on the slow path. The repair will re-fire on every packet until the table capacity drops below `max_sessions`, at which point the install succeeds, gets cached, and restores the self-healing property.

---

### 3. Pool-Mode-Only Scoping of I2 Correctness

The scoping of the dynamic allocator desync to **pool-mode SNAT only** is **correct**.
*   **Static NAT and DNAT:** Do not maintain dynamic allocator tables, port pools, or lease states at runtime. They are lookup-only mappings compiled from policy.
*   **Interface-mode SNAT:** In [nat/source.rs:442-452](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/nat/source.rs#L442-L452), interface mode allocates no port and returns a `NatDecision` with `rewrite_src_port: None`. As a result, when rolling back or releasing, `release_source_nat_allocation_with_mode` returns early at [nat/source.rs:350-351](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/nat/source.rs#L350-L351):
    ```rust
    let Some(rewrite_src_port) = nat.rewrite_src_port else {
        return;
    };
    ```
    No rollback occurs, no lease is cleared, and no desync is possible.
*   **Pool-mode SNAT:** In contrast, pool-mode SNAT translates the L4 port dynamically ([nat/source.rs:453+](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/nat/source.rs#L453)) and registers the flow in `pool_allocator`. A failure to roll back in this mode desynchronizes the allocator's free list from the wire tuple, which makes the scoping of the I2 leak to pool-mode correct.

---

### 4. Row I14: NAT64 Rollback on Refusal

Nothing in the NAT64 path requires rollback on refusal.
*   **Stateless allocation:** In [nat64.rs:97-105](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/nat64.rs#L97-L105), `allocate_v4_source` is a stateless round-robin address selection from the configured pool using an atomic counter:
    ```rust
    let idx = prefix.pool_index.fetch_add(1, Ordering::Relaxed);
    let addr = prefix.pool_v4[idx % prefix.pool_v4.len()];
    ```
    No state maps the flow to the selected IP at runtime; there is no allocation table, lease tracking, or reservation to roll back.
*   **Flow cache exclusion:** `FlowCacheEntry::should_cache` explicitly checks `!decision.nat.nat64` at [flow_cache.rs:229](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/flow_cache.rs#L229), preventing any NAT64 decision from ever being persisted statelessly in the flow cache. 
Thus, a refused NAT64 flow behaves strictly per-packet (analogous to stateless forwarding) with no persistent state leak.

---

### 5. Remaining Missing Interleavings or Column Errors

*   **No missing interleavings:** We traced the codebase for all occurrences of `install_with_protocol_with_origin`. They map 1:1 to the scenarios listed in the table (including fabric-return `I7`, LocalMiss `I8`, HA syncs `I11-I13`, and MissingNeighborSeed `I6`).
*   **Correctness of Row I6:** In [poll_descriptor/mod.rs:2504-2513](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L2504-L2513), if the `MissingNeighborSeed` install fails, the source NAT is rolled back, but the code falls through to buffer the packet at line 2536 (`if let Some(hop) = pending_decision.resolution.next_hop`). The buffered frame is later replayed without a session using the rolled-back SNAT tuple. Gating the buffering block on `pending_installed` as proposed in §5.3 completely resolves this leak.

---

### 6. Final Verdict: **PLAN-READY**

The draft v3 plan is technically sound, correctly scoped, and addresses all edge cases identified in prior rounds. No files have been modified.
