### Adversarial Review Verdict: **PLAN-NEEDS-MINOR**

---

### Numbered Findings

#### 1. Telemetry Over-count on Failed Repair Installs
* **Severity**: MINOR
* **Evidence**: [userspace-dp/src/afxdp/session_glue/mod.rs:1086](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/session_glue/mod.rs#L1086)
```rust
    Some(ResolvedFlowSessionDecision {
        key: flow.forward_key.clone(),
        decision,
        metadata,
        origin: SessionOrigin::ReverseFlow,
        created: true,
    })
```
* **Details**: Under Face (ii) (forward succeeds, reverse fails at cap), a reply packet triggers the userspace repair path via `lookup_forward_nat_across_scopes` and calls `install_reverse_session_from_forward_match`. However, if the reverse session install fails again at capacity, the code in `session_glue` still returns `created: true` unconditionally. This leads to a persistent over-count of the `session_creates` metric and causes `publish_bpf_conntrack_entry` to be called with a non-existent local session.
* **Resolution**: Modify `install_reverse_session_from_forward_match` in [userspace-dp/src/afxdp/shared_ops.rs:702](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/shared_ops.rs#L702) to return `(SessionLookup, bool)` indicating whether the session install actually succeeded. Propagate this boolean to the `created` field in `ResolvedFlowSessionDecision` inside `session_glue/mod.rs`.

---

#### 2. Verification of Flow-Cache NAT Tuple Leak (I2)
* **Severity**: CRITICAL
* **Evidence**: [userspace-dp/src/afxdp/poll_descriptor/mod.rs:1340-1350](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L1340-L1350), [userspace-dp/src/afxdp/flow_cache.rs:227](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/flow_cache.rs#L227), and [userspace-dp/src/afxdp/types/forwarding.rs:277](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/types/forwarding.rs#L277)
* **Details**: We verified that when a forward install fails, the source NAT allocation is rolled back on line 1341. However, control falls through without changing `decision.resolution.disposition`, which remains `ForwardingDisposition::ForwardCandidate`. Because `is_cacheable()` returns `true` for `ForwardCandidate`, the flow cache insertion at line 1996 proceeds with the *rolled-back* NAT decision in place. Since the flow cache has no auto-expiration TTL without config/HA changes, subsequent packets match on the fast path and are rewritten using the rolled-back SNAT tuple. Because the allocator has already marked this port as free, it can assign it to another same-destination flow. This leads to persistent wire-level tuple aliasing and reply misdelivery.
* **Conclusion**: This confirms that the I2 leak is 100% reachable and extremely severe, rendering a counter-only fix (Path C) completely unsafe.

---

#### 3. Seed-Path Buffer Replay Without Session Check (I6)
* **Severity**: IMPORTANT
* **Evidence**: [userspace-dp/src/afxdp/neighbor_dispatch.rs:205-207](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/neighbor_dispatch.rs#L205-L207)
```rust
        let pkt = binding
            .pending_neigh
            .remove(&key)
            .expect("key from this map");
        let mut decision = pkt.decision;
```
* **Details**: When neighbor resolution completes, `neighbor_dispatch.rs` forwards the buffered packet using the saved `pkt.decision` without querying the session table again. If a `MissingNeighborSeed` installation fails at capacity but is still buffered (because buffering is not gated on `pending_installed`), the replayed packet is forwarded on the rolled-back SNAT tuple. Gating the buffering on `pending_installed` is necessary to prevent this.
* **Dwell Accounting Safety**: Discarding the representative packet on failed seed install does not harm the ARP/NDP dwell accounting or cold-start machinery. Probes are still triggered via `trigger_kernel_arp_probe` on line 2276, and subsequent packet attempts will retry the probe or succeed if the table size drops below capacity.

---

#### 4. Hostile-Check on Plan Refutations (a) and (b)
* **Severity**: INFO
* **Evidence**: [userspace-dp/src/session/mod.rs:690-693](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/session/mod.rs#L690-L693) and [userspace-dp/src/afxdp/shared_ops.rs:556](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/shared_ops.rs#L556)
* **Details**:
  * **Refutation (a)**: Correct. Since `install_with_protocol_with_origin` has only one return-false path (`self.len() >= self.max_sessions`), and both installs execute synchronously on a single thread within the same descriptor loop tick, the reverse install cap check is guaranteed to fail if the forward install fails. Thus, the half-open reverse session is unreachable under cap-refusal conditions today.
  * **Refutation (b)**: Correct. When Face (ii) occurs, the forward session's reverse-index is populated during its installation. When a reply packet arrives, it misses the main lookup but is resolved by `lookup_forward_nat_across_scopes` via `find_forward_nat_match` querying `self.nat_reverse_index`. The packet is successfully forwarded using this matched state, meaning the flow does not blackhole but instead degrades to the cold path.

---

#### 5. Preflight Conservatism and Atomicity Invariants
* **Severity**: INFO
* **Evidence**: [userspace-dp/src/afxdp/worker/loop_body/mod.rs:495](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs#L495) (commands) and [userspace-dp/src/afxdp/worker/loop_body/mod.rs:567](file:///home/ps/git/bpfrx/.claude/worktrees/1861-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs#L567) (GC)
* **Details**:
  * **Conservatism**: Preflight `can_admit` charging full slots for replacements is correct and mandatory. Since `install_with_protocol_with_origin` checks the length before calling `remove_entry`, any attempt to bypass this conservatism in the preflight would cause `can_admit` to pass while the install itself fails, triggering a debug panic.
  * **Atomicity**: The table is modified synchronously on a single thread. Since GC and coordinator commands are processed strictly outside the packet polling loop (before `poll_binding` in the worker loop body), the table size cannot change between the preflight check and the second install within a single packet descriptor iteration.

---

### Response to Section 11 Open Questions

* **Q1**: Keep the preflight check conservative to match `install_with_protocol_with_origin`. Otherwise, we risk the preflight passing and the subsequent install failing, violating the impossible-state assert.
* **Q2**: The Cap-1 semantics change (refusing paired flows at `max - 1`) is acceptable Junos-parity behavior. Dropping the packet is far better than having a half-installed session that degrades reply traffic and incurs telemetry skew.
* **Q3**: Safe. Probes are still triggered via raw sockets, and the next packets will continue to trigger probes until the neighbor is resolved. No state leaks occur.
* **Q4**: Preserving the stateless fabric-return forwarding (I7) without a session is correct. The packet has already been validated by an active peer, and dropping it at capacity would cause unnecessary packet loss.
* **Q5**: Recommend fixing the `created: true` over-count as a ride-along in the same PR (see Finding 1).
* **Q6**: The three new counters are correct. They distinguish between preflight drops (`session_install_admission_refused_total`), impossible partial states (`session_install_partial_total`), and non-preflighted at-cap drops (`session_create_drops_total`).
* **Q7**: Correct. There is no gate preventing the cache insertion of the rolled-back NAT state.
* **Q8 (PLAN-KILL)**: The PLAN-KILL case fails because the I2 flow-cache leak is fully reachable, extremely harmful, and persists indefinitely. Path A is required for correctness.
