# AGY Adversarial Review: neighbor-dump race research plan (#1648)

This review challenges the implementation direction of the research plan `docs/research/1648-startup-neigh-race/plan.md` under issue #1648. We pressure-test assumptions, analyze race conditions, and identify hidden operational risks using concrete, line-level codebase evidence from `userspace-dp/src/afxdp/`.

---

## Executive Summary & Verdict

*   **Pivotal Decision:** **PLAN-READY for Gate-R measurement**, but **critical course correction is required before engineering**.
*   **Likely World:** **World 1 (Failover hits ~1.0s, highly production-relevant)**. The assumption that Standby nodes stay warm via passive learning is a fallacy under L2 unicast switching realities.
*   **Pivotal Bug Discovered:** A high-severity bug exists in `initial_neighbor_dump` (`neighbor.rs:434`) where all live multicast neighbor updates (seq = 0) that race the initial dump are **permanently lost**. This bug alone explains the ~1.7s latency, making **5.A.2** the only viable and complete fix, while **5.C.2** is proven to be **conceptually self-defeating** and blind to cold connects.

---

## Hostile Pressure Testing & Verification

### 1. The 1.7s Latency Mechanism: Single Dropped SYN -> Client TCP RTO

The research plan wonders if a flushed/empty kernel table dump (single-digit ms) combined with a fast probe retry schedule ($10/60/260\text{ ms}$) can actually produce a $1.7\text{ s}$ delay. 

We traced `userspace-dp/src/afxdp/poll_descriptor/mod.rs` and `userspace-dp/src/afxdp/neighbor_dispatch.rs` and confirmed that **the $1.7\text{ s}$ latency is indeed a single dropped SYN followed by a client TCP Retransmission Timeout (RTO)**.

#### **Line-by-Line Execution Trace:**
1.  **MissingNeighbor Detection:** When a cold SYN for an on-link target arrives, it hits `ForwardingDisposition::MissingNeighbor` in `poll_descriptor/mod.rs:2379`.
2.  **Kernel Probe Triggered:** It triggers a Raw ICMP probe via `trigger_kernel_arp_probe` in `poll_descriptor/mod.rs:2429`.
3.  **SYN Packet Buffering:** The descriptor is buffered into `binding.pending_neigh` at `poll_descriptor/mod.rs:2652-2660`:
    ```rust
    binding.pending_neigh.push_back(PendingNeighPacket {
        addr: desc.addr,
        desc,
        meta,
        decision: pending_decision,
        flow_key: pending_flow_key,
        queued_ns: now_ns,
        probe_attempts: 0,
    });
    recycle_now = false;
    ```
4.  **Fast Schedule Exhaustion:** The retry logic in `neighbor_dispatch.rs:47` polls the queue. It retries at `10ms`, `60ms`, and `260ms` (`neighbor_dispatch.rs:33-37`). After the $260\text{ ms}$ attempt, **no further probes are fired**; the packet simply sits in `pending_neigh`.
5.  **800ms Expiry & Recycled Drop:** When the elapsed time exceeds `pending_neigh_timeout_ns` (configured to **$800\text{ ms}$** in `neighbor_dispatch.rs:99-103`), the retry logic executes:
    ```rust
    // Timeout: recycle frame and drop.
    if now_ns.saturating_sub(pkt.queued_ns) > pending_neigh_timeout_ns {
        binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
        continue;
    }
    ```
    At `neighbor_dispatch.rs:111`, **the frame is recycled (meaning the SYN is dropped)**.
6.  **Client RTO Trigger:** A dropped SYN forces the client TCP stack to wait for its initial **Retransmission Timeout (RTO)**, which defaults to **$1.0\text{ s}$** on modern Linux/Windows systems.
7.  **Subsequent Resolution:** By the time the client retransmits the SYN at $1.0\text{ s}$, the background kernel ARP probe has long resolved, the netlink thread has populated `dynamic_neighbors`, and the second SYN is forwarded in $<1\text{ ms}$.
8.  **Total Latency:** $1.0\text{ s (RTO)} + 800\text{ ms (first buffer timeout/processing overhead)} \approx 1.7\text{ s}$.

#### **Drop Conditions:**
*   **Hard Drop (Immediate):** If `binding.pending_neigh.len() >= MAX_PENDING_NEIGH` (4096) at `poll_descriptor/mod.rs:2644`, `recycle_now` remains `true` and the SYN is dropped instantly.
*   **Soft Drop (Timeout):** Under normal conditions, the SYN is successfully buffered but is dropped after **$800\text{ ms}$** because the blocked netlink thread fails to write the resolved MAC to the userspace neighbor map.

---

### 2. Failover Impact (World 1 vs. World 2)

**Verdict: World 1 (Failover is affected and hits the 1s latency, making it a critical production fix).**

The plan suggests World 2 is possible because a standby node runs the passive learning path:
```rust
// poll_stages.rs:183
learn_dynamic_neighbor_from_packet(
    area,
    desc,
    meta,
    flow.src_ip,
    last_learned_neighbor,
    worker_ctx.forwarding,
    worker_ctx.dynamic_neighbors,
);
```
Indeed, this function has **no `is_forwarding_active` guard**, meaning the Standby node will actively learn neighbor entries from traffic it observes.

#### **Why World 2 is a Fallacy:**
1.  **L2 Unicast Traffic Isolation:** In active-passive clusters, unicast traffic is directed strictly to the active primary node's port by L2 switches due to standard MAC learning. The standby node **never** receives the unicast RX traffic of active sessions.
2.  **Multicast/Broadcast Limitation:** The Standby node only hears broadcast ARP/NDP requests. If a target is idle (the exact condition of a cold connect), it generates no broadcast traffic.
3.  **Kernel NUD Cache Aging:** Even if the Standby node had learned a neighbor previously, because the Standby node cannot transmit unicast probes (due to HA standby state restricting Tx), any existing entry in its kernel neighbor cache will naturally age out to `NUD_STALE` -> `NUD_FAILED`. This deletion is propagated via `RTM_DELNEIGH` to `dynamic_neighbors`.
4.  **Promote State:** At promotion, the Standby node is guaranteed to have a **completely cold/empty neighbor cache** for any on-link target that has not broadcasted within the last couple of minutes.

Thus, **failover is heavily affected**, and the $1\text{ s}$ penalty is highly production-relevant.

---

### 3. Option 5.C.2 is Conceptually Self-Defeating

**Verdict: 5.C.2 is blind to cold connects and should be rejected.**

Option 5.C.2 proposes: *"At RG-promote, re-warm the on-link hosts that had live sessions before failover (drawn from the synced session table's on-link destinations)."*

This is fundamentally flawed:
1.  **Definition of Cold Connect:** A cold connect, by definition, is a **new connection flow to a destination with no prior session**.
2.  **Self-Defeating:** Because there is **no prior session** in the synced session table for this cold-connect target, 5.C.2 will **never** identify or warm this host. It warms hosts that don't need it (because they already have established session states) and misses the one target we are measuring.
3.  **Existing Redundancy:** Furthermore, `prewarm_reverse_synced_sessions_for_owner_rgs` (`ha.rs:130`, `shared_ops.rs:72`) already runs during promotion to synthesize reverse path resolutions for existing sessions. Adding 5.C.2 adds duplicate lookup complexity with zero benefit for new cold flows.

---

### 4. The High-Severity Multicast Drop Bug in `initial_neighbor_dump`

**Verdict: 5.A.2 is the absolute critical fix. The seq skip bug is 100% verified.**

We analyzed `initial_neighbor_dump` in `userspace-dp/src/afxdp/neighbor.rs:394-460`. The netlink monitor thread binds to the multicast group `RTMGRP_NEIGH` at `neighbor.rs:487`, then immediately calls `initial_neighbor_dump` at `neighbor.rs:514`. 

During the dump, the loop reads from the raw socket using `recv()`:
```rust
// neighbor.rs:406
let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
```
Because the socket is already bound to the multicast group, **any live multicast updates (`RTM_NEWNEIGH`) generated by the kernel (e.g. from our raw ICMP ping probe) are read by this loop**.

However, the loop contains the following sequence-filtering guard:
```rust
// neighbor.rs:425-437
let nlmsg_seq = u32::from_ne_bytes([
    buf[offset + 8],
    buf[offset + 9],
    buf[offset + 10],
    buf[offset + 11],
]);
...
if nlmsg_seq != next_seq {
    offset += (nlmsg_len + 3) & !3;
    continue;
}
```

#### **The Core Bug:**
1.  **Dump Sequence:** The dump sends requests with a non-zero sequence number (`next_seq` starts at `1u32` at `neighbor.rs:400`, increments to `2u32` at `neighbor.rs:460`).
2.  **Multicast Sequence:** All live multicast notifications pushed by the kernel carry **`nlmsg_seq == 0`**.
3.  **Silent Discard:** Because `nlmsg_seq` (0) != `next_seq` (1 or 2), the loop executes `continue` at line 436.
4.  **Permanent Loss:** The packet is read from the socket queue, parsed, and **permanently discarded** without being applied to `dynamic_neighbors`.

#### **Is fixing this (5.A.2) the only viable fix?**
Yes. Even if you move the dump before the worker starts (5.A.1), any resolution that races the dump is lost. Gating worker startup (5.B) doesn't prevent seq-filtered drops. 

By fixing the seq skip in 5.A.2—allowing `nlmsg_seq == 0` messages to be parsed via `parse_neighbor_msg` (which is fully idempotent and safe, `neighbor.rs:297`) instead of skipped—the netlink monitor will instantly capture the resolved ARP/NDP notifications. The SYN packet buffered in the workers will resolve on its very first retry at $10\text{ ms}$, dropping connection latency from $1.7\text{ s}$ to **$<15\text{ ms}$**.

---

## High-Risk Architectural Warnings

1.  **Idempotency of `parse_neighbor_msg`:** If 5.A.2 is shipped, we must ensure that receiving a live multicast update *during* a dump doesn't create race conditions. We verified that `parse_neighbor_msg` (`neighbor.rs:297-362`) uses `update_dynamic_neighbor` and `remove_dynamic_neighbor`, which write to a sharded map. This is thread-safe and safe against duplicate events.
2.  **Egress Interface Resolution for Connected Routes:** In `queue_warm_pass`, the code currently skips `connected_v4` and `connected_v6` interfaces. If we try to warm all connected routes, we risk a probe storm across the entire `/24` or `/64` subnet. We must **never** do broadcast/sweeps. Fixing 5.A.2 makes proactive connected route warming completely unnecessary because on-demand fast-warm will reliably resolve in $<15\text{ ms}$.

---

## Recommendation Matrix for `/engineer`

| Scenario Tested | Action | Expected Latency |
| :--- | :--- | :--- |
| **Restart / Flush + 1st Connect** | Fix **5.A.2** (Accept `nlmsg_seq == 0` in dump loop) | **$<15\text{ ms}$** |
| **VRRP Failover + 1st Connect** | Rely on fixed **5.A.2** on-demand resolution | **$<15\text{ ms}$** |
| **Option 5.C.2** | **REJECT / PLAN-KILL Option** (Self-defeating) | N/A |
| **Option 5.A.1** | **REJECT / PLAN-KILL Option** (Adds blocking time to start path) | N/A |
