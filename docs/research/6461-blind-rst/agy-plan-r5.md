# AGY hostile plan review — round 5 convergence — #6461

Reviewer: Antigravity (jetski 1.1.6, direct `agy --print`, built-in file tools only). Scope: plan v6 @ e1f58e4e8. Transcript: .scratch/r5-agy-out1.txt (verbatim below).

---

PLAN YES

### Findings by Severity
*No new findings (0 BLOCKER, 0 HIGH, 0 MEDIUM, 0 LOW).*

---

### Round-4 LOW Disposition
* **AGY r4 LOW (`tcp_close_seq_rejected` export surface):** **FOLDED / RESOLVED.** In v6 ([plan.md:722-727](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L722-L727)), `tcp_close_seq_rejected: u64` is moved out of debug-only code and exported directly through the production worker statistics/metrics surface, paired with a rate-limited structured RT_FLOW/screen-class event for attack attribution.

---

### Analysis of v6 Mechanics

1. **Own-Ack Leg Rule (§5.4 Rule 1 Leg 3):**
   * **Legitimate Teardowns:** Standard `FIN+ACK`, active `RST+ACK` (e.g. `SO_LINGER` zero-timeout aborts), and RFC 9293 §3.5.2 reset responses carry `ACK=1` where `SEG.ACK` acknowledges received data (`seq_hi(O)`), validating cleanly under Leg 3. Bare `RST` segments with `ACK=0` on an untrusted-sequence direction (e.g. asymmetric pickup before reverse observation) soft-refuse early demotion. This residual is honest, bounded, and safe: packet delivery is never blocked, endpoints tear down normally via their own TCP stack, and the table entry simply ages out at its standard established/application timeout.
   * **Abuse Potential:** An off-path attacker sending a `RST+ACK` with a guessed `SEG.ACK` in `window(seq_hi(O))` (~1/2^14 guess) and garbage `SEG.SEQ` will trigger firewall demotion. However, this does not break endpoints: the packet is forwarded unchanged, and the receiving endpoint's TCP stack drops the garbage-SEQ packet per RFC 5961 §3.2. At the firewall level, demotion difficulty is identical (~1/2^14 per guess) whether matching `SEG.SEQ` or `SEG.ACK`.

2. **Closing-Never-Promote Hygiene & Deferred Window:**
   * **Legit Close-First-After-Failover Trace:** A legit close arriving as the first post-failover packet on a new owner stays `SharedMaterialize` because Rule 5 skips `maybe_promote_synced_session` on closing packets ([promote.rs:86-90](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/promote.rs#L86-L90)). The new owner's copy remains `is_peer_synced() == true` ([entry.rs:245-250](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session/entry.rs#L245-L250)) and emits no `Close` delta upon local reap ([expire.rs:341-347](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session/expire.rs#L341-L347)). The old owner's authoritative entry emits the cluster-wide `Close` delta. The eBPF `session_map` entry is deleted when the old owner reaps or when HA reconciliation sync runs; no unpromoted `SharedMaterialize` entry ever publishes to `session_map`, preventing stale-shared leaks.
   * **Deferred Window:** Non-close packets promote immediately upon forward commitment; closing packets forward under the current decision without promoting. Byte/packet counters continue accumulating locally ([lookup.rs:150](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session/lookup.rs#L150)), and forwarding decisions remain exact.

3. **Trusted Self-Slide Cost Model:**
   * Under §5.2 Rule 4, trusted self-sliding requires `seg_len > 0` and `s.wrapping_sub(seq_hi) ∈ (0, FWD_SLACK]`. Landing the initial sample inside `FWD_SLACK` (~128 KiB max) out of 2^32 sequence space requires an expected ~1/2^14 random guess. Once inside, sending contiguous data packets slides `seq_hi` forward, but the acceptance window (`FWD_SLACK` wide) follows the anchor. Anchor walking does not expand the window or increase the probability of landing a subsequent RST; an attacker with an in-window sample can demote immediately on packet 1 without walking.

4. **Establishment-Promote Proof & SYN-ACK Bounds:**
   * The proof interval `[isn+1, isn+SEG.LEN]` covers standard 3-way handshake SYN-ACKs (`SEG.ACK = ISN+1`), TFO data acceptance (`SEG.ACK = ISN+1+L`), TFO data rejection (`SEG.ACK = ISN+1`), SYN-ACK retransmissions, and simultaneous open (`ACK = ISN_B+1`). No legitimate SYN-ACK falls outside this interval under RFC 9293. If an exotic non-standard SYN-ACK failed the proof, the entry would safely retain its 20s `OPENING` window while data traffic continues forwarding normally.

5. **Commit Arms Audit:**
   * Placed in successful `PendingForwardRequest` dispatch enqueue (`dispatch/mod.rs`), fast-path rewrite success (`flow_cache_hit.rs`), and LocalDelivery reinject acceptance (`tx/dispatch/slow_path.rs`). GRE decapsulation feeds into these exact slow/fast path dispatch arms post-decap; NAT64 updates run only upon successful translation enqueue; fabric-return traffic is non-authoritative and deliberately bypasses commit hooks to prevent non-owner anchor corruption.

6. **Phase 2 Mechanics & Arithmetic:**
   * **Transport & Gating:** The 18-byte tail `{fwd_seq_hi, fwd_ack_hi, rev_seq_hi, rev_ack_hi, valid, trusted}` is presence-gated by payload length ([sync_protocol.go:95-102](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_protocol.go#L95-L102)) without requiring a capability bitmap. Only sides with `trusted == 1` are serialized, preventing untrusted state laundering across HA.
   * **Bulk vs. Quiet Arithmetic:** At 10–25 Gbit/s line rate, 1 second of bulk data advances sequence numbers by hundreds of MBs to GBs, exceeding `FWD_SLACK` (128 KiB). Bulk flows soft-refuse early demotion post-failover until local packets update the anchor, aging via standard timeouts. For quiet flows (SSH/BGP/IKE), 1s traffic is negligible (≪ 64 KiB), making the wire anchor exact at failover and restoring immediate 2s fast-reap for legitimate teardowns.

7. **Exported Counter Surface:**
   * `tcp_close_seq_rejected` exported via standard worker statistics/metrics paired with rate-limited structured event logging provides full production observability for monitoring and attack attribution.

---

### Bottom Line
Design plan v6 for issue #6461 is fully sound, mathematically rigorous, and ready for implementation. By eliminating fabric-ingress trust assumptions, restricting establishment promotion to strong handshake proofs, enforcing per-field sequence proofs with own-ack close legs, and gating ownership promotion away from closing packets, v6 completely closes off-path blind RST/FIN DoS attacks while protecting cluster HA invariants and ensuring zero disruption to legitimate TCP connection teardowns.
