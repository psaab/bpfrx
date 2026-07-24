# AGY hostile plan review — round 2 convergence pass on v3 — #6461

Reviewer: Antigravity (jetski 1.1.6, direct `agy --print`, built-in file tools only). Scope: plan v3 @ 396e24300. Transcript: .scratch/r2-agy-out3.txt (verbatim below).

---

### 1. Fold Dispositions (v2 Findings vs v3 Text & Code)

| Finding | v2 Flaw | v3 Fold Disposition & Verification | Status |
|---|---|---|---|
| **B1** | `account_packet` gated on `ForwardCandidate`/`FabricRedirect` at `poll_descriptor/mod.rs:3478-3503`, so host-inbound BGP/SSH/IKE (`LocalDelivery` at `:1744`) never updated anchors. | **Resolved.** v3 §5.2 site (b) adds anchor updates in `lookup_with_origin`, which every slow-path session hit transits (`resolve_flow_session_decision` at `poll_descriptor/mod.rs:412` -> `shared_ops.rs:602`) prior to disposition evaluation. | **Resolved** |
| **B2** | Permanent anchor stall after a `>FWD_SLACK` observation gap. | **Resolved.** v3 §5.2 "Stall analysis" documents that on a per-packet-tracked path, samples arrive contiguously (gap bounded by path reordering extent ≪ 64 KiB). Intentionally omits an unsafe re-anchor hatch to prevent re-opening r1 staging attacks. Residual soft-refused close idles out on standard timeout. | **Resolved** |
| **F3** | Born-alive reverse install after refused close seed was a junk-entry vector. | **Resolved.** v3 §5.6 changes `install_reverse_session_from_forward_match` (`shared_ops.rs:857-865`) so a refused close seed **skips reverse session installation entirely** (no entry minted; packet forwarded). | **Resolved** |
| **F4** | `FWD_SLACK` consumed `wnd(D)` (wrong direction). | **Resolved.** v3 §5.4 corrects `FWD_SLACK = clamp(2 * wnd(O), 64KiB, 512KiB)` to use the opposite direction's advertised window `wnd(O)` (the sender's effective send window). | **Resolved** |
| **F5** | Post-borrow interim state hazard during deferred marking. | **Resolved.** Rationale in v3 §5.5 verified: single-threaded worker loop guarantees no interleaving between borrow release and post-borrow propagation. | **Resolved** |
| **F6** | TFO false refusal on connection-refused / SYN-with-data. | **Resolved.** v3 §5.2(c)/§5.4 rule 2 seeds `isn + SEG.LEN` at SYN install and validates `ack == peer_isn + SEG.LEN` during `OPENING`. | **Resolved** |

---

### 2. Attack Analysis of v3 New Surfaces

#### (a) Trace Verification / Refutation

1. **Trace 1 (Post-Failover Cluster-Wide Session Kill): VERIFIED (BLOCKER)**
   - **Trace:** A synced session exists on a failover node without a local anchor. An attacker sends a blind RST as the first locally observed packet.
   - **Execution Path:**
     1. §5.4 Rule 3 ("No valid baseline in any form -> fail-open") triggers and accepts the blind RST.
     2. `materialize + promote` (`promote.rs:86-90`) runs because disposition is `ForwardCandidate`.
     3. Line 103 sets `origin: SessionOrigin::SharedPromote` on the promoted forward entry.
     4. The entry is marked `closing` and `reset`, setting a 2s reap timer.
     5. After 2s, `expire.rs:342-345` checks: `!metadata.is_reverse && !removed.origin.is_peer_synced() && !removed.origin.is_transient_local_seed()`.
     6. `entry.rs:245-250` defines `is_peer_synced()` strictly as `SyncImport | SharedMaterialize | WorkerLocalImport`. **`SharedPromote` is NOT `is_peer_synced()`.**
     7. `expire.rs:346` emits a `SessionDeltaKind::Close` delta.
     8. Go session sync receives the delta and applies it unconditionally (`sync_conn_gen.go:176-186`), **deleting the shared and standby session copies cluster-wide**.
   - **Result:** A single blind RST landing post-failover before legitimate traffic arrives kills the flow across the entire cluster.

2. **Trace 2 (Two-Packet Blind Anchor Poisoning & Demote): VERIFIED (HIGH)**
   - **Trace:** On an asymmetric flow or a flow where direction $D$ has not yet set its validity bit (`valid` bit = 0):
     1. **Packet 1:** Attacker sends a non-close data segment with arbitrary sequence `seq = X`. Per §5.2 Gating Rule, `!valid` adopts `X` unconditionally as the anchor seed (`seq_hi(D) = X + SEG.LEN`, `valid = 1`).
     2. **Packet 2:** Attacker sends a RST at `seq = X`. Per §5.4 Rule 1, `seq = X` is checked against `seq_hi(D)`. It falls squarely inside `[seq_hi - 64KiB, seq_hi + FWD_SLACK]` and is accepted.
   - **Result:** The attacker demotes the session using exactly 2 packets with zero sequence knowledge of the legitimate flow.

#### (b) Adjudication: Fail-Open vs Refuse-Demote on No-Baseline
- **Verdict:** No-baseline **MUST flip from fail-open to refuse-demote** (fail-closed for fast demotion reap, fail-open for packet forwarding).
- **Reasoning:**
  - On a legitimate RST-first-after-failover packet, refusing demote **does NOT block packet delivery**. The RST packet is forwarded to the endpoint, tearing down the TCP connection immediately. The firewall session entry simply idles out on its normal timeout (table-pressure cost), which §2 and §5.2 already explicitly accept as tolerable.
  - Fail-open permits Trace 1 (cluster-wide session kill via 1 blind RST post-failover) and Trace 2 (2-packet blind demote).
  - Refusing demote when no baseline exists completely eliminates both Trace 1 and Trace 2 without breaking endpoint TCP teardowns.

#### (c) Union-Window Arithmetic Honesty
- **Finding:** §2's claim of a $1/32768$ ($2^{17}/2^{32}$) acceptance probability at floor is **dishonest / understated by 2× to 8.8×**.
- **Proof:**
  - §5.4 Rule 1 checks: `seg.seq ∈ [seq_hi(D) - 64KiB, seq_hi(D) + FWD_SLACK] UNION seg.seq ∈ [ack_hi(O) - 64KiB, ack_hi(O) + FWD_SLACK]`.
  - At floor (`FWD_SLACK = 64 KiB`), each window is 128 KiB ($2^{17}$). The **UNION of two non-overlapping 128 KiB windows** spans **256 KiB** ($2^{18}$ bytes), yielding a floor hit probability of $2^{18}/2^{32} = \mathbf{1/16384}$ per guess (2× higher than §2 claims).
  - At max window scale (`FWD_SLACK = 512 KiB`), each window is 576 KiB. The union spans up to **1,152 KiB** (~1.15 MiB), yielding a hit probability of $\mathbf{1/3728}$ per guess (8.8× higher than §2 claims).

#### (d) Double Anchor Update
- **Finding:** **IDEMPOTENT & SAFE (LOW)**.
- **Reasoning:** `lookup_with_origin` and `account_packet` (`poll_descriptor/mod.rs:3497`) both execute `seq_hi = max(seq_hi, seq + seg_len)` for slow-path `ForwardCandidate` packets. `max(A, B)` is mathematically idempotent (`max(max(A, B), B) = max(A, B)`). The second update is a safe no-op.

#### (e) Skip-Install on Non-Owner
- **Finding:** **CONFIRMED SAFE (LOW)**.
- **Reasoning:** Synthesizing a reverse entry from `shared_nat_sessions` on a non-owner node creates a reverse entry (`metadata.is_reverse = true`).
  1. `expire.rs:342` checks `!metadata.is_reverse` before emitting a `Close` delta. For reverse entries, this check fails, so **no Close delta is emitted**.
  2. `propagate_tcp_state_to_companion` (`userspace-dp/src/session/mod.rs:1232-1278`) is local-table only and does not transmit HA messages. Non-owner born-dying reverse entries expire silently without affecting the owner.

---

### 3. Review Verdict & Numbered Findings

### Verdict: PLAN NO

#### Findings

1. **[BLOCKER] Post-Failover Cluster-Wide Demote via Fail-Open Baseline**
   - **Location:** `docs/research/6461-blind-rst/plan.md:447-450` (§5.4 Rule 3), `userspace-dp/src/session_glue/promote.rs:86-107`, `userspace-dp/src/session/expire.rs:342-345`
   - **Description:** Post-failover flows without a local anchor hit §5.4 Rule 3 and fail-open. A blind RST causes promotion to `SharedPromote` (`promote.rs:103`). Because `SharedPromote` is excluded from `is_peer_synced()` (`entry.rs:245-250`), its 2s reap emits a `SessionDeltaKind::Close` (`expire.rs:342-345`), which Go applies cluster-wide (`sync_conn_gen.go:176-186`), destroying standby and shared session copies.
   - **Remediation:** Flip §5.4 Rule 3 from fail-open to refuse-demote (fail-closed for fast reap, fail-open for packet forwarding).

2. **[HIGH] Un-Anchored Direction 2-Packet Blind Anchor Poisoning**
   - **Location:** `docs/research/6461-blind-rst/plan.md:366-368` (§5.2 Gating Rule)
   - **Description:** For any un-anchored direction (`valid` bit 0), an attacker sends a non-close packet with arbitrary `seq = X`. §5.2 adopts `X` unconditionally. A second packet carrying a RST at `seq = X` passes §5.4 validation, demoting the session in 2 packets without sequence knowledge.
   - **Remediation:** Refuse demotion on un-anchored directions until a valid baseline is established by non-closing transit traffic.

3. **[MEDIUM] Understated Union Acceptance Window Arithmetic in §2**
   - **Location:** `docs/research/6461-blind-rst/plan.md:129-131` (§2), `docs/research/6461-blind-rst/plan.md:435-437` (§5.4 Rule 1)
   - **Description:** §2 claims a $1/32768$ per-packet success probability based on a 128 KiB window. §5.4 Rule 1 evaluates a UNION of two 128 KiB windows (`seq_hi(D)` and `ack_hi(O)`), creating a 256 KiB acceptance interval ($1/16384$) at floor, expanding to 1,152 KiB ($1/3728$) at max window scale.
   - **Remediation:** Correct §2 arithmetic to accurately reflect the union window probability (1/16384 floor, 1/3728 scaled).

---

### Bottom Line
v3 successfully folds findings B1, B2, F3, F4, F5, and F6, but introduces a critical architectural vulnerability in its fail-open baseline strategy: post-failover un-anchored flows are vulnerable to a single blind RST that promotes to `SharedPromote` and emits a cluster-wide `Close` delta upon reaping (killing standby and shared copies across the cluster), while un-anchored flow directions can be demoted in just two packets via unconditional seed adoption. Flipping the no-baseline behavior from fail-open to refuse-demote (forwarding the RST packet while preserving normal session idle timeouts) cleanly resolves both vulnerabilities without breaking legitimate TCP teardowns.
