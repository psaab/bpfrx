# AGY hostile plan review — round 4 convergence — #6461

Reviewer: Antigravity (jetski 1.1.6, direct `agy --print`, built-in file tools only). Scope: plan v5 @ 078009c78. Transcript: .scratch/r4-agy-out1.txt (verbatim below).

---

# HOSTILE PLAN REVIEW (Round 4 — Convergence Round)

**Target:** `docs/research/6461-blind-rst/plan.md` (v5, commit `078009c78`)  
**Verdict:** **PLAN YES**

---

## Round-3 Finding Dispositions

1. **r3 MEDIUM Disposition (OPENING SYN-ACK authentication exactness):** **RESOLVED / FOLDED**. v5 replaces windowed acceptance against point seeds with the exact interval `[isn+1, isn+SEG.LEN]` (RFC 9293 SYN-SENT + RFC 7413 §4.2.2 TFO partial-ack) across BOTH handshake segment authentication ([plan.md:483-493](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L483-L493)) and OPENING close validation ([plan.md:620-631](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L620-L631)). No windowed tolerance around point seeds survives anywhere in OPENING.
2. **r3 LOW Disposition (Post-failover lingering):** **ACCEPTED & RESOLVED IN PHASE 2**. The Phase-1 absorbing state for imported entries ([plan.md:182-194](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L182-L194)) is accepted as a safe table-pressure trade (delivery unaffected, no broken connections, zero security compromise). Phase 2 ([plan.md:1047-1075](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1047-L1075)) is specified as a REQUIRED fast-follow that carries trusted anchors on the HA wire via an 18 B version-gated extension.

---

## Numbered Findings

### [LOW-1] Refused-Close Attack Telemetry Surface
- **Location:** [plan.md:658-659](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L658-L659), [plan.md:1127-1129](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1127-L1129); [`userspace-dp/src/session/lookup.rs:105-128`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/lookup.rs#L105-L128)
- **Description:** The plan specifies a per-worker counter `tcp_close_seq_rejected: u64` and a one-shot `debug_log!` per entry when a close is refused. While sufficient for basic unit/smoke testing, debug builds are not active in production. Under an active off-path blind RST spray attack, operators lack visibility unless a rate-limited screen/RT_FLOW counter or metric is emitted.
- **Recommendation:** Expose `tcp_close_seq_rejected` directly via the existing worker metrics export surface (`bpf_map/metrics.rs`) so Prometheus/control-plane telemetry reflects blind RST drop rates in production.

---

## Attack Analysis of v5 Mechanics

### 1. Verification of r3 MEDIUM Fold (OPENING Interval)
The exact-interval treatment `[isn+1, isn+SEG.LEN]` is consistently applied in both §5.2 rule 4 ([plan.md:483-493](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L483-L493)) and §5.4 rule 2 ([plan.md:620-631](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L620-L631)).
- Handshake authentication requires `seg.ack ∈ [isn+1, isn+SEG.LEN]`. For standard SYNs without data (`SEG.LEN=1`), this collapses to exact equality `isn+1`. For TFO payloads, it accepts partial-acks up to `isn+SEG.LEN`.
- OPENING close validation checks `seg.ack ∈ [peer_isn+1, peer_isn+SEG.LEN]` for ACK-bearing resets (connection refused) OR exact equality `seg.seq == seq_hi` for un-acked client self-aborts.
- **Verdict:** No windowed acceptance against point seeds survives anywhere in OPENING.

### 2. Provenance Matrix Completeness
Traced every caller of `install_with_protocol_with_origin` and `upsert_synced_with_origin` across the codebase:
- `poll_descriptor/mod.rs:981` (`ForwardCandidate`/`ForwardFlow`) $\rightarrow$ Primary miss install (**Self-authenticating**).
- `poll_descriptor/mod.rs:2450` (`LocalMiss`) $\rightarrow$ Primary miss install (**Self-authenticating**).
- `poll_descriptor/mod.rs:2779` (`MissingNeighborSeed`) $\rightarrow$ Primary miss install (**Self-authenticating**).
- `poll_descriptor/mod.rs:4787` (LocalDelivery new flow) $\rightarrow$ Primary miss install (**Self-authenticating**).
- `shared_ops.rs:857-865` (`install_reverse_session_from_forward_match`) $\rightarrow$ Reverse-companion synthesis (**Never self-authenticating**).
- `session_glue/mod.rs:1092-1118` (`materialize_shared_session_hit`) $\rightarrow$ `SharedMaterialize` (**Never self-authenticating**).
- `session_glue/mod.rs:786-800` (Tunnel `UpsertLocal`) $\rightarrow$ Tunnel refresh (**Never self-authenticating**).
- `session_glue/commands/upsert_synced.rs` $\rightarrow$ HA wire `SyncImport` (**Never self-authenticating**).
- `forwarding/fabric.rs:389-492` $\rightarrow$ Fabric return reverse seed (**Never self-authenticating**).

**Verdict:** Every constructor maps to exactly one provenance matrix class. Primary miss installs run only when no prior session entry or shared-map entry exists for the 5-tuple. An attacker packet targeting an existing or shared victim flow hits `SharedMaterialize` or session lookup, which map exclusively to *Never self-authenticating*. No attacker packet can reach a self-authenticating constructor for a flow it did not create.

### 3. Segment-Wide Weak Authentication & Deadlock Verification
- **Deadlock Claim Verification:** Confirmed. On a one-sided pickup (asymmetric routing, [`userspace-dp/src/session/mod.rs`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/mod.rs) #3152), direction REV is never observed on-box. Under per-field authentication, `ack(fwd)` requires `trusted(rev_seq_hi)` to authenticate. But `rev_seq_hi` requires `ack(fwd)` to become trusted. The circular dependency (`seq_hi(rev)` $\leftrightarrow$ `ack_hi(fwd)`) deadlocks both sides as untrusted forever, causing legitimate closes on asymmetric flows to soft-refuse permanently.
- **Security Trade Evaluation:** Segment-wide authentication breaks the deadlock by allowing an authenticated `seq(fwd)` to confer `trusted` status on `fwd_ack_hi`. For an off-path attacker to exploit this and plant a fake `fwd_ack_hi` (to enable a RST on REV), the attacker MUST land an in-window data packet on FWD, which requires guessing `seq(fwd)` within `window(fwd_seq_hi)` ($\sim 1/2^{13}$ probability). However, an attacker who can land a $1/2^{13}$ in-window guess on FWD can already directly demote the session by sending a RST on FWD!
- **Verdict:** Segment-wide weak authentication does not degrade the security bound below the $1/2^{13}$ floor. The trade is sound, and no fourth option exists that preserves asymmetric routing.

### 4. Commit-Hook Coverage
- Commit hooks run post-filter/admission/TTL/CoS at [`userspace-dp/src/afxdp/forward_request.rs:264-290`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/forward_request.rs#L264-L290) (slow path), flow-cache TX selection drop gate, and [`userspace-dp/src/afxdp/poll_descriptor/mod.rs:640-844`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_descriptor/mod.rs#L640-L644) (LocalDelivery host admission).
- **Committed but un-updated packets:** NAT64 forward-wire immutable matches (`find_forward_wire_match_with_origin`), `PASS_TO_KERNEL` packets, and non-first IP fragments (flowless). These are all documented, explicit residuals ([plan.md:300-302, 876-885](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L300-L302)).
- **Updated but un-committed packets:** Zero. Moving updates out of `lookup_with_origin` guarantees that filter-dropped, TTL=1, or CoS-dropped packets never touch the anchor.
- **Verdict:** Commit-hook coverage is complete and airtight.

### 5. Fabric-Ingress Peer-Vouched Authentication
- Inspected classification logic at [`userspace-dp/src/afxdp/poll_stages.rs:387-403`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/poll_stages.rs#L387-L403) (`stage_classify_fabric_ingress`) and [`userspace-dp/src/afxdp/frame/inspect.rs:1916-1940`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/frame/inspect.rs#L1916-L1940) (`parse_zone_encoded_fabric_ingress_from_frame`).
- `parse_zone_encoded_fabric_ingress_from_frame` executes line 1921: `if !ingress_is_fabric(forwarding, meta.ingress_ifindex as i32) { return None; }`.
- `ingress_is_fabric` and `ingress_is_fabric_overlay` validate `meta.ingress_ifindex` against the hardware interface indices of configured fabric links.
- **Verdict:** Even if an off-path attacker on a public interface crafts a frame with the synthetic fabric MAC header (`0x02 0xbf 0x72 ...`), `meta.ingress_ifindex` reflects the physical non-fabric ingress port, causing `ingress_is_fabric` to return `false`. Non-fabric ports fail this check unconditionally; an off-fabric packet can never be stamped `fabric_ingress`.

### 6. Phase-2 HA Wire Spec (§10.5)
- **New $\rightarrow$ Old:** The capability bitmap suppresses transmission of the 18 B extension when communicating with Phase-1 / legacy peers. The old peer receives standard framing and decodes normally.
- **Old $\rightarrow$ New:** The new peer receives standard payloads lacking the 18 B field. It initializes imported entries as `valid=0, trusted=0` (zero-trust baseline), gracefully falling back to Phase-1 refuse-until-churn behavior.
- **New $\leftrightarrow$ New:** Both nodes exchange and populate the 18 B trusted anchor fields.
- **Verdict:** Mixed-version and downgrade hazards are fully mitigated by the version-gated bitmap.

### 7. Phase-1 Absorbing State Under Sustained Spray Post-Failover
- Traced refused-close handling ([plan.md:649-689, 760-769](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L649-L689)): A refused close does NOT set `closing`/`reset`, does NOT update `last_seen_ns`, does NOT update `expires_after_ns`, and SKIPS `push_to_wheel`.
- Under a sustained spray of off-path RST/FIN packets, the imported session entry remains in its pre-attack timing wheel bucket.
- **Verdict:** Refused closes are completely inert. They cannot pin an entry alive (slot retention) nor trigger premature reaping. The entry expires on its original established timeout tick.

---

## Bottom Line
v5 delivers an airtight, mathematically rigorous, and architecturally sound DoS-hardening plan for issue #6461. By enforcing exact-interval OPENING validation `[isn+1, isn+SEG.LEN]`, strict provenance matrix gating, transactional trust updates at per-disposition commit hooks, complete refused-close inertness, and a version-gated Phase-2 HA wire anchor, v5 eliminates off-path RST/FIN session disruption while preserving legitimate TCP teardowns and asymmetric routing. **PLAN YES.**
