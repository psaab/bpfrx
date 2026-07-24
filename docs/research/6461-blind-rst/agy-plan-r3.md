# AGY hostile plan review — round 3 convergence — #6461

Reviewer: Antigravity (jetski 1.1.6, direct `agy --print`, built-in file tools only). Scope: plan v4.2 @ f99e1df0e. Transcript: .scratch/r3-agy-out1.txt (verbatim below).

---

VERDICT: **PLAN YES**

---

### Task 1: Verification of Round-2 Folds

| Issue | Status | Text Evidence (`docs/research/6461-blind-rst/plan.md`) | Code Evidence |
|---|---|---|---|
| **B1: Post-failover cluster kill** | **Resolved** | Lines 17–21, 596–613 (§5.4 rule 3), 692–705 (§5.6 site 2c), 780–799 (§7) | `userspace-dp/src/session/lookup.rs:146-149`<br>`userspace-dp/src/session/expire.rs:342-345`<br>`userspace-dp/src/session/entry.rs:245-250`<br>`userspace-dp/src/session_glue/mod.rs:1092-1118`<br>`userspace-dp/src/session_glue/shared_ops.rs:857-865` |
| **B2: 2-packet seed race** | **Resolved** | Lines 24–27, 466–501 (§5.2 rule 4), 579–595 (§5.4 rule 1) | `userspace-dp/src/session/lookup.rs:105-128`<br>`userspace-dp/src/flow_cache_hit.rs:312-317`<br>`userspace-dp/src/poll_descriptor/mod.rs:3494-3503` |
| **B3: Union-window arithmetic** | **Resolved** | Lines 28–32, 143–152 (§2), 568–577 (§5.4) | `userspace-dp/src/frame/tcp.rs` (`TcpSegView`) |

**Summary of Resolution:**
- **B1 Disposition:** v4 flips the missing/no-baseline policy from fail-open to **refuse-demote** across all hit, promote, materialize, synth, and missing-forward paths. Gating `materialize_shared_session_hit` (site 2c) to install copies ALIVE (`closing=false, reset=false`) prevents unvalidated closes from arming 2 s reaps on promoted entries.
- **B2 Disposition:** Seed trust acquisition now requires `!valid` seeds to cross-bound against an already-trusted opposite anchor (`ack_hi(O)` or `seq_hi(O)`). Unauthenticated samples adopt `valid` but `untrusted`. Untrusted sides never validate closes, and untrusted state cannot authenticate other segments.
- **B3 Disposition:** §2 and §5.4 restate ESTABLISHED union acceptance as up to two windows (`window(seq_hi(D)) ∪ window(ack_hi(O))`), correctly bounding worst-case acceptance at 262,146–393,214 values (~1/16384–~1/10923 per guess) and self-bounding `FWD_SLACK` at 131,070.

---

### Task 2: Attack Analysis of New Trust Mechanics

#### (a) Handshake Bootstrap & Early-Flow Segment Authentication
- **SYN / TFO / Pickup:** SYN self-authenticates (`fwd_seq` trusted). TFO SYN+data seeds `fwd_seq_hi = isn + SEG.LEN` (including payload length), so the server's SYN-ACK (`ack == isn + SEG.LEN`) matches `fwd_seed` and authenticates cleanly. Mid-stream pickup and asymmetric flows seed their observed direction as trusted at install time (`§5.2(c)`), allowing closes on the observed side to validate.
- **Simultaneous Open:** Host B's reverse SYN has no ACK bit matching `fwd_seq_hi` and adopts `valid`+`untrusted`. When Host B subsequently sends an ACK/data segment with `ack == fwd_seq_hi` (which is trusted from Host A's SYN), Host B's segment authenticates against `fwd_seq_hi`, adopting `rev_seq` and `rev_ack` as `trusted`.
- **Miss Consequence:** Soft-refused legitimate closes for unauthenticated flows cause the entry to linger to its ordinary established/opening timeout. Endpoint teardown delivery is unblocked.

#### (b) Attacker Amplification
- Spoofed data with `ack` inside `window(seq_hi(O))` requires guessing `ack` within a ~1/2^13 window of `seq_hi(O)`.
- Landing `ack` inside `window(seq_hi(O))` costs the exact same ~1/2^13 expected sprays as landing a direct RST on `ack_hi(O)` under the RFC 9293 §3.5.2 closed-TCB leg.
- There is **zero amplification** (seeding a fake `seq_hi(D)=X` confers no advantage over attacking the `ack_hi(O)` leg directly).

#### (c) OPENING Consistency & SYN-ACK Authentication
- In `§5.2 rule 4`, general segment authentication is described as windowed cross-bounding (`[seq_hi - BACK_SLACK, seq_hi + FWD_SLACK]`), whereas line 477 states SYN-ACK authenticates via `ack == fwd seed` (exact match, cost 1/2^32).
- If OPENING SYN-ACK authentication used windowed cross-bounding, a spoofed SYN-ACK with ACK within 192,000 of ISN would authenticate `rev_seq` as trusted at cost ~1/2^13.
- **Adjudication:** During OPENING (`!established`), SYN-ACK authentication MUST strictly enforce exact ACK equality (`seg.ack == fwd_seed`), matching line 477. Windowed acceptance is NOT required for SYN-ACK because SYN-ACK is the first reverse segment responding to SYN; no retransmits or SACK edges exist on the reverse side prior to SYN-ACK.

#### (d) HA-Imported Entries
- HA-imported entries (`SyncImport` / `SharedMaterialize`) start with `trusted = 0`. Legitimate closes occurring before local traffic arrives will soft-refuse, causing entries to age out at their established timeout rather than 2 s.
- Under high session counts (e.g., 50k synced flows), table pressure is bounded by worker slab capacity (131,072 slots/worker) and existing GC timeouts. Deferring the wire anchor field to a follow-up (§10) is an acceptable trade-off to keep the PR rolling-upgrade safe.

#### (e) Re-Import Wipe
- `upsert_synced_with_origin` calls `remove_entry`, discarding locally built trust anchors on HA re-sync (`§7`).
- Acceptable because HA re-sync is an infrequent administrative/failover event, and subsequent local data packets rapidly re-authenticate trust.

#### (f) Closing-Packet Promote Skip
- Skipping `established = true` promotion for `is_closing(flags)` SYN-ACK packets (`§5.2 rule 5`) is standards-compliant (RFC 9293: SYN-ACK+RST is an abort, not a connection establishment).

---

### Task 3: Findings & Bottom Line

#### Numbered Findings

1. **MEDIUM — Inconsistent SYN-ACK Authentication Window during OPENING**
   - **Location:** `docs/research/6461-blind-rst/plan.md:469-479`
   - **Evidence:** `§5.2 rule 4` text states segment authentication uses windowed cross-bounding, whereas line 477 states SYN-ACK authenticates via `ack == fwd seed` (exact match, cost 1/2^32).
   - **Impact:** If implemented with windowed cross-bounding during OPENING, a spoofed SYN-ACK with ACK within 192,000 of ISN would adopt `rev_seq` as trusted at windowed cost (~1/2^13).
   - **Resolution:** The implementation must explicitly enforce exact ACK equality (`seg.ack == fwd_seed`) for SYN-ACK authentication during OPENING (`!established`).

2. **LOW — Lingering Table Pressure for Unobserved Teardowns Post-Failover**
   - **Location:** `docs/research/6461-blind-rst/plan.md:178-190, 767-769`
   - **Evidence:** Imported entries refuse fast teardowns until local traffic arrives; teardowns occurring immediately post-failover before data traffic linger to the full established timeout.
   - **Impact:** Minor table pressure post-failover under high churn.
   - **Resolution:** Acceptable residual; bounded by 131,072 entry/worker slab capacity and GC aging.

---

#### Bottom Line
Plan v4.2 successfully converges on a robust, defensive architecture for #6461. By switching the no-baseline fallback to refuse-demote, gating shared-materialize constructors to install copies alive, anchoring state solely on the canonical forward entry, and strictly constraining seed trust acquisition, v4.2 completely eliminates the post-failover cluster kill (B1), the 2-packet seed race (B2), and the union arithmetic understatements (B3) without breaking packet forwarding or introduce wire-format incompatibility.
