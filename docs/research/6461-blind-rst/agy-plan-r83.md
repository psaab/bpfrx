VERDICT: PLAN YES

---

### Q1 (Gate Soundness): SOUND

**Evidence & Proofs (`docs/research/6461-blind-rst/plan.md`):**
- **Anchor Structure & Canonical Storage (`plan.md:386-429`)**: 40 B POD `TcpSeqAnchor` stored exclusively on the canonical forward `SessionEntry`.
- **Commit-Point Observation (`plan.md:177-187`, `plan.md:436-484`)**: Anchor updates run only on the receiving worker's RX final admission point after all geometry checks (MTU, frame geometry) and filtering/TTL/CoS evaluation have succeeded. `push_redirect_inbox` capacity discards and selective reinjection paths (`NoRoute`, `NextTableUnsupported`, `MissingNeighbor`) do not update the anchor.
- **Absorbing-State Claim**: Verified (`plan.md:195-208`, `plan.md:548-582`). Imported entries (`SyncImport`, `SharedMaterialize`, `WorkerLocalImport`) initialize with `trusted == 0`. Per-field conversion requires proving against pre-packet *trusted* state (`trusted(seq_hi(O))` or `trusted(ack_hi(O))`). With no trusted baseline present, no packet sequence can elevate `trusted` from 0 to 1 (`plan.md:571-578`). The entry remains absorbing until churn.
- **Walk Claim**: Verified (`plan.md:188-193`, `plan.md:527-535`, `plan.md:598-608`). Sliding a trusted anchor requires satisfying the continuity gate `s.wrapping_sub(cur) ∈ (0, FWD_SLACK]`, which itself demands an in-window sequence hit (~1/2^13–1/2^14 probability). Zero-length segments (`seg_len == 0`) are explicitly rejected for `seq_hi` slides (`plan.md:534-535`).
- **Commit-Point Claim**: Verified (`plan.md:177-187`, `plan.md:436-460`). Dropped, TTL-expired, or capacity-discarded packets never reach the RX final admission commit hooks and cannot alter anchor sequence bounds.
- **Leg Probability Recomputation (`plan.md:157-170`, `plan.md:712-727`, `plan.md:798-802`)**:
  - `BACK_SLACK` = 64 KiB = 65,536. `FWD_SLACK` = `max(2 × wnd, 64 KiB)`.
  - **Floor (`wnd = 0`, `FWD_SLACK = 65,536`)**: Each of the 3 legs has width `65,536 + 65,536 + 1 = 131,073`. Disjoint union floor = `3 × 131,073 = 393,219` (~**1/10,923**).
  - **Cap (`wnd = 65,535`, `FWD_SLACK = 131,070`)**: Legs 1 & 2 width = `65,536 + 131,070 + 1 = 196,607`. Leg 3 (symmetric `[-2×wnd, +FWD_SLACK]`) width = `131,070 + 131,070 + 1 = 262,141`. Disjoint union cap = `2 × 196,607 + 262,141 = 655,355` (~**1/6,554**).

---

### Q2 (Four Wire-Free Rules): SOUND

**Evidence & Proofs (`docs/research/6461-blind-rst/plan.md`):**
- **(a) Closing Packets Never Promote (`plan.md:635-658`, `plan.md:819-828`, `plan.md:847-864`)**: Both `promote_from_reverse` (`lookup.rs:146-149`) and `maybe_promote_synced_session` (`promote.rs:86-107`) explicitly skip `is_closing(flags)` packets.
- **(b) Reverse-Synth Gate (`plan.md:868-900`)**:
  - `ForwardSessionMatch` in `userspace-dp/src/session/shared_ops.rs:638-665` is a cloned decision/metadata struct.
  - On **Accept**: The reverse companion is installed and the forward family in the local worker's `SessionTable` is marked atomically in the same resolve (`plan.md:878-883`), ensuring exactly one producer.
  - On **Refuse**: The install is skipped wholesale (`created=false, install_failed=true`), but the packet is still forwarded (`plan.md:889-892`). No zero-producer, duplicate-producer, or re-synth livelock exists; subsequent legitimate non-close packets re-synthesize and establish the companion normally.
- **(c) Materialize Gate & Probation (`plan.md:902-927`)**:
  - Refused closing materialize installs ALIVE (`closing=false, reset=false`) with `probation: bool = true` at `TCP_OPENING_TIMEOUT_NS` (20 s).
  - `probation: bool` suppresses ownership promotion, Open emission, and replication (`plan.md:915-917`) and clears on the first COMMITTED non-close packet.
  - Family-clock coupling is cut (`plan.md:923-926`), eliminating live-sibling shortening. Stale zombies, fresh-publish pins, and blind-promote chains are impossible because probation entries emit no Open deltas, expire silently at 20 s if unconfirmed, and clear to normal timeouts only upon committing valid non-close traffic.
- **(d) Normative Mark Creation & Emission Gate (`plan.md:1037-1067`)**:
  - Master's `expire.rs:342-350` emission gate (`!is_reverse && !is_peer_synced && !is_transient_local_seed`) remains unchanged.
  - Refused closes never set `closing`/`reset` (`plan.md:778-794`), producing 0 Close deltas. Accepted closes set `closing` on exactly one emitting forward entry, producing exactly 1 Close delta.

---

### Q3 (Issue-Harm & Legit-Teardown Completeness): SOUND

**Evidence & Proofs (`docs/research/6461-blind-rst/plan.md`):**
- **Issue Harms Dead**:
  1. *Firewall-state kill*: Blind off-path closes outside the sequence gate (~1/2^12–1/2^14 window) are refused and leave state untouched (`plan.md:778-794`).
  2. *SNAT mid-flow port swap*: Active session state is retained on refused closes, preventing session reap and subsequent port re-allocation (`plan.md:81-85`, `plan.md:1269-1271`).
  3. *HA standby propagation*: Refused closes generate no mark and emit no Close delta, leaving standby nodes unaffected (`plan.md:1037-1044`).
- **Section-3 Legitimate Teardown Inventory Walk (`plan.md:300-318`, `plan.md:323-330`)**:
  - All legitimate teardown packets (Sites 1, 2, 2b, 2c, 3, 4, 5, 6, 8) are **ALWAYS delivered** (`plan.md:123-124`, `plan.md:323-330`).
  - Misjudged/stale sequence states result only in *refused-demote lingering* (session idles out at normal established timeout), never connection termination failure.
  - Walked scenarios: Asymmetric routing (pickup session seeds anchor on first packet, leg 3 own-ack covers), RST-after-timeout / half-open (OPENING interval `[isn+1, isn+SEG.LEN]` covers), TFO (OPENING interval handles partial-ack), `SO_LINGER(0)` (leg 3 own-ack proof), and RFC 9293 peer-restart resets (leg 2 `SEQ=SEG.ACK` covers).
- **Pending-Neighbor Rule (`plan.md:485-505`)**:
  - `retry_pending_neigh` re-resolves once fresh against live state and never transmits using buffered stale NAT/egress decisions. A second `MissingNeighbor` drops immediately without looping. Non-close outcomes match master while closing stale-decision transmit races.

---

### NEW TRACES SURVIVING THE TERMINAL CUT

**None.**
The terminal cut (v10.0.1) removes the unconverged Part-B distributed protocol machinery (hold tokens, escrow, incarnations, fence ledgers, mint tokens, floor sync) without opening any new ISSUE-class harm trace. All surviving residuals (imported-entry zero-trust absorbing state, both-direction path-switch anchor stalls, split-worker steering master-parity) are pre-existing, fully documented (`plan.md:195-214`, `plan.md:661-667`, `plan.md:1114-1131`), bounded in scope, and delivery-safe.
