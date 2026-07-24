# #6461 — blind off-path TCP RST/FIN demotes a live session with no sequence validation

**Status: DRAFT v3 — revised after round-2 AGY review (PLAN NO, 2 blockers folded); Codex round-2 in flight**

v1 → v2: round-1 review killed v1's architecture (attacker-writable trust
anchor, missed reverse-NAT constructor, invalid cross-store serial merge).
v2 was redesigned around a single two-direction anchor on the canonical
forward entry, plausibility-gated anchor updates, pre-packet validation,
and constructor gating.
v2 → v3: round-2 AGY found (a) `account_packet` never runs for
LocalDelivery dispositions, so v2 left host-inbound flows (BGP/IKE/SSH to
the firewall — the exact victims the issue names) with a frozen install-time
anchor; (b) v2's born-alive reverse install after a refused close seed was
an attacker-mintable junk-entry vector; (c) `FWD_SLACK` consumed the wrong
direction's advertised window. v3: anchor updates run in BOTH
`lookup_with_origin` (every slow-path session hit incl. LocalDelivery) AND
`account_packet` (cache-hit bulk); a refused close seed SKIPS the reverse
install entirely; `FWD_SLACK` derives from `wnd(O)`; the anchor-stall
analysis is made precise. Round-1/2 review docs sit alongside this file.

Research branch: `research/6461-blind-rst`. Plan-only deliverable; no
production code is changed by this branch. Implementation begins only after
manual approval via `/engineer 6461`.

---

## 1. Issue framing

A single blind off-path TCP RST or FIN whose 5-tuple matches a live session
permanently demotes that session to the 2 s (RST) / 30 s (FIN) reaper
window. There is no sequence-number validation anywhere on the session-HIT
path:

- `userspace-dp/src/session/lookup.rs:105-128` — every lookup computes
  `do_close = is_tcp && is_closing(tcp_flags)` and, on a FIN/RST-bearing
  segment, sets `entry.closing = true` (sticky, #3489) and
  `entry.reset |= has_rst(...)` (sticky, #3046). `SessionEntry` carries no
  sequence state at all.
- `lookup.rs:151-156` — subsequent hits recompute `expires_after_ns` to
  `TCP_RST_TIMEOUT_NS` (2 s) or `TCP_CLOSING_TIMEOUT_NS` (30 s).
- `userspace-dp/src/session/mod.rs:1232-1278`
  (`propagate_tcp_state_to_companion`, #4109) — the close is mirrored onto
  the forward/reverse companion, so both halves reap together.
- The session-miss NEW-FLOW path is guarded (#4400
  `strict_syn_check_drops_new_flow`): a bare RST/FIN never seeds a
  ForwardCandidate/MissingNeighbor session. That guard does NOT cover the
  reverse-companion synthesizer (see §3, site 2b).

Attack trace: the attacker knows or guesses a 5-tuple (well-known services,
observable/shared segments, SNAT pools with predictable port allocation)
and sends one RST or FIN. The entry flips to closing+reset stickily; the
first ≥2 s idle gap (routine for SSH/BGP/IKE/management flows) reaps it;
the wheel expiry emits a Close `SessionDelta` (`session/expire.rs:346-377`)
which the Go eventstream turns into an HA session-sync delete that also
kills the standby copy. The next real packet is a session miss and must
re-seed; per the issue verifier, a SNAT'd flow's re-seed can allocate a
*new* pool port, changing the translated source mid-connection and killing
endpoint TCP state even when both endpoints themselves ignored the RST
(modern stacks do, per RFC 5961). Repeating the RST keeps the flow dead.

The design question the issue poses: **what does Junos actually do here,
and what xpf behavior closes the DoS without breaking legitimate
teardowns** (asymmetric routing, RST after idle, half-open edges, RST after
peer state loss)?

### What Junos actually does (researched; sources below)

- **Default RST handling**: on a tuple-matching RST, Junos sets the session
  to time out **2 seconds** later — xpf's `TCP_RST_TIMEOUT_NS = 2s` (#3046)
  is exact Junos-default parity. `set security flow tcp-session
  rst-invalidate-session` (off by default) makes teardown *immediate*;
  `fin-invalidate-session` is the FIN analogue. **Correction from v1**:
  `rst-invalidate-session` is already in the xpf schema and compiler
  (`pkg/config/schema_security.go:796-800`,
  `compiler_security_flow.go:515-532`) — parsed, and like the other
  tcp-session knobs carried as config-parity surface.
- **Default general sequence check**: Junos performs window-based TCP
  sequence checking by default ("monitors the sequence numbers in TCP
  segments ... detects the window scale ... if the device detects a
  sequence number outside this range, it drops the packet");
  `no-sequence-check` disables it. xpf parses `no-sequence-check` but
  enforces nothing (#2008 M9 / #2078: commit-time warning "the userspace
  dataplane has no TCP state machine"). **xpf has no equivalent of this
  default check — a broader parity gap than RST handling, explicitly out of
  scope here (§10).**
- **RST-specific check**: `set security flow tcp-session
  rst-sequence-check` (off by default) verifies the RST's sequence number
  "matches the previous sequence number for a packet in that session or is
  the next higher number incrementally"; on mismatch Junos **drops the
  packet and sends the host a TCP ACK with the correct sequence number** —
  the RFC 5961 §3.2 challenge-ACK shape implemented by the middlebox. The
  existence of this separate opt-in knob implies Junos's default general
  check does NOT gate RST segments; **on RSTs specifically, xpf today ==
  Junos default** (2 s reap, no RST sequence validation).

### RFC 5961 §3 / RFC 9293 §3.5.2 (the endpoint-side shapes)

- RFC 5961 §3.2 (RST): a RST with `SEG.SEQ` completely outside
  `[RCV.NXT, RCV.NXT+RCV.WND]` is silently dropped; in-window but non-exact
  elicits a rate-limited challenge ACK (connection survives); only
  `SEG.SEQ == RCV.NXT` aborts.
- RFC 9293 §3.5.2 (reset generation): a reset for a CLOSED TCB (peer
  restart/state loss) answering an ACK-bearing segment carries
  `SEQ=SEG.ACK` — the **opposite direction's** ack position; without ACK it
  carries `SEQ=0, ACK=SEG.SEQ+SEG.LEN`. The repo's own
  `build_reject_rst_frame` (`frame/tcp.rs:328-385`) implements exactly
  this. Any validator that only consults the RST direction's own stream
  position wrongly refuses this canonical reset (round-1 Codex B9).
- A middlebox cannot know either endpoint's exact `RCV.NXT`; the feasible
  subset is the outer rule: refuse to *act on* a closing segment whose
  sequence placement is implausible given observed flow state.

Sources:
- <https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-rst-invalidate-session.html>
- <https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-no-sequence-check.html>
- <https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-rst-sequence-check.html>
- <https://www.juniper.net/documentation/us/en/software/junos/flow-packet-processing/topics/topic-map/security-tcp-session-checks.html>
- RFC 5961 §3.2/§3.3/§3.4; RFC 9293 §3.5.2; RFC 1982 (serial arithmetic).

---

## 2. Honest scope/value framing

What the fix buys, at absolute scale:

- Today: a **single** off-path packet with a guessed 5-tuple kills a chosen
  flow's firewall state (plus HA standby copy, plus a possible SNAT
  pool-port mid-flow swap). Attacker cost: 1 packet per ~2 s.
- After: with a ~128 KiB total acceptance window (64 KiB back-slack +
  64 KiB forward floor, §5.4) against a fresh anchor, a blind RST succeeds
  with probability ≈ 2^17/2^32 = **1/32768 per guess**. At 1,000
  minimum-size RST/s (~1 Mbit/s) the expected time to a lucky guess is
  ≈ 33 s of sustained spraying per kill — and every sprayed packet also
  reaches the endpoints, which apply their own RFC 5961 handling.
  Anchor-walking (feeding contiguous fake in-window data to slide the
  anchor, then RST) costs ≥ window/MSS packets (≥45 at 64 KiB) — but that
  capability is strictly stronger than the demote attack (it is blind data
  injection into the endpoint's reassembly queue, which the endpoints'
  own TCP handling governs), so the firewall ceases to be the weakest
  link. That is the honest goal: raise the firewall-state kill from
  1 packet to data-injection-equivalent effort, not to infinity.
- Cost: ~20–24 B of new state on `SessionEntry` (uniform slab — includes
  UDP/ICMP entries that never use it; ≈ 3 MiB per worker at the 131,072
  cap, ≈ 18 MiB at 6 workers), one 8-byte TCP-header read plus two
  plausibility-gated `u32` stores per TCP packet inside the existing
  `account_packet` session-table probe, and a second table probe only on
  closing-flag segments (which already take the full slow path).

What the fix does **not** buy: protection against an on-path attacker
(observes sequence numbers; out of threat model); protection of pre-5961
endpoints against in-window blind RSTs delivered through the firewall (the
packet is always forwarded — their stacks are the last line, as they are
today); a guarantee that a determined multi-thousand-packet spray cannot
eventually force one demote (it can — the endpoints still survive); the
Junos general data-plane sequence check (§10). Legitimate-teardown
residual, stated plainly: a real RST/FIN whose true in-flight data at abort
time exceeds the forward slack (64 KiB ≈ 21 µs at 25 Gbit/s) is refused the
early demote — the packet is delivered, endpoints tear down normally, and
the entry idles out on its ordinary timeout instead of the 2 s fast reap.
That is a table-pressure cost, never a broken connection.

*If reviewers conclude the residual attack surface or the blast radius does
not justify the churn (new per-entry state, a validation phase on the close
path, constructor gating), PLAN-KILL is an acceptable verdict — the parity
argument (xpf == Junos default for RST handling) is honest and documented
in §1.*

---

## 3. What's already shipped / partially batched

- **#3046** — sticky `reset` flag + 2 s RST reap (Junos parity).
- **#3152** — OPENING/ESTABLISHED half-open state machine; mid-stream
  pickup seeds ESTABLISHED from a non-SYN first packet (asymmetric-routing
  preservation). A pickup session's anchor seeds from its first observed
  packet — composes with this plan.
- **#3489** — sticky `closing` in `update_session` (write path).
- **#4109** — F16/F17 companion propagation
  (`propagate_tcp_state_to_companion`). Validation placed before the mark
  is inherited by the companion for free; v2 moves the marking itself into
  that post-borrow phase (§5.5).
- **#4400** — `strict_syn_check_drops_new_flow`: bare RST/FIN dropped at
  the ForwardCandidate/MissingNeighbor new-flow install sites
  (`poll_descriptor/mod.rs:1634-1644`). Always-on, no knob — the precedent
  for always-on hardening on this boundary.
- **#4453** — same predicate excludes bare RST/FIN from the fabric return
  fast path (`forwarding/fabric.rs:426-431`).
- **#4539/#4487/#2151** — host-inbound LocalDelivery session caching only
  off the handshake; declined first packets still delivered locally.
- **#2344** — `parse_session_flow_from_bytes` refuses non-first IP
  fragments (`frame/inspect.rs:1455-1470`): fragments are **flowless** — no
  SessionFlow, no session lookup, no cache insert, no `account_packet`.
  Fragments therefore cannot drive a demote, cannot seed an anchor, and
  cannot pollute one. (Round-1 AGY's cache-pollution-via-fragment claim is
  refuted by this chokepoint; no shim `meta_flags` bit is needed.)
- **#2501** — `account_packet` runs for **every** forwarded packet on a
  live session, on BOTH the flow-cache hit path (`flow_cache_hit.rs:312-317`)
  and the slow-path forward build (`poll_descriptor/mod.rs:3494-3503`),
  folding both directions' accounting onto the canonical forward entry.
  This is the existing chokepoint that makes a single-authoritative anchor
  possible (round-1 Codex B4).
- **Flow cache** (`flow_cache.rs:352-375`): only UDP and TCP pure-ACK are
  cache-eligible; every FIN/RST bypasses the cache and takes the full slow
  path. NAT64 (`should_cache` excludes) and LocalDelivery
  (`is_cacheable()` = ForwardCandidate|FabricRedirect only,
  `types/forwarding.rs:948-952`) are non-cacheable → every packet of those
  flows transits the slow path and `account_packet`.
- **Fabric return fast path** (`cluster_peer_return_fast_path`,
  `poll_descriptor/mod.rs:928`, `forwarding/fabric.rs:389-492`): established
  non-closing return traffic arriving on fabric ingress is forwarded with
  at most a first-packet reverse-seed install — it does NOT run
  `account_packet` or a session lookup per packet (round-1 AGY Q1). The
  affected entries are non-authoritative (reverse seeds / synced copies on
  the non-owner node); see §7's HA invariant for why that is safe, and
  §5.2 site (d) for the seed treatment.
- **#2008 M9 / #2078** — `no-sequence-check` parsed, unenforced.
  `rst-invalidate-session` parsed (schema + compiler, see §1).
  `rst-sequence-check` and `fin-invalidate-session` are NOT in the xpf
  schema.
- **#6457 (in flight, adjacent)** — flow-cache delete/invalidate on session
  reap. v2 no longer touches `FlowCacheEntry` at all (a v1 casualty:
  Codex B3/B4/B12), so the merge tension disappears.

### Packet-driven closing/reset sites (complete, round-1-verified inventory)

| # | Site | Trigger | v2 treatment |
|---|---|---|---|
| 1 | `session/lookup.rs:105-128` HIT path (real endpoint FIN/RST) | wire packet flags | gate via pre-packet anchor validation, marking moved to post-borrow phase (§5.5) |
| 2 | `session/mod.rs:1398-1412` `update_session` via `promote_synced_with_origin` (HA shared-promote, `session_glue/promote.rs:99-107`) | wire packet flags on the promoting packet | same gate (flags threaded with seq view) |
| 2b | **reverse-NAT companion synthesizer** — `session_glue/mod.rs:1262-1284` → `shared_ops.rs:857-865` → `install_with_protocol_with_origin` (seeds at `install.rs:399-400`) | wire packet flags on a reverse-tuple miss with a live forward match; runs at resolve time, BEFORE the #4400 guard | **the two-packet bypass round-1 Codex B2 proved** — gate the seed with the validator against the in-hand forward entry's track; refused close → entry born ALIVE (§5.6) |
| 3 | `install.rs:179-180` primary miss installs | creating packet flags | already unreachable for bare closes (#4400); SYN-bearing malformed closes are screen-owned; no change |
| 4 | HA wire re-import — `UpsertSynced` → `upsert_synced_with_origin` (`install.rs:399-400` with wire-carried flags) | no packet exists | validation-free by design (the peer validated before reaping and emitting the Close) |
| 5 | tunnel `UpsertLocal` (`tunnel.rs:563-615` → `session_glue/mod.rs:786-800`) | locally generated packets (firewall-originated tunnel TX) | trusted-local class, documented; not wire-attacker-controllable |
| 6 | fabric-return reverse seed (`cluster_peer_return_fast_path` install) | fabric-ingress packet flags | bare closes already excluded (#4453); SYN-flagged seeds carry no close; no change |
| 7 | CLI/control deletes, GC/reaper, screens/SYN-cookie | — | consumers / unaffected |

---

## 4. Multiple path options

### Option A — sequence-window demote gate, state-only (RECOMMENDED, v2 shape)

Track flow sequence progress at the existing accounting chokepoint; gate
**only** the `closing`/`reset` demotion (and its companion propagation and
install-time seeds) on the closing segment's placement. The packet itself
is always forwarded unchanged — endpoint teardown delivery is never
blocked, so no legitimate teardown can be broken by the firewall; the worst
failure is a *refused demote* (entry idles out on its normal timeout,
exactly as if the RST had been lost in transit — a condition #3046 already
tolerates by design). Always-on (no config knob), mirroring the #4400
precedent: the gate can only make the firewall *more* conservative about
killing state. Fail-open whenever no baseline exists (HA-imported entries
never locally observed): the active node, which sees the traffic, is the
validating node; standby copies die only via the peer's post-validation
Close delta.

### Option B — Junos `rst-sequence-check` parity (drop + challenge ACK)

Drop the out-of-window RST and emit a corrective ACK (reply-builder
machinery exists: `build_reject_rst_frame`, SYN-cookie builders). Off by
default behind a new schema leaf. Pros: shields pre-5961 endpoints;
Junos-shape; the ACK actively proves liveness. Cons: the firewall
originates TCP segments mid-flow (rate-limiting, TX budget, spoofed-source
interplay); a *stale-baseline false refuse* now blackholes a legitimate RST
— the exact breakage the issue forbids; the v1 draft of B also had the
reply direction wrong (corrective ACK goes to the RST's *source*, i.e. the
original sender, swapped L2/L3/L4 identity — the existing builders already
do this); bigger surface (schema + compiler + docs + reply path). Deferred
follow-up once Option A's anchor accuracy is proven in the field (AGY r1
independently argues A-first for the same reasons).

### Option C — bidirectional-confirmation teardown

Demote FIN only after FIN-class flags in both directions; RST is normally
one-directional (RFC 793: a RST elicits no response), so bidirectional
confirmation would *never* fast-reap a legitimate one-way RST — the #3046
fast-reap dies and RST-churn workloads hold dead entries for the full
established/OPENING window. Rejected (table-pressure regression).

### Option D — status quo + documentation (PLAN-KILL flavor)

xpf matches Junos default *for RST handling*; the issue class is
robustness-DoS; Junos ships its own RST mitigation off-by-default.
Presented for completeness; not recommended — the teeth (firewall-state
kill + SNAT port swap + HA propagation) apply even when both endpoints are
RFC 5961-immune.

---

## 5. Concrete design (Option A, v2)

### 5.1 The anchor: one two-direction track on the canonical forward entry

`SessionEntry` gains (~24 B; plain POD, worker-owned, no serde, no HA
wire):

```rust
/// #6461: two-direction sequence/ack anchor for FIN/RST demote validation.
/// Lives ONLY on the canonical FORWARD entry (reverse entries carry none —
/// `account_packet` and the close path already hop reverse→forward, the
/// #2501/#4109 pattern). Node-local derived state — NOT carried on the HA
/// session-sync wire (same precedent as `established`, #3152).
/// All arithmetic is RFC 1982 serial (wrapping).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TcpSeqAnchor {
    fwd_seq_hi: u32,  // max(seq+seg_len) accepted for the forward stream
    fwd_ack_hi: u32,  // max ack accepted on forward segments
    rev_seq_hi: u32,  // max(seq+seg_len) accepted for the reverse stream
    rev_ack_hi: u32,  // max ack accepted on reverse segments
    fwd_wnd: u16,     // last raw advertised window, forward
    rev_wnd: u16,     // last raw advertised window, reverse
    valid: u8,        // bit0 fwd seq, bit1 fwd ack, bit2 rev seq, bit3 rev ack
    _pad: [u8; 3],
}
```

Why the forward entry: `account_packet` already resolves the forward entry
for BOTH directions (`mod.rs:1177-1211`), so one store serves every
validation with no cross-store merge (round-1 Codex B3's 2^31-ordering
problem disappears: there is never a second store to merge). Reverse
entries carry no anchor; a missing forward entry (e.g. FabricRedirect flows
with no local forward entry — the same missing-companion case
`account_packet` tolerates) means no anchor → fail-open.

### 5.2 Anchor updates: plausibility-gated slides at the two chokepoints

Two update sites, one store, one gating rule — together they cover every
TCP forwarding class:

- (a) **`account_packet`** (`flow_cache_hit.rs:312` and
  `poll_descriptor/mod.rs:3497`) — covers the cache-hit bulk AND the
  ForwardCandidate/FabricRedirect slow-path forward build. TCP only: read
  the 8 bytes at `packet_frame[meta.l4_offset+4 .. +12]` → `(seq, ack)`;
  `seg_len` from IP-declared length (§5.3). **The active frame is
  `packet_frame`, NOT `raw_frame`** — native GRE builds a synthetic
  decapped frame and the meta offsets index into it
  (`flow_cache_hit.rs:65-103`); reading `raw_frame` would parse the GRE
  outer header.
- (b) **`lookup_with_origin`** — covers every slow-path session hit that
  never reaches (or precedes) the cache: control segments, pre-cache
  packets, NAT64/NPTv6, and — round-2 AGY B1 — **LocalDelivery**, whose
  per-packet `to-zone junos-host` re-evaluation
  (`poll_descriptor/mod.rs:1744+`, #3706/#3485) runs through
  `resolve_flow_session_decision` → `lookup_session_across_scopes` on every
  host-inbound packet. `account_packet` is gated on
  ForwardCandidate|FabricRedirect (`poll_descriptor/mod.rs:3478-3481`) and
  LocalDelivery is neither, so WITHOUT this site the anchor of a
  firewall-destined BGP/SSH/IKE session would freeze at its install-time
  seed and every post-handshake legitimate close would soft-refuse — the
  exact management flows the issue names as victims. A firewall-originated
  flow's outbound direction is kernel-TX (unseen at AF_XDP); its anchor
  side is pinned by the inbound ACK stream (cross-direction leg, §5.4).
- (c) install time — the creating packet seeds the anchor for its direction
  (adopt unconditionally, set validity bit): SYN seeds `isn + SEG.LEN`
  (TFO/SYN-with-data included), a mid-stream pickup seeds from its first
  segment. An attacker-invented pickup flow anchors itself — killing a flow
  you yourself created is no loss; victim flows anchor from victim traffic.

Reverse-direction samples fold onto the canonical forward entry exactly as
`account_packet` folds counters today (`mod.rs:1177-1211`); lookup-path
updates on a reverse hit use the same post-borrow companion hop the close
marking uses (§5.5).

**Gating rule (round-1 Codex B1 — the trust anchor must not be
attacker-jumpable):** an ordinary (non-close) sample `s = seq + seg_len`
slides `seq_hi` forward only when `s` is within the current window:
accepted iff `!valid` (seed) or `s.wrapping_sub(seq_hi) <= FWD_SLACK`
(serially: `s` is at most `FWD_SLACK` ahead; anything at or behind
`seq_hi` is a no-op via max). Jumpy samples — a poison ACK-only segment
planted ahead of the window — are ignored *for tracking* (still forwarded;
the endpoint's own TCP deals with them). `ack_hi` updates gate identically.

**Stall analysis (round-2 AGY B2, made precise):** on a per-packet-tracked
path every forwarded packet is a sample, so `seq_hi` advances essentially
contiguously — the gap between the anchor and the next new-sequence sample
is bounded by the *reordering extent* of the path (in practice ≪ 64 KiB),
NOT by in-flight size. The anchor can fall >`FWD_SLACK` behind only when
(a) observation is interrupted (an untracked stretch — the covered classes
are fixed by sites (a)+(b); the documented residuals in §7 stay) or
(b) reordering extent exceeds `FWD_SLACK` (512 KiB of in-flight reordering
is pathological on real networks). When it does happen, every later legit
close soft-refuses: delivery unaffected, endpoints tear down, the entry
idles out on its ordinary timeout — a table-pressure cost, never a broken
connection. **No re-anchor escape hatch**: an "N contiguous rejected
samples → re-anchor" rule reopens the staging weakness at ~N+1 packets of
contiguous fake data (send 16 contiguous fake segments ahead of the window,
re-anchor, then RST at the new position) — injection-equivalent effort
defeats the purpose of the hatch only if the hatch is expensive, and it
cannot be made expensive without also stalling the legitimate case it
exists for. The residual is accepted and documented, not engineered
around.

**Ordering:** on a closing-flag packet, validation (§5.4) reads the
pre-packet anchor; the packet's own sample updates the anchor afterwards,
only if the close was accepted (a refused close updates nothing, §5.7).

### 5.3 seq/ack/seg_len extraction helper

One helper in `afxdp/frame/tcp.rs` (the module that already owns TCP
inspection), used by both update sites and the close validator:

```rust
/// #6461: (seq, ack, wnd, seg_len) for a full TCP segment on the ACTIVE
/// frame. seg_len = payload (IP-declared length, frame-clamped) + SYN + FIN,
/// mirroring `tcp_segment_consumed_len` (frame/tcp.rs:388-452): IPv4
/// total_len / IPv6 payload_len, true L4 offset via the ext-aware walker,
/// clamped to the frame — never `meta.pkt_len - meta.payload_offset`
/// (invalid on native GRE synthetic frames and counts Ethernet padding).
/// Returns None for non-TCP, truncated, or non-first-fragment frames.
fn tcp_seg_view(packet_frame: &[u8], meta: UserspaceDpMeta) -> Option<TcpSegView>;
```

Non-first fragments return None — belt-and-braces: #2344 already makes them
flowless, so neither update site ever runs for them.

### 5.4 The validation rule (single SSOT)

```rust
/// #6461: RFC 5961 §3.2 / RFC 9293 §3.5.2-inspired middlebox gate. A
/// FIN/RST demotes only when its sequence placement is plausible against
/// the PRE-PACKET anchor. Fail-open (true) when no baseline exists.
fn close_seq_plausible(anchor: &TcpSeqAnchor, dir_is_reverse: bool,
                       seg: TcpSegView, established: bool) -> bool;
```

For a closing segment in direction D (opposite O), with
`BACK_SLACK = 64 KiB` and `FWD_SLACK = clamp(2 × wnd(O), 64 KiB, 512 KiB)`
— **`wnd(O)` is the window the OPPOSITE direction's packets advertise**:
D's outstanding-at-abort data is bounded by O's receive window (D's
effective SEND window), not by D's own advertisement (round-2 AGY F4 — v2
consumed `wnd(D)`, the wrong input). The raw 16-bit wnd understates scaled
windows; the double-and-cap keeps the total acceptance interval in
[128 KiB, ~1.1 MiB] — honest arithmetic in §2/§8, no dead clamp:

1. **ESTABLISHED:** accept iff
   `seg.seq ∈ [seq_hi(D) − BACK_SLACK, seq_hi(D) + FWD_SLACK]`
   **OR** `seg.seq ∈ [ack_hi(O) − BACK_SLACK, ack_hi(O) + FWD_SLACK]`.
   The second leg is the RFC 9293 §3.5.2 closed-TCB reset (`SEQ=SEG.ACK`
   from the opposite direction — peer restart / state loss) and subsumes
   the asymmetric-routing case (a direction never observed has no
   `seq_hi(D)` validity bit; the opposite ACK stream still pins it).
2. **OPENING** (`!established`): accept iff (`ACK` set and
   `seg.ack ==` the seeded peer-side `seq_hi` value — i.e.
   `peer_isn + SEG.LEN`, covering TFO/SYN-with-data, since the seed at
   §5.2(c) already folds the SYN's payload into `seq_hi`; this accepts the
   Linux/Windows `seq=0, ack=isn+SEG.LEN` connection-refused RST, round-1
   AGY Q6 / round-2 AGY F6) **or** `seg.seq ==` the seeded own-side
   `seq_hi` (self-abort). Missing handshake baseline → fail-open.
3. **No valid baseline in any form** (HA-imported entry never locally
   observed) → fail-open (demote as today).
4. All comparisons RFC 1982 wrapping; the membership test is
   `seq.wrapping_sub(lo) <= hi.wrapping_sub(lo)` — no plain `hi - lo`
   (debug-build panic on wrap, round-1 Codex B3). A
   `const _: () = assert!(BACK_SLACK + FWD_SLACK_MAX < (1 << 31))` pins the
   window under the serial midpoint.

A refused demote leaves `closing`/`reset` untouched, performs **no**
`last_seen_ns` refresh and **no** wheel re-queue (§5.7), and bumps a
worker-owned `tcp_close_seq_rejected: u64` (+ one-shot `debug_log!` per
entry, never per-packet logging).

### 5.5 Where the verdict is applied — marking moves to the post-borrow phase

Today `lookup_with_origin` marks the matched entry inside its `&mut`
borrow, then propagates post-borrow. Validation needs the FORWARD entry's
anchor even when the matched entry is the reverse companion — a second
probe that cannot happen inside the first borrow. Restructure (close
segments only; the no-close path is byte-identical):

1. In-borrow: compute `do_close` (flag check) as today; capture
   `actual_key` + `nat` (already captured for propagation). **Do not mark
   and do not refresh `last_seen_ns` yet for a closing segment.**
2. Post-borrow (same phase that already calls
   `propagate_tcp_state_to_companion`): probe the forward entry, read the
   pre-packet anchor, run §5.4.
   - **Accept:** re-probe the matched entry, set `closing`/`reset`, refresh
     `last_seen_ns`, recompute `expires_after_ns`, then propagate to the
     companion exactly as today (the propagation path is unchanged — it
     fires only on accepted marks, inheriting validation).
   - **Refuse:** no marks, no refresh, no wheel push; bump the counter.
     `expires_after_ns`/`last_seen_ns` stay at their prior values — the
     entry ages on its pre-attack trajectory.

`update_session` (site 2) applies the same conjunction: the promote path
threads the packet's `TcpSegView`; validation reads the forward entry's
anchor (the entry being promoted IS the forward entry in the promotable
case — `is_translated_forward_session_key` family — so no extra probe);
wire-driven `update_session` callers (no packet) skip validation.

### 5.6 Constructor gating (the two-packet bypass, round-1 Codex B2)

`install_reverse_session_from_forward_match` (`shared_ops.rs:857-865`)
holds the `forward_match` in hand — whose entry carries the anchor. When
the current packet is closing-flagged, validate it (§5.4) against the
FORWARD entry's anchor first (the cross-direction legs cover a
reverse-direction close — `ack_hi(fwd)` pins the reverse stream's
position):

- **Accept** → install with `closing`/`reset` seeded as today (a legit
  one-way server RST keeps the #3046 2 s fast reap on this path).
- **Refuse** → **skip the install entirely** (round-2 AGY F3). The packet
  is still forwarded (the synthesized decision is returned regardless, the
  #1861 §5.4 pattern), but NO reverse entry is minted. v2's born-alive
  install let an attacker mint junk reverse entries at the full established
  timeout (300 s default) on a miss path the #4400 guard does not cover —
  a table-pressure vector strictly worse than master's born-dying 2 s
  entries. Skip-install removes it: the attacker gains no state at all; the
  next legitimate reply re-synthesizes the companion and revalidates
  against the same forward anchor; the forward companion is never marked
  from an unvalidated seed. A legit close we misjudged (stale anchor)
  costs only a re-synth on the next reply packet.
- The fabric-return seed (site 6) is already close-free (#4453); primary
  miss installs (site 3) are #4400-guarded; tunnel UpsertLocal (site 5) is
  trusted-local; wire re-import (site 4) carries no packet.

### 5.7 Refused-close side effects (round-1 Codex B11)

A refused close is inert: no mark, **no `last_seen_ns` refresh**, no wheel
re-queue. Refreshing on a refused close would hand the attacker a pinning
primitive (indefinite slot + SNAT-reservation hold with refused packets)
and would let refused packets extend an already-running 2s/30s closing
window forever. Not refreshing does not accelerate natural expiry — the
entry ages exactly as if the refused packet had never arrived. Ordinary
data/ACK packets continue to refresh normally through the unchanged
non-close path.

### 5.8 Signature/signature-shape changes (all crate-internal)

- `account_packet(key, len, tcp_flags, dscp)` → gains `seg: Option<TcpSegView>`
  (Both call sites already have the frame + meta; the helper is invoked
  only when `protocol == TCP`.)
- `lookup_with_origin` — no signature change (the seg view is computed by
  the `session_glue` caller and threaded via a new small struct on the
  resolve path; `icmp_embed` callers pass `None` and flags 0 — validation
  never fires, byte-identical).
- `install_reverse_session_from_forward_match` gains the forward anchor
  read + validator call.
- `SessionUpdate` gains `seg: Option<TcpSegView>`.
- No `FlowCacheEntry` change, no shim/meta change (no `make generate`),
  no HA wire change, no shared-map schema change, no config schema change.

---

## 6. Public API preservation

No public API exists to preserve: `SessionTable`, `account_packet`,
`lookup_with_origin`, `update_session`, `install_with_protocol_with_origin`,
`FlowCacheEntry` are all `pub(crate)`/`pub(super)`. gRPC/REST/CLI surfaces
unchanged. HA sync wire unchanged (rolling-upgrade safe: no wire field
added or reinterpreted; a mixed-version peer pair simply has one gated node
and one ungated node, each gating only its own packet-driven marks).
`UserspaceDpMeta` and the XDP shim are untouched.

---

## 7. Hidden invariants the change must preserve

- **Anchor single-store invariant:** only the canonical forward entry
  carries an anchor; every update goes through `account_packet` (+install
  seed); every validation reads the same store. No second store, no merge.
- **Pre-packet validation:** a closing segment never updates the anchor
  before its own verdict; on refuse it updates nothing at all.
- **Plausibility-gated slides:** the anchor cannot jump more than
  `FWD_SLACK` per accepted sample; a `const _` assert pins
  `BACK_SLACK + FWD_SLACK_MAX < 2^31`.
- **Stickiness contracts:** `closing` (#3489), `reset` (#3046),
  `established` (#3152) remain monotone within an entry's life; the gate
  only withholds a mark, never clears one. The #3046 timeout-selection
  ordering (`reset` consulted before `expires_after_ns`) is unchanged.
- **HA replica no-Close invariant (LOAD-BEARING, round-1 Codex B8):**
  `expire.rs:342-345` emits Close deltas only for non-peer-synced,
  non-reverse, non-transient-seed origins; `SharedMaterialize`/`SyncImport`/
  `WorkerLocalImport` are all peer-synced (`entry.rs:245-250`), and
  promotion requires a `ForwardCandidate` disposition on the promoting node
  (`promote.rs:86-90`) — i.e. local RG ownership
  (`enforce_session_ha_resolution` → HAInactive on the non-owner). The Go
  side has NO origin/generation protection on decoded closes (gen-zero
  deletes apply unconditionally, `sync_conn_gen.go:176-186`), so this Rust
  gate is the only barrier between a non-owner reap and the owner's
  authoritative entry. The plan adds an exact regression test
  (`SharedMaterialize + reset + FabricRedirect + stale-ceiling reap` →
  no delta, no owner/shared deletion) and names the invariant in the
  module docs.
- **Hot-path discipline:** zero new allocations; zero new atomics; the
  per-TCP-packet cost inside `account_packet`'s existing probe is one
  8-byte read + ≤2 gated stores; closing segments add one table probe on a
  path that already takes the full slow path. `SessionEntry` grows ~24 B
  (§2 cost stated; slab is uniform — UDP/ICMP entries carry it unused).
- **Borrow shape:** close-path validation and marking happen post-borrow in
  the existing propagation phase; no new cross-`&mut` aliasing; the
  non-close path's borrow structure is byte-identical.
- **GRE/frame identity:** all frame reads use the ACTIVE `packet_frame`;
  seg_len from IP-declared lengths with frame clamping.
- **Fragments:** non-first fragments stay flowless (#2344); the helper
  returns None for them defensively.
- **Exotic extension chains (documented residual):** the shim walks ≤6
  known ext-header types (`userspace-xdp/lib.rs:1257-1289`); TCP behind
  Mobility/HIP/Shim6/experimental types or >6-deep chains is stamped as the
  ext protocol, so those packets never advance the TCP anchor (they also
  never join the TCP session). A later plain-header RST then sees a
  stale-but-valid anchor: legit close soft-refused (entry lingers, delivery
  unaffected), blind close no easier. Rare-transport residual, accepted.
- **LocalDelivery replies** leave via kernel TX and never traverse AF_XDP;
  the anchor for a firewall-originated flow's outbound direction is pinned
  by the inbound ACK stream (cross-direction leg) — the attack-relevant
  inbound direction is fully tracked.

---

## 8. Risk assessment

| Class | Verdict | Notes |
|---|---|---|
| Behavioral regression | MED | Gate only withholds demotion, never blocks delivery; fail-open on missing baseline. Residuals (stated in §2): soft-refused legit close on >64–512 KiB in-flight aborts → entry idles ≤ established timeout; tuple stays busy meanwhile — pre-existing semantics for silently-dead flows. Restart-RST covered by the union rule. OPENING covered by SEG.LEN-aware ack check. |
| Lifetime / borrow-checker | LOW | Anchor is `Copy` POD on an existing entry; marking restructured into the existing post-borrow propagation phase; no new cross-boundary borrows. |
| Performance regression | LOW-MED | ~24 B/entry slab growth (~3 MiB/worker at cap); one 8-byte read + ≤2 gated stores per TCP packet inside an existing probe; one extra probe per closing segment. Must be measured at minimum-frame rates (§9) — the 23 Gbit/s MTU-sized iperf run alone is insufficient (≈37 Mpps at 25 Gbit/s small-frame is the real gate). |
| Architectural mismatch | LOW | No new subsystem; anchors at the existing #2501 chokepoint; #4400-style always-on gate. No pipeline restructure. |
| HA / rolling upgrade | LOW | No wire change; mixed-version peers each gate only their own marks; the replica no-Close invariant is regression-tested. |
| Merge collision | LOW | No `FlowCacheEntry` change (v1's #6457 tension gone). `account_packet` signature change is local to two call sites. |

---

## 9. Test plan

Unit (cargo):

- Validator truth table: ESTABLISHED fresh anchor (accept in-window
  RST/FIN; refuse low/high out-of-window; refuse far-future), the union
  leg (restart-RST `SEQ=SEG.ACK` accepted via `ack_hi(O)` when `seq_hi(D)`
  refuses), serial-wrap edges (anchor near 2^32−1, `wrapping_sub`
  membership, no panic), OPENING (`ack == isn+SEG.LEN` accept incl. TFO,
  wrong-ack refuse, missing-baseline fail-open), asymmetric (only one
  direction observed), no-baseline fail-open.
- **Poisoning (round-1 Codex B1):** ACK-only plant ahead of window does not
  move the anchor; RST at the planted seq still refused; in-window
  contiguous fake data slides the anchor at most FWD_SLACK per packet;
  a close validates on the pre-packet anchor even when its own seq would
  extend it.
- **Two-packet reverse-NAT bypass (round-1 Codex B2):** blind RST on
  reverse tuple → reverse entry born ALIVE (`closing=false`); second blind
  RST → forward companion NOT marked, `tcp_close_seq_rejected` bumped;
  in-window variant → seeded closing and companion propagation fire exactly
  as today (#3046 fast reap preserved).
- Anchor single-store: reverse packets update only the forward entry;
  missing-forward fail-open (FabricRedirect no-local-reverse shape).
- Refused-close inertness: no `last_seen` change, no wheel re-queue, prior
  expiry trajectory preserved; closing-window not extendable by refused
  packets after an accepted close.
- **HA invariant regression (round-1 Codex B8):** `SharedMaterialize +
  reset + FabricRedirect + stale-ceiling reap` emits no Close delta and no
  shared/owner deletion.
- seg_len: GRE synthetic-frame correctness (active frame, IP-declared
  length), Ethernet-padding exclusion, IPv6 ext-chain walk, fragment →
  None, TFO SYN-with-data.
- Existing suites green: `make test-rust`, `make test-go`.

Smoke (loss userspace cluster, lock protocol per CLAUDE.md):

- `make cluster-deploy` + re-apply CoS.
- Throughput gate: `iperf3 -P 16 -t 30 -p 5203` → 172.16.80.200 ≥ 23
  Gbit/s (no regression vs pre-change), **plus a small-frame run**
  (`-l 64`/high-pps) to gate the per-packet anchor cost.
- Attack negative: long-lived SSH + iperf3 trust→untrust; off-path scapy
  RST/FIN with random seq (thousands, ≥ window scale) → flow survives,
  session stays established, `tcp_close_seq_rejected` advances.
- Legit positive: in-window RST (seq captured via tcpdump) → 2 s demote
  exactly as today; ordinary iperf3/SSH Ctrl-C teardown identical to
  master; connection-refused RST against a half-open → opening reap
  unchanged.
- HA: `make test-failover` (mandatory); standby copy survives the blind
  spray and dies only on the validated close.

---

## 10. Out of scope (explicitly)

- Junos general per-packet sequence check (`no-sequence-check` enforcement,
  #2008 M9 / #2078) — the wscale-aware data-plane window check on *every*
  segment. Bigger, throughput-sensitive, asymmetric-routing-hostile;
  separate issue. (Named honestly: xpf lacks this Junos-DEFAULT check;
  this plan closes only the RST/FIN demote DoS.)
- Option B (drop + challenge-ACK, `rst-sequence-check` leaf) and
  `fin-invalidate-session` — deferred until anchor accuracy is proven in
  the field. (`rst-invalidate-session` already parses; wiring its immediate
  teardown semantics is its own change.)
- Refused-close rate limiting / attack-escalation latch — follow-up if
  field data shows spray-forcing of the window.
- SYN-segment validation (RFC 5961 §3.3) — different class (desync, not
  teardown).
- Shim `meta_flags` fragment bit — unnecessary: #2344 makes non-first
  fragments flowless.
- Any change to reap windows, wheel, deltas, RT_FLOW, or the Go control
  plane (the HA no-Close invariant is TESTED, not modified).

---

## 11. Open questions for adversarial review (round 2)

1. **Plausibility-gated slides:** with updates gated to
   `[anchor, anchor + FWD_SLACK]`, is there any legitimate traffic pattern
   that stalls the anchor (real data repeatedly arriving >FWD_SLACK ahead —
   e.g. a burst after a long loss episode where the endpoint accepted a
   >window jump)? TCP endpoints themselves drop beyond-window data, so the
   anchor should re-converge on the next in-window sample — is that
   reasoning airtight, and does the re-convergence need an explicit
   "resync after N consecutive rejected samples" escape hatch?
2. **The reverse-synth born-alive path:** after a refused close seed, the
   reverse entry lives at the full established window though the endpoint
   may already be dead (legit RST we misjudged). Bounded by the idle
   timeout — acceptable, or should refused-seeds get a shorter probationary
   window (and is that worth a new timer class)?
3. **`FWD_SLACK = clamp(2 × wnd(D), 64 KiB, 512 KiB)`:** defensible middle
   of the legit-refuse vs spray-cost tradeoff at 10–25 Gbit/s? Show the
   arithmetic both ways.
4. **Post-borrow marking:** the restructure moves the close mark + refresh
   out of the first `&mut` borrow into the propagation phase (one extra
   probe on close segments). Any correctness hazard in the interim state
   (a concurrent... single-threaded worker — the only interleaving is the
   same packet's later stages; confirm nothing between the two probes can
   observe the un-marked entry), and any measurable hot-path cost?
5. **Missing-forward fail-open:** FabricRedirect flows with no local
   forward entry have no anchor → blind RST demotes as today. Is that
   class enumerable in the field (how often is the forward entry absent
   when a reverse close arrives), and does the fabric/sync coverage make it
   a non-issue in practice?
6. **Should the anchor ride the HA wire after all?** v2 keeps it node-local
   (fail-open post-failover until first local packet). The alternative
   (additive wire field, rolling-gated) would let a post-failover node
   validate immediately. Is the failover-window residual (a blind RST
   landing in the seconds after promotion, before the first observed
   packet) small enough to stay node-local?
7. **Counter surface:** is a per-worker `tcp_close_seq_rejected` enough
   observability, or should refused closes also emit a rate-limited
   RT_FLOW/screen-class record so operators can see an attack in progress
   without debug builds?
