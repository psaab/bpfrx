# #6461 — blind off-path TCP RST/FIN demotes a live session with no sequence validation

**Status: DRAFT v4 — revised after round-2 convergence (Codex PLAN NO, AGY
PLAN NO, Claude SMR PLAN NO — same core verdict: flip no-baseline to
refuse-demote, gate the materialize constructor, bound seed trust)**

v1 → v2: round-1 review killed v1's architecture (attacker-writable trust
anchor, missed reverse-NAT constructor, invalid cross-store serial merge).
v2 was redesigned around a single two-direction anchor on the canonical
forward entry, plausibility-gated anchor updates, pre-packet validation,
and constructor gating.
v2 → v3: round-2 AGY folds — anchor updates in BOTH `lookup_with_origin`
(every slow-path session hit incl. LocalDelivery) AND `account_packet`
(cache-hit bulk); refused close seed SKIPS the reverse install; `FWD_SLACK`
from `wnd(O)`; TFO-aware OPENING seed.
v3 → v4: round-2 convergence (all three reviewers independently traced the
same blocker): (a) no-baseline **fail-open re-admitted the cluster kill** —
post-failover, a blind RST as the first locally-observed packet promotes a
synced entry to `SharedPromote` (NOT peer-synced, `entry.rs:245-250`), and
its 2 s reap emits a Close delta that deletes the shared + standby copies
cluster-wide; (b) the **materialize seed** (`materialize_shared_session_hit`
threads the current packet's flags into `upsert_synced_with_origin` →
`install.rs:399-400`) is a third packet-derived constructor v3 missed;
(c) **seed trust**: `!valid` seeds are now cross-bounded against an
already-trusted opposite anchor (kills the 2-packet seed race), ack samples
require `has_ack` (a SYN retransmit's zero ACK field permanently poisoned a
near-zero acceptance leg), seq slides require `seg_len > 0`, closing
segments never update the anchor, closing packets never promote; (d)
arithmetic restated — the ESTABLISHED union acceptance is TWO windows
(1/16384 floor, ~1/10923 max reachable), and `2×wnd(O)` self-bounds at
131,070 (the 512 KiB cap was dead). Round-1/2 review docs sit alongside
this file.

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
  pool-port mid-flow swap). Attacker cost: 1 packet per ~2 s, anytime.
- After: a blind close validates only inside the ESTABLISHED union
  acceptance interval — up to **two** windows,
  `window(seq_hi(D)) ∪ window(ack_hi(O))`, each `BACK_SLACK + FWD_SLACK + 1`
  wide (`FWD_SLACK = max(2×wnd(O), 64 KiB)`, self-bounding at 131,070 since
  raw `wnd` is u16). Worst-case (both legs valid and disjoint):
  floor `2 × 131,073 = 262,146` values ≈ **1/16384 per guess**; maximum
  reachable `2 × 196,607 = 393,214` ≈ **1/10923**. When the legs overlap
  (the common case — seq and ack positions track within a window) the
  figure halves toward 1/32768. At 1,000 minimum-size closes/s (~1 Mbit/s)
  the expected spray-to-kill is **~16 s (floor) to ~11 s (max)** of
  sustained spraying per kill — stated as the honest worst case, not the
  best.
- **Observation boundary (round-2 Codex, restated honestly):** the anchor
  learns from segments the *session layer observes*, which is not
  identical to "packets endpoints receive." Both `account_packet` sites
  are post-TTL (the cache path's TTL check is hoisted above its side
  effects, `flow_cache_hit.rs:321-325`; the slow-path site runs after the
  :846-880 TTL arm), but site (b) at resolve time precedes input-filter
  and host-admission drops, and site (a) precedes output-filter/CoS drops
  (`forward_request.rs:264-290, :368`). A TTL-crafted or filter-dropped
  in-window close can therefore demote without endpoint delivery — but
  that is master's existing trust boundary for closing state (marking has
  always happened at lookup, before those drops), the in-window
  difficulty is unchanged, and the gate strictly *reduces* what an
  observed packet can do. Moving the anchor to a post-forward-commit hook
  is purity without a security delta; rejected, with the boundary
  documented here instead. The endpoint-backstop framing from v1-v3 is
  dropped: sprayed closes may never reach an endpoint, so RFC 5961
  endpoint handling is not part of the cost model.
- Anchor-walking (feeding contiguous fake in-window data to slide the
  anchor, then RST) requires landing a first in-window sample (the same
  ~1/2^13–1/2^14 guess) and buys the attacker nothing beyond it: the
  acceptance window follows the anchor, so a single kill needs a single
  in-window guess regardless. `seg_len > 0` is required for `seq_hi`
  slides (v4), so zero-length probes cannot walk the anchor at one packet
  per slack.
- **First-observation race residual (v4, bounded):** entries with no
  trusted local baseline (HA-imported and never locally observed,
  pre-upgrade) refuse demotion outright — the post-failover
  `SharedPromote` cluster-kill trace is dead. A direction's first
  observed sample seeds only if cross-bounded against an *already-trusted*
  opposite anchor (attacker cost: one in-window guess, ~1/2^13, same as
  attacking the close directly — no amplification); seeds with no trusted
  opposite anchor stay untrusted and never validate a close. The
  irreducible residual: with *zero* wire-truth on both sides, any policy
  is arbitrary — refuse-demote is the safe one, and it costs legit
  RST-first-after-failover flows a lingering entry (≤ ordinary timeout,
  delivery unaffected, endpoints tear down). The additive HA-wire anchor
  field (§10 follow-up) closes even that for synced flows.
- What this costs a legitimate teardown when the gate misjudges: the
  packet is always delivered (endpoints tear down normally), the entry
  idles out on its ordinary timeout instead of the 2 s/30 s fast reap —
  a table-pressure cost, never a broken connection. Aggregate version
  (round-2 Codex): a both-direction path-switch can stall an anchor
  permanently (§5.2); many flows stalling after one path event linger to
  their established timeouts — bounded, self-healing as flows churn.
- Cost: ~26 B of new state on `SessionEntry` (uniform slab — includes
  UDP/ICMP entries that never use it; ≈ 3 MiB per worker at the 131,072
  cap, ≈ 18 MiB at 6 workers), one 8-byte TCP-header read plus two
  plausibility-gated `u32` stores per TCP data packet inside the existing
  `account_packet` session-table probe, and a second table probe only on
  closing-flag segments (which already take the full slow path).

What the fix does **not** buy: protection against an on-path attacker
(observes sequence numbers; out of threat model); protection of pre-5961
endpoints against in-window blind RSTs delivered through the firewall (the
packet is always forwarded — their stacks are the last line, as they are
today); a guarantee that a determined multi-thousand-packet spray cannot
eventually force one demote (it can); the Junos general data-plane sequence
check (§10). Legitimate-teardown residual, stated plainly: a real RST/FIN
whose unobserved in-flight data at abort time exceeds the forward slack
(64–128 KiB ≈ 21–42 µs at 25 Gbit/s — sized for reordering, not BDP) is
refused the early demote — the packet is delivered, endpoints tear down
normally, and the entry idles out on its ordinary timeout instead of the
2 s fast reap. That is a table-pressure cost, never a broken connection.

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
  the non-owner node); see §7's coverage residuals for why a later close
  there kills nothing authoritative.
- **#2008 M9 / #2078** — `no-sequence-check` parsed, unenforced.
  `rst-invalidate-session` parsed (schema + compiler, see §1).
  `rst-sequence-check` and `fin-invalidate-session` are NOT in the xpf
  schema.
- **#6457 (in flight, adjacent)** — flow-cache delete/invalidate on session
  reap. v2 no longer touches `FlowCacheEntry` at all (a v1 casualty:
  Codex B3/B4/B12), so the merge tension disappears.

### Packet-driven closing/reset sites (complete, round-2-verified inventory)

| # | Site | Trigger | v4 treatment |
|---|---|---|---|
| 1 | `session/lookup.rs:105-128` HIT path (real endpoint FIN/RST) | wire packet flags | gate via pre-packet anchor validation, marking moved to post-borrow phase (§5.5); closing packets never promote (§5.5) |
| 2 | `session/mod.rs:1396-1432` `update_session` via `promote_synced_with_origin` (HA shared-promote, `session_glue/promote.rs:99-107`) | wire packet flags on the promoting packet | same gate (flags threaded with seg view); no-baseline → refuse (§5.4 rule 3) |
| 2b | **reverse-NAT companion synthesizer** — `session_glue/mod.rs:1262-1284` → `shared_ops.rs:857-865` → `install_with_protocol_with_origin` (seeds at `install.rs:179-180`) | wire packet flags on a reverse-tuple miss with a live forward match; runs at resolve time, BEFORE the #4400 guard | gate the seed with the validator against the in-hand forward entry's anchor; refused close → **skip the install entirely** (§5.6); a SHARED `ForwardSessionMatch` carries no anchor (`entry.rs:209`) → no-baseline → refuse → skip-install (round-2 Codex 8) |
| 2c | **reactive shared materialize** — `materialize_shared_session_hit` (`session_glue/mod.rs:1092-1118`) threads the current packet's `tcp_flags` into `upsert_synced_with_origin` (seeds at `install.rs:399-400`) | wire packet flags on a shared-map hit | **round-2 Codex 1 / SMR 2 — v3 missed this constructor.** Gate the flag seed with the validator; an imported entry has no anchor → no-baseline → refuse → install the copy **alive** (`closing=false, reset=false`; the install cannot be skipped — the packet needs its decision and the entry must own the flow going forward) |
| 3 | `install.rs:179-180` primary miss installs | creating packet flags | already unreachable for bare closes (#4400); SYN-bearing malformed closes are screen-owned; no change |
| 4 | HA wire re-import — eventstream `UpsertSynced` → `upsert_synced_with_origin` (no packet exists) | peer delta | validation-free by design (the peer validated before reaping and emitting the Close); distinct from site 2c, which HAS a packet |
| 5 | tunnel `UpsertLocal` (`tunnel.rs:563-615` → `session_glue/mod.rs:786-800`) | locally generated packets (firewall-originated tunnel TX) | trusted-local class, documented; not wire-attacker-controllable. Inbound tunnel closes land on site 1 with whatever anchor the inbound stream built — none if the flow is outbound-only → refuse-demote; local blast radius (round-2 Codex 5) |
| 6 | fabric-return reverse seed (`cluster_peer_return_fast_path` install) | fabric-ingress packet flags | bare closes already excluded (#4453); the non-close seed bypasses both anchor sites (round-2 Codex 5) — a later close demotes only the local reverse seed and `is_reverse` suppresses the Close delta; no owner kill; documented |
| 7 | CLI/control deletes, GC/reaper, screens/SYN-cookie | — | consumers / unaffected |
| 8 | **forward-wire immutable match** — `find_forward_wire_match_with_origin` (`lookup.rs:258-293` via `shared_ops.rs:614-628`): NAT64 forward direction, hairpin, non-bijective NAT | wire packet on the forward-wire tuple | **demote-free by construction (round-2 Codex 4):** the match is immutable (cloned decision/metadata — no `&mut`, no mark, no refresh, today and after this change). Closes on this path never demoted on master, so there is nothing to gate. The anchor for these flows advances from the reverse (mutable alias) direction only; pre-existing forward-direction accounting/refresh asymmetry (NAT64) is out of scope — filed as a follow-up candidate |

---

## 4. Multiple path options

### Option A — sequence-window demote gate, state-only (RECOMMENDED, v4 shape)

Track flow sequence progress at the existing accounting chokepoints; gate
**only** the `closing`/`reset` demotion (and its companion propagation and
install-time seeds) on the closing segment's placement against a *trusted*
anchor. The packet itself is always forwarded unchanged — endpoint teardown
delivery is never blocked, so no legitimate teardown can be broken by the
firewall; the worst failure is a *refused demote* (entry idles out on its
normal timeout, exactly as if the RST had been lost in transit — a
condition #3046 already tolerates by design). Always-on (no config knob),
mirroring the #4400 precedent: the gate can only make the firewall *more*
conservative about killing state. **v4: refuse-demote whenever no trusted
baseline exists** (round-2 convergence) — fail-open was the wrong edge
policy precisely where the attacker has the most control: the
no-baseline windows (post-failover, post-upgrade, post-materialize) are
observable/timable (failover GARP is a public signal), and the
`SharedPromote` reap path turns a fail-open mark into a cluster-wide
delete (§5.4 rule 3 trace). The active node remains the validating node;
standby copies die only via the peer's post-validation Close delta.

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

## 5. Concrete design (Option A, v4)

### 5.1 The anchor: one two-direction track on the canonical forward entry

`SessionEntry` gains (~26 B; plain POD, worker-owned, no serde, no HA
wire):

```rust
/// #6461: two-direction sequence/ack anchor for FIN/RST demote validation.
/// Lives ONLY on the canonical FORWARD entry (reverse entries carry none —
/// `account_packet` and the close path already hop reverse→forward, the
/// #2501/#4109 pattern). Node-local derived state — NOT carried on the HA
/// session-sync wire (same precedent as `established`, #3152; carrying it
/// is the §10 follow-up).
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
    trusted: u8,      // same bit layout: this side may validate a close (§5.2)
    _pad: [u8; 2],
}
```

Why the forward entry: `account_packet` already resolves the forward entry
for BOTH directions (`mod.rs:1177-1211`), so one store serves every
validation with no cross-store merge (round-1 Codex B3's 2^31-ordering
problem disappears: there is never a second store to merge). Reverse
entries carry no anchor; a missing forward entry (e.g. FabricRedirect flows
with no local forward entry — the same missing-companion case
`account_packet` tolerates) means no anchor → **refuse-demote** (v4; the
non-owner's copies are non-authoritative — `is_reverse`/peer-synced origins
suppress their Close deltas — and the owner validates the redirected close
against its own anchor).

### 5.2 Anchor updates: trust, gating, and the two chokepoints

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
  outer header. Both sites are post-TTL (cache path: #3779 hoisted the
  TTL check above the side effects, `flow_cache_hit.rs:321-325`; slow
  path: the :846-880 TTL arm precedes the :3494 forward build).
- (b) **`lookup_with_origin`** — covers every slow-path session hit that
  never reaches (or precedes) the cache: control segments, pre-cache
  packets, NAT64/NPTv6, and — round-2 AGY B1 — **LocalDelivery**, whose
  per-packet `to-zone junos-host` re-evaluation
  (`poll_descriptor/mod.rs:640-654`, #3706/#3485) runs through
  `resolve_flow_session_decision` → `lookup_session_across_scopes` on every
  host-inbound packet. `account_packet` is gated on
  ForwardCandidate|FabricRedirect (`poll_descriptor/mod.rs:3478-3481`) and
  LocalDelivery is neither, so WITHOUT this site the anchor of a
  firewall-destined BGP/SSH/IKE session would freeze at its install-time
  seed and every post-handshake legitimate close would soft-refuse — the
  exact management flows the issue names as victims. A firewall-originated
  flow's outbound direction is kernel-TX (unseen at AF_XDP); its anchor
  side is pinned by the inbound ACK stream (cross-direction leg, §5.4).
  **Boundary note (round-2 Codex 2):** site (b) runs at resolve time,
  before input-filter/host-admission drops — anchor samples are
  session-layer observations, not forwarded-commitments. That is master's
  existing trust boundary for closing state (marking has always happened
  at lookup); the in-window difficulty of abusing it is unchanged; the
  gate strictly reduces what an observed packet can do. Not moved (§2).
- (c) install time — the creating packet seeds the anchor for its direction
  (adopt unconditionally, set the validity **and trust** bits — a locally
  observed handshake/pickup is wire-truth): SYN seeds `isn + SEG.LEN`
  (TFO/SYN-with-data included), a mid-stream pickup seeds from its first
  segment. Install seeds set **seq validity only** — never ack validity
  (a SYN's ACK field is meaningless; round-2 Codex 3 — see the gating
  rule). An attacker-invented pickup flow anchors itself — killing a flow
  you yourself created is no loss; victim flows anchor from victim traffic.

Reverse-direction samples fold onto the canonical forward entry exactly as
`account_packet` folds counters today (`mod.rs:1177-1211`); lookup-path
updates on a reverse hit use the same post-borrow companion hop the close
marking uses (§5.5). A slow-path ForwardCandidate packet transits BOTH
sites — the same sample applied twice, value-idempotent via the gated max
(sequential borrows, no hazard; deliberately no dedup token — round-2
Codex 9 confirms none is required).

**The gating rules (round-1 Codex B1 + round-2 Codex 3 — the trust anchor
must be neither attacker-jumpable nor attacker-seedable):**

1. **Closing segments never update the anchor.** A FIN/RST's own sample is
   not applied at any site, before or after validation (validation reads
   the pre-packet anchor; on accept the entry is dying and the anchor is
   moot). `account_packet` skips anchor updates for `is_closing(flags)`
   packets outright — it never learns the close verdict (round-2 Codex 9).
2. **seq slides:** an ordinary (non-close) sample `s = seq + seg_len` with
   **`seg_len > 0`** slides `seq_hi` forward only within the current
   window: accepted iff `!valid` (seed — rule 4) or
   `s.wrapping_sub(seq_hi) <= FWD_SLACK` (serially: at most `FWD_SLACK`
   ahead; anything at or behind is a no-op via max). Zero-length samples
   update `wnd`/`ack_hi` only — one packet per slack of anchor-walking is
   no longer available (round-2 Codex 3).
3. **ack slides:** `ack_hi` updates ONLY from ACK-bearing segments
   (`has_ack`), same window rule. Without this, a SYN retransmit's zero
   ACK field seeds `ack_hi ≈ 0` on an OPENING hit, and the real ACK stream
   (≫ `FWD_SLACK` away) can never repair it — a permanent acceptance
   window near sequence zero that a naive `seq=1` blind RST validates
   (round-2 Codex 3; this was a live hole in v1–v3).
4. **seed trust (round-2 Codex 3 / SMR 3):** trust is acquired per
   *segment*, not per field — **a segment authenticates when ANY of its
   fields cross-bounds against trusted state, and all samples of an
   authenticated segment are adopted `valid`+`trusted`**:
   - a seq sample for direction D cross-bounds against `ack_hi(O)`
     (O's ack of D's data tracks D's real position even while D is
     unobserved, so legit asymmetric rejoins pass);
   - an ack sample for D cross-bounds against `seq_hi(O)`;
   - install seeds (rule (c)) are self-authenticating (the session exists
     because the firewall saw this segment; an attacker's spoofed SYN
     anchors only its own invented flow).
   The handshake bootstraps cleanly: the SYN self-authenticates (fwd seq
   trusted); the SYN-ACK authenticates via `ack == fwd seed` (the
   handshake proof — a spoofed SYN-ACK needs the client ISN, 1/2^32) so
   BOTH its seq and ack are trusted (a fast server abort right after
   connect validates — rule-1 leg `seq_hi(rev)` is trusted from birth);
   the client's first ACK authenticates via `ack == rev seed`. Mid-flow,
   every real segment authenticates trivially (contiguity). Attacker
   cost: landing ANY field inside a trusted window is one ~1/2^13 guess —
   identical to attacking the close directly, so seeding confers **no
   amplification** (a fake trusted seed at X then a RST at X costs the
   same expected sprays as a direct in-window RST guess).
   Samples of an UNauthenticated segment are adopted `valid` but
   **untrusted** (tracking only): they never validate a close (§5.4), and
   untrusted state cannot authenticate other segments (a fabricated
   self-consistent pair stays untrusted). The 2-packet seed race from v3
   (spoof data seq=X, then RST at X) dies: either trusted state exists to
   bound against (the seed is a 1/2^13 guess, same as the direct attack)
   or it doesn't (the close is refused regardless).
   The residual: an HA-imported/pre-upgrade entry with zero local
   wire-truth never authenticates a segment — its legit teardowns linger
   to the ordinary timeout (bounded; delivery unaffected; churn replaces
   the entry with trusted seeds). The additive HA-wire anchor field (§10
   follow-up) restores fast-reap for the synced class.
5. **Closing packets never promote.** `promote_from_reverse`
   (`lookup.rs:146-149`) currently sets `established` in-borrow on any
   reverse SYN-ACK — including a SYN+ACK+RST-flagged packet whose close is
   later refused. v4: the in-borrow promote is skipped for
   `is_closing(flags)` packets (a legit simultaneous SYN-ACK+RST is
   pathological; screens own the malformed combos) so every close-packet
   mutation is gated by the verdict (round-2 Codex 9).

**Stall analysis (round-2 AGY B2 + Codex 7, made precise):** on a
per-packet-tracked path every forwarded packet is a sample, so `seq_hi`
advances essentially contiguously — the gap between the anchor and the
next new-sequence sample is bounded by the *reordering extent* of the
path (in practice ≪ 64 KiB), NOT by in-flight size. The anchor can fall
>`FWD_SLACK` behind when (a) observation is interrupted (an untracked
stretch — the covered classes are fixed by sites (a)+(b); the documented
residuals in §7 stay), (b) reordering extent exceeds `FWD_SLACK`, or
(c) **a both-direction path switch** (round-2 Codex 7): a route/asymmetry
flap lets seq AND cumulative-ack progress advance off-box together, then
rejoin >slack ahead — the endpoints accepted the stretch, nothing
retransmits near the stale anchor, and both legs stay rejected
permanently. The consequence per flow is soft-refused legit closes +
ordinary-timeout aging (delivery unaffected, endpoints tear down
normally); the aggregate version is many flows lingering to their
established timeouts after one path event — bounded, self-healing as
flows churn. **No re-anchor escape hatch**: an "N contiguous rejected
samples → re-anchor" rule is stageable at ~N+1 packets of contiguous fake
data, reopening the round-1 B1 weakness; round-2 Codex 7 independently
reached the same refusal. Recovery belongs to trusted state (the §10
HA-wire follow-up), not to observation-counting heuristics.

**Ordering:** on a closing-flag packet, validation (§5.4) reads the
pre-packet anchor; per rule 1 the packet never updates it.

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
/// the PRE-PACKET anchor AND the consulted leg is TRUSTED (§5.2 rule 4).
/// Refuse (never fail-open) when no trusted baseline exists.
/// `established` and the anchor are ALWAYS read from the canonical
/// FORWARD entry (round-2 Codex 8: a synthesized reverse is born
/// ESTABLISHED at install.rs:161 even while the forward is OPENING — the
/// matched entry's own flag is the wrong input).
fn close_seq_plausible(anchor: &TcpSeqAnchor, dir_is_reverse: bool,
                       seg: TcpSegView, established: bool) -> bool;
```

For a closing segment in direction D (opposite O), with
`BACK_SLACK = 64 KiB` and `FWD_SLACK = max(2 × wnd(O), 64 KiB)` —
**`wnd(O)` is the window the OPPOSITE direction's packets advertise**:
D's outstanding-at-abort data is bounded by O's receive window (D's
effective SEND window), not by D's own advertisement (round-2 AGY F4).
Raw u16 `wnd` self-bounds the slack at 131,070 — no upper clamp (v2's
512 KiB cap was dead arithmetic, round-2 Codex 6); wscale tracking is
deliberately not done (the slack covers reordering + abort-time in-flight
on the *observed* path, not BDP; unobserved stretches are the stall
residual regardless of slack size). The total union acceptance interval
is honestly stated in §2 (262,146–393,214 values worst case):

1. **ESTABLISHED:** accept iff
   (`trusted(seq_hi(D))` AND `seg.seq ∈ [seq_hi(D) − BACK_SLACK, seq_hi(D) + FWD_SLACK]`)
   **OR** (`trusted(ack_hi(O))` AND `seg.seq ∈ [ack_hi(O) − BACK_SLACK, ack_hi(O) + FWD_SLACK]`).
   The second leg is the RFC 9293 §3.5.2 closed-TCB reset (`SEQ=SEG.ACK`
   from the opposite direction — peer restart / state loss) and subsumes
   the asymmetric-routing case (a direction never observed has no trusted
   `seq_hi(D)`; the opposite ACK stream still pins it).
2. **OPENING** (`!established` on the FORWARD entry): accept iff (`ACK`
   set and `seg.ack ==` the seeded peer-side `seq_hi` value — i.e.
   `peer_isn + SEG.LEN`, covering TFO/SYN-with-data, since the seed at
   §5.2(c) already folds the SYN's payload into `seq_hi`; this accepts the
   Linux/Windows `seq=0, ack=isn+SEG.LEN` connection-refused RST, round-1
   AGY Q6 / round-2 AGY F6) **or** `seg.seq ==` the seeded own-side
   `seq_hi` (self-abort). Install seeds are trusted, so an OPENING entry
   always has at least its creating direction's trusted baseline; a
   materialized OPENING import with no local observation falls to rule 3
   (its natural timeout is the 20 s opening window — the lingering cost
   of a refused legit close is negligible).
3. **No trusted baseline in any form → REFUSE-DEMOTE (v4, the round-2
   convergence flip).** The closing packet is forwarded unchanged; no
   mark, no constructor seed of `closing`/`reset`, no `last_seen_ns`
   refresh, no wheel push; the entry ages on its ordinary timeout. The
   trace that forced this (round-2 Codex 1 / AGY 1 / SMR 1, all three
   independent): post-failover, a blind RST as the first locally-observed
   packet of a synced flow → materialize (site 2c) + promote
   (`promote.rs:86-90`: ForwardCandidate = local RG ownership) →
   `update_session` retags the entry `SharedPromote` — which is NOT
   `is_peer_synced` (`entry.rs:245-250`) — so the 2 s reap emits a Close
   delta (`expire.rs:342-345`); the promote's Open delta
   (`mod.rs:1480-1530`) means the Close draws a fresh stamped delete
   generation that applies unconditionally (`sync_conn_write.go:53-82`,
   `sync_conn_gen.go:493-506`; the gen-zero fallback at :176-186 is
   equally unconditional) — deleting the shared copy and the peer's
   standby copy cluster-wide. Under refuse-demote the chain dies at step
   one: nothing is marked, nothing reaps early, nothing emits.
4. All comparisons RFC 1982 wrapping; the membership test is
   `seq.wrapping_sub(lo) <= hi.wrapping_sub(lo)` — no plain `hi - lo`
   (debug-build panic on wrap, round-1 Codex B3). A
   `const _: () = assert!(BACK_SLACK + 2 * u16::MAX as usize + 1 < (1 << 31))`
   pins each leg under the serial midpoint (typed next to the constants;
   it bounds each interval, not the union probability — §2 states the
   union).

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
   and do not refresh `last_seen_ns` yet for a closing segment.** The
   in-borrow SYN-ACK promote (`promote_from_reverse`) is skipped for
   closing-flagged packets (§5.2 rule 5).
2. Post-borrow (same phase that already calls
   `propagate_tcp_state_to_companion` — the only code between borrow end
   and here is that propagation + `push_to_wheel`, `lookup.rs:198-218`,
   same thread, no observer of the interim state): probe the forward
   entry, read the pre-packet anchor AND the forward entry's
   `established`, run §5.4.
   - **Accept:** re-probe the matched entry, set `closing`/`reset`
     (`reset |=` BEFORE timeout selection, preserving #3046 ordering;
     OR-assignment preserves #3489 stickiness), refresh `last_seen_ns`,
     recompute `expires_after_ns`, then propagate to the companion
     exactly as today (the propagation path is unchanged — it fires only
     on accepted marks, inheriting validation).
   - **Refuse:** no marks, no refresh, no wheel push; bump the counter.
     `expires_after_ns`/`last_seen_ns` stay at their prior values — the
     entry ages on its pre-attack trajectory.

`update_session` (site 2) applies the same conjunction: the promote path
threads the packet's `TcpSegView`; validation reads the forward entry's
anchor (the entry being promoted IS the forward entry in the promotable
case — `is_translated_forward_session_key` family — so no extra probe);
wire-driven `update_session` callers (no packet) skip validation.

### 5.6 Constructor gating (sites 2b + 2c)

**Reverse-NAT synth (site 2b, round-1 Codex B2):**
`install_reverse_session_from_forward_match` (`shared_ops.rs:857-865`)
holds the `forward_match` in hand. When the current packet is
closing-flagged, validate it (§5.4) against the FORWARD entry's anchor
first (the cross-direction legs cover a reverse-direction close —
`ack_hi(fwd)` pins the reverse stream's position). A LOCAL forward entry
carries its anchor; a SHARED `ForwardSessionMatch` carries only
key/decision/metadata (`entry.rs:209`, `shared_ops.rs:638-665`) → no
baseline → refuse (round-2 Codex 8):

- **Accept** → install with `closing`/`reset` seeded as today (a legit
  one-way server RST keeps this path's teardown semantics — stated
  honestly per round-2 Codex 8: the accepted RST marks only the reverse
  entry; #4380 companion retention (`expire.rs:318`, `companion_keeps_alive`)
  defers the reverse's 2 s reap while the forward companion is live
  (≤ the 20 s opening window for a half-open forward); the NEXT accepted
  hit propagates the mark to both halves. The test plan (§9) asserts
  THESE semantics, not an idealized 2 s whole-flow reap).
- **Refuse** → **skip the install entirely** (round-2 AGY F3), on owner
  AND non-owner alike (with the flip, the non-owner shared-replica case
  no longer mints a born-dying `ReverseFlow` either — "mints nothing"
  holds absolutely, and no shared reverse publish survives to need
  cleanup). The packet is still forwarded (the synthesized decision is
  returned regardless, the #1861 §5.4 pattern; `created=false,
  install_failed=true` suppresses create telemetry and cache insertion,
  `poll_descriptor/mod.rs:509-547, :3900`). The next legitimate reply
  re-synthesizes the companion and revalidates against the same forward
  anchor; the forward companion is never marked from an unvalidated seed.
  A legit close we misjudged (stale anchor) costs only a re-synth on the
  next reply packet.

**Reactive materialize (site 2c, round-2 Codex 1 / SMR 2):**
`materialize_shared_session_hit` threads the current packet's `tcp_flags`
into `upsert_synced_with_origin`, which seeds `closing`/`reset` at
`install.rs:399-400`. An imported replica carries no anchor → every
closing-flagged materialize is no-baseline → **refuse**: install the copy
ALIVE (`closing=false, reset=false`) regardless of the packet's flags.
Unlike site 2b the install cannot be skipped — the packet needs its
decision and the entry must own the flow — so the seed is suppressed
instead. (If the §10 wire-anchor follow-up lands, a wire-carried anchor
makes this site validatable; until then every materialize-seed close is
refused by construction.)

The fabric-return seed (site 6) is already close-free (#4453); primary
miss installs (site 3) are #4400-guarded; tunnel UpsertLocal (site 5) is
trusted-local; wire re-import (site 4) carries no packet; the forward-wire
immutable match (site 8) never marks.

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
  only when `protocol == TCP` and `!is_closing(flags)` — rule 1.)
- `lookup_with_origin` — the seg view is computed by the `session_glue`
  caller and threaded via a new small struct on the resolve path
  (`resolve_flow_session_decision` already receives `tcp_flags`; it gains
  the pre-computed view); `icmp_embed` callers pass `None` and flags 0 —
  validation never fires and no anchor updates, byte-identical.
- `SessionInstall` (`session/ctx.rs:31-48` — today carries flags only)
  gains `seg: Option<TcpSegView>` so install-time seeding (§5.2(c)) and
  the materialize gate (site 2c) have the seq/ack/seg_len inputs
  (round-2 Codex 10: v3 claimed no install-side plumbing change; that was
  not implementable).
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
  carries an anchor; every update goes through `account_packet` /
  `lookup_with_origin` (+install seed); every validation reads the same
  store. No second store, no merge.
- **Trust invariant (v4):** a close validates only against a TRUSTED
  anchor side; trust is born at install seeds or conferred by
  cross-bounding against an already-trusted opposite side; untrusted
  sides never confer trust. No-baseline ⇒ refuse-demote, everywhere
  (hit path, promote, materialize, synth, missing-forward).
- **Pre-packet validation:** a closing segment never updates the anchor
  (rule 1), never promotes (rule 5), and on refuse mutates nothing at all.
- **Plausibility-gated slides:** the anchor cannot jump more than
  `FWD_SLACK` per accepted sample; seq slides require `seg_len > 0`;
  ack slides require `has_ack`; a `const _` assert pins each leg's
  interval under 2^31.
- **Stickiness contracts:** `closing` (#3489), `reset` (#3046),
  `established` (#3152) remain monotone within an entry's life; the gate
  only withholds a mark, never clears one. The #3046 timeout-selection
  ordering (`reset` set before `expires_after_ns` is chosen) is preserved
  on the accepted-mark path.
- **HA replica no-Close invariant (LOAD-BEARING, round-1 Codex B8):**
  `expire.rs:342-345` emits Close deltas only for non-peer-synced,
  non-reverse, non-transient-seed origins; `SharedMaterialize`/`SyncImport`/
  `WorkerLocalImport` are all peer-synced (`entry.rs:245-250`), and
  promotion requires a `ForwardCandidate` disposition on the promoting node
  (`promote.rs:86-90`) — i.e. local RG ownership
  (`enforce_session_ha_resolution` → HAInactive on the non-owner). The Go
  side has NO origin/generation protection that would save the owner
  (stamped deletes apply, `sync_conn_gen.go:493-506`; gen-zero fallback
  deletes apply unconditionally, :176-186), so this Rust gate plus the
  refuse-demote flip are the barriers between a non-owner/unvalidated
  reap and the owner's authoritative entry. **`SharedPromote` is
  deliberately NOT peer-synced** (the promoted node IS the owner; its
  validated closes MUST propagate) — which is exactly why refuse-demote
  on no-baseline is load-bearing: without it, a blind first-packet close
  on a freshly promoted entry emits a cluster-wide Close (the §5.4
  rule-3 trace). The plan adds exact regression tests
  (`SharedMaterialize + reset + FabricRedirect + stale-ceiling reap` →
  no delta, no owner/shared deletion; blind first-packet close on a
  promotable import → no mark, install-alive, no delta) and names the
  invariant in the module docs.
- **Hot-path discipline:** zero new allocations; zero new atomics; the
  per-TCP-data-packet cost inside `account_packet`'s existing probe is one
  8-byte read + ≤2 gated stores; closing segments add one table probe on a
  path that already takes the full slow path. `SessionEntry` grows ~26 B
  (§2 cost stated; slab is uniform — UDP/ICMP entries carry it unused).
- **Borrow shape:** close-path validation and marking happen post-borrow in
  the existing propagation phase; no new cross-`&mut` aliasing; the
  non-close path's borrow structure is byte-identical.
- **GRE/frame identity:** all frame reads use the ACTIVE `packet_frame`;
  seg_len from IP-declared lengths with frame clamping.
- **Fragments:** non-first fragments stay flowless (#2344); the helper
  returns None for them defensively.
- **Coverage residuals (documented, round-2 Codex 4/5):**
  - **forward-wire immutable matches** (NAT64 fwd, hairpin, non-bijective
    NAT): demote-free by construction — the match returns a copy; nothing
    marks, today or after. Anchors for these flows advance from the
    reverse (mutable alias) direction only.
  - **PASS_TO_KERNEL** (`bpf_map/mod.rs:3-12`: peer-synced forward
    LocalDelivery, no tunnel): packets bypass AF_XDP entirely; the
    Rust-side imported entry carries no anchor. While bypassing, those
    packets cannot demote Rust state (no userspace path runs); after a
    REDIRECT/publish transition the entry is no-baseline → refuse-demote
    until local observation builds trust.
  - **fabric-return reverse seeds** bypass both anchor sites; a later
    close demotes only the local reverse seed, `is_reverse` suppresses
    the Close delta — no owner kill.
  - **tunnel UpsertLocal** entries anchor only from inbound traffic;
    outbound-only flows refuse inbound closes until observed (local blast
    radius only).
  - **Exotic extension chains:** the shim walks ≤6 known ext-header types
    (`userspace-xdp/lib.rs:1257-1289`); TCP behind Mobility/HIP/Shim6/
    experimental types or >6-deep chains never advances the TCP anchor
    (and never joins the TCP session). A later plain-header close sees a
    stale-or-absent anchor: refuse (entry lingers, delivery unaffected).
  - **Both-direction path-switch stall** (§5.2): permanent per-flow
    soft-refuse after an unobserved both-direction stretch; bounded
    aggregate table pressure; no hatch.
  - **Re-import anchor wipe:** `upsert_synced_with_origin` `remove_entry`s
    any prior entry, so an HA re-sync/bulk re-import discards locally-built
    anchor trust — the flow returns to the imported-entry residual (closes
    refuse until churn). Same bounded class as the failover residual; the
    §10 wire-anchor follow-up covers it.
- **LocalDelivery replies** leave via kernel TX and never traverse AF_XDP;
  the anchor for a firewall-originated flow's outbound direction is pinned
  by the inbound ACK stream (cross-direction leg) — the attack-relevant
  inbound direction is fully tracked.

---

## 8. Risk assessment

| Class | Verdict | Notes |
|---|---|---|
| Behavioral regression | MED | Gate only withholds demotion, never blocks delivery; refuse on missing/untrusted baseline. Residuals (stated in §2/§5.2/§7): soft-refused legit close after unobserved stretches or both-direction path switches → entry idles ≤ established timeout; imported entries never validate closes until churn (bounded lingering; §10 wire-anchor restores); tuple stays busy meanwhile — pre-existing semantics for silently-dead flows. Restart-RST covered by the union rule. OPENING covered by SEG.LEN-aware ack check against the FORWARD entry's state. |
| Lifetime / borrow-checker | LOW | Anchor is `Copy` POD on an existing entry; marking restructured into the existing post-borrow propagation phase; no new cross-boundary borrows. |
| Performance regression | LOW-MED | ~26 B/entry slab growth (~3 MiB/worker at cap); one 8-byte read + ≤2 gated stores per TCP data packet inside an existing probe (closing segments skip updates entirely); one extra probe per closing segment. Must be measured at minimum-frame rates (§9) — the 23 Gbit/s MTU-sized iperf run alone is insufficient (≈37 Mpps at 25 Gbit/s small-frame is the real gate; `iperf3 -l 64` is a proxy, not a demonstrated line-rate generator — gate on pps, not bandwidth). |
| Architectural mismatch | LOW | No new subsystem; anchors at the existing #2501/#3706 chokepoints; #4400-style always-on gate. No pipeline restructure. |
| HA / rolling upgrade | LOW | No wire change; mixed-version peers each gate only their own marks; pre-upgrade entries converge to trusted seeds on first observed traffic and refuse closes until then (behavior strictly more conservative than master); the replica no-Close invariant + the SharedPromote refuse trace are regression-tested. |
| Merge collision | LOW | No `FlowCacheEntry` change (v1's #6457 tension gone). `account_packet` signature change is local to two call sites; `SessionInstall`/`SessionUpdate` gains are crate-internal. |

---

## 9. Test plan

Unit (cargo):

- Validator truth table: ESTABLISHED fresh trusted anchor (accept
  in-window RST/FIN; refuse low/high out-of-window; refuse far-future),
  the union leg (restart-RST `SEQ=SEG.ACK` accepted via trusted
  `ack_hi(O)` when `seq_hi(D)` refuses), serial-wrap edges (anchor near
  2^32−1, `wrapping_sub` membership, no panic), OPENING (`ack ==
  isn+SEG.LEN` accept incl. TFO, wrong-ack refuse, untrusted-baseline
  refuse), asymmetric (only one direction observed/trusted), missing/
  untrusted baseline → refuse (NEVER fail-open).
- **Trust acquisition (v4):** `!valid` seed cross-bounded by a trusted
  opposite anchor → adopted+trusted inside window, rejected outside;
  seed with no trusted opposite → valid-but-untrusted, close refused;
  untrusted sides cannot confer trust (fabricated self-consistent pair
  stays untrusted, close refused); install seeds born trusted.
- **ack poisoning (round-2 Codex 3):** SYN retransmit on an OPENING hit
  does NOT set ack validity (no near-zero acceptance leg); non-ACK
  segments never slide `ack_hi`; zero-length samples never slide
  `seq_hi`.
- **Poisoning (round-1 Codex B1):** ACK-only plant ahead of window does not
  move the anchor; RST at the planted seq still refused; in-window
  contiguous fake data slides the anchor at most FWD_SLACK per packet;
  closing segments never update the anchor at any site (accepted or
  refused).
- **Two-packet reverse-NAT bypass (round-1 Codex B2):** blind RST on
  reverse tuple → NO reverse entry minted (skip-install), forward
  companion NOT marked, `tcp_close_seq_rejected` bumped; in-window
  variant → seeded closing + the honest master chain (reverse marked;
  #4380 companion retention defers its reap while the forward lives;
  next accepted hit propagates to both) — NOT an idealized 2 s whole-flow
  reap (round-2 Codex 8).
- **Materialize gate (site 2c):** closing-flagged shared-hit materialize
  installs the copy ALIVE (`closing=false, reset=false`), no Close delta
  on its later ordinary reap; non-closing materialize unchanged.
- **SharedPromote refuse trace (round-2 convergence):** blind first-packet
  close on a promotable import → no mark, no promote-driven close seed,
  entry ages on ordinary timeout, reap emits NO Close delta (nothing was
  marked); validated post-trust close on a promoted entry DOES emit the
  Close (owner semantics preserved).
- **Promote staging (round-2 Codex 9):** closing-flagged SYN+ACK never
  sets `established` in-borrow, accept or refuse.
- Anchor single-store: reverse packets update only the forward entry;
  missing-forward refuse (FabricRedirect no-local-reverse shape); slow-path
  ForwardCandidate double-update is value-idempotent.
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
  Gbit/s (no regression vs pre-change), **plus a small-frame/high-pps
  run** to gate the per-packet anchor cost (measured in pps).
- Attack negative: long-lived SSH + iperf3 trust→untrust; off-path scapy
  RST/FIN with random seq (thousands, ≥ window scale) → flow survives,
  session stays established, `tcp_close_seq_rejected` advances.
- Legit positive: in-window RST (seq captured via tcpdump) → demote
  exactly as today; ordinary iperf3/SSH Ctrl-C teardown identical to
  master; connection-refused RST against a half-open → opening reap
  unchanged.
- HA: `make test-failover` (mandatory); **post-failover blind-spray
  negative (v4)**: immediately after RG switchover, spray blind closes at
  synced-but-not-yet-observed flows → entries survive (refuse-demote),
  no Close deltas, standby copies intact; the next legit traffic
  re-establishes trust and a later in-window close demotes normally.

---

## 10. Out of scope (explicitly)

- Junos general per-packet sequence check (`no-sequence-check` enforcement,
  #2008 M9 / #2078) — the wscale-aware data-plane window check on *every*
  segment. Bigger, throughput-sensitive, asymmetric-routing-hostile;
  separate issue. (Named honestly: xpf lacks this Junos-DEFAULT check;
  this plan closes only the RST/FIN demote DoS.)
- **HA-wire anchor carriage (follow-up issue to file):** an additive,
  rolling-gated wire field (`fwd/rev seq_hi/ack_hi` + valid bits, ~18 B)
  lets a post-failover node validate closes on imported entries
  immediately instead of refusing until churn — it shrinks the §2
  first-observation residual for the entire synced class. Deliberately
  NOT in this PR (§6's no-wire-change rolling-upgrade story stays clean).
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
- Forward-wire (NAT64) forward-direction accounting/refresh asymmetry
  observed during review (immutable match path never refreshes/marks —
  pre-existing, demote-free by construction); file as its own issue if
  telemetry confirms field impact.
- Any change to reap windows, wheel, deltas, RT_FLOW, or the Go control
  plane (the HA no-Close invariant is TESTED, not modified).

---

## 11. Open questions for adversarial review (round 3)

1. **Seed authentication soundness (§5.2 rule 4):** a segment
   authenticates when ANY field cross-bounds against trusted state, and
   all its samples then adopt trusted. Verify the TCP invariant both
   directions: (a) legit — the handshake chain (SYN self-authenticates;
   SYN-ACK via `ack == fwd seed`; client ACK via `ack == rev seed`) plus
   mid-flow contiguity must leave every real flow fully trusted within
   the handshake; is there ANY real segment early in a flow that fails
   to authenticate (asymmetric start, simultaneous open, TFO, pickup
   from a data segment)? (b) attacker — is the fake-authentication cost
   really identical to a direct close guess (one ~1/2^13 window hit
   either way, no amplification), and does the
   untrusted-can-never-authenticate rule have any legit casualty beyond
   the documented imported-entry lingering?
2. **Refuse-demote cost bound (§5.4 rule 3):** post-failover, every
   imported flow's closes refuse until churn. Quantify the worst realistic
   table pressure: N imported flows × peers that died during failover →
   all linger to established/application timeout instead of 2 s. Is the
   131,072-slot headroom argument sufficient, or does this need a
   probationary shorter timeout for never-trusted entries (a new timer
   class — the complexity v3 was told to avoid)?
3. **Closing-packet promote skip (§5.2 rule 5):** is there ANY
   standards-compliant flow where a SYN-ACK bearing RST or FIN is a
   required promote signal (simultaneous-open abort, TFO edge)? If yes,
   stage the promote on accept instead of skipping outright.
4. **`FWD_SLACK = max(2×wnd(O), 64 KiB)`:** with wscale untracked the
   slack self-bounds at 131,070. Show the arithmetic that this covers
   reordering + abort-time in-flight on observed paths at 10/25 Gbit/s,
   and that wscale tracking would only shrink the blind-hit probability
   from ~1/10923 toward 1/16384 — not worth the SYN-option parse state.
5. **Site (b) pre-filter observation (§5.2 boundary note):** the
   rebuttal is "master's existing trust boundary, gate strictly reduces,
   no security delta for moving." Punch a hole in it if one exists —
   concretely: name a packet class that (i) updates/marks via site (b),
   (ii) is dropped before delivery, AND (iii) creates an attack or
   regression master does not already have.
6. **Counter surface:** is a per-worker `tcp_close_seq_rejected` enough
   observability, or should refused closes also emit a rate-limited
   RT_FLOW/screen-class record so operators can see an attack in progress
   without debug builds?
