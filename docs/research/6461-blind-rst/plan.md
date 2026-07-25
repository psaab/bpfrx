# #6461 — blind off-path TCP RST/FIN demotes a live session with no sequence validation

**Status: DRAFT v7.2 — revised after round-6 reviews (Codex PLAN NO 5B/3H/1M/1L on v7; AGY single-question runs: 2 SOUND folds, 2 UNSOUND folds applied)**

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
same blocker): refuse-demote on no-baseline everywhere; the materialize
constructor gated (install-alive); seed trust model (cross-bounded seeds);
`has_ack`/`seg_len>0` slide gates; closing segments never update/promote;
dead 512 KiB cap removed; union arithmetic restated.
v4 → v5: round-3 folds — provenance matrix, commit-point observation,
OPENING exact interval, trust transaction semantics, plumbing types,
promote-write inertness, absorbing-state honesty, arithmetic residuals.
v5 → v6: round-4 folds — fabric authority removed; closing packets never
promote; trusted continuity self-slide; per-field proofs + own-ack leg;
`open_ack_lo` persisted; proof-gated establishment promote; dispatch-arm
apply; `LocalMiss` context; Phase-2 first spec.
v6 → v7: round-5 folds (Codex 1-9, AGY clean): (a) **activation-time
authority transfer** — v6's "old owner cleans up" premise was false
(owner demotion retags entries `SyncImport`, `install.rs:572` /
`shared_ops.rs:179-206`: both copies peer-synced, neither emits Close;
stale shared NAT aliases could rematerialize after allocator reuse).
The RG-activation self-heal (`expire.rs:213-237`) now also flips
imported entries to locally-authoritative origin — Close authority
comes from HA state, never from packets; (b) **immutable OPENING
proof endpoints** — the handshake proof and self-abort rule used the
LIVE-sliding `seq_hi`, cutting the OPENING proof from 1/2^32 to
~1/2^16; the immutable `[open_ack_lo, open_ack_hi]` pair is now
explicit state (+8 B → 40 B); (c) **Phase 2 gets a real pipeline** —
the Go sweep cannot observe anchor changes (`sync_conn_sweep.go:125-137`
keys on Created/counters) and the userspace sweep is 15s/60s
(`manager.go:452`), so the anchor rides a new coalesced `AnchorUpdate`
delta kind (the unused `MSG_SESSION_UPDATE` wire type) with per-entry
seqno, a quiet-flow emission filter, lossy-with-watermark dirty ring,
and in-place import; (d) **slack per stream receiver** — every
quantity's slack derives from the window advertised by the RECEIVER of
its stream (seq legs: wnd(O); ack leg/slides: wnd(D)) — v6 used wnd(O)
uniformly, wrong for the own-ack leg and ack slides; (e) **three-leg
arithmetic** — a blind RST|ACK guesses against up to three independent
windows: worst ≈ 1/7,282 (cap) / 1/10,923 (floor), stated unvarnished;
(f) **commit boundary completed** — apply only on CONFIRMED enqueue
(`push_redirect_inbox` discard now reported), plus the fallback
reinjection arms (`dispatch/mod.rs:898, :1378`); establishment promote
is computed at resolve but APPLIED in the commit arm. Round-1..5 review
docs sit alongside this file.

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
- After: a blind RST|ACK carries **two** independently chosen 32-bit
  values — `seg.seq` (tested against the union of the two seq legs) and
  `seg.ack` (tested against the own-ack leg, §5.4) — each leg
  `BACK_SLACK + slack + 1` wide (slack self-bounding at 131,070 since raw
  `wnd` is u16, and `wnd` accepted only from authenticated segments).
  Worst case (all legs disjoint): floor `2×131,073 + 131,073 = 393,219`
  ≈ **1/10,923 per packet**; cap `2×196,607 + 262,141 = 655,355` ≈
  **1/6,554** (round-6 Codex 9 — leg 3 is symmetric ±slack at the cap).
  With the two seq windows fully overlapped the floor is `2W ≈ 1/16,384`;
  the typical case lies between. At 1,000 minimum-size closes/s
  (~1 Mbit/s) the expected spray-to-kill is **~11 s (floor) to ~6.5 s
  (cap)** of sustained spraying per kill. The honest framing (round-6
  Codex 9): against an RFC 5961 endpoint's exact `RCV.NXT` coordinate the
  firewall remains the weaker validator — the improvement is from
  **1 packet anytime** to **~6.5–16 s of sustained spray per kill plus
  the endpoint's own handling**, not parity with the endpoint. A
  precursor seed attempt can place independent guesses in BOTH the seq
  and ack fields of one packet — its chances are additive even where the
  close's intervals overlap, so "seed cost == direct close cost" is
  optimistic by up to ~2× (stated, not hidden).
- **Observation boundary (v5 — commit-point):** the anchor learns ONLY
  from packets the firewall committed to forward or deliver (per-disposition
  commit hooks, §5.2 — post input-filter, host-admission, TTL, and
  output-filter/CoS drop evaluation). v3–v4's resolve-time updates let
  TTL=1 or filter-dropped bounded packets walk a trusted anchor and convert
  the endpoint's next legit close into a refusal (griefing regression);
  that class is closed. The DEMOTE decision still happens at lookup
  (pre-filter), exactly as master's marking always has — an in-window
  close with TTL expiring at the firewall demotes without delivery on
  master too; no regression there. RFC 5961 endpoint handling is not part
  of the cost model: sprayed closes may never reach an endpoint.
- Anchor-walking (feeding contiguous fake in-window data to slide the
  anchor, then RST) requires landing a first in-window sample (the same
  ~1/2^13–1/2^14 guess) and buys the attacker nothing beyond it: the
  acceptance window follows the anchor, so a single kill needs a single
  in-window guess regardless. `seg_len > 0` is required for `seq_hi`
  slides (v4), so zero-length probes cannot walk the anchor at one packet
  per slack.
- **Imported-entry absorbing state (v5, stated without varnish):** an
  HA-imported (`SyncImport`/`SharedMaterialize`/`WorkerLocalImport`) or
  pre-upgrade entry has no trusted bootstrap, and per the transaction
  semantics NO observed packet can create the first trusted bit — the
  state is absorbing until the entry churns. Every such flow's closes
  (legit included) refuse demotion for the entry's remaining life:
  entries linger to their inactivity timeout (300 s default; per-app
  values up to 86,400 s) instead of the 2 s/30 s fast reap. Delivery is
  never blocked; endpoints tear down normally. Slot pressure: bounded by
  the synced-flow count at the event; note honestly that synced upserts
  bypass the local admission cap (`install.rs:295-323`) so 131,072 is an
  admission ceiling, not headroom — a high-churn failover can hold
  thousands of lingering entries for minutes while new local installs
  contend. This residual is exactly what the **REQUIRED Phase-2 HA-wire
  anchor (§10.5)** closes; it is not optional for the synced class. The
  post-failover `SharedPromote` cluster-kill trace is dead regardless
  (nothing marks without trust).
- What this costs a legitimate teardown when the gate misjudges: the
  packet is always delivered (endpoints tear down normally), the entry
  idles out on its ordinary timeout instead of the 2 s/30 s fast reap —
  a table-pressure cost, never a broken connection. Aggregate version
  (round-2 Codex): a both-direction path-switch can stall an anchor
  permanently (§5.2); many flows stalling after one path event linger to
  their established timeouts — bounded, self-healing as flows churn.
- Cost: 40 B of new state on `SessionEntry` (uniform slab — includes
  UDP/ICMP entries that never use it; ≈ 5 MiB per worker at the 131,072
  cap, ≈ 30 MiB at 6 workers), one TCP-header view compute (seq/ack/wnd/
  flags/seg_len) plus ≤2 plausibility-gated `u32` stores per committed
  TCP data packet, and a second table probe only on closing-flag segments
  (which already take the full slow path).

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
| 6 | fabric-return reverse seed (`cluster_peer_return_fast_path` install) | fabric-ingress packet flags | bare closes already excluded (#4453); the seed bypasses the commit hooks (round-2 Codex 5) so the reverse seed carries no anchor — a later close on it is REFUSED (missing-forward/no-baseline, §5.1) and the seed ages on its ordinary timeout; `is_reverse` suppresses any Close delta; no owner kill; documented |
| 7 | CLI/control deletes, GC/reaper, screens/SYN-cookie | — | consumers / unaffected |
| 8 | **forward-wire immutable match** — `find_forward_wire_match_with_origin` (`lookup.rs:258-293` via `shared_ops.rs:614-628`): NAT64 forward direction, hairpin, non-bijective NAT | wire packet on the forward-wire tuple | The match itself never marks (cloned decision/metadata — no `&mut`, today and after). **But it is not demote-free (round-3 Codex 7a):** a promotable-origin forward-wire hit reaches `maybe_promote_synced_session` → `update_session`, which marks closing/reset from the packet's flags on master — that path is gated by §5.5's transactional promote rule like every other promote (no anchor on an import → refuse, inert). The anchor for these flows advances from the reverse (mutable alias) direction only; pre-existing forward-direction accounting/refresh asymmetry (NAT64) is out of scope — filed as a follow-up candidate |

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

`SessionEntry` gains (40 B; plain POD, worker-owned, no serde, no HA
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
    valid: u8,        // bit0 fwd seq, bit1 fwd ack, bit2 rev seq, bit3 rev ack;
                      // bit4 fwd OPENING interval, bit5 rev OPENING interval
                      // (round-6 Codex 8: rule 2 requires open_valid(dir) — a
                      // default [0,0] interval must never validate a seq=0 RST)
    trusted: u8,      // same bit layout as valid: this side may validate a close
    _pad: [u8; 2],
    fwd_open_ack_lo: u32,  // OPENING interval lower bound (isn+1), forward — IMMUTABLE
    rev_open_ack_lo: u32,  // same, reverse (simultaneous open)
    fwd_open_ack_hi: u32,  // OPENING interval upper bound (isn+SEG.LEN) — IMMUTABLE
    rev_open_ack_hi: u32,  // (round-5 Codex 2: the proof endpoints must NOT be
                           // the live-sliding seq_hi — see §5.4 rule 2)
}
```
(40 B total — round-4 Codex 4a + round-5 Codex 2/9: both OPENING interval
endpoints are explicit immutable state; a compile-time layout assertion
pins the 40-byte size; `seq+SEG.LEN` arithmetic is `wrapping_add`
everywhere.)

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

### 5.2 Anchor updates: commit-point observation, trust, and gating

**Where updates run (v6 — round-3 Codex 6 + round-4 Codex 5):** the anchor
learns ONLY from packets the firewall **successfully committed to the
wire or the local stack** — applied in the successful dispatch arms,
never inside the session lookup or the request-build stage:

- **Commit point = FINAL ADMISSION (v7.2, round-6 Codex 5):** neither
  the request build nor the queue append is the commit — cache "rewrite
  success" only appends a `PreparedTxRequest` (`flow_cache_hit.rs:444`),
  slow-path enqueue appends to software queues (`cos.rs:100`), and CoS
  admission can still drop on flow-share/buffer pressure while
  returning `Ok(())` (`cos_classify.rs:1449, :1527`; bounded pending
  queues evict at `drain/mod.rs:33`). The anchor applies only on
  final-admission SUCCESS — the CoS/admission layer must REPORT its
  drop (another signature fix) — on all three arms: transit slow path
  (dispatch final admission, after binding/MTU/translation/CoS),
  cache path (prepared-TX final admission), LocalDelivery + the
  ForwardCandidate dispatch-failure fallback reinjection
  (`poll_descriptor/mod.rs:5117-5139`, `dispatch/mod.rs:898, :1378` →
  `slow_path.rs:186-357`).
- **Pending-neighbor carriage (v7.2, round-6 Codex 5b):**
  `PendingNeighPacket` (`types/mod.rs:77`) currently carries no
  segment/proof token and `retry_pending_neigh`
  (`neighbor_dispatch.rs:156, :344`) has no `SessionTable` — a buffered
  SYN-ACK would deliver without its establishment promote (a live flow
  could reap on the 20 s opening trajectory), and buffered non-close
  samples would update nothing. The packet gains a mutation token (seg
  view + the pre-computed proof outcome, bound to the session
  incarnation id); the retry path applies anchor updates and the staged
  promote only on successful final enqueue; a pending-queue eviction/
  timeout discards them. Demote marking for an ACCEPTED close stays at
  resolve time (master parity — a close buffered for ARP already
  demotes on master; only anchor updates and the establishment promote
  are delivery-gated).
- **Residual (documented):** TX-completion failure (driver/UMEM ring
  after final admission) is the irreducible unobserved tail — not
  per-packet steerable in any sequence-targeted way. #2501 counter
  placement is UNCHANGED (`account_packet` keeps counting attempted
  forwards at `flow_cache_hit.rs:312` / `poll_descriptor/mod.rs:3497` —
  RT_FLOW volume semantics untouched); the anchor rides its own apply
  hook fed by the same seg view.
- **`lookup_with_origin` does NO anchor updates (v5+):** the lookup path
  validates and marks only. Closing segments never update (rule 1);
  committed non-close packets update at the dispatch arms above.
- **Install-time seeds** are applied at the constructors (rule 4's
  provenance matrix).

Reverse-direction samples fold onto the canonical forward entry exactly as
`account_packet` folds counters today (`mod.rs:1177-1211`); commit-hook
updates on a reverse-direction packet use the same reverse→forward key
hop. One store, one gating rule, per-disposition commit hooks.

**The gating rules (round-1 Codex B1 + round-2/3 Codex — the trust anchor
must be neither attacker-jumpable nor attacker-seedable nor
attacker-poisonable):**

1. **Closing segments never update the anchor.** A FIN/RST's own sample
   is not applied anywhere, before or after validation (validation reads
   the pre-packet anchor; on accept the entry is dying and the anchor is
   moot).
2. **seq slides:** an ordinary (non-close) sample `s = seq + seg_len` with
   **`seg_len > 0`** slides `seq_hi` forward only within the current
   window: accepted iff `!valid` (seed — rule 4) or
   `s.wrapping_sub(seq_hi) <= FWD_SLACK` (serially: at most `FWD_SLACK`
   ahead). "Behind is a no-op" is a **serial max**, not `u32::max`
   (round-3 Codex 8): advance iff `s.wrapping_sub(cur)` is in
   `(0, FWD_SLACK]`; tracker wrap tested separately from validator wrap.
   Zero-length samples never slide `seq_hi` (one packet per slack of
   anchor-walking is not available).
3. **ack slides:** `ack_hi` updates ONLY from ACK-bearing segments
   (`has_ack`), with the per-stream slack (§5.4 intro): `ack_hi(D)`
   carries stream-O quantities, so its slide gate uses
   `FWD_SLACK(O) = max(2×wnd(D), 64 KiB)` (v7, round-5 Codex 4). Without
   the `has_ack` gate, a SYN retransmit's zero ACK field seeds
   `ack_hi ≈ 0` on an OPENING hit, and the real ACK stream
   (≫ slack away) can never repair it — a permanent acceptance window
   near sequence zero that a naive `seq=1` blind RST validates
   (round-2 Codex 3).
4. **Trust acquisition (v6, provenance matrix + per-field proofs +
   strong-proof exception):** every anchor side carries
   `(value, valid, trusted)`.
   - **Self-authenticating constructors (only these, with context):** the
     *primary miss install* of a genuinely new flow — origins
     `ForwardFlow`/`MissingNeighborSeed` and the LocalDelivery new-flow
     install — **only when the install displaces nothing synced**: the
     `LocalMiss` installer can `remove_entry` an existing peer-synced
     LocalDelivery entry and reinstall the same key
     (`local_delivery.rs:75-113`, `take_synced_local` at
     `lookup.rs:407-418`), so provenance is `(origin, context)` —
     `FreshPrimary` self-authenticates; `ReplacedSyncedLocal` adopts
     untrusted only (round-3 Codex 8, with a mandatory replacement test).
     An attacker's spoofed SYN anchors only its own invented flow. SYN
     seeds `seq_hi = isn + SEG.LEN` (TFO included), a mid-stream pickup
     seeds from its first segment — both born `trusted`, **seq side
     only** (a SYN's ACK field is meaningless; ack trust comes from the
     first authenticated ACK-bearing segment).
   - **Never self-authenticating:** `SyncImport`, `SharedMaterialize`,
     `WorkerLocalImport`, reverse-companion synthesis, fabric-return
     seeds, tunnel `UpsertLocal` refreshes, `ReplacedSyncedLocal`
     installs, and any re-import/upsert (which `remove_entry`s the prior
     record — an anchor wipe, §7). Their packets' samples adopt
     `valid`+**untrusted** only.
   - **Per-field proofs for untrusted→trusted conversion:** a sample for
     an untrusted side is adopted `trusted` only when that SAME field
     proves against trusted state — a seq sample for direction D proves
     inside `window(ack_hi(O))`; an ack sample for D proves inside
     `window(seq_hi(O))` — using the PRE-PACKET anchor including the
     pre-packet `wnd` (a segment never widens the window used to prove
     itself, round-4 Codex 9c). **There is no segment-wide weak adoption
     (v6, round-4 Codex 6):** a weak proof covers only its own field.
     The asymmetric-bootstrap deadlock this creates
     (`seq_hi(rev)` needs `ack_hi(fwd)` needs `seq_hi(rev)`) is closed
     NOT by blessing unrelated fields but by the own-ack close leg
     (§5.4 rule 1 leg 3): an ACK-bearing close carries its own proof in
     its ACK field and never needs the deadlocked sides.
   - **Strong OPENING handshake proof (segment-wide, exact):** against an
     install point seed, the proving ack must lie in the exact interval
     `[isn+1, isn+SEG.LEN]` — RFC 9293 SYN-SENT's
     `ISS < SEG.ACK <= SND.NXT`, covering RFC 7413 §4.2.2 TFO
     partial-ack (a server rejecting SYN data acks only the SYN). For a
     bare SYN the interval collapses to one value (a spoofed SYN-ACK
     needs the client ISN, 1/2^32; with a TFO payload up to the 4,096-byte
     frame ceiling, ≥ ~1/2^20 — round-4 Codex 4c). A SYN-ACK proving this
     way authenticates the WHOLE segment (the exact ISN knowledge is
     cryptographic-strength evidence the sender is the real peer) → both
     its seq and ack adopt trusted (fast server abort validates), and it
     drives the establishment promote (rule 5). **Not windowed** (a
     BACK/FWD window would drop the proof to ~1/2^13).
   - **Trusted self-slide (v6, round-4 Codex 3):** a sample for an
     already-trusted side slides on its OWN bounded continuity gate
     (`s.wrapping_sub(cur) ∈ (0, FWD_SLACK]`, serial max) — no cross-proof
     required. Without this, a one-direction-observed LocalDelivery flow
     (firewall-originated: only inbound packets seen) could never advance
     its trusted inbound anchor, and full-duplex scaled-window traffic
     (seq ahead of the opposite ack by up to the window) would stall on
     every packet — both fully-observed legit classes frozen by the
     over-strict v5 rule. The continuity gate is the same FWD_SLACK bound
     the slide always had; attack difficulty is unchanged (the first
     in-window guess is the hard part).
   - **Transaction semantics (round-3 Codex 3b/c):** on each packet,
     per side: (i) a proving sample for a `!trusted` side **replaces**
     the stored untrusted value (never max-merges with it —
     attacker-planted untrusted values are discarded, never blessed);
     (ii) a sample for a `trusted` side applies the serial-max
     continuity slide (rule 2/3); (iii) a non-proving sample adopts ONLY
     into a `!valid` slot as untrusted — it NEVER clears or alters
     existing valid/trusted state (a SYN retransmit cannot demote the
     trusted SYN seed); (iv) untrusted state never validates a close and
     never authenticates other segments (fabricated self-consistent
     pairs stay untrusted); (v) `wnd` updates only from proving/trusted
     segments (a no-knowledge precursor advertising 65,535 must not
     widen `FWD_SLACK`).
   - **No transport-based authority (v6, round-4 Codex 1):** v5's
     fabric-ingress "peer-vouched" refinement is REMOVED. An inactive
     node converts ordinary external traffic into `FabricRedirect`
     (`poll_descriptor/mod.rs:3438-3476`, `fabric.rs:331-342`), so a
     fabric-ingress stamp proves only "arrived via the fabric link" —
     never sequence placement, endpoint acceptance, or peer validation.
     A blind packet redirected by the non-owner would otherwise
     authenticate a planted anchor on the new owner's zero-trust import
     and revive the two-packet post-failover kill. Fabric-ingress
     packets authenticate exactly like any other packet: by proof
     against trusted state, or not at all.
5. **Closing packets never promote — at all (v6, round-4 Codex 2).**
   `promote_from_reverse` (`lookup.rs:146-149`) sets `established`
   in-borrow on any reverse SYN-ACK; `maybe_promote_synced_session`
   (`promote.rs:86-107`) flips a synced entry's origin to `SharedPromote`
   on any packet with a ForwardCandidate disposition. BOTH are skipped
   for `is_closing(flags)` packets:
   - The in-borrow established-promote is skipped (SYN-ACK+RST is an
     abort, not an establishment signal; round-3 Codex 10).
   - The ownership promote is skipped: a blind first close post-failover
     must not flip `SyncImport`→`SharedPromote` — the flip both arms
     Close authority (a forward `SharedPromote` emits a Close delta at
     ANY expiry, marked or not, `expire.rs:342-377`) and suppresses the
     import's RG-activation self-heal (`expire.rs:213-237`), letting a
     refused close convert a silent standby reap into an authoritative,
     possibly accelerated, Close. **Close authority = live RG ownership
     + a single-producer race (v7.2, round-6 Codex 1/2):** the
     `expire.rs:342-345` delta gate becomes `!is_reverse &&
     !is_transient_seed && (origin is locally-born
     (ForwardFlow/SharedPromote/LocalMiss family) || owner_rg_id is
     currently active on this node)`, AND an imported entry additionally
     emits only after **winning the node-local shared-map delete race**
     (the reaping worker removes the shared alias first; the Close fires
     only if the alias was present). Authority therefore follows CURRENT
     HA state with NO stored-provenance transition (no origin flip —
     round-6 Codex 1's per-worker fanout flip transaction and its
     `fabric_ingress` early-Age bypass are both moot), and the shared
     map itself serializes producers: imports fanned to every worker
     (`session_import.rs:215`) reap on all of them, but exactly one
     worker wins the alias — no duplicate Closes, no RT_FLOW dupes, and
     the stale-alias stranding (round-5 Codex 1: demotion retags make
     BOTH copies peer-synced; shared deletion is Close-driven at
     `session_delta.rs:406-452`; a stale shared NAT alias could
     rematerialize after allocator reuse) dies because the winning
     reaper deletes the alias as the price of authority. On the standby
     nothing attempts (RG not active); demotion silences instantly;
     VRRP-overlap double-wins across nodes are idempotent gen-rule
     deletes (milliseconds). The winning Close carries the import's
     stored generation, so a newer same-key incarnation (re-seeded on
     the peer) wins the gen compare (round-6 Codex 2's gen-zero concern
     does not apply — no Open-on-promote is required for authority).
     The blind close remains inert (no mark, no refresh, no accelerated
     reap). The close packet itself forwards on the current decision;
     packet-driven promotion still exists for entries imported after
     activation and still skips closing packets.
   - The establishment promote additionally requires the strong OPENING
     proof (rule 4): a reverse SYN-ACK promotes OPENING→ESTABLISHED only
     when its ack lies in the IMMUTABLE `[open_ack_lo, open_ack_hi]`
     interval. The proof is computed at resolve on the pre-packet anchor,
     but the promote is **APPLIED in the packet's commit arm** (round-5
     Codex 7: a proved SYN-ACK that is then input-filtered, TTL-expired,
     or dispatch-dropped must not promote or refresh — mutations follow
     acceptance only). An unproven or undelivered SYN-ACK can no longer
     pin a half-open entry into the 300 s established window — strictly
     stronger than master, where the promote is unauthenticated and
     pre-commit.

**Stall analysis (round-2 AGY B2 + Codex 7, made precise):** **Stall analysis (round-2 AGY B2 + Codex 7, made precise):** on a
per-packet-tracked path every committed packet is a sample, so `seq_hi`
advances essentially contiguously — the gap between the anchor and the
next new-sequence sample is bounded by the *reordering extent* of the
path (in practice ≪ 64 KiB), NOT by in-flight size. The anchor can fall
>`FWD_SLACK` behind when (a) observation is interrupted (an untracked
stretch — the documented residuals in §7), (b) reordering extent exceeds
`FWD_SLACK`, (c) **a both-direction path switch** (round-2 Codex 7): a
route/asymmetry flap lets seq AND cumulative-ack progress advance off-box
together, then rejoin >slack ahead — the endpoints accepted the stretch,
nothing retransmits near the stale anchor, and both legs stay rejected
permanently, or (d) **an ack repair jump beyond slack** (round-6 Codex 7):
with window scaling the effective receive window can be megabytes while
raw `wnd` stays small; a lost segment holds the cumulative ack while
later data buffers, and the hole-fill produces a single legal ack jump
far beyond the ≤131,070 raw-wnd gate — `ack_hi` stalls permanently.
Consequence is deliberately NARROW: only leg 2 (the restart-RST leg)
consults `ack_hi(O)`; normal closes still validate via leg 1 (`seq_hi`)
and leg 3 (the close's own ack against `seq_hi(O)` — seq tracking is
unaffected by loss, since the firewall forwards the data). A restart-RST
on such a stalled flow soft-refuses and the entry idles out on its
ordinary timeout — the peer is already dead, so the residual is table
pressure only. **wscale tracking is rejected again**: a gate wide enough
to swallow multi-MB repair jumps (≥1 MiB) widens the blind acceptance
interval by ~3×, and a "K dup-acks then accept the jump" repair hatch is
stageable for free (dup acks don't advance, so they cost the attacker
nothing — the r2 rejection applies). The scaled-window test asserts the
documented behavior: stall confined to leg 2. The consequence per flow is soft-refused legit closes +
ordinary-timeout aging (delivery unaffected, endpoints tear down
normally); the aggregate version is many flows lingering to their
established timeouts after one path event — bounded, self-healing as
flows churn. **No re-anchor escape hatch**: an "N contiguous rejected
samples → re-anchor" rule is stageable at ~N+1 packets of contiguous fake
data, reopening the round-1 B1 weakness; round-2 Codex 7 independently
reached the same refusal (round-3 Codex 10 confirms). Recovery belongs to
trusted state (the §10 HA-wire follow-up), not to observation-counting
heuristics.

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

For a closing segment in direction D (opposite O): `BACK_SLACK = 64 KiB`,
and **slack is per stream receiver (v7, round-5 Codex 4):** any quantity
in stream S is bounded by the window advertised by the RECEIVER of S —
`FWD_SLACK(S) = max(2 × wnd(receiver(S)), 64 KiB)`. Concretely: a
`seg.seq` candidate in stream D uses `FWD_SLACK(D) = max(2×wnd(O), 64 KiB)`
(D's outstanding-at-abort data is bounded by O's receive window — D's
effective SEND window, round-2 AGY F4); a `seg.ack` candidate (a stream-O
quantity, as are `ack_hi(D)` slides) uses `FWD_SLACK(O) = max(2×wnd(D),
64 KiB)` (O's unacked in-flight is bounded by D's advertised receive
window). v6 used `wnd(O)` uniformly — wrong for the own-ack leg and for
ack slides under asymmetric windows (excess acceptance one way, legit
refusal the other). Raw u16 `wnd` self-bounds either slack at 131,070 —
no upper clamp (v2's 512 KiB cap was dead arithmetic); wscale tracking is
deliberately not done (the slack covers reordering + abort-time in-flight
on the *observed* path, not BDP; unobserved stretches are the stall
residual regardless of slack size). The total acceptance interval across
all three legs is honestly stated in §2 (up to 3W disjoint ≈
1/10,923 floor, 1/7,282 cap):

1. **ESTABLISHED:** accept iff ANY of three legs proves against
   PRE-PACKET trusted state (including the pre-packet `wnd`, round-4
   Codex 9c):
   - **leg 1 (own stream):** `trusted(seq_hi(D))` AND
     `seg.seq ∈ [seq_hi(D) − BACK_SLACK, seq_hi(D) + FWD_SLACK]`;
   - **leg 2 (opposite ack stream):** `trusted(ack_hi(O))` AND
     `seg.seq ∈ [ack_hi(O) − BACK_SLACK, ack_hi(O) + FWD_SLACK]` — the
     RFC 9293 §3.5.2 closed-TCB reset (`SEQ=SEG.ACK` — peer restart /
     state loss), subsuming the asymmetric case;
   - **leg 3 (own-ack proof, v6 round-4 Codex 6):** `has_ack(seg)` AND
     `trusted(seq_hi(O))` AND
     `seg.ack ∈ [seq_hi(O) − max(2×wnd(D), 64 KiB), seq_hi(O) + FWD_SLACK(O)]`
     — the close carries its OWN cross-proof in its ACK field (the ack
     is a stream-O quantity: its lag behind `seq_hi(O)` is O's unacked
     in-flight, bounded by D's advertised window — the v7 per-stream
     slack above). Legit forms covered: FIN+ACK cumulative teardown,
     `SO_LINGER(0)` abort RST+ACK, and the RFC 9293 §3.5.2 reset forms
     (reset #2 carries `ACK=SEG.SEQ+SEG.LEN` of the incoming segment;
     reset #1/#3 derive `SEQ=SEG.ACK`). A bare no-ACK RST in a state
     where legs 1-2 have no trusted side soft-refuses (bounded
     residual: delivery unaffected, entry idles out).
   A blind close must hit one of these windows (~1/2^13–1/2^14 per
   guess, §2).
2. **OPENING** (`!established` on the FORWARD entry): both legs consult
   ONLY the IMMUTABLE per-direction interval
   `[open_ack_lo(D̂), open_ack_hi(D̂)]` = `[isn+1, isn+SEG.LEN]`, and each
   leg first requires **`open_valid(direction)`** (§5.1 bit4/bit5 — set
   only when that direction's SYN actually seeded the interval;
   round-6 Codex 8: without the predicate the default `[0,0]` interval
   of the un-seeded direction accepts a bare `seq=0` RST through the
   self-abort leg). The interval is v7's immutability fix (round-5
   Codex 2: the live `seq_hi` slides on any committed in-window sample,
   which would let an attacker move the proof ceiling or the self-abort
   coordinate at ~1/2^16 guess cost; the immutable pair keeps the proof
   at 1/2^32 for a bare SYN, ≥ ~1/2^20 for max TFO):
   (a) **ack leg:** `ACK` set and `seg.ack ∈ [open_ack_lo(D̂), open_ack_hi(D̂)]`
   — RFC 9293 SYN-SENT `ISS < SEG.ACK <= SND.NXT`, covering RFC 7413
   §4.2.2 TFO partial-ack; accepts the Linux/Windows connection-refused
   RST AND its TFO-reject sibling; (b) **self-abort leg:**
   `seg.seq ∈ [open_ack_lo(D), open_ack_hi(D)]` (the aborting side's own
   SYN interval — a client aborting its half-open connection RSTs at
   `isn+1`; the residual — sent-data-then-abort before establishment,
   seq beyond the SYN interval — soft-refuses inside the 20 s opening
   window, negligible). Install seeds are trusted, so an OPENING entry
   always has at least its creating direction's trusted baseline; a
   materialized OPENING import with no local observation falls to rule 3
   (20 s opening window — the lingering cost of a refused legit close is
   negligible).
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
worker-owned `tcp_close_seq_rejected: u64`, **exported through the
ordinary worker statistics/metrics surface** (production-visible, no
debug build — AGY r4 LOW + round-4 Codex 9e) plus a rate-limited
structured RT_FLOW/screen-class record for attack attribution (never
per-packet).

### 5.5 Where the verdict is applied — marking moves to the post-borrow phase

Today `lookup_with_origin` marks the matched entry inside its `&mut`
borrow, then propagates post-borrow. Validation needs the FORWARD entry's
anchor even when the matched entry is the reverse companion — a second
probe that cannot happen inside the first borrow. Restructure (close
segments only; the no-close path is byte-identical):

1. In-borrow: compute `do_close` (flag check) as today; capture
   `actual_key` + `nat` (already captured for propagation). **Do not mark
   and do not refresh `last_seen_ns` yet for a closing segment.** The
   SYN-ACK established-promote moves to the post-borrow phase and fires
   only on the strong OPENING proof (§5.2 rule 5) — closing packets
   never promote, and unproven SYN-ACKs no longer pin half-open entries
   into the established window.
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

`update_session` (site 2): the promote path threads the packet's
`TcpSegView`; validation reads the forward entry's anchor (the entry
being promoted IS the forward entry in the promotable case —
`is_translated_forward_session_key` family — so no extra probe). **A
closing-flagged packet never reaches this path at all (rule 5 — the
ownership promote is skipped wholesale)**, so there is no partial-promote
transaction to specify: no origin flip, no Close-authority arming, no
self-heal suppression, no refresh question (round-4 Codex 2). A
non-closing promoting packet refreshes/promotes exactly as today.
Wire-driven `update_session` callers (no packet) skip validation.

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

**Reactive materialize (site 2c, round-2 Codex 1 / SMR 2, round-3 Codex
1):** `materialize_shared_session_hit` threads the current packet's
`tcp_flags` into `upsert_synced_with_origin`, which seeds `closing`/`reset`
at `install.rs:399-400`. Two v5 rules apply: (i) the constructor is NOT in
the self-authenticating provenance set — the driving packet's samples
adopt `valid`+untrusted only, so a non-close attacker packet materializing
a shared victim plants nothing usable; (ii) an imported replica carries no
trusted anchor → every closing-flagged materialize is no-baseline →
**refuse**: install the copy ALIVE (`closing=false, reset=false`)
regardless of the packet's flags. Unlike site 2b the install cannot be
skipped — the packet needs its decision and the entry must own the flow —
so the seed is suppressed instead. (Phase 2 §10.5's wire-carried anchor
makes this site validatable; until then every materialize-seed close is
refused by construction.)

**Primary-install context (site 3 supplement, round-4 Codex 8):** the
self-authenticating provenance is `(origin, FreshPrimary)` — the
`LocalMiss` installer can displace a peer-synced LocalDelivery entry
(`local_delivery.rs:75-113` + `take_synced_local`, `lookup.rs:407-418`);
a `ReplacedSyncedLocal` install adopts untrusted only, so a driving SYN
can never reclassify a synced victim as a fresh self-authenticating flow.
The installer returns the displacement outcome; a mandatory unit test
covers the replacement branch.

The fabric-return seed (site 6) is already close-free (#4453); primary
miss installs (site 3) are #4400-guarded; tunnel UpsertLocal (site 5) is
trusted-local; wire re-import (site 4) carries no packet; the forward-wire
immutable match (site 8) never marks directly (its promote-mediated marks
are gated by rule 5 — closing packets never promote).

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

- **Commit-hook plumbing (v5):** the §5.3 seg view is computed once per
  TCP packet at the flow-resolve stage and threaded to the per-disposition
  commit hooks (transit slow path, cache path, LocalDelivery). The anchor
  apply helper is invoked only at the commit point; #2501
  `account_packet` counters keep their current placement and semantics.
- **`TcpSegView` carries flags (round-3 Codex 5c):**
  `(seq, ack, wnd, seg_len, tcp_flags)` — the OPENING predicate needs
  `has_ack`; the update rules need `is_closing`/`has_ack` without a second
  header read. `Option<TcpSegView>` = `None` is reserved for control-path
  callers with NO packet (wire-driven updates, tunnel refreshes,
  `icmp_embed` lookups); an unparseable wire TCP closing segment is NOT
  `None` — it fails closed to refuse-demote (round-3 Codex 5d).
- **Install threading (round-3 Codex 5b):** the seg view threads BOTH
  install paths — the positional primary install
  (`install_with_protocol_with_origin`, `install.rs:106-122`; fresh
  SYN/pickup seeds incl. LocalDelivery) and the synced-upsert context
  (`SessionInstall`, `session/ctx.rs:31-48`) used by materialize.
- **`ForwardSessionMatch` provenance (round-3 Codex 5a):** gains the
  match scope (LOCAL vs SHARED) plus an anchor/`established` snapshot
  taken at match time — `lookup_forward_nat_across_scopes`
  (`shared_ops.rs:638-665`) can select a shared entry while a local
  fabric placeholder coexists, and re-probing by key would read the wrong
  local anchor.
- `install_reverse_session_from_forward_match` gains the forward anchor
  read + validator call.
- `SessionUpdate` gains `seg: Option<TcpSegView>`.
- No `FlowCacheEntry` change, no shim/meta change (no `make generate`),
  no HA wire change (Phase 1; the §10 Phase-2 field is a separate PR),
  no shared-map schema change, no config schema change.

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
  carries an anchor; every update goes through the per-disposition
  commit hooks (+install seeds); every validation reads the same store
  (`lookup_with_origin` validates/marks only — never updates). No second
  store, no merge.
- **Trust invariant (v6):** a close validates only against TRUSTED
  state — tracked anchor legs (rule 1 legs 1-2) or the close's own ack
  field against a trusted opposite seq (leg 3). Trust is born ONLY at
  `(FreshPrimary)` install seeds, per-field proofs against trusted
  state, or the strong OPENING handshake proof; trusted sides advance
  on their own continuity gate. Untrusted sides never confer trust,
  are never blessed by later proofs (replacement, not max-merge), and
  never validate a close. No-baseline ⇒ refuse-demote, everywhere
  (hit path, promote, materialize, synth, missing-forward).
  **Closing packets never promote** (neither `established` nor the
  `SharedPromote` ownership flip), so no Close authority can be armed
  by an unvalidated close.
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
- **Close authority = live RG ownership + shared-delete race (v7.2):**
  the `expire.rs:342-345` delta gate consults CURRENT HA state
  (`owner_rg_id` active locally) in addition to the stored origin
  class, and an imported entry emits only after winning the node-local
  shared-alias delete (the alias IS the single-producer ticket and its
  deletion IS the cleanup). No origin flip anywhere; authority is never
  stored, never packet-driven; the lazy self-heal window, the
  per-worker fanout flip, the `fabric_ingress` bypass, and the
  demotion-retag stranding are all moot. Packet-driven promotion
  (`SharedPromote` on a committed non-close packet) remains for entries
  imported after activation; closing packets never trigger it.
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
  path that already takes the full slow path. `SessionEntry` grows 40 B
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
    NAT): the match returns a copy — nothing marks DIRECTLY, today or
    after; the promote-mediated mark path behind it is gated by rule 5
    (closing packets never promote). Anchors for these flows advance
    from the reverse (mutable alias) direction only.
  - **PASS_TO_KERNEL** (`bpf_map/mod.rs:3-12`: peer-synced forward
    LocalDelivery, no tunnel): packets bypass AF_XDP entirely; the
    Rust-side imported entry carries no anchor. While bypassing, those
    packets cannot demote Rust state (no userspace path runs); after a
    REDIRECT/publish transition the entry sits in the absorbing
    zero-trust state — closes refuse until churn (§2); Phase 2 §10.5
    restores validation for the synced class.
  - **fabric-return reverse seeds** bypass the commit hooks; a later
    close on such a seed is refused (no anchor), the seed ages on its
    ordinary timeout, and `is_reverse` suppresses any Close delta — no
    owner kill.
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
| Performance regression | LOW-MED | 40 B/entry slab growth (~5 MiB/worker at cap); one TCP-header view compute (seq/ack/wnd/flags/seg_len) + ≤2 gated stores per committed TCP data packet (closing segments skip updates entirely); one extra probe per closing segment. Must be measured at minimum-frame rates (§9) — the 23 Gbit/s MTU-sized iperf run alone is insufficient (≈37 Mpps at 25 Gbit/s small-frame is the real gate; `iperf3 -l 64` is a proxy, not a demonstrated line-rate generator — gate on pps, not bandwidth). |
| Architectural mismatch | LOW | No new subsystem; anchors at the existing #2501/#3706 chokepoints; #4400-style always-on gate. No pipeline restructure. |
| HA / rolling upgrade | LOW-MED | Phase 1: no wire change; mixed-version peers each gate only their own marks; pre-upgrade and imported entries sit in the absorbing zero-trust state — closes refuse until churn (strictly more conservative than master; bounded lingering, §2; Phase 2 §10.5 closes it for synced flows). The replica no-Close invariant + the SharedPromote refuse trace are regression-tested. |
| Merge collision | LOW | No `FlowCacheEntry` change (v1's #6457 tension gone). `account_packet` signature change is local to two call sites; `SessionInstall`/`SessionUpdate` gains are crate-internal. |

---

## 9. Test plan

Unit (cargo) — all close-placement cases use DETERMINISTIC in/out-of-window
values (round-3 Codex 9: probabilistic sprays can legitimately hit the
admitted interval):

- Validator truth table: ESTABLISHED fresh trusted anchor (accept
  in-window RST/FIN; refuse low/high out-of-window; refuse far-future),
  the union leg (restart-RST `SEQ=SEG.ACK` accepted via trusted
  `ack_hi(O)` when `seq_hi(D)` refuses), serial-wrap edges (anchor near
  2^32−1, `wrapping_sub` membership, no panic — tracker serial-max wrap
  tested separately from validator membership wrap), OPENING (`ack ∈
  [isn+1, isn+SEG.LEN]` accept incl. TFO partial-ack at both interval
  ends, `isn` refuse, `isn+SEG.LEN+1` refuse, untrusted-baseline refuse),
  asymmetric (only one direction observed/trusted), missing/untrusted
  baseline → refuse (NEVER fail-open).
- **Provenance matrix (v5, round-3 Codex 1):** primary miss install
  self-authenticates (SYN/pickup seeds trusted); materialize/import/
  reverse-synth/upsert NEVER self-authenticate — a non-close attacker
  packet materializing a shared victim plants only untrusted state, a
  following close refuses, and the UNPROMOTED entry emits NO Close
  delta on its ordinary reap (peer-synced origin). (A later non-close
  packet may promote it; the then-promoted entry's natural reap DOES
  emit Close — correct owner semantics, round-6 Codex 10.)
- **Trust transactions (v5, round-3 Codex 3):** authenticated sample
  REPLACES untrusted storage (planted X discarded, not blessed/max-merged);
  unauthenticated sample never clears/alters trusted state (SYN
  retransmit preserves the trusted seed); untrusted never authenticates
  (fabricated self-consistent pair stays untrusted); `wnd` updates only
  from authenticated segments (no-knowledge precursor advertising 65535
  does not widen FWD_SLACK).
- **Handshake bootstrap:** SYN-ACK exact-interval authentication (TFO
  partial-ack inside interval authenticates both fields; outside
  refuses); client first ACK authenticates via rev anchor; fast server
  abort right after SYN-ACK validates (trusted rev seq from birth).
- **Commit-point observation (v5, round-3 Codex 6):** TTL=1 bounded data
  (Time-Exceeded at the firewall) does NOT update the anchor;
  input/output-filter-dropped packets do NOT update it; LocalDelivery
  admitted packets DO (post-admission hook).
- **ack poisoning (round-2 Codex 3):** SYN retransmit on an OPENING hit
  does NOT set ack validity (no near-zero acceptance leg); non-ACK
  segments never slide `ack_hi`; zero-length samples never slide
  `seq_hi`.
- **Poisoning (round-1 Codex B1):** ACK-only plant ahead of window does not
  move the anchor; RST at the planted seq still refused; in-window
  contiguous fake data slides the anchor at most FWD_SLACK per packet;
  closing segments never update the anchor anywhere (accepted or
  refused).
- **Two-packet reverse-NAT bypass (round-1 Codex B2):** blind RST on
  reverse tuple → NO reverse entry minted (skip-install), forward
  companion NOT marked, `tcp_close_seq_rejected` bumped; in-window
  variant → seeded closing + the honest master chain (reverse marked;
  #4380 companion retention defers its reap while the forward lives;
  next accepted hit propagates to both) — NOT an idealized 2 s whole-flow
  reap (round-2 Codex 8). Match-provenance: a SHARED forward match with a
  coexisting local fabric placeholder validates against the SHARED
  snapshot (refuse), never the wrong local anchor.
- **Materialize gate (site 2c):** closing-flagged shared-hit materialize
  installs the copy ALIVE (`closing=false, reset=false`), no Close delta
  on its later ordinary reap; non-closing materialize adopts untrusted
  tracking only.
- **Close authority = live ownership + shared-delete race (v7.2):**
  (a) blind first-packet close on a pre-activation import → NO
  ownership promote (origin stays `SharedMaterialize`), no mark, no
  refresh — fully inert; ordinary reap silent (RG not active).
  (b) post-activation: a blind close is still refused (inert); the
  entry reaps at its TRUE natural timeout; exactly ONE worker wins the
  shared-alias delete and emits the authoritative Close (no duplicate
  deltas, no RT_FLOW dupes); the alias is GONE (no rematerialization).
  (c) `fabric_ingress` imports take the same path (no early-Age
  bypass). (d) a validated post-trust close on a packet-promoted entry
  emits the Close. (e) demoted-node copies never attempt the race
  (RG not active). (f) RG flap: VRRP-overlap double-wins are
  idempotent under the gen rules. (g) a newer same-key incarnation
  (re-seeded on the peer) wins the gen compare against a stale winning
  Close.
- **Phase-2 contract (v7.2):** wire tail round-trips all fields
  (seq/ack/wnd/OPENING endpoints/seqno/session_id); `session_id`
  mismatch discards; seqno serial-compare rejects late updates;
  re-baseline-on-skip resumes emission after a fast stretch;
  receiver trust decay reverts an unrefreshed wire anchor to untrusted
  after T_anchor (stale blind-close window dies); batched aggregate cap
  holds the 256 records/s budget under a quiet-heavy churn flood.
- **Ack-stall residual (v7.2, round-6 Codex 7):** scaled-window loss
  burst (repair jump > raw-wnd gate) stalls `ack_hi` — leg-2
  restart-RST soft-refuses, legs 1/3 still validate normal closes;
  no wscale gate widening.
- **Pending-neigh token (v7.2):** a buffered SYN-ACK promotes only on
  successful retry enqueue (not at buffer admission, not on eviction);
  buffered non-close samples apply on retry; buffered accepted close
  marks at resolve (master parity).
- **Promote staging (v6):** closing-flagged packets never promote
  (neither in-borrow `established` nor the ownership flip); a reverse
  SYN-ACK promotes OPENING→ESTABLISHED only with `ack ∈ [isn+1,
  isn+SEG.LEN]` (inside → promote; outside → no promote, 20 s window
  retained; blind SYN-ACK spray cannot pin half-open entries — a
  master-parity improvement to assert).
- **Own-ack close leg (v6):** ACK-bearing close with ack in
  `window(seq_hi(O))` validates while its own seq is arbitrary;
  no-ACK bare RST in the same state soft-refuses.
- **Trusted self-slide (v6):** one-direction LocalDelivery flow advances
  its trusted inbound anchor on continuity alone; full-duplex
  scaled-window traffic (seq ahead of opposite ack ≤ window) never
  stalls.
- **LocalMiss replacement (v6, round-4 Codex 8):** a SYN driving a
  `ReplacedSyncedLocal` install adopts untrusted only — the synced
  victim's close validation is unchanged.
- **Commit arms (v6):** anchor applies on successful dispatch enqueue /
  cache-path rewrite success / reinject acceptance; MTU-fail,
  NAT64-protocol-reject, binding-miss, output-drop, TTL-expired packets
  do NOT move it.
- **Tracker deltas (round-4 Codex 9d):** exact wrap cases
  `0xfffffff0 → 0x20`, zero delta, `FWD_SLACK`, `FWD_SLACK+1`, `2^31`
  boundary; OPENING wrap; tracker serial-max wrap separate from
  validator membership wrap; `wrapping_add` for `seq+SEG.LEN` everywhere;
  compile-time 40-byte layout assertion.
- **Immutable OPENING endpoints (v7, round-5 Codex 2):** a committed
  in-window non-close sample slides `seq_hi` but NOT `open_ack_hi`;
  a same-direction RST at the moved `seq_hi` value is REFUSED (the
  self-abort leg consults only the immutable interval); a spoofed
  SYN-ACK acking the moved ceiling fails the proof.
- **Per-stream slack (v7, round-5 Codex 4):** asymmetric-window truth
  table — leg-3 ack-lag bound derives from `wnd(D)`; `ack_hi(D)` slides
  gate on `FWD_SLACK(O)`; a scaled-window asymmetric pair neither
  false-refuses nor over-accepts.
- **Commit boundary (v7, round-5 Codex 6/7):** `push_redirect_inbox`
  capacity discard is reported and does NOT move the anchor; fallback
  reinjection success (`dispatch/mod.rs:898` arm) DOES; a proved
  SYN-ACK that is then filtered/TTL-expired/dispatch-dropped does NOT
  promote.
- **Simultaneous open (documented residual):** crossed SYN-ACK with ack
  in interval promotes; lost reverse SYN-ACK (final ACK only) stays
  OPENING exactly as master (no regression — master's promote also
  requires is_syn_ack); no new transition is added by this change.
- **Re-import wipe (round-3):** `upsert_synced_with_origin` over a
  locally-observed entry discards the anchor → closes refuse (documented
  absorbing state).
- Anchor single-store: reverse packets update only the forward entry;
  missing-forward refuse (FabricRedirect no-local-reverse shape).
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
  RST/FIN with DETERMINISTIC out-of-window seq (below/above the tracked
  anchor, far-future, seq≈0) → flow survives, session stays established,
  `tcp_close_seq_rejected` advances.
- Legit positive: in-window RST (seq captured via tcpdump) → demote
  exactly as today; ordinary iperf3/SSH Ctrl-C teardown identical to
  master; connection-refused RST against a half-open → opening reap
  unchanged.
- HA: `make test-failover` (mandatory); **post-failover blind-spray
  negative (v6)**: immediately after RG switchover, spray blind closes at
  synced-but-not-yet-observed flows → entries survive (refuse-demote,
  NO ownership promote on closing packets, no Close deltas, standby
  copies intact, self-heal unsuppressed); the imported flows' later legit
  closes refuse and entries linger to ordinary timeout (the absorbing
  state — trust does NOT return until churn; Phase 2 §10.5 restores
  fast-reap for quiet flows via the wire anchor, and its smoke gate
  re-runs this test expecting validated closes on quiet flows to reap at
  2 s again).

---

## 10. Out of scope (explicitly)

- Junos general per-packet sequence check (`no-sequence-check` enforcement,
  #2008 M9 / #2078) — the wscale-aware data-plane window check on *every*
  segment. Bigger, throughput-sensitive, asymmetric-routing-hostile;
  separate issue. (Named honestly: xpf lacks this Junos-DEFAULT check;
  this plan closes only the RST/FIN demote DoS.)
(See §10.5 for the Phase-2 HA-wire anchor — a REQUIRED fast-follow, not
an option for the synced class.)

### 10.5 Phase 2 (required, same feature, ordered second PR): HA-wire anchor carriage

Phase 1 leaves the §2 absorbing-state residual: imported entries never
validate closes until churn. Phase 2 carries the trusted anchor from the
RG owner to the standby so a post-failover/re-import node inherits a
validated baseline. The full contract (v7.2, round-6 Codex 3/4/6):

- **Payload (~50 B, additive tail, presence-gated):**
  `{fwd_seq_hi, fwd_ack_hi, rev_seq_hi, rev_ack_hi: u32,
  fwd_wnd, rev_wnd: u16, valid: u8, trusted: u8,
  fwd_open_ack_lo, fwd_open_ack_hi, rev_open_ack_lo, rev_open_ack_hi: u32,
  anchor_seqno: u32, session_id: u64}`. Every field the import rule or
  the slack arithmetic needs is on the wire (v7's 18 B tail omitted the
  seqno, the wnds, the OPENING endpoints, and an incarnation identity —
  round-6 Codex 3). `session_id` (#4915, already node-unique) binds the
  anchor to the session INCARNATION: an update for a reaped/re-seeded
  tuple whose id mismatches is discarded, so an old high-seqno update
  can never bless a same-tuple replacement. The existing payload framing
  tolerates trailing length-gated fields (`sync_protocol.go:95-102,
  :470-497`); tail presence per message IS the rolling gate (no bitmap —
  none exists in `syncHeader`/the auth HELLO).
- **Channel (dedicated, not MSG_SESSION_UPDATE):** current
  `MSG_SESSION_UPDATE` decodes as a full session and maps to "open"
  (`eventstream.go:559` → `daemon_ha_userspace_stream.go:205` → a fresh
  install generation + full upsert) — unusable. Phase 2 adds a dedicated
  `AnchorUpdate` message type on the Rust→Go event stream and a matching
  `anchor_update` op in the Rust helper control protocol
  (`sync_session.rs:19` today has only upsert/delete), applied IN PLACE
  (no `remove_entry`, no anchor wipe, no index churn) to the shared
  aliases AND worker replicas; worker commands gain the operation
  (`types/runtime.rs:408`).
- **Go-side store + bulk (the scope guard is restated honestly):** Go
  gains anchor fields in its synced session store (updated by
  `AnchorUpdate`), and the authoritative reconnect bulk
  (`sync_bulk.go:40, :95` — which enumerates the anchorless
  BPF-compatible store and deliberately not the Rust table,
  `daemon_ha_sync.go:974`) carries them as the same additive tail. v7's
  "no Go behavioral change beyond decode/re-encode" was impossible
  (round-6 Codex 3): a reconnect full-upsert of tail-less snapshots
  would otherwise wipe a previously current quiet-flow anchor with no
  repair. Phase 2's Go surface = the new opcode handler, the store
  fields, and the bulk tail — no control-plane BEHAVIOR change beyond
  those.
- **Emission (single writer, interval seqno, aggregate budget):** only
  the worker that OBSERVES the flow emits (the shim's flow-hash steering
  binds both directions to one worker, so the writer is naturally
  unique — round-6 Codex 6a). `anchor_seqno` increments per EMISSION
  INTERVAL (per entry ≤ 1/s — not per packet; a u32 then outlives any
  deployment at 2^31 s). Emission rules: (i) at most one update per
  entry per interval (~1 s); (ii) emit only when the anchor advanced
  ≤ one slack since the last BASELINE; (iii) on an over-threshold
  interval, RE-BASELINE silently (baseline := current, nothing sent) —
  so a fast flow that later quiets resumes emitting with a fresh
  baseline (v7's cumulative-since-last-emit filter had a terminal
  no-emit state, round-6 Codex 4); (iv) a per-worker bounded dirty ring
  (~4,096 keys, drop-oldest with watermark) feeding BATCHED messages
  (up to ~64 anchor records per control message), under a per-worker
  AGGREGATE cap (~256 records/s, jittered — round-6 AGY Q1: per-entry
  limits alone scale linearly with flow count; the stream is shared
  with Open/Close installs and the peer's 4,096-message nonblocking
  queue, `sync_conn_write.go:36`).
- **Receiver trust decay (v7.2, round-6 Codex 4):** a wire-trusted
  anchor side DECAYS to untrusted if not refreshed within `T_anchor`
  (~4 × the emission interval). Without decay, a stale-but-trusted
  standby anchor accepts blind closes in dead sequence space forever
  (a wrong-accept window at normal blind-guess difficulty — the
  firewall demotes on a packet the endpoint long moved past). With
  decay, loss (ring eviction, overflow, a deliberately fast-moving
  anchor — all observable via the watermark counter) degrades to the
  Phase-1 refuse-biased posture instead of a permanent stale-accept
  channel. An attacker suppressing a victim's updates (keeping the
  anchor fast-moving, or filling the ring with permitted-client flows)
  buys exactly that refuse-biased posture and nothing more.
- **Semantics on import:** a wire-carried side lands `valid`+`trusted`
  (validated by the owner from real traffic). Stated honestly: the
  anchor is at most ~1 interval stale at failover, and a fast flow
  advances far beyond slack in 1 s (64–128 KiB ≈ 52–105 µs at 10 Gbit/s,
  21–42 µs at 25 Gbit/s) — the wire anchor is EXACT for quiet and
  moderate flows (precisely the idle SSH/BGP/IKE/management class the
  issue names) and REFUSE-BIASED for bulk flows (emission filter +
  trust decay both point there; their churn cost is lowest). This is
  the design intent: the victims are the quiet flows.
- **Security review surface:** the wire is the cluster trusted domain
  (same as heartbeat/session sync today — an attacker who can inject
  session-sync frames already owns the table). The field adds content to
  an existing trust domain, not a new one.

---

## 11. Open questions for adversarial review (round 7)

1. **Shared-delete race (§5.2 rule 5, §7):** Close authority for an
   imported entry requires winning the node-local shared-alias delete.
   Verify: (a) the alias exists at reap time for every import class
   (SharedMaterialize, SyncImport, WorkerLocalImport, fabric_ingress —
   does EVERY one publish a node-local shared alias, or are there
   import classes with no alias whose Close then never fires?); (b)
   the delete is atomic per key under the coordinator lock; (c) the
   winning worker's Close carries the import's stored generation (a
   newer same-key incarnation on the peer wins the gen compare); (d)
   owner-BORN entries keep today's direct emission (no race needed —
   their alias is the live session's own).
2. **Receiver trust decay + re-baseline (§10.5):** an unrefreshed wire
   anchor reverts to untrusted after T_anchor (~4 s). Verify the
   interaction with legit quiet flows whose keepalive period EXCEEDS
   T_anchor (a 30 s BGP keepalive flow emits an update only when the
   anchor MOVES — a totally idle flow emits nothing for minutes → its
   wire anchor decays to untrusted → post-failover closes refuse until
   the next packet re-refreshes. Is that the right posture — the anchor
   IS stale by then — or should idle entries emit a heartbeat refresh
   (cheap: re-emit current anchor before decay)? Adjudicate.
3. **Final-admission apply (§5.2):** the anchor updates at final CoS/
   admission success, with the admission layer reporting drops. Verify
   no post-admission drop class remains except the documented
   TX-completion tail, and that the pending-neigh token cannot be
   replayed across a session re-seed (incarnation binding).
4. **Leg-2 ack-stall residual (§5.2):** the design accepts `ack_hi`
   stalls on scaled-window repair jumps >131,070 (restart-RST leg
   soft-refuses; legs 1/3 unaffected). Check the claim that seq
   tracking cannot stall from the same loss event (the firewall
   forwards the data, so seq_hi advances past the hole — true for
   downstream loss; what about loss BEFORE the firewall on the inbound
   path — sender side — does the retransmit repair it in-window?).
5. **OPENING open_valid predicate (§5.4 rule 2):** interval legs
   require open_valid(direction). Any legit case where the interval
   seeded but the bit didn't set (mid-stream pickup of a SYN-ACK —
   does the pickup seed BOTH the rev interval (from the SYN-ACK) and
   infer the fwd one (from its ack)?)?
6. **Phase-2 Go surface (§10.5):** dedicated opcode + store fields +
   bulk tail + in-place apply across shared aliases and worker
   replicas. Verify the apply fanout cost (N workers × M updates under
   the aggregate cap) and that the bulk tail keeps old-decoder
   tolerance.
7. **Observability:** `tcp_close_seq_rejected` via worker metrics +
   rate-limited structured event. Sufficient, or per-zone?
