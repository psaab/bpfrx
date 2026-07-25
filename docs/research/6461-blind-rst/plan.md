# #6461 — blind off-path TCP RST/FIN demotes a live session with no sequence validation

**Status: DRAFT v9 — CONVERGENCE RESTRUCTURE: Part A (the dataplane
demote gate) is the ship candidate; the HA cleanup shrinks to minimal
machinery; the Phase-2 HA-wire anchor protocol splits to its own
research track (docs/research/6461-blind-rst/phase2-brief.md)**

Twelve rounds in one paragraph: the packet-level plausibility gate has
been stable since v6 and Codex's round-12 verdict confirms it has
"substantially converged" — refuse-demote on no trusted baseline,
per-field proofs + own-ack leg, immutable OPENING interval, trusted
continuity slides, closing-never-promote, commit-point observation,
constructor gating, never-drop delivery. The last six rounds of PLAN NO
verdicts were ALL in the HA cleanup/Phase-2 layer, where every fix at
level N exposed level N+1 (authority → ticket → incarnation → protocol →
clocks → versions → ownership terms). v9 restructures: Part A ships the
gate; Part B handles its HA consequences with the minimum machinery that
survives review (closing-never-promote, ONE emission predicate, a
family-clock TTL sweep with a commit-time incarnation recheck, and the
NAT-release investigation FILED as its own pre-existing bug); Phase 2 —
the HA-wire anchor that would restore fast-reap for synced flows — moves
to its own research track with the rounds 6-12 findings preserved as its
design brief. The issue's HA teeth are closed by Part A alone, stated
precisely (round-13/14 Codex's wording catch): a blind close can mark
ONLY inside the acceptance window (~1/2^12–1/2^14 per blind packet) and
every such mark was validated against observed flow state; a REFUSED
(out-of-window or no-baseline) close can never mark — so the
1-packet-anytime cluster kill is dead, and what remains is the
documented sustained-spray capability at window probability, whose every
successful mark is, by construction, one the endpoints' own RFC 5961
handling also had a chance to reject.

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
windows: worst ≈ 1/6,554 (cap) / 1/10,923 (floor), stated unvarnished;
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
  optimistic by up to ~2× (stated, not hidden). Difficulty across all
  configurations: ~1/2^12 (cap) to ~1/2^14 (floor) per blind packet.
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
  contend. This residual is what the Phase-2 HA-wire anchor closes ON
  ITS OWN RESEARCH TRACK (§10.5 — deferred after twelve rounds showed
  the protocol keeps unfolding; it is an optimization for this residual,
  NOT part of this issue's gate). The post-failover `SharedPromote`
  cluster-kill trace is dead regardless (a refused close never marks).
- What this costs a legitimate teardown when the gate misjudges: the
  packet is always delivered (endpoints tear down normally), the entry
  idles out on its ordinary timeout instead of the 2 s/30 s fast reap —
  a table-pressure cost, never a broken connection. Aggregate version
  (round-2 Codex): a both-direction path-switch can stall an anchor
  permanently (§5.2); many flows stalling after one path event linger to
  their established timeouts — bounded, self-healing as flows churn.
- Cost (stated whole, v8.4): 56 B of anchor/proof/lease state on
  `SessionEntry` plus ~48 B of Phase-2 scheduling state (incarnation
  fields, per-bundle seqnos/baselines/observation timestamps, writer
  identity, heartbeat/dirty state) — ≈ 104 B/entry on the uniform
  slab (UDP/ICMP entries carry it unused; ≈ 13.6 MiB per worker at
  the 131,072 cap, ≈ 82 MiB at 6 workers), plus the Go sidecar
  (~80 B per synced entry ×2 nodes; sidecar entries are created only
  for live synced entries and deleted on close/bulk reconcile — max
  size = the session cap). Per-packet: one TCP-header view compute
  (seq/ack/wnd/flags/seg_len) plus ≤2 plausibility-gated `u32` stores
  per committed TCP data packet, and a second table probe only on
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
| 3 | `install.rs:179-180` primary miss installs | creating packet flags | unreachable for bare closes on TRANSIT dispositions (#4400) and LocalDelivery caches TCP only with SYN (`local_delivery.rs:20` — the "LocalDelivery bare-close seed" residual from round 11 does not exist, round-13 Codex M9). The actual residual: a SYN|RST/SYN|FIN new-flow packet passes the #4400 guard (it has SYN, `session_admission.rs:53`) and seeds closing/reset from raw flags — a self-anchoring invented-tuple entry (attacker kills only a flow it created — no victim impact, master parity since install.rs:179 seeded from flags before this plan); malformed SYN+close combos are screen-owned where screened |
| 4 | HA wire re-import — eventstream `UpsertSynced` → `upsert_synced_with_origin` (no packet exists) | peer delta | validation-free by design (the peer validated before reaping and emitting the Close); distinct from site 2c, which HAS a packet |
| 5 | tunnel `UpsertLocal` (`tunnel.rs:563-615` → `session_glue/mod.rs:786-800`) | locally generated packets (firewall-originated tunnel TX) | trusted-local class, documented; not wire-attacker-controllable. Inbound tunnel closes land on site 1 with whatever anchor the inbound stream built — none if the flow is outbound-only → refuse-demote; local blast radius (round-2 Codex 5) |
| 6 | fabric-return reverse seed (`cluster_peer_return_fast_path` install) | fabric-ingress packet flags | bare closes already excluded (#4453); SYN|ACK|RST/FIN combos pass the guards (`fabric.rs:404`) and seed raw flags — an unvalidated constructor, harmless-by-class (the seed is `is_reverse` → silent at reap; the non-owner's forward import validates closes at site 1 with no anchor in Phase 1 → refuse → no mark). The seed bypasses the commit hooks so it carries no anchor — a later close on it is REFUSED (missing-forward/no-baseline, §5.1); documented |
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

`SessionEntry` gains (56 B; plain POD, worker-owned, no serde, no HA
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
(40 B for the tracking/proof state — round-4 Codex 4a + round-5 Codex
2/9: both OPENING interval endpoints are explicit immutable state; a
compile-time layout assertion pins the size; `seq+SEG.LEN` arithmetic is
`wrapping_add` everywhere — plus 16 B of per-side wire leases, v7.5:
56 B total.)

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

- **Commit point = RX-WORKER FINAL ADMISSION with geometry hoisted
  and selective no-learn (v8.2, round-10 Codex 9):** the anchor lives
  on the canonical forward entry in the RECEIVING worker's table;
  CoS can hand the request to a different owner before final
  admission (`cos.rs:125`), and a target-side admission point cannot
  mutate the RX worker's table without a per-packet cross-worker
  callback (rejected: worse than the residual). The anchor applies at
  the RX worker's OWN final admission point — after binding/MTU/
  translation/CoS-selection AND after every **geometry-determined**
  check (MTU, slice validity, frame malformed — `transmit/stage.rs:23`;
  packet geometry is attacker-chosen and pairs with any chosen
  sequence, so a geometric check left in the tail is a
  sequence-targeted poisoning channel). `push_redirect_inbox`
  capacity discard MUST be reported (`umem/mod.rs:1290`'s reporting
  API) and does not move the anchor (mandatory, not best-effort).
  **Selective no-learn (round-10 Codex 9's narrower fix):** no anchor
  learning on `NoRoute`/`NextTableUnsupported`/`MissingNeighbor`
  reinjection or ForwardCandidate build-failure fallback
  (`slow_path.rs:60`) — those exceptional paths are transient by
  construction. The remaining async-write tail (LocalDelivery
  reinjection incl. GRE-mapped at `slow_path.rs:213/:297`, TUN-egress
  at `tunnel.rs:119/:180`, kernel slow path at `slowpath.rs:534/:607`)
  admits per-packet malformed `EINVAL` — geometry-steerable. Stated
  with full honesty (round-11 Codex 8): the channel adds NOTHING to
  the demote attack's probability (a malformed precursor needs the
  SAME ~1/6,554–1/10,923 in-window hit as a direct blind close), but
  it is NOT strictly dominated for every attacker objective — after
  one hit, contiguous malformed follow-ons ride the trusted
  self-slide, and poisoning the anchor so the endpoint's legitimate
  close is soft-refused RETAINS a slot/NAT reservation for the
  entry's ordinary timeout (300 s default, up to 86,400 s per-app) —
  a resource-retention objective some attackers prefer over a 2 s
  demote that releases resources. Its honest bound (round-12 Codex 11
  + round-13 M9): spray duration PLUS one inactivity timeout — the
  walk's follow-on packets are ordinary non-close packets that refresh
  `last_seen` through the unchanged non-close path (`lookup.rs:150`,
  `flow_cache_hit.rs:295`), so the attacker holds the entry only by
  continuing to spray — exactly what a plain valid-looking keep-alive
  spray already buys on master at identical in-window guess cost, so
  this is NOT a new pin primitive; when the spray stops, the entry
  idles out within one timeout. Accepted because the alternatives
  (per-packet post-commit callbacks, or freezing these anchors and
  soft-refusing every close on the host-inbound victim class) are
  worse. All other arms are commit-clean.
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
  timeout discards them. **On incarnation mismatch the retry must
  RE-RESOLVE ONCE against the new incarnation — preserving the original
  pending deadline and probe budget — or drop (v7.5, round-8 Codex 9;
  v8.2, round-10 Codex 11):** suppressing the stale mutations is not
  enough — transmitting with the OLD decision can use a released or
  reassigned SNAT port (the retry currently reuses the buffered
  decision at `neighbor_dispatch.rs:272, :310, :344, :369`), and an
  unbounded re-pend loop would pin the frame (re-admission today
  resets `queued_ns`/`probe_attempts`, `poll_descriptor/mod.rs:5057`).
  The rule for EVERY fresh result: standard-dispatch the FRESH
  decision (ForwardCandidate, LocalDelivery, FabricRedirect, NoRoute,
  NextTableUnsupported — each takes its normal path) or drop; NEVER
  transmit using the stale NAT/egress decision. The close proof and
  establishment promote are recomputed against the new incarnation
  during that single re-resolution; a second `MissingNeighbor` drops. Demote marking for an
  ACCEPTED close stays at resolve time (master parity — a close
  buffered for ARP already demotes on master; only anchor updates and
  the establishment promote are delivery-gated).
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
     Close authority (on MASTER today, a forward `SharedPromote` emits a
     Close delta at ANY expiry, marked or not, `expire.rs:342-377`) and
     suppresses the
     import's RG-activation self-heal (`expire.rs:213-237`), letting a
     refused close convert a silent standby reap into an authoritative,
     possibly accelerated, Close. **Close authority (v8 — the simplification round,
     replacing the v7.x ticket tower):**
     - **Gate (v8.2 — one exact predicate, round-10 Codex 1):** the
       `expire.rs:342-345` delta gate becomes
       `!is_reverse && !is_transient_seed &&
       (owner_rg_id > 0 && owner_rg_active(owner_rg_id) ||
        owner_rg_id == 0 && locally-born) &&
       (locally_born || marked)` where **`marked` is the entry's
       existing sticky `closing || reset` bits with NORMATIVE creation
       rules** — set ONLY by (i) a locally ACCEPTED close validation
       (§5.4, with companion propagation #4109), (ii) a wire import
       carrying closing flags (site 4: the PEER validated before
       marking and syncing), or (iii) trusted-local tunnel packets;
       never cleared within an entry's life; inherited per wire flags
       on reimport (a full reimport remove/replaces the record and
       re-seeds the bits from the wire — a peer-validated close is
       never lost, round-10 Codex 7b); never set by a refused close
       (§5.7). **Enforcement point (v8.3, round-11 AGY Q1):** the raw
       flag seeds at `install.rs:179-180/399-400` run BEFORE validation
       today, so the rules are enforced at the constructors per §5.6 —
       the reverse-synth validates BEFORE seeding (refuse → skip
       install), the materialize installs ALIVE on a refused closing
       hit (no seed), and fabric-ingress closing hits validate at site
       1 like any other (the non-owner's import has no trusted anchor
       in Phase 1 → refuse → no mark → the 2 s failover window AGY
       traced is closed); propagation fires only on ACCEPTED marks
       (§5.5). **The mark on the wire (v8.4, round-11 Codex 3):** the
       current import path carries NO close flags (`SessionSyncRequest`
       has none, `control.rs:988`; import hardcodes `tcp_flags: 0`,
       `server/helpers/session_sync.rs:168`) — the peer-validated mark
       rides the Phase-2 anchor tail (a `closing: u8` on the anchor
       message, which is exactly closing-state carriage). Phase 1's
       zero-producer residuals are documented and hygiene-bounded:
       (a) accepted close on the old node → failover → full reimport
       before the 2 s reap erases the mark (flags=0) → entries idle
       out naturally and the reservation-release/alias sweep cleans
       up (the prompt delete and RT_FLOW close record are lost — a
       telemetry/hygiene degradation, never a stale-alias hazard);
       (b) a reverse-synth accepted close marks the FULL forward
       family atomically in the same resolve (v9.2+; the reverse entry
       stays `is_reverse`-silent at reap) — the forward emits at its
       2 s reap; with no later packet the emission still happens (the
       mark was applied at accept time, not on a later hit). The mark
       is incarnation-bound
       by entry lifetime — live state at reap time
       (closes the publish-before-command demotion window for stamped
       entries; `owner_rg_id` is now stamped on EVERY forward install
       path via `owner_rg_for_resolution` — round-9 AGY 1: today only
       promote stamps, `promote.rs:93-94`, and LocalDelivery passes 0
       explicitly — LocalDelivery stays owner-zero BY DESIGN since Go
       excludes host-local sessions from HA sync,
       `daemon_ha_userspace_stream.go:29`, so no cluster cleanup is
       owed; the #2120 held standby class stays zero-and-silent).
     - **Emission is uniform and at-least-once (v8.2, round-10 Codex
       7):** ANY entry satisfying the gate with `marked` set emits at
       its reap — locally-born entries emit at natural reap as today
       (owner semantics), and import-class entries
       (`SyncImport`/`SharedMaterialize`/`WorkerLocalImport`) emit ONLY
       when marked — i.e., after a VALIDATED close (local §5.4-accepted,
       or peer-validated wire import) — because the mark exists only
       where the close was validated, deletion is correct by
       construction, and unmarked replicas stay silent exactly as
       master (the round-7 Codex 1 stale-sibling hazard stays dead:
       an unmarked sibling can never emit, and a marked sibling
       validated the close — the flow IS closing). Exactly-once falls
       out of the EXISTING delete propagation (the winning Close's
       downstream fan-out removes the companions and worker replicas,
       `session_delta.rs:436, :453` → `delete_synced.rs:16`): for a
       split-steering flow, worker B's marked replica emits at 2 s and
       the propagation removes worker A's entry BEFORE its natural
       reap — one Close, no duplicate RT_FLOW. The bounded duplicate
       case (two workers marked by a retransmitted valid close before
       the delete lands — round-10 Codex 7a) is idempotent at the
       store plus a documented rare duplicate RT_FLOW record. No alias
       CAS, no mint-on-zero, no promote-ordering machinery — the v7.x
       incarnation-ticket tower is deleted, not patched.
     - **Stranded-alias cleanup via a TTL reaper (v8.2, round-10 AGY
       Q2 + Codex 2/3):** the hazard round-5 Codex 1 found
       (close-first failover leaves no Close producer; stale shared
       NAT aliases can rematerialize after allocator reuse,
       `upsert_synced.rs:80`) is closed NOT by authority semantics but
       by a coordinator-side **shared-map TTL sweep with a real
       liveness clock and compare-delete**:
       (a) `SyncedSessionEntry` gains `last_touch_ns: u64` AND
       `expires_after_ns: u64` (shared-map schema is node-local —
       additive; the timeout is COPIED at publish time AND refreshed
       on every later stamp — v9.2, round-13 Codex H6: a SYN publishes
       the 20 s opening timeout (`install.rs:157` →
       `poll_descriptor/mod.rs:2560`) and the handshake later gives the
       entry its established/application timeout (`lookup.rs:146`);
       the promote re-publish updates the field, and the 30 s batched
       push carries BOTH `last_touch_ns` and the worker entry's current
       `expires_after_ns`, each incarnation-conditional — a quiet
       established flow can never be swept at `K × opening_timeout`
       while its worker entry is valid, and an explicit
       OPENING→ESTABLISHED sweep test is mandatory). The family's clock
       lives on the CANONICAL-KEY record of the family — the forward
       canonical entry when present, the REVERSE canonical entry for
       a lone reverse import (`ha/session_import.rs:78` — a
       reverse-only family has a clock too, round-12 Codex 6). It is
       stamped on events (materialize/promote/replicate/
       `refresh_owner_rgs` — worker control events only) and by the
       v8.1 batched worker push (each worker's expire pass, every
       30 s, refreshes the aliases of entries whose local
       `last_seen_ns` is within the interval — one lock per shard).
       **Reads do NOT touch (v8.4, round-11 Codex 1):** v8.2's
       read-touch let any tuple-matching packet — including a blind
       spray — refresh a stale alias indefinitely and made a refused
       close a shared-alias refresh, violating §5.7's inertness; a
       live flow's alias is kept by its worker-local entries' pushes,
       so reads need no clock.
       (b) The sweep purges only entries with
       `now − last_touch_ns > K × expires_after_ns`, K ≥ 4 — the
       floor is the standby-hold ceiling (~T + 3T, `session/mod.rs:103`,
       `expire.rs:585`), so a held standby entry cannot be swept mid-
       hold; jitter is absorbed by the 4× margin.
       (c) **ONE family liveness record + ordered compare-delete +
       commit-time incarnation recheck (v9):** the family's clock lives
       on the canonical-KEY record (per (a) — forward when present,
       reverse for a lone reverse import) — every family event/push on
       any member (canonical forward, canonical REVERSE
       (`ha/session_import.rs:104` — named in the family), NAT alias,
       forward-wire alias, and the `dnat_table` side effect created at
       `ha/session_import.rs:122` and removed by normal cleanup at
       `:273` — named in the family and in the deletion order, round-13
       Codex M9) stamps THAT record's
       `last_touch_ns` via a helper that resolves the canonical key
       (reads never stamp, per (a));
       the sibling clones carry no clock of their own (round-11 Codex
       2's incoherent-clones defect: a NAT lookup refreshing only its
       own clone could orphan or preserve the wrong member). The
       sweep reads the canonical clock; the scan + recheck + deletes
       run under a DOCUMENTED lock order (canonical → NAT → wire →
       indexes — every publisher, promote, touch helper, sweep, and
       materialization commit takes them in this order), and each
       member is deleted ONLY if its stored `flow_incarnation_id`
       equals the candidate's — a live colliding E2 that displaced
       E1's alias (`shared_ops.rs:918`) is never removed by E1's
       sweep, and a promote/republish mid-scan either updates the
       incarnation (mismatch → skip) or the recheck passes (same
       incarnation → correct delete). **The
       detached-clone race (round-12 Codex 2) is closed at
       every shared-decision commit (v9.2, round-13 Codex B2/H5):**
       the recheck applies at EVERY consumer of a cloned shared
       decision — `materialize_shared_session_hit`; the reverse-synth
       path (`lookup_forward_nat_across_scopes`,
       `shared_ops.rs:638-665` → `install_reverse_session_from_forward_match`);
       the embedded-ICMP consumers — BOTH the NAT-match paths
       (`icmp_embed/nat_match_v4.rs:41` and the session-fallback lookups
       at `nat_match_v4.rs:78, :87`, `nat_match_v6.rs:66, :100, :117`)
       and the return-resolution path (`icmp_embed/return_resolution.rs:20`);
       the `keep_transient` clone branch at
       `session_glue/mod.rs:1194-1195`; and the asynchronous
       upsert/prewarm
       command consumption (activation prewarm clones at
       `shared_ops.rs:304, :357`; replication clones at
       `session_glue/mod.rs:838`; install at `upsert_synced.rs:64`).
       (The icmp_embed session-fallback and keep_transient consumers
       were round-14 AGY's final coverage catch.)
       Each consumer re-reads BOTH the canonical record AND the exact
       source alias slot it consumed under the canonical lock at
       commit, requiring each stored `flow_incarnation_id` to still
       match the clone's (v9.4, round-14 Codex H3a: a different-forward
       E2 can displace E1's NAT/wire alias while E1's canonical record
       is unchanged — a canonical-only compare would pass on a stale
       alias; static/interface NAT has no allocator conflict to catch
       it). For NAT'd decisions the consumer performs an atomic
       **verify-and-retain** under the allocator's lock (v9.5 —
       round-14 Codex B1 sharpened further: a READ-ONLY verify can
       still race release+reuse between the check and the install's
       publish, leaving the installed entry holding E1's decision on
       E2's port): in one critical section, check that the live
       allocation for this tuple equals the decision's exact translated
       tuple AND register a holder on it. The hold is an **owned token
       with a complete lifecycle (v9.6, round-15 Codex B3):** the token
       carries the exact allocator/allocation identity; a re-import/
       upsert TRANSFERS it atomically from the old entry to the new
       one in the same operation (retain-before-replace — never
       leak-per-refresh and never release-then-reacquire,
       `install.rs:322`); every non-reap deletion path releases it
       explicitly (common `remove_entry` returns the entry — all
       callers drain the token, `session/mod.rs:1746`), and worker
       shutdown drains the table's outstanding tokens
       (`loop_body/mod.rs:1428`); one-shot consumers (embedded-ICMP)
       use a SCOPED guard token released at end of packet processing
       (the µs-scale window is the only exposure, and the packet
       already forwarded is the only effect); a synthesized reverse
       entry's hold references the FORWARD allocation and releases
       through the forward allocation's refcount (not the reverse
       early-return path at `source.rs:789`); and the refcount itself
       is overflow-checked. **Reconcile hold escrow (v9.9, round-18
       Codex B1 — join-first would destroy the holds before the keeper
       could acquire them, since joining waits for worker-local state
       to destruct and the RAII side map drops every old hold during
       the join, `worker_manager.rs:146`):** the reconcile sequence is
       a TWO-PHASE stop (a NEW mechanism — today `teardown.rs:80`'s
       `stop_inner(false)` signals `stop=true` and joins/destructs
       worker threads in one step, `worker_manager.rs:146`, with no
       quiesce-without-destruct state; it is added here): (1) SIGNAL
       quiesce — workers stop processing NEW packets (no new commits)
       but stay ALIVE and keep their tables and side-map tokens, AND
       drain or extract the tokens held in pending COMMAND QUEUES
       (round-19 AGY: unconsumed queued commands can reference holds —
       a join/destruct would RAII-drop them and release the holds
       prematurely instead of transferring them); (2) HANDOFF — each
       worker transfers its outstanding `NatHoldToken`s (table-held
       AND queue-drained) to the coordinator escrow
       DURING its own shutdown, while it still owns them (the keeper
       set is complete: every hold that existed at quiesce is in the
       escrow before any worker's side map can drop); (3) JOIN
       (`worker_manager.rs:146`) — side maps drop with nothing left
       to drop; (4) the teardown SNAPSHOT runs QUIESCED
       (`teardown.rs:54`) — no worker can commit a new SNAT flow
       mid-shutdown (`loop_body/mod.rs:332`,
       `poll_descriptor/mod.rs:2560` — the v9.7 race where a
       post-snapshot commit escaped both snapshot and escrow is
       closed); (5) bring-up
       (`coordinator/reconcile/bringup.rs:421`,
       `coordinator/mod.rs:761`) replays detached
       `SyncedSessionEntry` clones, and every queued upsert gains an
       **install acknowledgement**: `handle_upsert_synced`
       (`upsert_synced.rs:64`) returns an outcome per command
       (`Installed` — emitted ONLY after the side-map token is
       inserted, so an ack implies the hold exists — or `Rejected`),
       and each installed entry performs its own verify-and-retain
       (which succeeds because the escrow kept the allocation alive
       and increments the refcount per replica — solving "one linear
       token cannot transfer into every worker replica": the replicas
       retain, the escrow only keeps the allocation alive meanwhile).
       **Persistent-NAT lease migration (v9.9.13, round-28 Codex B3):**
       distinct flows can share ONE persistent source key and
       translated tuple (`source.rs:201`, `allocator.rs:1114, :1224`,
       with the regression test at `tests_pool.rs:2536` confirming),
       and per-flow `reserve_flow(F1,P)` records `persistent_key:
       None`, so `reserve_flow(F2,P)` then fails because P is occupied
       (`allocator.rs:1654, :1682, :1691`) — a per-flow migration of a
       shared persistent lease can never work. The token and the
       migration API therefore carry the persistent KEY, the permit,
       the timeout, and the co-holder semantics: the migration
       transfers the persistent LEASE OBJECT (key, timeout, co-holder
       count) into the target allocator as a unit (the distinct
       persistent address-only API at `allocator.rs:1894` confirms
       lease scope/refcount semantics require separate machinery), and
       each co-holder flow's entry references the migrated lease
       (retaining increments the lease's holder count, not a new
       reservation), so a shared persistent lease migrates atomically
       with all its co-holders intact.
       The escrow's lifetime is UNTIL REPLAY CONSUMPTION BY WHICHEVER
       DATAPLANE COMES UP — new or restored-old (v9.9.8, round-23
       partial's "lose the final NAT holder" trace: reconcile
       ABANDONMENT after teardown means some dataplane must still come
       up and serve traffic; draining the escrow on abandonment would
       free every preserved allocation and kill every preserved NAT'd
       flow mid-connection. The escrow therefore does NOT drain on
       abandonment — it persists until the up-coming dataplane's
       replay consumption is confirmed, exactly as on success; a full
       helper RESTART (as opposed to a reconcile) loses session state
       anyway and is out of scope).
       **Keeper accounting (v9.9.9, round-24 Codex B3 — the durable
       escrow):** the escrow is a coordinator-owned DURABLE
       `NatHoldEscrow` object whose lifetime is INDEPENDENT of command
       permits and of `PreservedReconcileState` (which is consumed by
       bring-up at `reconcile/mod.rs:102, :391`) — it persists across
       reconcile attempts (teardown → bring-up → failure → retry)
       until a dataplane is up AND its replay consumption is
       confirmed, and it drains only when a dataplane is declared
       permanently down (a full helper stop — which loses session
       state anyway and is out of scope) or when that confirmation
       lands. `PreservedReconcileState` merely POINTS at it (the
       post-teardown-failure case at `reconcile/mod.rs:403`, which
       leaves the dataplane down rather than automatically restoring
       old workers, is covered: the next reconcile attempt or operator
       restore consumes the replay through the same escrow, which is
       explicitly coordinator-owned across attempts). Per allocation,
       the escrow holds ONE keeper token from quiesce until
       replay-consumption-confirmed; command outcomes NEVER release it
       (a `Rejected` decrements the allocation's pending COMMAND count
       but never touches the keeper — the keeper is permit-independent);
       when the last outcome lands, the keeper TRANSFERS to the
       replayed entries that retained (or releases if none did — the
       flow failed to reinstall, and freeing is correct); a REJECTED
       replay command additionally performs explicit family cleanup
       (v9.9.12, round-27 Codex B3: shared state
       survives teardown (`coordinator/mod.rs:709`), replay publishes
       once and fans the same entry to EVERY worker
       (`coordinator/mod.rs:770`, `session_glue/mod.rs:838`), and a
       rejected upsert today performs no family cleanup
       (`upsert_synced.rs:64`) — so the pre-published BPF row and
       shared family would linger; a later materialization would see
       stale E1 (`session_glue/mod.rs:1157`), fail its retain, and
       re-resolve — potentially changing the live flow's port. The
       rule: an individual rejection only DECREMENTS the pending count
       (round-26 Codex B3's mixed-outcome trace:
       W0 installs E1, retains its hold, and publishes successfully
       (`upsert_synced.rs:64`); W1 rejects; W1's cleanup carries the
       same incarnation, so alias fencing passes and deletes the
       common family/BPF row underneath W0's live entry). The family
       cleanup (removing the pre-published row and the shared family
       under the alias-token fencing) runs ONLY after the FINAL
       outcome for the complete `(incarnation, allocation, family)`
       COHORT — the forward entry AND its synthesized reverse
       (separate shared entries at `ha/session_import.rs:104`,
       separately snapshotted, pre-published, and fanned out at
       `coordinator/mod.rs:753, :771`) AND any reactive
       materialization through `session_glue/mod.rs:1157` (which is
       NOT counted in replay `installed_count` — a live
       materialized holder must veto the cleanup too); cleanup runs
       only when NO holder exists across the whole family (every
       replay of every family entry rejected AND no live materialized
       entry and no retained hold), serialized with non-replay retain
       (a materialize that commits a hold before the cleanup's
       incarnation check completes takes the family off the cleanup
       list), so a mixed-outcome fanout or a live materialized holder
       can never delete beneath a successfully installed or
       materialized family member). Pending
       commands are claimed-before-executed: a worker CLAIMS a pending
       command before running it, and the barrier converts only
       UNCLAIMED commands to rejections at the deadline; a CLAIMED
       command gets its execution window — BOUNDED by a claim PERMIT
       with expiry AND a single-winner terminal transition at the
       coordinator's pending map (`transition(command, state) ->
       winner`) — a claimed-but-stuck command whose permit expires
       converts `Claimed → Abandoned` THERE (rolling back ITS OWN
       retained hold via the worker's recheck, NEVER the escrow
       keeper), and the late executor's FINAL step before side-map
       insertion is `if pending_map.claim_state(cmd) == Abandoned {
       release the retained hold immediately; abort } else { insert
       side-map; emit Installed }` — a single winner, no split-brain,
       and the abandoned-but-retained case releases AT THE RECHECK
       because the worker is alive to recheck. The terminal-winner-
       before-insertion race (a worker panic before insertion drops
       its retained token during unwind, `supervisor.rs:98`) is safe
       because the ESCROW KEEPER still holds the allocation (refcount
       ≥ 1) until replay consumption is confirmed — the worker's
       retained-but-never-installed hold releases via RAII (correct —
       the entry never installed), and the port survives for the next
       attempt. The RAII drop DISARMS the permit expiration timer at
       drop time (round-22 AGY: without disarming, a worker that
       claims, retains, and dies before the recheck would fire BOTH
       the RAII drop (releasing the hold) AND the later permit expiry
       (releasing the pending slot again) — a double-release racing
       subsequent allocations; the permit timer is cancelled when the
       token's RAII drop fires, and the permit expiry fires only for
       tokens still live at expiry). The residual pinning
       where RAII cannot run is bounded by worker lifetime; the
       supervisor's panic-only death marking at `supervisor.rs:95` /
       `worker_runtime.rs:239` covers the unwind case. A genuinely
       dead worker's commands convert on worker DEATH
       (`supervisor.rs:80, :95-98`, panic-only at
       `worker_runtime.rs:239`), and the supervisor's join blocking at
       `worker_manager.rs:146` is then irrelevant to keeper release. `Installed` is emitted only after the side-map
       token is inserted, and unlaunched-worker queues get EXPLICIT
       rejections (their queued commands contain no hold token yet,
       `runtime.rs:408` — replay queues carry pending-outcome
       tickets); reconcile ABANDONMENT does NOT drain the escrow —
       it persists until a dataplane (new or restored-old) confirms
       replay consumption, draining only on a declared permanent
       dataplane stop or on that confirmation (v9.9.9's durable-escrow
       rule — this line supersedes the older drain-on-abandonment
       phrasing); reconcile
       can never stall on a permanently absent acknowledgement
       (workers report READY before consuming commands,
       `loop_body/mod.rs:150, :682`, and launched workers retain the
       queue-map `Arc`, `bringup.rs:598`). The
       BPF-before-consume ordering at `coordinator/mod.rs:771` is
       covered by the alias-token fencing (external deletes re-check
       the alias at delete time). The token itself is an owned, LINEAR `NatHoldToken`
       (v9.9.12, round-27 Codex H5): it owns the exact allocator HANDLE
       (`Arc<PortAllocator>`, `allocator.rs:742` — `SourceNatRule` has
       no stable allocator identifier, `source.rs:251`, and allocators
       are shared/reused by pool configuration, `source.rs:327, :726`),
       AND it carries the allocation's COLLISION DOMAIN (the pool's
       address space at retain time) so allocator changes migrate
       safely: the `SourceNatPoolAllocatorKey` includes `pool_name`
       (`source.rs:327`) and allocator reuse requires exact-key
       equality (`source.rs:726`), so a name-only rename creates
       allocator B while E1 remains held only in A — B may then assign
       E1's public tuple to another flow, and re-resolving E1 may swap
       its pool port mid-connection. AND the migration covers the
       IN-PLACE REFRESH path, not just restore (v9.9.13, round-28
       Codex B2: NAT configuration is ABSENT from the binding-plan
       key (`server/helpers/planning.rs:85`), so a healthy rename
       takes the in-place refresh path (`server/handlers/snapshot.rs:163,
       :239`) and publishes new forwarding WITHOUT replay/restore
       (`afxdp/coordinator/snapshot_refresh.rs:212, :319, :397`) —
       because the allocator key includes `pool_name` and reuse is
       exact-key only (`source.rs:327, :726`), B starts with an empty
       bitmap and can issue E1's tuple to E2 (`allocator.rs:595,
       :999`), and the repository identifies identical tuples from
       independent allocators as reverse-NAT misdelivery
       (`pkg/config/compiler_tailgates.go:212`). The rule: the refresh
       path DETECTS allocator changes (allocator key or collision
       domain) and either MIGRATES in place WITH A CUTOVER FENCE
       (v9.9.14, round-29 Codex B1: today allocator B is built while
       A remains worker-visible (`afxdp/coordinator/snapshot_refresh.rs:212`),
       B is published later at `:397`, and workers retain A until their
       per-loop Arc refresh (`worker/loop_body/mod.rs:467`) — so a
       worker still holding A can admit E1 and claim P AFTER the
       migration snapshot through the live allocation path
       (`allocator.rs:999`), B is published WITHOUT P, and E2 then
       claims P in B; independent allocator bitmaps issuing the same
       tuple produce the documented reverse-NAT misdelivery
       (`pkg/config/compiler_tailgates.go:212`). The fence: the
       migration FREEZES A's allocation path at snapshot time
       (allocator-level: A's `allocate_translation` returns a
       transient error or redirects to B during the window;
       already-committed in-flight allocations are fine), migrates
       the retained tuples into B, THEN publishes B — so no worker
       can still allocate through A after the migration snapshot.
       Alternatively the dual-write bridge: during the migration
       window, allocations through A are also reserved in B, with an
       acknowledgement that no worker can still allocate through A
       after the cutover) or forces the quiesced reconcile path (which has the
       escrow); a collision-domain-compatible change migrates in
       place; an incompatible change forces the reconcile). The rule
       for the reconcile/restore path itself: on a config change
       whose pool collision domain is COMPATIBLE (same address space,
       regardless of name), the restore path MIGRATES E1's exact
       reservation — PAT, NAT64 (`nat64.rs:915`), and address-only
       alike — into every compatible current allocator BEFORE
       releasing A's hold (via `reserve_flow` / `reserve_address_only`,
       confirmed available per round-27 AGY), so B can never assign
       E1's public tuple elsewhere (`source.rs:829`,
       `allocator.rs:1617`'s collision is thereby prevented
       structurally, not just detected); on a config change that
       shrinks or replaces the collision domain incompatibly, the
       escrow tokens for the old domain are invalidated at restore
       time — the verify-and-retain fails cleanly and the flow
       re-resolves, which is semantically REQUIRED because the
       translation changed; the escrow's job is to preserve flows
       whose collision domain is compatible),
       the flow tuple, the expected translation, and the allocation
       KIND (SNAT / NAT64 — the NAT64 allocator's equivalent identity
       scheme at `nat64.rs:915` — / address-only). It lives in a
       PER-WORKER SIDE MAP (entry handle → token) so `SessionEntry`
       does NOT grow (the 56 B claim stands); RAII semantics: `Drop`
       releases the hold unless the token was defused by an explicit
       `take()`/transfer — so exceptional destruction is covered too
       (a worker panic unwinds and drops the side map before the
       supervisor catches it, `supervisor.rs:80`: every token's `Drop`
       fires, decrementing refcounts correctly; queue rejection/drop
       and unlaunched-worker queues use the same RAII path). Every
       removal path takes() the token exactly once and either
       releases or transfers it:
       reap (via `ExpiredSession`), `remove_entry` returns,
       fresh-install replacement (`install.rs:139`), explicit
       deletion (`install.rs:538`), synced-upsert replacement
       (`install.rs:322` — transfer), `take_synced_local`
       (`lookup.rs:407`), scoped one-shot guards, the reconcile
       escrow above, and the worker drain. A concurrent same-entry
       reap is NOT a hazard (`SessionTable` is worker-owned and
       single-threaded, `session/mod.rs:429`); the contract is
       exactly-once consumption across every path. Its reap decrements
       the holder count
       REGARDLESS of origin (the retain is per-entry), and the
       allocation frees only at refcount zero. **That refcount IS
       #6522's machinery — this plan now includes it as a Part-B
       requirement** (it also fixes the premature-release class
       directly: the sibling replica's reap decrements its holder,
       the live owner's stays, the port survives until the last
       holder reaps; the v9.4 locally-born-only release rule is
       superseded by the refcount, which is the general form).
       Address-only flows retain identically (compare the requested
       translated IP, `allocator.rs:1748` today returns the same-flow
       allocation without comparing). A stale E1 decision whose
       translation no longer matches is DISCARDED with a re-resolve
       (and on retain failure the entry is never installed, so no
       holder leaks); an E2 whose translation is identical to E1's is
       the SAME NAT decision and commits correctly (retain succeeds).
       On any failure the packet re-resolves through the normal path
       (never installs or forwards on a stale clone).
       **Uniform incarnation fencing for every local Close mutation
       (v9.2, round-13 Codex B1):** a stale E1 Close can otherwise
       erase replacement E2 locally — the worker reaps E1, queues the
       Close (`loop_body/mod.rs:811`), processes packets that install
       same-key E2 (`:887`), then drains the stale Close (`:970`) —
       which today key-deletes queued traffic, BPF/conntrack/DNAT
       state, current shared aliases, and peer replicas
       (`session_delta.rs:84, :406`, `shared_ops.rs:960`). Every local
       mutation driven by a Close delta becomes incarnation-conditional
       on the delta's `flow_incarnation_id` (queued packet drops are
       tuple-scoped and safe; state deletes compare first).
       (d) **Reap-side release via the holder refcount (v9.5 —
       supersedes the v9.4 locally-born-only rule):**
       locally-born forwards replicate to every sibling worker
       (`poll_descriptor/mod.rs:2560`, `session_glue/mod.rs:838`), and
       every expired forward unconditionally calls release
       (`loop_body/mod.rs:1481`), while the allocation has NO replica
       refcount (`nat/allocator.rs:1318, :1664`) — an unobserving
       sibling's AGE-reap can therefore release the live worker's
       shared allocation TODAY, on master, independent of this plan
       (the pre-existing premature-release bug this plan's holder
       refcount fixes as Part B — **filed as #6522** for tracking,
       since master has it today independent of this plan). The rule:
       every entry carrying a NAT hold releases it at reap and the
       allocation frees only at refcount zero — the #6522 machinery
       shipped as Part B (the forward entry's original reserve counts
       as the first holder; replicas/materializes/synths retain at
       commit per the verify-and-retain above; each reap decrements;
       the sibling replica's reap no longer frees the live owner's
       port, and the re-steering edge (two locally-born entries for
       one flow) is also covered by the refcount). `ExpiredSession` gains the
       entry's `flow_incarnation_id` (`entry.rs:337` lacks it today),
       and every EXTERNAL-map mutation is fenced by the canonical
       shared alias AS THE INCARNATION TOKEN (v9.6, round-15 Codex B1:
       the conntrack values are exact 136/184-byte C mirrors whose
       padding is 1/2/4-byte alignment gaps, not a spare u64
       (`xpf_conntrack.h:17, :82`, `bpf_session_value.go:5, :39, :59`),
       the redirect map stores a u8 action, and DNAT values lack any
       incarnation — so no map-ABI field is possible without a shim
       change this plan forbids; the canonical shared alias already
       carries the id and IS the sidecar). **Ownership rule (v9.8,
       round-17 Codex B2):** ALL session-related external-map
       mutations — create or delete, on the redirect, conntrack, DNAT,
       and canonical session maps — are HELPER-OWNED under the
       canonical alias lock; the Go side NEVER deletes session-map
       state directly for closes (a delayed E1 Close otherwise races
       Rust committing same-key E2, and Go's `DeleteWithCompanionsV4`
       reads E2's current BPF value and deletes the derived DNAT
       record before the helper can compare the E2 alias,
       `session_store.go:391, :537` — retired for session closes; Go
       routes the Close to the helper, which performs the fenced
       transaction; Go's direct map writes are confined to paths where
       no fencing is needed, e.g. quiesced full-table rebuilds at
       bring-up, and `manager_ha.go:1771`'s mutex-drop during helper
       IPC becomes irrelevant because the fence lives entirely in the
       helper). **Conditional control-plane selection is HELPER-AUTHORITATIVE with
       TEMPORAL CUTS (v9.9.4, round-19 Codex B1 + round-20 Codex B1):
       the named selectors receive only BPF `Key + SessionValue` whose
       fixed ABI omits the identity fields (`maps_session.go:225`,
       `bpf_session_value.go:31`), so capturing the incarnation at
       selection through the BPF-only API is impossible — and a
       HELPER-side current-state selection is still wrong for
       HISTORICAL predicates:** Go submits the filter/predicate to the
       helper, and the HELPER selects matching entries from its own
       shared aliases (which carry `flow_incarnation_id`), captures
       the selected identities atomically under the canonical lock,
       and deletes under the alias-token fencing in one transaction —
       the incarnation never leaves the helper, so the
       select→replace→delete race has no window. The three predicate
       classes get their correct temporal semantics: (a) **policy
       invalidation** (`daemon_policy_invalidate.go:311 → :357`, which
       runs AFTER the new policy snapshot activates,
       `daemon_apply_commit.go:245, :256-270`, and targets OLD numeric
       policy IDs, `daemon_policy_invalidate.go:129, :160-168,
       :261-266` — which can collide with a different NEW policy,
       `policies_ids.go:60`): the selection is cut by a CONFIG EPOCH
       (a monotonic counter bumped per commit; entries stamp their
       admission epoch at install; the invalidation predicate selects on the STABLE ADMITTING-RULE
       identity and the forwarding generation carried in the SAME
       immutable policy snapshot (v9.9.5, round-21 Codex B1 — numeric
       policy IDs are POSITIONAL and collide across configurations,
       `policies_ids.go:52`, `session/README.md:876`: C1 inserting B
       before A renumbers A's old ID to B while the existing alias
       retains the number (policy re-resolution updates only the BPF
       row, `bpf_map/mod.rs:384`), so `(old numeric ID,
       admission_epoch < activation)` would delete still-permitted
       flows of the displaced policy A when B is later deleted
       (`daemon_policy_invalidate.go:62`). The rule: entries stamp the
       admitting rule's STABLE LOGICAL identity (the
       `<from>-><to>/<name>` triple, `policies_ids.go:101` —
       position-independent and same-content-different-name safe:
       distinct P1 with identical content C inserted ahead of P2 gets
       `<from>-><to>/P1` while P2 keeps `<from>-><to>/P2`, so deleting
       P1 later can never select P2's flow — the content-addressed
       rule hash supplement from earlier drafts was superseded in
       v9.9.9 because a content-only identity cross-selects
       same-content rules) plus the immutable forwarding generation
       at install; the invalidation predicate selects only entries
       whose stamped stable rule identity is in the deleted set AND
       whose stamped forwarding generation is BEFORE the invalidated
       snapshot's generation — and because selection keys on the
       FORWARDING generation (the snapshot that actually carries
       policy), the split publication race (coordinator stores
       validation then forwarding at `snapshot_refresh.rs:397`;
       workers load validation then forwarding at `loop_body/mod.rs:462`
       — a worker can admit under new policy while stamping old
       validation) is closed: the stamp and the admission both come
       from the same immutable forwarding snapshot. A usable monotonic
       generation exists today (`manager_generation.go:33`, published
       through `ValidationState` at `snapshot_refresh.rs:397`, and
       the stamp is a NEW write-once
       `admission_config_version: u64` field — NOT `install_epoch`
       (round-21 AGY's suggestion of `session/mod.rs:348` is corrected:
       `install_epoch` is a worker-local MUTATION counter rewritten on
       update and promotion, `session/mod.rs:761, :1384`, so it is NOT
       the admission generation; the write-once field is stamped once
       at entry creation and never rewritten) — and the stamped value
       is the AUTHORITY-ISSUED CONFIG EPOCH (v9.9.13, round-28
       Codex B1 — `configGenCounter` (`pkg/cluster/sync_conn_config.go:222`)
       is NOT sufficient as-is: A publishes C2, performs invalidation,
       and only then pushes it (`daemon_apply_commit.go:245, 270, 274`),
       while `QueueConfig` first allocates `g+1` at send time
       (`sync_conn_config.go:234`), so an E2 admitted under a
       still-permitting modified policy after C2 activates can only
       stamp old `g`; cutoff `g+1` falsely selects and identity-deletes
       E2, while cutoff `g` retains C1/E1; unchanged reconnect
       re-pushes allocate another generation
       (`configsync_reconcile_5863_test.go:171`), and the receiver
       skips rebuilding equal text (`daemon_ha_sync.go:549`) but
       advances its high-water (`sync_conn_config.go:389`), causing
       current-config installs to fail `epoch < barrier`
       (`sync_conn_gen.go:424`); and repository tests explicitly
       define this as a directional sender namespace, with a future
       authority's counter remaining frozen
       (`sync_config_epoch_active_active_6284_test.go:12, 90`). The
       rule: the config authority RESERVES the epoch BEFORE LOCAL
       APPLY (the new generation is allocated at apply time, not at
       send time — the epoch and the config it names are committed
       together, so invalidation never precedes publication), the
       same epoch is REUSED on every resend (never re-allocated per
       send), and on authority transition the new authority ADOPTS
       `max(own, received)` as its counter floor (so the counter is
       cluster-monotonic across failovers even though it is
       authority-namespaced). The version is carried through
       config apply (the receiver callback at `daemon_ha_sync.go:910`
       currently passes only config text, not that generation — it
       must also capture and store the generation) and rides
       `ForwardingState` (which gains it —
       `types/forwarding.rs:33` has none today; the compiler stamps
       the config-sync generation the snapshot was built from, so the
       version and the policy it carries are published atomically
       together, closing the old-validation/new-forwarding observation
       race at `snapshot_refresh.rs:397` and `loop_body/mod.rs:462`),
       and the invalidation cutoff is the invalidated config's
       config-sync generation (the same cluster-ordered value on every
       node), and BOTH selector fields (`stable_rule_id_hash`,
       `admission_config_version`) are stamped into local, shared, AND
       imported entries with their install/import carriage defined
       (installed entries stamp at creation from the config-sync
       generation the admitting snapshot was built from; imported
       entries inherit the sender's stamp via the same additive install
       tail that carries the incarnation — and because both are the
       authority-issued config-sync generation, A's stamp and B's
       cutoff are ordered correctly); (b) **cluster-bulk cleanup**
       (`sync.go:1069, :1080-1126` — BulkStart-snapshot-driven, with a
       secondary→primary ownership flip expressly permitted mid-bulk,
       `sync_test.go:1535, :1573-1585`): the delete re-validates the
       CANDIDATE CLASS at commit time (the entry is still peer-owned
       AND still locally absent at the moment of deletion) — a
       locally authoritative E2 committed after the flip fails the
       re-validation and is skipped, even though it satisfied the old
       snapshot predicate; (c) **filtered administrative clearing**
       (`grpcapi/server_sessions.go:1234`): current-state selection is
       CORRECT by intent (the operator means "delete whatever matches
       — but CHUNKED via an explicit
       STABLE CURSOR (v9.9.9, round-22 partial + round-24 Codex 5: the
       Go implementation relies on BPF `GET_NEXT_KEY` as a live anchor
       (`server_sessions.go:1298`), which does NOT translate to the
       helper's authoritative tables — single `Mutex<FxHashMap<…>>`
       values (`coordinator/session_manager.rs:12`, `types/mod.rs:37`)
       whose `SessionKey` has NO ordering (`session/key.rs:9`); a naive
       release-and-rescan is O(N²), retaining the iterator holds the
       global lock across the full clear, and collecting/sorting is
       O(N) memory): the shared session map gains an INSERTION-ORDERED
       SECONDARY INDEX (ordered by a COORDINATOR-GLOBAL immutable
       insertion sequence — a u64 seqno allocated by an `AtomicU64`
       fetch_add INSIDE the map's insertion lock span (v9.9.10.1,
       round-26 AGY's cursor-safety catch: allocating the seqno OUTSIDE
       the lock lets out-of-order lock acquisition insert seq 101
       before seq 100, and a cursor advancing to 101 permanently skips
       the late-inserted 100 in subsequent `seqno > cursor` scans;
       allocating inside the insertion lock guarantees monotonic
       cursor safety — alternatively per-map seqnos, also allocated
       inside that map's lock; the seqno is already unique per
       allocation, so no tiebreak is needed — round-27 Codex LOW);
       v9.9.10,
       round-25 Codex M5: `(install_epoch,
       key)` is unusable because `install_epoch` is per-worker and
       mutable (`session/mod.rs:761, :1384`) and `SessionKey` has no
       order (`session/key.rs:9`). The index lives under the CANONICAL
       shared map's OWN mutex — each shared map has its own mutex
       (`coordinator/session_manager.rs:12`), so the index for map M
       is maintained inside M's lock, and the documented family lock
       order (canonical → NAT → wire → indexes) governs cross-map
       transactions; the owner-index update at `shared_ops.rs:897` is
       one of those separate locks and follows the same order). The
       scan uses an EXCLUSIVE range cursor (entries with seqno >
       cursor), with a scan-start high-watermark (entries inserted
       after the watermark are next pass's work — the sweep is
       periodic, so stragglers are covered next cycle); replacement
       preserves the original seqno (upserts update the entry in
       place keeping its seqno; a true remove+insert gets a new
       seqno),
       and the scan iterates the INDEX with a cursor position, taking
       the lock per ≤1,024-entry chunk, advancing, releasing, and
       resuming from the cursor position — O(N) total with bounded
       per-chunk lock holds, and inserts/deletes update the index
       under the same lock so the cursor never observes an
       inconsistent map.,
       with each chunk its own canonical-lock span and per-chunk
       candidate re-validation at delete. The HA continuation is
       handled node-locally first (v9.9.4): BOTH nodes run the same
       policy-invalidation pass independently (the config authority
       invalidates at `daemon_apply_commit.go:245`, and the receiving
       secondary retains `oldActive` and performs the same clear at
       `daemon_apply_commit.go:326` — each node deletes its own E1s
       with the carried identity, so the common case needs NO
       propagated delete and NO wire change (round-20 Codex B2's
       contradiction between the identity fence and the no-wire
       requirement dissolves for this case). **Where propagation does
       happen it is per-entry-owner-gated (v9.9.5, round-21 Codex B3):
       today owning ANY RG enables delete sync for EVERY matched
       forward entry (`daemon_policy_invalidate.go:294, :366`) — a
       node owning RG1 can clear a peer-owned RG2 E1 and propagate
       that delete to an old peer currently owning RG2 with
       replacement E2; the sender never installed that peer-owned E1,
       so `takeDeleteGen` returns zero (`sync_conn_gen.go:176`) and
       the gen-zero delete applies unconditionally
       (`sync_conn_gen.go:263`), deleting the AUTHORITATIVE E2 and its
       NAT companions (`session_store.go:537`). The rule: an
       invalidation delete sync is emitted only for entries whose
       `owner_rg_id` the SENDER currently owns (per-entry owner gate);
       a peer-owned E1 is deleted only by its owner's own pass (which
       runs on both nodes, above). For the residual
       propagation still needed (asymmetric invalidation timing, where
       one node's standby entries outlive the other's pass), the
       session DELETE delta gains a small ADDITIVE identity tail
       `{(origin_process_nonce, flow_incarnation_id)}` — the wire
       framing tolerates trailing length-gated fields
       (`sync_protocol.go:95-102, :470-497`), so this is rolling-gated
       with an explicit honest statement: Part A has NO wire change;
       Part B adds the additive delete tail, and a mixed-version pair
       keeps today's gen-based unconditional delete on the old peer
       (the documented mixed-version behavior — and the stronger rule
       (v9.9.10, round-24 Codex B1 + round-25 Codex B1): a new sender
       SUPPRESSES EVERY incarnation-dependent delete — invalidation/
       conditional deletes AND plain Close deltas — toward a peer that
       has not negotiated identity enforcement. A Close is
       incarnation-dependent by CONSTRUCTION (it is about the sender's
       own incarnation I1; the legacy receiver's key-based application
       cannot distinguish E1 from a re-seeded E2 sharing the tuple:
       during dual-primary overlap, legacy B replaces E1 with
       authoritative same-key E2; new A later emits E1's legitimate
       (or documented in-window blind) Close; A's local owner view
       passes (`daemon_ha_userspace_stream.go:28`); the Close enters
       the key-only delete path (`:393`); legacy B ignores the
       identity tail, reads only generation (`sync_conn_read.go:150`),
       accepts A's fresh/non-stale generation (`sync_conn_gen.go:263`),
       and key-deletes current E2 and its NAT companions
       (`sync_conn_gen.go:493`, `session_store.go:537`) — the exact
       HA-propagated authoritative kill this issue forbids). The rule:
       an identity-dependent delete (Close, invalidation, or
       conditional) is emitted ONLY to a peer that has negotiated
       enforcement — and the negotiation is per-CONNECTION and checked
       at EVERY write/replay (v9.9.11, round-26 Codex B2: deletes are
       opaque `[]byte` queue/journal entries (`sync.go:467`,
       `sync_conn_write.go:114`), and `sendLoop` retries an
       already-dequeued frame on whichever connection becomes active
       WITHOUT a send-time capability check (`sync_conn_write.go:268`)
       — so an E1 Close admitted while B was capable can cross after B
       reconnects as legacy and installs authoritative same-key E2,
       and legacy B ignores identity and key-deletes E2 and its NAT
       companions. The rule: every queued frame is tagged
       `requires_identity_enforcement` (Close/invalidation/conditional
       delete frames) or not; the frame is written or replayed ONLY on
       a connection whose negotiated capabilities include enforcement,
       and DROPPED (not retried) on any connection that lacks it — so
       a capability downgrade between dequeue and write can never
       carry an identity-dependent delete across. The capability
       exchange runs on EVERY connection type (round-26 Codex B2's
       second gap: the cited handshake at `sync_auth.go:321, :345`
       carries no feature set and runs only when a PSK is configured —
       the version/feature-flag exchange is made connection-type-
       independent (a lightweight capabilities word in every
       connection's hello), and unnegotiated legacy peers (raw frames
       or `keyed=0`) never receive identity-dependent deletes); to an
       unnegotiated peer, NO
       incarnation-dependent delete is sent at all — the legacy peer
       cleans up its own E1 standby via its own aging, invalidation
       pass (both nodes run it, per v9.9.5), and TTL-sweep machinery
       (master's pre-existing behavior, documented) — and plain
       owner-validated Close deltas are SUPPRESSED toward the legacy
       peer too (v9.9.10+: a Close is incarnation-dependent by
       construction — the legacy receiver's key-based application
       cannot distinguish E1 from a re-seeded E2 sharing the tuple
       (legacy B replaces E1 with authoritative same-key E2; new A
       sends E1's Close; B ignores the identity, accepts the
       generation at `sync_conn_gen.go:263, :282`, and key-deletes E2
       plus companions at `sync_conn_gen.go:493`), so suppressing it
       is the only safe posture). **Mixed-version
       bulk reconciliation is suppressed entirely (v9.9.13, round-28
       Codex B4):** a reconnect unconditionally sends authoritative
       bulk (`sync_conn.go:138, :194`), and its markers and installs
       are direct writes outside the tagged queue
       (`sync_bulk.go:81, :105, :183`) — the implicit delete channel:
       new A suppresses E1's Close to legacy B, then reconnects with
       E1 absent; B snapshots secondary ownership at `BulkStart`
       (`sync_conn_read.go:183, :196`), flips primary and installs
       same-key E2 — a supported mid-bulk transition
       (`sync_test.go:1535, :1573`); `BulkEnd` invokes legacy
       reconciliation (`sync_conn_read.go:240`), which uses frozen
       ownership and selects the absent key (`sync.go:1080, :1114`);
       the legacy store deletes current E2 and its NAT/reverse
       companions (`session_store.go:626, :644, :399`). The plan's
       receiver-side revalidation cannot retrofit legacy B, so the
       rule: on an unnegotiated connection the sender sends bulk as
       INSTALL-ONLY PRIMING (no reconciliation pass — the receiver's
       stale entries are left to its own aging/invalidation/sweep
       machinery); reconciliation (the delete-stale-entries step) runs
       only on negotiated connections. The mixed-version
       POLICY-INVALIDATION window gets an explicit operational gate
       (v9.9.12, round-27 Codex H6: the legacy binary publishes the
       new policy BEFORE clearing old sessions
       (`daemon_apply_commit.go:245`) and selects only by reused
       numeric `PolicyID` (`daemon_policy_invalidate.go:311`) — during
       that window, a surviving rule can inherit a deleted rule's
       numeric slot and admit E2, and the old pass selects E2 as
       belonging to the deleted rule and companion-deletes it
       (`session_store.go:391`); capability negotiation cannot retrofit
       the stable selector into an old binary. The gate: during a
       mixed-version pair (capability unnegotiated), the NEW node
       suppresses its own policy-invalidation pass entirely (no
       invalidation happens on the new node during the window), and
       the operator guidance is to sequence policy deletions outside
       mixed-version windows (which are brief during rolling
       upgrades); the residual — the legacy node's own local pass
       mis-selecting E2 during that window — is an explicitly accepted
       risk, documented, and bounded by the per-entry owner gate on
       propagation (v9.9.5: the NEW node never propagates invalidation
       deletes for peer-owned entries during the window, limiting the
       kill surface to the legacy node's own local pass). A legacy receiver
       decodes only the generation (`sync_conn_read.go:150`) and
       applies gen-based deletes unconditionally (`sync_conn_gen.go:263`),
       so suppression is the only safe posture toward it); the receiver applies an identity-carrying
       delete only when its stored incarnation matches. Only
       deliberately unconditional administrative clears ("delete
       everything regardless") keep separate, unconditional semantics
       and are documented as such. **Per-operation span (normative, v9.8):** every
       external mutation is its own transaction — canonical lock →
       re-read the EXACT SOURCE ALIAS for the key being mutated (the
       derived key's own alias record, not just the canonical family —
       a different-forward E2 can displace E1's derived alias
       independently, `shared_ops.rs:918`) → one syscall → unlock;
       no initial alias win is ever cached as authorization for a
       later syscall. WRITES are last-writer-wins driven by live
       traffic — E2's publish is never blocked by E1's stale slot
       (round-15 Codex B1's E2-rejection defect); the write's own
       commit-time verify-and-retain already established that the
       writer is live. The E1-lookup→E2-overwrite→E1-delete race
       (`publish_conntrack.rs:142`'s BPF_ANY write vs
       `bpf_map/mod.rs:321`'s key-only delete) is closed: E1's delete
       re-reads the exact alias in the same syscall span and finds E2.
       No shim/meta change, no `make generate`. Tuple-scoped
       queued-frame cancellation stays unconditional (bounded packet
       loss only, safe).
       No Close producer is required; staleness is bounded. (The
       Go-side floor already exists — `pkg/conntrack` GC with HA
       delete-sync callbacks.)
     - **One flow incarnation, end to end (v8.4, round-11 Codex 7):**
       every entry, replica, and alias gains `flow_incarnation_id: u64`,
       SEPARATE from the RT_FLOW `session_id` (#4915 per-worker
       correlation ids are untouched). Minting authority is the
       FORWARD entry only: locally-born flows stamp the alias with the
       forward mint at publication (today id 0,
       `poll_descriptor/mod.rs:2560`); the reverse entry and its
       publication INHERIT the forward's id (the reverse synth and
       fabric/tunnel constructors all hold a forward match in hand —
       it carries the id; today the primary reverse publication
       carries zero, `poll_descriptor/mod.rs:2897`); worker replicas
       inherit from the alias/wire at materialize/install instead of
       minting from zero; HA coordinator imports mint ONCE before
       fanout (`session_import.rs:115` publishes before cloning —
       round-9 AGY 2's per-worker divergence dies). `DeleteSynced`
       becomes incarnation-conditional (today key-only,
       `session_glue/mod.rs:851` → `delete_synced.rs:9`: a delayed E1
       cleanup can kill replacement E2) — the command carries the
       expected id and deletes only on match. The Close delta carries
       `(origin_process_nonce, flow_incarnation_id)` end to end
       (additive fields on `SessionDelta` + the event codec + the Go
       decoder — today the codec drops both, `session_sync.rs:215`,
       `entry.rs:283`). The **fence tuple is
       `(origin_process_nonce, flow_incarnation_id)`** — a RANDOM
       per-boot process nonce (the `heartbeat.go:624` precedent,
       retained from the wire import alongside the id) plus the
       incarnation id; the node identity comes from the connection
       the Close arrives on (no separate node_id field — round-10
       Codex 8's tuple inconsistency dies). Go close processing
       (`daemon_ha_userspace_stream.go:393`) applies the delete only
       when the store's tuple matches; the store learns the tuple
       from the sync payload (and Phase 2's sidecar for the fields
       the BPF ABI drops, `bpf_session_value.go:204`). Phase 1 keeps
       master's unconditional gen-zero behavior for id-less entries
       (the mark→reap vs re-seed race is master's existing exposure,
       documented). A refused (out-of-window or no-baseline) close
       remains inert (no mark, no
       refresh, no accelerated reap). The close packet itself
       forwards on the current decision; packet-driven promotion
       still exists for entries imported after activation and still
       skips closing packets.
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
Consequence is deliberately NARROW: leg 2 (the restart-RST leg)
consults `ack_hi(O)` and stalls; leg 3 (the close's own ack against
`seq_hi(O)`) is unavailable DURING an unresolved hole (the ack lag
exceeds the bound) and recovers after repair (round-7 Codex 9); leg 1
(`seq_hi`) is unaffected throughout (the firewall forwards the data, so
retransmits arrive in-window). A restart-RST or abort-during-hole on
such a stalled flow soft-refuses and the entry idles out on its
ordinary timeout — table pressure only. **wscale tracking is rejected again**: a gate wide enough
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
all three legs is honestly stated in §2 (worst disjoint
655,355 ≈ 1/6,554 at the cap; 393,219 ≈ 1/10,923 at the floor):

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
     residual: delivery unaffected, entry idles out). **Loss-episode
     nuance (round-7 Codex 9):** while a loss hole is outstanding, D's
     cumulative ack can lag `seq_hi(O)` by the whole buffered extent
     (megabytes with scaling) — an abort DURING the hole can miss leg 3
     (soft-refuse, table retention only); legs 1/3 recover after the
     repair. Do not read "loss-immune" as "loss-proof during the
     hole".
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
   (debug-build panic on wrap, round-1 Codex B3). Per-leg compile-time
   asserts (round-7 Codex 10): `const _: () = assert!(BACK_SLACK + 2 * u16::MAX as usize + 1 < (1 << 31))`
   for the seq legs (196,607 max) AND
   `const _: () = assert!(2 * (2 * u16::MAX as usize) + 1 < (1 << 31))`
   for the symmetric own-ack leg (262,141 max); the union probability is
   stated in §2 (worst 655,355 ≈ 1/6,554).

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
   `established`, run §5.4. An accepted mark applies the FULL mark
   semantics atomically (v9.2, round-13 Codex M8): sticky `closing`/
   `reset` with `reset` set BEFORE the timeout recomputation, the
   `expires_after_ns` recompute, the `last_seen_ns` refresh, and the
   wheel push — on the matched entry and, at the reverse-synth accept
   site, on the forward family in hand (so the forward emits at its
   2 s reap; §5.6).
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
non-closing promoting packet's OWNERSHIP promote is computed at resolve
but APPLIED at the packet's commit arm (v9.6, round-15 Codex B2 —
uniform with the establishment promote: today
`maybe_promote_synced_session` flips origin, refreshes, republishes,
replicates, and emits Open at RESOLVE time, before input filters and
the TTL check at `poll_descriptor/mod.rs:846`, so an undelivered
packet would stamp ownership/refresh/Open state; at the commit arm
only delivered packets do). **Probation entries additionally SUPPRESS
ownership promotion, Open emission, replication, and every family-clock
stamp until a committed non-close packet clears the flag** (round-15/16
Codex's two-packet chain, resolved precisely: refused close →
probation zombie; a blind non-close that is FILTERED/TTL-dropped
neither promotes nor refreshes anything (the commit arm never runs);
a blind non-close that COMMITS clears the flag and may promote
exactly once — and that is not a kill: the promote sets no close
mark, retains the NAT decision, and refreshes/recomputes only the
ORDINARY established idle timeout (`session/mod.rs:1397, :1430`), so
any Close is emitted only at normal inactivity expiry of an entry
that is genuinely idle — correct cluster hygiene (Junos reaps idle
flows too), with any retention effect bounded by the attacker's
spray budget (the documented poisoned-anchor residual class).

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

- **Accept** → install with `closing`/`reset` seeded as today, AND
  the mark is applied to the FORWARD family atomically in the same
  resolve (v9, round-12 Codex 10: v8.x marked only the reverse entry —
  `is_reverse`-silent — leaving zero producers when the forward was an
  unmarked import and no later packet arrived; the forward match is in
  hand at this site, so the forward entry/import is marked at accept
  time, giving exactly one producer on the owner's forward entry).
  Stated honestly per round-2 Codex 8: #4380 companion retention
  (`expire.rs:318`, `companion_keeps_alive`) defers the reverse's 2 s
  reap while the forward companion is live (≤ the 20 s opening window
  for a half-open forward); the test plan (§9) asserts THESE
  semantics, not an idealized 2 s whole-flow reap.
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
but at the PROBATIONARY opening-window timeout (v9.2, round-13 Codex
H7: a full-timeout alive install lets an attacker renew an obsolete
non-NAT permit indefinitely with periodic blind closes — each
materialize stamps the family clock and each zombie lives 300 s;
probation bounds the zombie to 20 s and the sustain cost to
1 packet/20 s), and a closing-flagged materialize does NOT stamp the
family clock (only committed non-close packets and non-close events
stamp). The probation entry carries an explicit `probation: bool`
(v9.4, round-14 Codex H4: construction necessarily sets
`last_seen_ns = now` at `install.rs:345`, so the generic 30 s push
would otherwise cover the probationary entry — stamping the family
with the 20 s probation timeout and potentially SHORTENING a live
established sibling's horizon from K × 300 s to K × 20 s): the push
SKIPS probation entries until a committed non-close packet clears
the flag, and the push NEVER lowers a family's `expires_after_ns`
(it stores `max(stored, pushed)` — the family timeout is monotone
non-decreasing). Unlike site 2b the install cannot be skipped — the packet
needs its decision and the entry must own the flow —
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

**Wire schema (normative, consolidated — v9.9.14):**
The session INSTALL/Open delta carries the additive identity tail
`{(origin_process_nonce, flow_incarnation_id, stable_rule_id_hash,
admission_config_version)}` (v9.9.14, round-29 Codex H4: the main
design requires imported entries to inherit `stable_rule_id_hash` and
`admission_config_version` through the INSTALL tail, and they cannot
be reconstructed from the BPF projection (`bpf_session_value.go:168`),
whose positional policy ID is rewritten across policy reorder
(`bpf_map/mod.rs:384`) — a §5.8 implementation without them retains
the numeric-ID selection at `daemon_policy_invalidate.go:311` where a
surviving rule's E2 can alias a deleted rule's old position and be
companion-deleted through `session_store.go:391`); the session DELETE
delta carries `{(origin_process_nonce, flow_incarnation_id)}`.
The sender/receiver store lifecycle: the Go sidecar synced store gains
`(origin_process_nonce, flow_incarnation_id, row_version)` per entry,
learned from the install delta, compared on delete; the install data
for bulk and periodic resend is produced by the helper-authoritative
ATOMIC SNAPSHOT (a new helper method acquiring the canonical hierarchy
locks (`synced` → `nat` → `forward_wire` → indexes,
`coordinator/session_manager.rs:12-18`) and producing `(BPF/NAT row,
identity, row_version, stable_rule_id_hash, admission_config_version)`
tuples in one lock span); the sender's install
pipeline RE-VALIDATES at send time that the row's current version still
matches the snapshot's stored version (else re-resolve — closing the
ABA trace where bulk captures E1's row while E2 replaces the tuple and
identity and a later sidecar lookup returns I2). Today's install
payload ends with `ConfigEpoch` and `RTFlowSessionID` at
`sync_protocol.go:192, :485`, `SessionValue` contains neither identity
component at `types.go:89`, `SessionDelta` has no nonce/incarnation
pair at `entry.rs:283`, and `SyncedSessionEntry` has no pair at
`worker/mod.rs:375` — the tail is additive on both message kinds, and
a receiver-minted incarnation can never equal the sender's, so the
identity must come from the wire. Bulk and periodic resend currently
reconstruct installs from BPF rows alone (`sync_bulk.go:95`,
`sync_conn_sweep.go:142`), whose projection deliberately drops
sync-only fields (`bpf_session_value.go:168, :204`) — so an
incremental Open tail would be lost on resend without the atomic
source.


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
  no HA wire change in Part A (the demote gate); Part B adds the
  rolling-gated additive identity tails on session INSTALL/Open AND
  DELETE messages (tolerated by old decoders via the
  `sync_protocol.go:95-102, :470-497` trailing-field tolerance), and
  no config schema change. The NODE-LOCAL shared-map
  schema gains additive fields (`last_touch_ns`, `expires_after_ns`,
  `flow_incarnation_id`) — never wire-carried in Phase 1, so
  rolling-upgrade safe.

---

## 6. Public API preservation

No public API exists to preserve: `SessionTable`, `account_packet`,
`lookup_with_origin`, `update_session`, `install_with_protocol_with_origin`,
`FlowCacheEntry` are all `pub(crate)`/`pub(super)`. gRPC/REST/CLI surfaces
unchanged. HA sync wire unchanged IN PART A (the demote gate adds no wire
field); Part B adds the rolling-gated additive identity tails on session
INSTALL/Open AND DELETE messages (old decoders ignore them via the
`sync_protocol.go:95-102, :470-497` trailing-field tolerance; a
mixed-version peer pair has the new node suppressing ALL
incarnation-dependent deletes toward the unnegotiated peer, with the
legacy peer cleaning up via its own aging/invalidation/sweep machinery —
documented mixed-version behavior).
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
  by a refused (out-of-window or no-baseline) close.
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
- **Close authority (v8.3):** the `expire.rs:342-345` delta gate is
  `!is_reverse && !is_transient_seed &&
  (owner_rg_id > 0 && owner_rg_active(owner_rg_id) ||
   owner_rg_id == 0 && locally-born) && (locally_born || closing ||
   reset)` — the full predicate (live owner state at reap time; the
  sticky mark with its normative creation rules; `owner_rg_id` stamped
  on EVERY forward install path; LocalDelivery owner-zero by design —
  Go excludes host-local sessions from HA sync; the #2120 held class
  zero-and-silent). Import-class entries emit ONLY when marked;
  unmarked import reaps are silent. Stranded shared aliases are
  purged by the reservation-release-driven alias delete (NAT'd
  flows) and the coordinator shared-map TTL sweep (backstop, K ×
  timeout without event/read/touch) — no Close producer required, no
  incarnation ticket anywhere. `WorkerLocalImport` and
  fabric replicas never race (their owner worker emits directly, or
  they stay silent). The authority-ARMING origin flip is never
  driven by a CLOSING packet; the committed non-close ownership
  promote (`SharedPromote`, `promote.rs:86-99`) remains — computed at
  resolve, applied at the commit arm. Documented pre-existing: the
  publish-before-command demotion ordering (`state.rs:72`,
  `loop_body/mod.rs:682`) can emit an old-owner Close during the retag
  window — master has this race today; this plan does not widen it.
  Packet-driven promotion remains for entries imported after
  activation; closing
  packets never trigger it.
- **HA replica no-Close invariant (LOAD-BEARING, round-1 Codex B8,
  restated for v8.3):** the master's gate (`expire.rs:342-345`:
  non-peer-synced, non-reverse, non-transient-seed origins) is
  REPLACED by the v8.3 predicate above — peer-synced entries
  (`SharedMaterialize`/`SyncImport`/`WorkerLocalImport`,
  `entry.rs:245-250`) still cannot emit UNMARKED (their
  `locally_born` is false and a REFUSED (out-of-window or
  no-baseline) blind close never marks — an in-window blind guess
  validates by design at the documented window probability), and a
  marked import emits only because its close was validated (locally
  or by the peer). The Go side has NO origin/generation protection
  that would save the owner (stamped deletes apply,
  `sync_conn_gen.go:493-506`; gen-zero fallback deletes apply
  unconditionally, :176-186), so this Rust gate plus the refuse-demote
  flip are the barriers between a non-owner/unvalidated reap and the
  owner's authoritative entry; a refused (out-of-window or
  no-baseline) close never crosses them, while an in-window blind
  guess validates by design at the documented window probability. The plan adds exact regression tests
  (`SharedMaterialize + reset + FabricRedirect + stale-ceiling reap` →
  no delta, no owner/shared deletion; blind first-packet close on a
  promotable import → no mark, install-alive, no delta) and names the
  invariant in the module docs.
- **Hot-path discipline:** zero new allocations; zero new atomics; the
  per-TCP-data-packet cost inside `account_packet`'s existing probe is one
  8-byte read + ≤2 gated stores; closing segments add one table probe on a
  path that already takes the full slow path. `SessionEntry` grows 56 B
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
- **Split-direction steering (v7.5, round-8 Codex 5 — quantified and
  re-adjudicated):** the shim steers by physical RX queue
  (`userspace-xdp/lib.rs:1460`); with non-symmetric hashing ~1−1/N of
  flows split (~83% at 6 queues), each direction consistently on its
  own worker. The precise consequence, verified against master: a
  reverse-direction close lands on the reverse-observing worker B,
  whose canonical forward copy is a `WorkerLocalImport` replica.
  **On master, B's mark propagates only within B's local table
  (`mod.rs:1232-1278`) and never reaches worker A's authoritative
  entry, and B's replica/synth entries are peer-synced/is_reverse —
  silent reaps with NO delta — so master ALSO cannot demote the
  authoritative state from B; A's entry idles out on its ordinary
  timeout, and a blind reverse close on B kills only B's 2 s
  re-synthesizable caches (toothless).** Under this plan, B's replica
  anchor is untrusted (Phase 1) → the reverse close soft-refuses →
  B's replica stays fresh — ≈ master's outcome for the flow (A idles
  out identically) and strictly better for B (no 2 s replica churn).
  Forward-direction closes land on A (full anchor → validated).
  **So the split class is master-parity in Phase 1, not a new
  residual.** Phase 2 repairs B properly: the same-node shared alias
  carries A's trusted fwd sides (the anchor_update op already applies
  to shared aliases), and B's observed rev samples cross-prove against
  them → B's sides become trusted → validated demote on B, better
  than master (and refused blind closes never mark at all). Writer migration (queue
  re-balance) is covered by the per-side lease: the old writer's
  sides decay unless it keeps observing (its heartbeats stop when its
  observation stops — the heartbeat is an OBSERVATION refresh, not a
  timer, so a migrated-away writer cannot heartbeat indefinitely).
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
| Performance regression | LOW-MED | ~104 B/entry slab growth (~13.6 MiB/worker at cap); one TCP-header view compute (seq/ack/wnd/flags/seg_len) + ≤2 gated stores per committed TCP data packet (closing segments skip updates entirely); one extra probe per closing segment. Must be measured at minimum-frame rates (§9) — the 23 Gbit/s MTU-sized iperf run alone is insufficient (≈37 Mpps at 25 Gbit/s small-frame is the real gate; `iperf3 -l 64` is a proxy, not a demonstrated line-rate generator — gate on pps, not bandwidth). |
| Architectural mismatch | LOW | No new subsystem; anchors at the existing #2501/#3706 chokepoints; #4400-style always-on gate. No pipeline restructure. |
| HA / rolling upgrade | LOW-MED | Part A: no wire change; Part B adds rolling-gated additive identity tails on INSTALL/Open AND DELETE (old decoders ignore them via the trailing-field tolerance; mixed-version behavior documented: gen-based deletes apply only to non-locally-authoritative entries, and identity-dependent deletes are suppressed toward unnegotiated peers); pre-upgrade and imported entries sit in the absorbing zero-trust state — closes refuse until churn (strictly more conservative than master; bounded lingering, §2; Phase 2 §10.5 closes it for synced flows). The replica no-Close invariant + the SharedPromote refuse trace are regression-tested. |
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
- **Probation two-branch (v9.8, round-17 Codex M4):** (a) a blind
  non-close packet that is FILTERED/TTL-dropped: probation untouched
  (no clear, no refresh, no Open, no replication, no publication, no
  family stamp); (b) a blind non-close that COMMITS: probation clears
  exactly once, ordinary established idle refresh, exactly one
  Open/replication/stamp, and subsequent hits do NOT re-promote; no
  accelerated reap and no close mark in either branch.
- **Escrow + conditional-delete fences (v9.9.9):** (f) the stable
  logical rule ID (`<from>-><to>/<name>`, `policies_ids.go:101`) plus
  content version and the write-once admission config-sync generation
  as DISTINCT fields: same-content-different-name rules never
  cross-select (the round-24 G1/G2/G3 trace); a rule edited in place
  keeps its name and is correctly selected; a renamed rule is
  delete+add; the admission generation is stamped once at entry
  creation and never rewritten (unlike `install_epoch`'s mutation
  counter); (g) new-sender suppression toward unnegotiated (legacy)
  peers: an identity-dependent delete is emitted only to a negotiated
  peer (capability bit in the handshake); to an unnegotiated peer,
  invalidation/conditional deletes are NOT sent at all — the legacy
  peer's own invalidation pass deletes its own E1s with the old
  gen-based semantics (master's pre-existing behavior), while plain
  owner-validated Close deltas are SUPPRESSED toward the legacy peer
  too (a Close is incarnation-dependent by construction — the legacy
  receiver's key-based application cannot distinguish E1 from a
  re-seeded E2 sharing the tuple, so suppressing it is the only safe
  posture); (h) the durable
  coordinator-owned escrow: lifetime independent of command permits
  and of `PreservedReconcileState`, persisting across reconcile
  attempts (teardown → bring-up → failure → retry) until a dataplane
  is up AND replay consumption is confirmed, draining only on a
  declared permanent dataplane stop or on that confirmation; the
  terminal-winner-before-insertion race (worker panic before
  insertion, `supervisor.rs:98`) is safe because the escrow keeper
  still holds the allocation (refcount ≥ 1) until consumption is
  confirmed; (i) the mixed-version gen-based fallback: gen-based
  deletes apply only to NON-locally-authoritative entries (standby/
  replica copies); locally authoritative entries (locally-born or
  `SharedPromote`) are IMMUNE to gen-based peer deletes in a
  mixed-version pair — a stale gen-based delete from the old sender
  (whose fresh generation always advances past the receiver's tracked
  generation for that key, `sync_conn_write.go:69`) can never delete
  the new node's re-seeded E2 in the dual-active window.
- **Escrow + conditional-delete fences (v9.9.3, round-19 Codex M4):**
  (a) two-phase stop: quiesce acknowledged (no new commits) BEFORE
  handoff; handoff completes BEFORE any side-map drop (no hold
  escapes to RAII at join, incl. pending command-queue tokens);
  (b) partial spawn: a worker that never launches has its pending
  commands EXPLICITLY rejected (not dropped via Drop), and the DURABLE
  escrow keeper is never released by command outcomes at all — it
  transfers to the replayed entries that retained only when replay
  consumption is confirmed (or releases if none retained), across as
  many reconcile attempts as needed (the `reconcile/mod.rs:403`
  dataplane-down case included);
  (c) multi-replica pending: an early `Rejected` never drops the
  keeper while later replicas are pending; (d) deadline-vs-claim:
  an unclaimed command converts to `Rejected` at the deadline; a
  claimed command gets its permit-bounded execution window; a
  claimed-but-stuck command whose permit expires converts
  `Claimed → Abandoned` at the coordinator pending map (single-winner
  terminal transition); a late executor rechecks the permit before
  side-map insertion — `Abandoned` releases the retained hold
  immediately and aborts; a late verify-and-retain on a freed/reused
  allocation MISMATCHES and aborts (no hold re-created on a reused
  port — the round-19 AGY trace); the RAII drop DISARMS the permit
  expiration timer at drop time (no double-release of the pending
  slot when a worker claims, retains, and dies before the recheck —
  the round-22 AGY trace); (e) helper-authoritative
  conditional delete with TEMPORAL CUTS: Go submits the predicate;
  (e2) the wire identity matrix: new-sender→new-receiver (tail
  applied), old-sender→new-receiver (tail-less install → the receiver
  stores NO identity; new-sender→old-receiver: the INSTALL tail is
  ignored by old decoders (harmless extra bytes), while
  identity-dependent DELETEs (Close, invalidation, conditional) are
  SUPPRESSED entirely toward the unnegotiated peer (v9.9.14, round-29
  Codex H5: the matrix previously said new→old "tail ignored" AND
  "mixed-version pairs fall back to generation deletes" generically —
  followed for DELETE, A's E1 Close reaches legacy B; B decodes key
  plus generation (`sync_conn_read.go:150`), accepts the equal/fresh
  generation (`sync_conn_gen.go:263`), and key-deletes current
  same-key E2 plus companions at `sync_conn_gen.go:493-506`; so the
  old-receiver fallback is: gen-based deletes — but ONLY
  v9.9.8, round-23 partial: a stale gen-based delete from the old
  sender carries the sender's fresh generation (which always advances
  past the receiver's tracked generation for that key,
  `sync_conn_write.go:69`), and E2 re-seeded on the NEW node does NOT
  advance the OLD sender's generation — so an unconditional gen-based
  fallback would delete the new node's authoritative E2 in the
  dual-active mixed-version window (the quadruple coincidence:
  mixed-version pair + failover + policy invalidation + new flow in
  the same ~100 ms masterDownInterval window). The rule: gen-based
  deletes in a mixed-version pair apply only when the entry is NOT
  locally authoritative on the receiver (a standby/replica copy —
  the owner's gen-based delete correctly kills it); locally
  authoritative entries (locally-born or `SharedPromote`) are IMMUNE
  to gen-based peer deletes — the new node's re-seeded E2 survives,
  and the old node's own invalidation pass deletes its own E1 copy
  with its own fence. The hazard is thereby closed, not just
  bounded), new-sender→old-receiver
  (tail ignored), and the dual-active propagation case (both nodes
  believe they own the RG: the delete delta carries the selected
  identity and the receiver applies it only when its stored
  incarnation matches, so node A's propagated delete of E1 never kills
  node B's live E2 aliasing the same key);
  the helper selects from its own shared aliases, captures the
  selected `(origin_process_nonce, flow_incarnation_id)` under the
  canonical lock, and deletes under the alias-token fencing in one
  transaction — CHUNKED via the same insertion-ordered secondary index
  with a cursor position (the `Mutex<FxHashMap>` stores have no key
  ordering, `session/key.rs:9` — the index is ordered by
  COORDINATOR-GLOBAL immutable insertion sequence (a u64 seqno
  allocated by an `AtomicU64` fetch_add INSIDE the map's insertion
  lock span — round-26 AGY's cursor-safety catch: allocating outside
  the lock lets out-of-order lock acquisition insert seq 101 before
  seq 100, and a cursor advancing to 101 permanently skips the
  late-inserted 100 in subsequent `seqno > cursor` scans; allocating
  inside guarantees monotonic cursor safety) and maintained alongside
  the map under the
  same lock exactly as `nat_reverse_index`/`forward_wire_index` are;
  the scan iterates the INDEX with a cursor position, taking the lock
  per ≤1,024-entry chunk, advancing, releasing, and resuming —
  O(N) total, no O(N²) rescan, no full-clear lock hold), The test schedules are the OPERATIVE
  races (round-20 Codex M5): policy invalidation — E2 admitted AFTER
  the new snapshot activates by the still-permitting version is
  NEVER selected (the stable logical rule ID
  (`<from>-><to>/<name>`, `policies_ids.go:101`) disambiguates
  same-content rules by name; the numeric positional ID
  (`RuntimePolicyIndex`, `policies_ids.go:112`) is never consulted,
  and the admission config-sync generation (write-once at entry
  creation, never rewritten — NOT `install_epoch`'s mutation counter)
  bounds the selection to entries admitted before the invalidated
  snapshot's generation); cluster-bulk
  cleanup — a locally authoritative E2 committed after a mid-bulk
  secondary→primary flip (`sync_test.go:1535, :1573-1585`) FAILS the
  commit-time candidate-class re-validation (still peer-owned AND
  locally absent?) and is skipped; filtered clearing — current-state
  selection deletes whatever matches now, in ≤1,024-key chunks;
  same-`session_id`/different-process-nonce — the fence compares the
  FULL `(origin_process_nonce, flow_incarnation_id)` pair, so a
  post-restart E2 with the same per-worker counter value is not
  deleted by a pre-restart E1's delta; the peer delete delta carries
  the SELECTED identity (rolling-gated additive tail) and the
  receiver applies it only when its stored incarnation matches (a
  mixed-version pair falls back to today's gen-based delete,
  documented).
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
  variant → seeded closing + the FULL mark applied atomically to the
  forward family in hand (sticky bits + reset-before-timeout recompute
  + last_seen + wheel push in the same resolve, v9.2+) so the forward
  emits at its 2 s reap — NOT an idealized whole-flow reap and NOT a
  later-hit propagation (round-2 Codex 8, round-17 Codex M5). Match-provenance: a SHARED forward match with a
  coexisting local fabric placeholder validates against the SHARED
  snapshot (refuse), never the wrong local anchor.
- **Materialize gate (site 2c):** closing-flagged shared-hit materialize
  installs the copy ALIVE (`closing=false, reset=false`), no Close delta
  on its later ordinary reap; non-closing materialize adopts untrusted
  tracking only.
- **Close authority v8:** (a) a validated close on an import-class
  entry marks it and the marking worker's 2 s reap emits the
  authoritative Close (single producer in the normal case; the
  documented rare exception is two workers marked by a retransmitted
  valid close before the delete lands — idempotent at the store plus
  a bounded duplicate RT_FLOW record, round-10 Codex 7a); (b) an
  unmarked import reaps silently on every worker (no fanout
  duplication, no RT_FLOW dupes); (c) the shared-map TTL sweep purges
  a stale canonical + NAT + wire alias family after K × timeout (the
  round-5 stranding) and a rematerialize after the sweep finds
  nothing; (d) Go close processing is `(origin_process_nonce,
  flow_incarnation_id)`-conditional where the id exists — a stale E1
  Close cannot kill E2's cluster entry; (e) owner_rg_id is stamped on
  every forward install
  path (assert no forward entry carries 0 except the LocalDelivery and
  #2120 held classes); (f) the demotion live-state gate: an entry
  whose RG just demoted emits nothing at its next reap.
- **Phase-2 contract (deferred to the phase2-brief.md track):** per-direction bundles merge by
  lexicographic `(bulk_epoch, writer_gen, seqno)` per bundle
  (coordinator-issued writer generation kills equal-version
  migration conflicts); updates are incarnation-conditional on
  `flow_incarnation_id` (delayed E1 cannot attach to E2);
  `BulkStart` carries the sender process nonce and incrementals are
  accepted only after the first BulkStart of a connection (nonce
  change resets the floor); `fresh` is computed at write time;
  the owner-epoch gate (sender is current RG owner per the
  receiver's view) rejects non-owner renewals; a full session
  install applies the sidecar's MERGED anchor state; heartbeats are
  observation-gated AND staggered by key-hash; flush floor ≥ steady
  state rate.
- **Close authority v8 semantics:** (a) blind first-packet close on a
  pre-activation import → NO ownership promote, no mark, no refresh —
  fully inert; ordinary reaps silent on every worker (no fanout
  duplication). (b) post-activation: a REFUSED (out-of-window or no-baseline) blind
  close is still refused
  (inert); entries reap at their TRUE natural timeout, silently;
  the TTL sweep purges the alias family after K × timeout without
  event or batched touch (no rematerialization after the sweep).
  (c) `fabric_ingress` imports take the same path. (c2) the
  pre-materialization transient purge (`session_glue/mod.rs:1165,
  :1181`, `promote.rs:167` — a detached `hit.shared_entry` driving
  shared/local/BPF deletion and NAT release), the activation
  prewarm/republisher publication paths (`shared_ops.rs:304, :357,
  :390, :448, :462`), and the runtime tunnel-remap purge
  (`ha/tunnel_purge.rs:24, :77` — snapshots keys/deltas under the
  shared lock, then deletes by key later, and `session_import.rs:227,
  :243, :264` treats the helper-local deletion as authoritative)
  all become incarnation-conditional: the
  purge/publish fires only when the detached entry's
  `flow_incarnation_id` still matches the canonical record's (v9.4,
  round-14 Codex H3b/c/d + round-15 Codex H4). (d) a validated
  close on an import marks it and the marking worker's 2 s reap emits
  the authoritative Close (exactly one in the normal case — forward
  emits, reverse suppressed by `is_reverse`; the documented rare
  exception is two workers marked by a retransmitted valid close
  before the delete lands — idempotent at the store plus a bounded
  duplicate RT_FLOW record, round-10 Codex 7a). (e) a live-but-quiet flow's alias
  SURVIVES the sweep via the worker's 30 s batched touch; a truly
  dead flow's aliases die. (f) demoted-node copies never emit (RG not
  active). (g) a newer same-key incarnation (re-seeded on the peer)
  is protected by the `(origin_process_nonce, flow_incarnation_id)`-
  conditional Go close processing where ids exist; (h) the reverse-synth
  accept marks the forward family ATOMICALLY (sticky bits +
  reset-before-timeout recompute + last_seen + wheel push in the same
  resolve — not on a later hit).
- **Part-B mechanism tests (v9.2):** (a) mark rules — no constructor
  seeds closing/reset without validation (reverse-synth refuse → no
  install; materialize refuse → probationary alive install, unmarked,
  no clock stamp; fabric SYN|ACK|RST seed is `is_reverse`-silent;
  SYN|RST invented-tuple self-anchors); (b) uniform fencing — every
  local Close mutation is incarnation-conditional (a queued stale E1
  Close drained after E2's install cannot delete E2's
  BPF/conntrack/DNAT/aliases/replicas); `DeleteSynced` deletes only on
  id match; (c) commit coverage — materialize, reverse-synth,
  icmp_embed, and async upsert/prewarm consumption all perform the
  incarnation recheck + the atomic verify-and-retain (a stale
  translation mismatches → discard, never publish); (d) TTL/family —
  one canonical-key family clock
  (forward when present, reverse for lone reverse imports) with
  `expires_after_ns` copied at publish and refreshed on every stamp
  (OPENING→ESTABLISHED: a quiet established flow is never swept at
  K × opening_timeout); compare-delete per member on
  flow_incarnation_id under the documented lock order incl. the
  dnat_table side effect; a colliding E2 alias survives E1's sweep;
  the NAT reservation release purges the alias family only via the
  holder refcount zero (the holder refcount shipped as Part B — NOT
  "pending #6522"; #6522's premature-release class is what the
  refcount fixes); (e) emission — the reverse-synth accept
  marks the forward family atomically (full mark semantics: sticky
  bits + reset-before-timeout recompute + last_seen + wheel push);
  exactly one Close per flow in the normal case (forward emits,
  reverse suppressed; the documented rare two-marked-workers case
  emits an idempotent duplicate at the store);
  (f) resource-retention residual asserted: a poisoned anchor
  soft-refuses the endpoint's close; the entry is held only while the
  spray continues (bound: spray duration + one timeout); (g) wire
  mark (Phase-2 track — see phase2-brief.md).
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
  no-ACK bare RST in the same state soft-refuses; an abort DURING an
  unresolved loss hole (ack lag > raw-wnd bound) soft-refuses and
  validates again after repair (round-7 Codex 9, round-10 Codex 12).
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
  compile-time 56-byte layout assertion.
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
  shared/owner deletion (the reset here is a REFUSED/out-of-window
  blind close — an in-window guess validates by design).
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
  negative (v6)**: immediately after RG switchover, spray blind closes
  with DETERMINISTIC out-of-window/no-baseline seq at
  synced-but-not-yet-observed flows → entries survive (refuse-demote,
  NO ownership promote on closing packets, no Close deltas, standby
  copies intact, self-heal unsuppressed); an in-window guess is
  ACCEPTED by design (the acceptance window is the honest capability
  claim, §2). The imported flows' later legit closes refuse and
  entries linger to ordinary timeout (the absorbing state — Phase 2
  restores fast-reap for quiet flows on its own track).

---

## 10. Out of scope (explicitly)

- Junos general per-packet sequence check (`no-sequence-check` enforcement,
  #2008 M9 / #2078) — the wscale-aware data-plane window check on *every*
  segment. Bigger, throughput-sensitive, asymmetric-routing-hostile;
  separate issue. (Named honestly: xpf lacks this Junos-DEFAULT check;
  this plan closes only the RST/FIN demote DoS.)
(See §10.5 for the Phase-2 HA-wire anchor — on its own research track
as of v9; an optimization for the absorbing-state residual, not part of
this issue's gate.)

### 10.5 Phase 2 (SEPARATE RESEARCH TRACK): HA-wire anchor carriage

Phase 1 (this plan's ship candidate) closes the issue and its HA teeth
without any wire change: a blind close can mark only inside the
acceptance window (~1/2^12–1/2^14 per blind packet), and every mark was
validated against observed flow state — the 1-packet-anytime cluster
kill is dead. What Phase 1
does NOT restore is the 2 s fast-reap for synced flows after failover —
imported entries refuse closes until churn (the §2 absorbing-state
residual, bounded, delivery-safe, accepted). Phase 2 — carrying a trusted
anchor on the HA wire so a post-failover node inherits a validated
baseline — is a real protocol in its own right, and six rounds of hostile
review (r6-r12) showed it keeps unfolding: every transport, freshness,
ordering, identity, or ownership-term answer exposed the next layer.
It is therefore split to its own research track:

- The accumulated design state and every open protocol question are
  collected in `docs/research/6461-blind-rst/phase2-brief.md` (payload
  shape, per-direction bundles, coordinator sequencing, owner authority
  during overlap, connection/stream readiness, cross-node clock
  normalization, wire-mark emission trigger, version namespacing,
  capacity/flush accounting). That document is the starting brief for
  `/research` on the Phase-2 issue, NOT part of this plan's gate.
- Phase 2 is NOT required for this issue's fix to be correct or safe.
  It is an optimization for a bounded residual. The plan recommends
  shipping Part A + Part B first and running Phase 2 as its own
  converged design before implementation.

---

## 11. Open questions for the convergence round (v9)

1. **The scope split itself (the v9 question):** Part A (the dataplane
   demote gate) closes the issue AND its HA teeth with no wire change
   IN PART A (Part B adds the rolling-gated additive identity tails on
   session INSTALL/Open AND DELETE — see the normative wire schema in
   §5.8)
   (a REFUSED — out-of-window or no-baseline — blind close never marks
   → never produces a Close delta → the 1-packet-anytime cluster-kill
   channel is dead; an in-window blind guess validates by design at the
   documented window probability). Phase 2 (wire anchor, restoring
   fast-reap for synced flows) is an optimization for the bounded
   absorbing-state residual and is split to its own research track
   (phase2-brief.md). Is any part of the ISSUE's actual harm left
   unaddressed by Part A + Part B? Name it with a trace, or the split
   stands.
2. **The pre-existing NAT release bug (round-12 Codex 1, filed):**
   every expired forward unconditionally calls release
   (`loop_body/mod.rs:1481`) and the allocation has no replica
   refcount (`nat/allocator.rs:1318, :1664`), so an idle sibling
   replica's reap can free a live flow's port ON MASTER TODAY. Is the
   trace right (does anything actually gate the release on origin or
   holder?), and is filing it separately (with the last-holder
   refcount as the fix) the correct disposition for this plan?
3. **Family clock + sweep (Part B):** the clock lives on the family's
   canonical-KEY record (forward when present, reverse for lone
   reverse imports); `expires_after_ns` is copied at publish; the
   materialize commit re-reads the canonical record and requires
   incarnation match + live NAT reservation. Find a stale-clone or
   stale-permit path that survives these, or confirm the sweep is
   now safe.
4. **Emission predicate + reverse-synth atomic forward mark:** any
   remaining zero-producer or duplicate-producer trace (the synth
   now marks the forward family at accept time; wire-marked imports
   emit at their 2s reap; unmarked reaps are silent)?
5. **Residual inventory (final):** (a) Phase-1 mark erasure on
   reimport (hygiene, sweep covers); (b) fabric SYN|ACK|RST +
   LocalDelivery bare-close seeds (harmless-by-class); (c)
   resource-retention anchor poisoning on the async tail (bound:
   spray duration + one timeout — the attacker interleaves non-close
   walk packets that refresh last_seen, so the bound is the attacker's
   own spray budget, not a new pin primitive); (d) absorbing zero-trust
   imports (Phase-2 track); (e) the pre-existing NAT release bug
   (filed). Complete and shippable?
6. **Observability:** counter + rate-limited structured event.
   Sufficient?
