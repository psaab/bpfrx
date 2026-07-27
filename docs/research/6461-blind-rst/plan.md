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
pre-existing NAT release bug SHIPPED as Part B's holder-lifetime
machinery — #6522, closed by this plan); Phase 2 —
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
       member is deleted ONLY if its stored `SessionIdentity` —
       the FULL `(origin_process_nonce, flow_incarnation_id)` pair
       (v9.9.23, round-38 Codex B4: every identity comparison in the
       design uses ONE `SessionIdentity { nonce, id }` type — the
       family sweep here, the Close fencing, `ExpiredSession`,
       `DeleteSynced`, the alias fence, and the cleanup recheck; a
       scalar `flow_incarnation_id` collides across a sender restart
       (queued A1/E1 `(n1,id7)` cleanup matching restarted A2/E2
       `(n2,id7)` and removing the replacement through the
       key-driven deletion path, `session_import.rs:243`) —
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
       commit, requiring each stored `SessionIdentity` (the full
       pair, v9.9.27) to still match the clone's (v9.4, round-14 Codex H3a: a different-forward
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
       tuple AND register a holder on it (v9.9.21: this
       direct-registration path is the `DirectHold` variant —
       LOCALLY-BORN flows and locally-born shared-entry
       materializations only; IMPORTED flows never register here —
       their entries carry `GroupHold` clones distributed at
       fan-out, and an imported shared-entry materialization clones
       the published entry's group-hold instead). The hold is an **owned token
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
       and — v9.9.20, round-35 Codex B2: re-expressed by the
       coordinator-owned GROUP-HOLD below — each replica's "retain"
       is a CLONE of the group-hold Arc distributed at fan-out/
       replay time, not a per-replica allocator refcount increment;
       the allocator reservation releases exactly when the LAST
       clone (canonical + every worker replica + materializations +
       escrow keeper) drops — solving "one linear
       token cannot transfer into every worker replica": the replicas
       hold clones, the escrow only keeps the allocation alive meanwhile).
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
       **Persistent-lease ORDINARY peer INSTALLs (v9.9.15, round-30
       Codex B2):** the same lease discipline applies to initial and
       replayed peer INSTALLs, not just reconcile migration — the
       generic per-flow reservation cannot represent a shared
       persistent lease on the standby. The active allocator
       legitimately issues ONE persistent lease to co-holder flows
       F1/F2 sharing a translated tuple (`allocator.rs:1114, :1224`;
       regression test `tests_pool.rs:2536`), but the standby's
       generic reservation (`upsert_synced.rs:64` → `source.rs:868` →
       `reserve_flow`, `allocator.rs:1654`) records
       `persistent_key: None` per flow, so F2's import fails the
       occupied-bit check (`allocator.rs:1688`) while the upsert still
       publishes (`upsert_synced.rs:112`); after failover F1's
       teardown takes the non-persistent release branch and frees P
       (`allocator.rs:1318`) with F2 still live and holding no lease
       membership, and a same-remote E3 can then obtain P —
       reverse-NAT misdelivery. The `PersistentSourceKey` is a pure
       function of the flow key, the pool's persistent flag, and the
       permit (`allocator.rs:1116`'s
       `flow.persistent_source_key(persistent_nat_permit)`; the flag
       and permit are RULE config, `source.rs:302-305`, not per-flow
       state) — but deriving it from the standby's LOCALLY APPLIED
       rule config is unsound under config-epoch skew (v9.9.16,
       round-31 Codex B1: config receipt only QUEUES asynchronous
       application (`sync_conn_read.go:298`) while a session INSTALL
       is processed immediately (`sync_conn_read.go:96`), and
       `configEpochStale` refuses only epochs BELOW the high-water
       mark (`sync_conn_gen.go:398`), so a g2-stamped INSTALL can be
       processed while g1 is still locally applied: C1
       `target-host-port` → C2 `any-remote-host`, F1/F2 with the same
       internal tuple and different remotes sharing P under C2 — B
       derives distinct C1 keys, F1 creates P, F2 is rejected, the
       later C2 apply reuses the allocator (its key omits the permit,
       `source.rs:327, :723`), and crash takeover — which is NOT
       gated on config application (`manager.go:321`; a stuck apply
       is only a diagnostic annotation, #6387) — leaves F2 absent to
       re-resolve under C2, where P belongs to the mis-keyed F1
       lease, so F2 obtains Q: a prohibited mid-flow SNAT port swap.
       Waiting for the exact applied epoch needs a deferral queue
       with delete-delta ordering hazards, and version-addressable
       NAT policy retention is heavier still; the chosen fix is the
       third option): the INSTALL's additive tail CARRIES the
       authoritative lease derivation inputs `(persistent_nat,
       persistent_nat_permit)`, stamped by the sender from the
       ADMITTING rule at admission (the same authority-stamp
       provenance as the selector fields, and for SNAT and NAT64
       alike — both allocate through `PortAllocator.allocate_translation`
       with those parameters); the receiver derives the lease key
       from the WIRE inputs, never from its local rule config; and a
       legacy sender's tail-less install imports non-persistently
       (today's pre-existing semantics — no regression). The
       port/address occupancy structures remain the structural
       backstop across key shapes: whatever the lease key, P's
       ownership is singular. The rule:
       every initial or replayed peer install of an entry whose
       decision belongs to a persistent pool performs an ATOMIC exact
       lease-create-or-retain BEFORE publication, DISPATCHED BY
       ALLOCATION KIND exactly like the restore rule (v9.9.16,
       round-31 Codex H3): PORT-BEARING persistent — in one allocator
       critical section, derive the key from the wire inputs; if the
       lease exists, verify its translated tuple equals the wire
       decision and increment its co-holder count (mismatch =
       failure); if not, create the lease object (key, timeout,
       translated tuple, co-holder count 1) and reserve the port bit
       in the same section; and the imported flow's `LiveAllocation`
       records `persistent_key: Some(key)`, so teardown releases
       through the lease refcount and the port frees only when the
       LAST co-holder releases. ADDRESS-ONLY persistent (#6041) — an
       address-only persistent lease create-or-retain keyed by the
       same wire-carried permit, pinning the WIRE-carried public
       address (pool-membership-validated, NEVER a fresh pick) and
       minting the reverse-identity token per the #5336/#6041
       semantics, consuming NO port bit (today's standby arm uses the
       plain per-flow `reserve_address_only`, `source.rs:894-912` —
       the same co-holder gap; and routing an address-only decision
       through the port-bearing path is doubly wrong because the
       bitmap begins at port 1024, `source.rs:675`, so exact bitmap
       reservation rejects out-of-range preserved ports like 80,
       `allocator.rs:537` — the install would be refused on the
       standby and the flow's public address would swap at failover).
       NON-persistent port-bearing → `reserve_flow`; NON-persistent
       address-only → `reserve_address_only` (unchanged). Any
       failure (the port or address is owned by a different
       allocation, or an existing lease carries a mismatched tuple)
       REJECTS the install — the upsert does NOT publish; the
       standby lacks that copy until the next resend retries (a
       standby gap is safe; a misdelivering alias is not), and the
       rejection is observable via a named counter
       (`nat_persistent_import_rejected_total`) so a persistent
       standby gap is diagnosable rather than silent.
       Co-holder imports then arrive in any order: F1 creates,
       F2 retains, and neither fails the occupied-bit check.
       **Future-epoch deferral (v9.9.17, round-32 Codex B2):** the
       wire-carried lease inputs fix key DERIVATION, but the
       receiver's allocator SHAPE checks (port-range bitmap,
       `allocator.rs:537, :672`; pool membership, `source.rs:900`)
       still evaluate against the LOCALLY APPLIED config, and a
       future-epoch exact reservation can fail them before its
       allocator configuration arrives: C1's pool ends at port
       40000, C2 expands it to 40001; A admits E1 at 40001; B
       receives E1's g2 INSTALL before applying C2 (config receipt
       only queues asynchronous application,
       `sync_conn_read.go:298`, while session frames process
       immediately, `:96`, and the epoch fence refuses only epochs
       BELOW the applied/applying barrier, `sync_conn_gen.go:424`),
       and B's C1 bitmap rejects 40001 out of range. Sender-side
       retry cannot close this: the rejection is invisible to the
       sender — the sweep considers only entries created since its
       prior cutoff and advances that cutoff after LOCAL QUEUE
       success, not receiver acceptance (`sync_conn_sweep.go:137,
       :185`) — so B can apply C2 after the resend window and A can
       crash before any reconnect/bulk (crash takeover is expressly
       ungated, `manager.go:321`), leaving E1 to re-seed at Q: a
       prohibited mid-flow port swap. The fix is RECEIVER-SIDE
       EXACT-EPOCH DEFERRAL, with the protocol pinned as follows
       (v9.9.18, round-33 Codex B1 + round-33 AGY reset-loop +
       round-33 SMR heartbeat — the v9.9.17 whole-stream park had
       three code-verified defects: it admitted when
       `applying == stamp` although C2's allocator is not published
       until the apply callback succeeds (`sync_conn_config.go:289,
       :343, :389`); it could put the enabling Config frame behind
       the parked g2 INSTALL — `OnPeerConnected`'s config push is
       asynchronous while BulkStart/INSTALLs are direct writes
       (`sync_conn.go:130, :142, :194`, `sync_bulk.go:81, :95`) —
       self-deadlocking the drain; and BulkStart RESET the
       watermarks (`sync_conn_read.go:183`, `sync_conn_gen.go:324`),
       while the watermark itself was directional — the config
       authority never applies peer-pushed config, so its receive
       high-water stays zero
       (`sync_config_epoch_active_active_6284_test.go:12, :71`) and
       a non-authority's locally-born g2 flow would park forever at
       the authority in active/active):
       (1) THE WATERMARK is a NODE-GLOBAL fully-published
       forwarding-config epoch — `max(own_committed_epoch as
       authority, lastAppliedConfigGen from the peer)` — advanced by
       BOTH local-authority commits and successful peer applies,
       cluster-monotonic, and NEVER cleared by BulkStart (the
       per-bulk reset at `sync_conn_read.go:183` /
       `sync_conn_gen.go:324` is removed for these watermarks).
       (2) THE READINESS PREDICATE at the Go receive layer (the same
       pre-helper gate where `configEpochStale` is authoritative,
       `sync_conn_gen.go:404-412`): `epoch < stale-barrier` →
       refuse (existing #5274 semantics, unchanged); process IFF
       `stamp <= published_epoch AND applyingConfigGen == 0`;
       otherwise PARK — `applying == stamp` stays PARKED, because
       lastApplied advances only after the apply callback (and its
       dataplane publication) succeeds.
       (3) THE PARK IS MESSAGE-CLASS-SELECTIVE (round-33 SMR:
       heartbeats ride the SAME connection —
       `syncMsgHeartbeat`/`syncMsgHeartbeatAck` are handled in the
       same `handleMessage` dispatcher as installs,
       `sync_conn_read.go:284, :296`, and a whole-stream park would
       stall heartbeat-acks and trip missed-heartbeat failover
       during a routine apply lag — a self-inflicted availability
       hazard): SESSION-STATE messages (session installs, deletes,
       bulk Start/End/markers — everything that mutates or
       reconciles session state) buffer behind the park in arrival
       order (the FIFO ordering proof is preserved: buffered deltas
       keep stream order, so a delete can never bypass a deferred
       install for the same key — the naive per-key deferral zombie
       is impossible by construction); CONTROL messages
       (heartbeat/ack, and the Config frame — whose receipt only
       queues the async apply, `sync_conn_read.go:298`) keep
       flowing, so the enabling Config always reaches the apply
       queue regardless of the park (the reconnect self-deadlock is
       closed by construction, with the sender-side ordering —
       config push serialized BEFORE BulkStart for the same epoch —
       kept as belt-and-suspenders). Bulk markers park with the
       deltas (`reconcileStaleSessions` at BulkEnd must not run
       against a partially-buffered bulk).
       (4) OVERFLOW REPAIR, NO RESET LOOP, NO SILENT LOSS (v9.9.19,
       round-34 Codex B1 + round-34 SMR F1 — the v9.9.18 clause was
       wrong twice over: `syncBackfillNeeded` is a SENDER-local flag
       armed by OUTBOUND `sendCh` overflow (`sync_conn_write.go:36,
       :46`; the sweep replays only LOCALLY OWNED sessions,
       `sync_conn_sweep.go:65, :137`), so the receiver setting it
       cannot make owner A resend a frame B discarded — and A
       already advanced its sweep window on queue success
       (`sync_conn_sweep.go:180`); and a discarded DELETE is
       recoverable ONLY by authoritative bulk repair, since deletes
       are journaled just when local enqueue fails
       (`sync_conn_write.go:69`). The corrected protocol: the park
       buffer is bounded; on overflow the receiver (i) marks the
       in-flight bulk/window LOSSY — a bulk that discarded ANY
       member neither reconciles at BulkEnd nor ACKs
       (`sync_conn_read.go:205, :241`) — and (ii) raises a
       LOGICAL-PEER FULL-RESYNC OBLIGATION (v9.9.20, round-35 Codex
       B1 — a per-connection disconnect does NOT guarantee the
       repair in the dual-fabric transport: `handleDisconnect`
       removes only the failed connection (`sync_conn.go:480`), a
       surviving fabric avoids the full-disconnect path (`:498`),
       survivor re-bulk runs only while `outboundBulkAcked` is
       false (`:572`) — a flag deliberately sticky forever after
       any successful bulk (`sync.go:479`) — and reconnection does
       not cold-prime because `wasDisconnected` requires BOTH
       slots empty (`:248`): B can overflow-close fab0 while A
       continues on fab1, no queue overflows, no bulk ever
       follows). The obligation is per-PEER, not per-connection,
       and its driver is stated precisely (v9.9.21, round-36 AGY
       Q1 + round-36 SMR F1 + round-36 Codex B1 — the v9.9.20
       "drive the existing BulkSync machinery over the SURVIVING
       active connection, no new wire message" clause is
       unreachable, twice over: `doBulkSync` is SENDER-driven only
       (`sync_conn.go:130-194`, `sync_bulk.go:40-90`) AND —
       round-36 Codex's sharper point — `BulkSync` exports the
       INVOKING node's locally-owned table (`sync_bulk.go:50,
       :95`), so B driving "a bulk" sends B→A and can never
       reconstruct the A→B INSTALL/DELETE that B discarded; and
       `outboundBulkAcked` is SENDER-side state ("set ONLY when
       the peer acks OUR outbound bulk", `sync.go:475-482`), the
       survivor re-drive at `sync_conn.go:572` being the sender
       re-driving its OWN stranded outbound bulk — a receiver-side
       obligation cannot clear the sender's flag without a
       message): the repair bulk must be A→B, and exactly two
       mechanisms can produce it. (a) PRIMARY — the TRUE
       ALL-FABRIC RESET: overflow marks the window lossy and
       closes BOTH connections to the peer ATOMICALLY — and the
       sender-visible both-empty signal is the EXISTING heartbeat
       detector, not a cascade over sender state the primary path
       does not have (v9.9.23, round-38 Codex B1 + round-38 SMR F1:
       the v9.9.22 "sender-side first-EOF cascade with an
       obligation outstanding" is incoherent on the primary path —
       the overflow obligation is RECEIVER-side, A holds no
       obligation, and A cannot distinguish B's deliberate
       full-close from an ordinary one-fabric flap, where clearing
       the surviving slot would be an availability regression;
       round-38 Codex's alternatives — an authenticated reset/ack
       signal or an unconditional cascade with an accepted
       flap-cost — are both unnecessary): the detection runs on
       EXISTING machinery at two speeds (v9.9.23.1 — constants and
       mechanism corrected: the earlier "threshold 5 × 200 ms
       declares the peer down" conflated the cluster-manager
       heartbeat with the session-sync detector): (i) B's atomic
       close delivers FIN on both fabrics within milliseconds in
       the common case, and A's per-connection `receiveLoop`
       treats the read error as an immediate `handleDisconnect`
       for that slot (`sync_conn_read.go:14-30`) — both slots
       empty in ~ms; and (ii) if a FIN is lost (partition), each
       connection's own heartbeat-ack timeout closes it
       independently: the `receiveLoop` sends a heartbeat request
       after `syncReadDeadline` (10 s, `sync.go:90`) of read
       silence and closes the connection after 2 consecutive
       missed acks (`sync_conn_read.go:33-44`) — every slot is
       cleared within ~20-30 s deterministically,
       PER-CONNECTION (no peer-wide declaration is needed; each
       slot's own detector cleans it), and a one-fabric flap
       keeps acks flowing on the survivor so its detector never
       fires (the flap confusion does not exist). The reconnect
       side is a BARRIER-AND-DRAIN invariant, not a race
       (v9.9.24, round-39 Codex B1 — "B does not redial early"
       is insufficient: A's OWN dialer reconnects independently
       (`sync_conn.go:388, :435`) and can install fab0 while
       fab1's slot is still occupied → `wasDisconnected ==
       false`, no cold-prime, and fab1's later clear finds fab0
       live — no cold-prime ever): B REFUSES inbound connections
       during its barrier — and the refusal is pinned
       (v9.9.25, round-39 SMR F1): (i) on the ACCEPT side B
       accepts-and-immediately-closes every attempt (immediate
       close, never "never-answer" — silence wedges A's
       connect-timeout accounting and retry backoff detection);
       and (ii) B SUPPRESSES ITS OWN outbound dial for the
       barrier's duration (a B-initiated early dial is an
       install on B too), so no install during the barrier can
       occupy a slot on either
       node; A's slots therefore drain to both-empty via EOF or
       the per-connection detector regardless of A's dialer
       retries (each retry installs briefly on A, dies at B, and
       — crucially — the cold-prime gate is evaluated PER
       INSTALL, so it need not fire on the first reconnect: the
       dialer's retry loop guarantees a LATER install); the
       barrier is sized to the SLOW detector (≥ the 2-missed-ack
       bound + RTT margin — a repair event, not a fast path),
       and the FIRST install after the barrier finds both slots
       empty on both nodes and cold-primes deterministically —
       the cold-prime that matters is the SENDER's bulk drive on
       A's `installConn` decision, and A's post-barrier install
       always computes both-empty because the barrier outlasts
       A's slot drain. The refusal's END is pinned (v9.9.26,
       round-40 SMR F1): it releases when the barrier timer
       expires (≥ the slow-detector bound + RTT margin) AND B
       observes both of ITS OWN slots empty — and it is strictly
       TIME-bound, never message-bound, so the dual-simultaneous
       case (BOTH nodes raise obligations in the same window,
       both close-both, both refuse) cannot deadlock: each
       barrier expires independently, both nodes have drained by
       then, and the first install on either side cold-primes
       (a message-bound refusal would wait for the peer's repair
       bulk that the peer is itself refusing — impossible by
       construction here). The teardown bound and the install
       fence are complete (v9.9.27, round-40 Codex B1 — two
       residual gaps: `missedHeartbeats` increments only when
       `peerHeartbeatAckEver` is already true
       (`sync_conn_read.go:32, :296`), so the ack-timeout arm
       covers only ESTABLISHED connections; and sockets admitted
       before the barrier can complete their asynchronous
       handshake mid-barrier and call `installConn` with no
       barrier recheck (`sync_conn.go:100, :388`,
       `sync_admission.go:66`)): every slot's teardown is bounded
       by the EARLIEST of (i) the FIN/read error (immediate —
       the common case, and always the case for the refused
       immediate-close attempts), (ii) the established-connection
       heartbeat-ack timeout (2 missed acks after
       `syncReadDeadline` 10 s — peers that ever acked, i.e.
       every connection that was live before the barrier), and
       (iii) the setup/handshake bound (a connection whose
       handshake cannot complete closes by the handshake's own
       timeout — the pre-ACK case can therefore never outlive
       the barrier); and a BARRIER GENERATION (a per-peer
       counter bumped at barrier start) fences installation:
       `installConn` REJECTS any socket whose setup/admission
       predates the barrier generation (immediate close), so an
       async handshake completing mid-barrier can never occupy a
       slot — the both-empty state at barrier end is guaranteed
       by the fence, not by timing alone. The generation's
       mechanics are pinned (v9.9.28, round-41 SMR F1): the
       ACCEPT side checks the barrier BEFORE admission (no new
       setup starts during the barrier — the generation recheck
       then only catches setups already in flight at the bump);
       and the generation is a per-peer atomic whose bump AND
       whose comparison both happen under `s.mu` (the slot-
       registry lock), so a setup racing the bump cannot slip an
       install between the bump and the fence arming. Two
       completeness rules (v9.9.29, round-41 Codex B1): (i) EVERY
       installed connection carries an ABSOLUTE liveness teardown
       independent of prior ACK history — a keyed handshake
       clears its deadline before installation
       (`sync_auth.go:336`), an unkeyed connection has no
       handshake deadline (`:329`), and post-install the
       missed-ack accounting stays disabled until
       `peerHeartbeatAckEver` (`sync_conn_read.go:27, :296`), so
       a slot whose close/read error is lost before the first
       ACK would otherwise persist past ANY finite barrier: the
       bound is a hard per-connection max-silence teardown (any
       installed connection with no inbound frame for the
       silence limit closes, ack history irrelevant — the
       `syncPeerSilenceTimeout` concept, `sync.go:91`, promoted
       from liveness query to teardown; a quiet-but-VALID
       connection is never at risk (v9.9.30, round-42 SMR F1:
       heartbeat requests are outbound and the peer's ACK is an
       inbound frame that resets the silence clock, so an
       idle-but-alive connection always answers when asked —
       silence means no inbound frames at all, including ACKs,
       i.e. dead or partitioned), which makes the slot's
       drain deterministic in all cases — BUT the absolute
       teardown is CAPABILITY-SCOPED (v9.9.31, round-42 Codex B1:
       today's regression explicitly keeps a quiet LEGACY peer
       connected even when it never acknowledges heartbeat
       traffic (`sync_test.go:4721`), so the silence teardown
       applies only to negotiated pairs; legacy connections keep
       today's behavior, and the legacy repair path relies on
       FIN delivery plus the durable-obligation escalation —
       documented as eventually-consistent, with the takeover
       fence backstopping a permanently-impaired peer); and the
       barrier's remote guarantee is a NEGOTIATED
       RESET-GENERATION HANDSHAKE for pairs whose NEGOTIATED
       reset version is ≥ 1 (v9.9.54.20, round-65 Codex H4:
       "capable pairs" was generic — a repair-v1/reset-v0
       pair following this branch would wait for unsupported
       RESET frames; every reset branch tests the negotiated
       reset VERSION explicitly) (v9.9.31,
       round-42 Codex B1 — the finite node-local barrier cannot
       prove the REMOTE peer observed both slots empty: a retry
       accepted-and-immediately-closed just before the barrier
       ends can occupy A's slot until ITS silence timeout
       expires, and extending the barrier only moves the
       endpoint race): B sends `RESET_GEN(g)` (rolling-gated
       additive frame), A quiesces its dialers AND rejects
       inbound, records both slots empty, and answers
       `RESET_ACK(g)`; B reopens admission only after
       `RESET_ACK(g)` (with the silence-timeout backstop for a
       lost ACK); peers whose negotiated reset version is 0
       use the time barrier above (v9.9.54.20 — never
       "unnegotiated" generically: the test is the negotiated
       reset version).
       The exchange's channel and the dual case are pinned
       (v9.9.32, round-43 SMR F1): the handshake rides the NEXT
       connection's setup (both fabrics are closed at reset time
       — B dials after its drain, `RESET_GEN(g)` rides the
       handshake, A quiesces dialers AND rejects other inbound,
       records both slots empty, and answers `RESET_ACK(g)` in
       the handshake response; the connection then cold-primes);
       and the dual-simultaneous case is two INDEPENDENT
       barriers — A's barrier governs the B→A repair, B's
       barrier the A→B repair, each node processes the peer's
       GEN on its own connection, and the generations are
       node-scoped AND direction-scoped (each barrier's state is
       the triple `(direction, node incarnation, generation)`,
       so two simultaneous resets proceed as two independent
       transitions, never one tied state machine). The PHYSICAL
       setup ownership is tie-broken deterministically
       (v9.9.35, round-44 Codex H4: today one address-ordered
       endpoint owns each fabric's dialer (`sync_conn.go:12,
       :319`), and crossed reset setups compete for one slot,
       each install closing its predecessor (`sync_conn.go:244`)
       — two endpoints can retain opposite halves of different
       connections and repeatedly miss cold-prime: the
       stable-node-ID-ordered setup owner dials ONE tie-broken
       setup (v9.9.54.10, round-58 Codex M7's totality sweep —
       stable node-ID ordering, never address parsing)
       that carries BOTH directional reset triples — through a
       barrier-EXEMPT authenticated pre-slot RESET LANE
       (v9.9.37, round-45 Codex H6: if B owns the barrier while
       A is the selected dialer, B's own barrier refusal would
       reject A's only setup before the generations exchange,
       and simultaneous barriers would reject both directions
       until timeout; and the address ordering is NOT total —
       parse failure returns "dial" on either endpoint
       (`sync_conn.go:12`, `sync_test.go:1337`) and each fabric
       currently selects its owner independently
       (`sync_conn.go:319`): the reset exchange rides a
       dedicated pre-slot control lane EXEMPT from
       `barrierActive` (it exists precisely to negotiate the
       barrier, so it cannot be gated by it); the setup owner
       is chosen by a STABLE node-pair ordering key (node ids,
       not address parsing); a deterministic live-fabric
       fallback covers a failed preferred fabric; the lane is
       type-constrained and incarnation-bound (v9.9.38, round-46
       SMR F4; confinement completed v9.9.39, round-46 Codex H3:
       the lane runs a RESET-ONLY parser — HELLO/capability plus
       fixed-size `RESET_GEN`/`RESET_ACK` only; today's setup
       reader accepts any message type up to 16 MiB
       (`sync_auth.go:289`) and a non-HELLO becomes an
       arbitrary pending frame (`:363`) dispatched before slot
       installation (`sync_conn.go:119`), so Bulk/Config frames
       could mutate receive state before a slot token exists
       (`sync_conn_read.go:183, :298`) — the lane rejects every
       other type at demux with strict size, admission, and
       deadline bounds; the reset capability is restricted to
       AUTHENTICATED peers (unkeyed setups perform no
       authentication at all, `sync_auth.go:321` — they get NO
       reset lane and use the time-barrier/legacy path); and
       the hello binds the stable node ID AND the current
       process incarnation, revalidated before any barrier
       mutation — a stale-incarnation frame is discarded; and
       the freshness is lifecycle-bound (v9.9.40, round-47 SMR
       F2: a peer restart mid-lane kills the lane with the
       connection — TCP reset or the silence teardown — and the
       new lane re-handshakes with the new incarnation; a
       delayed old-incarnation `RESET_ACK` arriving on a NEW
       lane is discarded because the frame's incarnation must
       equal the LANE's bound incarnation, not any
       recently-seen one); and the incarnation TRANSITION is
       one locked state machine (v9.9.41, round-47 Codex H2 —
       overlapping authenticated setups (accepts in independent
       goroutines, `sync_conn.go:388`; setup tracking records
       only membership, `sync_admission.go:66`; the process
       nonce is random, not ordered, `heartbeat.go:624`) can
       interleave n1-stalled → n2-completes → n1-resumes, and
       both naive rules fail (reject-every-mismatch can leave
       the genuine restart permanently non-current;
       last-completer-wins can regress to n1 and apply its
       stale reset): the peer-incarnation registry maintains
       `{current, pending, retired}` and every slot/pre-slot
       lane under ONE lock (`s.mu`): the registry admits at
       most ONE `pending` incarnation per peer, and the
       transition CAS includes the SETUP ADMISSION GENERATION
       (v9.9.47, round-50 Codex B2 — a delayed PRE-AUTH setup
       can regress the peer incarnation after a newer process
       is current: handshakes run concurrently
       (`sync_conn.go:388-430`), setup tracking records only
       membership (`sync_admission.go:66-83`), authentication
       finishes before slot installation (`sync_conn.go:100-130`),
       and incarnations are random, not ordered
       (`heartbeat.go:624-632`): n2 admitted and paused
       pre-auth, n3 authenticates and becomes current, n2
       completes — without the admission generation in the
       CAS, n2 would be treated as "newest authenticated" and
       retire n3, then fail installation at the
       setup-generation fence and strand n3 un-readoptable:
       every pre-auth admission carries a PROVISIONAL pending
       slot keyed by its admission generation — bounded and
       expiring (v9.9.48, round-51 SMR F2: an admission that
       never authenticates dies at the handshake deadline —
       the auth handshake's own failure path closes the
       connection — and the provisional set is bounded by the
       existing admission cap (`sync_admission.go:66`'s slot
       limit), so stalled admissions can neither leak nor
       exhaust it); promotion is
       atomically coupled with slot authorization (a
       transition that cannot authorize its slot fails
       entirely); promotion REVOKES older unbound pre-slot
       tokens; and n2-resume loses the CAS because its
       admission generation predates n3's promotion); the registry admits at
       most ONE `pending` incarnation per peer (v9.9.44,
       round-49 SMR F3: a THIRD incarnation arriving while one
       is pending REPLACES the pending entry — the newest
       authenticated incarnation is always authoritative; the
       replaced pending is retired without ever becoming
       current; and the completion CAS checks the transition
       epoch against the CURRENT pending, so a superseded
       pending's completion fails the CAS and cannot promote):
       a different incarnation
       first REVOKES the current incarnation's lane tokens and
       retires it, then ATOMICALLY promotes pending and
       RELEASES the lock BEFORE closing or joining anything
       (v9.9.43, round-48 Codex M3 + round-48 AGY trace-2 —
       "drain under `s.mu`" admits a blocking interpretation:
       holding `s.mu`, closing n1, and synchronously awaiting
       its handler deadlocks, because `receiveLoop`'s deferred
       `handleDisconnect` blocks acquiring the same mutex
       (`sync_conn_read.go:14`, `sync_conn.go:480`): the lock-
       held phase is metadata-only — revoke exact lane tokens,
       retire n1, promote n2 — and socket close/join happens
       AFTER release; a superseded connection's natural death
       then completes cleanup automatically, v9.9.42's
       drain-cannot-hang rule; an asynchronous pending state is
       keyed by TRANSITION EPOCH plus the live-lane set —
       natural lane death cancels it, and completion CASes the
       same epoch before promotion);
       pending; the `(node_id, incarnation, lane_token)`
       triple is rechecked immediately before every mutation;
       a retired incarnation is never readopted; and a
       reset-generation high-water is kept PER
       `(direction, node_id, process_incarnation)` (v9.9.43,
       round-48 Codex M3 — not merely per incarnation: the
       triple keys it, and the `RESET_GEN` behavior is defined
       for lower (stale — discard), equal (idempotent re-ACK),
       and higher (supersede — arm) generations),
       STARTING FRESH (v9.9.42, round-48 SMR F2: the high-water
       is per `(node_id, incarnation)`; a new incarnation
       inherits NOTHING from its predecessor — the old
       high-water retires with the old incarnation — so n3 can
       neither be confused with n2's retired state nor starved
       by it), so
       n1's frames can never pass n2's lane);
       and the
       connection installs only after BOTH reset triples have
       drained and ACK'd), and an
       equal-generation `RESET_ACK` is idempotent so the loser
       of a setup race re-ACKs without re-mutating). The
       handshake's loss semantics are pinned (v9.9.33, round-43
       Codex B1): `RESET_GEN(g)` is retransmitted on the
       control/setup connection until `RESET_ACK(g)` or a
       defined retry count, and TIMEOUT ALONE IS NEVER PROOF of
       remote drain — the silence-timeout backstop only re-opens
       admission (avoiding a permanent wedge); the OBLIGATION
       remains outstanding and readiness stays degraded until a
       repair actually completes (so "GEN never arrived" and
       "ACK was lost" need not be distinguished: both leave the
       obligation armed and the node not-ready, and the next
       successful handshake-driven cold-prime's terminal
       exchange completes it — the receiver's readiness on the
       applied `JOURNAL_END`, the sender's obligation on the
       matching `JOURNAL_ACK`, v9.9.45);
       the re-open's driver is the existing per-install gate
       (v9.9.34, round-44 SMR F3: the first install after the
       drain computes both-empty and cold-primes, and that
       cold-prime's bulk re-drive IS the next repair attempt —
       the backstop needs no separate driver, and the obligation
       discharges only when that (or a later) repair completes
       with `JOURNAL-END`).
       and (ii) the barrier's
       linearization is ONE lock domain: admission
       (`preAuthMu`, `sync_admission.go:66`), generation capture,
       `barrierActive`, slot closure, and install rejection are
       ordered under the same mutex as the slot registry
       (`s.mu`) — `installConn` atomically rejects BOTH
       stale-generation setups AND any setup attempted while
       `barrierActive` is set, so no setup can slip between the
       bump and the fence arming.
       B's inbound-repair obligation is DURABLE —
       a pathological miss (no bulk arrives) never clears it, and
       B escalates to a second close-both with exponential backoff
       (the barrier grows past any feasible detector delay, so
       the retry terminates).
       Cold-prime then drives the sender's FULL bulk A→B with the
       config-first ordering of (3); the
       once-per-latched-epoch latch keeps this from hot-looping.
       (b) OPTIONAL fast path for negotiated pairs — an additive
       authenticated RESYNC_REQUEST(repair-ID) message
       (rolling-gated like the identity tails): the RECEIVER
       requests with an incarnation-scoped repair ID (monotone per
       (sender, peer-incarnation)); a new SENDER arms an
       outbound-repair obligation for that ID and repeatedly
       drives its outbound FULL bulk A→B over the surviving
       connection (clearing its own sticky gates per the
       obligation), ECHOING the repair ID in `BulkStart`,
       `BulkEnd`, and the receiver's `JOURNAL_ACK` (never a
       bulk ACK — v9.9.41, round-47 Codex B1: `JOURNAL_END` is
       the terminal MARKER the receiver applies, `JOURNAL_ACK`
       is the receiver's return that alone discharges the
       sender's obligation; negotiated `BulkEnd` and bare
       `BulkAck(u64)` NEVER clear either obligation or
       readiness) (v9.9.22, round-37 Codex
       B1: `BulkStart` today carries only the sender-local bulk
       epoch (`sync_bulk.go:53, :65`), so a PRE-REQUEST snapshot
       delayed on the survivor can arrive after the request and
       masquerade as the repair while omitting later state — the
       repair ID is the correlation: a bulk that does not carry
       the current repair ID is not the repair; pre-request bulks
       in flight are serialized behind or superseded by the
       repair bulk); the RECEIVER's INBOUND obligation and its
       readiness clear ONLY after APPLYING the exact
       `JOURNAL_END`, and the SENDER's OUTBOUND obligation (this
       one) clears ONLY at the matching full-triple
       `JOURNAL_ACK` (v9.9.43, round-48 Codex B1 — every
       discharge clause in this plan names its obligation:
       `JOURNAL_END` is never a sender-side discharge, a bare
       `BulkAck(u64)` or a `BulkEnd` write never clears either
       obligation, `sync_conn.go:194`, `sync_bulk.go:282`); a legacy sender ignores the
       request, and the receiver falls back to (a) after a
       bounded wait; peers whose negotiated repair version is 0
       (v0) always use (a) (v9.9.54.20 — "unnegotiated"
       named by the version machine). The repair
       path's stream hygiene is explicit (v9.9.27, round-40 Codex
       B2 — a sender quiesce cannot recall bytes already accepted
       by ANOTHER TCP stream: `I(E1)` written to delayed fab1 can
       land after `D(E1)` arrived on fab0 and an E1-absent repair
       committed, because bulk pins one connection
       (`sync_bulk.go:53`) while incrementals choose the active
       fabric (`sync_conn_write.go:268`)): the PRIMARY close-both
       path is immune by construction — every old stream is dead
       and the repair arrives on a NEW post-reset connection, so
       no old-stream byte can follow it; and the RESYNC_REQUEST
       fast path RESETS EVERY NON-SURVIVOR STREAM at repair start
       (their TCP resets discard in-flight bytes), and the
       receiver fences any straggler by repair-ID and generation
       (a frame whose generation predates the repair cutoff is
       discarded, never published — absence reconciliation
       records no tombstone, `sync.go:1080`, so the fence, not
       the transport, is the ordering guarantee off the pinned
       stream; the fence's sufficiency rests on the in-order
       argument (v9.9.28, round-41 SMR F2: the receiver's own
       `close()` of a reset stream discards its kernel receive
       buffer, so only application-accepted stragglers exist;
       those were accepted in stream order BEFORE the repair and
       route to the armed-repair freeze buffer — they flush
       AFTER the repair's `BulkEnd`, the correct recency; and a
       straggler cannot masquerade as a repair member — the
       message types differ and the repair members carry the ID
       echo). And the DECODED-handler residual is fenced at the
       publication point, not the transport (v9.9.29, round-41
       Codex B2: `receiveLoop` verifies a frame and calls
       `handleMessage` synchronously (`sync_conn_read.go:70`), so
       an old connection's handler can pass its generation check,
       pause before `PutClusterSyncedV4`
       (`sync_conn_gen.go:435`), and resume AFTER an E1-absent
       repair committed — `handleDisconnect` clears the slot but
       neither joins the handler nor revokes its started
       mutation (`sync_conn.go:480`): the repair cutoff is
       carried EXPLICITLY in the repair's wire schema (a
       `repair_cutoff_epoch` field on `BulkStart`), and EVERY
       canonical session publication revalidates
       `(connection_generation, repair_cutoff_epoch)` atomically
       inside the coordinator's canonical lock — a mutation from
       a pre-cutoff connection or a superseded repair generation
       is discarded at the publication point, never published,
       on BOTH the primary and the request paths; the
       `connection_generation` is PER-PEER monotonic (v9.9.30,
       round-42 SMR F2: a per-peer install counter bumped at
       every `installConn` — never per-connection, or two
       simultaneous connections sharing a value would let a
       pre-cutoff handler's mutation pass the fence on the
       sibling connection) — and the fence's exact stream
       identity is an OPAQUE PER-FABRIC SLOT-MEMBERSHIP TOKEN
       (v9.9.31, round-42 Codex B2: a peer-global monotone
       counter cannot distinguish the pinned repair stream from
       a later non-repair connection — advancing it either
       invalidates the valid stream or permits the later one;
       and a pending frame can be handled BEFORE `installConn`
       assigns the slot (`sync_conn.go:100`), while the
       generation guard and the canonical `Put` are separate
       operations (`sync_conn_gen.go:381, :435`): each installed
       connection is minted an opaque token BEFORE any frame
       dispatch — structured `(node/process incarnation,
       monotone counter)` so the identity is never reused
       (v9.9.33, round-43 Codex H5: "opaque" alone does not
       establish never-reused identity; and the legacy pending
       frame is handled ONLY AFTER token installation — today
       it is handled first, `sync_conn.go:119`);
       every mutation presents its connection's token;
       the repair protocol authorizes the pinned stream's token
       for the repair era; the token is revoked at disconnect
       AND AT SUPERSESSION (v9.9.33, round-43 Codex H5:
       installing C2 closes and overwrites C1's slot under
       `s.mu` (`sync_conn.go:244`), and C1's LATER disconnect
       sees the stale connection and returns without revoking
       T1 (`sync_conn.go:480`) — so the displaced token's
       revocation is atomic WITH the slot swap: T1 is revoked
       BEFORE T2 installs, and the revocation is mirrored into
       the repair commit, so a paused C1 handler can never
       publish after the repair); and the revocation's
       Go↔helper linearization is an ACKNOWLEDGED TRANSACTION
       (v9.9.35, round-44 Codex H5: ordinary supersession has no
       repair commit to mirror into, and a T1 handler can pass
       the Go check, pause, and publish after T2's slot swap
       while the helper still accepts T1 — today's helper
       publication is a separate call (`sync_conn_gen.go:435`)
       and the `SessionStore` interface carries no token or
       registry epoch (`session_store.go:50`): the slot swap
       performs a helper-side `replace(slot, T1, T2,
       token_epoch)` transaction ACKNOWLEDGED BEFORE T2's first
       dispatch, and EVERY canonical mutation and repair commit
       validates the current token epoch against the registry —
       Go and Rust share the one epoch; the transaction is
       ATOMIC (v9.9.36, round-45 SMR F3: revoke-T1 and
       register-T2 are one step — on failure (helper
       unreachable) NOTHING changes: T1 remains live, T2 is
       not installed, and the install retries; the publication
       path's epoch validation is a single atomic load,
       negligible against the map operation); and the outcome
       and family-side-effect contracts are complete (v9.9.37,
       round-45 Codex H5: helper IPC has unreachable/hung
       outcomes (`manager_ha.go:1771, :1806`), and a cluster
       install writes forward, reverse, and DNAT state
       SEQUENTIALLY (`session_store.go:274, :284, :289`) with
       reverse writes bypassing helper validation
       (`manager_ha.go:1125`) — a T1 handler can commit its
       forward, be superseded, then resume stale reverse/DNAT
       writes: the `replace` CAS is IDEMPOTENT AND QUERYABLE —
       on a lost ACK, Go QUERIES the registry keyed on the
       EXACT T2 VALUE (monotone never-reused tokens — T2-present
       means THIS attempt's commit, never a stale aborted
       attempt's, v9.9.38, round-46 SMR F4) (T2 present → the
       commit landed; absent → retry), and the slot is STAGED
       NON-DISPATCHABLE while the outcome is uncertain, with
       bounded retry and the repair/not-ready fallback; and
       EVERY family side effect (forward, reverse, DNAT) is one
       epoch-validated transaction — each write validates the
       presented token epoch, and a superseded epoch rolls the
       whole family write back atomically; and the transaction
       is serialized with replacement (v9.9.39, round-46 Codex
       H2: T1 can write its forward row
       (`session_store.go:274`), T2 can replace T1 while helper
       IPC has released `m.mu` (`manager_ha.go:1779`), and T1
       resumes at the reverse/DNAT writes
       (`session_store.go:284, :289`) — a blind snapshot
       rollback (`session_store.go:237`) could restore prior
       rows over T2, while declining rollback leaves T1's
       partial family; and reverse writes bypass helper
       validation today (`manager_ha.go:1125`): the family
       transaction holds a shared FAMILY-TRANSACTION PERMIT
       from its first write to its last — HELPER-ISSUED
       (v9.9.40, round-47 SMR F1: Go acquires it with the
       family's first write, identified by the canonical key;
       the helper tracks outstanding permits in the same
       transaction context as `replace(slot, T1, T2,
       token_epoch)` — the map writes are helper-owned state, so
       a Go-only permit would leave the reverse/DNAT writes
       outside the drain's reach) — `replace(T1, T2)`
       DRAINS or CAS-invalidates outstanding family permits
       before retargeting (the drain never waits indefinitely:
       a family transaction carries its own deadline — µs-ms
       for three sequential map writes — after which `replace`
       CAS-invalidates it, preserving availability), and the rollback is token-conditional
       CAS per preimage — a preimage is restored only if the
       row's current token still matches T1, never a blind
       restore-over).
       and the canonical transaction (Go AND the mirrored Rust
       side) checks the presented token's validity and
       repair-era authorization ATOMICALLY with the
       publication — so a handler paused with a then-valid token
       whose connection was revoked mid-handler is discarded AT
       PUBLICATION, never at handle time; and the minting is
       monotone never-reused (a per-node u64 counter — no ABA
       after revocation, v9.9.32, round-43 SMR F2)). The repair
       ID also orders the repair's CONTENTS, not just its
       completion (v9.9.23, round-38 Codex B2: `BulkSync` pins one
       connection (`sync_bulk.go:53`) while queued incrementals
       choose whichever fabric is currently active
       (`sync_conn_write.go:268`) — repair N's bulk on delayed
       fab1 carries E1's older INSTALL while fab0 delivers E1's
       fresh higher-generation DELETE first
       (`sync_conn_gen.go:156`), and the delayed fab1 `BulkStart`
       then clears the tombstone via `resetRecvGen`
       (`sync_conn_read.go:183`, `sync_conn_gen.go:324`), letting
       the stale INSTALL publish and the exact-N `BulkEnd`
       reconcile/ACK/discharge with B holding stale E1): while a
       repair obligation is armed, the receiver FREEZES
       incremental application — incoming installs/deletes on any
       fabric BUFFER (in order) rather than publishing — and
       flushes the buffer AFTER the repair's BulkEnd lands (the
       buffered DELETE then lands after the repair's older
       INSTALL, restoring recency by construction); and the
       SENDER takes a CUTOFF at repair start (v9.9.24, round-39
       Codex B2 — buffering what the receiver OBSERVES before
       BulkEnd does not cover frames delayed until after it:
       `BulkSync` pins one connection (`sync_bulk.go:53`) while
       `sendLoop` drains opaque frames over whichever connection
       is active (`sync_conn_write.go:268`), so a stale pre-repair
       INSTALL can land after an E1-absent repair has reconciled
       — and absence reconciliation records no generation
       tombstone, `sync.go:1080`): the sender PAUSES incremental
       emission when it arms the repair — and the pause is a
       QUIESCE-AND-JOIN of the `sendLoop`, not merely an enqueue
       gate (v9.9.25, round-39 SMR F2: the `sendLoop` retries an
       already-dequeued frame on whichever connection becomes
       active, `sync_conn_write.go:268`, so an enqueue pause alone
       lets a pre-cutoff frame land post-`BulkEnd` from the retry
       path — the cutoff is taken with the sendLoop's retry loop
       JOINED — and frames re-queued DURING the join (a fabric
       flap mid-join pushes them back through the paused enqueue
       gate) are tagged pre-cutoff and DISCARDED, because the
       cutoff snapshot subsumes their state: the join's
       completion is a real fixed point, so no frame that
       entered the system before the cutoff can land after
       `BulkEnd`), FLUSHES the pre-cutoff
       queue, takes the snapshot (the snapshot IS the cutoff —
       every pre-cutoff frame is either flushed before
       `BulkStart` or subsumed by the snapshot), drives the bulk,
       and resumes incrementals only after `BulkEnd` — no
       pre-cutoff frame can ever land after the repair. The bulk
       itself is TRANSACTIONAL: its member installs AND the
       generation-map reset are STAGED and committed only when a
       matching `BulkEnd` validates (all-or-nothing — an aborted
       bulk, or one superseded by a newer obligation O2 mid-way,
       commits nothing, so O1's partial members and generation
       wipe can never leak in; the freeze/repair buffer's own
       overflow INVALIDATES the repair and raises a fresh
       obligation generation rather than committing partial
       state); and repair epochs are namespaced by the
       authenticated SENDER INCARNATION (the sender's
       process-local bulk counter restarts on restart
       (`sync.go:474`, `sync_bulk.go:65`), so epoch 1 from a
       restarted sender can never exceed the receiver's old
       raising point — the comparison key is
       `(sender_incarnation, bulk_epoch)`); the POST-CUT window is
       bounded and its delivery gates discharge (v9.9.27,
       round-40 Codex H4: during a long joined repair, explicit
       producers keep queueing into the 4,096-frame channel
       (`sync.go:805`, `sync_conn_write.go:14`) — installs merely
       arm backfill while deletes enter the journal
       (`sync_conn_write.go:36, :69`), and a `BulkEnd` that
       WOULD discharge B's obligation/readiness before the next
       sweep replays that window leaves a takeover missing E2
       or retaining deleted E1 — the hazard; under this design a
       `BulkEnd` NEVER discharges anything: readiness moves only
       on the applied `JOURNAL_END` (v9.9.41, round-47 Codex
       B1): post-cut frames enter a BOUNDED
       post-cut journal; journal overflow INVALIDATES the repair
       and re-arms the obligation with a fresh generation (never
       a silently-truncated window); and the obligation
       discharges ONLY after the post-cut window has been
       DELIVERED and ACKNOWLEDGED — with the terminal ordering
       pinned (v9.9.29, round-41 Codex H5: the journal seals at a
       SECOND cutoff (it closes when the repair's bulk completes
       on the sender), transmits IN ORDER on the SAME pinned
       repair stream (never the active-fabric lottery,
       `sync_conn_write.go:268`), and terminates with an
       explicit JOURNAL-END marker (an additive frame); the
       receiver's readiness moves ONLY on APPLYING the marker
       (bulk commit AND journal application both complete —
       never on the bulk's `BulkEnd`), and the sender's
       obligation clears ONLY at the matching `JOURNAL_ACK`
       (v9.9.43) — so a post-cut E2 delta
       delayed on another fabric can never arrive after
       readiness cleared, because readiness clears only at the
       marker — and this rule SUPERSEDES every older
       "clears on a clean `BulkEnd`" clause (v9.9.31, round-42
       Codex H5: `JOURNAL-END` carries and validates the exact
       current repair ID plus the journal epoch/terminal
       sequence, and ONLY that validation discharges the
       negotiated repair obligation; a crash before the marker
       leaves the obligation armed and the partial journal is
       superseded by a new full repair; the marker validation is
       IDEMPOTENT (v9.9.32, round-43 SMR F5: the
       receiver→sender ACK can be lost, the sender's OUTBOUND
       obligation persists and re-kicks the repair, and the
       receiver treats a duplicate repair carrying the same
       repair ID as a no-side-effect revalidation — the bulk is
       loss-free and already committed, so it re-ACKs without
       re-mutating); the normative §5.8 wire
       schema gains `repair_cutoff_epoch` on `BulkStart`, the
       repair-ID echo on the bulk markers, the optional declared
       member count, and the `JOURNAL-END` frame — additive,
       rolling-gated like the identity tails); a sender crash/restart mid-repair is equally
       pinned (v9.9.30, round-42 SMR F5: the obligation stays
       undischarged BY DESIGN, and the sender's NEW incarnation
       — new `origin_process_nonce` — supersedes every
       outstanding repair obligation from the old incarnation,
       because repair epochs are `(sender_incarnation,
       bulk_epoch)`; the new incarnation's cold-prime bulk IS
       the new repair, so no protocol-level recovery path is
       needed for a half-flushed journal). The staging itself has a capacity and
       progress contract (v9.9.27, round-40 Codex H5: `BulkStart`
       advertises no member count and the per-payload 16 MiB cap
       (`sync_conn_read.go:62`) leaves aggregate staged state
       unbounded, while a missing `BulkEnd` would retain it
       forever; an arbitrary fixed cap would loop
       invalidate/re-bulk on a legitimate full table): the staged
       budget is CONFIGURED-CAPACITY-based (v9.9.29, round-41
       Codex B4 — the table-DERIVED budget loops forever on an
       empty or light receiver, which can never size a legitimate
       full snapshot from A; the session-table capacity is
       CONFIGURED, so a legitimate full table ALWAYS fits —
       optionally tightened by an authenticated declared member
       count on `BulkStart`, additive and bounded by capacity);
       a repair DEADLINE bounds the staged state (deadline or
       connection teardown releases it — never an indefinite
       pin), and progress is
       guaranteed by an INVISIBLE SHADOW with an atomic
       visibility switch (v9.9.29, round-41 Codex B4 — the
       shadow-chunked commit contradicted the no-partial-
       visibility rule: row application becomes live immediately
       today (`sync_conn_gen.go:452`, `session_store.go:257`)):
       the staged rows apply to an INVISIBLE shadow store (not
       visible to lookups), committed atomically at `BulkEnd`
       validation — with the commit's REAL storage semantics and
       the capacity contract stated (v9.9.31, round-42 Codex B4:
       "a legitimate full table always fits" is FALSE for
       asymmetric peers — import capacity derives from the
       receiving node's own workers and limits
       (`session_import.rs:24, :61`), and the control plane
       explicitly recognizes a larger peer can legitimately
       exceed a smaller receiver (`protocol_status.go:259`) — so
       capacity compatibility is an HA-READINESS PREREQUISITE
       negotiated at the handshake (peers exchange capacity; an
       asymmetric pair reports a DEFINED DEGRADED STATE — HA
       repair incomplete-by-config, operator-visible — rather
       than looping rollback/retry forever); and the atomic
       root swap has no matching storage primitive — session,
       DNAT, and conntrack are SEPARATE fixed BPF maps updated
       per key (`bpf_maps.rs:8`, `bpf_map/mod.rs:48`), companion
       rows published sequentially (`session_store.go:257`), and
       a whole-root swap would lose a locally-authoritative E2
       admitted after shadow creation: the commit is a QUIESCED
       REBUILD with explicit availability semantics — dataplane
       lookups pause briefly (a bounded, stated unavailability
       window for a repair event), the maps are rebuilt from the
       shadow with LOCALLY-AUTHORITATIVE entries admitted after
       shadow creation MERGED AND REVALIDATED at commit
       (peer-owned state comes from the shadow;
       locally-authoritative state is preserved by the merge,
       never root-swapped away — the merge's precedence is
       locally-authoritative-WINS (v9.9.32, round-43 SMR F4: the
       shadow carries only peer-owned state, so a
       locally-authoritative E2 admitted after shadow creation
       is preserved and any shadow row aliasing its tuple is
       discarded by the incarnation/identity fence; and the
       rebuild quiesce and the migration gate's quiesce
       SERIALIZE on the coordinator's single-threaded lifecycle
       — one quiesced operation at a time, no cross-quiesce
       deadlock possible), and lookups resume — or the
       whole repair rolls back, with no partial visibility at
       any point. The rebuild's stop contract and the
       capacity/conflict rules are pinned (v9.9.33, round-43
       Codex B3 + M8): (a) the capacity negotiation is
       GENERATION-TAGGED (worker count is a binding-plan input,
       `planning.rs:93`, so capacity re-negotiates whenever the
       plan changes); (b) the commit PREFLIGHTS the complete
       peer/local union against every target map — B's own
       locally-born flows publish into the same shared map
       (`poll_descriptor/mod.rs:2560, :2591`) whose length the
       import admission compares against B's worker-derived cap
       (`session_import.rs:24, :91`), so a valid K-entry repair
       plus L local entries can exceed C: the preflight runs
       AFTER freezing admissions (v9.9.35, round-44 Codex B2 —
       an any-time preflight races local admission: workers can
       still create and publish E2 (`poll_descriptor/mod.rs:2560,
       :2591`) between the check and the quiesce): the order is
       FREEZE admissions → AWAIT quiesce → REPEAT the complete
       capacity and NAT-conflict preflight INSIDE the frozen
       interval → commit or rollback (exact by construction:
       the freeze stops NEW commits but lets in-flight
       slow-path commits COMPLETE — that drain IS the quiesce
       (v9.9.36, round-45 SMR F2) — so L cannot change in the
       frozen interval and the preflight counts the drained
       commits exactly), and on
       overflow the repair
       enters the defined degraded state (operator-visible,
       not-ready) rather than committing an over-capacity table;
       and a rejected cohort is never stranded: EVERY
       reservation rejection — not only repair-era ones — arms a
       durable cohort-scoped not-ready condition (v9.9.35,
       round-44 Codex B1: outside an active repair, no
       obligation is armed, and the sender advances its sweep
       cutoff after LOCAL ENQUEUE, not receiver acceptance
       (`sync_conn_sweep.go:137, :185`), so an ordinary
       rejected E1 would never be retried after the conflicting
       holder drops): the receiver records the rejected
       `(flow key, tuple, SessionIdentity)` cohort in a durable
       pending-rejection set — LATCHED per cohort (deduped by
       `(flow key, SessionIdentity)`) and bounded by the
       shared-table capacity (v9.9.36, round-45 SMR F1: a
       rejection can only follow a legitimate peer install
       attempt — blind packets fail earlier at the identity/gen
       checks, so no blind-reject flood exists; a legitimate
       wide config skew producing many pending cohorts is the
       CORRECT conservative posture — the standby genuinely
       lacks them) — the allocator's release path
       notifies that set on EVERY hold drop through ONE hook at
       the hold CELL's zero transition (the single release
       point — reap, rollback, GC, migration, and conversion
       all release through it, so coverage is total by
       construction, v9.9.36) (when the
       conflicting holder drops, the receiver requests the
       cohort's re-drive — a sequenced re-request on the
       existing channel — and the peer's periodic resend also
       retries it), and the node reports not-ready/degraded
       until the cohort imports — so HA readiness can never
       stand while a live flow's standby cohort is missing); the
       set's own lifecycle is complete (v9.9.37, round-45 Codex
       B1): an entry is CANCELLED on (a) a matching DELETE for
       the cohort's key (B's delete path deletes only an
       INSTALLED key today, `sync_conn_gen.go:493` — the pending
       entry must be retired explicitly, or B would stay
       not-ready for a cohort that can never import), (b) a
       clean authoritative absence (a bulk/repair whose
       VALIDATED snapshot omits the cohort — only a current,
       repair-ID-correct bulk whose `BulkEnd` validates; a
       stale/wrong-ID repair is non-mutating and can never
       cancel, v9.9.38, round-46 SMR F1), (c) a newer
       same-key identity, and (d) peer-incarnation retirement;
       and RETRY is driven by a bounded pending-set timer PLUS
       every state transition that can make the claim
       satisfiable — including LEASE GC (E2's final flow drop
       only schedules lease expiry while retaining P
       (`allocator.rs:1349`); P is actually freed later by GC
       (`allocator.rs:2138, :2292`), so the GC path ALSO
       notifies the set — the zero-transition hook covers direct
       holds, and the lease-GC notification covers persistent
       ownership; a retried cohort that loses P to a THIRD flow
       re-arms against the NEW conflicting holder with the same
       lifecycle rules (each churn cycle requires a legitimate
       owner for P, and the bounded timer independently drives
       retries — no livelock, v9.9.38));
       (c) a NAT tuple conflict — A's missing E1 claiming public
       P while B's different-key LOCAL E2 already owns P
       (`allocator.rs:1617, :1682`) — resolves LOCAL-AUTHORITY-
       WINS: E2 keeps P, E1's exact reserve fails, E1's cohort
       remains UNPUBLISHED (rejected, resend retries), and the
       repair NEVER reports E1 protected — the obligation
       remains outstanding and readiness stays degraded without
       the `JOURNAL-END` acknowledgement (a local-wins-plus-ACK
       outcome is explicitly forbidden); and (d) the stop is
       BOUNDED BY ONE DEADLINE over the WHOLE sequence
       (v9.9.35, round-44 Codex H6 — a join-only deadline leaves
       the escrow's quiesce-acknowledgement and token-handoff
       phases able to block indefinitely): ONE deadline covers
       quiesce + handoff + join (`worker_manager.rs:141, :146,
       :149, :154`, `coordinator/mod.rs:680`); the migration
       gate's WRITE permit is NEVER held across the
       quiesce/join; and on deadline expiry the rebuild ABORTS —
       XSK is disabled, the OLD worker/allocator/registry/escrow
       generation is retained until the workers actually exit,
       and every late publication is rejected (readiness
       degraded, never a silent half-rebuilt table); the
       terminal state is RECOVERABLE and operator-visible
       (v9.9.36, round-45 SMR F4: the failure surfaces through
       the existing reconcile-stage reporting (#6244); the old
       generation's retention is what lets the NEXT reconcile
       attempt retry with a fresh generation; and force-killing
       the stuck worker is explicitly rejected — kernel-state
       corruption risk) — GATED BY A DURABLE TEARDOWN-FAILED
       LATCH (v9.9.37, round-45 Codex B4: a deadline expiry
       BEFORE quiesce acknowledgement can leave an old worker
       inside its loop — it checks stop only at
       `loop_body/mod.rs:332` — able to publish BPF/shared/DNAT
       state later (`poll_descriptor/mod.rs:2578`), while the
       escrow contract would let the next reconcile bring up
       another dataplane whose replay/allocate races the
       never-handed-off holds: rebind/reconcile is PROHIBITED
       while the latch is set — it clears only when EVERY
       unquiesced old worker has exited (or the process
       restarts); the retained generation AND the latch are
       operator-visible, and the documented recovery action for
       a latch that outlives the workers' ability to exit is a
       process restart). and a bulk
       whose ID is not the current repair ID is WHOLLY
       NON-MUTATING — its `BulkStart` does not `resetRecvGen`,
       its installs do not publish, its BulkEnd neither
       reconciles nor ACKs (it is quarantined/discarded, never
       "applied but unable to discharge" — today's handlers would
       otherwise publish every INSTALL and reconcile every
       completed bulk immediately, `sync_conn_read.go:98, :241`).
       The generation reset itself becomes transactional
       (v9.9.23.1, round-38 AGY Q3a — a PRE-EXISTING master
       hazard the repair protocol must not inherit: `BulkStart`
       wipes the receiver's generation maps via `resetRecvGen`
       (`sync_conn_read.go:183`, `sync_conn_gen.go:324, :340`)
       BEFORE the bulk validates, and a mismatched/aborted
       `BulkEnd` (`sync_conn_read.go:228-239`) then leaves the
       maps cleared with `bulkInProgress` set — stale messages
       bypass the generation checks and the standby
       desynchronizes): the reset is STAGED with the bulk and
       applies only when the bulk's BulkEnd validates (an
       aborted or wrong-ID bulk never touches the generation
       maps).
       The repair covers SENDER-SIDE in-flight loss identically
       (v9.9.23, round-38 SMR F2: during the close→detect window
       A's outbound queue keeps accepting and transmitting deltas
       into dying sockets; the cold-prime/repair FULL bulk
       reconstructs those too — the repair is not limited to
       receiver-park drops).
       (c)
       OBLIGATION BOOKKEEPING, direction-split and
       generation-specific (round-36 Codex B1: bulk epochs are
       allocated at `sync_bulk.go:65` but the pending epoch is
       installed only near BulkEnd, `:169`, and TODAY's ACK
       handler accepts any epoch not lower than pending (the
       pre-design behavior this plan replaces: under the
       negotiated protocol a bare `BulkAck` never discharges —
       only `JOURNAL_ACK`, v9.9.41),
       `sync_conn_read.go:257` — a delayed pre-obligation ACK, or
       an ACK for obligation O1's bulk after a second overflow
       O2, must never discharge the current obligation): the
       RECEIVER keeps an INBOUND-REPAIR obligation, cleared only
       after APPLYING the exact `JOURNAL_END` (v9.9.39,
       round-46 Codex B1 — direction-explicit); the SENDER keeps an
       OUTBOUND-BULK obligation, cleared only at the matching
       full-triple `JOURNAL_ACK` (v9.9.39 — this supersedes
       "the exact ACK for a bulk started after the applicable
       obligation generation" and every other bulk-ACK
       discharge; a bare `BulkAck(u64)` never clears); and a FAILED
       redrive is explicitly re-kicked (while
       `bulkRedriveInFlight` is set, another disconnect loses the
       CAS trigger and completion currently only clears the
       flag, `sync_conn.go:594`: the obligation, not the CAS, is
       the durable state — and its completion is the matching
       full-triple `JOURNAL_ACK`, never a clean replacement bulk
       on its own (v9.9.41, round-47 Codex B1); failure re-arms
       the drive). A second overflow
       while an obligation is outstanding re-arms the
       raising-point generation. During the outage the
       sender's own send queue fills and self-arms
       `syncBackfillNeeded` (`sync_conn_write.go:46`), holding its
       sweep window; on reconnect the config-first ordering (3)
       applies the config BEFORE the re-driven bulk, the park
       drains, and the full resync plus the sender's held-window
       replay restore everything. With a stuck apply (#6387) the
       park latches again after the next buffer of churn — the
       cycle repeats at reconnect/bulk cadence (not hot), the node
       stays operator-visible via `configSyncFailing`, and (5)
       keeps it from mastering; progress is guaranteed whenever the
       config can apply.
       (5) THE TAKEOVER FENCE: a node whose config apply is stuck
       (the #6387 `configSyncFailing` condition — diagnostic-only
       today, `manager.go:321`, `readiness.go:20`) is NOT
       transfer-ready for takeover until BOTH (a) its published
       forwarding epoch reaches the peer's high-water — where the
       peer high-water itself advances from EVERY authenticated
       observed session INSTALL epoch, not only Config frames
       (v9.9.19, round-34 Codex H4: the authority can publish/admit
       under C2 before the peer push, `daemon_apply_commit.go:245,
       :270`, so a Config-only high-water at
       `sync_conn_read.go:301` lags the sessions it must cover) —
       AND (b) its parked queues are EMPTY with no outstanding
       repair (a successful apply advances `lastAppliedConfigGen`
       and clears `applyingConfigGen` immediately,
       `sync_conn_config.go:389`; a crash in the
       apply-success→FIFO-drain interval must not promote a node
       whose parked E1 is still unapplied); the readiness gate
       gains both conditions.
       At processing time the receiver's local rule config IS the
       sender's admitting config, so the shape checks and the
       wire-carried lease inputs agree — the two mechanisms are
       complementary: deferral aligns the allocator SHAPE, the
       wire-carried stamps pin the lease-input PROVENANCE (resend/
       bulk re-emission never re-derives from queue-time state).
       (Rejected alternatives: exact-epoch deferral ON THE SENDER
       cannot work — the sender does not know the receiver's apply
       watermark; NACK/backfill adds a protocol ack for a problem
       the receiver can solve locally.)
       **Import-transaction rollback edge (v9.9.17, round-32 Codex
       M3; transaction shape pinned v9.9.18, round-33 Codex B2):**
       inverting today's order (upsert succeeds first, NAT
       reserved after, `upsert_synced.rs:64`) into
       create-or-retain-BEFORE-publication opens an orphan edge: a
       replay can reserve P and then lose a later check (the
       locally-authoritative-entry check, `install.rs:310`), leaving
       an orphan lease at `active_flows=1` that expiry GC will not
       reclaim (`allocator.rs:2302`). But the naive fix — bare
       `rollback_flow(flow, tuple)` on failure — is NOT the inverse
       of the reservation (round-33 Codex B2, both traces
       code-verified): (a) `reserve_flow`'s replacement path removes
       the displaced record and frees its port BEFORE attempting the
       new claim (`allocator.rs:1671`), so a failed replacement
       (replacement E2's Q is owned elsewhere, `:1682`) leaves the
       displaced E1's PUBLISHED decision pointing at unreserved P —
       another flow claims P through the normal path, the
       prohibited reverse-NAT alias; and (b) an idempotent replay's
       exact same-flow reservation is a NO-OP (`allocator.rs:1636,
       :1944`), while `rollback_flow` unconditionally removes the
       current record and decrements/frees (`:1398, :1405, :1419`),
       so a post-retain failure would destroy ownership that existed
       BEFORE this import. The import reservation is therefore
       NON-DESTRUCTIVE-ON-FAILURE and returns a TYPED UNDO RECEIPT:
       in one allocator critical section, evaluate the request
       against current state and return `NoChange` (idempotent
       replay — the exact record already exists; nothing was
       mutated, nothing to undo), `Inserted` (a new per-flow record
       / new lease was created), `Retained` (an existing lease's
       co-holder count was incremented), or `Replaced(old_state)`
       (the displaced record's complete prior ownership state —
       translated tuple, persistent-key membership, address-only
       token — captured; the new claim attempted only after the old
       state is preserved, and on claim failure the old state is
       reinstated IN THE SAME CRITICAL SECTION so a failed
       replacement never leaves the incumbent unreserved). The
       import transaction is then: preflight every check that does
       not require the reservation → reserve-with-receipt → publish
       — and ANY post-reservation failure (including the publish
       path and panic unwind) invokes the RAII guard, which undoes
       EXACTLY the receipt's mutation (`NoChange` → nothing;
       `Inserted` → remove the record/lease; `Retained` → decrement
       the lease refcount; `Replaced(old_state)` → remove the new
       record and reinstate `old_state`) — never a blind
       `rollback_flow` of whatever the flow currently maps to.
       **Single reservation point (v9.9.19, round-34 Codex B2):**
       the receipt alone does not make reserve→publish one
       transaction across WORKERS — the coordinator publishes the
       canonical shared entry first (`ha/session_import.rs:115`),
       then fans the identical entry to EVERY worker
       (`ha/session_import.rs:215`), each importing independently
       (`session_glue/mod.rs:744`) through one Arc-shared allocator
       (`allocator.rs:742`): W0 reserves F/P (`Inserted`); before
       W0 publishes, W1 observes F/P (`NoChange`) and publishes E1;
       W0's covered post-reservation failure then removes F/P under
       W1's live entry, and E2 claims P through the normal bitmap
       CAS (`allocator.rs:1018`). The reservation therefore moves
       OUT of the per-worker import entirely: the coordinator's
       import entry point performs the reserve-with-receipt ONCE,
       BEFORE canonical publication and fan-out — one transaction,
       one receipt, one rollback site, no cross-worker pending
       window — and on receipt-failure the install is rejected
       before ANY worker (or the canonical shared entry) ever sees
       it; per-worker fan-out imports (and later materializations,
       `session_glue/mod.rs:1157`) find ownership already committed
       and NEVER create or mutate it (their `NoChange` is an
       assertion against committed state, not a transaction). The
       receipt's inverse captures the FULL mutation, not just a
       refcount: `Retained` records and restores the complete delta
       (the `live_by_flow` record, the expiry-index entries, the
       activation metadata, `active_flows`, and for address-only
       the reverse-owner token, `allocator.rs:1238, :2018`), and
       `Replaced(old_state)` DUAL-HOLDS the old and new ownership
       from the critical section until the transaction commits (the
       old tuple cannot be claimed between allocator unlock and a
       later rollback — preserving the DATA alone would leave P
       claimable in that window). **The holder DISTRIBUTION is a
       coordinator-owned GROUP-HOLD (v9.9.20, round-35 Codex B2 —
       "workers never create or mutate ownership" contradicts the
       plan's per-entry retain contract (:915's every-replica
       retain, :1650's per-worker token-Drop decrement, :1710's
       retain-at-commit) under a scalar refcount: coordinator
       reserve = one holder, W0/W1 add none, and W0's independent
       reap (`loop_body/mod.rs:1481`) would release the SOLE holder
       while W1 still forwards E1, freeing P under a live replica):
       the coordinator's reservation produces ONE group-hold object
       per imported flow (an `Arc`); the canonical shared entry,
       its synthesized REVERSE companion (`ha/session_import.rs:104`
       — a separately published family member,
       `coordinator/mod.rs:753, :771`, whose clone keeps the
       family-cohort accounting exact),
       every fanned-out worker entry, every later materialization
       (`session_glue/mod.rs:1092, :1157`), and the escrow keeper
       each hold a CLONE of that Arc; worker-entry reap and
       token-Drop drop their clone — they NEVER touch the allocator
       directly — and the allocator reservation releases exactly
       when the LAST clone drops (canonical + all replicas +
       materializations + escrow) — v9.9.33, round-43 Codex B2:
       the Arc finalizer is only the DETECTION mechanism for the
       last reference; the release itself is the per-credit
       HOLD CELL's zero transition (the Arc never owns a count
       of its own — the single-counter rule of v9.9.31 governs
       every release path, and no text in this plan prescribes a
       separate Arc-side release). The per-entry "retain" contract
       is thereby re-expressed as clone distribution at fan-out/
       materialize time (not per-entry allocator mutations): the
       early-replica-reap trace dies by construction (W0's reap
       drops only its clone; the reservation lives until W1's and
       the canonical clones also drop), the "NoChange only" clause
       and the per-entry-release clause reconcile (workers mutate
       no allocator state, yet every entry holds lifetime), and the
       coordinator's receipt undo applies to the group-hold's
       creation — a failed/rejected import never distributes a
       clone, so no replica can ever hold lifetime the coordinator
       rolled back. The token representation is TYPED, one
       unambiguous lifecycle per variant (v9.9.21, round-36 Codex
       H2 — the direct-holder and group-holder models must never
       share one undifferentiated drop path: coordinator-only
       reservation with today's direct per-worker reap
       (`loop_body/mod.rs:1491`) would free the sole reservation
       under surviving clones; direct retains with clone-only reap
       would never drain): `NatHoldToken` is an enum —
       `DirectHold` for LOCALLY-BORN allocations (today's model,
       unchanged: the dataplane allocation registers a direct
       allocator refcount holder per entry; reap/panic-Drop
       decrements the allocator refcount directly;
       `upsert_synced.rs:80`-style per-entry reserve applies only
       here) and `GroupHold(Arc<GroupHold>)` for IMPORTED flows
       (clone distribution; reap/panic-Drop drops only the clone;
       the allocator releases exactly when the last clone drops —
       and that finalizer NEVER runs inline (v9.9.22, round-37
       Codex H6: an inline finalizer can fire in contexts holding
       `A.live` or the migration gate's WRITE permit and deadlock
       on the gate READ): the last-clone Drop ENQUEUES the release
       to a lock-free deferred-release queue drained by a context
       holding no other locks, which performs the
       `slot.with_current()` release following the declared
       canonical→allocator lock order and NEVER reacquires
       canonical locks from inside allocator cleanup). The
       lifecycle sites per variant: FAN-OUT — DirectHold: each
       worker replica verify-and-retains (direct increment);
       GroupHold: each worker replica receives a clone from the
       coordinator's fan-out. REVERSE SYNTHESIS — DirectHold: the
       reverse entry's hold references the FORWARD allocation and
       releases through its refcount (per the earlier rule);
       GroupHold: the reverse companion receives its own clone at
       synthesis. MATERIALIZATION — DirectHold (a locally-born
       shared entry): the consumer's verify-and-retain registers a
       direct holder; GroupHold (an imported shared entry): the
       materialize clones the PUBLISHED entry's group-hold (never
       a direct allocator mutation). REPLACEMENT — DirectHold:
       retain-before-replace transfers the direct hold atomically
       (`install.rs:322`); GroupHold: the replacement is
       IDENTITY-CONDITIONAL (v9.9.22, round-37 Codex B3 — the
       worker sink replaces any prior same-key entry
       (`install.rs:310, :322`), so for E1/P1/G1 → E2/P2/G2 a
       literal "take the displaced entry's clone" leaves worker
       E2 holding G1 while the coordinator's deletion removes
       E2's canonical/reverse G2 clones before queuing worker
       deletes (`session_import.rs:290, :313`) — P2 reclaimed
       under a forwarding E2): IDENTICAL ownership (same
       incarnation AND allocation) reuses the displaced clone
       (clone-then-drop in one step — the count never dips);
       DIFFERENT incarnation/allocation installs the INCOMING
       entry's G2 clone FIRST and only then drops G1
       (retain-before-replace at the group level — the incoming
       hold is distributed with the incoming entry and the
       displaced hold drops after the replacement publishes).
       PROMOTION/DEMOTION (v9.9.22, round-37 Codex H4): hold
       provenance is IMMUTABLE and carried INDEPENDENTLY of
       `SessionOrigin` — origin mutates in place (imported →
       `SharedPromote` at `promote.rs:99, :116`, locally-born →
       `SyncImport` at `install.rs:542`, and `SharedPromote` is
       not peer-synced per the origin predicate, `entry.rs:245`)
       and projections reduce entries to key/decision/metadata
       (`shared_ops.rs:638`), so the variant can NEVER be derived
       from origin: the token's own enum tag is the provenance,
       carried through promotion, demotion, commands,
       `SyncedSessionEntry`, `ForwardSessionMatch`, synthesis, and
       materialization; a promoted imported flow KEEPS its
       GroupHold (the origin flip touches no allocator state —
       no retain is needed at promote and no variant transition
       ever occurs; the DirectHold path applies to EVERY
       locally-admitted allocation path (v9.9.23, round-38 Codex
       H5 — not just `allocate_translation`: deterministic PAT
       (`source.rs:1431`), deterministic NAT64 (`source.rs:995`),
       address-only round-robin (`source.rs:1523`), and persistent
       address-only (`source.rs:1497`) admit locally too and hold
       `DirectHold`), never to promoted imports). The token's enum
       tag is the provenance, but the CARRIAGE rule separates the
       two variants (v9.9.23, round-38 Codex H5 — "the tag travels
       through commands" contradicted the replay rule that queued
       commands contain no hold token (:1732)): `DirectHold` is
       LINEAR and never cloned — a queued command that would need
       one references the durable coordinator registry entry
       instead (the side-map token is inserted by the executing
       worker from the registry, never by the queue); `GroupHold`
       clones are freely clonable BY DESIGN — fan-out, commands,
       and detached carriers each hold a clone, which is exactly
       the distribution model. The registry and the cross-variant
       transition are pinned (v9.9.24, round-39 Codex H4): the
       clonable descriptor is `AllocationRef { slot,
       allocation_id, SessionIdentity }` — references, never
       ownership; the DURABLE coordinator registry is keyed by
       allocation id, keeps a strong reference per live
       allocation, and retires an entry only through the same
       ownership paths (it persists across stop/rebind exactly
       like the escrow — the detached snapshots and commands that
       are freely cloned today (`runtime.rs:408`,
       `coordinator/mod.rs:753`) carry `AllocationRef`s, and the
       executing worker rehydrates the hold from the registry —
       claim-then-execute (v9.9.26, round-40 SMR F4: the worker
       takes a STRONG registry reference at dequeue, so registry
       retirement can never race a rehydrating command — the
       retired entry's strong reference lives in the executing
       worker's hand until the command completes);
       and a peer-state REPLACEMENT of a locally-born or demoted
       `DirectHold` entry (the in-place demotion at
       `install.rs:542` then a permitted peer replacement,
       `upsert_synced.rs:29`) NEVER mints an uncredited
       `GroupHold` over the direct reservation (the eventual
       direct release would free P beneath the imported
       replacement): the direct hold CONVERTS atomically — in one
       allocator critical section, a `GroupHold` is minted owning
       the SAME reservation and the direct count is decremented
       as the group registers (the entry's token variant swaps;
       and the conversion can never race a local re-promotion
       (v9.9.26, round-40 SMR F4: a demoted entry re-promoted
       locally to `SharedPromote` before the peer replacement
       lands is locally authoritative and IMMUNE to the
       replacement — the candidate-class re-validation skips it
       first, per the mixed-version matrix — so the conversion
       only ever runs on an entry that is still peer-owned at
       commit time);
       the hold itself is a stable shared CELL, ending the
       publication-gap release race (v9.9.29, round-41 Codex B3:
       converting inside the allocator critical section and then
       unlocking before canonical publication leaves the old
       `DirectHold` reachable from the incumbent worker/canonical
       entry — a worker reap (`loop_body/mod.rs:1481`) or a
       canonical replacement (`shared_ops.rs:897`) can decrement
       the direct credit a SECOND time before E2 publishes; and
       the version fence had no shared linearization point
       (promotion mutates the worker table first, `promote.rs:99`,
       and publishes canonical later at `:131-138`): no token
       carries its variant — every token (a `DirectHold` or a
       `GroupHold` clone) points at a per-allocation HOLD CELL,
       whose content (variant, ownership count) swaps atomically
       inside the allocator critical section (conversion IS the
       cell's content swap); every `Drop` routes through the
       cell's CURRENT state at drop time, so a pre-conversion
       token and a post-conversion clone decrement the SAME cell
       and the reservation releases exactly when the cell
       reaches zero — double-release and pin-loss are
       structurally impossible; and promotion, reap, replacement,
       and conversion participate in ONE canonical version/CAS
       (the canonical entry's version covers origin, identity,
       AND the hold-cell content — a worker-table mutation
       happens only after the CAS wins, so the promote-first-
       worker-then-canonical ordering can no longer split the
       linearization) — and the cell is the ONLY ownership
       model (v9.9.31, round-42 Codex B3: the
       `DirectHold`/`GroupHold(Arc)` text as a TWO-counter
       duality conflicts with the cell — a pre-conversion direct
       token could outlive the last Arc's finalizer, or the Arc
       finalizer and the cell count could release the same
       credit twice: the duality collapses to reference
       FLAVORS over the single per-credit cell counter — a
       "direct" hold is a linear reference to the cell, a
       "group" hold is a clonable reference to the SAME cell;
       the Arc is only the reference mechanism and never owns a
       count of its own, so exactly one counter exists per
       credit and exactly one release fires at zero);
       and the canonical side gains a coordinator-global
       ROW VERSION on `SyncedSessionEntry` (v9.9.31 — the
       conversion recheck cannot be the worker-local
       `install_epoch` (`session/mod.rs:737, :1384`; the
       canonical `SyncedSessionEntry` has no corresponding
       version, `worker/mod.rs:375`): the canonical row version
       is bumped by every canonical mutation — PER-ENTRY, never
       a global counter (v9.9.32, round-43 SMR F3: a global
       version would serialize unrelated conversions into an
       availability hazard; unrelated entries never contend),
       and the
       conversion is an explicit PENDING-CONVERSION transaction
       — prepare (read row version + identity), execute the
       cell swap, COMMIT by CAS on the row version, with
       promotion/reap/replacement joining the same CAS domain,
       so the promote-first-worker-then-canonical ordering
       (`promote.rs:99, :131`) can no longer split the
       linearization); the cell's own ordering is pinned
       (v9.9.30, round-42 SMR F3: the cell swap is
       COUNT-PRESERVING across variants (direct 1 → group 1);
       the canonical version/CAS runs after the allocator
       section releases, per the no-nesting rule; a reap landing
       between them decrements the CELL — the single counter, so
       order-safe; a CAS failure swaps the cell BACK, which is a
       no-op if the cell already released — the
       `Converted(old_state)` undo IS the swap-back, never a
       variant-specific decrement). With the cell,
       the receipt×variant transition matrix (v9.9.27, round-40
       Codex B3 — `NoChange` is defined as no-mutation/no-undo,
       so the conversion CANNOT be a `NoChange` arm: it is its own
       receipt): `NoChange` on a
       DirectHold incumbent is IMPOSSIBLE for a peer replacement —
       the arm is `Converted(old_state)`, a mutation receipt with
       its own exact undo — the count-preserving CELL SWAP-BACK
       (v9.9.33, round-43 Codex B2: this supersedes the earlier
       "re-increment the direct count and drop the minted group
       clone" — under the single-counter hold cell there is no
       variant-specific decrement; the undo swaps the cell's
       content back, a no-op if the cell already released), and the conversion is conditioned on a
       VERSIONED identity/origin recheck serialized with commit
       (the demoted entry's origin/identity version at reserve
       time must equal the version at publish-commit — the
       version is the canonical PER-ENTRY ROW VERSION
       (v9.9.33, round-43 Codex B2: this supersedes the v9.9.28
       `install_epoch` declaration — `install_epoch` is allocated
       independently per worker `SessionTable`
       (`session/mod.rs:737, :1384`) and the canonical
       `SyncedSessionEntry` has no counterpart
       (`worker/mod.rs:375`): the canonical row version is a
       per-entry CAS field on `SyncedSessionEntry` itself, valued
       from a never-reused coordinator sequence and refreshed
       across deletion/reinsertion; `admission_config_version`
       remains the write-once admission stamp and is NOT this
       either; the recheck reads
       `(row_version, SessionIdentity)` inside the entry's
       table critical section — an
       intervening local re-promotion (`promote.rs:99`) bumps the
       version, the commit fails the recheck, and the
       `Converted(old_state)` undo restores the direct hold
       exactly, closing the demote→convert→re-promote→reject
       schedule); `NoChange` on a
       GroupHold incumbent → clone; `Inserted` → new hold of the
       appropriate variant; `Retained` → increment within the
       incumbent's variant; `Replaced` → per the
       identity-conditional rule). ALLOCATION-INSTANCE IDENTITY (v9.9.23,
       round-38 Codex B3 — the identity-conditional replacement
       fixed P1→P2 ordering but not a NEW incarnation reusing the
       SAME flow key K and tuple P: `SourceNatFlowKey` carries no
       session identity (`source.rs:144`), an exact `(K,P)`
       reserve is a no-op (`allocator.rs:1664`), so a
       different-incarnation G2 over the same `(K,P)` receives no
       new allocator credit — and G1's later deferred release by
       `(K,P)` (`allocator.rs:1318`) would remove ownership
       beneath the live E2, freeing P for reissue
       (`allocator.rs:1007`)): `LiveAllocation` gains an
       immutable ALLOCATION GENERATION (a u64 minted at every
       ownership creation, namespaced to the STABLE SLOT with its
       counter floor preserved across compatible retargets plus
       an allocator-instance nonce — v9.9.24, round-39 Codex B3:
       a counter restarting in each rebuilt allocator would let
       an old deferred receipt's generation match a fresh
       allocation); the group-hold and
       every deferred-release receipt carry it; a same-`(K,P)`
       `NoChange` across session incarnations TRANSFERS the
       incumbent group to the new incarnation (the incoming entry
       clones the incumbent group-hold — reservation continuity
       is by allocation generation, never re-credited); and the
       last-drop→release path is TICKETED, closing the
       pending-release ABA (v9.9.24, round-39 Codex B3's
       schedule: E1/G1's last clone drops and queues `D(K,P,g)`;
       before D drains, E2 with the same `(K,P)` arrives and
       exact-reserves `NoChange` (`allocator.rs:1664`); G1 no
       longer exists to clone, G2 references the same `g`, and
       D's drain finds the live record at `g` and removes it
       beneath the live E2 (`allocator.rs:1318`), P reissued at
       `:1007`): the last drop atomically marks
       `PendingRelease(g, ticket)` on the allocation INSTEAD of a
       bare enqueue; a same-`(K,P)` `NoChange` (or any new
       retain) atomically CANCELS/CLAIMS that ticket in the same
       critical section as its reservation check (the reservation
       continues, the pending release revoked — or, if the
       pending release already committed, the new claim is a
       FRESH allocation evaluated under the same critical
       section: P free → a genuinely NEW credit with a new
       generation; P claimed by a third flow in the interim →
       the exact-reserve fails and the import rejects (v9.9.26,
       round-40 SMR F3 — a re-resolution, not a continuation:
       the committed pending release means the reservation was
       legitimately dead, so nothing is ever "revived")); and the drain
       compares BOTH the allocation generation AND the ticket
       before removal — a claimed ticket or a moved generation is
       discarded as stale, so a queued release can never land on
       a re-acquired allocation. ESCROW — the keeper holds the variant's
       token (a DirectHold keeper or a GroupHold clone); the
       handoff/retokenization moves the variant unchanged. REAP —
       each variant drops only its own representation; and
       PANIC-DROP — RAII drops the enum, whose Drop routes by
       variant. Every earlier "register a holder in the allocator"
       clause (the :858 verify-and-retain, the per-worker
       token-Drop decrement) is scoped to `DirectHold` by this
       sentence; imported flows NEVER take the direct path.
       The allocator critical section NEVER nests
       with the canonical publish (v9.9.20, round-35 SMR F1: the
       reserve-with-receipt completes and RELEASES the allocator
       lock before `publish_shared_session` takes the canonical
       `synced → nat → forward_wire → indexes` hierarchy
       (`session_manager.rs:12-18`) — reserve → unlock → publish;
       the RAII guard re-acquires the allocator lock for a
       post-publish undo — so no thread ever holds both orders
       (import: allocator-live then synced; delete/TTL-sweep:
       synced then allocator-live) and the two-lock inversion is
       impossible by construction).
       **Capability gate (v9.9.17, round-32 Codex):** clustered
       persistent source NAT is COMMIT-TIME REJECTED today
       (`capabilities.go:87`, `persistentSourceNATHAUnsupportedReason`
       — a cluster + `persistent-nat` config fails the userspace
       capability check), so the persistent-import machinery above
       defends a currently-disarmed configuration and ships dark;
       the gate REMAINS until the lease-input capability is
       negotiated cluster-wide (the same rolling-upgrade negotiation
       that gates the INSTALL identity tail), and only then is
       persistent NAT armable on a cluster. Non-clustered persistent
       NAT is unaffected by every mechanism in this plan.
       **Temporary stop/rebind (v9.9.15, round-30 Codex B3):** the
       two-phase sequence and the durable escrow are NOT scoped to
       the reconcile sequence — they are THE worker-teardown
       discipline for EVERY stop that anticipates a later bring-up.
       `stop()` → `stop_inner(clear_synced_state = true)`
       (`stop_workers.rs:7` → `coordinator/mod.rs:429`, used by
       PrepareLinkCycle before a link DOWN/UP, and the
       disarmed-forwarding stop at `server/helpers/status.rs:377`)
       today joins and drops worker-held state in one step
       (`stop_and_clear`, `coordinator/mod.rs:645`) — RAII-dropping
       every `NatHoldToken` — and then drops the allocators
       themselves (`ForwardingState::default()`), so E1's final
       reservation disappears during a temporary link cycle even
       though E1's BPF session-map row persists in the kernel (only
       the coordinator's fd is closed at `coordinator/mod.rs:675`;
       the pinned map content survives), the Go sidecar keeps its
       copy, and the HA peer keeps its exported copy: after the
       rebind, a peer re-push of E1 (bulk re-sync carrying the
       original translated tuple) or a fresh E2 allocation against
       the new empty allocator can produce the identical public
       reverse tuple — the documented reverse-NAT misdelivery
       (`pkg/config/compiler_tailgates.go:212`). Permanent shutdown
       remains a distinct path (`stop_with_event_stream`,
       `coordinator/mod.rs:441`), so treating every `stop()` as
       permanent is not a valid fence. The generalization: (1) the
       temporary stop runs the SAME quiesce → handoff → join
       ordering — workers quiesce (no new commits), every
       outstanding token transfers to the durable escrow BEFORE
       `stop_and_clear` can RAII-drop it and BEFORE `ForwardingState`
       is defaulted (the escrow keeper's `Arc` keeps allocator A
       alive past the default); (2) a temporary stop is NOT the
       escrow's "declared permanent dataplane stop" — that
       declaration is process shutdown (`stop_with_event_stream` /
       process exit), the only path that drains without replay
       confirmation; (3) the synced-map wipe at
       `coordinator/mod.rs:709` moves to the declared-permanent path
       only — a temporary stop PRESERVES the synced session maps
       exactly as `stop_inner(false)` does, so the rebind's
       bring-up (`rebind.rs` → `reconcile_status_bindings` →
       teardown/bringup) has the SAME finite, acknowledged replay
       set as a reconcile (the `rebind.rs:18` comment already
       documents today's wipe as wrong for a rebind: the synced map
       "should be replayed into BPF maps on bringup" — preserving
       it also stops losing sessions across a RETH-MAC link cycle,
       the behavioral change that comment asserts as intended); and
       (4) the rebind bring-up is the consuming dataplane: escrowed
       reservations migrate into the new allocators under the same
       collision-domain compatibility rule (incl. allocation mode,
       v9.9.15 above) BEFORE workers resume admission, and the
       escrow drains on the bring-up's replay-consumption
       confirmation, keepers releasing for reservations no replayed
       or materialized entry retained. Three invariants are explicit
       (v9.9.16, round-31 SMR): (a) re-entrancy is STRUCTURAL —
       `stop_inner` takes `&mut self` and every server handler
       serializes on the guard mutex, so two teardown sequences can
       never interleave and the escrow is exactly one
       coordinator-owned object; (b) a temporary stop whose rebind
       NEVER comes pins the preserved sessions and escrowed ports
       until process exit (no workers, no reaper) — an accepted
       residual whose escape is the operator's declared-permanent
       stop, and strictly more conservative than today's
       lose-everything behavior; (c) the disarmed-forwarding stop
       (`status.rs:377`) replays through the same machinery, whose
       re-resolution (`upsert_synced.rs:55-63`'s HAInactive gate)
       and incompatible-collision-domain invalidation reject entries
       whose config vanished while disarmed.
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
       materialized family member). Under the GROUP-HOLD the
       no-holder predicate is TWO-STAGE (v9.9.22, round-37 Codex H5 —
       the canonical forward and reverse entries themselves own
       clones, and imports pre-publish both before the asynchronous
       fan-out (`session_import.rs:115, :187`), so an all-rejected
       cohort can NEVER satisfy "no holder anywhere in the family"
       — the canonical family's own clones always exist):
       stage 1 checks EXTERNAL/live holders only (worker replicas,
       materialized entries, AND pending queue clones — v9.9.27,
       round-40 Codex M6: a queued `GroupHold` command owns a
       clone, so the fan-out outcomes include not-yet-consumed
       commands); failed stage-1 families are RETAINED on a
       durable cleanup retry queue woken on EVERY external-clone
       drop (v9.9.29, round-41 Codex H6: a `Claimed → Abandoned`
       conversion at the terminal transition sees the late
       executor's clone and stops; the executor's late recheck
       then drops it, and no outcome remains to wake cleanup —
       the quarantined family would linger and stay
       materializable (`session_glue/mod.rs:1092, :1157`); the
       retry queue is notified by the group-hold's drop path
       whenever the family is quarantined, and stage 2 re-runs
       on the external count's transition to zero —
       alternatively and equivalently, the drop site runs stage 2
       inline under the canonical lock when the count hits
       zero — the INLINE alternative is WITHDRAWN and the
       queue's arm/wake is an ATOMIC ARM-THEN-RECHECK state
       machine (v9.9.31, round-42 Codex H6: a final drop can
       occur while canonical locks are held, so inline stage 2
       would conflict with the lock-free finalizer rule; and the
       naive arm order has a lost-wakeup window — a clone
       dropping after the holder count is read but before the
       quarantine flag is armed sees no waiter, and stage 1 then
       queues a zero-holder family with no future wake: the
       quarantine flag arms BEFORE the holder count is read, so
       a drop after the read sees the flag and re-notifies;
       queue entries are deduplicated by family key; the
       quarantine and its retry entry are INCARNATION-SCOPED
       (v9.9.32, round-43 SMR F6; lifecycle pinned v9.9.33,
       round-43 Codex H6: the state is the tuple `(family key,
       SessionIdentity, quarantine generation, row version)` — a
       new import with a DIFFERENT
       identity is a new family epoch and installs normally,
       with stage 2 proceeding against the old identity only;
       and a SAME-identity re-import ATOMICALLY CANCELS the
       quarantine in the same critical section as its
       publication — the flag lives in the SAME canonical lock
       domain as the publication (the canonical store mutex, not
       an ordered pair — v9.9.34, round-44 SMR F2) — never a blind clear: a same-E1 resend that
       republishes (`session_import.rs:53` accepts
       equal-generation resends) cancels the OLD stage-2
       cleanup, so the stale cleanup can never remove the
       newly-published family before its worker clones fan out
       (`session_import.rs:115, :187, :215`); and a SUCCESSFUL
       stage 2 removes the flag and the queue entry atomically
       in the same transaction as the family removal; and the
       placement and supersession are pinned (v9.9.35, round-44
       Codex M7: publication today spans separate forward,
       reverse, and fan-out operations (`session_import.rs:115,
       :187, :215`) and `publish_shared_session` releases
       `synced` before locking companion maps
       (`shared_ops.rs:897`) — the quarantine state lives in the
       canonical `synced` LOCK DOMAIN (the same mutex the
       publication's forward entry takes, so the cancel and the
       publication are one critical section); and a
       DIFFERENT-identity publication (or any identity mismatch
       against the queued entry) is TERMINAL SUPERSESSION of the
       old quarantine generation — the old retry entry is
       cancelled and removed, never left as obsolete durable
       work — while the old identity's stage 2 has already been
       superseded by the new epoch's publication); and the OLD
       family's companions are never stranded by the
       supersession (v9.9.37, round-45 Codex B3: E1(K,P1)
       prepublishes K and reverse R1 before fan-out
       (`session_import.rs:104, :187`); E2(K,P2)'s publication
       replaces K and inserts only P2-derived aliases
       (`shared_ops.rs:907, :918`) — it does NOT remove R1/P1,
       and a later deletion derives companions from the CURRENT
       K/P2 (`session_import.rs:257`), so R1 and G1's hold
       would linger, R1 remaining materializable
       (`session_glue/mod.rs:1157`): the quarantine preserves an
       IMMUTABLE old-family cleanup record keyed by
       `(family, SessionIdentity, quarantine_generation)` —
       capturing the old family's companions (reverse, NAT/wire
       aliases, the group hold) at quarantine time — with the
       capture ordering guaranteed (v9.9.38, round-46 SMR F3:
       the reverse is synthesized and pre-published BEFORE
       fan-out (`session_import.rs:104` synthesizes, `:115`
       publishes forward, `:187` publishes the reverse), and
       the record is captured at fan-out completion — all
       replicas rejected — so R1 is always inside the record) — and the
       cleanup (stage 2 OR the supersession path) removes ONLY
       identity-matching old companions against that record
       before dropping G1, regardless of what currently
       occupies K);
       and the
       notification is lock-free, drained ONLY with canonical,
       allocator, migration-gate, and queue locks released);
       the retry queue drains from the coordinator side —
       the same drain context as the deferred-release queue —
       deduped by family key (a family re-quarantined while
       queued updates in place, v9.9.30, round-42 SMR F6)); stage 2, with
       no external holder, atomically removes the quarantined
       canonical family (the pre-published BPF row and the shared
       forward+reverse entries, under the alias-token fencing) and
       THEN drops its internal clones — the reservation releases
       only if no external clone ever existed, which is exactly
       the all-rejected case; the two stages run under the same
       incarnation recheck so a concurrent materialize between
       them re-quarantines. Pending
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
       tickets; v9.9.27, round-40 Codex M6: "no hold token" is
       scoped to `DirectHold` — a queued `GroupHold` command DOES
       own a clone (that is the distribution model), and the
       clone's lifecycle is accounted: rejection or queue
       destruction DROPS the clone explicitly (never a stranded
       last-clone), and the two-stage cohort cleanup's
       external-holder check COUNTS pending queue clones
       alongside replicas and materializations, so a never-
       consumed command can neither hold the reservation open
       indefinitely nor outlive it); reconcile ABANDONMENT does NOT drain the escrow —
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
       through the STABLE ALLOCATION-SLOT INDIRECTION (v9.9.18,
       round-33 Codex B3 — the token references an `Arc` slot per
       pool-rule allocator whose inner `Arc<PortAllocator>` the
       migration gate retargets A→B atomically at the cut, so a
       pre-cut token's later release always lands in the CURRENT
       allocator; `SourceNatRule` has
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
       (`pkg/config/compiler_tailgates.go:212`). The fence is a
       per-allocator MIGRATION GATE (v9.9.17, round-32 AGY Q2 +
       round-32 Codex r31-B2-disposition — this SUPERSEDES the
       v9.9.14 freeze and the v9.9.16 dual-record/lockstep bridge:
       AGY verified the lockstep is unimplementable as stated,
       because `allocate_translation` performs the lock-free
       `occ.claim()` at `allocator.rs:1017` BEFORE acquiring
       `shared.live` at `:1034` (no mutex wrapper can mirror that
       claim into B), and A/B are distinct `PortAllocator` objects
       with independent `shared.live` mutexes (`allocator.rs:720,
       :743`) so cross-allocator locking invites inversion): an
       RW-style gate on the allocator object. EVERY
       ownership-mutating entry point acquires the gate's READ
       permit BEFORE any mutation — the full enumeration:
       `allocate_translation`, the deterministic PAT path
       (`source.rs:1431`), deterministic NAT64 (`source.rs:995`),
       address-only round-robin (`source.rs:1523`), persistent
       address-only (`source.rs:1497`), the import/restore
       reservations (`reserve_flow` / `reserve_address_only*`), the
       release paths (`release_flow` / `free_translated_port` / the
       address-only release), `rollback_flow` (`allocator.rs:1392`
       — round-32 AGY trace-1: omitted in v9.9.16, it destroys
       ownership on flow-setup abort and would leak B's record),
       and expiry GC (`allocator.rs:2302`) — including the lock-free
       bitmap claim, which happens INSIDE the read permit (the gate
       is taken before `occ.claim()`, not just before the `live`
       lock). The in-place-refresh migration takes the gate's WRITE
       permit — draining in-flight mutations (µs-scale, bounded) —
       snapshots A's COMPLETE ownership state (occupancy bitmaps,
       `live_by_flow`, `persistent_by_source` leases,
       `address_only_owners`, recycle queues, deterministic state)
       into B under A's `live` lock, atomically publishes B (the
       existing Arc swap at `snapshot_refresh.rs:397`), then opens
       B's gate; A's gate stays CLOSED (retired). HOLDER LIFETIME
       crosses the cut by INDIRECTION, not by copying (v9.9.18,
       round-33 Codex B3 — the v9.9.17 text copied A's ownership
       into B and closed A while every `NatHoldToken` still owned
       the exact `Arc<PortAllocator>` A: a surviving pre-cut
       token's later release lands in the closed A, so B's copied
       refcount becomes a permanent ghost (eventual pool
       exhaustion) — or, if the unretargetable count is omitted
       from the copy, B frees and reissues P while E1's session
       still forwards with P; and an RAII `Drop` has neither the
       current allocator nor a retry channel, so "fails
       transiently and re-resolves" is not a lifecycle. The fix is
       option (ii) of the three explicit lifecycles): the token
       (and every holder — worker side maps, queued commands, the
       escrow) references a STABLE ALLOCATION-SLOT INDIRECTION (an
       `Arc` slot per pool-rule allocator, shared by the
       forwarding state's rule and every token) whose inner
       allocator handle the migration atomically RETARGETS from A
       to B at the cut — one atomic swap per slot under the write
       permit — so every pre-cut token's later release lands in B,
       which owns the migrated ownership state; no per-holder walk
       is needed at cutover, retired A owns nothing and is simply
       dropped when its last raw `Arc` dies, and the
       temporary-stop escrow's tokens cross rebinds the same way.
       (Rejected: option (i), quiesce-and-retokenize every
       worker/queue/escrow holder before publishing B — an
       O(holders) walk under the write permit with per-worker
       coordination the in-place-refresh path does not have —
       retained as the fallback for any holder class that cannot
       hold the indirection; option (iii), a retired-A→B
       release-forwarding record — keeps retired A alive for the
       longest token lifetime, an unbounded pin.) The release path
       is LINEARIZED with the retarget (v9.9.19, round-34 Codex B3
       — an atomic pointer swap alone does not make "load allocator
       → acquire gate → release" atomic with the cut: a token that
       loads `slot.current == A` and pauses before acquiring A's
       READ permit resumes after the migration drained, snapshotted,
       retargeted, and closed A, and its release into cached-A can
       never decrement B's copied holder — a permanent B ghost, or a
       reissue-under-live-session if the count was omitted): every
       ownership operation — release included, RAII `Drop`
       included — goes through `slot.with_current()`: load
       `(generation, allocator)`, acquire that allocator's gate
       READ permit, REVALIDATE the slot while holding the permit
       (generation unchanged AND the allocator not retired); on
       mismatch or closed-gate, drop the permit, reload, and RETRY
       — the loop is CPU-only, bounded (the slot converges; a
       retarget happens at most once per migration), and safe from
       RAII context; the migration takes the slot-WRITE before the
       allocator-WRITE (the stated lock order — no reverse order
       exists because ownership operations never take slot-WRITE),
       so a release is always observed on exactly one side of the
       cut. The WRITE-permit span is TOKEN-DROP-FREE (v9.9.22,
       round-37 Codex H6 + round-37 AGY Q2 — the last-clone
       finalizer's inline `with_current()` would deadlock twice
       over: a worker holding `A.live` during reap whose Drop
       blocks on the gate READ inverts against the migration
       thread holding gate-WRITE and waiting for `A.live`; and a
       drop fired on the migration thread itself — e.g. the
       tunnel-remap purge synchronously removing shared entries
       mid-refresh (`snapshot_refresh.rs:316`, `tunnel_purge.rs:77`)
       — self-deadlocks on the same RW lock): (i) every
       potentially-final token drop ENQUEUES the release
       obligation to a lock-free deferred-release queue instead of
       releasing inline — a `Drop` never acquires any lock, from
       any context (worker reap, panic unwind, migration cleanup);
       the queue is drained by a coordinator-side task woken on
       every enqueue (v9.9.23, round-38 SMR F3 — the drain context
       is named and its progress rule stated: the task drains on
       wake AND at least once per reconcile/migration span, holding
       NO other locks; a finalizer's reservation lives at most one
       drain interval longer than its last clone — never less,
       bounded more; the queued item carries the allocation
       generation and NO allocator handle, so a slot retarget
       between enqueue and drain is resolved fresh by the drain),
       which performs the actual `slot.with_current()` release
       (bounded retry on retarget — the reservation simply lives
       until the drain, never less); and (ii) the migration's
       WRITE span performs NO token drops — the tunnel-remap purge
       runs BEFORE the WRITE permit is acquired (or its removals
       defer to after retarget+publish+WRITE-release), so the
       finalizer can never fire inside the span at all.
       Two ordering invariants make the continuity exact
       (v9.9.20, round-35 SMR F2): (a) the migration's snapshot
       runs AFTER the gate-WRITE drain, so any release that
       observed `slot == A` under A's READ permit completes into A
       BEFORE the snapshot and is thereby included in B's copied
       state (snapshot-before-drain would lose that in-flight
       release from B's copy); (b) the retarget publishes BEFORE
       A's gate is marked retired — or, equivalently, a
       `with_current()` loader that lands in the close-then-retarget
       window spins CPU-only until the retarget publishes (bounded:
       the retarget is the very next step; the loop converges in at
       most two iterations). A stale raw `Arc<PortAllocator>` A-handle used for a
       NEW allocation (a worker that has not yet refreshed its
       forwarding Arc) still fails transiently at A's closed gate
       and re-resolves through the current published allocator.
       The slots are keyed by `SourceNatPoolAllocatorKey`, NOT by
       rule ordinal (round-34 AGY trace-2: a pool reorder/rename
       must not retarget slot-0's tokens into a different pool's
       allocator; a deleted/renamed pool's retired allocator
       persists until its last pre-cut token drops). There is NO
       dual-record and NO cross-allocator mutex: B is never
       worker-visible until fully populated, and the Arc swap is
       the single handoff, so B can neither issue a held tuple nor
       leak a freed one. New
       mutations arriving during the window block briefly on the
       gate or fail transiently (the packet path re-resolves on the
       next packet — the window is µs-ms and config changes are
       rare), AND the compatibility detection includes
       ALLOCATION MODE, not just address space (v9.9.15, round-30
       Codex B1a: `SourceNatPoolAllocatorKey` contains only pool
       name, addresses, and port range — NOT `no_translation` or
       ownership mode (`source.rs:327`) — so exact-key reload reuses
       the same allocator (`source.rs:726`) without triggering the
       migration fence: C1 PAT E1 owns public P in the occupancy
       bitmap (`allocator.rs:999`); C2 changes the same pool to
       `port no-translation`; E2 has preserved source port P and the
       same remote; address-only admission checks only
       `address_only_owners` (`allocator.rs:1727`) and succeeds
       despite P's bitmap ownership; E1 and E2 now have the
       identical public reverse tuple, and the reverse transition is
       symmetric (an address-only owner is invisible to new PAT
       bitmap allocation). The rule: the collision domain is
       (address space, ALLOCATION MODE (PAT — round-robin AND
       deterministic (`deterministic_v4`, #5178; deterministic
       NAT64 is the NAT64-side equivalent) — / no-translation
       (address-only, incl. #6041 persistent address-only) /
       ownership mode)); a mode change is treated as an INCOMPATIBLE
       collision-domain change (the old domain's escrow tokens are
       invalidated and flows re-resolve, which is semantically
       REQUIRED because the translation shape changed); and the
       cross-mode occupancy check is structural in BOTH directions —
       address-only admission ALSO consults the PAT occupancy bitmap
       (not just `address_only_owners`), and PAT allocation ALSO
       consults `address_only_owners` — so the identical public
       reverse tuple can never be issued across modes regardless of
       detection timing. The retain/release side is covered by the
       same migration gate: retain AND release operations through A
       during the window hold the gate's read permit, so the
       drained-snapshot into B already contains every ownership
       state at the cut — a post-snapshot materialization
       (`session_glue/mod.rs:1157`) either completes before the
       write permit lands (its result is in the snapshot) or fails
       transiently at the closed gate and re-resolves through B
       (v9.9.17: this supersedes the v9.9.15 dual-record bridge,
       which left B's release point undefined) — or forces the
       quiesced reconcile path (which has the
       escrow); a collision-domain-compatible change migrates in
       place; an incompatible change forces the reconcile). The rule
       for the reconcile/restore path itself: on a config change
       whose pool collision domain is COMPATIBLE (same address space,
       regardless of name), the restore path MIGRATES E1's exact
       reservation — PAT, NAT64 (`nat64.rs:915`), and address-only
       alike — into every compatible current allocator BEFORE
       releasing A's hold, ROUTED BY ALLOCATION KIND (v9.9.15,
       round-30 Codex B2): NON-persistent reservations via
       `reserve_flow` / `reserve_address_only` (confirmed available
       per round-27 AGY); PERSISTENT leases via the lease-object
       transfer above — a per-flow `reserve_flow` can never migrate
       a shared persistent lease (`persistent_key: None` per flow,
       `allocator.rs:1654`, so the second co-holder fails the
       occupied-bit check) — so B can never assign
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
       fires, routing by variant (v9.9.21) — a `DirectHold`
       decrements the allocator refcount directly, a `GroupHold`
       clone decrements only the Arc (the allocator release fires
       from the last clone's finalizer, in canonical→allocator
       order, never reacquiring canonical locks inside the
       cleanup); queue rejection/drop
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
       on the delta's `SessionIdentity` (the full pair, v9.9.27) (queued packet drops are
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
       one flow) is also covered by the refcount — v9.9.20: for
       IMPORTED flows the "refcount" is the coordinator-owned
       GROUP-HOLD Arc's clone count (below): replicas receive clones
       at commit and each reap drops only its own clone, so an early
       replica reap can never free the reservation under a surviving
       replica). `ExpiredSession` gains the
       entry's full `SessionIdentity` (the
       `(origin_process_nonce, flow_incarnation_id)` pair —
       `entry.rs:337` lacks both today; v9.9.23, round-38 Codex B4:
       one identity type everywhere, no scalar-ID stragglers),
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
       shared aliases (which carry the full `SessionIdentity`), captures
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
       NEVER falls back to gen-based unconditional deletes toward the
       old peer (v9.9.16, round-31 Codex H4: the earlier "keeps
       today's gen-based unconditional delete on the old peer"
       phrasing — retained from a superseded draft — authorized
       exactly the A→legacy-B stale-Close trace that key-deletes the
       replacement E2 (`sync_conn_gen.go:263, :493`,
       `session_store.go:537`); removed). The rule
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
       independent (v9.9.51, round-52 Codex M2: the HELLO's
       capabilities word is ADVERTISEMENT ONLY — it selects the
       transcript version and names what CAN be confirmed later;
       on a v1-proof connection NO capability becomes active
       except through matching authenticated same-connection
       `CAPABILITY_CONFIRM`s, and unnegotiated legacy peers (raw frames
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
       delete only when its stored incarnation matches ("incarnation"
       HERE AND EVERYWHERE in this plan means the full
       `SessionIdentity { nonce, id }` pair, v9.9.23 — every
       comparison is the pair, never the scalar
       `flow_incarnation_id`). Only
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
       every entry, replica, and alias gains the full
       `SessionIdentity { origin_process_nonce, flow_incarnation_id }`
       (v9.9.24, round-39 Codex M5: the umbrella rule — the
       incarnation COMPONENT is
       SEPARATE from the RT_FLOW `session_id` (#4915 per-worker
       correlation ids are untouched), and EVERY comparison,
       inheritance, command field, and test in this plan uses the
       pair, never the scalar component; where this paragraph and
       the §9 tests say "the id" they mean the incarnation
       component of the pair, with the nonce carried alongside —
       the detached consumers, Close processing, helper aliases,
       and purge paths all compare the full pair). Minting authority is the
       FORWARD entry only: locally-born flows stamp the alias with the
       forward mint at publication (today id 0,
       `poll_descriptor/mod.rs:2560`); the reverse entry and its
       publication INHERIT the forward's id (the reverse synth and
       fabric/tunnel constructors all hold a forward match in hand —
       it carries the id; today the primary reverse publication
       carries zero, `poll_descriptor/mod.rs:2897`); worker replicas
       inherit from the alias/wire at materialize/install instead of
       minting from zero; and HA coordinator imports ADOPT the
       wire-carried identity BYTE-FOR-BYTE (v9.9.33, round-43
       Codex H7 — this supersedes "mint ONCE before fanout":
       §5.8's rule is that the sender's pair is wire-carried and
       a receiver-minted identity can never equal it; if A sends
       E1 with identity IA and B minted IB, A's conditional
       delete for IA would be refused on B and B would retain
       stale E1 plus its NAT hold. Only LOCALLY-BORN forwards
       mint; every import inherits — the single canonical
       adoption happens ONCE at canonical publication
       (`session_import.rs:115`) and fan-out copies it verbatim,
       so round-9 AGY 2's per-worker divergence still dies). `DeleteSynced`
       becomes incarnation-conditional (today key-only,
       `session_glue/mod.rs:851` → `delete_synced.rs:9`: a delayed E1
       cleanup can kill replacement E2) — the command carries the
       expected `SessionIdentity` (the FULL pair, v9.9.23 — not a
       scalar id) and deletes only on match. The Close delta carries
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

**Wire schema (normative, consolidated — v9.9.33):**
The session INSTALL/Open delta carries the additive identity tail
`{(origin_process_nonce, flow_incarnation_id, stable_rule_id_hash,
admission_config_version, persistent_nat, persistent_nat_permit)}`
(v9.9.17, round-32 Codex B1: the lease-derivation inputs are part of
the NORMATIVE tail, not just the §5.2 narrative — they are stamped
INTO THE ENTRY at admission by the helper (a new entry-level field
pair; `NatDecision` carries only rewrite fields today,
`nat/mod.rs:84`, and neither `SessionDelta` nor `SyncedSessionEntry`
stores lease provenance, `entry.rs:283` / `worker/mod.rs:375`), and
EVERY wire emission — initial install, periodic resend, and bulk —
carries the ENTRY's stamps, never a queue-time re-derivation from
the sender's current rule config (which would reopen the r31-B1
epoch-skew trace through the resend path: an empty-standby bulk
without the stamps imports non-persistently, F2 fails the
occupied-bit check, and takeover swaps its port). The selector
fields (v9.9.14, round-29 Codex H4: the main
design requires imported entries to inherit `stable_rule_id_hash` and
`admission_config_version` through the INSTALL tail, and they cannot
be reconstructed from the BPF projection (`bpf_session_value.go:168`),
whose positional policy ID is rewritten across policy reorder
(`bpf_map/mod.rs:384`) — a §5.8 implementation without them retains
the numeric-ID selection at `daemon_policy_invalidate.go:311` where a
surviving rule's E2 can alias a deleted rule's old position and be
companion-deleted through `session_store.go:391`); the session DELETE
delta carries `{(origin_process_nonce, flow_incarnation_id)}`.
The REPAIR PROTOCOL frames (v9.9.33, round-43 Codex B4 —
consolidated v9.9.35, round-44 Codex B3: EVERY repair frame,
namespace, capability, terminal ACK, receipt rule, and discharge
predicate lives HERE, additive and rolling-gated like the
identity tails): the capability handshake exchanges
`(node_id, process_incarnation, capacity,
capacity_config_generation, heartbeat-ack-capable,
identity-enforcement-capable, lease-input-capable,
repair-vN, reset-vN, repair-v2 (the decision phase —
ONE name, v9.9.54.18, round-63 Codex L8))` — with the
CLASS-COMMIT frames defined NORMATIVELY (v9.9.54.20,
round-65 Codex M7: current code defines only
AUTH_HELLO/AUTH_PROOF (`sync_auth.go:60`) — the shared
class commit is not rolling-interoperable until the frames
and sequencing are named: the `CAPABILITY_CONFIRM` frame
(ID **32** — the additive rolling-gated frames occupy
32+, leaving 27-31 headroom over the current 1-26
(`sync.go:39-76`), v9.9.54.21, round-66 Codex H7; payload
= the full capability tuple laid out per the §5.8 record
grammar — `(node_id, process_incarnation, capacity,
capacity_config_generation, capability bits)` as
u32/u64/u64/u64/u32 little-endian (28 bytes), the same
byte layout the
transcript vectors already pin) IS the capability record on
a v1-proof connection (the HELLO carries only version,
keyed flag, nonce — `sync_auth.go:345`); the decision
phase's own frames are `CAPABILITY_DECISION` (**33** —
payload `(sender_incarnation u64, decision_seqno u64,
computed_class u8)`) and
`CAPABILITY_DECISION_ACK` (**34** —
payload `(sender_incarnation u64, decision_seqno u64)` —
the ACK correlates by echoing the decision's exact
`(sender_incarnation, decision_seqno)` pair) (v9.9.54.21,
round-66 Codex H7 — literal IDs, layouts, and
correlation); the repair/reset frames take **35-39**
(`RESYNC_REQUEST` = 35, `JOURNAL_END` = 36,
`JOURNAL_ACK` = 37, `RESET_GEN` = 38, `RESET_ACK` = 39),
each with the payload layout its definition pins; sent
only after a COMPLETE bidirectional CONFIRM
exchange commits v2, never before); and a decision-phase
frame arriving on a connection whose committed class is
BELOW v2 is a protocol violation and closes the connection
(v9.9.54.21, round-66 SMR F7: the allowlisted
decision-phase reader's allowlist is CLASS-SCOPED — a v1
connection's allowlist excludes decision frames, so a
buggy or malicious peer cannot inject the phase); and a v0 peer needs NO
declaration frame (round-65 SMR F2 — the 'authenticated
v0 declaration' was dead text: v0 commits on the first
COMPLETE ordinary frame with no record, and a peer that
CAN send a record sends one with all repair bits zero,
which min()s to v0 on its own)) — the identity fields are part of the
AUTHENTICATED HELLO TRANSCRIPT under an explicit
AUTH-TRANSCRIPT PROTOCOL VERSION (v9.9.43, round-48 Codex H2 —
a direct proof-algorithm change would break rolling upgrades:
current peers compute `HMAC(tag || nonce)` (`sync_auth.go:217`,
verified at `:401`), so a whole-transcript proof and the
nonce-only proof would reject each other and reconnect
indefinitely — with the mixed-version rules byte-exact
(v9.9.45, round-49 Codex H2: the LEGACY HELLO PREFIX is
preserved byte-for-byte — today's v1 reads its challenge from
the fixed bytes `payload[2:34]` and always uses the nonce-only
proof (`sync_auth.go:345-376, :387-404`), so the v2 fields
ride a NEW FRAME TYPE — but NEVER between the legacy HELLO
and the AUTH_PROOF (v9.9.49, round-51 Codex B1: the v1 peer
during authentication does NOT use `handleMessage`'s skip
logic — after HELLO it reads exactly ONE raw frame
(`sync_auth.go:392`) and requires it to be
`syncMsgAuthProof` (`:401-404`); unknown-frame skipping
starts only at `sync_conn_read.go:96`, AFTER auth and
wrapper installation (`sync_conn.go:116`): a v2 endpoint
that has read the peer HELLO sends the v1 AUTH_PROOF
IMMEDIATELY when EITHER version is v1 (no pre-proof frame of
any new type), and the capability exchange occurs INSIDE the
authenticated wrapper (post-install, via `CAPABILITY_CONFIRM`);
a pre-proof capability record may be sent only when BOTH
HELLO versions are v2 — the version field in the HELLO
(`sync_auth.go:345`'s `{version, keyed, nonce}`) tells the
v2 peer which case it is in, and its pre-proof
unauthenticated state is safe by construction (v9.9.50,
round-52 SMR F2: a v2 peer seeing a v1-version claim simply
uses v1 rules — ALL capabilities are disabled on a v1-proof
connection until matching CONFIRMs, so a false v1 claim can
only DE_FEATURE the connection, never elevate it; a v1 peer
ignores the version entirely and reads the nonce; and
between v2 peers the version is covered by the v2 transcript
itself — no proof-covered version field is needed); the v1 HELLO's own layout is
NEVER reordered or extended in-frame, or an old peer would
authenticate different bytes and reconnect-loop at
`:401-404`); EITHER peer being v1 selects the v1 proof (a v2
peer proving to a v1 peer uses the v1 nonce-only proof over
the legacy prefix bytes), and on a v1-proof connection the
capability rule is TOTAL (v9.9.47, round-50 Codex H3 — the
v1 proof covers only the nonce (`sync_auth.go:217-224`), so
capability bits in the HELLO are unauthenticated: an
asymmetric `repair-vN` bit would leave one side waiting for
`JOURNAL_ACK`, and an asymmetric identity-enforcement bit
would permit a delete toward a key-deleting decoder
(`sync_conn_gen.go:263-290, :493-506`): EITHER every
capability is MASKED under v1 proof (a v1-proof connection
offers NO negotiated capabilities — both peers fall back to
legacy behavior for everything), OR, to preserve `repair-vN`
on such connections, a post-wrapper authenticated
`CAPABILITY_CONFIRM` frame carries the full tuple and a
feature enables ONLY when both sides' CONFIRMs agree — with
the ACTIVATION BARRIER pinned (v9.9.53, round-53 Codex H2:
the wrapper and slot install at `sync_conn.go:118`, the
receive loop starts at `:132`, and cold-prime starts
immediately at `:138-194`, while a bulk is one live
`BulkStart → rows → BulkEnd` transaction (`sync_bulk.go:50`)
— a CONFIRM arriving DURING an install-only prime would
activate `repair-vN` mid-transaction (continuing the prime
leaves stale peer rows; switching protocols mid-window
produces incompatible terminal processing): the
`CAPABILITY_CONFIRM` exchange COMPLETES BEFORE slot
installation, session dispatch, and cold-prime (the
confirmation is part of the pre-dispatch handshake — and
its lifecycle is TRACKED AND DEADLINED (v9.9.54.2,
round-54 Codex H2: a confirmation phase between the wrapper
(`sync_conn.go:118`) and slot installation (`:130`) can
otherwise wait with NO deadline while belonging to neither
lifecycle registry — `Stop` closes installed slots
(`:363-370`) and tracked setups (`:371-375`) but would miss
it: the connection KEEPS its setup registration and a HARD
confirmation deadline until the atomic
finish-setup/install transition, so `Stop` covers it and
the deadline is real; admission-cap retention follows the
same registration); the
protocol class — legacy vs repair-era — is LATCHED for the
connection's lifetime at that point; and the timeout path
was the LATCH, never an abort-retry flap (v9.9.54.1,
round-54 AGY Q2/Q3 — SUPERSEDED at v9.9.54.20 (round-65
Codex B1): the timeout path CLOSES and retries with
bounded backoff; no timer commits any class; the earlier
text had BOTH "aborts the
install and retries" AND the latch fallback, which are
mutually exclusive: a slow or never-arriving CONFIRM
CLOSES the connection and retries with bounded backoff —
it NEVER latches a class (v9.9.54.20, round-65 Codex B1 —
the v9.9.54.19 "latch v1-extras-inactive" rule was built
on a false premise: on a v1-proof connection the
capability record IS the authenticated `CAPABILITY_CONFIRM`
(the HELLO carries only version, keyed flag, and nonce —
`sync_auth.go:345`), so a zero-byte CONFIRM timeout proves
RECORD ABSENCE for that window, not "record already
arrived"; a baseline peer can pause after wrapper
installation but before `ClockSync` (`sync_conn.go:118,
:137`), and latching v1 on the timeout splits the class
when B later commits v0 by the ordinary-frame rule —
A would expect `JOURNAL_END`/`JOURNAL_ACK` while B uses
legacy `BulkEnd`/`BulkAck` (`sync_conn_read.go:205`):
zero bytes with no complete record closes and retries with
bounded backoff (the DECISION-timeout discipline), v1/v2
commit ONLY on a COMPLETE authenticated record/CONFIRM
exchange, and v0 commits ONLY on a COMPLETE ordinary
frame — never on any timer); and the
latch binds for the CONNECTION's lifetime with NO
in-connection escape (v9.9.54.3, round-55 SMR F1: a peer
that upgrades to v2 mid-connection still finishes this
connection in the legacy class, and the upgrade takes
effect on the NEXT connection — a new incarnation
re-runs the full negotiation: hello, v2 proof, CONFIRM,
repair-era — so the latch can never strand a capable peer
and never permits a mid-connection protocol flip); and the
class DECISION is a SHARED COMMIT, never two independent
local latches (v9.9.54.4, round-55 Codex B1 — independent
deadlines can split the class on ONE connection: A receives
B's CONFIRM before its deadline (repair-era for A) while
A's CONFIRM reaches B after B's deadline (B latches
legacy); TCP preserves order but cannot reverse B's
completed latch, so A speaks repair terminal semantics
while B follows legacy `BulkEnd` processing
(`sync_conn_read.go:205`) — an inconsistent-reconciliation
wedge: the DECLARATION input is REMOVED (v9.9.54.21,
round-66 Codex H7: the declarations were
deadline-dependent — "each declares repair-era iff it
received the peer's CONFIRM before its own deadline" —
and NO frame ever carried the non-owner's declaration,
leaving fully capable peers without an implementable
input; v9.9.54.20's close+retry eliminated the
deadline-dependent state entirely — a side that times out
CLOSES, it never declares while retaining: BOTH sides
compute the class DETERMINISTICALLY as min() over the two
authenticated records — identical inputs, identical
result, nothing to declare), and the setup owner — bound to the AUTHENTICATED STABLE NODE-ID
ordering plus the setup token and the dialer/acceptor role
(v9.9.54.7, round-56 Codex H3: "address-ordered" is NOT
total — address parsing failure returns "dial" on EITHER
endpoint (`sync_conn.go:12`, and `sync_test.go:1337`
preserves it), so hostname or unparsable endpoints can make
BOTH nodes act as owner on crossed setup connections,
competing installs replacing the same fabric slot
(`sync_conn.go:244`) with repeated setup/cold-prime churn;
the plan's OWN stable node-ID ordering (already specified
for the incarnation state machine) is the total rule, and
the owner identity is `(stable node-ID order, setup token,
role)` — with COLLISION DETECTION at the transcript
(v9.9.54.8, round-57 SMR F3: the transcript carries BOTH
cap records (`dialer_cap` and `acceptor_cap` each carry
`node_id`), so a misconfigured collision — both sides
provisioned the same ID — is detected at the transcript);
and REJECTION-BEFORE-OWNER-SELECTION is the SOLE equal-ID
rule (v9.9.54.10, round-58 Codex M7: equal authenticated
node IDs are REJECTED with an operator-visible not-ready
state — the existing duplicate-ID fail-closed precedent
(`heartbeat.go:811-820`, `election.go:195-202`) — never a
fallback-to-legacy and never a competing-owner outcome;
this supersedes any earlier "falls back to legacy with an
operator-visible alarm" phrasing)) —
publishes `CAPABILITY_DECISION(class)` carrying its
deterministic computation, the peer VALIDATES the
published class against its OWN computation (a MISMATCH
is a protocol violation and closes the connection — the
peer never accepts a class it cannot derive) and echoes
acceptance in `CAPABILITY_DECISION_ACK(decision_seqno)`,
and BOTH sides install the class ONLY at the ACK'd
decision installation — the SINGLE commit point
(v9.9.54.21, round-66 Codex L8: the class is TENTATIVE at
the capability exchange and COMMITS at the ACK'd
installation — resolving the exchange-vs-installation
contradiction; the pre-v9.9.54.21 "a side that latched
legacy locally REVERSES to the published class" is
superseded — nothing latches on a timeout under
v9.9.54.20, so there is no local legacy latch to reverse;
the install is safe because nothing has dispatched yet: the decision precedes session dispatch —
the full pre-dispatch order is pinned (v9.9.54.5,
round-56 SMR F1: hello → proof → wrapper → CONFIRM
declarations → `CAPABILITY_DECISION` + ACK → slot
install → session dispatch/cold-prime — the decision
ALWAYS completes before `sync_conn.go:138-194`'s
cold-prime, so a side that declared repair-era locally
has dispatched NOTHING when the decision arrives));
a timeout with NO committed decision closes and retries
with bounded backoff (never an independent class selection
while retaining the connection; and if the
stable-node-ID-ordered owner DIES before publishing
(v9.9.54.10, round-58 Codex M7's totality sweep), the
decision is UNCOMMITTED (v9.9.54.5, round-56 SMR F2: the
connection closes and retries with bounded backoff; the
retry's new connection may elect a different owner per
the same deterministic STABLE-NODE-ID-ordered rule
(v9.9.54.9, round-57 Codex H4 + v9.9.54.10, round-58 Codex
M7: this sweeps the last
"address-ordered" stragglers — address parsing returns
"dial" at EITHER endpoint on failure
(`sync_conn.go:12-20`), enabling crossed setups to
repeatedly supersede the same slot (`sync_conn.go:244-266`);
the owner rule is stable-node-ID-ordered EVERYWHERE, with
NO address-ordered reference remaining); and
EQUAL node IDs are explicitly REJECTED (v9.9.54.9, round-57
Codex H4: equal authenticated node IDs have no strict
ordering, and the existing HA code treats duplicate IDs as
invalid and fails closed (`heartbeat.go:811-820`,
`election.go:195-202`): a transcript presenting equal
`node_id`s is rejected with an OPERATOR-VISIBLE not-ready
state, and the setup token and connection role NEVER turn
duplicate IDs into competing owners); and the
decision is IDEMPOTENT — the same declarations yield
the same class regardless of who publishes)); and the decision lane
handles partial frames explicitly (a partial frame at
timeout — `sync_auth.go:289` can consume part of a frame —
CLOSES the transport and retries on a fresh stream
(v9.9.54.7, round-56 Codex M4 — "discard the partial frame
and re-establish framing" is not implementable over a
stream: `readSyncFrameRaw` consumes header and payload with
`io.ReadFull` (`sync_auth.go:289`), so a deadline firing
after partial consumption leaves no record boundary to jump
to, and starting the ordinary receive loop at its next
header read (`sync_conn_read.go:27`) would interpret the
suffix as a new frame: every incomplete or timed-out
decision frame closes the transport, and the retry runs on
a fresh stream — and the post-wrapper decision phase runs an
ALLOWLISTED AUTHENTICATED reader, never the bare
header+payload reader (v9.9.54.9, round-57 Codex H3:
authenticated writes append a sequence/HMAC trailer
(`sync_protocol.go:49-62`) that the setup reader does NOT
strip (`sync_auth.go:289-310`), and trailer
consumption/verification exists only in the ordinary
receive loop (`sync_conn_read.go:71-94`), which cannot
start early (it dispatches before the slot token exists) —
literal reuse leaves the trailer to be parsed as the next
header, a bad-magic reconnect loop: the pre-install reader
consumes and verifies header, payload, AND trailer while
advancing `authConn.recvSeq`, and it is allowlisted to the
decision-phase frame types) — and the phase's ENTRY rule
(v9.9.54.10, round-58 Codex B1: a BASELINE authenticated
peer completes authentication, installs its slot
(`sync_conn.go:118, :130`), and immediately sends
`ClockSync` (`sync_conn.go:137`, `sync_conn_write.go:256`)
— a NON-decision frame that an allowlisted-only reader
would reject, looping the connection and defeating the
zero-byte timeout's legacy latch: the decision phase is
entered ONLY after authenticated support ADVERTISEMENT
(the peer must advertise the decision capability — BIT 5 of
the capability record, rolling-gated; the advertisement
point on a v1-proof connection is the capability record
itself, which rides the authenticated connection and is
therefore authenticated by construction — and BIT 5 follows
the SAME v1-proof rule as every other capability (v9.9.54.13,
round-60 SMR F1); and the DECISION PHASE is a distinct repair
protocol VERSION (`repair-v2`), not a bit-flag dependency
(v9.9.54.16, round-61 Codex B1: an intersection computed by
the NEW side cannot constrain the OLD endpoint — old B
ignores BIT 5 (and it sits inside the existing fixed-width
capability word, not an additive trailing field), sees A's
`repair=1`, and activates its older repair protocol under
ITS older matching-CONFIRM rule (both records show
`repair=1`) while A selects legacy: the decision phase is
versioned as `repair-v2` (BIT 5 = `repair-v2`), and the
version negotiation is MAX-COMMON-VERSION — each side
advertises its immutable own maximum UNCONDITIONALLY (the
symmetric setup writes its own record before waiting for
the peer's — `sync_auth.go:326, :336`, `sync_conn.go:100`
— so an advertisement can never be conditional on the
peer's record; v9.9.54.17, round-62 Codex B1 + round-62
SMR F3), then both sides compute `min(own_max, peer_max)`
DETERMINISTICALLY AFTER the exchange (v1 if either lacks
v2, v2 iff both have it) — ONE cumulative v0/v1/v2 state
machine, never a per-bit presence test — so an
intermediate peer lacking v2 can never activate v2
semantics against A, and A never ACTIVATES v2 semantics
toward a v1 peer (ACTIVATION, not advertisement, is the
gated step); and the INTERSECTION rule of v9.9.54.14
governs ONLY the non-versioned remaining bits
under the same discipline (v9.9.54.14, round-60
Codex B1: new A sends `{repair=1, decision=1}` while
intermediate B sends `{repair=1, decision=0}` — B's OLD
decoder IGNORES the unknown BIT 5 (the normative decode
rule, stated explicitly at v9.9.54.17 (round-62 SMR F2):
a conforming decoder IGNORES unknown SET capability bits
and NEVER rejects the record — "reserved-zero" is an
ENCODE-only constraint, and the retracted
"trailing tolerance" justification does not apply inside a
fixed-width word), sees
A's repair bit, and activates its older repair protocol,
expecting terminal semantics A will not provide: each side
computes the INTERSECTION of the two records ONCE at the
capability exchange and activates
only capabilities present in BOTH (never a capability
absent from the peer's record — the intermediate's
`decision=0` zeroes the intersection, so BOTH sides use
legacy; for the VERSIONED repair bit the intersection is
subsumed by the min-version rule of v9.9.54.16, with the
THREE negotiated classes defined EXACTLY (v9.9.54.18,
round-63 Codex B1 + round-63 SMR F4 — "min() yields v1,
both sides use legacy" conflated the v1 repair contract
with the v0 baseline path): **v0** = NO NEGOTIATED REPAIR —
committed by EXACTLY TWO evidence paths (v9.9.54.21,
round-66 Codex B1 — "record absence + ordinary frame"
alone was unsatisfiable for a recorded-v0 peer, which
sends no ordinary frame before its record
(`sync_conn.go:130, :137`): (a) an authenticated
capability record with ALL repair/version bits zero
(commits at the CONFIRM exchange; `min(own_max, 0) = 0`),
or (b) the first buffered ordinary frame (`ClockSync` or a
session frame, `sync_conn.go:137`) arriving with NO record
(commits at the frame; `min(own_max, absent) = v0`) —
the two paths are exhaustive and exclusive and no timer
is either; NO repair protocol runs —
completion is the current `BulkEnd`/`BulkAck`
(`sync_conn_read.go:205`) and nothing else; **v1** = the
EXACT old repair-v1 contract — the peer's record carries
`repair-vN` (bit 2) without bit 5; the repair protocol
RUNS (RESYNC_REQUEST, the
cutoff/marker frames, JOURNAL_END/JOURNAL_ACK as the only
discharge) — the RESET lane (`RESET_GEN`/`RESET_ACK`, the
reset-generation handshake) activates IFF `reset-vN`
INDEPENDENTLY negotiates (repair and reset versions are
independent machines, v9.9.54.19, round-64 Codex H4: a
repair-v1 peer without reset support selects the
time-barrier path, and its peer must NOT wait on the
reset lane) — and the DECISION PHASE never activates (no
decision frames are sent or expected — the phase's
terminal completion simply does not exist at v1);
**v2** = cumulative bits 2+5 — min() ≥ 2 adds the decision
phase with its own terminal completion; each class
LATCHES at its commit point (v0 at the first ordinary
frame, v1/v2 at the capability exchange) for the
connection's lifetime — on the round-60 trace (new A
bits 2+5 vs intermediate B bit 2 only) min() = v1:
repair-v1 RUNS on both sides and the decision phase is
simply absent — B never activates semantics A lacks and
A never waits for decision frames B cannot send,
v9.9.54.18) — the intersection LATCHING for the connection's
lifetime (v9.9.54.15, round-61 SMR F1: a capability-record
replacement mid-connection (a newer record with fewer bits)
does NOT re-open the intersection — the recomputation is
ignored for the current connection (no class change is
possible mid-connection) and takes effect only on the NEXT
connection; the same latch covers the negotiated
min-version — a mid-connection record replacement never
re-negotiates the version, v9.9.54.17); the v9.9.54.16
repair-v2 versioning ADOPTS what was the documented
alternative (a repair version the intermediate cannot
interpret) — it is the operative rule, no longer an
alternative); and BIT 5 follows
the SAME v1-proof rule as every other capability (v9.9.54.13,
round-60 SMR F1: on a v1-proof connection it is advertised,
not active, until the matching authenticated
`CAPABILITY_CONFIRM` — the decision phase requires BOTH
bit 5 present AND, on a v1-proof connection, the
post-wrapper CONFIRM), v9.9.54.12,
round-59 Codex B1); a baseline peer's first ordinary
legacy frame is BUFFERED, the connection latches legacy,
installs, and dispatches the buffered frame in order —
never rejected — and the latch SETTLES PERMANENTLY on that
first ordinary frame (v9.9.54.18, round-63 Codex B1: this
IS the v0 class — RECORD ABSENCE committed by the first
buffered ordinary frame; `min(own_max, absent) = v0`, no
repair protocol runs, completion is the current
`BulkEnd`/`BulkAck` and nothing else) (v9.9.54.11, round-59 SMR F1: the
arrival of the first ordinary legacy frame (ClockSync or a
session frame) IS the proof of the baseline class — there
is no advertisement-timeout retry cycle; the latch settles
at the frame, not on a timer, and holds for the
connection's lifetime); and the CONFIRM-timeout byte
rules are exact (v9.9.54.9: the stream CLOSES and retries
with bounded backoff if ZERO bytes were consumed
(v9.9.54.20, round-65 Codex B1: on a v1-proof connection
the CONFIRM IS the record (`sync_auth.go:345` — the HELLO
carries no capability payload), so zero bytes proves
record absence for that window, and no timer may commit
any class; v0 commits by EXACTLY TWO evidence paths
(v9.9.54.21, round-66 Codex B1: (a) an authenticated
capability record with ALL repair/version bits zero —
commits at the CONFIRM exchange; or (b) a COMPLETE
ordinary frame with NO record — commits at the frame;
the two paths are exhaustive and exclusive, and no timer
is either),
v1/v2 only on a complete authenticated CONFIRM) — with
the retry ladder stated (v9.9.54.21, round-66 SMR F2: the
inner bounded backoff hands off to the OUTER session-sync
connect loop (immediate first attempt, 1s retry) — the
loop is NEVER fatal to a slow-but-healthy peer (a
pathologically-skewed CONFIRM always lands within a few
retry cycles; N consecutive failures are operator-visible,
not terminal), and a COMPLETE late CONFIRM on a FRESH
retry stream is HONORED — it is ignored only on the
stream that already timed out); a partial
CONFIRM frame closes; a COMPLETE late CONFIRM is consumed
and IGNORED before declarations — where "ignored" means
INELIGIBLE FOR FEATURE ACTIVATION ONLY (v9.9.54.10,
round-58 Codex H4: the late CONFIRM's identity is needed
for owner selection — on a v1-proof connection the HELLO
carries only `{version, keyed, nonce}` (`sync_auth.go:345`)
and the node ID and process incarnation arrive in the
capability record, so a delayed CONFIRM can otherwise
leave the owner uncomputable: the late CONFIRM is still
schema-validated and its identity/provenance BOUND, and a
node-ID or incarnation mismatch closes the connection;
true legacy peers bypass the shared decision entirely, per
the entry rule above) — and ONLY on tuple match
(v9.9.54.10, round-58 SMR F3: the late CONFIRM is a
duplicate only when its tuple equals the connection's
negotiated tuple; a MISMATCHED tuple is not "late" — it is
a protocol violation and closes the connection)); with the two timeout CLASSES reconciled:
the DECISION timeout closes and retries with bounded
backoff, and the CONFIRM timeout does the SAME
(v9.9.54.20, round-65 Codex B1 — the pre-v9.9.54.20 rule
latched "the legacy class" on a CONFIRM timeout; a
zero-byte CONFIRM timeout proves record absence for that
window only, and no timer may commit any class: close and
retry with bounded backoff — the earlier "never aborts over a
late CONFIRM" refers only to the CONFIRM class)); the connection never aborts over a late
CONFIRM, so there is no reconnect flap); and when a
capability transitions inactive→active on a LATER
connection, a FRESH repair-era full bulk is explicitly
scheduled — and the ACTIVATION ITSELF is one transaction
(v9.9.54.2, round-54 Codex H3: the legacy-class prime
completing and readiness clearing BEFORE repair-vN
activates leaves an interval where transfer can occur with
the obligations and freeze unarmed: on ANY transition to
repair-vN, the activation FIRST mints the repair ID and
atomically establishes the outbound obligation AND the
not-ready state — one critical section under the same lock
domain that owns the sync state (v9.9.54.3, round-55 SMR
F2: the `SessionSync` mutex owning obligations and
cold-prime state; the readiness gate reads under the same
lock, so a takeover decision observes either (armed,
not-ready) or (unarmed, legacy-complete) — never (armed,
ready)); and the activation acquires a GENERATION-SCOPED
ELECTION HOLD BEFORE exposing `repair-vN` (v9.9.54.9,
round-57 Codex B1: the VRRP operational hold is acquired
only during daemon startup
(`daemon_run_bringup.go:226-233`) and a completed legacy
bulk RELEASES it (`daemon_ha_sync.go:90-100`), restoring
preemption (`vrrp/manager.go:389-404`) — while the packed
`syncReady` state gates only private-RG election
(`cluster/manager.go:289-293`), NOT normal VRRP: a legacy
bulk completing, then a later connection activating
`repair-vN` and going not-ready, would leave normal VRRP
preemption ENABLED before the repair's `JOURNAL_END` (a
priority event preempts mid-repair): the activation
transaction acquires the election hold scoped to ITS
generation before exposing `repair-vN`; the hold releases
ONLY after CURRENT-GENERATION INBOUND `JOURNAL_END`
APPLICATION — never on an outbound `JOURNAL_ACK` alone
(v9.9.54.10, round-58 Codex B2: applying inbound
`JOURNAL_END` proves LOCAL readiness, while receiving
`JOURNAL_ACK` proves only that the PEER received this
node's outbound state: B receiving A's ACK for B→A while
A→B remains incomplete would release its VRRP hold and
restore preemption (`vrrp/manager.go:389`) while still
lacking A's complete table — and normal VRRP does not
consume the packed private-election readiness bit
(`cluster/manager.go:289`); and the hold is a STATE
MACHINE, not a one-shot acquisition (v9.9.54.12, round-59
Codex B2: acquisition limited to the initial `repair-vN`
activation leaves a later readiness LOSS unfenced — an
overflow, a reservation rejection, or an epoch park can
make the node incomplete WITHOUT reacquiring the hold, and
normal VRRP preemption does not consume cluster `syncReady`
(`instance.go:880`, `sync_state.go:11`), so an initial
repair can complete, a later overflow can lose E1, and a
priority event can promote the incomplete standby before
the replacement `JOURNAL_END`: EVERY aggregate readiness
true→false transition acquires a new generation-scoped
hold — MINTED FRESH per transition, with releases
generation-validated (v9.9.54.13, round-60 SMR F2: a
true→false→true flap mints a fresh hold generation per
transition, and a completion releases ONLY the exact
generation it armed — a release for generation N is a no-op
when the current hold is generation N+K, so an earlier
hold's release can never race a newer hold)); the alternative is the explicit
aggregate: EVERY locally relevant obligation discharged at
the current generation — enumerated EXACTLY (v9.9.54.11,
round-59 SMR F2 + v9.9.54.14, round-60 Codex B2: the FIVE
classes are the inbound repair obligation (peer→local table
completeness), the outbound bulk obligation (local→peer
state), every cohort in the pending-rejection set, the
epoch/config publication state (a future-epoch park means
the config that admitted the flow is not yet applied —
`plan.md`'s own epoch-park machinery), and the parked FIFO
drain (no deferred session message still buffered) — a
future-epoch E1 parked against an unapplied config can
otherwise satisfy an incomplete three-item release
predicate while its own admission is unverified); and ONE
complete readiness generation is published and REVALIDATED
at every non-authoritative ownership commit (v9.9.54.14,
round-60 Codex B2: acquisition otherwise races an
already-authorized promotion — `SetSyncHold` updates
instances after acquiring only `Manager.mu`
(`vrrp/manager.go:354`), while the instance loop can pass
its priority check and call `becomeMaster` independently
(`instance.go:839`): the promotion's ownership commit
revalidates the readiness generation under the SAME lock
domain — `Manager.mu` covering BOTH operations (v9.9.54.15,
round-61 SMR F2: the commit (`becomeMaster`) and the
acquisition's instance update are both Manager-mutex
operations — SUPERSEDED at v9.9.54.19 (round-64 Codex H5):
the serialization object is the `PromotionPermit`, not
`Manager.mu`; the commit's revalidation takes NO
`vrrp.Manager.mu` (v9.9.54.18), so the
`UpdateInstances`/`vi.stop` join cannot cycle with a
committing run loop; `SetSyncHold`'s instance update
still takes `Manager.mu`, and the permit's outermost
ordering makes whichever lands second re-check and fail
if the generation moved), so the revalidation serializes naturally — the
commit reads the readiness generation under `Manager.mu`,
the acquisition's update writes under `Manager.mu`, and
whichever lands second re-checks and fails if the
generation moved); and the promotion gate is ONE NAMED
permit held from validation THROUGH publication (v9.9.54.16,
round-61 Codex H4: `SetSyncHold` uses `vrrp.Manager.mu` and
per-instance state (`vrrp/manager.go:354`), while
`becomeMaster` uses separate instance/VIP state — it
rechecks `ownerGen` at `instance.go:1305`, releases
`vipMu`, then publishes advert/event at `:1330`, so
readiness can advance after the check but before
publication: the promotion gate's permit is held from
generation validation THROUGH the final ownership
publication, with explicit ordering across normal VRRP and
private/direct RG commits — no advance can slip between
the check and the publish; and the permit is a DISTINCT
NAMED OBJECT, `PromotionPermit`, with a stated lock order
(v9.9.54.17, round-62 Codex H5 + round-62 AGY Q3 +
round-62 SMR F6: `Manager.mu` cannot BE the permit —
`UpdateInstances` holds it across reconciliation
(`vrrp/manager.go:432`) and can wait without a deadline in
`vi.stop()` (`:510`) which joins the instance run loop
(`instance.go:1382`), so a permit holder that needs the
run loop while holding `Manager.mu` deadlocks the domain;
and private/direct ownership publishes under `directVIPMu`
(`daemon_ha_vip.go:166`), outside the `Manager.mu` domain
entirely: `PromotionPermit` is owned by the cluster
manager and is the OUTERMOST acquisition in the order —
acquired BEFORE `Manager.mu`/`vipMu`/`directVIPMu` and any
instance lock, released after all of them, NEVER acquired
while holding any of them; the false→true readiness
ADVANCER never acquires it (the generation CHECK under the
permit covers it — a stale validation fails fast), but
EVERY true→false readiness-LOSS writer takes the permit
(exclusive, same outermost order — v9.9.54.18, round-63
Codex B4: otherwise G2's not-ready publication can slip
into G1's validate→publish window and fence or race a
just-promoted master — whoever holds the permit first
wins deterministically); the generation revalidation
under the permit NEVER acquires `vrrp.Manager.mu` (the
readiness generation lives in the CLUSTER manager's
domain; `becomeMaster`'s VRRP-side reads
(`instance.go:1305`) take instance locks only — v9.9.54.18,
round-63 SMR F1: otherwise the
`UpdateInstances`-holds-`Manager.mu`-across-`vi.stop()`
join (`vrrp/manager.go:432-436, :449`, `instance.go:1382`)
cycles with a run loop mid-commit, and the permit would be
decoration on a live deadlock); and run-loop JOINS never
occur while holding `Manager.mu` at all (v9.9.54.18,
round-63 Codex B4: `UpdateInstances` collects its
stop-set under the mutex and joins AFTER releasing it —
and the collect-then-join runs under ONE reconciliation
epoch (v9.9.54.19, round-64 Codex H5 + round-64 SMR F5:
periodic reconciliation (`daemon_ha.go:654`) and config
apply (`daemon_apply_tail.go:50`) can overlap the
unlocked join window — double-stop, overwrite, or an
unindexed live instance: ONE reconciliation mutex/epoch
serializes every `UpdateInstances` pass (the loser
re-reads the desired set and re-diffs); the stop-set
detaches EXACT POINTERS under the lock with
generation-tagged tombstones (never keys — a re-created
key maps a NEW object), and completion is
pointer-and-generation CAS; and the epoch's ordering
against the permit is STATED (v9.9.54.20, round-65 Codex
H5 + round-65 AGY T4 + round-65 SMR F5: a reconciliation
pass holds the epoch across the detached-instance join
while that run loop, mid-`becomeMaster`, holds the
`PromotionPermit` — and a config/readiness path holding
the permit entering `UpdateInstances`
(`daemon_apply_tail.go:50`) would wait for the epoch:
epoch → join → run-loop → permit → epoch is a cycle:
NO path ever acquires or waits on the reconciliation
epoch while holding the `PromotionPermit` (config apply
under the permit QUEUES the reconciliation — it never
enters `UpdateInstances` inline — but the queue carries
TRUTH (v9.9.54.21, round-66 Codex H6 + round-66 SMR F5:
current apply synchronously relies on `UpdateInstances`
validation (`daemon_apply_tail.go:42`), which REJECTS
malformed or conflicting instances (`manager.go:443,
:461`) — merely queueing permits config push and
`MarkActiveApplied` before the queued failure
(`daemon_apply_commit.go:274, :284`): the synchronous
path performs PURE validation (no side effects) BEFORE
the push, enqueues an IMMUTABLE config-generation
snapshot, and AWAITS that generation's result AFTER
releasing the permit; the drainer re-reads the desired
set at drain time — the queue carries a generation
marker, never a desired-set snapshot — so two queued
passes coalesce onto the LATEST desired state), and the promotion
recheck includes the detach/tombstone generation));
it is acquired BEFORE the generation
read it validates; its span covers BOTH the normal VRRP
publication (`instance.go:1305` recheck → `:1330`
advert/event) and the private/direct `directVIPMu`
publication — the two commit paths hold the SAME permit;
every publication step under the permit is
deadline-bounded or nonblocking (v9.9.54.18, round-63
Codex H5 + round-63 SMR F6: `sendAdvert`'s IPv4/IPv6
socket writes have no production write deadline
(`instance_send.go:39, :140, :218`) — one blocked write
would stall G2 fencing and every unrelated RG promotion
indefinitely); the publication OPERATION is cancellable
and token-fenced, bounded STRICTLY BELOW the peer's
master-down horizon (v9.9.54.19, round-64 Codex H6: a
socket deadline alone does not bound the synchronous VIP
operations — `addVIPsLocked`'s uncontexted
`netlink.AddrAdd` (`instance_vip.go:185, :208`), direct
mode likewise (`daemon_ha_vip.go:244`) — and `sendAdvert`
returns no result while ignoring per-family failures
(`instance_send.go:39, :68`): the netlink calls gain
context/deadline, `sendAdvert` returns PER-FAMILY
outcomes, the whole publication is one cancellable
token-fenced operation bounded below masterDownInterval,
and a publication timeout is POSSIBLY-PUBLISHED —
forward-only idempotent recovery, never reclaim (the
PONR rule)); the permit is ALWAYS released by its
own deadline, never held past it);
and no permit holder ever joins an instance run loop while
holding it (the run loop does not take the permit))), so an acquisition can never land after the
promotion's commit without the commit re-checking); and the hold's timeout
NEVER silently releases while a negotiated repair
obligation remains armed (a stale timeout checks the
generation and re-arms); and the hold's SCOPE is
spontaneous preemption only (v9.9.54.10, round-58 SMR F1:
a PLANNED/manual failover (`request mastership`,
`ForceRGMaster`) and priority-0 takeover are
operator-authoritative and BYPASS the hold via an EXPLICIT
post-barrier override (v9.9.54.10, round-58 Codex M6: the
hold is an AUTOMATIC-ELECTION fence — spontaneous
priority-driven election only, in BOTH normal VRRP and
private/direct RG mode (whose `takeoverReadinessForRG`
today omits sync readiness, `daemon_ha_vip.go:40`) — and a
planned transfer uses the explicit post-barrier override
equivalent to VRRP's `ForceRGMaster` path
(`vrrp/manager.go:761`) — issued as a ONE-SHOT, PER-RG
TRANSFER-GENERATION TOKEN with operator-intent provenance
(v9.9.54.12, round-59 Codex H5: `ClusterEvent` carries no
transition reason (`cluster/manager.go:73`) and `sendEvent`
discards the textual reason (`:460`), so every
`Secondary → Primary` event invokes `ForceRGMaster`
(`daemon_ha.go:314`) and a literal "ForceRGMaster-equivalent"
cannot distinguish planned transfer from automatic election:
the token is issued only after the explicit repair/barrier
proof — AND only after the MISSING-STATE PREDICATES CLEAR
(v9.9.54.12, round-59 Codex B3: `WaitForPeerBarrier` proves
only that earlier queued frames were processed
(`sync_bulk.go:329`; the receiver merely acknowledges the
marker, `sync_conn_read.go:496`) — it cannot reconstruct E1
discarded during overflow or rejected before publication,
and the demoting node explicitly skips bulk readiness,
stops retry, and then sends the barrier
(`daemon_ha_userspace_readiness.go:155, :160, :186`): the
override issues only after the pending-rejection set is
empty AND no repair obligation is outstanding AND the last
full repair completed through `JOURNAL_END` at the current
generation — including the epoch-park state (a parked
future-epoch cohort is outstanding state, v9.9.54.14,
round-60 Codex B2's full predicate) — the barrier alone
never substitutes for state completeness; and EVERY planned
demotion entry point uses the same terminally validated
protocol (v9.9.54.16, round-61 Codex H5: ISSU
`ForceSecondary` immediately marks every RG secondary
WITHOUT invoking ManualFailover's pre-hook
(`failover.go:140, :159`) — if B lacks E1, an ISSU drain
can demote A without the forced repair/`JOURNAL_END`/token
sequence, after which B assumes ownership incomplete:
`ForceSecondary` runs the same forced-repair →
`JOURNAL_END` → token sequence BEFORE marking RGs
secondary (its pre-hook is the same transaction), as ONE
BOUNDED ALL-RG TRANSACTION (v9.9.54.17, round-62 Codex B4
+ round-62 AGY Q3 + round-62 SMR F7: `ForceSecondary` is
today a bounded immediate mark-and-return
(`failover.go:140-165`) gated only by `peerAlive`
(`:144-146`) — an UNBOUNDED forced-repair wait would hang
the ISSU drain indefinitely (a live-but-slow or
mid-upgrade peer that never acknowledges `JOURNAL_END`),
and a mid-sequence failure was undefined: the sequence
SNAPSHOTS every RG's state generation at start (the
`peerAlive` gate is re-validated at sequence start), runs
the forced repair WITHOUT holding the cluster manager
lock, and on `JOURNAL_END` ATOMICALLY revalidates EVERY
member RG's snapshot generation before ANY RG is marked
(the recheck discipline of batch manual failover,
`failover.go:569, :641`) — demote-ALL-or-mutate-NONE; the
whole sequence is bounded by a NAMED timeout, and on
timeout, peer loss, or generation mismatch it returns an
error, marks NOTHING, and retains ownership (the ISSU
drain aborts operator-visible — the operator re-drives),
never proceeding without the validated transfer; and the
transaction applies a CONTINUE-AND-JOURNAL admission
policy with an END-TO-END CUTOFF WATERMARK (v9.9.54.19,
round-64 Codex B2 + round-64 SMR F1/F3 — the v9.9.54.18
"freeze" was ambiguous between two policies, and a hard
freeze would stall production new-flows for the whole
drain, a regression in the opposite direction of the fix;
and "in-flight commits" was undefined against the
two-step accept (`install.rs:209, :235` enqueue) → worker
drain (`loop_body/mod.rs:1096`) → helper→Go stream → Go
journal pipeline: new admissions CONTINUE under the
journal during the repair (no production stall — every
post-snapshot admission is journaled by construction); at
the cutoff a BRIEF FINAL admission/publication fence
engages at the dataplane admission point (v9.9.54.20,
round-65 Codex B2 — the v9.9.54.19 peer-ACK drain
predicate was causally unsatisfiable: the only negotiated
peer proof is `JOURNAL_ACK`, produced AFTER `JOURNAL_END`;
the helper ACK proves only callback completion
(`eventstream.go:145`), and `QueueSessionV4` discards
queue failure (`sync_conn_write.go:36, :56`); and
admissions continuing AFTER the seal left E2 buffered to
`loop_body/mod.rs:1096`, reaching Go post-demotion and
ignored (`daemon_ha_userspace_stream.go:191`) — B lacking
E2 and its NAT reservation; and the fence is an RW-FENCE
with an admission/watermark ATOMIC boundary (v9.9.54.21,
round-66 Codex B2: a worker can allocate NAT BEFORE the
fence (`poll_descriptor/mod.rs:2142, :2256`), pause, and
resume after the coordinator drains and seals — then
install E2 and publish shared state
(`poll_descriptor/mod.rs:2449, :2591`) with its Open delta
waiting for the loop tail (`loop_body/mod.rs:1096`) and
reaching Go post-demotion, discarded
(`daemon_ha_userspace_stream.go:185`): every admission
takes a READ PERMIT held from BEFORE NAT allocation
THROUGH publication AND durable local-journal receipt;
the fence's WRITE side acquires only after every held
read permit drains (workers keep draining — the fence
never blocks an in-flight admission); a NEW admission
arriving while the write side is held receives a DISTINCT
NONBLOCKING FENCED RESULT — drop-without-RST (round-66
SMR F3: an RST kills the flow outright; a drop lets the
client's retransmit land after the fence lifts on the new
primary; UDP/ICMP first packets rely on application retry
— both right for a millisecond fence); and the fence has
its OWN INDEPENDENT MILLISECOND-SCALE deadline (v9.9.54.21,
round-66 Codex H5: production/manual demotion pass 30-
and 60-second bounds (`daemon_ha_userspace_readiness.go:51,
:126`) and `WaitForPeerBarrier` may consume the whole
interval (`sync_bulk.go:363`) — holding the fence
throughout would drop every new TCP handshake and
UDP/ICMP datagram for the full timeout: the fence
releases IMMEDIATELY on connection, repair-generation,
or barrier failure, and the long transaction timeout
runs OUTSIDE the fence)): the drain's completion
predicate is DURABLE LOCAL-JOURNAL acceptance of every
delta admitted up to the watermark (accepted → published →
locally journaled — never a peer frame that cannot exist
yet); the FINAL fence stops NEW dataplane admissions/publishes
only for the seal→barrier→demote window (milliseconds —
the long repair runs fence-free; the fence is what
prevents post-seal arrivals, not the post-demotion
ignore); the post-cut journal seals ONLY after the
local watermark drains (the seal-on-bulk ordering is
subordinated to the watermark); the terminal
barrier/marker is sent ONLY AFTER the seal (so the
barrier covers the sealed set); the freeze applies ONLY
to non-journaled state (NAT pool releases, config-epoch
publications) and is held THROUGH the demotion; and an
abort RELEASES the fence and unseals (the transaction
already retains ownership) — with the abort consistency
rule stated (v9.9.54.20, round-65 AGY T2 + round-65 SMR
F3: A's table remains authoritative — A retains primary;
B's partial applications are idempotent installs
superseded by the next bulk/repair; an aborted drain
BUMPS the repair obligation so the reconnect's full
repair reconciles B's partials — the abort is a no-op for
dataplane correctness on both sides) — no old-owner commit lands
after the cutoff UN-covered); and the snapshot's substrate is a
NEVER-REUSED per-RG incarnation PLUS a global
membership/config generation (v9.9.54.18, round-63 Codex
H6: today's only per-RG generation is expressly a
`ResetFailover` supersession counter (`manager.go:306`,
`failover.go:200`) — elections change RG state without
bumping it (`election.go:337`) and config apply
adds/mutates/removes RGs without touching it
(`group_state.go:20, :42`), so a config adding RG N during
the off-lock repair would be missed or demoted
unsnapshotted: each RG gains a never-reused incarnation
(`ResetFailover` supersedes by BUMPING, never resetting)
and a GLOBAL membership generation bumps on every RG
add/mutate/remove; the atomic revalidation checks BOTH
the exact membership set and every member incarnation,
and a membership change aborts the transaction (error,
ownership retained))); the alternative
is to FORCE AND VALIDATE a full repair through
`JOURNAL_END` BEFORE STOPPING RETRY (v9.9.54.14, round-60
Codex B3: the demoting node stops bulk retry BEFORE sending
the barrier (`daemon_ha_userspace_readiness.go:155, :160`),
so forcing the repair must come FIRST — stop retry only
after the forced repair's `JOURNAL_END` lands, never
before), with the forced repair running through the NORMAL
obligation machinery (arm → drive → `JOURNAL_END`,
re-arming the retry machinery for one cycle) and NEVER
gated by the barrier (the barrier only gates the override's
issue — no wait cycle, v9.9.54.13, round-60 SMR F3) — and
its content is mastership-INDEPENDENT (v9.9.54.15,
round-61 SMR F3: the forced repair transfers the DEMOTING
NODE'S OWN table, which exists independent of which node is
master — a mid-repair VRRP priority drop (demotion cost or
priority-0 advertisements) does not invalidate the repair
(the peer needs A's table regardless of who holds
mastership), and the override's barrier follows the
repair's completion regardless of the then-current master) —
carrying its TRANSFER-GENERATION and validated
like the readiness writers — and bound to the readiness
proof it authorizes (v9.9.54.14, round-60 Codex B4: a proof
completing at generation G followed by an overflow
advancing readiness to G+1 must not let the token bypass
the newer hold: the token binds `(local/peer incarnation,
request ID, transfer generation, readiness generation)`;
and the activation is a DURABLE
`Authorized → Claimed → Applied` TRANSACTION (v9.9.54.16,
round-61 Codex B2 — a ONE-SHOT token cannot be CAS-consumed
before EVERY activation side effect, because ownership
activation is multi-stage
(`commitRequestedPeerFailover` applies the override and
runs election (`failover.go:313, :335`); the daemon later
performs `SetCluster`, `SetRGActive`, route changes, and
`ForceRGMaster` (`daemon_ha.go:287, :314`)): ONE initial
CAS claims the exact tuple BEFORE any side effect (the
`Authorized → Claimed` transition); each later IDEMPOTENT
stage (election, `SetCluster`, `SetRGActive`, routes,
`ForceRGMaster`) validates that IMMUTABLE claim and records
its progress (the claim is never re-consumed — stages
validate it); and the transaction's FAILURE boundary is
the POINT OF NO RETURN with a STAGE LEDGER (v9.9.54.17,
round-62 Codex B2 + round-62 SMR F4 — "rolls back or
retains the old-owner lease" was undefined for
wire-visible stages and an already-demoted old owner): the
PONR is the FIRST externally visible ownership publication
(`ForceRGMaster`'s VIP publish + advertisement,
`instance.go:1296, :1330`); the claim carries a stage
ledger (each idempotent stage records its completion
against the immutable claim); a failure BEFORE the PONR
compensates the recorded stages in REVERSE order (every
pre-PONR stage is cluster-local state — override removal,
election reversion — none has emitted wire ownership) and
the transition aborts to the conservative DUAL-SECONDARY
outcome: the demoting node's `ManualFailover` latch
(`failover.go:159`) IS the retained old-owner lease — the
node stays secondary, operator-visible and alarming, and
any auto-restore lease (`daemon_ha_sync.go:999`) is
suspended until the latch is explicitly cleared; a failure
AT or AFTER the PONR never compensates by reclaim (an
emitted advertisement cannot be unsent) — the transition
either completes FORWARD through the remaining stages or
reverses through the SAME terminally validated transfer
protocol in the opposite direction (a new authorized
transaction back toward the old owner); and the ledger is
VOLATILE BY DESIGN with QUIESCED restart recovery
(v9.9.54.18, round-63 Codex B3 + round-63 AGY Q2 +
round-63 SMR F5: a crash BETWEEN the first ownership
publication and the stage-ledger record is
indistinguishable from pre-PONR — and the old owner's
uncommitted transfer lease can expire and restore it
(`daemon_ha_sync.go:999`, `election.go:67`), while local
promotion precedes sending the final peer commit
(`failover.go:296`): the final peer commit is REORDERED
BEFORE the first VIP/netlink ownership mutation in EVERY
mode — the commit is the write-ahead PONR marker and the
PEER is its durable store (no local-disk write on the
failover critical path — the TWO named exceptions are the
crash-durable `Prepared`/`Applied` receipt and the
peerless operator intent, both written on the
commit/operator path, NEVER the failover path,
v9.9.54.21, round-66 SMR F8); the commit requires the peer's
ACK before the first mutation (round-64 SMR F8), and a
sent-but-unACKed commit enters a DURABLE `CommitUncertain`
claim — NEVER a unilateral abort (v9.9.54.19, round-64
Codex B3: B may apply the commit, become secondary, and
clear its restore lease (`failover.go:471`,
`daemon_ha_sync.go:1045`) with its ACK lost
(`sync_failover.go:477, :490`); A's timeout
(`sync_failover.go:255, :271`) aborting before publication
(`failover.go:305`) leaves B non-restoring and A never
publishing — dual-secondary availability loss: the
timeout does NOT abort — the claim retains (both
incarnations, request/transfer generation, the exact RG
set) as `CommitUncertain`, the commit is idempotently
QUERYABLE, and on reconnect A queries B's commit status;
B answers from its applied record (applied → the
transition completes per the record; not-applied → A
aborts cleanly pre-PONR); the claim clears ONLY on a
definitive answer; and the applied receipt is CRASH-DURABLE
(v9.9.54.20, round-65 Codex B3 + round-65 AGY T3: B's
restart recreates the receipt and lease maps EMPTY
(`manager.go:372, :386`) — B can no longer give the
definitive answer, absence-as-not-applied lets A abort
without restoring B's lease, and unknown stalls
indefinitely: the receipt persists in TWO durable states
(v9.9.54.21, round-66 Codex B3 — a single write-ahead
"applied" can LIE: B demotes and arms its restoration
lease (`daemon_ha_sync.go:999`), the lease expires, B
re-elects itself (`election.go:67`), and a delayed commit
then persists "applied" BEFORE execution — but
`FinalizePeerTransferOut` REJECTS because B is Primary
(`failover.go:471`), and after a crash A queries the
receipt and publishes while B remains Primary: the
receipt persists `Prepared` BEFORE execution (one small
local write, off the failover critical path) and `Applied`
ONLY AFTER finalization AND lease disposition BOTH
succeed; a `Prepared`-present restart REPLAYS the
prepared commit BEFORE any election or status answer
(so B can never re-elect past a pending prepared commit,
and A's query never sees "applied" for a commit that was
never finalized); every commit stage stays an
unconditionally-written value (set/delete — round-66 SMR
F4), never a counter or a conditional mutation, so the
replay is idempotent); a receipt-absent
restart (or a NEW `process_incarnation` answering for an
old-incarnation claim) answers `unknown-incarnation`,
never `not-applied` — and the pair runs the
new-incarnation RECOVERY TRANSACTION (atomically restore
B's lease OR complete A's transfer, exactly one, under
the `PromotionPermit` — and the COMPLETE leg is gated on
B's completeness (v9.9.54.21, round-66 SMR F1: completing
against a receipt-absent EMPTY B would promote an
incomplete table — the exact failure the plan exists to
kill: the forced-repair → `JOURNAL_END` sequence runs
FIRST and B proves the five-class predicate BEFORE the
transfer completes; otherwise the recovery restores B's
lease and A keeps ownership)); the dual-secondary recovery is
precise (round-65 SMR F4: a `ForceSecondary` abort marks
NOTHING (v9.9.54.17), so no latch exists to clear; a
`ManualFailover` latch is operator-persistent BY DESIGN —
operator-visible, operator-clearable, never auto-cleared;
B's lease restart-defaults to absent, which is CORRECT
for a not-applied resolution (the transfer never
happened))); the old owner's lease-expiry
restore CHECKS the commit record first — a committed
transfer NEVER auto-restores (and after ANY restart the
restore is itself quiesced exactly like a fresh
promotion — it is one, v9.9.54.19 round-64 SMR F4); a restarted node ALWAYS
enters the existing startup sync-hold (`preempt=false`),
never resumes an ownership transaction from volatile
local state alone, and revalidates (old-owner lease,
transfer generation) WITH THE PEER before any promotion;
an incomplete ledger reconstructs as pre-PONR and its
compensation is CLUSTER-LOCAL ONLY (override removal,
election reversion — never wire reclaim: the "post-PONR
never compensates by reclaim" invariant holds in BOTH
classifications because compensation NEVER emits wire
traffic); a stale advertisement self-expires
(masterDownInterval ~97ms) and the network reconverges
through the surviving node's adverts); the pre-v9.9.54.16
"CAS-consumed BEFORE EVERY activation side effect" clause
is RETRACTED (v9.9.54.17, round-62 Codex B2: one claim,
one CAS — each stage validates the immutable claim's
recorded readiness generation against the packed word at
its mutation point, never re-consumes); and it
persists with the exact desired-transition generation
across event replay — `ClusterEvent` carries the token
reference (never dropped without the token's lifecycle), so
a dropped-and-replayed event cannot re-present a stale
token (`cluster/manager.go:73, :460`), and the dataplane
activation before `ForceRGMaster` (`daemon_ha.go:287`)
validates the same tuple), carries the operator intent (the request's
authenticated source and reason), and is consumed by the
override; a `Secondary → Primary` event WITHOUT a token is
an automatic election and fenced by the hold; and the
initiating preflight at `failover.go:267` (which can reject
pending bulk before that repair sequence begins) is
reconciled — its pending-bulk rejection defers to the
token flow, not an independent rejection), which does NOT clear the
underlying repair obligation: the pre-v9.9.54.17
planned-transfer CODE path bypassed bulk readiness and
relied on the final barrier (a disconnected sync peer
returned success, readiness explicitly skipped, retry
stopped, only the FIFO barrier awaited —
`daemon_ha_userspace_readiness.go:147, :155, :186` — and a
barrier cannot reconstruct E1 discarded during overflow:
`sync_bulk.go:329` proves only that earlier queued frames
were processed and `sync_conn_read.go:496` merely
acknowledges the marker): v9.9.54.17 RETRACTS the
barrier-only rule (round-62 Codex B4 — the barrier-only
path is the code being REPLACED, never the plan's rule;
planned transfer runs the SAME five-class predicate +
forced-repair → `JOURNAL_END` → token sequence as every
other planned demotion), so
the packed not-ready state must NOT fold into the
`RequestPeerFailover` admission/commit rejection
(`failover.go:233, :321`) — the override is explicit, not
an accidental fold-in, and issues only after the
five-class predicate clears (v9.9.54.14)); exactly as they
bypass the sync-hold preempt gate today (the same existing
exemption class) — the repair continues or is superseded by
the failover's own state transition, and the operator path
makes NO unconditional-progress promise (v9.9.54.16,
round-61 Codex M6: the safe gate withholds the token while
pending rejections, repair, or epoch/park state are
incomplete — and a PERSISTENT local-authority tuple
conflict can keep a cohort pending until the local holder
exits (`plan.md`'s own local-authority-wins rule), which no
amount of repeated repair can satisfy: the withheld state
is OPERATOR-VISIBLE as a defined not-ready failure (never a
silent stall and never a promise of progress), and the only
bypass is a SEPARATELY EXPLICIT disruptive mode
(operator-confirmed, named, and alarming — with defined
POSTCONDITIONS (v9.9.54.17, round-62 Codex M6 + round-62
AGY Q4 + round-62 SMR F8: a disruptive transfer RETAINS
every pending-rejection/repair obligation on the receiver,
keeps the receiver's published readiness FALSE (never
`syncReady = true` — that would falsely signal table
completeness to the cluster), FENCES every subsequent
automatic AND ordinary safe transfer, and latches a
durable DEGRADED alarm until a current full repair
completes through `JOURNAL_END`; and it NEVER reports
through the normal safe-stop path — the ISSU completion
check (`upgrade_drain.go:46, :115`) prints safe-to-stop
only when the five-class predicate is green, and the
disruptive mode is a DISTINCT named API whose report says
degraded, never safe — and it carries a one-shot
`DisruptiveTransfer` CLAIM (v9.9.54.18, round-63 Codex H7
+ round-63 SMR F2: ordinary transfer tokens issue only
when the five predicates are green, an event without a
token is classified automatic and fenced, and the
disruptive action exists precisely while those predicates
are FALSE — a broad bypass is unsafe because current
events carry neither reason nor token and may be
dropped/replayed (`manager.go:73, :460`): the claim binds
(the exact RG set, both incarnations, request ID, transfer
generation, readiness generation), is claimed once, and
enters the SAME `Authorized → Claimed → Applied` stage
ledger, PONR, `CommitUncertain`, and recovery protocol as
an ordinary transfer (v9.9.54.19, round-64 Codex H7 +
round-64 SMR F7: the disruptive transition is itself
multi-stage (demote + election + dataplane + routes +
`ForceRGMaster`) — the ONLY difference from an ordinary
transfer is the admission predicate (the five-class gate
is bypassed by operator confirmation; everything else is
identical)), with ONE further difference: the PEERLESS
operator PONR (v9.9.54.20, round-65 Codex H6 + round-65
AGY T5 + round-65 SMR F1 — the disruptive mode exists
precisely when the peer is unreachable, so the ordinary
write-ahead (the peer's commit record + ACK) and the
`CommitUncertain` definitive-answer rule cannot operate:
`SendFailoverCommit` to a dead peer has no transport or
times out (`sync_failover.go:225, :255`), parking the
explicitly requested permanent-loss operation forever:
when the peer is unreachable, the operator's confirmed
intent — named, audited, bound to the exact RG set and
generations, and LOCALLY DURABLE (persisted, one small
write off the failover critical path) — IS the write-ahead
PONR marker; the disruptive claim RETIRES the missing peer
incarnation and FENCES it pending authoritative reseed;
and the retirement is enforced AT THE ELECTION SURFACE
(v9.9.54.21, round-66 Codex B4 + round-66 SMR F6:
heartbeats carry node/RG state but NO session-sync
process incarnation or retirement generation
(`heartbeat.go:93`) — a resumed/restarted peer passes the
replay checks (`heartbeat.go:560`), installs its RG
state, and runs election IMMEDIATELY (`heartbeat.go:848`,
`heartbeat_manager.go:293`), so priority processing can
yield ownership BEFORE the authoritative reseed
(`election.go:172`): the retirement record rides the
heartbeat (the sender's session-sync incarnation and the
peer's retired-incarnation generation), and a heartbeat
from a retired or unvalidated incarnation is LIVENESS-ONLY
— it proves the node is up, and its RG state and
priorities are IGNORED for election until authenticated
quiescence, reseed, and fence clearance complete; a
STILL-LIVE partitioned owner (heartbeat arriving from the
incarnation the operator retired) requires EXTERNAL
fencing (the operator's disruptive confirmation names it —
the surviving node advertises the retirement so the
partitioned owner demotes itself on sight)); a returning
peer is quiesced and re-seeded from the surviving
cluster state exactly like a `CommitUncertain`
resolution (applied-by-operator-intent → forward), and
the revalidation exchange NAMES the retired incarnation
so the returner re-seeds rather than re-asserts
(round-66 SMR F6); the
claim NEVER waits on a dead peer's answer, and an operator
CLEAR of a peer-absent `CommitUncertain` is itself
operator-confirmed, named, and alarming), validated under the
`PromotionPermit` for ONLY that
transition; and the OPERATOR force path (`ForceRGMaster`
force=true, priority-0 takeover — today's ungated
exemption class) carries the same operator-minted claim
(named, audited), so the exemption is never a bare fence
bypass and never discarded for want of a transaction); and
the permanent-loss fence lift is an operator RESET
(v9.9.54.18, round-63 SMR F3: a full repair through
`JOURNAL_END` requires the old owner alive — if the old
owner is permanently gone, no `JOURNAL_END` can complete
and the degraded latch would never lift: the
`ManualFailover`-reset analog clears the latch after the
receiver's table is authoritatively re-seeded from the
surviving cluster state)) — "the operator
is never blocked" is superseded by "the operator is never
SILENTLY blocked")); and the repair is BOUND TO THE NEGOTIATING
CONNECTION (v9.9.54.7, round-56 Codex B1: the protocol
class is connection-local, but `BulkSync` calls
`getActiveConn()` (`sync_bulk.go:50`), which ALWAYS prefers
fabric 0 when present (`sync_conn.go:27`) — fabric 0
remaining v0-class-latched while fabric 1 reconnects and
commits `repair-vN` would arm the obligation yet drive the
bulk over the v0 sibling, which can neither emit the
repair frames nor complete the terminal exchange, leaving
the obligation permanently armed despite a usable
repair-capable connection: the activation, the repair ID,
every redrive, and the terminal exchange bind to the EXACT
negotiated slot token (the connection that negotiated
`repair-vN`), so a repair-era bulk is pinned to that
token's connection and never selected by fabric
preference; the documented alternative — RETIRE every
legacy sibling connection before exposing `repair-vN` —
composes with the barrier/reset machinery and is the
fallback for transports where pinning is unsafe); and the
pin's failure mode is defined (v9.9.54.8, round-57 SMR F1:
a pinned connection's death mid-repair fails the ATTEMPT
(its `JOURNAL_ACK` can't arrive) but never strands the
repair — the repair ID is sender-INCARNATION-scoped (a
connection death is not an incarnation change), the
obligation is durable, and the NEXT connection's
negotiation re-arms the repair drive pinned to the NEW
token: the pin follows the token, the obligation follows
the incarnation);
and the readiness STATE ITSELF is versioned
(v9.9.54.4, round-55 Codex H2: a legacy `BulkEnd` queues
`go s.OnBulkSyncReceived()` ASYNCHRONOUSLY
(`sync_conn_read.go:246`) and the callback carries no
connection, protocol, or activation generation (`func()` at
`sync.go:407`), so a delayed G1 can call
`SetSyncReady(true)` (`daemon_ha_sync.go:90`) AFTER the
activation armed not-ready — and the older readiness timer
(`:40-47`) can do the same; readiness is a separate boolean
under `Manager.m.mu` (`sync_state.go:13`): every readiness
writer — the `OnBulkSyncReceived` callback, the readiness
timer, and the activation transaction — carries the
`(connection, protocol, activation)` generation and sets
ready ONLY through ONE packed atomic readiness word
(v9.9.54.6, round-56 AGY Q2 + round-56 Codex H2's domain
completion — the earlier "CAS when its generation remains
current AND no repair obligation is armed" is TWO atomic
reads across two lock domains, which does NOT compose
atomically: a delayed callback G1 can read
no-obligation-armed under `SessionSync.mu`, drop it, and
CAS ready=true under `Manager.m.mu` while an activation
G2 arms the obligation and sets ready=false in between
(`sync_state.go:13`): readiness is a SINGLE packed
atomic word (generation in the high bits, the ready bit
low) — a readiness writer CASes
`{gen, not-ready} → {gen, ready}` in ONE atomic
operation, and the WINNER RULE is explicit (v9.9.54.8,
round-57 SMR F4: the activation's bump is a CAS LOOP
(`{gen, *} → {gen+1, not-ready}`, retrying on contention)
and always wins by monotonicity — the generation only
increases; a writer's CAS can succeed only for an OLD
generation's completion BEFORE the bump lands, after which
the bump's `{gen+1, not-ready}` is authoritative and the
takeover decision reads the final state (armed, not-ready),
never a stale ready), so a generation bump by the activation
(`{gen, not-ready} → {gen+1, not-ready}`) invalidates
the writer's expectation ATOMICALLY with no cross-lock
check at all; the callback captures its generation at
queue time and its stale `{gen, ready}` expectation
fails the CAS deterministically), and the CAS ORDER and
bundle serialization are explicit (v9.9.54.9, round-57
Codex H2: the readiness writer is ONE-SHOT (its CAS attempt
fires once — a writer that CASes `{g, not-ready} →
{g, ready}` and pauses has committed ONLY the bit so far,
and its remaining effects run as generation-tagged
idempotent follow-ups OUTSIDE the packed word's critical
section (v9.9.54.12, round-59 Codex H4: this strikes the
last "inside the packed word's critical section" straggler
— the v9.9.54.10 `Completing(g, ticket)` rule is the only
effect-placement contract), so an activation's bump can never split
them); the activation CAS-loops `{g, *} → {g+1, not-ready}`;
if the writer wins the CAS, the activation WAITS for the
entire completion bundle under a RECOVERABLE
`Completing(g, ticket)` state with a deadline and
generation-tagged, idempotent effects (v9.9.54.10,
round-58 Codex H3 — "wait under the packed word's critical
section" can hang FOREVER (and v9.9.54.12, round-59 Codex H4:
the `Completing(g, ticket)` state gets a DURABLE
same-generation watchdog/executor — G1 can enter
`Completing`, block acquiring `vrrp.Manager.mu` through
`ReleaseSyncHold` (`daemon_ha_sync.go:90`,
`vrrp/manager.go:389`), and expire while `UpdateInstances`
waits indefinitely in `vi.stop()` (`:432`, `:510`,
`instance.go:1382`), so with no later activation nothing
would retry G1 and G2 cannot safely execute G1's ready
effects: the executor retries abandoned tickets for the
CURRENT generation; EACH target API validates ticket AND
generation before executing an effect — with the APIs
VERSIONED to take them (v9.9.54.14, round-60 Codex H5:
today's APIs are unversioned (`ReleaseSyncHold()`,
`daemon_ha_sync.go:19`'s timer cancellation) — each gains a
`(generation, ticket)` parameter it validates before
acting, so a stale ticket's effect performs nothing even if
dispatched); and the submission is COALESCED and
NONBLOCKING with at most ONE in-flight attempt per ticket
(v9.9.54.14, round-60 Codex H5: a naïve watchdog that
itself calls the blocking API accumulates blocked
goroutines and cannot cancel a blocked mutex acquisition —
the executor submits each effect to its target API's own
deadline-aware submission path (never blocking on
`vrrp.Manager.mu` in the control path), coalesces retries
for the same ticket, and caps in-flight attempts at one);
and the executor's
OWN liveness is structural (v9.9.54.13, round-60 SMR F5:
the watchdog dispatches effects to per-ticket WORKERS that
validate ticket+generation, and the watchdog itself NEVER
calls any effect API — it cannot block on `vrrp.Manager.mu`
or anything else; it monitors worker deadlines, and a hung
WORKER's ticket is abandoned by deadline, never by the
watchdog blocking); and supersession is
explicit — and FENCE-FIRST (v9.9.54.16, round-61 Codex B3:
ordering the supersession after G1's completion or "safe
abandonment" lets a G1 worker validate, clear the hold,
restore one instance, and block during the remaining
multi-instance release (`vrrp/manager.go:389`), so an
overflow creating G2 missing state can see the restored
instance process `preemptNowCh` before G2's fence exists
(`instance.go:880`): G2 FIRST revokes T1, publishes
`G2/not-ready`, and establishes the ownership fence, and
ONLY THEN drains or abandons G1 — never completes-first;
and target validation is atomic with each EXTERNALLY
VISIBLE mutation (each effect checks ticket+generation at
the mutation point, not merely once on API entry); and the
fence RE-COVERS every instance G1 touched — the
`G2/not-ready` publication re-acquires the per-instance
election hold on any instance G1 already released, never
an aggregate word alone (v9.9.54.17, round-62 SMR F5);
and the QUEUED promotion carries the claim (v9.9.54.17,
round-62 Codex B3: the force-promote path sets the scalar
`forcePreemptOnce` and enqueues an UNVERSIONED wakeup
(`vrrp/manager.go:767`) whose delayed consumer reads
`force=true`, bypasses the normal preemption test, and
enters `becomeMaster` with no ticket check
(`instance.go:880, :895`) — a G1-queued promotion would
cross G2's fence: the wakeup carries `(claim,
generation)` and the instance run loop — which NEVER
acquires the `PromotionPermit` itself (v9.9.54.17 lock
order) — only DELIVERS the tuple into `becomeMaster`,
whose commit path already holds the permit and validates
`(claim, generation)` under it BEFORE any publish
(`instance.go:1305` recheck → `:1330` advert/event); a
stale queued promotion — ticket revoked or generation
advanced — is DISCARDED at that validation, never
published); supersession is ALWAYS fence-first — the
pre-v9.9.54.16 completes-first clause ("a new activation
supersedes the old ticket only after the executor confirms
the old ticket's effects either completed or were safely
abandoned") is RETRACTED (v9.9.54.17, round-62 Codex B3:
G1's remaining effects are abandoned by ticket revocation
— each per-mutation validation rejects them — never
awaited; each effect stays idempotent, so a revoked-then-
retried effect set re-runs safely)): the bundle's `ReleaseSyncHold`
waits for `vrrp.Manager.mu` (`vrrp/manager.go:389`), and
`UpdateInstances` holds that mutex across reconciliation
(`:432`) and can wait without a deadline in `vi.stop()`
(`:510`, `instance.go:1382`) — a G1 writer that wins and
hangs in the bundle would block every later activation: the
CAS commits the state transition, the external effects run
as generation-tagged IDEMPOTENT follow-ups with their own
deadlines OUTSIDE the packed word's critical section (with
completion-time validation (v9.9.54.15, round-61 SMR F4:
every target API validates ticket AND generation at BOTH
submission and completion — an attempt whose ticket was
abandoned while it blocked is rejected at completion, so a
stale completion can never land an effect), the
activation serialization NEVER spans VRRP/netlink
operations), and a hung effect abandons its ticket so a
later activation retries it — IDEMPOTENTLY (v9.9.54.11,
round-59 SMR F3: the effect set contains NO counters and NO
one-shots — the hold release is a state (release twice =
no-op), the mirror write is a value (write twice = same
value), the primed flag is a flag (set twice = no-op), and
the timer cancellation is a cancel (twice = no-op) — so the
retry re-runs the whole effect set idempotently with no
double-execution hazard) (v9.9.54.10: this REPLACES the
v9.9.54.10-SMR-F2 "no I/O in the critical section" premise,
which was wrong about `ReleaseSyncHold`)); then bumps the
generation AND RE-ARMS THE ELECTION HOLD before exposing
`repair-vN`; the CAS ALWAYS precedes irreversible effects;
and a process crash mid-bundle reconstructs not-ready/hold
from current state at restart); and the generation check
authorizes the ENTIRE completion transaction, not just the
readiness bit (v9.9.54.7, round-56 Codex H2: the
`OnBulkSyncReceived` callback marks bulk primed, stops the
timer, and calls `ReleaseSyncHold()` BEFORE setting the
Manager readiness bit (`daemon_ha_sync.go:90`) — and
releasing the hold restores preemption immediately
(`vrrp/manager.go:380`), so a stale callback whose
generation fails can still release the operational hold:
the completion is ONE serialized, generation-conditional
transaction — the packed-word CAS authorizes the WHOLE
bundle (timer cancellation, `syncBulkPrimed`, the VRRP hold
release, and the Manager mirror) and a stale callback
performs NONE of them — the bundle being STALENESS-atomic
(v9.9.54.8, round-57 SMR F2: the generation check gates the
whole bundle atomically against STALENESS (current callback
→ all effects + ready; stale → none), and a PROCESS crash
mid-bundle is a different failure class covered by the
restart-time state rebuild (the VRRP hold is re-acquired,
primed recomputed, the timer re-armed, readiness recomputed
from current state) — no persistent inconsistency is
possible in either class), so a stale callback or timer
can never restore readiness over an armed repair);
and only THEN exposes `repair-vN` and
drives the bulk — so readiness never clears ahead of the
armed repair); the
negotiated feature state being PER-CONNECTION (v9.9.48,
round-51 SMR F3: it never persists across connections — a
reconnect re-runs the full negotiation (hello, proof,
wrapper, CONFIRM) before any feature enables, so there is
no cross-connection feature memory to race a downgrade);
"post-authenticated" meaning concretely (v9.9.46, round-50
SMR F2): on a v1-proof connection the capability fields are
exchanged but NOT transcript-covered; a peer wanting them
authenticated performs the v2 transcript proof as a SECOND
proof exchange once the connection's authenticated wrapper
is installed (the wrapper exists by then, so the v2 proof
can ride it), and until then the fields are advisory-only —
a v1 peer treats them as hints and keeps v1 behavior for
anything security-relevant — where the "second proof" IS
the authenticated `CAPABILITY_CONFIRM`/`CAPABILITY_DECISION`
exchange itself (v9.9.54.10, round-58 Codex H5: the earlier
"second v2 transcript proof" reading would define a
SECOND, incompatible v1-proof activation protocol —
implementations following opposite clauses would latch
different protocol classes: there is exactly ONE
post-wrapper authentication step, the CONFIRM/decision
exchange, and no separate transcript re-proof); the
v2 byte vectors are literal: the domain tag string, the
record-order rule, u16-LE length widths, little-endian
integers, and the proof-direction rule (each side proves its
OWN transcript)): v1 peers keep the v1 nonce-only proof and the
v1-v1 pair MASKS `reset-vN` plus every transcript-dependent
capability — enumerated EXACTLY (v9.9.44, round-49 SMR F1:
the transcript-dependent features are the reset lane itself,
`RESET_GEN`/`RESET_ACK`, and the reset-generation handshake,
so the mask is `reset-vN` plus those named frames; the
REPAIR protocol (`repair-vN`, `JOURNAL_END`/`JOURNAL_ACK`,
`RESYNC_REQUEST`, the cutoff/marker frames) rides the
ESTABLISHED authenticated connection and does not depend on
the v2 transcript — BUT on a v1-proof connection it is
INACTIVE like everything else until the matching
authenticated `CAPABILITY_CONFIRM` (v9.9.51, round-52 Codex
M2: this supersedes "negotiated independently — never
masked": on a v1-proof connection NO capability becomes
active except through matching same-connection CONFIRMs; the
repair protocol's independence from the v2 transcript is why
it CAN be confirmed post-wrapper rather than requiring the
v2 transcript at all);
when BOTH peers are v2, they exchange bounded raw HELLO
records and `AUTH_PROOF` authenticates a DOMAIN-SEPARATED,
length-prefixed, ORDERED pair of those exact records — with
ONE exact byte formula and golden vectors for both
directions (v9.9.47, round-50 Codex H4 — the raw-record and
field-list phrasings could conflict and independent
implementations could compute different proofs and
reconnect-loop (`sync_auth.go:401-404`,
`sync_conn.go:106-110, :435-477`):
`AUTH_PROOF_v2 = HMAC-SHA256(key, tag_v2 || prover_role ||
term(dialer_hello) || term(acceptor_hello) ||
term(dialer_cap) || term(acceptor_cap))` — the algorithm
named exactly (v9.9.53, round-53 Codex B1: "HMAC" alone is
ambiguous; the existing v1 proof already uses HMAC-SHA256,
`sync_auth.go:217`) — with an EXECUTABLE
byte grammar (v9.9.51, round-52 Codex B1 — without it, two
conforming implementations hash different bytes and
reconnect-loop (`sync_auth.go:401-404`,
`sync_conn.go:106-110, :435-477`)): every term is
`u16-LE(len) || the exact raw PAYLOAD bytes as transmitted`
(the wire payload, frame header EXCLUDED —
`readSyncFrameRaw` returns the payload separately from its
header (`sync_auth.go:289-310`), so the term covers the
payload bytes plus their u16-LE length, never the frame
header); the capability record's own layout is fully defined
(field order `(node_id, process_incarnation, capacity,
capacity_config_generation, capability bits)`, fixed widths —
u32/u64/u64/u64/u32, the bits packed LSB-first in the u32 per
the assignment table (v9.9.52, round-53 SMR F2 + v9.9.54.12,
round-59 Codex B1: bit 0 =
identity-enforcement, bit 1 = lease-input, bit 2 = repair-vN,
bit 3 = reset-vN, bit 4 = heartbeat-ack-capable, BIT 5 =
repair-v2 (the decision phase — the shared capability commit,
rolling-gated like the others; the decision-phase entry
predicate is the negotiated MAX-COMMON-VERSION ≥ 2
(v9.9.54.17, round-62 Codex B1 + round-62 SMR F1: ONE name,
ONE predicate — the retracted "BIT 5 = DECISION-PROTOCOL …
reads BIT 5 explicitly and NEVER infers decision support
from `repair-vN`" phrasing specified a bit-flag dependency
that diverges from the version rule the day a repair-v3
exists); an intermediate peer carrying `repair-vN` but not
bit 5 negotiates min-version v1 — repair-v1 RUNS unchanged
and the decision phase never activates (the
buffered-first-frame path is reserved for RECORD-LESS (v0)
peers, v9.9.54.18, round-63 Codex B1); every `-vN`
capability bit follows the SAME version machine (base bit
= v1, a future extension bit = the next version, min()
governs) while plain flags follow the intersection — a
future reset-v2 or repair-v3 never re-opens the r61/r62
class (v9.9.54.18, round-63 SMR F7a)); bits 6-31
reserved-zero (ENCODE-only — a conforming decoder IGNORES
unknown set bits, v9.9.54.17) — so "packed LSB-first" is unambiguous),
little-endian integers, no padding); never as reconstructed
fields, which could diverge in integer widths and field
order; the SHARED record segment
(`term(dialer_hello) || term(acceptor_hello) ||
term(dialer_cap) || term(acceptor_cap)`) is byte-identical
for both sides, and the FULL inputs differ ONLY by
`prover_role`; and the golden vectors are NORMATIVE AND
LITERAL (v9.9.54.1, round-54 AGY Q1 + round-53 Codex B1 —
computed per the formula above): the shared test key is
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`;
the shared inputs are `dialer_hello =
02014141414141414141414141414141414141414141414141414141414141414141`
(v2, keyed, 32×0x41), `acceptor_hello =
02014242424242424242424242424242424242424242424242424242424242424242`
(v2, keyed, 32×0x42), `dialer_cap =
01000000887766554433221100093d000000000007000000000000003f000000`
(node_id 1, incarnation 0x1122334455667788, capacity 4000000,
gen 7, bits 0x3F — BIT 5 exercised, v9.9.54.14, round-60
Codex L6; the standalone literal matches the complete
inputs, v9.9.54.16, round-61 Codex M7), and `acceptor_cap =
02000000112233445566778800093d000000000007000000000000003f000000`
(node_id 2, incarnation 0x8877665544332211, capacity 4000000,
gen 7, bits 0x3F); the DIALER vector (prover_role 0x01) has
input
`7870662d636c75737465722d73796e632f76322f68656c6c6f2d7472616e73637269707401220002014141414141414141414141414141414141414141414141414141414141414141220002014242424242424242424242424242424242424242424242424242424242424242200001000000887766554433221100093d000000000007000000000000003f000000200002000000112233445566778800093d000000000007000000000000003f000000`
and expected digest
`6a56876cb0155a1b37d3a91b9dc742aba33e04d30c4f17d81b80085acbab9344`;
the ACCEPTOR vector (prover_role 0x02) has input
`7870662d636c75737465722d73796e632f76322f68656c6c6f2d7472616e73637269707402220002014141414141414141414141414141414141414141414141414141414141414141220002014242424242424242424242424242424242424242424242424242424242424242200001000000887766554433221100093d000000000007000000000000003f000000200002000000112233445566778800093d000000000007000000000000003f000000`
and expected digest
`f46254ed135d2c127421bec0ff2f2f40f5a99c96830ec9abea850f78363d7c4b`
(both computed with HMAC-SHA256 over the formula's exact byte
grammar; each vector is a labeled triple of hex strings —
the key, the complete role-specific input concatenation,
the expected digest — with every field label named, so the
test file leaves no interpretation freedom, v9.9.54,
round-54 SMR F1)
(v9.9.52, round-53 SMR F1: each vector pins the ENTIRE input
byte string — both HELLO payloads and both capability
records with EVERY field value written out, not a
representative subset — plus the exact HMAC key bytes and
the expected output, for BOTH roles; a vector that leaves
any field unpinned lets two conforming implementations
diverge on that field); and the cap records entering the proof as
the EXACT WIRE BYTES sent and received (v9.9.50, round-52 SMR
F1: the sender hashes what it sent, the verifier hashes what
it received — byte-identical by TCP) (v9.9.49, round-51 Codex B2 — the earlier
`prover_record || verifier_record` conflicted with
"dialer-first" for an acceptor proof, and the legacy HELLO
carries only `{version, keyed, nonce}` (`sync_auth.go:345`),
so the capability fields need their own record): `tag_v2` is
the literal ASCII `xpf-cluster-sync/v2/hello-transcript`;
`prover_role` is one byte (`0x01` dialer / `0x02` acceptor)
identifying WHICH side computed this proof; `dialer_hello`
and `acceptor_hello` are BOTH sides' exact legacy-HELLO
payloads in FIXED (dialer, acceptor) order regardless of
who proves; `dialer_cap` and `acceptor_cap` are the two
capability records (each carrying `(node_id,
process_incarnation, capacity, capacity_config_generation,
the capability bits)`) in the same fixed order, each prefixed
by its u16-LE length; all integers are little-endian; and
golden HEXADECIMAL input/output vectors for BOTH proof
directions ship in the test plan — with the pair IDENTICAL for
both sides (v9.9.48, round-51 SMR F4: `prover_record` is the
prover's OWN sent HELLO, which the verifier also holds as
received, and `verifier_record` is the peer's HELLO as
received, so the dialer and the acceptor compute a
byte-identical SHARED RECORD SEGMENT despite each HELLO
carrying per-side nonces (the FULL inputs then differ ONLY
by `prover_role` — v9.9.54.2, round-54 Codex B1's wording
reconciliation), and
all integers are little-endian; the golden vectors for both
directions ship in the test plan),
the separator being a fixed tag distinct from the v1 proof tag
(v9.9.44, round-49 SMR F2: a different constant —
`xpf-cluster-sync/v2/hello-transcript` — so a v2 transcript
proof can never collide with or be mistaken for a v1 nonce
proof) — and
the proof runs BEFORE the authenticated frame wrapper
installs (the wrapper installs only after verification,
`sync_auth.go:406` — the transcript is not "inside" the
wrapper; it is what the wrapper's installation is gated on));
the canonical transcript — node ID, process incarnation,
capabilities, nonces — is what `AUTH_PROOF` covers (not a
bare nonce) — and the proof is verified BEFORE the
authenticated frame wrapper installs (v9.9.45, round-49 Codex
H2: this strikes the contradictory "inside the wrapper"
phrasing — the wrapper installs only after verification,
`sync_auth.go:406`; and v9.9.51 strikes the older field-list
encoding formerly here — the v9.9.51 executable grammar above
is the ONLY transcript grammar); and the RESET-only
allowlist explicitly includes the handshake sequence (HELLO
transcript → capability exchange → `AUTH_PROOF(transcript)` →
`RESET_GEN`/`RESET_ACK`), so the required proof is never an
implicit exception) — the two protocol-version bits are
explicit (v9.9.37, round-45 Codex H7: an intermediate peer can
support identity/heartbeat features while speaking only legacy
`BulkEnd`/`BulkAck`, and without the version bits a new node
would wait indefinitely for a terminal frame the peer cannot
send; today's hello is auth-only and keyed-only
(`sync_auth.go:314`), so the connection-independent hello
ADVERTISES `repair-vN` and `reset-vN` (v9.9.51, round-52
Codex M2: "negotiates" is corrected to "advertises" — the
HELLO only selects the transcript version and names what can
be confirmed later; on a v1-proof connection NO advertised
capability becomes active except through a matching
authenticated same-connection `CAPABILITY_CONFIRM`) — an
intermediate peer gets the v1/v0 class paths and never a
wait-forever (v9.9.54.19, round-64 Codex L8));
`RESYNC_REQUEST(repair_id)` (incarnation-scoped:
`(sender_incarnation, request_seqno)`); `RESET_GEN` /
`RESET_ACK` carry `(direction, node_incarnation,
reset_generation)`; `BulkStart` carries
`(repair_cutoff_epoch, repair_id, declared_member_count?)`; the
bulk markers echo `repair_id`; the CAPABILITY-CONDITIONED
COMPLETION MATRIX (v9.9.45, round-49 Codex B1 — the two-frame
rule cannot apply to mixed-version pairs: a legacy receiver
can't return `JOURNAL_ACK` (or even a bare `BulkAck` when
new→legacy synchronization is INSTALL-only without `BulkEnd`,
this plan's own install-only rule), and arming a negotiated
obligation there would strand the sender's cold-prime
forever; while legacy→new REQUIRES the current `BulkEnd`
readiness path (`sync_conn_read.go:241-247` →
`daemon_ha_sync.go:90-100`), which the "BulkEnd never
discharges" rule would forbid): (a) `repair-vN` pairs —
applied `JOURNAL_END` clears receiver inbound/readiness;
matching full-triple `JOURNAL_ACK` clears sender
outbound/cold-prime; `BulkEnd` and bare `BulkAck` clear
neither; (b) legacy→new full bulk — LEGACY completion is
retained (the `BulkEnd` readiness path stands for
unnegotiated senders; the "never discharges" rule applies
ONLY to negotiated repair-era bulks); (c) new→legacy
INSTALL-only prime — NO negotiated repair obligation is
armed AT ALL (the prime is fire-and-forget: cold-prime
clears after successful lossless emission, and the legacy
peer converges by its own invalidation and aging — the
pre-existing legacy semantics; suppressing the obligation is
the only safe posture, since the legacy peer can neither ACK
nor enforce identity; and the DOWNGRADE TRANSITION is
explicit (v9.9.47, round-50 Codex B1: an OUTBOUND repair
obligation can already exist under `repair-vN` when the peer
reconnects as legacy — capabilities are per-connection
(`sync_auth.go`), and the INSTALL-only prime can't produce
`JOURNAL_ACK`: obligations are keyed by `(creation protocol,
both peer incarnations)`, and a negotiated→legacy downgrade
either (i) persists the obligation in an explicit DEGRADED
state until the negotiated repair returns (the takeover
fence as backstop — never an implicit clear, because
clearing on emission would treat an unacknowledged prime as
repair; and a v2↔legacy FLAPPING peer never clears the
v2-incarnation obligation this way — the obligation keys
include both incarnations, so a legacy incarnation's
completion can't touch it, and each legacy→v2 flap re-arms
the negotiated path with the obligation discharging on the
next negotiated repair, v9.9.48, round-51 SMR F1), or (ii) ATOMICALLY supersedes the obligation into
the documented LEGACY BASELINE — ATOMICALLY at downgrade
detection, never lazily (v9.9.48: the baseline's prime is
defined concretely: the fresh incarnation-scoped close-both
+ cold-prime cycle — the legacy baseline's own reset —
whose completion is the lossless INSTALL-only emission);
and a legacy
`BulkEnd` NEVER clears a negotiated (repair-ID-bound)
obligation implicitly — the matrix's legacy-completion class
applies only to obligations CREATED as legacy); and the readiness ownership is explicit
(v9.9.46, round-50 SMR F1: the new node's transfer-readiness
for the install-only prime gates on its OWN sync state and
the lossless emission — never on the legacy peer's state,
which converges by its own mechanisms; and when a legacy→new
bulk completes while the new node ALSO has a negotiated
repair obligation outstanding, the two completion classes are
independent — the legacy bulk's completion does not touch the
armed obligation, and the node's readiness is the
CONJUNCTION: every armed obligation discharged per its own
rule, plus the legacy completion); the terminal exchange is TWO
distinct frames with LOCKED ROLES (v9.9.43, round-48 Codex B1 —
this supersedes calling `JOURNAL-END` "the terminal ACK" or
"the ONLY discharge": `JOURNAL_END(repair_id, journal_epoch,
terminal_seqno)` flows sender→receiver as the terminal MARKER
the receiver applies — its APPLICATION clears the RECEIVER's
inbound obligation and readiness, and it is NOT an
acknowledgement of anything; `JOURNAL_ACK` flows
receiver→sender carrying the SAME immutable triple and is the
ONLY discharge for the SENDER's outbound obligation and the
cold-prime latch; a bare `BulkAck`
u64 can never discharge: the legacy `BulkEnd`→reconcile/ACK
path (`sync_conn_read.go:205`) and the epoch-floor `BulkAck`
check (`:249`) are retained for v0-class peers only (v9.9.54.20 —
the class name, not "unnegotiated"), and a
delayed O1 ACK is never accepted against O2's obligation);
the terminal exchange is TWO distinct frames (v9.9.37,
round-45 Codex B2 — earlier text had the receiver "send an
ACK" while calling `JOURNAL-END` itself the terminal ACK and
defining no receiver→sender frame; today's only return frame
is a bare `BulkAck(u64)`, `sync_bulk.go:282`, with epoch-only
handling at `sync_conn_read.go:249`):
`JOURNAL_END(repair_id, journal_epoch, terminal_seqno)` flows
sender→receiver and is applied; `JOURNAL_ACK` flows
receiver→sender carrying the SAME immutable triple and is the
ONLY discharge for the sender's OUTBOUND obligation (the
cold-prime latch likewise clears only on `JOURNAL_ACK`, never
on `doBulkSync` merely writing `BulkEnd`, `sync_conn.go:194`);
the completed-repair RECEIPT is keyed by the FULL immutable
triple `(repair_id, journal_epoch, terminal_seqno)` and
retained through the terminal retransmission lifetime (a
duplicate `JOURNAL_END` revalidates against it and re-ACKs
WITHOUT re-mutating); after receipt expiry the sender mints a
FRESH repair ID for the next attempt (a receipt is never
reused past expiry, so a changed same-ID attempt can never be
mistaken for the original; and a `JOURNAL_END` whose repair ID
matches no current obligation and no live receipt is
DISCARDED, never processed as a repair — a very-late duplicate
of an expired repair can never mutate state, v9.9.38,
round-46 SMR F2); and every session frame is
presented with its connection's slot-membership token out-of-band
(the token is per-connection metadata, not a frame field).
The sender/receiver store lifecycle: the Go sidecar synced store gains
`(origin_process_nonce, flow_incarnation_id, row_version,
stable_rule_id_hash, admission_config_version, persistent_nat,
persistent_nat_permit)` per entry (v9.9.15,
round-30 Codex M5: the two selector fields are STORED per entry, not
recomputed — they cannot be reconstructed from the BPF projection
(`bpf_session_value.go:168`), whose positional policy ID is rewritten
across policy reorder (`bpf_map/mod.rs:384`), so dropping them here
would re-open the numeric-ID selection at
`daemon_policy_invalidate.go:311`),
learned from the install delta, compared on delete; the install data
for bulk and periodic resend is produced by the helper-authoritative
ATOMIC SNAPSHOT (a new helper method acquiring the canonical hierarchy
locks (`synced` → `nat` → `forward_wire` → indexes,
`coordinator/session_manager.rs:12-18`) and producing `(BPF/NAT row,
identity, row_version, stable_rule_id_hash, admission_config_version,
persistent_nat, persistent_nat_permit)` tuples in one lock span); the sender's install
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
  `origin_process_nonce`, `flow_incarnation_id`,
  `stable_rule_id_hash`,
  `admission_config_version`, `persistent_nat`,
  `persistent_nat_permit` — v9.9.15, round-30 Codex M5 + v9.9.17,
  round-32 Codex B1 + v9.9.22, round-37 Codex B2: the fence is the
  FULL `(origin_process_nonce, flow_incarnation_id)` pair, and the
  helper-local inventory listed only the incarnation —
  `SyncedSessionEntry` carries neither today (`worker/mod.rs:375`),
  so a queued cleanup for A1/E1 `(n1,id7)` could match same-key
  A2/E2 `(n2,id7)` after a sender restart and delete the
  replacement inside Rust before the Go sidecar can protect it;
  the FULL pair is carried and compared through canonical entries,
  aliases, worker entries, detached snapshots, and queued
  mutations; the selector fields AND the lease-derivation
  inputs must live on the shared entries too, since the
  helper-side current-state selection of §5.2 reads its own shared
  aliases and neither can be reconstructed from the BPF
  projection) — of these, `last_touch_ns` and `expires_after_ns`
  are node-local only (never wire-carried); the identity and
  selector fields ride the Part-B rolling-gated INSTALL tail
  described above (v9.9.16, round-31 Codex L5: the earlier blanket
  "never wire-carried in Phase 1" predated the v9.9.14
  selector-tail fold) — and the shared-map growth itself is
  rolling-upgrade safe either way.

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
| HA / rolling upgrade | LOW-MED | Part A: no wire change; Part B adds rolling-gated additive identity tails on INSTALL/Open AND DELETE PLUS the negotiated repair protocol (v9.9.37: capability-negotiated `repair-vN`/`reset-vN` — RESET_GEN/RESET_ACK on a barrier-exempt lane, RESYNC_REQUEST, repair_cutoff_epoch/repair_id on BulkStart, JOURNAL_END/JOURNAL_ACK as the only discharge, the post-cut journal, the completed-repair receipt, slot-membership tokens, and capacity negotiation; intermediate peers get the v1/v0 class paths via the version bits, never a wait-forever; old decoders ignore additive frames via the trailing-field tolerance; mixed-version behavior documented: gen-based deletes apply only to non-locally-authoritative entries, and identity-dependent deletes are suppressed toward unnegotiated peers); pre-upgrade and imported entries sit in the absorbing zero-trust state — closes refuse until churn (strictly more conservative than master; bounded lingering, §2; Phase 2 §10.5 closes it for synced flows). The replica no-Close invariant + the SharedPromote refuse trace are regression-tested. Accepted residual (v9.9.16): a temporary stop whose rebind never comes pins preserved sessions + escrowed NAT ports until process exit — no workers, no reaper; escape is the declared-permanent stop; strictly more conservative than today's lose-everything link-cycle behavior; and a teardown-failed latch (v9.9.37) prohibits rebind/reconcile after a deadline-expired teardown until every unquiesced old worker exits or the process restarts (operator-visible). |
| Teardown-failed latch | LOW (probability) | v9.9.40: a deadline-expired teardown arms the durable latch — rebind/reconcile prohibited until every unquiesced old worker exits or the process restarts. Terminal state: XSK disabled, dataplane down, readiness degraded, operator-visible (#6244 stage reporting); recovery action documented (worker exit or `systemctl restart xpfd`); next reconcile retries with a fresh generation once the latch clears. |
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
  logical rule ID (`<from>-><to>/<name>`, `policies_ids.go:101`) and
  the write-once admission config-sync generation as the DISTINCT
  selector fields — exactly `stable_rule_id_hash` +
  `admission_config_version` (v9.9.15, round-30 Codex M5: the
  content-addressed hash supplement was superseded in v9.9.9 — §5.2 —
  so there is NO "content version" selector; earlier drafts' mention
  of one is removed): same-content-different-name rules never
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
- **Persistent-import provenance + epoch deferral (v9.9.17, round-32
  SMR):** (a) epoch-skew lease import — C1 `target-host-port` → C2
  `any-remote-host`; g2 INSTALLs processed while C1 is applied; F1/F2
  co-hold P via the wire-carried `(persistent_nat,
  persistent_nat_permit)` inputs and NO mid-flow port swap occurs at
  takeover; (b) allocator-shape deferral — C1 pool ends at 40000, C2
  expands to 40001; the g2 INSTALL at 40001 parks the connection
  stream until C2 applies, then reserves exactly (no out-of-range
  rejection, no silent gap); a following delete for the same key can
  never bypass the parked install (stream-order proof); (c) kind
  dispatch — a persistent address-only flow preserving source port 80
  imports on the standby with NO port-bit reservation and keeps its
  public address at failover; (d) the import-transaction receipt —
  a post-reservation failure (incl. the install.rs:310 check) undoes
  EXACTLY the receipt's mutation through the RAII guard (v9.9.19:
  never a bare `rollback_flow` — `NoChange` undoes nothing,
  `Inserted`/`Retained` undo their full captured delta incl. expiry
  indexes/activation metadata/reverse-owner token, `Replaced`
  reinstates the dual-held old ownership), leaving no orphan lease
  (`active_flows` returns to the pre-import value); (e) legacy tail-less import stays
  non-persistent (rolling-upgrade parity with master); (f) the
  migration gate — a deterministic-PAT allocation, a `rollback_flow`,
  and an expiry-GC pass each attempted during the migration window
  either complete before the write permit (their state is in the
  drained snapshot) or transient-fail at the closed gate; B is
  published with the complete ownership state and never issues a
  held tuple or leaks a freed one; (g) resend/bulk fidelity — an
  empty-standby bulk re-emits the ENTRY's stamped lease inputs (not
  a queue-time re-derivation), so the restart-bulk co-holder case
  imports persistently.
- **Epoch-park protocol + import receipt + token indirection
  (v9.9.18, round-33):** (a) readiness predicate — a g2 INSTALL
  arriving while `applyingConfigGen == g2` (apply callback not yet
  succeeded) stays PARKED and processes only after
  `lastAppliedConfigGen >= g2 AND applyingConfigGen == 0`; (b)
  selective park — heartbeats and the enabling Config frame flow
  while session-state messages buffer: no missed-heartbeat failover
  during an apply lag, and the Config frame is never behind a parked
  INSTALL (the reconnect self-deadlock case: BulkStart/INSTALLs
  racing the async config push); (c) node-global watermark — in
  active/active, a non-authority's locally-born g2 flow does NOT
  park at the authority (both published C2), and BulkStart does not
  clear the watermarks; (d) no silent loss and no hot loop
  (v9.9.21, superseding the v9.9.18 drop-oldest clause): overflow
  marks the bulk/window LOSSY (no BulkEnd reconcile, no ACK),
  raises the logical-peer full-resync OBLIGATION whose PRIMARY
  driver closes BOTH fabrics (receiver-side, no wire change —
  cold-prime on reconnect drives the full bulk), with the
  rolling-gated RESYNC_REQUEST fast path for negotiated pairs and
  SEQUENCED DISCHARGE (v9.9.39: the receiver's inbound
  obligation clears only after APPLYING the exact
  `JOURNAL_END`; the sender's outbound obligation and the
  cold-prime latch clear only at the matching full-triple
  `JOURNAL_ACK` — this supersedes the earlier "ACK epoch above
  every in-flight epoch at raising" clause; a pre-overflow,
  in-flight, or bare-epoch ACK never clears), and a
  stuck apply repeats at bulk cadence with the takeover fence
  keeping the node not-transfer-ready until its published epoch
  reaches the peer's high-water AND its parked queues are empty
  with no outstanding obligation; (d2) resync CAUSALITY
  (v9.9.21, round-36 Codex M3; discharge wording updated
  v9.9.35): the repair bulk is asserted
  A→B (B's loss causes SENDER A's full-table iteration — a
  wrong-direction B→A bulk fails the test); a delayed
  PRE-obligation ACK does not discharge; a second overflow O2
  during O1's repair re-arms the raising-point generation;
  the RECEIVER's readiness moves only after APPLYING the exact
  post-O2 `JOURNAL_END`, and the SENDER's obligation clears
  only at the matching `JOURNAL_ACK` (v9.9.43); a
  failed redrive re-kicks (the obligation, not the
  `bulkRedriveInFlight` CAS, is the durable state); the
  close-both reset asserts the reconnect barrier (one fabric
  cannot reconnect before the other's EOF registers — no
  `wasDisconnected == false` cold-prime miss); and the typed
  token asserts `DirectHold` (locally-born: direct refcount,
  reap decrements) vs `GroupHold` (imported: clone distribution,
  reap drops only the clone, last-clone finalizer releases in
  canonical→allocator order) with no shared drop path; (d3)
  v9.9.22 mechanisms — with the v9.9.23.1/v9.9.24 corrections:
  the barrier-and-drain reset (B refuses inbound dial+accept
  during the barrier; A's slots drain to both-empty via EOF or
  the per-connection heartbeat-ack detector — NOT a sender-side
  first-EOF cascade, which v9.9.22 posited and v9.9.23+
  replaced; the cold-prime gate fires on the first POST-barrier
  install, and A's dialer retries never SURVIVE as occupied
  slots during the barrier (v9.9.29 — brief install-then-die is
  the refusal mechanism itself; the guarantee is that no retry
  occupies a slot AT barrier end); the repair-ID correlation
  (a bulk without the current repair ID is not the repair; a
  pre-request delayed bulk is serialized/superseded; the
  receiver's readiness moves only on the applied
  `JOURNAL_END`, and the sender's obligation clears only at
  the matching `JOURNAL_ACK` (v9.9.43)); the full
  identity pair in the helper inventory (a queued cleanup for
  `(n1,id7)` never matches `(n2,id7)` after sender restart);
  identity-conditional replacement (E1/P1/G1 → E2/P2/G2 installs
  G2's clone BEFORE dropping G1; identical ownership reuses the
  displaced clone with no count dip); immutable hold provenance
  (a promoted imported flow keeps its GroupHold across
  `SharedPromote` and demotion retags — variant never derives
  from origin); the two-stage cohort cleanup (an all-rejected
  import cohort is deleted — external-holders check, then
  canonical-family removal, then internal-clone drop); and the
  token-drop-free WRITE span (a last-clone drop during a
  migration defers to the release queue — no inline gate READ;
  the tunnel-remap purge runs before the WRITE permit). (d4)
  v9.9.23 mechanisms — with the v9.9.23.1/v9.9.24/v9.9.27
  corrections: the barrier-and-drain reset with the barrier
  generation fence (B closes both and refuses dial+accept;
  A's slots drain via FIN or the per-connection heartbeat-ack
  detector (2 missed acks after the 10 s `syncReadDeadline` —
  NOT the cluster-manager's 5×200 ms election heartbeat — and
  async handshakes completing mid-barrier are rejected at
  `installConn` by the barrier generation; a one-fabric flap
  never triggers any of it); repair-content ordering (with a repair armed, incrementals
  on any fabric BUFFER and flush after the repair's BulkEnd — the
  fab0-DELETE-then-delayed-fab1-INSTALL schedule restores
  recency; a wrong-ID bulk is wholly non-mutating — no
  resetRecvGen, no publish, no reconcile, no ACK); the
  allocation generation (same-(K,P)/different-incarnation
  `NoChange` TRANSFERS the incumbent group to the new incarnation
  without re-crediting; a deferred release whose generation
  mismatches the live allocation is discarded — no
  release-beneath-live-E2); one `SessionIdentity` type (the
  family sweep, Close fencing, `ExpiredSession`, `DeleteSynced`,
  the alias fence, and the cleanup recheck all compare the full
  pair — a `(n1,id7)` cleanup never matches `(n2,id7)`);
  DirectHold scope (every locally-admitted path — PAT,
  deterministic, address-only, persistent address-only — holds
  DirectHold; commands reference the durable registry, never a
  cloned linear token); and the two-stage cleanup counts queued
  clones consistently (r37-5's disposition condition). (d5)
  v9.9.24 mechanisms: the barrier-and-drain reset (B refuses
  inbound dial+accept during the barrier — A's dialer retries
  install-and-die (never surviving as occupied slots at
  barrier end, v9.9.29); the first
  post-barrier install cold-primes on BOTH nodes); the sender
  cutoff (no pre-cutoff incremental lands after the repair's
  BulkEnd — pause, flush, snapshot, drive, resume); the
  transactional bulk (members + generation-map staged, committed
  only at a validating BulkEnd; O2 superseding O1 mid-way
  commits nothing; freeze-buffer overflow invalidates and
  re-raises rather than committing partial state);
  incarnation-namespaced repair epochs (`(sender_incarnation,
  bulk_epoch)` — a restarted sender's epoch 1 cannot discharge
  an old obligation); the pending-release ticket (last-drop
  marks `PendingRelease(g, ticket)`; a same-(K,P) `NoChange`
  claims/cancels the ticket atomically; the drain compares
  generation AND ticket — the re-acquire-before-drain schedule
  cannot release beneath live E2); and the DirectHold→GroupHold
  conversion (a peer replacement of a demoted locally-born entry
  converts the direct hold atomically — group minted owning the
  same reservation, direct count decremented in the same
  critical section; no uncredited GroupHold). (d6)
  v9.9.31 failure boundaries (round-42 Codex L7): a retry
  installed at the barrier endpoint (the RESET_GEN/RESET_ACK
  handshake closes it; the time-barrier-only path (negotiated
  reset version 0 — v9.9.54.20, round-65 Codex H4, never
  "legacy-only") is
  covered by the durable obligation + takeover fence); a quiet
  LEGACY peer under the hard silence teardown (capability-scoped
  — never torn down; `sync_test.go:4721`'s contract preserved);
  exact per-slot publication tokens (a mutation from a revoked
  or non-authorized token is discarded at the canonical
  transaction); asymmetric capacity (handshake negotiation →
  defined degraded state, never a rollback loop); shadow
  interruption (deadline/teardown releases; no partial
  visibility) and the locally-authoritative merge at commit;
  O1/O2 terminal correlation (only the exact post-O2
  `JOURNAL_END` moves the receiver's readiness and only the
  matching `JOURNAL_ACK` clears the sender's obligation;
  crash-before-marker leaves both armed, v9.9.43); hold-cell
  conversion ordering (single
  per-credit counter, reference flavors only); and the cleanup
  lost-wakeup interleaving (arm-before-read closes it; the
  drop-after-read re-notifies). (d7)
  v9.9.33 transition boundaries (round-43 Codex L9): RESET_GEN
  loss and simultaneous resets (retransmit on the control
  connection; timeout never discharges the obligation, only
  readiness is restored by a matching repair completion);
  (d10) v9.9.54.9 boundaries (round-57 Codex L5): pinned-token
  death and successor repair (the pin follows the token, the
  obligation follows the incarnation; the next connection's
  negotiation re-arms the drive pinned to the new token);
  both packed-CAS winner orders (writer-wins → activation
  waits for the bundle, bumps, re-arms the election hold;
  activation-wins → writer drops every effect); VRRP-hold
  re-arming on activation (the generation-scoped hold
  precedes repair-vN exposure; a stale timeout re-arms,
  never silently releases while an obligation is armed);
  equal-node-ID rejection (transcript with equal node_ids →
  refused repair-era, operator-visible not-ready, fail-closed
  per heartbeat.go:811-820 / election.go:195-202);
  authenticated decision trailers (the pre-install
  allowlisted reader consumes and verifies header + payload +
  trailer and advances authConn.recvSeq — no bad-magic loop);
  and absent-vs-partial CONFIRM timeout (zero bytes consumed →
  close and retry with bounded backoff (v9.9.54.20 — no
  timer commits any class); partial → close; complete late →
  consume and ignore before declarations);
  (d11) v9.9.54.12 boundaries (round-59 Codex L6): exact
  decision-support gating (BIT 5 present/absent on the two
  records → negotiated min-version v2 vs v1 for the
  decision class (v9.9.54.17 — the gating predicate is the
  version machine, not a presence test); an intermediate
  repair-vN peer without bit 5 negotiates v1 — repair-v1
  runs, the decision phase is absent, and only a
  RECORD-LESS (v0) peer gets the buffered-first-frame path
  (v9.9.54.18), never a
  reconnect loop); baseline-frame replay (the buffered
  ClockSync dispatches in order after the legacy latch);
  later readiness-loss hold reacquisition (an overflow,
  rejection, or epoch park after a completed repair arms a
  fresh generation-scoped hold before any priority event can
  promote); completion expiry without another activation
  (the durable same-generation executor retries the
  abandoned ticket; each target API validates ticket AND
  generation); late abandoned effects racing G2 (G2's bump
  wins by monotonicity; G1's stale effects perform nothing);
  planned transfer with missing state (the override issues
  only after the pending-rejection set is empty, no repair
  obligation is outstanding, and the last full repair
  completed through JOURNAL_END at the current generation —
  or a forced-and-validated full repair runs first); and the
  one-shot per-RG transfer-generation token (a
  Secondary→Primary event without a token is an automatic
  election and fenced);
  (d12) v9.9.54.14 boundaries (round-60 Codex L6): asymmetric
  old-peer activation (new A `{repair=1, decision=1}` vs
  intermediate B `{repair=1, decision=0}` — BOTH compute the
  negotiated min-version (v1) — repair-v1 RUNS with the
  decision phase absent (v9.9.54.19, round-64 Codex L8 —
  the "use legacy" phrasing was the retracted conflation;
  v9.9.54.17 —
  the intersection is subsumed by the version machine for
  the repair bit); B never
  activates a repair version A lacks (v9.9.54.20 — min()=v1
  means BOTH run repair-v1; the fenced case is a version
  the peer lacks); epoch-park release (a
  future-epoch E1 parked against an unapplied config is
  outstanding state — the release predicate's five classes
  must ALL discharge); acquisition racing becomeMaster (the
  ownership commit revalidates the readiness generation
  under the PromotionPermit with the revalidation
  serialized per round-61 SMR F2 (v9.9.54.18) — an acquisition landing after
  the commit fails the recheck); stale transfer-token
  consumption and event loss (the token binds
  (local/peer incarnation, request ID, transfer generation,
  readiness generation) and is claimed by ONE initial CAS
  with every later stage validating the immutable claim at
  its mutation point (v9.9.54.17 — per-side-effect
  CAS-consumption retracted); a dropped-and-replayed ClusterEvent
  cannot re-present a stale token); bounded executor under a
  permanently blocked target (the coalesced nonblocking
  submission caps in-flight attempts at one per ticket and
  abandons by deadline — no goroutine accumulation, no
  blocked-mutex cancellation needed); and the literal HMAC
  vectors with BIT 5 set (0x3F — digests recomputed:
  dialer 6a56876c..., acceptor f46254ed...);
  (d13) v9.9.54.17 boundaries (round-62 Codex L7): the
  cumulative version-selection matrix (v0/v1/v2 cross
  product — v1/v2 sides advertise their immutable maximum
  unconditionally while a v0 peer is RECORD-LESS (no
  advertisement exists to test — its class commits at the
  first buffered ordinary frame), both compute min()
  after the exchange, a v1 cell runs repair-v1 with the
  decision phase absent (never buffered-legacy,
  v9.9.54.18), and a conforming decoder ignores unknown
  set capability
  bits without rejecting the record); fence-first
  queued-promotion rejection (a wakeup carrying a revoked
  ticket or stale generation is discarded under the
  PromotionPermit — no publish, no becomeMaster); the
  G2 fence re-covering an instance G1 already released;
  activation stage recovery (a pre-PONR failure compensates
  the recorded stage ledger in reverse and lands
  dual-secondary with the ManualFailover latch retained;
  a post-PONR failure completes forward or reverses via a
  new authorized transaction); ForceSecondary peer loss
  and all-RG atomicity (peerAlive re-validated at start;
  snapshot generations; repair off-lock; atomic revalidate;
  demote-all-or-mutate-none; timeout/loss/mismatch →
  error, nothing marked, ownership retained);
  promotion-permit lock ordering (PromotionPermit is the
  outermost acquisition, never taken under Manager.mu /
  vipMu / directVIPMu, never held by the false→true
  readiness advancer, taken by every true→false
  readiness-loss writer (v9.9.54.18), never held while
  joining an instance run
  loop); and disruptive-mode postconditions (readiness
  stays false, obligations retained, subsequent transfers
  fenced, durable degraded alarm until a current full
  repair completes — and the report never says
  safe-to-stop);
  (d14) v9.9.54.18 boundaries (round-63 Codex B2/B3/H5/H6/H7
  + round-63 SMR F1/F5): the ForceSecondary admission
  cutoff (admissions continue-and-journal through the
  repair; a BRIEF final fence covers only the
  seal→barrier→demote window; the drain predicate is
  durable local-journal acceptance up to the watermark;
  the terminal barrier follows the seal — v9.9.54.20,
  superseding the hard-freeze phrasing — a post-proof E2
  cannot miss the handoff); the
  never-reused RG incarnation plus global membership
  generation (a config adding RG N mid-repair aborts the
  transaction with ownership retained); the reordered
  peer commit (the final peer commit lands BEFORE the
  first VIP/netlink ownership mutation in every mode —
  the old owner's lease-expiry restore checks the commit
  record and a committed transfer never auto-restores);
  quiesced restart recovery (a restarted node always
  enters sync-hold, never resumes from volatile local
  state, revalidates lease + transfer generation with the
  peer; an incomplete ledger reconstructs as pre-PONR with
  cluster-local-only compensation — never wire reclaim);
  the readiness-loss writer taking the PromotionPermit
  (G2's not-ready cannot slip into G1's validate→publish
  window); becomeMaster's revalidation taking NO
  vrrp.Manager.mu (the UpdateInstances/vi.stop join cannot
  cycle with a committing run loop; joins happen after
  the mutex is released); the publication write deadline
  (a blocked advert write times out as a post-PONR failure
  and the permit always releases by its own deadline);
  and the DisruptiveTransfer claim (bound to the exact RG
  set, both incarnations, request/transfer/readiness
  generations, claimed once with every stage validating the
  immutable claim (v9.9.54.20 — "consumed once" was the
  retracted one-shot phrasing), validated under the permit —
  the operator force path carries the same operator-minted
  claim);
  (d15) v9.9.54.19 boundaries (round-64 Codex B1/B2/B3/H4/H5/H6/H7
  + round-64 SMR F1/F3/F4/F8): the CONFIRM timeout closes
  and retries with bounded backoff — no timer commits any
  class (v9.9.54.20, superseding the v1-extras-inactive
  latch; v0 commits only on a
  complete ordinary frame with no record, v1/v2 only on a
  complete authenticated CONFIRM); the reset lane activates iff
  reset-vN independently negotiates (a repair-v1 peer
  without reset support never waits on the reset lane);
  the continue-and-journal cutoff watermark (admissions
  continue under the journal; the drain predicate is
  durable local-journal acceptance of every accepted delta
  up to the watermark (v9.9.54.20 — the peer-ACK predicate
  was causally unsatisfiable);
  the post-cut journal seals after the watermark drains;
  the terminal barrier follows the seal; abort releases
  the non-journaled freeze); the CommitUncertain claim (a
  sent-but-unACKed commit never unilaterally aborts — it
  retains (incarnations, generations, RG set), is
  idempotently queryable, and resolves only on a
  definitive peer answer); the lease-expiry restore is
  quiesced after any restart; ONE reconciliation epoch
  with pointer-identity stop-sets and generation-tagged
  tombstones; the cancellable token-fenced publication
  bounded below masterDownInterval (netlink calls
  contexted, sendAdvert per-family outcomes, timeout =
  possibly-published with forward-only recovery); and the
  DisruptiveTransfer claim entering the full
  Authorized → Claimed → Applied / PONR / CommitUncertain
  lifecycle;
  (d16) v9.9.54.20 boundaries (round-65 Codex B1/B2/B3/H4/H5/H6/M7
  + round-65 AGY T1-T5 + round-65 SMR F1-F7): the
  zero-byte CONFIRM timeout close+retry (a baseline peer
  pausing after wrapper install cannot split the class —
  v0 needs a complete ordinary frame, v1/v2 a complete
  CONFIRM, everything else retries); the brief final
  admission fence (seal→barrier→demote only) with the
  abort consistency rule (A's table authoritative; B's
  partials idempotent and superseded; the aborted drain
  bumps the repair obligation); the crash-durable applied
  receipt (write-ahead persist before applying; a
  receipt-absent restart answers unknown-incarnation,
  never not-applied; the new-incarnation recovery
  transaction restores B or completes A, exactly one);
  every reset branch testing the negotiated reset version
  (a repair-v1/reset-v0 pair takes the time barrier); NO
  path acquiring the reconciliation epoch while holding
  the PromotionPermit (config apply under the permit
  queues the reconciliation; the promotion recheck
  includes the detach/tombstone generation); the peerless
  operator PONR for DisruptiveTransfer (locally durable
  operator intent retires the missing peer incarnation,
  fences it pending authoritative reseed; the claim never
  waits on a dead peer); the class-commit frames named
  normatively (CAPABILITY_CONFIRM IS the record on
  v1-proof; CAPABILITY_DECISION + ACK carry the decision
  phase; no v0 declaration frame exists); and the §9
  d12/d14/d15 amendments themselves;
  (d17) v9.9.54.21 boundaries (round-66 Codex B1/B2/B3/B4/H5/H6/H7/L8
  + round-66 SMR F1-F8): the two v0 evidence paths (an
  authenticated all-zero repair-bit record commits at the
  CONFIRM exchange; a recordless complete ordinary frame
  commits at the frame — exhaustive and exclusive); the
  RW-fence cutoff (read permit held from before NAT
  allocation through publication and durable journal
  receipt; the write side drains held permits; new
  admissions during the fence get drop-without-RST; the
  fence has its own millisecond deadline and releases on
  any failure — the 30/60s transaction timeout runs
  outside it); the Prepared → Applied two-state receipt
  (Applied only after finalization AND lease disposition;
  a Prepared-present restart replays before any election
  or status answer); the recovery complete-leg gated on
  B's completeness (forced-repair → JOURNAL_END first);
  the retirement riding the heartbeat (a retired or
  unvalidated incarnation is liveness-only for election
  until quiescence + reseed + fence clearance; a
  still-live partitioned owner requires external fencing);
  synchronous pure validation plus an immutable
  config-generation snapshot awaited after permit release
  (the drainer re-reads the latest desired set); the
  declaration input removed (deterministic min() over the
  two records; the owner publishes, the peer validates
  against its own computation — mismatch closes; the
  class commits ONLY at the ACK'd installation); literal
  frame IDs 32-39 with layouts and ACK correlation; a
  decision frame on a sub-v2 connection is a protocol
  violation (class-scoped allowlist); and the retry
  ladder (inner bounded backoff → outer 1s connect loop,
  never fatal; a complete late CONFIRM on a fresh stream
  is honored);
  the pending-rejection GC wakeup
  re-opens admission with readiness degraded); same-fabric
  token supersession (C2 installs → T1 revoked before the slot
  swap; a paused C1 handler never publishes); merged-capacity
  preflight (K + L > C → defined degraded state, no
  over-capacity commit) and the NAT tuple conflict (local
  authority wins; the conflicting peer cohort stays
  unpublished; the repair never ACKs E1 protected);
  terminal-marker/ACK retry (the completed-repair receipt
  re-ACKs a duplicate JOURNAL-END without re-mutating);
  identity adoption (an import carries the wire identity
  byte-for-byte — A's conditional delete for IA matches on B);
  the same-E1-resend vs stage-2 race (the resend's publication
  atomically cancels the stale cleanup); the rebuild stop
  contract (join deadline; migration WRITE never held across
  quiesce/join; failure leaves XSK disabled + readiness
  degraded); and the Arc-vs-cell single-counter assertion (no
  release path outside the cell's zero transition). (d8)
  v9.9.37-39 boundaries (round-46 Codex L4): cold-prime waits
  for `JOURNAL_ACK` (a `BulkEnd` write never releases the
  latch); receipt expiry plus a late old marker (discarded);
  the exact-T2 query after a lost replace ACK (stale aborted
  attempts never match); replacement concurrent with a family
  transaction (the permit drains/CAS-invalidates before
  retarget; rollback is token-conditional per preimage);
  reset-lane frame rejection and current-incarnation fencing
  (non-RESET types dropped; stale incarnation discarded;
  unkeyed peers get no lane); (d9) v9.9.45 protocol boundaries
  (round-49 Codex L3): v2↔v1 interoperability (a v2 peer uses
  the v1 nonce-only proof over the legacy prefix bytes —
  connection establishes, ALL capabilities inactive until the
  matching authenticated `CAPABILITY_CONFIRM` on the same
  connection, v9.9.51); the v2 proof's literal KEYED
  HEXADECIMAL vectors for BOTH roles (v9.9.51, round-52
  Codex B1: `term(x) = u16-LE(len) || exact raw payload
  bytes`, frame header excluded; dialer vector: tag
  `xpf-cluster-sync/v2/hello-transcript`, prover_role 0x01;
  acceptor vector: prover_role 0x02; the shared record
  segment byte-identical across both, the full inputs
  differing only by prover_role — the vectors are normative
  test constants, not examples);
  canonical transcript vectors (byte-exact: literal domain
  tag, record-order rule, u16-LE lengths, little-endian
  integers, own-transcript proof direction); the legacy HELLO
  prefix preserved byte-for-byte (an old peer authenticates
  the same bytes — no reconnect loop); capability masking on a
  v1-proof connection (v9.9.49, round-51 Codex M3 — EVERY
  capability is DISABLED on a v1-proof connection until
  MATCHING authenticated `CAPABILITY_CONFIRM`s have been
  received ON THAT SAME CONNECTION: no `reset-vN`, no
  `repair-vN`, no identity enforcement, nothing negotiated —
  a capability asserted without a matching confirm is ignored,
  so neither side can enter repair-era completion while the
  other follows legacy `BulkEnd` processing); the mixed-version discharge matrix (repair-vN:
  JOURNAL_END/JOURNAL_ACK; legacy→new: BulkEnd readiness
  retained; new→legacy INSTALL-only: no obligation armed,
  cold-prime clears on lossless emission); pre-HELLO
  incarnation fencing (frames before the transcript verified
  are not session frames); and the stale transition-CAS (a
  superseded pending's completion fails the CAS);
  the pending-rejection GC wakeup
  (persistent P freed at GC notifies; a third-flow reclaim
  re-arms); old-family DNAT cleanup (the immutable record
  covers the reverse/DNAT aliases); and the teardown latch
  clearing after a late worker exit (rebind then permitted). (e) the typed undo receipt — `NoChange` replay rolls
  back nothing (pre-existing ownership untouched), `Inserted`/
  `Retained` undo exactly their mutation, and `Replaced(old_state)`
  with a FAILED new claim reinstates the displaced record's tuple +
  lease + token in the same critical section (E1's published
  decision never points at unreserved P); (f) token indirection —
  a pre-cut token released AFTER the migration cut lands in B
  (B's refcount decrements; retired A owns nothing), and a stale
  raw A-handle's NEW allocation transient-fails and re-resolves;
  (g) ordering — config push serialized before BulkStart for the
  same epoch.
- **Overflow repair + single reservation point + slot
  linearization (v9.9.19, round-34):** (a) lossy-bulk suppression —
  a bulk that discarded any parked member neither reconciles at
  BulkEnd nor ACKs; the once-per-latched-epoch disconnect drops the
  parked buffer and the reconnect's full resync is the repair
  (installs AND deletes reconstructed); (b) takeover-after-drain —
  readiness requires BOTH published epoch >= peer high-water (the
  high-water advanced by an observed INSTALL stamp, no Config
  frame) AND empty parked queues with no outstanding repair (a
  crash in the apply-success→drain interval does not promote);
  (c) single reservation point — two workers importing the same
  flow concurrently never race the allocator: the coordinator's
  pre-publication reserve-with-receipt is the only transaction;
  a coordinator-side failure rejects before any worker or the
  canonical entry sees the install (W1 can never publish against
  W0's later-rolled-back reservation); (d) slot linearization —
  the pause-between-slot-load-and-gate-acquire race: the release
  revalidates under the READ permit and retries into B (lands on
  exactly one side of the cut; no B ghost, no reissue under a live
  session); (e) pool reorder/rename — slots keyed by
  `SourceNatPoolAllocatorKey`: a renamed pool's retired allocator
  persists until its last pre-cut token drops, a reordered
  rule never retargets tokens into a different pool's allocator,
  AND the compatible cross-key migration is asserted end-to-end
  (v9.9.20, round-35 Codex M3: `SourceNatPoolAllocatorKey`
  includes `pool_name`, `source.rs:327`, and reuse is exact-key
  only, `:726` — persistence of A alone does not stop an
  independently keyed B from issuing E1's tuple; the test asserts
  the drained-snapshot migration into B, the old slot's retarget,
  and release-accounting continuity — a pre-cut token's release
  decrements B's migrated holder, never a ghost);
  (f) receipt-vs-GC — a `Replaced(old_state)` reinstatement runs
  entirely inside the allocator critical section, so expiry GC
  cannot interleave; (g) early replica reap — two worker replicas
  of an imported flow hold group-hold clones; the first reap drops
  only its clone (the reservation survives until the canonical and
  second replica also reap; the port is never freed under a live
  replica); (h) lock-order — the allocator critical section never
  nests with the canonical publish (assert by construction: no
  code path holds both); (i) the COMPOSITION scenario (v9.9.20,
  round-35 SMR F3): config change → apply lag on the standby →
  epoch park → RG failover mid-park → in-place-refresh migration
  on the survivor → drain, full resync with the obligation
  clearing on ACK, slot retarget, and every pre-cut token
  releasing into B.
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
  (e2) the wire identity matrix — the ONLY satisfiable form
  (v9.9.15, round-30 Codex H4: the previously retained clauses —
  "new-sender→old-receiver (tail ignored)" and "mixed-version pairs
  fall back to generation deletes" — made the matrix internally
  unsatisfiable: followed literally, A's E1 Close reaches legacy B,
  which decodes key plus generation (`sync_conn_read.go:150`),
  accepts the equal/fresh generation (`sync_conn_gen.go:263`), and
  key-deletes the current same-key E2 plus companions at
  `sync_conn_gen.go:493-506`. There is NO gen-based fallback for
  sender-initiated deletes toward a legacy receiver, full stop):
  new-sender→new-receiver — the tail is applied: identity-dependent
  deletes carry the selected `(origin_process_nonce,
  flow_incarnation_id)` and the receiver applies them only when its
  stored incarnation matches; old-sender→new-receiver — the
  tail-less install stores NO identity, and the legacy sender's
  gen-based deletes apply ONLY to entries that are NOT locally
  authoritative on the receiver (a standby/replica copy — the
  owner's gen-based delete correctly kills it), while locally
  authoritative entries (locally-born or `SharedPromote`) are
  IMMUNE: the old sender's fresh generation always advances past
  the receiver's tracked generation for that key
  (`sync_conn_write.go:69`), while E2 re-seeded on the NEW node does
  NOT advance the OLD sender's generation — so an unconditional
  gen-based fallback would delete the new node's authoritative E2 in
  the dual-active mixed-version window (the v9.9.8 quadruple
  coincidence: mixed-version pair + failover + policy invalidation
  + new flow in the same ~100 ms masterDownInterval window), and the
  old node's own invalidation pass deletes its own E1 copy with its
  own fence — the hazard is closed, not just bounded;
  new-sender→old-receiver — the INSTALL tail is ignored by old
  decoders (harmless extra bytes), and identity-dependent DELETEs
  (Close, invalidation, conditional) are SUPPRESSED ENTIRELY toward
  the unnegotiated peer: the new sender emits them only to
  negotiated peers (capability bit in the handshake), and the legacy
  receiver converges by its OWN local invalidation pass and aging —
  master's pre-existing behavior for every entry today; dual-active
  propagation (both nodes believe they own the RG) — the delete
  delta carries the selected identity and the receiver applies it
  only when its stored incarnation matches, so node A's propagated
  delete of E1 never kills node B's live E2 aliasing the same key;
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
  same-incarnation-value/different-process-nonce (v9.9.29 —
  the RT_FLOW `session_id` is distinct from the fence's
  incarnation component, `:2728-2740`; the case is a restarted
  process reusing the incarnation value) — the fence compares the
  FULL `(origin_process_nonce, flow_incarnation_id)` pair, so a
  post-restart E2 with the same per-worker counter value is not
  deleted by a pre-restart E1's delta; the peer delete delta carries
  the SELECTED identity (rolling-gated additive tail) and the
  receiver applies it only when its stored incarnation matches;
  toward an UNNEGOTIATED (legacy) peer the delete is SUPPRESSED
  entirely — never a gen-based fallback (per (g)/(e2) — and a legacy
  SENDER's gen-based deletes apply only to non-locally-authoritative
  entries on the new receiver, per (i)).
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
  migration conflicts); updates are incarnation-conditional on the full
  `SessionIdentity` pair (delayed E1 cannot attach to E2);
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
  full `SessionIdentity` still matches the canonical record's (v9.4,
  round-14 Codex H3b/c/d + round-15 Codex H4; v9.9.27 — the pair,
  not the scalar). (d) a validated
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
  K × opening_timeout); compare-delete per member on the full
  `SessionIdentity` pair under the documented lock order incl. the
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
2. **The pre-existing NAT release bug (round-12 Codex 1, #6522 —
   CLOSED by this plan):**
   every expired forward unconditionally calls release
   (`loop_body/mod.rs:1481`) and the allocation has no replica
   refcount (`nat/allocator.rs:1318, :1664`), so an idle sibling
   replica's reap can free a live flow's port ON MASTER TODAY.
   DISPOSITION DECIDED (v9.9.22, round-37 Codex L7 — this question
   was stale): the trace was verified in round 12 and the fix —
   the holder-lifetime machinery, now the typed
   `DirectHold`/`GroupHold` token with the group-hold clone
   distribution for imported flows — SHIPS AS PART B of this plan
   (§5.2's escrow/token paragraphs); #6522 tracks the master bug
   for the commit reference and is CLOSED by this work, not filed
   separately.
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
   (#6522 — SHIPPED as Part B's typed holder-lifetime machinery,
   closed by this plan, not deferred). Complete and shippable?
6. **Observability:** counter + rate-limited structured event.
   Sufficient?
