# #6461 — blind off-path TCP RST/FIN demotes a live session with no sequence validation

**Status: DRAFT v10.11.0 — THE TERMINAL CUT, round-94 folds (THE
RWoLB RETRACTION: the v10.4.1 same-dispatch re-entry is retracted to
master-verbatim — master's post-purge packet continues the HIT branch
on the retained lookup (`session_glue/mod.rs:1194-1196`), and the
install/Open/seed happen on the later clean-miss packet with a fresh
derivation; the close-aware purge gate with unconditional retention is
the plan's ONLY departure on this path; the reservation-success
condition retracted (a cached bit is not a live ownership fence); the
overdue-K adopt preserves S2 in place without a wheel re-queue). Ship
candidate = the Part-A dataplane demote gate plus the wire-free local HA
rules. The RG-incarnation/retirement/fence-ledger protocol that rounds
13–82 grew is KILLED (not deferred): its two customers are re-scoped —
the pre-existing NAT-release bug #6522 to its own issue, and the Phase-2
HA-wire anchor to its own research track (phase2-brief.md, split at v9).
Part A changes no HA wire format, no schema, no public API (one additive
Go worker-status decode field for the counter). Round-83: AGY YES; Codex
NO (3B/1M/2L — folded v10.1.x); SMR NO (1L/5nit — folded v10.0.2).
Round-84: AGY YES; Codex NO (4B/1H/1M — folded v10.2.0 incl. the
pending-neighbor RETREAT, accepted round 85); SMR NO (2nit — folded
v10.1.1). Round-85: AGY YES; Codex NO (4B — folded v10.3.0); SMR NO
(2nit — folded in-revision). Round-86: AGY YES; Codex NO (5B/1H/1L —
THE SECOND RETREAT: seed-lifecycle completion retracted v10.4.0;
accepted round 87); SMR NO (2nit — folded in-revision). Round-87: AGY
YES; Codex NO (2B/1L + editorials — the purged class now re-enters the
cold/miss pipeline from the packet, sole-decision end-to-end; folded
v10.4.1). Round-88: AGY YES (6th consecutive); Codex NO (1B/1L +
editorials — the probation lookup's pre-filter refresh would pin
zombies; the in-borrow refresh/recompute/wheel now skips probation
entries and the clear+refresh rides the matched entry's commit hook;
folded v10.5.0). Round-89: SMR YES (the arc's first). v10.5.1:
master-drift fold, doc-only — origin/master advanced from the citation
base `023f17a606d8` to `fff7a4ab5` (+19 commits); #6478 REMOVED the
cluster-peer return fast path (site 6 and the #4453 guard are gone —
the site-6 residual is closed by deletion, not by this plan); #6432
wrapped the MissingNeighbor arm in the StageOutcome ownership enum;
#6433 extracted the flow-cache seed path; #6458/#6474 shifted line
numbers. Every inline `file:line` citation below cites the worktree
branch base `023f17a606d8` (where each was re-verified this round); the
master-side deltas are tabulated in §3.1 for `/engineer`. No design
rule changed.** Round-89: SMR YES (the arc's first); Codex NO (3B/2L —
B1: a SYN-bearing close under `ResolvedWithoutLocalBacking`/
`ReplacedSyncedLocal` provenance passes #4400 and would seed closing on
a REAL victim tuple + emit Open; B2: reactive re-materialization
bypasses the probation fold pre-admission; B3: the probation deadline
was not fenced from expire.rs SelfHeal/Hold/companion retention or
`refresh_for_ha_transition`; L: §3.1 table corrections + two editorial
stragglers — all folded v10.6.0); AGY SOUND (7th consecutive, covering
the v10.6.0 folds). Round-90: SMR YES (fold verification); Codex NO
(2B/2H/1L — the v10.6.0 fold reused the borrowed-replica probation
model for the OWNED RWoLB P2: a no-release/no-delete probation reap
would leak P2 + aliases, and clearing a no-Open probation entry would
emit a generation-zero Close with unconditional peer-delete authority;
the key+NAT materialize probe was decision-incomplete; companion
propagation was an unlisted probation refresh path; §3.1 row nits —
all folded v10.7.0: closing packets under peer-synced provenance now
SKIP the install/publication entirely and roll back the fresh
allocation (the site-2b precedent), so no owned resource is ever held
by a suppressed entry and no no-Open probation entry ever exists to
clear; the materialize guard atomically adopts the shared S2 while
preserving only the probation deadline/flag; companion propagation
skips probation targets). Round-91: AGY SOUND (8th consecutive,
covering the v10.7.0 folds); Codex NO (2B/1H/2L — the v10.7.0
rollback-then-forward freed P2 while a buffered packet could still
rewrite with it (the allocator's documented reply-misdelivery
collision), and the destructive purge made provenance one-shot (close
#2 would FreshPrimary-install with Open and overwrite the peer's
family); the propagation fence protected only targets, not a matched
probation row; adopt-S2 could extend a shorter-timeout S2; one §9 test
asserted an impossible counter invariant — all folded v10.8.0: the
purge gate is now close-aware so a closing packet never purges and
takes the shared-backed `ExistingResolved` outcome (nothing derived,
allocated, installed, published, or emitted; the packet buffers with
the victim's own P1 and transmits on resolution), the accepted-mark
rule skips a probation matched entry, adopt-S2 preserves the min()
absolute deadline). Round-92: AGY SOUND (9th consecutive, covering the
v10.8.0 folds incl. the spray bounds and the ordering interleaves);
Codex NO (1B/1H/2L — B: the close-aware purge is not an absorbing
fence because a spoofed NON-close SYN still takes master's
purge+re-entry+Open path and overwrites the peer's family; adjudicated
PRE-EXISTING and out of the demote gate's scope — the driving packet
carries no closing flags and no sequence validation applies to a SYN;
re-scoped to #6599; H: the import-window reservation race, likewise
pre-existing and packet-class-agnostic, re-scoped to #6600; L: the
adopt-S2 deadline encoding now specified (last_seen_ns = now,
expires_after_ns = D − now, wheel sum re-derives D) and the §9
oracles narrowed to the purge-target state with conditional
transmission and K-wins/S2-wins fixtures). Round-93: AGY SOUND (10th
consecutive — verified both re-scope traces step-by-step against
master, proved the adopt-S2 wheel re-derivation algebraically, and
confirmed the five-location consistency); Codex NO (2B/1H/2M/1L, fresh
thread — B1: master's post-purge packet stays in the HIT branch on the
retained lookup (`session_glue/mod.rs:1194-1196`) and installs only on
a later clean miss, so v10.4.1's same-dispatch re-entry collapsed the
pre-existing #6599 class from two packets to one — the re-entry is now
INSTALL-FREE (fresh derivation serves the packet's forward/buffer
only; install/Open/seed/cache defer to the next packet's clean-miss
dispatch); B2: an overdue K (D ≤ now) made the encoding degenerate
into a current-tick re-queue that a one-packet-per-tick spray could
pin ahead of the phase-shifted GC — the adopt is now skipped wholesale
for overdue K; H: close-aware retention could extend a
reservation-FAILED (conflicted-P1) row's forwarding across its whole
lifetime where master self-cleans on any packet — retention now
requires a succeeded reservation (the upsert records the outcome
locally; #6600's propagation remains its own fix); M: the §9
bare-close-RWoLB oracle relabeled defense-in-depth (unreachable once
closes never purge) and the producer invariant scoped to the prompt
marked producer (the cross-worker SharedPromote second emitter is
§5.6's documented caveat); L: #4400 citation fixes +
the fabric-seed provenance row scoped branch-base-only). AGY's
round-93 review (fresh eyes on the fold) returned UNSOUND with exactly
two editorial findings — the §5.2 (iv) and §9 RWoLB test bullets still
described the same-dispatch install as live; both re-scoped to the
deferred install in v10.10.1.

The 82-round arc in one paragraph: the packet-level plausibility gate has
been stable since v6 — refuse-demote on no trusted baseline, per-field
proofs + the own-ack leg, immutable OPENING intervals, trusted continuity
slides, closing-never-promote, commit-point observation, constructor
gating, never-drop delivery — and Codex's round-12 verdict confirmed it
had "substantially converged". Rounds 6–12 unfolded the Phase-2 HA-wire
anchor (every transport/freshness/ordering answer exposed the next layer;
split to phase2-brief.md at v9). Rounds 13–82 unfolded the Part-B
lifecycle machinery the same way: the #6522 holder-lifetime fix grew
typed hold tokens → escrow → import receipts → incarnations → fence
ledgers → predecessor vectors → mint tokens → transfer CAS → cohort
roots → floor sync → CONFIG_APPLIED_ACK, and every round's fold exposed
level N+1 (round-81 Codex: 6 BLOCKERs + 2 HIGHs; round-81 AGY: 2 UNSOUND
+ 3 traces — ALL in that machinery, none in the gate). Seventy rounds is
the convergence data: that machinery is a genuinely hard distributed
protocol that does not converge in plan-doc form, and its customers are
both out of this issue's blast radius. v10 therefore cuts the plan to
what closes the issue: the gate, plus the small local rules that keep HA
emission correct behind it. The issue's HA teeth are closed by the gate
alone, stated precisely: a blind close can mark ONLY inside the
acceptance window (~1/2^12–1/2^14 per blind packet) and every such mark
was validated against observed flow state; a REFUSED (out-of-window or
no-baseline) close can never mark, never reaps early, never emits a Close
delta — the 1-packet-anytime cluster kill is dead, and what remains is
the documented sustained-spray capability at window probability, whose
every successful mark is one the endpoints' own RFC 5961 handling also
had a chance to reject.

v1 → v9 history: preserved in git on this branch (the v9.9.54.36 plan and
all 82 rounds of review docs sit alongside this file). v9 → v10: the
terminal cut — §5 shrinks from 7,310 lines to the gate mechanics; the
machinery's disposition is §10.6; #6522 is honestly re-scoped (§10.6.1);
Part B is a small set of local rules (§5.5–§5.6, §5.8): closing packets
never promote (either promote), constructor gating with a bounded
probation and a local-only probation reap, normative mark-creation with
master's emission gate UNCHANGED, the MissingNeighbor typed-outcome
gate, and the 2b scope/identity discipline (the seed-lifecycle
completion was retreated to a §10.6.2 follow-up at v10.4.0).

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
  sequence state at all. (All inline `file:line` citations in this plan
  reference the worktree branch base `023f17a606d8`; re-verified there at
  v10.5.1. origin/master has since advanced to `fff7a4ab5` — the deltas,
  including one site removal, are tabulated in §3.1.)
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
the wheel expiry emits a Close `SessionDelta` (`session/expire.rs:342-350`
gate: `!is_reverse && !is_peer_synced && !is_transient_local_seed`) which
the Go eventstream turns into an HA session-sync delete that also kills the
standby copy. The next real packet is a session miss and must re-seed; per
the issue verifier, a SNAT'd flow's re-seed can allocate a *new* pool port,
changing the translated source mid-connection and killing the endpoint TCP
state.

### What Junos actually does (researched; sources below)

- **Default RST handling**: on a tuple-matching RST, Junos sets the session
  to time out **2 seconds** later — xpf's `TCP_RST_TIMEOUT_NS = 2s` (#3046)
  is exact Junos-default parity. `set security flow tcp-session
  rst-invalidate-session` (off by default) makes teardown *immediate*;
  `fin-invalidate-session` is the FIN analogue. `rst-invalidate-session`
  is already in the xpf schema and compiler
  (`pkg/config/schema_security.go:796-800`,
  `compiler_security_flow.go:515-532`).
- **Default general sequence check**: Junos performs window-based TCP
  sequence checking by default and drops out-of-window data packets;
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

So the honest class is robustness-DoS, not a straight parity failure — and
the design question the issue poses ("what does Junos actually do") has a
researched answer: Junos's default tears down on any tuple-matching RST
(xpf parity); Junos's opt-in mitigation is drop + challenge-ACK (Option B,
deferred); the RFC 5961 §3 endpoint shape is exact-`RCV.NXT` abort /
in-window challenge / out-of-window silent drop. A middlebox cannot know
either endpoint's exact `RCV.NXT`; the feasible subset — and this plan's
shape — is the outer rule: **refuse to *act on* a closing segment whose
sequence placement is implausible given observed flow state, while always
delivering the segment.**

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
  output-filter/CoS drop evaluation). Resolve-time updates let TTL=1 or
  filter-dropped bounded packets walk a trusted anchor and convert the
  endpoint's next legit close into a refusal (griefing regression); that
  class is closed. The DEMOTE decision still happens at lookup
  (pre-filter), exactly as master's marking always has — an in-window
  close with TTL expiring at the firewall demotes without delivery on
  master too; no regression there. RFC 5961 endpoint handling is not part
  of the cost model: sprayed closes may never reach an endpoint.
- Anchor-walking (feeding contiguous fake in-window data to slide the
  anchor, then RST) requires landing a first in-window sample (the same
  ~1/2^13–1/2^14 guess) and buys the attacker nothing beyond it: the
  acceptance window follows the anchor, so a single kill needs a single
  in-window guess regardless. `seg_len > 0` is required for `seq_hi`
  slides, so zero-length probes cannot walk the anchor at one packet
  per slack.
- **Imported-entry absorbing state (stated without varnish):** an
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
  ITS OWN RESEARCH TRACK (§10.5). The post-failover `SharedPromote`
  cluster-kill trace is dead regardless (a refused close never marks,
  and closing packets never promote — §5.5 rule 5).
- What this costs a legitimate teardown when the gate misjudges: the
  packet is always delivered (endpoints tear down normally), the entry
  idles out on its ordinary timeout instead of the 2 s/30 s fast reap —
  a table-pressure cost, never a broken connection. Aggregate version
  (round-2 Codex): a both-direction path-switch can stall an anchor
  permanently (§5.2); many flows stalling after one path event linger to
  their established timeouts — bounded, self-healing as flows churn.
- Cost (stated whole, v10): **40 B** of anchor/proof state on
  `SessionEntry` (no wire leases, no incarnation ids, no scheduling
  state — those were machinery and are gone) on the uniform slab
  (UDP/ICMP entries carry it unused; ≈ 5.2 MiB per worker at the
  131,072 cap, ≈ 31 MiB at 6 workers). No Go sidecar. Per-packet: one
  TCP-header view compute (seq/ack/wnd/flags/seg_len) plus ≤2
  plausibility-gated `u32` stores per committed TCP data packet, and a
  second table probe only on closing-flag segments (which already take
  the full slow path).

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
  is inherited by the companion for free; the marking itself moves into
  that post-borrow phase (§5.5).
- **#4400** — `strict_syn_check_drops_new_flow`: bare RST/FIN dropped at
  the ForwardCandidate/MissingNeighbor new-flow install sites
  (`poll_descriptor/mod.rs:1642-1650`). Always-on, no knob — the precedent
  for always-on hardening on this boundary.
- **#4453** — same predicate excludes bare RST/FIN from the fabric return
  fast path (`forwarding/fabric.rs:426-431`). **REMOVED on master by
  #6478** together with the fast path itself (§3.1).
- **#4539/#4487/#2151** — host-inbound LocalDelivery session caching only
  off the handshake; declined first packets still delivered locally.
- **#2344** — `parse_session_flow_from_bytes` refuses non-first IP
  fragments (`frame/inspect.rs:1455-1470`): fragments are **flowless** — no
  SessionFlow, no session lookup, no cache insert, no `account_packet`.
  Fragments therefore cannot drive a demote, cannot seed an anchor, and
  cannot pollute one.
- **#2501** — `account_packet` runs for **every** forwarded packet on a
  live session, on BOTH the flow-cache hit path (`flow_cache_hit.rs:312-317`)
  and the slow-path forward build (`poll_descriptor/mod.rs:3494-3503`),
  folding both directions' accounting onto the canonical forward entry.
  This is the existing chokepoint that makes a single-authoritative anchor
  possible (round-1 Codex B4).
- **Flow cache** (`flow_cache.rs:352-375`): only UDP and TCP pure-ACK are
  cache-eligible; every FIN/RST bypasses the cache and takes the full slow
  path. NAT64 and LocalDelivery (`is_cacheable()` =
  ForwardCandidate|FabricRedirect only, `types/forwarding.rs:948-952`) are
  non-cacheable → every packet of those flows transits the slow path and
  `account_packet`.
- **Fabric return fast path** (`cluster_peer_return_fast_path`,
  `poll_descriptor/mod.rs:928`, `forwarding/fabric.rs:389-492`): established
  non-closing return traffic arriving on fabric ingress is forwarded with
  at most a first-packet reverse-seed install — it does NOT run
  `account_packet` or a session lookup per packet. The affected entries are
  non-authoritative (reverse seeds / synced copies on the non-owner node);
  see §7's coverage residuals for why a later close there kills nothing
  authoritative. **REMOVED on master by #6478** (merged `7b7119db1`): the
  fast path, its reverse-seed install, and its #4453 guard are gone —
  fabric-ingress return traffic now takes the ordinary session pipeline.
  The site-6 residual below is therefore closed by deletion on current
  master; the branch-base analysis is retained for the record (§3.1).
- **#2008 M9 / #2078** — `no-sequence-check` parsed, unenforced.
  `rst-invalidate-session` parsed (schema + compiler, see §1).
  `rst-sequence-check` and `fin-invalidate-session` are NOT in the xpf
  schema.

### Packet-driven closing/reset sites (complete, round-2-verified inventory)

This is the issue's "find every legitimate teardown caller first" — the
exhaustive inventory, re-verified against this branch's master base:

| # | Site | Trigger | v10 treatment |
|---|---|---|---|
| 1 | `session/lookup.rs:105-128` HIT path (real endpoint FIN/RST) | wire packet flags | gate via pre-packet anchor validation, marking moved to post-borrow phase (§5.5); closing packets never promote (§5.5) |
| 2 | `session/mod.rs:1396-1432` `update_session` via `promote_synced_with_origin` (HA shared-promote, `session_glue/promote.rs:86-107`) | wire packet flags on the promoting packet | closing packets never reach this path (rule 5 — the ownership promote is skipped wholesale); a non-closing promote threads the seg view for anchor purposes |
| 2b | **reverse-NAT companion synthesizer** — `session_glue/mod.rs:1262-1284` → `shared_ops.rs:857-865` → `install_with_protocol_with_origin` (seeds at `install.rs:179-180`) | wire packet flags on a reverse-tuple miss with a live forward match; runs at resolve time, BEFORE the #4400 guard | gate the seed with the validator against the in-hand forward entry's anchor; refused close → **skip the install entirely** (§5.6); a SHARED `ForwardSessionMatch` carries no anchor (`entry.rs:209`) → no-baseline → refuse → skip-install |
| 2c | **reactive shared materialize** — `materialize_shared_session_hit` (`session_glue/mod.rs:1092-1118`) threads the current packet's `tcp_flags` into `upsert_synced_with_origin` (seeds at `install.rs:399-400`) | wire packet flags on a shared-map hit | gate the flag seed with the validator; an imported entry has no anchor → no-baseline → refuse → install the copy **alive** (`closing=false, reset=false`) at the bounded probation timeout (§5.6); re-materialization against an existing probation entry atomically ADOPTS the shared S2 decision/metadata while preserving only the probation deadline/flag — no decision split-brain, no clock restart (§5.6, v10.7.0) |
| 3 | `install.rs:179-180` primary miss installs | creating packet flags | unreachable for bare closes on TRANSIT dispositions (#4400) and LocalDelivery caches TCP only with SYN (`local_delivery.rs:20`). The actual residual: a SYN|RST/SYN|FIN new-flow packet passes the #4400 guard (it has SYN, `session_admission.rs:82-87`) and seeds closing/reset from raw flags — a self-anchoring invented-tuple entry (attacker kills only a flow it created — no victim impact, master parity); malformed SYN+close combos are screen-owned where screened. **Provenance bound (v10.8.0, rounds 89-91 Codex):** the invented-tuple harmlessness holds ONLY when the tuple is genuinely new in this dispatch; when the tuple carries peer-synced provenance (`ResolvedWithoutLocalBacking` re-entry or `ReplacedSyncedLocal` displacement) it is a REAL victim's — a closing-flagged packet (SYN-bearing included) never triggers the transient purge (it takes the shared-backed `ExistingResolved` outcome: buffer with the resolver's stored decision, no derivation/allocation/install/publication/emission) and never displaces the synced victim (`ReplacedSyncedLocal`: deliver locally, no install) — §5.6 site-3 supplement |
| 4 | HA wire re-import — eventstream `UpsertSynced` → `upsert_synced_with_origin` (no packet exists) | peer delta | validation-free by design (the peer validated before reaping and emitting the Close); distinct from site 2c, which HAS a packet |
| 5 | tunnel `UpsertLocal` (`tunnel.rs:563-615` → `session_glue/mod.rs:786-800`) | locally generated packets (firewall-originated tunnel TX) | trusted-local class, documented; not wire-attacker-controllable. Inbound tunnel closes land on site 1 with whatever anchor the inbound stream built — none if the flow is outbound-only → refuse-demote; local blast radius |
| 6 | fabric-return reverse seed (`cluster_peer_return_fast_path` install) — **REMOVED on master by #6478; the row below is the branch-base analysis, retained for the record** | fabric-ingress packet flags | bare closes already excluded (#4453); SYN|ACK|RST/FIN combos pass the guards (`fabric.rs:404`) and seed raw flags — an unvalidated constructor, harmless-by-class (the seed is `is_reverse` → silent at reap; the non-owner's forward import validates closes at site 1 with no anchor in Phase 1 → refuse → no mark). The seed bypasses the commit hooks so it carries no anchor — a later close on it is REFUSED (missing-forward/no-baseline, §5.1); documented. On current master the site no longer exists: #6478 deleted the fast path and its seed install, so the residual is closed by deletion |
| 7 | CLI/control deletes, GC/reaper, screens/SYN-cookie | — | consumers / unaffected |
| 8 | **forward-wire immutable match** — `find_forward_wire_match_with_origin` (`lookup.rs:258-293` via `shared_ops.rs:614-628`): NAT64 forward direction, hairpin, non-bijective NAT | wire packet on the forward-wire tuple | The match itself never marks (cloned decision/metadata — no `&mut`, today or after). But it is not demote-free: a promotable-origin forward-wire hit reaches `maybe_promote_synced_session` → `update_session`, which marks closing/reset from the packet's flags on master — gated by §5.5's rule 5 like every other promote (closing packets never promote → never reach `update_session`). The anchor for these flows advances from the reverse (mutable alias) direction only; pre-existing forward-direction accounting/refresh asymmetry (NAT64) is out of scope — filed as a follow-up candidate |
| 9 | **MissingNeighbor disposition arm** — `poll_descriptor/mod.rs:4034-4798`: a packet (HIT or MISS) whose disposition is MissingNeighbor reaches the common arm, which runs seed-only NAT derivation/allocation (:4680, :4745), metadata/counters, and installs `MissingNeighborSeed(..., meta.tcp_flags)` at :4787 — `install_with_protocol_with_origin` `remove_entry`s any existing key (`install.rs:140`) and seeds `closing`/`reset`/timeout from the raw flags (`install.rs:179-180`) | any closing-flagged packet with a cold next hop; the #4400 guard at :1642-1650 covers only the ForwardCandidate/MissingNeighbor MISS path | **gated by typed provenance (v10.4.1, rounds 83-87 Codex):** the arm branches on the resolve outcome AT THE ARM HEAD — before ANY seed-only work (NAT/NPT derivation or allocation, metadata, counters, install, rollback, publication): `ExistingResolved` (a live local or shared resolve-time entry backs the resolve — incl. a validator-REFUSED close, a 2b REFUSE, or an accepted marked close) buffers the packet with the RESOLVER's stored decision and does NOTHING else (allocator state, metadata, counters, install, publication all untouched — an unowned `live_by_flow` allocation can never leak, `nat/source.rs:1548`); `ResolvedWithoutLocalBacking` is RETRACTED as a distinct outcome (v10.11.0, round-94 Codex 1-3): master keeps the purged packet in the HIT branch on the retained lookup (`session_glue/mod.rs:1194-1196`), the plan dispatches it byte-identically (retained decision; no derivation/allocation/install/publication/seed/cache this dispatch — the install happens on a later packet's genuine clean miss, derived fresh there), and the packet reaches this arm, if at all, as `ExistingResolved` (buffer-only); a closing-flagged packet never purges at all — the transient-purge gate is close-aware (v10.8.0), so the close keeps the shared backing and takes `ExistingResolved`; `SeedInstalled` (genuine top-level miss, #4400-passed) runs the full seed transaction as today; `SeedRefused` (miss, refused) drops as today. The gated verdict is terminal across dispatch; a live/marked entry can never be replaced by a transient raw-flags seed; the accepted close's sole producer survives (§5.5/§5.6) |

---

## 3.1 Master drift since the citation base (v10.5.1; verified `023f17a606d8` → `fff7a4ab5`)

origin/master advanced 19 commits while this plan iterated. Re-verified
this round; **no design rule in §5–§9 changes**. Implementation
(`/engineer 6461`) branches from the then-current master and applies
these deltas:

| Change on master | Consequence for this plan |
|---|---|
| **#6478** (`7b7119db1` + docs `fff7a4ab5`) removed `cluster_peer_return_fast_path`, its reverse-seed install, and the #4453 bare-close guard (`fabric.rs:389-492`, the call at `poll_descriptor/mod.rs:928`) | Site 6 no longer exists — its residual is closed by deletion. §3's fast-path bullet, the #4453 bullet, site row 6, and the §5/§5.6/§7 fabric-seed mentions are branch-base record. Post-#6478, fabric-ingress return traffic WITH a live session takes the ordinary HIT path (site-1 gate applies); SESSIONLESS fabric-ingress packets take the ordinary MISS path (master `poll_descriptor/mod.rs:941-959`), where #4400 guards bare closes — covered either way (round-90 Codex 5 corrected an earlier overstatement that all such traffic runs site-1 HIT accounting) |
| **#6432** wrapped the MissingNeighbor arm in the `poll_stages::StageOutcome` ownership enum (arm head now `poll_descriptor/mod.rs:4015`; seed install `:4792`/`:4816`) | Site 9's "branch on the resolve outcome AT THE ARM HEAD" composes: the typed resolve-outcome branch becomes the arm's first StageOutcome-producing stage. No rule change |
| **#6433** extracted the flow-cache seed path | Editorial; the §5.6 constructor sites are unchanged |
| **#6458** added the fabric zone-stamp owner-RG gate (`gate_fabric_zone_override_on_owner_rg`, master `fabric.rs:289-307`; the worktree's `fabric.rs:331` is `redirect_via_fabric_if_needed`, a different function) | §5.4's "no transport-based authority" bullet stands verbatim — the stamp proves even less post-#6458 |
| **#6474** re-NATs outbound ICMP errors through SNAT | Orthogonal (ICMP error path, not TCP closing); shifted `poll_descriptor/mod.rs` line numbers |
| **#6473** flipped inbound NAT to static-first (static NAT now evaluated before DNAT rules) | Non-fatal for this plan: the clean-miss install dispatch (the only install point for the purged class, v10.11.0) derives DNAT/routing/zone/policy/SNAT fresh from the packet against current config through the full pipeline, so the reorder is composed automatically (round-89 Codex 4 confirmed) |
| Line drift (verified; round-90 Codex 5 corrections applied) | `account_packet` call sites: `flow_cache_hit.rs:312-317`→`:318`, `poll_descriptor/mod.rs:3494-3503`→`:3556`; strict-syn guard call statement `:1642-1650` (guard expression `:1646`) in BOTH revisions; the predicate body is `session_admission.rs:82-87` in both (the plan's `:53`/`:1634-1644` cites were the doc-comment/comment blocks — round-93 Codex 6); input filter `:592`→`:612`; TTL check `:846`→`:866`; `materialize_shared_session_hit` `session_glue/mod.rs:1092-1118`→`:1122`; transient-purge call block `:1178-1193`→`:1208-1223`; `touch_if_stale` call `flow_cache_hit.rs:301`→`:307`; `build_reject_rst_frame` at `frame/tcp.rs:347` in BOTH revisions (no drift); `parse_session_flow_from_bytes` `frame/inspect.rs:1455-1470`→`:1424+`; `is_cacheable` `types/forwarding.rs:948-952`→`:959`; tunnel `UpsertLocal` push `tunnel.rs:739/:741`→`:765-767`; LocalDelivery gate fn `local_delivery.rs:20` in BOTH revisions (master's `:39-44` is the predicate's doc comment, not the fn); `live_by_flow` correction: the field sits at `nat/allocator.rs:481` in BOTH revisions (no move) — the plan's `nat/source.rs:1548` cite is the `allocate_translation` CALL site, which is the unowned-allocation leak site itself and stands as cited |
| Unchanged on master (re-verified exact) | The issue site itself — `lookup.rs:105-128` (`do_close`/`closing`/`reset`) and `:151-156`; `session/mod.rs:1232` `propagate_tcp_state_to_companion`, `:1118` `touch_if_stale`, `:1299`+`1396-1432` `update_session` head + sticky-RST body; `expire.rs:342-350` Close-delta gate; `entry.rs:209` `ForwardSessionMatch`; `install.rs:113`/`:139`/`:179-180`/`:295`/`:399-400`; `shared_ops.rs:614`/`:857`; `lookup.rs:258` `find_forward_wire_match_with_origin`; `session_admission.rs:82-87`; `schema_security.go:798`; `compiler_security_flow.go:527-528` |

---

## 4. Multiple path options

### Option A — sequence-window demote gate, state-only (RECOMMENDED, the v10 ship candidate)

Track flow sequence progress at the existing accounting chokepoints; gate
**only** the `closing`/`reset` demotion (and its companion propagation and
install-time seeds) on the closing segment's placement against a *trusted*
anchor. The packet itself is always forwarded unchanged — endpoint teardown
delivery is never blocked, so no legitimate teardown can be broken by the
firewall; the worst failure is a *refused demote* (entry idles out on its
normal timeout, exactly as if the RST had been lost in transit — a
condition #3046 already tolerates by design). Always-on (no config knob),
mirroring the #4400 precedent: the gate can only make the firewall *more*
conservative about killing state. **Refuse-demote whenever no trusted
baseline exists** (round-2 convergence) — fail-open was the wrong edge
policy precisely where the attacker has the most control: the no-baseline
windows (post-failover, post-upgrade, post-materialize) are
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
— the exact breakage the issue forbids; bigger surface (schema + compiler +
docs + reply path). Deferred follow-up once Option A's anchor accuracy is
proven in the field (AGY r1 independently argues A-first for the same
reasons).

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

### Option E — full lifecycle hardening (the v9.x shape, REJECTED by 70 rounds of review)

Bundle the gate with the #6522 NAT holder-lifetime fix, incarnation-fenced
Close application, and an HA identity/retirement protocol. Rounds 13–82
grew this into a distributed protocol (hold tokens → escrow → incarnations
→ fence ledgers → predecessor vectors → mint tokens → transfer CAS →
floor sync) that never converged — every fold exposed level N+1, and the
round-81 reviews still found 6 BLOCKERs + 2 HIGHs + 2 UNSOUNDs + 3 fresh
traces, ALL in the machinery, none in the gate. Rejected as a plan shape:
the machinery's customers are re-scoped (§10.6), and the gate ships alone.

---

## 5. Concrete design (Option A)

### 5.1 The anchor: one two-direction track on the canonical forward entry

`SessionEntry` gains (40 B; plain POD, worker-owned, no serde, no HA
wire):

```rust
/// #6461: two-direction sequence/ack anchor for FIN/RST demote validation.
/// Lives ONLY on the canonical FORWARD entry (reverse entries carry none —
/// `account_packet` and the close path already hop reverse→forward, the
/// #2501/#4109 pattern). Node-local derived state — NOT carried on the HA
/// session-sync wire (same precedent as `established`, #3152; carrying it
/// is the Phase-2 track, §10.5).
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
`wrapping_add` everywhere.)

Why the forward entry: `account_packet` already resolves the forward entry
for BOTH directions (`mod.rs:1177-1211`), so one store serves every
validation with no cross-store merge (round-1 Codex B3's 2^31-ordering
problem disappears: there is never a second store to merge). Reverse
entries carry no anchor; a missing forward entry (e.g. FabricRedirect flows
with no local forward entry — the same missing-companion case
`account_packet` tolerates) means no anchor → **refuse-demote** (the
non-owner's copies are non-authoritative — `is_reverse`/peer-synced origins
suppress their Close deltas — and the owner validates the redirected close
against its own anchor).

### 5.2 Anchor updates: commit-point observation, trust, and gating

**Where updates run:** the anchor learns ONLY from packets the firewall
**successfully committed to the wire or the local stack** — applied in the
successful dispatch arms, never inside the session lookup or the
request-build stage:

- **Commit point = RX-WORKER FINAL ADMISSION with geometry hoisted
  and selective no-learn:** the anchor lives on the canonical forward
  entry in the RECEIVING worker's table; CoS can hand the request to a
  different owner before final admission (`cos.rs:125`), and a
  target-side admission point cannot mutate the RX worker's table
  without a per-packet cross-worker callback (rejected: worse than the
  residual). The anchor applies at the RX worker's OWN final admission
  point — after binding/MTU/translation/CoS-selection AND after every
  **geometry-determined** check (MTU, slice validity, frame malformed —
  `transmit/stage.rs:23`; packet geometry is attacker-chosen and pairs
  with any chosen sequence, so a geometric check left in the tail is a
  sequence-targeted poisoning channel). `push_redirect_inbox` capacity
  discard MUST be reported (`umem/mod.rs:1290`'s reporting API) and does
  not move the anchor (mandatory, not best-effort). **Selective
  no-learn:** no anchor learning on
  `NoRoute`/`NextTableUnsupported`/`MissingNeighbor` reinjection or
  ForwardCandidate build-failure fallback (`slow_path.rs:60`) — those
  exceptional paths are transient by construction. The remaining
  async-write tail (LocalDelivery reinjection incl. GRE-mapped at
  `slow_path.rs:213/:297`, TUN-egress at `tunnel.rs:119/:180`, kernel
  slow path at `slowpath.rs:534/:607`) admits per-packet malformed
  `EINVAL` — geometry-steerable. Stated with full honesty: the channel
  adds NOTHING to the demote attack's probability (a malformed precursor
  needs the SAME ~1/6,554–1/10,923 in-window hit as a direct blind
  close), but it is NOT strictly dominated for every attacker objective —
  after one hit, contiguous malformed follow-ons ride the trusted
  self-slide, and poisoning the anchor so the endpoint's legitimate
  close is soft-refused RETAINS a slot/NAT reservation for the entry's
  ordinary timeout (300 s default, up to 86,400 s per-app) — a
  resource-retention objective some attackers prefer over a 2 s demote
  that releases resources. Its honest bound: spray duration PLUS one
  inactivity timeout — the walk's follow-on packets are ordinary
  non-close packets that refresh `last_seen` through the unchanged
  non-close path (`lookup.rs:150`, `flow_cache_hit.rs:295`), so the
  attacker holds the entry only by continuing to spray — exactly what a
  plain valid-looking keep-alive spray already buys on master at
  identical in-window guess cost, so this is NOT a new pin primitive;
  when the spray stops, the entry idles out within one timeout.
  Accepted because the alternatives (per-packet post-commit callbacks,
  or freezing these anchors and soft-refusing every close on the
  host-inbound victim class) are worse. All other arms are commit-clean.
- **Pending-neighbor posture (v10.2.0 — THE RETREAT, round-84 Codex
  2/3/5/6):** master's buffered-decision retry is **UNCHANGED** —
  `retry_pending_neigh` (`neighbor_dispatch.rs:156, :272, :310, :344,
  :369`) transmits the buffered decision exactly as today, and the
  pending machinery (`types/mod.rs:77`, `poll_descriptor/mod.rs:5057`)
  is untouched. The v10.1 re-resolve-once design and its interim-expiry
  hold are RETRACTED: they produced four BLOCKERs in one corner (the
  hold had no typed family identity; `Some(resolved)` does not imply a
  live entry after the transient purge at `promote.rs:167`; the
  per-binding pending timeout is not a cumulative per-session bound;
  wheel reinsertion/bounding was unspecified) — each fixable, but every
  fix added local machinery to defend an improvement (never-transmit-
  stale) that is OUTSIDE this issue's blast radius. What the gate
  actually needs here is only: (i) **a buffered packet never moves the
  anchor and never drives post-borrow state** (no anchor update, no
  establishment promote, no probation clear on the retry path — the
  retry has no `SessionTable`; the next unbuffered packet does all
  three). The consequence is a documented residual, not a channel: a
  flow whose traffic is mostly buffered (long ARP stalls) lets its
  anchor lag the stream — later closes soft-refuse and the entry idles
  out on its ordinary timeout, the same bounded class as the
  unobserved-stretch residual (§2), always fail-toward-refuse (a
  skipped update can never walk or poison an anchor). A buffered
  SYN-ACK that delivers without its promote leaves the entry OPENING
  exactly as on master (the promote fires on the next unbuffered
  packet; if none comes, the 20 s opening window reaps — master
  parity). (ii) **the buffered stale-decision transmit window is
  documented as PRE-EXISTING** (§7 races): master today can transmit a
  pending packet with a NAT/egress decision whose entry expired (or was
  transient-purged, `promote.rs:167`) during the ARP wait — including
  an admitted close, which master DELIVERS (and this plan preserves
  that delivery: the demote verdict is terminal at resolve — refuse =
  no mark, accept = marked at resolve — so the retry needs no
  re-validation and no re-resolution). The v7.5-era never-transmit-
  stale hardening is NOT shipped by this plan; it is a follow-up
  candidate (§10.6.2) whose correct design is the typed-outcome work
  round-84 sketched — not a prerequisite for the demote gate.
  (iii) **the seed class is documented, not completed (v10.4.0 — THE
  SECOND RETREAT, round-86 Codex 2/3/4/6):** the v10.2.0/v10.3.0
  seed-lifecycle completion (origin flip, flip-time `session_limit_inc`,
  flip-time Open, `session_id`-guarded alias cleanup) is RETRACTED.
  Round-86 review showed each layer of it opens the next (flip-time inc
  bypasses the configured per-IP admission cap — `session_admission.rs:29`
  is miss-only and `session_limit_inc` performs no check,
  `session/mod.rs:909`; flip publication can overwrite a newer
  generation or undo an HA demotion — publication is unconditional
  replace, `shared_ops.rs:897`; `session_id` is not collision-free
  cross-node — worker/counter namespacing at `session/mod.rs:766` +
  import-adopted ids at `install.rs:324` + bulk-export zero ids at
  `ha/export.rs:143` — and check/delete has no linearization point,
  `shared_ops.rs:960`, `checksum.rs:246`, `xpf_maps.h:508`; the flipped
  seed retains stub policy metadata and the wrong idle timeout —
  `neighbor_dispatch.rs:606` hardcodes policy 0 / timeout None).
  Closing those correctly needs count-at-admission, a
  compare-and-transition publication, a process-local collision-free
  alias-owner token with serialized conditional deletion, and metadata
  preservation — the same unfold pattern as rounds 13-82 and the
  pending-neighbor corner, in a class that is OUTSIDE this issue's
  blast radius: **every seed-lifecycle gap is pre-existing on master**
  (master's transient seeds never emit a Close — `expire.rs:342-350`'s
  exclusion — and no HA peer copy exists to orphan because seeds emit
  no Open; master's seed reaps never remove the install-published
  shared/DNAT aliases — the stale-alias materialize-with-released-
  translation trace exists on master today; master's seed-born flows
  keep the stub metadata for life). The plan therefore documents the
  class (§7 emission carve-out, §7 races (e)-(g), §10.6.2 follow-up
  with the round-86 design notes) and changes NOTHING in the seed
  lifecycle: `MissingNeighborSeed` install, metadata, accounting
  (uncounted), publication, retry, and expiry are all byte-identical to
  master. What the demote gate needs from the seed corner is only the
  site-9 typed-outcome gate (no raw-flags replace of a live/marked
  entry — §3 site 9); the `ResolvedWithoutLocalBacking` re-entry is
  RETRACTED to master-verbatim (below, v10.11.0).
  (iv) **`ResolvedWithoutLocalBacking` is MASTER-VERBATIM (v10.11.0 —
  the re-entry is RETRACTED, round-94 Codex 1-3):** when the
  resolve-time transient purge fires, master's own machinery keeps the
  packet in the HIT branch on the retained lookup
  (`session_glue/mod.rs:1194-1196` — `resolved = hit.lookup.clone()`),
  and this plan keeps that dispatch byte-identical: the packet
  forwards/buffers/replays/reinjects with the retained decision —
  master's single-decision consumption (the v10.4.0 P1/P2 split and
  the blanket-clear DNAT-erasure risks both arose from the plan's OWN
  intermediate re-derivation shapes, never from master) — with NO
  derivation, allocation, install, publication, seed, or cache
  mutation for the purged packet. The NEXT packet re-resolves as a
  genuine clean miss and installs/seeds with a fresh current-config
  derivation — the round-87 correctness property lands at the install,
  where it matters: no stale retained decision is ever installed.
  The v10.4.1 same-dispatch re-entry is retracted because it
  (round-93 Codex 1) collapsed the pre-existing #6599 class from two
  packets to one (master installs only on the later clean miss),
  (round-94 Codex 2) in its install-free-with-derivation form stranded
  an unowned P2 for a one-packet flow (fresh SNAT/NAT64 derivation
  allocates before forwarding, `poll_descriptor/mod.rs:2142-2156`;
  the no-install paths must either leak the slot or resurrect the
  retracted rollback-then-forward race), and (round-94 Codex 3) its
  no-cache rule made packet two deterministically miss+install+Open
  where master's cache-eligible subclass forwards from the sessionless
  cached decision (`poll_descriptor/mod.rs:3856-3960`) with no install
  at all — a plan-introduced #6599 acceleration. The retained-decision
  staleness window under a mid-dispatch config change is master's
  documented pre-existing behavior (§7 race (d), the v10.2.0 retreat).
  The close-aware purge gate (§5.6 site-3 supplement) is unchanged and
  remains the plan's ONLY departure on this path.
- **Residual (documented):** TX-completion failure (driver/UMEM ring
  after final admission) is the irreducible unobserved tail — not
  per-packet steerable in any sequence-targeted way. **Runtime-capacity
  tail (round-83 Codex 4, documented):** the local/prepared TX queues
  evict their OLDEST already-admitted request when bounded
  (`tx/drain/mod.rs:33, :56`; enqueue sites push first and bound
  afterward, `tx/dispatch/mod.rs:665, :786`), so a packet whose anchor
  update already ran can be discarded by a LATER enqueue under queue
  pressure. Same posture as the async `EINVAL` tail: exploitation needs
  the same ~1/6,554–1/10,923 in-window hit as a direct blind close, the
  channel adds nothing to the demote probability, and the honest bound
  is the attacker's own spray budget plus one timeout. Accepted —
  restructuring the bound-then-apply order across every enqueue site is
  worse than the residual. **All other arms are commit-clean.**
- **`account_packet` is UNCHANGED; the anchor apply rides a DISTINCT
  post-admission hook (v10.4.0 wording fix, round-86 Codex 7):** #2501
  counter placement is untouched (`account_packet` keeps counting
  attempted forwards at `flow_cache_hit.rs:312` /
  `poll_descriptor/mod.rs:3497` — RT_FLOW volume semantics; the
  slow-path call PRECEDES build/output-filter/CoS failures, which is
  why it cannot host the anchor). The anchor's update hooks are the
  per-disposition FINAL-ADMISSION apply points of §5.2 (two call
  classes: the cache-hit commit arm and the slow-path commit arms),
  fed by the same seg view; no signature change to `account_packet`
  at all. **The apply hook has NO missing-forward fallback (round-83
  Codex, core-gate note):** unlike
  `account_packet`'s tolerant reverse hop (`session/mod.rs:1205`), a
  missing canonical forward entry means the hook is a NO-OP — updates
  land only on the one canonical store (validation refuses regardless,
  §5.1).
- **`lookup_with_origin` does NO anchor updates:** the lookup path
  validates and marks only. Closing segments never update (rule 1);
  committed non-close packets update at the dispatch arms above.
- **Install-time seeds** are applied at the constructors (rule 4's
  provenance matrix).

Reverse-direction samples fold onto the canonical forward entry exactly as
`account_packet` folds counters today (`mod.rs:1177-1211`); commit-hook
updates on a reverse-direction packet use the same reverse→forward key
hop. One store, one gating rule, per-disposition commit hooks.

**The gating rules (the trust anchor must be neither attacker-jumpable
nor attacker-seedable nor attacker-poisonable):**

1. **Closing segments never update the anchor.** A FIN/RST's own sample
   is not applied anywhere, before or after validation (validation reads
   the pre-packet anchor; on accept the entry is dying and the anchor is
   moot).
2. **seq slides:** an ordinary (non-close) sample `s = seq + seg_len`
   with **`seg_len > 0`** slides `seq_hi` forward only within the current
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
   `FWD_SLACK(O) = max(2×wnd(D), 64 KiB)`. Without the `has_ack` gate, a
   SYN retransmit's zero ACK field seeds `ack_hi ≈ 0` on an OPENING hit,
   and the real ACK stream (≫ slack away) can never repair it — a
   permanent acceptance window near sequence zero that a naive `seq=1`
   blind RST validates (round-2 Codex 3).
4. **Trust acquisition (provenance matrix + per-field proofs +
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
     seeds (branch-base class — the fast path was removed on master by
     #6478, §3.1), tunnel `UpsertLocal` refreshes, `ReplacedSyncedLocal`
     installs, and any re-import/upsert (which `remove_entry`s the prior
     record — an anchor wipe, §7). Their packets' samples adopt
     `valid`+**untrusted** only.
   - **Per-field proofs for untrusted→trusted conversion:** a sample for
     an untrusted side is adopted `trusted` only when that SAME field
     proves against trusted state — a seq sample for direction D proves
     inside `window(ack_hi(O))`; an ack sample for D proves inside
     `window(seq_hi(O))` — using the PRE-PACKET anchor including the
     pre-packet `wnd` (a segment never widens the window used to prove
     itself, round-4 Codex 9c). **There is no segment-wide weak
     adoption:** a weak proof covers only its own field. The
     asymmetric-bootstrap deadlock this creates (`seq_hi(rev)` needs
     `ack_hi(fwd)` needs `seq_hi(rev)`) is closed NOT by blessing
     unrelated fields but by the own-ack close leg (§5.4 rule 1 leg 3):
     an ACK-bearing close carries its own proof in its ACK field and
     never needs the deadlocked sides.
   - **Strong OPENING handshake proof (segment-wide, exact):** against an
     install point seed, the proving ack must lie in the exact interval
     `[isn+1, isn+SEG.LEN]` — RFC 9293 SYN-SENT's
     `ISS < SEG.ACK <= SND.NXT`, covering RFC 7413 §4.2.2 TFO
     partial-ack (a server rejecting SYN data acks only the SYN). For a
     bare SYN the interval collapses to one value (a spoofed SYN-ACK
     needs the client ISN, 1/2^32; with a TFO payload up to the
     4,096-byte frame ceiling, ≥ ~1/2^20). A SYN-ACK proving this way
     authenticates the WHOLE segment (the exact ISN knowledge is
     cryptographic-strength evidence the sender is the real peer) → both
     its seq and ack adopt trusted (fast server abort validates), and it
     drives the establishment promote (rule 5). **Not windowed** (a
     BACK/FWD window would drop the proof to ~1/2^13).
   - **Trusted self-slide:** a sample for an already-trusted side slides
     on its OWN bounded continuity gate (`s.wrapping_sub(cur) ∈ (0,
     FWD_SLACK]`, serial max) — no cross-proof required. Without this, a
     one-direction-observed LocalDelivery flow (firewall-originated: only
     inbound packets seen) could never advance its trusted inbound
     anchor, and full-duplex scaled-window traffic (seq ahead of the
     opposite ack by up to the window) would stall on every packet —
     both fully-observed legit classes frozen by the over-strict
     alternative. The continuity gate is the same FWD_SLACK bound the
     slide always had; attack difficulty is unchanged (the first
     in-window guess is the hard part).
   - **Transaction semantics:** on each packet, per side: (i) a proving
     sample for a `!trusted` side **replaces** the stored untrusted
     value (never max-merges with it — attacker-planted untrusted values
     are discarded, never blessed); (ii) a sample for a `trusted` side
     applies the serial-max continuity slide (rule 2/3); (iii) a
     non-proving sample adopts ONLY into a `!valid` slot as untrusted —
     it NEVER clears or alters existing valid/trusted state (a SYN
     retransmit cannot demote the trusted SYN seed); (iv) untrusted
     state never validates a close and never authenticates other
     segments (fabricated self-consistent pairs stay untrusted); (v)
     `wnd` updates only from proving/trusted segments (a no-knowledge
     precursor advertising 65,535 must not widen `FWD_SLACK`).
   - **No transport-based authority:** a fabric-ingress stamp proves only
     "arrived via the fabric link" — never sequence placement, endpoint
     acceptance, or peer validation (an inactive node converts ordinary
     external traffic into `FabricRedirect`,
     `poll_descriptor/mod.rs:3438-3476`, `fabric.rs:331-342`). A blind
     packet redirected by the non-owner would otherwise authenticate a
     planted anchor on the new owner's zero-trust import and revive the
     two-packet post-failover kill. Fabric-ingress packets authenticate
     exactly like any other packet: by proof against trusted state, or
     not at all.
5. **Closing packets never promote — at all.** `promote_from_reverse`
   (`lookup.rs:146-149`) sets `established` in-borrow on any reverse
   SYN-ACK; `maybe_promote_synced_session` (`promote.rs:86-107`) flips a
   synced entry's origin to `SharedPromote` on any packet with a
   ForwardCandidate disposition. BOTH are skipped for `is_closing(flags)`
   packets:
   - The in-borrow established-promote is skipped (SYN-ACK+RST is an
     abort, not an establishment signal; round-3 Codex 10). The
     establishment promote for NON-closing SYN-ACKs moves to the
     post-borrow phase and fires only on the strong OPENING proof
     (rule 4) — unproven SYN-ACKs no longer pin half-open entries into
     the established window.
   - The ownership promote is skipped: a blind first close post-failover
     must not flip `SyncImport`→`SharedPromote` — the flip arms Close
     authority (on MASTER today, a forward `SharedPromote` emits a Close
     delta at ANY expiry, marked or not — the `expire.rs:342-350` gate
     excludes only peer-synced/reverse/transient-seed origins) and
     suppresses the import's RG-activation self-heal
     (`expire.rs:213-237`), letting a refused close convert a silent
     standby reap into an authoritative, possibly accelerated, Close.
     **Close authority under v10 is master's gate, UNCHANGED** — the
     v9.x `owner_rg_active` predicate and its per-install RG stamping
     are cut (§10.6): master's gate plus rule 5 (no closing-packet
     promote) plus §5.6's probation suppression (no blind promote of a
     probation entry) plus the refuse-demote flip (no blind mark) are
     the barriers; the pre-existing old-owner retag-window race is
     documented in §7, not widened, and owned by §10.6.

**Stall analysis (made precise):** on a both-direction path switch (the
firewall stops seeing EITHER direction's packets — reroute around the
firewall with the flow still up), the anchor freezes at the last observed
positions. When the path returns, the live streams may be arbitrarily far
ahead; the first observed sample lands outside `FWD_SLACK` and adopts
untrusted-only (transaction rule iii), never replacing the trusted state
— so the anchor is permanently stalled for that flow and every later
close soft-refuses. Bounded: the flow's entries idle out on their
ordinary established timeout; delivery is never blocked; the aggregate
version is table pressure proportional to stalled flows, self-healing as
flows churn. This is the price of never letting an attacker repair (walk)
an anchor at will — the same rule that stops anchor-walking stops legit
repair. Accepted, documented, no hatch (a hatch re-opens the walk).

**Ordering:** on a closing-flag packet, validation (§5.4) reads the
pre-packet anchor — closing segments never update first (rule 1). On a
non-close packet, the update hooks run only after the commit decision
(§5.2), so a packet the firewall drops never moves the anchor.

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
and **slack is per stream receiver:** any quantity in stream S is bounded
by the window advertised by the RECEIVER of S — `FWD_SLACK(S) = max(2 ×
wnd(receiver(S)), 64 KiB)`. Concretely: a `seg.seq` candidate in stream D
uses `FWD_SLACK(D) = max(2×wnd(O), 64 KiB)` (D's outstanding-at-abort
data is bounded by O's receive window — D's effective SEND window); a
`seg.ack` candidate (a stream-O quantity, as are `ack_hi(D)` slides) uses
`FWD_SLACK(O) = max(2×wnd(D), 64 KiB)` (O's unacked in-flight is bounded
by D's advertised receive window). Raw u16 `wnd` self-bounds either slack
at 131,070 — no upper clamp; wscale tracking is deliberately not done
(the slack covers reordering + abort-time in-flight on the *observed*
path, not BDP; unobserved stretches are the stall residual regardless of
slack size). The total acceptance interval across all three legs is
honestly stated in §2 (worst disjoint 655,355 ≈ 1/6,554 at the cap;
393,219 ≈ 1/10,923 at the floor):

1. **ESTABLISHED:** accept iff ANY of three legs proves against
   PRE-PACKET trusted state (including the pre-packet `wnd`):
   - **leg 1 (own stream):** `trusted(seq_hi(D))` AND
     `seg.seq ∈ [seq_hi(D) − BACK_SLACK, seq_hi(D) + FWD_SLACK]`;
   - **leg 2 (opposite ack stream):** `trusted(ack_hi(O))` AND
     `seg.seq ∈ [ack_hi(O) − BACK_SLACK, ack_hi(O) + FWD_SLACK]` — the
     RFC 9293 §3.5.2 closed-TCB reset (`SEQ=SEG.ACK` — peer restart /
     state loss), subsuming the asymmetric case;
   - **leg 3 (own-ack proof):** `has_ack(seg)` AND `trusted(seq_hi(O))`
     AND `seg.ack ∈ [seq_hi(O) − max(2×wnd(D), 64 KiB), seq_hi(O) +
     FWD_SLACK(O)]` — the close carries its OWN cross-proof in its ACK
     field (the ack is a stream-O quantity: its lag behind `seq_hi(O)`
     is O's unacked in-flight, bounded by D's advertised window). Legit
     forms covered: FIN+ACK cumulative teardown, `SO_LINGER(0)` abort
     RST+ACK, and the RFC 9293 §3.5.2 reset forms (reset #2 carries
     `ACK=SEG.SEQ+SEG.LEN` of the incoming segment; reset #1/#3 derive
     `SEQ=SEG.ACK`). A bare no-ACK RST in a state where legs 1-2 have no
     trusted side soft-refuses (bounded residual: delivery unaffected,
     entry idles out). **Loss-episode nuance:** while a loss hole is
     outstanding, D's cumulative ack can lag `seq_hi(O)` by the whole
     buffered extent (megabytes with scaling) — an abort DURING the hole
     can miss leg 3 (soft-refuse, table retention only); legs 1/3
     recover after the repair. Do not read "loss-immune" as "loss-proof
     during the hole".
   A blind close must hit one of these windows (~1/2^13–1/2^14 per
   guess, §2).
2. **OPENING** (`!established` on the FORWARD entry): both legs consult
   ONLY the IMMUTABLE per-direction interval `[open_ack_lo(D̂),
   open_ack_hi(D̂)]` = `[isn+1, isn+SEG.LEN]`, and each leg first requires
   **`open_valid(direction)` AND `open_trusted(direction)`** (§5.1
   bit4/bit5 set only when that direction's SYN actually seeded the
   interval — install seeds are trusted, so a seeded interval is always
   trusted, but the predicate is written explicitly (round-83 Codex 5):
   without it the default `[0,0]` interval of the un-seeded direction
   would accept a bare `seq=0` RST through the self-abort leg, and a
   mixed trusted-forward/untrusted-reverse entry must validate only the
   trusted side). The interval is
   immutable (the live `seq_hi` slides on any committed in-window
   sample, which would let an attacker move the proof ceiling or the
   self-abort coordinate at ~1/2^16 guess cost; the immutable pair keeps
   the proof at 1/2^32 for a bare SYN, ≥ ~1/2^20 for max TFO):
   (a) **ack leg:** `ACK` set and `seg.ack ∈ [open_ack_lo(D̂),
   open_ack_hi(D̂)]` — RFC 9293 SYN-SENT `ISS < SEG.ACK <= SND.NXT`,
   covering RFC 7413 §4.2.2 TFO partial-ack; accepts the Linux/Windows
   connection-refused RST AND its TFO-reject sibling; (b) **self-abort
   leg:** `seg.seq ∈ [open_ack_lo(D), open_ack_hi(D)]` (the aborting
   side's own SYN interval — a client aborting its half-open connection
   RSTs at `isn+1`; the residuals — sent-data-then-abort before
   establishment, seq beyond the SYN interval, and TFO retransmit
   seed-variance (a retransmitted SYN carrying a different data length
   than the first SYN can make a legit SYN-ACK ack beyond
   `open_ack_hi`, stranding the proof and leaving the ack side
   untrusted for the entry's life — the §2 absorbing class, bounded)
   — soft-refuse inside the 20 s opening window, negligible). Install seeds are trusted, so an
   OPENING entry always has at least its creating direction's trusted
   baseline; a materialized OPENING import with no local observation
   falls to rule 3 (20 s opening window — the lingering cost of a
   refused legit close is negligible).
3. **No trusted baseline in any form → REFUSE-DEMOTE (the round-2
   convergence flip).** The closing packet is forwarded unchanged; no
   mark, no constructor seed of `closing`/`reset`, no `last_seen_ns`
   refresh, no wheel push; the entry ages on its ordinary timeout. The
   trace that forced this (round-2 Codex 1 / AGY 1 / SMR 1, all three
   independent): post-failover, a blind RST as the first
   locally-observed packet of a synced flow → materialize (site 2c) +
   promote (`promote.rs:86-90`: ForwardCandidate = local RG ownership) →
   `update_session` retags the entry `SharedPromote` — which is NOT
   `is_peer_synced` (`entry.rs:245-250`) — so the 2 s reap emits a Close
   delta (`expire.rs:342-350`); the promote's Open delta means the Close
   draws a fresh stamped delete generation that applies unconditionally
   (`sync_conn_write.go:53-82`, `sync_conn_gen.go:493-506`; the gen-zero
   fallback at :176-186 is equally unconditional) — deleting the shared
   copy and the peer's standby copy cluster-wide. Under refuse-demote
   plus rule 5 the chain dies at step one: nothing is marked, nothing
   promotes, nothing reaps early, nothing emits.
4. All comparisons RFC 1982 wrapping; the membership test is
   `seq.wrapping_sub(lo) <= hi.wrapping_sub(lo)` — no plain `hi - lo`
   (debug-build panic on wrap, round-1 Codex B3). Per-leg compile-time
   asserts: `const _: () = assert!(BACK_SLACK + 2 * u16::MAX as usize + 1 < (1 << 31))`
   for the seq legs (196,607 max) AND
   `const _: () = assert!(2 * (2 * u16::MAX as usize) + 1 < (1 << 31))`
   for the symmetric own-ack leg (262,141 max); the union probability is
   stated in §2 (worst 655,355 ≈ 1/6,554).

A refused demote leaves `closing`/`reset` untouched, performs **no**
`last_seen_ns` refresh and **no** wheel re-queue (§5.7), and bumps a
worker-owned `tcp_close_seq_rejected: u64`, **exported through the
ordinary worker statistics/metrics surface** (production-visible, no
debug build) plus a rate-limited structured RT_FLOW/screen-class record
for attack attribution (never per-packet).

### 5.5 Where the verdict is applied — marking moves to the post-borrow phase

Today `lookup_with_origin` marks the matched entry inside its `&mut`
borrow, then propagates post-borrow. Validation needs the FORWARD entry's
anchor even when the matched entry is the reverse companion — a second
probe that cannot happen inside the first borrow. Restructure (close
segments only; the no-close path is byte-identical **for NON-PROBATION
entries** — probation entries take the deferred-refresh path of §5.6,
round-88 Codex 1: no in-borrow `last_seen_ns` stamp, timeout recompute,
or wheel push before final admission):

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
   `established`, run §5.4. **Family identity is verified BEFORE the
   anchor is read (v10.3.0, round-85 Codex 4):** when the matched entry
   is the REVERSE companion, the re-probed forward entry must
   RECIPROCATE the matched entry's family — the forward entry's
   `(key, nat)` reversed via the same `reverse_session_key` derivation
   the propagation path uses (`expire.rs:476-496`) must equal the
   matched reverse entry's `(key, nat)`. Forward and reverse halves can
   be separated on master (an HA import creates both; a stale-sync
   expiry or `purge_translated_synced_hit` removes only the old forward
   `K/NAT1`; a replacement forward `K/NAT2` installs; the stale reverse
   `R1/NAT1` remains) — without the check, a close direct-hitting `R1`
   (`lookup.rs:48`) would validate against whatever now occupies `K`
   and, on acceptance, mark `K/NAT2` through the key-derived propagation
   (`session/mod.rs:1241`) — an unjustified timeout transition AND an
   authoritative Close + fan-out caused by a packet on the OLD reply
   tuple. Reciprocity fails whenever `NAT1 ≠ NAT2` (the reverse key
   embeds the translation) → REFUSE-DEMOTE: no validation, no mark, no
   propagation; the orphan reverse ages out `is_reverse`-silent. Exact
   tuple+NAT reuse needs no generation token: when tuple AND
   translation are identical, the two generations are
   packet-indistinguishable at the firewall — the re-probed anchor IS
   the flow's anchor. A forward-hit match (site 1) needs no check (the
   matched entry IS the anchor's entry); the propagation target is
   generation-correct by construction once acceptance requires
   reciprocity (the same derivation function, agreed nats). An accepted mark applies the FULL mark
   semantics atomically: sticky `closing`/`reset` with `reset` set
   BEFORE the timeout recomputation (#3046 ordering), the
   `expires_after_ns` recompute, the `last_seen_ns` refresh, and the
   wheel push — on the matched entry and, at the reverse-synth accept
   site, on the forward family in hand (so the forward emits at its
   2 s reap; §5.6).
   - **Accept:** re-probe the matched entry, set `closing`/`reset`
     (OR-assignment preserves #3489 stickiness), refresh `last_seen_ns`,
     recompute `expires_after_ns`, then propagate to the companion
     **subject to target reciprocity (v10.4.0, round-86 Codex 5):**
     propagation derives the companion key (`lookup.rs:204`) and today
     blindly mutates whatever occupies it (`session/mod.rs:1241`) — an
     unrelated authoritative forward B can occupy
     `R = reverse_session_key(K, NAT_A)` with no companion (a supported
     state, `expire.rs:508`), and A's accepted close would mark B,
     handing B the 2 s/30 s timeout, an authoritative Close, a NAT
     release, and a delete fan-out. The propagation target is marked
     only when it RECIPROCATES the matched entry's family — its
     `(key, nat)` reversed via the same `reverse_session_key`
     derivation equals the matched entry's `(key, nat)` — AND, when the
     matched entry is a FORWARD, the target `is_reverse` (the
     forward-hit companion must be a reverse entry; the unrelated
     forward B fails this; when the matched entry is a reverse, the
     target is the forward — not `is_reverse` — whose reciprocity was
     already established at validation in the same post-borrow phase,
     same thread, same derivation inputs). A mismatch (empty slot,
     unrelated occupant, wrong flag) skips ONLY the companion mark —
     the matched entry's own mark and emission are unaffected
     (the #4109 propagation is a best-effort mirror, not the producer).
     This also closes the pre-existing master wrong-mark of the same
     shape. **A MATCHED probation entry is never marked (v10.8.0,
     round-91 Codex 3):** the validator reads the family's trusted
     anchor (the canonical forward entry, §5.1), so a close that hits a
     reverse-key PROBATION entry directly (`lookup.rs:62`) can validate
     against the live forward F — and the accepted-mark rule above
     would otherwise restamp the matched probation row (closing state,
     `last_seen_ns`, timeout, wheel) and move its immutable ≤20 s
     deadline to `now + 30 s`. The rule: when the matched entry is
     probation, the matched-entry mark/refresh/recompute/re-queue is
     SKIPPED wholesale (the propagation to the live, non-probation
     companion F proceeds and marks F normally — F is the authoritative
     family; the probation zombie loses nothing, its local-only reap
     emits nothing). Combined with the v10.7.0 propagation-target skip,
     a probation entry is never marked or restamped whether matched or
     propagation target.
   - **Refuse:** no marks, no refresh, no wheel push; bump the counter.
     `expires_after_ns`/`last_seen_ns` stay at their prior values — the
     entry ages on its pre-attack trajectory.

`update_session` (site 2): **a closing-flagged packet never reaches this
path at all (rule 5 — the ownership promote is skipped wholesale)**, so
there is no partial-promote transaction to specify: no origin flip, no
Close-authority arming, no self-heal suppression, no refresh question. A
non-closing promoting packet's ownership promote keeps MASTER's timing
(resolve-time, `promote.rs:86-107`) — the v9.x commit-arm restructure is
cut (§10.6); the probation suppression below is the only new promote
rule. **Probation entries additionally SUPPRESS ownership promotion, Open
emission, and replication until a committed non-close packet clears the
flag** (the refused-close → probation-zombie → blind-promote chain,
resolved precisely: a blind non-close that is FILTERED/TTL-dropped
neither promotes nor refreshes anything; a blind non-close that COMMITS
clears the flag and may promote exactly once — and that is not a kill:
the promote sets no close mark, retains the NAT decision, and
refreshes/recomputes only the ORDINARY established idle timeout
(`session/mod.rs:1397, :1430`), so any Close is emitted only at normal
inactivity expiry of an entry that is genuinely idle — correct cluster
hygiene, Junos reaps idle flows too).

### 5.6 Constructor gating (sites 2b + 2c)

**Reverse-NAT synth (site 2b):** `install_reverse_session_from_forward_match`
(`shared_ops.rs:857-865`) holds the `forward_match` in hand. **The match
carries explicit scope and identity (v10.2.0, round-84 Codex 4):**
`lookup_forward_nat_across_scopes` returns the same `ForwardSessionMatch`
shape for both scopes today (`shared_ops.rs:638`), and the type carries
only key/decision/metadata (`entry.rs:208`) — the plan's Local-vs-Shared
rule is not implementable on that shape. The match gains a
`scope: Local | Shared` tag plus the identity it was found under
(canonical key + NAT decision). Validation runs ONLY on a `Local` match,
and the anchor read/mark re-probe must confirm IDENTITY AGREEMENT — the
re-probed entry's canonical key AND NAT decision equal the match's —
before reading or marking (round-84 Codex 4's wrong-flow trace: an old
shared reverse alias for `K/NAT1` can survive while a local replacement
`K/NAT2` exists; the old reply tuple misses the local NAT index, returns
the Shared `K/NAT1` match, and a key-only re-probe would validate against
the WRONG flow and mark the replacement while synthesizing the old
decision — shared publication inserts new aliases without removing the
prior decision's, `shared_ops.rs:897`). **A `Shared` match refuses even
when the same canonical key is locally occupied** (the local entry is a
different flow generation), and any identity disagreement refuses.
When the current packet is
closing-flagged, validate it (§5.4) against the FORWARD entry's anchor
first (the cross-direction legs cover a reverse-direction
close — `ack_hi(fwd)` pins the reverse stream's position). A LOCAL forward
entry carries its anchor; a SHARED `ForwardSessionMatch` carries only
key/decision/metadata (`entry.rs:209`, `shared_ops.rs:638-665`) → no
baseline → refuse:

- **Accept** → install with `closing`/`reset` seeded as today, AND the
  mark is applied to the FORWARD family in the same resolve — two
  sequential same-worker writes: install the reverse companion, then
  re-probe and mark the local forward entry (the `forward_match` in hand
  is a CLONE, `shared_ops.rs:638-665`; worker-owned tables have no
  cross-worker observer, so the pair is indivisible to any reader; the
  SHARED-match case never reaches the mark — no anchor → refuse)
  (v9, round-12 Codex 10 — v8.x marked only the reverse entry,
  `is_reverse`-silent, leaving zero producers when the forward was an
  unmarked import and no later packet arrived; the forward match is in
  hand at this site, so the forward entry/import is marked at accept
  time, giving exactly one producer on the owner's forward entry — the
  claim scopes to the mark-creation sites; a same-node cross-worker
  SharedPromote copy is a second LEGITIMATE emitter on master and v10
  alike, deduped by the existing delete fan-out, `session_delta.rs:436,
  :453` → `delete_synced.rs:16`).
  Stated honestly: #4380 companion retention (`expire.rs:318`,
  `companion_keeps_alive`) defers the reverse's 2 s reap while the
  forward companion is live (≤ the 20 s opening window for a half-open
  forward); the test plan (§9) asserts THESE semantics, not an
  idealized 2 s whole-flow reap.
- **Refuse** → **skip the install entirely**, on owner AND non-owner
  alike (the non-owner shared-replica case mints no born-dying
  `ReverseFlow` either — "mints nothing" holds absolutely, and no shared
  reverse publish survives to need cleanup). The packet is still
  forwarded (the synthesized decision is returned regardless, the #1861
  §5.4 pattern; `created=false, install_failed=true` suppresses create
  telemetry and cache insertion, `poll_descriptor/mod.rs:509-547,
  :3900`). The next legitimate reply re-synthesizes the companion and
  revalidates against the same forward anchor; the forward companion is
  never marked from an unvalidated seed. A legit close we misjudged
  (stale anchor) costs only a re-synth on the next reply packet.

**Reactive materialize (site 2c):** `materialize_shared_session_hit`
threads the current packet's `tcp_flags` into `upsert_synced_with_origin`,
which seeds `closing`/`reset` at `install.rs:399-400`. Two rules apply:
(i) the constructor is NOT in the self-authenticating provenance set —
the driving packet's samples adopt `valid`+untrusted only, so a non-close
attacker packet materializing a shared victim plants nothing usable; (ii)
an imported replica carries no trusted anchor → every closing-flagged
materialize is no-baseline → **refuse**: install the copy ALIVE
(`closing=false, reset=false`) but at the **probationary opening-window
timeout** (bounded as `min(TCP_OPENING_TIMEOUT_NS, the imported
entry's own expires_after_ns)` — a per-app value shorter than 20 s is
never extended; a full-timeout alive install lets an attacker renew an
obsolete non-NAT permit indefinitely with periodic blind closes — each
materialize re-installs and each zombie lives 300 s; probation bounds the
zombie to ≤20 s and the sustain cost to 1 packet/20 s — the same pinning
cost an attacker already pays on master to keep any entry alive with
ordinary traffic, so no new pin primitive). **Re-materialization
preserves probation (v10.7.0, round-89 Codex 2 + round-90 Codex 3):**
master's materialize is unconditional — the shared canonical
deliberately wins over a surviving fabric placeholder
(`shared_ops.rs:594`; coexistence pinned by `session_glue/tests.rs:704`),
the upsert `remove_entry`s the existing local row and restamps
`last_seen_ns`/timeout/wheel (`install.rs:295`, `:345-400`, `:427-433`),
and it runs BEFORE the input filter/TTL/output admission — so without a
guard, each packet that reaches a materialize after a refused close
created probation K would replace K (restarting its clock or
substituting a full-timeout row) and repetition would pin the uncapped
synced-upsert slot. The rule: `materialize_shared_session_hit` against
an existing local probation entry under the same canonical key
ATOMICALLY ADOPTS the shared S2 while preserving ONLY the probation
deadline — the upsert runs, installing S2's decision and metadata
wholesale, while from K only `probation=true`, the alive `closing=false,
reset=false` state, and the timing carry over — and the carried timing
is the MINIMUM absolute deadline (v10.8.0, round-91 Codex 4):
`min(K.last_seen_ns + K.expires_after_ns, now_ns + S2's own candidate
from metadata.inactivity_timeout_ns, install.rs:382)` — K's 20 s
remainder never extends an S2 whose own per-app timeout is shorter (the
§5.6 shorter-timeout-never-extended promise holds in both directions),
and the wheel re-queue uses exactly that preserved absolute deadline.
Encoding (v10.9.0, round-92 Codex 3): `SessionEntry` stores only
`last_seen_ns` + `expires_after_ns` (`session/mod.rs:349`) and the
wheel computes their saturating sum (`expire.rs:50`), so the adopted
entry stores `last_seen_ns = now_ns` and `expires_after_ns =
D.saturating_sub(now_ns)` with D the selected minimum absolute
deadline — the wheel sum re-derives D exactly; the §9 test covers both
K-wins and S2-wins cases. **The overdue branch (v10.11.0, round-93 Codex 3 + round-94 Codex
5):** when D ≤ `now_ns` (K is already past due — expiry is strict and
wheel-driven, `expire.rs:130-168`, `wheel.rs:39-50`), the encoding
degenerates (`expires_after_ns = 0` targets the CURRENT tick, and a
packet per tick boundary ahead of the phase-shifted GC would re-queue
K forever). The rule: an adopt against an overdue probation entry
ADOPTS S2's decision/metadata IN PLACE (no S1/S2 split-brain — the
v10.10.0 skip-wholesale left K/S1 lookupable while the packet
forwarded on S2, and a later committed non-close could have refreshed
S1 for a full ordinary timeout, round-94 Codex 5) while preserving
K's `last_seen_ns`/`expires_after_ns` VERBATIM and running NO wheel
re-queue — K's existing hint fires on schedule and the GC reaps the
(now S2-consistent) entry on the original clock; a later committed
non-close clears probation and applies the ordinary refresh to the
S2-consistent entry (correct liveness — a real packet committed). The
§9 test covers the phase-shifted GC regression (adopts at
one-per-tick can never pin an overdue K) AND decision agreement after
the in-place adopt. Wording correction: the preserved deadline is
"shorten-only, never extended" — the `last_seen_ns = now_ns` write in
the non-overdue encoding is the vehicle, not a refresh (the absolute
deadline D is what is preserved; earlier "immutable/never restamped"
phrasing refers to D, not to the stored fields). (v10.7.0 replaces the v10.6.0
skip-the-upsert shape: key+NAT agreement is not decision agreement —
`SessionDecision` also carries `ForwardingResolution`, `entry.rs:11-12`,
and metadata carries owner-RG/zones/policy state that shared publication
can independently replace, `shared_ops.rs:897` — so skipping would
forward the packet with S2 while the surviving K still served S1.
Adopt-S2 makes the entry and the packet agree by construction; a
generation change inherits the min() deadline too — bounded harm, it
only ever SHORTENS a new materialization to the prior clock, never
extends.) Only the entry's own successful final-admission commit hook
(a committed non-close packet) clears probation and applies the
ordinary refresh. A non-probation existing entry takes today's upsert
unchanged. The probation entry carries
an explicit `probation: bool` that (a) suppresses ownership promotion,
Open emission, and replication (§5.5), and (b) clears on the first
COMMITTED non-close packet, which also refreshes the entry to its
ordinary established timeout. **The clear+refresh runs at the MATCHED
entry's own commit arm — the entry the packet hit — independent of the
anchor's reverse→forward hop** (the probation flag lives on the
materialized entry, which may be a reverse-key entry; wiring the clear
through the anchor hook would clear the wrong store and strand a live
flow on 20 s probation churn). Unlike site 2b the install cannot be
skipped — the packet needs its decision and the entry must own the flow
going forward — so the seed is suppressed instead. **A probation entry's
reap is LOCAL-ONLY (v10.1.0, round-83 Codex 2):** `ExpiredSession`
carries the probation flag, and a probation expiry removes ONLY the
worker's local table entry — NO Close delta (as before), NO
`release_source_nat_allocation`/`release_nat64_allocation`
(`worker/loop_body/mod.rs:1491-1504`), and NO BPF session-map family-key
delete (`bpf_map/mod.rs:633, :704`). **The probation deadline is fenced
from HA/GC retention (v10.6.0, round-89 Codex 3):** master's expiry
evaluates the standby retention gate BEFORE removal (`expire.rs:168`),
and a `SharedMaterialize` entry is peer-synced (`entry.rs:245`), so
without a fence a probation entry at its deadline could SelfHeal-restamp
(`expire.rs:213-237`), Hold-rebucket (`expire.rs:239-273` — ceiling 3×
the entry timeout, `session/mod.rs:103-121`), or ride companion
freshness (`expire.rs:296-320`, `:490-523`) — each a `continue`
upstream of the `ExpiredSession` probation flag, silently breaking the
≤20 s promise. The rule: at expiry evaluation a probation entry whose
immutable deadline has passed BYPASSES SelfHeal, Hold, and
companion-freshness retention and proceeds straight to the local-only
removal above; `refresh_for_ha_transition` (`session/mod.rs:1594` —
owner-RG refresh and demotion both call it) PRESERVES a probation
entry's deadline (no `last_seen_ns` restamp, no timeout recompute; any
wheel re-queue uses the unexpired probation deadline). HA transitions
neither extend nor shorten probation. **Companion propagation skips
probation targets (v10.7.0, round-90 Codex 4):**
`propagate_tcp_state_to_companion` (`session/mod.rs:1232`) otherwise
unconditionally marks the reciprocal entry and restamps
`last_seen_ns`/timeout/wheel (`:1254-1276`) — an accepted FIN on the
live half F would move a probation companion R's immutable ≤20 s
deadline to `now + 30 s` (and repeated accepted closes would restamp
it). The rule: a propagation TARGET with `probation=true` is skipped
wholesale — no `closing`/`reset` mark, no restamp, no recompute, no
re-queue. The close's authoritative mark lives on the validated live
family; a probation companion is a local-only zombie whose reap emits
nothing, so the skipped mark loses no signal. Those keys and the NAT reservation
are process-global and serve the LIVE family's owner entry (the zombie
is a non-owner copy of it); the unconditional master cleanup path is the
#6522 class, and the probation constructor must not multiply its trigger
rate — with the local-only reap the zombie is strictly safer than
master's born-dying materialized copy, which runs the full cleanup at
its 2 s reap today. The owner/live entry's own reap performs the global
cleanup — the authoritative cleanup event for the family (master's
unrefcounted sibling calls are the pre-existing #6522 class, §10.6.1).
**No family clock, no
sweep, no incarnation recheck** (v9.x's probation-family-clock coupling
existed only to keep the family-clock push from shortening live siblings;
the family clock is cut machinery (§10.6), and with it that coupling —
probation is per-entry state only). (Phase 2 §10.5's wire-carried anchor
makes this site validatable; until then every materialize-seed close is
refused by construction.)

**Probation lookup does NOT refresh (v10.5.0, round-88 Codex 1):**
master's in-borrow lookup stamps `last_seen_ns`, recomputes
`expires_after_ns`, and re-queues the wheel (`lookup.rs:146-156,
:214-218`) BEFORE the input filter (`poll_descriptor/mod.rs:592`) or
the TTL check (`poll_descriptor/mod.rs:846`) consume the packet — so
under a naive "byte-identical non-close path" a blind
filtered/TTL-dropped non-close packet would refresh the zombie's clock
on every try and pin it indefinitely (and pinned materialized entries
pressure the admission ceiling: synced upserts bypass `max_sessions`,
`install.rs:294`, while fresh installs refuse, `install.rs:113`). The
rule: for a probation entry, the in-borrow lookup SKIPS the
`last_seen_ns` stamp, the `expires_after_ns` recompute, and the wheel
push (the ≤20 s probation clock runs unextended); `touch_if_stale` on
the cache-hit path (`flow_cache_hit.rs:295` → `session/mod.rs:1118`)
likewise skips probation entries (a cache-hit packet that drops at
MTU/egress after the touch must not refresh). Only the matched entry's
SUCCESSFUL final-admission commit hook — the same commit arms the
anchor hooks ride — clears `probation` AND applies the ordinary
established refresh (stamp `last_seen_ns`, recompute the ordinary
established/per-app timeout, wheel push) in one write; a packet that
drops anywhere before final admission (input filter, TTL, output
filter/CoS, redirect-inbox capacity, cache-tail) never clears and
never refreshes. The §5.5 "non-close path byte-identical" statement is
qualified accordingly: byte-identical for NON-PROBATION entries;
probation entries take this deferred-refresh path.

**Primary-install context (site 3 supplement):** the self-authenticating
provenance is `(origin, FreshPrimary)` — the `LocalMiss` installer can
displace a peer-synced LocalDelivery entry (`local_delivery.rs:75-113` +
`take_synced_local`, `lookup.rs:407-418`); a `ReplacedSyncedLocal` install
adopts untrusted only, so a driving SYN can never reclassify a synced
victim as a fresh self-authenticating flow. **Closing packets never
trigger the transient purge (v10.8.0, rounds 89-91 Codex):** the site-3
invented-tuple harmlessness holds ONLY when the tuple is genuinely new
in this dispatch. Two constructor contexts carry peer-synced provenance
for the SAME tuple — the transient-purge class (the resolve matched a
real peer-synced translated victim, classified at `promote.rs:48`,
purge driven from `session_glue/mod.rs:1178-1188` into
`promote.rs:167-207`; the v10.4.1 re-entry is retracted v10.11.0, so
the purged packet's dispatch is master-verbatim) and the
`ReplacedSyncedLocal` displacement above — and in both, a closing-flagged
packet that survives #4400 ONLY because it also carries SYN
(`strict_syn_check_drops_new_flow` rejects closes without SYN,
`session_admission.rs:83`) would otherwise reach a raw install, seed
`closing`/`reset` from the packet (`install.rs:179-180`), and emit Open
(`install.rs:234-260`) — the fresh entry's 2 s reap then emits Close
(`expire.rs:342-377`, the fresh origin passes the emission gate) and the
peer's helper delete executes unconditionally (`delete_synced.rs:16-17`),
killing the victim's authoritative entry and companions on the peer.
The rules:

- **RWoLB (v10.11.0 — unconditional retention; the reservation
  condition is retracted, round-94 Codex 4/6):** a closing-flagged
  packet NEVER takes the
  transient purge. The purge gate is close-aware: when
  `should_keep_synced_hit_transient` matches but the packet is
  closing-flagged, the purge is SKIPPED and the resolve returns the
  shared-backed `ExistingResolved` outcome — the packet buffers with
  the resolver's stored decision (the victim's own P1 translation; no
  fresh DNAT/SNAT derivation, no allocation, no rollback), transmits on
  neighbor resolution with P1 via master's buffered-decision transmit
  (never-drop preserved), the validator refuse-demotes (a peer-synced
  entry carries no trusted anchor → no mark), and NOTHING is purged,
  derived, allocated, installed, published, or emitted. Repeated
  closing packets are all inert — the provenance survives, so a second
  SYN|close sees the same shared backing and stays inert (no one-shot
  destruction). Retention is UNCONDITIONAL: the v10.10.0
  reservation-succeeded condition is retracted because (round-94
  Codex 4) a cached success bit is not a live ownership fence — the
  import fans one entry to every worker, cloned allocators share one
  token, same-flow reservations succeed idempotently without
  refcounting (`allocator.rs:1664-1674`), and an unrefcounted sibling
  reap can release the sole token later
  (`worker/loop_body/mod.rs:1490-1505`, `allocator.rs:1318-1332`) —
  and (round-94 Codex 1) the failed-row purge fallback would route
  reservation-failed closes into a path that drops bare closes master
  delivers. The exact fence is #6522/#6600 scope; the residual
  interaction is documented in §7. A subsequent NON-close packet
  purges and dispatches MASTER-VERBATIM (v10.11.0 — the re-entry is
  retracted: retained-lookup forward, no derivation/allocation/
  install/publication/seed/cache this dispatch; the install/Open/seed
  happen on the LATER clean-miss packet with a fresh derivation —
  master's two-packet shape exactly, §5.2 (iv)).
  (v10.8.0 retracts the v10.7.0 rollback + skip-install shape, which
  round-91 Codex killed twice: freeing P2 and then forwarding/buffering
  with the derived decision races the allocator — the existing rollback
  sites pair release with DROP and suppress buffering because replay
  would use "an unreserved NAT tuple with no session",
  `poll_descriptor/mod.rs:4670`, `:4891`, `:4974`; a buffered
  `PendingNeighPacket` would NAT-rewrite with the freed tuple,
  `poll_descriptor/mod.rs:5057` → `neighbor_dispatch.rs:272`/`:344`,
  the allocator's documented reply-misdelivery collision,
  `allocator.rs:1617`. And even paired with a drop, the destructive
  purge made provenance one-shot: close #2 would find a clean miss and
  FreshPrimary-install with closing seeded + Open, overwriting the
  peer's family, `sync_conn_gen.go:435` → `session_store.go:257`. The
  close-aware purge creates nothing and frees nothing, so both traces
  die by construction — and §4's teardowns-always-forwarded promise
  stands.)
- **`ReplacedSyncedLocal` (v10.7.0, confirmed sound at round 91):** a
  closing-flagged packet SKIPS the displacement —
  `take_synced_local` never runs, the synced victim survives — and the
  packet delivers locally without a cached session (the #4539
  decline-delivery precedent; LocalDelivery consumes no SNAT
  allocation, `poll_descriptor/mod.rs:1967`, so no rollback question
  arises). No install, no Open, no displacement.
The victim flow's next legitimate NON-close packets dispatch
master-verbatim: the first purges and forwards with the retained
lookup (no derivation/allocation/install — v10.11.0); the second
resolves as a clean miss and installs with Open — master's two-packet
shape exactly. A genuinely-new
tuple (no peer-synced
provenance this dispatch) keeps master's raw-flags seed exactly —
site-3 master parity stands for invented tuples. The installer returns
the displacement outcome; a mandatory unit test covers the replacement
branch.

The fabric-return seed (site 6) is already close-free (#4453) at the
branch base and **deleted outright on master by #6478** (§3.1); primary
miss installs (site 3) are #4400-guarded; tunnel UpsertLocal (site 5) is
trusted-local; wire re-import (site 4) carries no packet; the forward-wire
immutable match (site 8) never marks directly (its promote-mediated marks
are gated by rule 5 — closing packets never promote).

### 5.7 Refused-close side effects

A refused close is inert: no mark, **no `last_seen_ns` refresh**, no wheel
re-queue. Refreshing on a refused close would hand the attacker a pinning
primitive (indefinite slot + SNAT-reservation hold with refused packets)
and would let refused packets extend an already-running 2s/30s closing
window forever. Not refreshing does not accelerate natural expiry — the
entry ages exactly as if the refused packet had never arrived. Ordinary
data/ACK packets continue to refresh normally through the unchanged
non-close path — with the §5.6 probation exception: a probation entry is
refreshed ONLY by a committed non-close packet at its commit hook (and a
pre-admission materialize against it preserves its deadline while
adopting the shared decision/metadata, §5.6).

### 5.8 Signature/signature-shape changes (all crate-internal)

- `SessionEntry` gains the 40 B `TcpSeqAnchor` (§5.1) + `probation: bool`
  (§5.6) — POD, `Copy`, no serde, never on the HA wire (the sync
  install/upsert paths zero/default both fields exactly as they do
  `established`-class local state today).
- `tcp_seg_view()` (§5.3) — new helper in `frame/tcp.rs`.
- `close_seq_plausible()` (§5.4) — new pure function in `session/`.
- `account_packet` is UNCHANGED (v10.4.1 wording, round-87 Codex
  r86-7-disposition): counters stay exactly where #2501 put them
  (`flow_cache_hit.rs:312-317`, `poll_descriptor/mod.rs:3494-3503` —
  the slow-path call PRECEDES request construction/output filtering,
  `poll_descriptor/mod.rs:3752`, which is exactly why it cannot host
  the anchor). The anchor's update hooks (rule 2/3/4) are NEW
  per-disposition FINAL-ADMISSION apply points in the commit arms
  (cache-hit commit arm and slow-path commit arms), fed by the same
  seg view — a discarded packet never reaches them, so it never moves
  the anchor.
- `lookup_with_origin` — close-path restructure per §5.5 (in-borrow
  capture, post-borrow validate+mark); non-close path byte-identical
  for NON-PROBATION entries (probation entries take the §5.6
  deferred-refresh path).
- `install_reverse_session_from_forward_match` (site 2b) and
  `materialize_shared_session_hit` (site 2c) thread the `TcpSegView` to
  the constructor gate; `install_with_protocol_with_origin` /
  `upsert_synced_with_origin` gain a seed-suppression input (validated
  vs refused) replacing today's raw `tcp_flags` seed at
  `install.rs:179-180/399-400` for the gated paths. The site-2c
  materialize against an existing probation entry under the same
  canonical key ADOPTS the shared decision/metadata wholesale while
  preserving only `last_seen_ns`/`expires_after_ns`/`probation`/alive
  flags (v10.7.0, round-89 Codex 2 + round-90 Codex 3 — §5.6).
- The transient-purge gate becomes close-aware and the
  `ReplacedSyncedLocal` constructor branches on closing flags BEFORE
  `take_synced_local` (v10.8.0, rounds 89-91 Codex — §5.6 site-3
  supplement): a closing-flagged packet (SYN-bearing included, which
  #4400 does not reject) never purges the shared backing (RWoLB — it
  takes the shared-backed `ExistingResolved` outcome: buffer with the
  resolver's stored decision, no derivation/allocation/rollback/
  install/publication/emission; retention requires the row's synced
  reservation to have SUCCEEDED — reservation-failed rows take master's
  flag-agnostic purge even for closes, v10.10.0) and never displaces
  the synced victim (`ReplacedSyncedLocal` — deliver locally, no
  install). The purged-packet dispatch itself is MASTER-VERBATIM
  (v10.11.0, round-94 Codex 1-3 — the v10.4.1 re-entry is retracted):
  the packet continues the HIT branch on the retained lookup
  (`session_glue/mod.rs:1194-1196`); install/publication/Open/seed/
  cache all happen on the next packet's clean-miss dispatch with a
  fresh derivation (master's two-packet shape exactly).
- Expiry/HA: the probation deadline fence (v10.6.0, round-89 Codex 3 —
  §5.6) touches `expire.rs`'s retention gate (probation bypass) and
  `refresh_for_ha_transition` (deadline preserved); companion
  propagation skips probation targets (v10.7.0, round-90 Codex 4) and
  the accepted-mark rule skips a probation MATCHED entry (v10.8.0,
  round-91 Codex 3).
- `retry_pending_neigh` is **UNCHANGED** (master's buffered-decision
  transmit; the v10.1 re-resolve/hold design is retracted, §5.2). A
  buffered packet never runs the anchor hook, the promote, or the
  probation clear (no `SessionTable` on the retry path — the next
  unbuffered packet does all three).
- **MissingNeighbor dispatch typed outcomes (v10.4.1, rounds 83-87
  Codex):** the
  disposition arm branches
  AT THE ARM HEAD on the resolve outcome — `ExistingResolved` (a live
  local or shared resolve-time entry backs the resolve: buffer with the
  resolver's stored decision; no seed-only NAT/NPT derivation or
  allocation, metadata, counters, install, rollback, or publication
  runs),
  `ResolvedWithoutLocalBacking` is RETRACTED as a distinct outcome
  (v10.11.0, round-94 Codex 1-3): master's resolve keeps the purged
  packet in the HIT branch on the retained lookup
  (`session_glue/mod.rs:1194-1196`), and this plan dispatches it
  byte-identically — the packet continues with the retained decision
  and reaches this arm, if the next hop is cold, as
  `ExistingResolved`-with-retained-decision (buffer only, nothing
  else); the install/Open/seed all happen on a LATER packet's genuine
  clean miss with a fresh current-config derivation. Only NON-closing
  packets ever take the purge — the transient-purge gate is
  close-aware (v10.8.0): a closing packet keeps the shared backing and
  takes the `ExistingResolved` outcome (buffer with the resolver's
  stored decision; no derivation, allocation, rollback, install,
  publication, or emission),
  `SeedInstalled` (genuine miss: today's full seed transaction),
  `SeedRefused` (miss refused: today's drop). Mechanically the resolve
  layer returns the provenance alongside the decision (including the
  purge flag); the arm's seed-only block is skipped wholesale only for
  `ExistingResolved`.
- **The seed lifecycle is UNCHANGED from master (v10.4.0 — the second
  retreat):** no origin flip, no flip-time `session_limit_inc`, no
  flip-time Open, no `session_id`-guarded alias cleanup. The
  pre-existing seed-class gaps are documented (§7 emission carve-out,
  §7 races (e)-(g)) and their completion is a §10.6.2 follow-up with
  the round-86 design notes.
- **`ForwardSessionMatch` scope + identity (v10.2.0, round-84 Codex
  4):** the type gains `scope: Local | Shared` and the identity
  (canonical key + NAT decision) it was found under; site-2b validation
  and anchor re-probe require Local scope AND identity agreement
  (§5.6).
- **Probation local-only reap (v10.1.0, round-83 Codex 2 — confirmed
  RESOLVED at round 84):** `ExpiredSession` carries the probation flag;
  a probation expiry skips the NAT release
  (`worker/loop_body/mod.rs:1491-1504`) and the BPF session-map
  family-key delete (`bpf_map/mod.rs:633, :704`), removing only the
  worker's local table entry.
- The `promote_from_reverse` in-borrow established-promote becomes
  post-borrow and proof-gated; `maybe_promote_synced_session` skips
  closing-flagged packets wholesale and probation entries until cleared.
- Worker stats: `tcp_close_seq_rejected: u64` exported through the
  ordinary worker statistics surface.

Go changes: exactly one additive decode field for the counter in the
worker-status path (the `screen_reason_drops` pattern — Rust exports,
`BindingStatus` decodes, the manager aggregates; optionally surfaced in
`show` output). No HA session-sync wire change. No schema change. No
gRPC/REST/CLI grammar change.

---

## 6. Public API preservation

No public API exists to preserve: `SessionTable`, `account_packet`,
`lookup_with_origin`, `update_session`, `install_with_protocol_with_origin`,
`FlowCacheEntry` are all `pub(crate)`/`pub(super)`. gRPC/REST/CLI surfaces
unchanged apart from one additive worker-status counter field (the
`screen_reason_drops` decode pattern, §5.8). **HA sync wire UNCHANGED** —
the gate adds no wire field, no identity tail, no capability negotiation; a mixed-version pair behaves
exactly as a same-version pair (a pre-upgrade node simply keeps master's
demote behavior for its own table). `UserspaceDpMeta` and the XDP shim are
untouched.

---

## 7. Hidden invariants the change must preserve

- **Anchor single-store invariant:** only the canonical forward entry
  carries an anchor; every update goes through the per-disposition commit
  hooks (+install seeds); every validation reads the same store
  (`lookup_with_origin` validates/marks only — never updates). No second
  store, no merge.
- **Trust invariant:** a close validates only against TRUSTED state —
  tracked anchor legs (rule 1 legs 1-2) or the close's own ack field
  against a trusted opposite seq (leg 3). Trust is born ONLY at
  `(FreshPrimary)` install seeds, per-field proofs against trusted state,
  or the strong OPENING handshake proof; trusted sides advance on their
  own continuity gate. Untrusted sides never confer trust, are never
  blessed by later proofs (replacement, not max-merge), and never
  validate a close. No-baseline ⇒ refuse-demote, everywhere (hit path,
  promote, materialize, synth, missing-forward). **Closing packets never
  promote** (neither `established` nor the `SharedPromote` ownership
  flip), so no Close authority can be armed by a refused (out-of-window
  or no-baseline) close. **Family-generation identity (v10.3.0):** a
  reverse-hit close additionally requires the re-probed forward entry to
  reciprocate the matched reverse entry's `(key, nat)` family (§5.5) —
  a separated/orphan reverse (`NAT1 ≠ NAT2` after a forward
  replacement) never validates, never marks, never propagates; a
  site-2b validation requires a Local-scope match with key+NAT identity
  agreement (§5.6) — no close can validate against, mark, or propagate
  to a DIFFERENT flow generation anywhere.
- **Pre-packet validation:** a closing segment never updates the anchor
  (rule 1), never promotes (rule 5), and on refuse mutates nothing at all.
- **Plausibility-gated slides:** the anchor cannot jump more than
  `FWD_SLACK` per accepted sample; seq slides require `seg_len > 0`; ack
  slides require `has_ack`; a `const _` assert pins each leg's interval
  under 2^31.
- **Stickiness contracts:** `closing` (#3489), `reset` (#3046),
  `established` (#3152) remain monotone within an entry's life; the gate
  only withholds a mark, never clears one. The #3046 timeout-selection
  ordering (`reset` set before `expires_after_ns` is chosen) is preserved
  on the accepted-mark path.
- **HA replica no-Close invariant (LOAD-BEARING, restated for v10):**
  master's emission gate (`expire.rs:342-350`: non-peer-synced,
  non-reverse, non-transient-seed) is UNCHANGED. Peer-synced entries
  (`SharedMaterialize`/`SyncImport`/`WorkerLocalImport`,
  `entry.rs:245-250`) cannot emit at all; under the refuse-demote flip a
  blind close can never mark them anyway, and rule 5 keeps a blind close
  from flipping their origin. The Go side has NO origin/generation
  protection that would save the owner (stamped deletes apply,
  `sync_conn_gen.go:493-506`; gen-zero fallback deletes apply
  unconditionally, :176-186), so master's Rust gate plus this plan's
  refuse-demote flip plus rule 5 are the barriers between a
  non-owner/unvalidated reap and the owner's authoritative entry; a
  refused close never crosses them, while an in-window blind guess
  validates by design at the documented window probability. Regression
  tests: `SharedMaterialize + reset + FabricRedirect + reap` → no delta,
  no owner/shared deletion; blind first-packet close on a promotable
  import → no mark, no promote, no delta.
- **Emission completeness (the zero-producer rules):** an ACCEPTED close
  always leaves exactly one PROMPT MARKED emitting entry (v10.10.0
  scoping, round-93 Codex 5 — the same-node cross-worker `SharedPromote`
  copy is a second LEGITIMATE emitter on master and v10 alike until the
  delete fan-out removes it, §5.6; the invariant here is about the marked
  producer): the hit-path accept marks the
  matched entry and propagates to the reciprocated companion (#4109,
  target-reciprocity-gated, §5.5); the reverse-synth accept marks the
  forward family at resolve
  (§5.6) so the owner's forward entry emits at its 2 s reap; **and no
  dispatch path can replace a live/marked entry with a transient seed
  (the site-9 typed-outcome gate, §3/§5.8) — the accepted close's sole
  producer survives to its reap**; a refused
  close leaves no mark anywhere, so master's ordinary-timeout emission
  semantics apply unchanged (locally-born entries emit at natural reap;
  unmarked import-class reaps stay silent exactly as master). **Carve-out
  (pre-existing, master-parity — v10.4.0):** an accepted close whose
  mark lands on a transient `MissingNeighborSeed` — the hit path's
  matched entry, or the reverse-synth accept's forward family — reaps
  at 2 s with NO Close delta (`expire.rs:342-350`'s transient-seed
  exclusion — master's exact behavior for this class). The carve-out is
  HA-safe by construction: seeds emit no Open, so no HA peer copy exists
  to orphan; the residue is process-local (the install-published
  shared/DNAT aliases linger past the seed's NAT release — the
  pre-existing stale-alias trace, §7 race (f), §10.6.2 follow-up). A
  peer-validated close's mark survives on the peer's own entries (the
  peer marked before reaping and emitting); the Phase-1 residual — an
  accepted close immediately followed by failover and full reimport
  before the 2 s reap loses the prompt delete and RT_FLOW close record
  (reimport hardcodes `tcp_flags: 0`,
  `server/helpers/session_sync.rs:168`) — is a telemetry/hygiene
  degradation only: the entries idle out naturally, delivery unaffected;
  the wire-carried mark is Phase-2 scope (§10.5).
- **Reap-side locality (v10.1.0, round-83 Codex 2 — confirmed RESOLVED
  at rounds 84/85/86):** a probation entry's expiry is
  local-only (§5.6/§5.8): no NAT release, no BPF family-key delete, no
  delta. The global cleanup of a flow's NAT reservation and BPF keys
  happens at the owner/live entry's own reap — the authoritative
  cleanup event for the family (master's unrefcounted sibling cleanup
  calls are the pre-existing #6522 class, §10.6.1) — and the probation
  constructor must not multiply its trigger rate.
- **Probation deadline integrity (v10.7.0, rounds 89-90 Codex):** a
  probation entry's immutable deadline is preserved end-to-end — the
  in-borrow lookup and `touch_if_stale` skip the refresh (v10.5.0), a
  pre-admission re-materialize adopts the shared S2 while preserving
  only the deadline/flag (no clock restart, no decision split-brain),
  the expire-time standby retention gate (SelfHeal/Hold/
  companion-freshness) is bypassed at the deadline, companion
  propagation skips probation targets wholesale (no mark, no restamp),
  and `refresh_for_ha_transition` never restamps it. No packet,
  materialize, propagation, retention path, or HA transition can extend
  or reset the ≤20 s clock. Probation entries are only ever created by
  the site-2c materialize-refuse (borrowed-replica class — the
  no-release/no-delete local reap is sound because the copy owns no
  reservation); the v10.6.0/v10.7.0 RWoLB/ReplacedSyncedLocal
  constructor shapes are retracted — a closing packet under peer-synced
  provenance never purges, never displaces, and never installs (§5.6
  site-3 supplement), so no probation entry
  ever holds an owned allocation and no no-Open probation entry ever
  exists to clear into a generation-zero Close
  (`sync_conn_gen.go:176`/`:263`). And a probation entry is never
  marked or restamped — not by the lookup/cache paths (v10.5.0), not by
  re-materialization (adopt-preserve with the min() absolute deadline),
  not by retention or HA transitions (v10.6.0), not as a propagation
  target (v10.7.0), and not as the MATCHED entry of an accepted close
  (v10.8.0, round-91 Codex 3).
- **Hot-path discipline:** zero new allocations; zero new atomics; the
  per-TCP-data-packet cost at the commit-arm anchor hook (a DISTINCT
  final-admission apply point from the pre-admission #2501 accounting
  call, §5.2) is one
  8-byte read + ≤2 gated stores; closing segments add one table probe on a
  path that already takes the full slow path. `SessionEntry` grows 40 B
  (+1 B probation) — slab is uniform, UDP/ICMP entries carry it unused.
- **Borrow shape:** close-path validation and marking happen post-borrow in
  the existing propagation phase; no new cross-`&mut` aliasing; the
  non-close path's borrow structure is byte-identical for NON-PROBATION
  entries (probation entries skip the in-borrow refresh/recompute/wheel
  and take the deferred-refresh commit-hook path, §5.6).
- **GRE/frame identity:** all frame reads use the ACTIVE `packet_frame`;
  seg_len from IP-declared lengths with frame clamping.
- **Fragments:** non-first fragments stay flowless (#2344); the helper
  returns None for them defensively.
- **Coverage residuals (documented):**
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
  - **fabric-return reverse seeds** (branch-base class, removed on master
    by #6478 — §3.1) bypass the commit hooks; a later
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
    §10.5 wire-anchor follow-up covers it.
  - **Transient-purge/Open provenance-integrity class (v10.9.0,
    round-92 Codex 1 — PRE-EXISTING, re-scoped):** a spoofed NON-close
    first packet (e.g. a SYN with the victim's translated 5-tuple) on
    the non-owner node takes master's unchanged purge-then-later-miss path:
    `purge_translated_synced_hit` destroys the shared entry/P1
    reservation/aliases (`promote.rs:167-207`, `shared_ops.rs:960`),
    the purged packet itself forwards with the RETAINED lookup decision
    (`session_glue/mod.rs:1194-1196`), and the LATER clean-miss packet
    installs a fresh `ForwardFlow` with a new
    translation and emits an identity-less Open
    (`install.rs:234`; fresh generation, `sync_conn_write.go:53`), and
    the peer's latest-generation-wins upsert overwrites the victim's
    authoritative family (`sync_conn_gen.go:435`,
    `session_store.go:257`). This is master's behavior verbatim, and
    v10.11.0 retracts the plan's one divergence: the v10.4.1
    same-dispatch re-entry had collapsed the class from two packets to
    one (round-93 Codex 1) — with the retraction the plan is
    packet-for-packet master-identical here, and the v10.8.0
    close-aware gate neither widens nor narrows it. It is NOT the issue's
    blind-close class: the driving packet carries no closing flags, no
    demote gate can see it, and no sequence validation applies to a SYN
    (a SYN is the sequence bootstrap — the attacker legitimately knows
    the state it just seeded; anti-spoof/ingress filtering is the
    classical mitigation, and the sync-layer fix is identity-carrying
    deltas, the Phase-2 §10.5 territory). Once the sync-integrity class
    is fixed, the gate composes correctly: the attacker-crafted flow's
    own teardown kills only the attacker's own seeded state. Filed as
    #6599 (§10.6.2).
  - **Import-window reservation race (v10.9.0, round-92 Codex 2 —
    PRE-EXISTING):** the HA import publishes the shared entry before
    the worker command reserves P1 (`session_import.rs:115`/`:215` →
    `upsert_synced.rs:64`/`:80`), and workers can poll packets with an
    empty command queue (`loop_body/mod.rs:682`/`:887`); in that window
    another local flow can allocate P1 and the later reservation
    refuses to steal it without propagating failure
    (`allocator.rs:1636`/`:1682`). The exposure is shared by EVERY
    packet forwarded on a shared-backed decision in that window on
    master today (data packets included); the v10.8.0 buffered close
    inherits exactly that pre-existing exposure and adds none. Filed as
    #6600. Interaction stated whole (round-93 Codex 2 + round-94 Codex
    4/6): master's flag-agnostic purge self-cleans a conflicted row on
    ANY packet, while the close-aware gate retains such a row for
    closing packets until the first NON-close packet or expiry — a
    bounded retention extension inside an already-broken pre-existing
    state; the v10.10.0 attempt to condition retention on a recorded
    reservation-success bit was retracted because a cached bit cannot
    track later ownership loss (single shared token, idempotent
    same-flow reservations, unrefcounted sibling release —
    `allocator.rs:1664-1674`, `worker/loop_body/mod.rs:1490-1505`) and
    its purge fallback would have dropped bare closes master delivers
    (round-94 Codex 1). The exact holder fence is #6522/#6600 scope.
- **Split-direction steering (quantified and adjudicated):** the shim
  steers by physical RX queue (`userspace-xdp/lib.rs:1460`); with
  non-symmetric hashing ~1−1/N of flows split (~83% at 6 queues), each
  direction consistently on its own worker. The precise consequence,
  verified against master: a reverse-direction close lands on the
  reverse-observing worker B, whose canonical forward copy is a
  `WorkerLocalImport` replica. **On master, B's mark propagates only
  within B's local table (`mod.rs:1232-1278`) and never reaches worker
  A's authoritative entry, and B's replica/synth entries are
  peer-synced/is_reverse — silent reaps with NO delta — so master ALSO
  cannot demote the authoritative state from B; A's entry idles out on
  its ordinary timeout, and a blind reverse close on B kills only B's
  2 s re-synthesizable caches (toothless).** Under this plan, B's replica
  anchor is untrusted (Phase 1) → the reverse close soft-refuses → B's
  replica stays fresh — ≈ master's outcome for the flow (A idles out
  identically) and strictly better for B (no 2 s replica churn).
  Forward-direction closes land on A (full anchor → validated). **So the
  split class is master-parity in Phase 1, not a new residual.** Phase 2
  repairs B properly (§10.5).
- **LocalDelivery replies** leave via kernel TX and never traverse AF_XDP;
  the anchor for a firewall-originated flow's outbound direction is pinned
  by the inbound ACK stream (cross-direction leg) — the attack-relevant
  inbound direction is fully tracked.
- **Documented pre-existing races (not widened by this plan; owned by
  §10.6):** (a) the publish-before-command demotion ordering (the loop
  publishes binding state before applying queued coordinator commands,
  `worker/loop_body/mod.rs:678-690`) can emit an old-owner
  Close during the retag window — master has this race today; the gate
  neither widens nor narrows it; (b) a stale queued Close delta can
  key-delete a reinstalled same-key replacement entry (the delta
  application is not identity-fenced) — pre-existing; the gate REDUCES
  Close-delta volume (refused closes emit nothing) and never creates new
  delta classes; (c) #6522, the unconditional NAT release at reap
  (`worker/loop_body/mod.rs:1491-1498` → `nat/allocator.rs:1318`
  `release_flow` — no replica refcount) — pre-existing, verified, own
  issue (§10.6.1); **(d) the pending-neighbor buffered stale-decision
  transmit window (v10.2.0, stated):** master's retry transmits the
  buffered NAT/egress decision even when the entry expired or was
  transient-purged (`promote.rs:167`) during the ARP wait — including
  an admitted close, which master DELIVERS; this plan preserves master's
  retry byte-for-byte (the v7.5-era never-transmit-stale hardening is a
  follow-up candidate, §10.6.2 — the round-84 review sketched its
  correct typed-outcome shape, and the v10.1 attempt at it here
  generated four BLOCKERs of local machinery for zero gate benefit);
  **(e) the transient-seed zero-producer (v10.4.0, stated):** an
  accepted close whose mark lands on a `MissingNeighborSeed` (the hit
  path's matched entry, or the reverse-synth accept's forward family)
  reaps at 2 s with NO Close delta — master's exact behavior
  (`expire.rs:342-350`'s exclusion); HA-safe by construction (seeds
  emit no Open → no peer copy exists to orphan); **(f) the stale-alias
  trace:** a seed's reap releases its NAT (the unconditional cleanup,
  §10.6.1's #6522 class) but never removes the install-published
  shared/DNAT aliases (`poll_descriptor/mod.rs:4823, :4879`) — a stale
  shared seed can later be materialized with a released/reassigned
  translation, on master today; **(g) the stub-metadata gap:** a
  seed-born flow keeps the `build_missing_neighbor_session_metadata`
  stub (policy 0, logging false, `inactivity_timeout_ns=None`,
  `neighbor_dispatch.rs:606`) for its whole life on master — a per-app
  flow admitted at 3600 s still reaps at the global 300 s. (e)-(g) are
  PRE-EXISTING, outside this issue's blast radius; their completion is
  the §10.6.2 follow-up with the round-86 design notes.

---

## 8. Risk assessment

| Class | Verdict | Notes |
|---|---|---|
| Behavioral regression | MED | Gate only withholds demotion, never blocks delivery; refuse on missing/untrusted baseline. Residuals (stated in §2/§5.2/§7): soft-refused legit close after unobserved stretches or both-direction path switches → entry idles ≤ established timeout; imported entries never validate closes until churn (bounded lingering; §10.5 wire-anchor restores); tuple stays busy meanwhile — pre-existing semantics for silently-dead flows. Restart-RST covered by the union rule. OPENING covered by SEG.LEN-aware ack check against the FORWARD entry's state. |
| Lifetime / borrow-checker | LOW | Anchor is `Copy` POD on an existing entry; marking restructured into the existing post-borrow propagation phase; no new cross-boundary borrows. |
| Performance regression | LOW-MED | ~41 B/entry slab growth (~5.4 MiB/worker at cap); one TCP-header view compute (seq/ack/wnd/flags/seg_len) + ≤2 gated stores per committed TCP data packet (closing segments skip updates entirely); one extra probe per closing segment. Must be measured at minimum-frame rates (§9) — the 23 Gbit/s MTU-sized iperf run alone is insufficient (≈37 Mpps at 25 Gbit/s small-frame is the real gate; `iperf3 -l 64` is a proxy, not a demonstrated line-rate generator — gate on pps, not bandwidth). |
| Architectural mismatch | LOW | No new subsystem; anchors at the existing #2501/#3706 chokepoints; #4400-style always-on gate. No pipeline restructure. No distributed protocol. |
| HA / rolling upgrade | LOW | No wire change; mixed-version pair behaves as same-version (a pre-upgrade node keeps master's demote behavior for its own table; the upgraded node simply refuses blind demotes on its own). Pre-upgrade and imported entries sit in the absorbing zero-trust state — closes refuse until churn (strictly more conservative than master; bounded lingering, §2; Phase 2 §10.5 closes it for synced flows). The replica no-Close invariant + the SharedPromote refuse trace are regression-tested. |
| Pending-neighbor behavior | LOW | Master's buffered-decision retry is UNCHANGED (v10.2.0 retreat): no re-resolution, no hold, no new drop class, no stale-transmit change — the admitted-close delivery is master-parity, and the pre-existing stale-decision window is documented (§7 race d, follow-up §10.6.2). Buffered packets never move the anchor — a fail-toward-refuse residual (anchors lag behind long ARP stalls; closes soft-refuse; entries idle out normally), never a walk/poison channel. |
| Dispatch-path provenance | LOW-MED | The MissingNeighbor arm branches on typed resolve outcomes at the arm head (round-83 Codex 1 + round-84 Codex 1): `ExistingResolved` preserves the resolver decision and allocator state exactly (no seed-only work runs); `SeedInstalled`/`SeedRefused` are today's miss paths. Risk is confined to the hit-with-cold-neighbor corner (previously the live entry was replaced by a raw-flags seed — master's unguarded demote path); unit-tested for refused and accepted closes and for the no-allocation-leak case. |
| Probation reap locality | LOW | A probation expiry is local-only (round-83 Codex 2): no NAT release, no BPF family-key delete. Strictly safer than master's born-dying materialized copy (which runs the full cleanup at 2 s — the #6522 class); the owner entry's own reap is the family's authoritative cleanup event. |
| Seed class | LOW | Master's seed lifecycle is UNCHANGED (v10.4.0 — the second retreat): no flip, no flip-time accounting, no id-guarded cleanup. The zero-producer transient-seed case is HA-safe by construction (no peer copy exists); the stale-alias and stub-metadata gaps are pre-existing master behavior, documented (§7 races e-g) with a §10.6.2 completion follow-up. |
| Merge collision | LOW | No `FlowCacheEntry` change. The anchor apply hooks are local to the commit arms; `SessionInstall`/`SessionUpdate` gains are crate-internal. |

---

## 9. Test plan

Unit (cargo) — all close-placement cases use DETERMINISTIC in/out-of-window
values (probabilistic sprays can legitimately hit the admitted interval):

- **Validator truth table:** ESTABLISHED fresh trusted anchor (accept
  in-window RST/FIN; refuse low/high out-of-window; refuse far-future),
  the union leg (restart-RST `SEQ=SEG.ACK` accepted via trusted
  `ack_hi(O)` when `seq_hi(D)` refuses), the own-ack leg (FIN+ACK and
  SO_LINGER(0) RST+ACK accepted via leg 3 with legs 1-2 untrusted; bare
  no-ACK RST with no trusted seq side soft-refuses), serial-wrap edges
  (anchor near 2^32−1, `wrapping_sub` membership, no panic — tracker
  serial-max wrap tested separately from validator membership wrap),
  OPENING (`ack ∈ [isn+1, isn+SEG.LEN]` accept incl. TFO partial-ack at
  both interval ends, `isn` refuse, `isn+SEG.LEN+1` refuse, `seq=0` RST
  refuse when `open_valid` unset, self-abort `seq ∈ [isn+1, isn+SEG.LEN]`
  accept, untrusted-baseline refuse, **mixed trusted-forward /
  untrusted-reverse OPENING entry validates only the trusted side
  (round-83 Codex 5)**), asymmetric (only one direction
  observed/trusted), missing/untrusted baseline → refuse (NEVER
  fail-open). The compile-time leg asserts (§5.4 rule 4) exist and the
  union arithmetic in §2 is re-derived in a test comment.
- **Anchor update rules:** closing segments never update (rule 1);
  seq slides require `seg_len > 0` and the serial-max gate (rule 2);
  ack slides require `has_ack` and the per-stream slack (rule 3);
  SYN-retransmit cannot demote a trusted seed (transaction rule iii);
  `wnd` updates only from proving/trusted segments (rule v); proving
  sample REPLACES untrusted state, never max-merges (rule i); trusted
  self-slide advances within FWD_SLACK without cross-proof (continuity
  gate); a segment never widens the window used to prove itself
  (pre-packet `wnd`).
- **Provenance matrix:** primary miss install self-authenticates
  (SYN/pickup seeds trusted, seq side only); `ReplacedSyncedLocal` adopts
  untrusted only (mandatory replacement-branch test); materialize/import/
  reverse-synth/tunnel-refresh NEVER self-authenticate (the fabric-seed
  row of this matrix is branch-base-only — #6478 deleted that
  constructor on master, §3.1, round-93 Codex 6) — a
  non-close attacker packet materializing a shared victim plants only
  untrusted state, a following close refuses, and the UNPROMOTED entry
  emits NO Close delta on its ordinary reap (peer-synced origin). (A
  later committed non-close packet may promote it; the then-promoted
  entry's natural reap DOES emit Close — correct owner semantics.)
- **Strong OPENING proof:** exact-interval SYN-ACK authenticates the whole
  segment (both sides trusted) and drives the establishment promote;
  windowed-but-not-exact SYN-ACK does NOT; TFO partial-ack at either
  interval end proves; the proof endpoints are immutable (a later
  in-window slide does not move them).
- **Closing-never-promote:** a SYN-ACK+RST neither establishes in-borrow
  nor ownership-promotes; an unproven SYN-ACK does not pin a half-open
  entry into the established window; a closing-flagged packet never
  reaches `update_session` (rule 5) — no origin flip, no Open delta, no
  refresh.
- **Commit-point:** an in-window precursor that is input-filter-dropped,
  TTL-expired, output-filter/CoS-dropped, or `push_redirect_inbox`
  capacity-discarded does NOT move the anchor (the endpoint's next legit
  close still validates); selective no-learn arms (NoRoute /
  NextTableUnsupported / MissingNeighbor reinjection / ForwardCandidate
  build-failure) skip updates; a COMMITTED packet updates exactly once.
- **Constructor gating:** site 2b accept → companion installed with the
  seed AND the forward family marked atomically (exactly one producer;
  #4380 retention semantics asserted, not an idealized 2 s whole-flow
  reap); site 2b refuse → NO install (`created=false,
  install_failed=true`, no cache insert, packet still forwarded, next
  reply re-synthesizes and revalidates); site 2c refuse → install ALIVE
  at the probation timeout with `closing=false, reset=false`; site 2c
  with a non-close attacker packet → untrusted samples only.
- **Materialize preservation + retention fence (v10.7.0, rounds 89-90
  Codex):** (a) with a probation entry K installed (refused-close
  materialize), a second packet that reaches
  `materialize_shared_session_hit` for the same canonical key BEFORE
  any admission (placeholder/shared coexistence per
  `session_glue/tests.rs:704`) — the upsert ADOPTS the shared S2
  decision/metadata wholesale while K's immutable deadline, probation
  flag, and alive flags carry over: assert the entry's decision and
  metadata equal S2's (no S1/S2 split-brain — include a fixture where
  S2's `ForwardingResolution`/metadata differ from K's), assert the
  absolute deadline is `min(K's preserved deadline, now + S2's own
  candidate)` in the §5.6 encoding (`last_seen_ns = now_ns`,
  `expires_after_ns = D.saturating_sub(now_ns)`, wheel sum re-derives
  D) — cover BOTH K-wins and S2-wins fixtures (round-92 Codex 3); the
  OVERDUE-K fixture (D ≤ now at adopt time): S2's decision/metadata is
  adopted IN PLACE (assert the entry equals S2 — no S1 residue,
  round-94 Codex 5), K's `last_seen_ns`/`expires_after_ns` are
  preserved VERBATIM, NO wheel re-queue runs, and K reaps on its
  existing wheel slot at the next GC pass even under one-adopt-per-tick
  pressure ahead of the phase-shifted GC (round-93 Codex 3's pin
  trace); and
  assert
  repetition across 3× the probation window never extends the clock;
  a non-probation existing entry takes master's
  unconditional upsert; (b) a probation entry at its deadline with a
  LIVE companion and an HA-active posture: the standby retention gate
  does NOT SelfHeal-restamp, Hold-rebucket, or companion-retain it —
  the local-only removal runs (assert no `continue` is taken at
  `expire.rs:168`'s gate for probation entries); (c)
  `refresh_for_ha_transition` (owner-RG refresh AND demotion) leaves a
  probation entry's deadline unchanged (no `last_seen_ns` restamp, no
  timeout recompute); (d) an accepted close on the live half F with a
  probation companion R: `propagate_tcp_state_to_companion` skips R
  wholesale — no mark, no restamp, no recompute, no re-queue — and
  repeated accepted closes never move R's deadline (round-90 Codex 4);
  (e) the mirrored direction: an accepted close whose MATCHED entry is
  the probation row R (validated against the live forward family's
  anchor) skips the matched-entry mark/restamp/recompute/re-queue on R
  while the propagation marks the live F normally (round-91 Codex 3).
- **Peer-synced-provenance close inertness (v10.8.0, rounds 89-91
  Codex):** (a) a SYN|RST/SYN|FIN packet whose resolve matches a
  peer-synced translated-forward entry: the transient purge NEVER runs
  (the shared entry, the P1 reservation, and the shared aliases are
  unchanged after the dispatch — the byte-identity claim is scoped to
  the purge-target state; a buffered close never reaches
  `account_packet`, and any accounting-field advance on an unrelated
  live local row is master's own behavior, round-92 Codex 4), NO fresh derivation
  reaches the allocator (counters AND live-ownership/used-port gauges
  all bit-identical — possible because nothing is derived at all, so
  the round-91 Codex 5 monotonic-counter impossibility does not
  arise), NO install/publication/Open, the packet buffers with the
  resolver's stored decision and transmits on resolution with the
  victim's own P1 SUBJECT TO the pending-neighbor admission/timeout
  rules (duplicate-drop keeps the oldest, capacity is bounded at 4096
  next hops, and the stale-buffer drop fires at the ~2 s neighbor
  timeout — `afxdp/mod.rs:418`, `neighbor_dispatch.rs:187`; a dropped
  buffer is delivery-parity with master's cold-neighbor drops, not a
  new blackhole); a SECOND closing packet is equally inert
  (provenance survives — no one-shot destruction). Retention requires
  a SUCCEEDED synced reservation (v10.10.0, round-93 Codex 2): the
  retention is unconditional (v10.11.0 — the v10.10.0
  reservation-success condition is retracted: a cached bit is not a
  live ownership fence, round-94 Codex 4/6, and the purge fallback
  would have dropped bare closes master delivers, round-94 Codex 1;
  the §7 #6600 residual documents the bounded interaction); (b)
  `ReplacedSyncedLocal` with a SYN|close: `take_synced_local` never
  runs (the synced victim survives), no install, packet delivered
  locally; (c) the follow-up NON-close packets on the same tuple
  dispatch MASTER-VERBATIM (v10.11.0): the FIRST purges and forwards
  with the retained lookup (no derivation/allocation/install/
  publication/seed/cache beyond master's own); the SECOND resolves as a
  genuine clean miss and installs with Open exactly as master
  (packet-count parity — the #6599 class stays at two packets, never
  one; no zero-producer); (d) no entry of any kind is created by
  (a)/(b), so no clear can ever emit a generation-zero Close (the
  round-90 Codex 2 trace stays dead by construction).
- **Probation two-branch (both directions, all drop classes — v10.5.0,
  round-88 Codex 1):** (a) a blind non-close
  packet that is FILTERED (input), TTL-dropped, output-filter/CoS-
  dropped, redirect-inbox capacity-discarded, or cache-tail-dropped:
  probation untouched — no clear, NO REFRESH (the in-borrow lookup
  skips the `last_seen_ns` stamp / `expires_after_ns` recompute / wheel
  push for probation entries; `touch_if_stale` skips them too), no
  Open, no replication — the ≤20 s clock is NEVER extended by an
  uncommitted packet, so repeated blind packets cannot pin the zombie
  (the admission-ceiling pressure bound: pinned zombies age out on the
  unextended clock; synced-upsert cap bypass at `install.rs:294` vs
  fresh-install refusal at `install.rs:113` asserted in the test); (b)
  a blind non-close that COMMITS:
  probation clears exactly once AT THE MATCHED ENTRY (forward-key AND
  reverse-key materialized entries each covered — the clear is not
  routed through the anchor's forward hop) AND the ordinary established
  refresh (stamp + recompute + wheel push) lands in the same write at
  the commit hook, at most one
  promote/Open/replication, and subsequent hits do NOT re-promote; no
  accelerated reap and no close mark in either branch; zombie reap at
  ≤20 s (and never beyond the imported entry's own shorter per-app
  timeout) is silent (peer-synced origin, unmarked).
- **Refused-close inertness:** no mark, no `last_seen_ns` refresh, no
  wheel re-queue, `tcp_close_seq_rejected` bumps; the entry's
  pre-refusal expiry trajectory is bit-identical.
- **Pending-neighbor (v10.2.0 posture):** master's buffered-decision
  retry is byte-identical (an admitted close transmits on the buffered
  decision even after an interim expiry — delivery parity); a buffered
  packet NEVER moves the anchor, NEVER drives the establishment promote,
  NEVER clears probation (the next unbuffered packet does all three);
  a buffered SYN-ACK delivering without its promote leaves the entry
  OPENING exactly as master (20 s window if no further packet).
- **Site-9 typed outcomes (round-83 Codex 1 + round-84 Codex 1 +
  round-85 Codex 1):**
  (a) `ExistingResolved` on a validator-REFUSED close with a cold next
  hop: NO seed transaction — assert no NAT/NPT derivation ran (no
  `live_by_flow` allocation leak, `nat/source.rs:1548`), no metadata/
  counters/install/publication, the live entry survives unmarked, the
  packet buffers with the resolver's stored decision; (b)
  `ExistingResolved` on an ACCEPTED marked close: the marked entry is
  never replaced, the sole producer survives to its 2 s reap and emits
  exactly one Close delta (or zero when the marked entry is a transient
  `MissingNeighborSeed` — the `is_transient_local_seed` emission gate,
  `expire.rs:342`, per the seed-class bullet below); (c) the purged
  class is MASTER-VERBATIM (v10.11.0 — the RWoLB re-entry is
  retracted): the purged packet continues the HIT-branch dispatch on
  the retained lookup (`session_glue/mod.rs:1194-1196`) — assert NO
  derivation, NO allocation, NO install, NO publication, NO seed, and
  NO flow-cache mutation beyond master's own cache behavior for the
  retained dispatch (`poll_descriptor/mod.rs:3856-3960`); if the next
  hop is cold the packet buffers as
  `ExistingResolved`-with-retained-decision (buffer only). The NEXT
  packet's genuine clean-miss dispatch derives fresh and installs/
  seeds with Open exactly as master: `P2 != P1`,
  current-rule-no-longer-matches yields no translation, the DNAT
  same-address port remap (`destination.rs:699`) is preserved by the
  full fresh derivation, the deterministic persistent reacquire
  (`allocator.rs:1265`) still reacquires `P1`, and the capacity
  rollback uses the FRESH `P2` (`poll_descriptor/mod.rs:4890` →
  `nat/source.rs:781`) — the round-86/87 correctness tests all run at
  THIS dispatch, where the install happens; the upstream-equivalence
  assertion is packet-count parity for the #6599 class (two packets,
  never one); (d) a genuine top-level(d) a genuine top-level
  MISS with a bare
  close still drops at the #4400 guard before the arm (`SeedRefused`);
  (e) a miss with SYN|close combo on a genuinely-new tuple still seeds
  from raw flags (`SeedInstalled`, site-3 residual, self-anchoring
  invented tuple) — and the same SYN|close under peer-synced provenance
  never purges (takes the shared-backed `ExistingResolved`: buffered
  with the stored decision, nothing derived/installed/emitted) and
  never displaces a synced local victim (v10.8.0, rounds 89-91 Codex —
  the tuple is a real victim's, not invented);
  (f) a config-update pool-SNAT-matching live no-SNAT flow HIT with a
  cold next hop: `ExistingResolved` — allocator state bit-identical
  (round-84 Codex 1's pool-exhaustion trace).
- **Seed class (v10.4.0 posture):** the seed lifecycle is byte-identical
  to master — an accepted close on a transient `MissingNeighborSeed`
  marks it and reaps it at 2 s with NO Close delta (master parity, no
  HA peer copy exists); a seed expiry releases NAT exactly as master
  (the pre-existing §10.6.1 class) and leaves the install-published
  aliases exactly as master (the pre-existing §7 race (f)); no flip,
  no flip-time `session_limit_inc` (admission behavior unchanged,
  `session_admission.rs:29`), no flip-time Open, no id-guarded cleanup.
- **Propagation target reciprocity (round-86 Codex 5 + round-87 Codex
  3):** an accepted
  forward close whose derived companion slot holds an UNRELATED forward
  B (`is_reverse` false, or key/NAT not reciprocating): B is NOT marked
  (no wrong timeout, no wrong Close, no wrong NAT release, no fan-out);
  A's own mark and emission are unaffected; a reciprocating reverse
  companion is marked exactly as #4109 today; the pre-existing master
  wrong-mark trace is closed by the same rule. **Positive translated-
  family coverage (round-87 Codex 3):** reverse-hit AND forward-hit
  propagation succeed with full key/NAT reciprocity for plain SNAT,
  composed SNAT+DNAT hairpin, NPTv6, and NAT64 families
  (`NatDecision::reverse` + `reverse_session_key` round-trip all four) —
  a raw-NAT equality mistake that would skip a valid translated
  companion fails these tests.
- **The purged class is MASTER-VERBATIM (v10.11.0 — the v10.4.1
  re-entry is retracted, round-94 Codex 1-3):** the purged packet
  continues the HIT-branch dispatch on the retained lookup
  (`session_glue/mod.rs:1194-1196`; no derivation/allocation/install/
  publication/seed/cache beyond master's own); the NEXT packet's
  genuine clean-miss dispatch installs the
  seed/aliases with the OWNED `P2` and later cleanup releases
  `P2` (no collision with `P1`'s new owner, no leak);
  current-rule-no-longer-matches case — no translation; DNAT
  same-address port remap (`K.dst:443 → same-IP:8443`,
  `destination.rs:699`) is preserved by full derivation (never stranded
  on the stored decision's stale value); persistent deterministic
  reacquire (`allocator.rs:1265`) still reacquires `P1` through the
  allocator (the owned path); one decision object across install,
  publication, buffering, replay, and reinjection (no P1/P2 split,
  `poll_descriptor/mod.rs:5126` → `slow_path.rs:199`).
- **Site-2b scope + identity (round-84 Codex 4):** a `Shared` match
  refuses even when the same canonical key is locally occupied; a Local
  match whose re-probed entry disagrees on key or NAT decision refuses
  (the `K/NAT1` shared-alias vs `K/NAT2` local-replacement wrong-flow
  trace); a Local identity-agreeing match validates and marks the
  forward family in the same resolve.
- **Reverse-hit family identity (round-85 Codex 4):** a close
  direct-hitting a separated stale reverse `R1/NAT1` with a replacement
  forward `K/NAT2` present: reciprocity fails (NAT1 ≠ NAT2) →
  REFUSE-DEMOTE — no validation, no mark, no propagation, no Close, no
  fan-out; the orphan reverse ages out `is_reverse`-silent; exact
  tuple+NAT reuse validates (packet-indistinguishable generations need
  no token); a forward-hit close propagates only to the reciprocated
  companion.
- **Probation local-only reap (round-83 Codex 2):** a probation expiry
  removes only the local table entry — assert NO `release_flow` call, NO
  NAT64 release, NO BPF family-key delete, NO delta; the owner/live
  entry's own later reap performs the family's authoritative global
  cleanup; a
  same-node cross-worker live flow's NAT reservation and BPF keys
  survive the zombie's expiry (the #6522-class regression guard for
  this constructor).
- **Emission / HA no-Close invariant:** `SharedMaterialize + reset +
  FabricRedirect + reap` → no delta, no owner/shared deletion; blind
  first-packet close on a promotable import → no mark, no promote, no
  delta, install-alive at probation; accepted hit-path close → exactly
  one Close delta (companion propagation target-reciprocity-gated)
  UNLESS the marked entry is a transient `MissingNeighborSeed` (the
  documented §7 race (e) carve-out: mark lands, 2 s reap, no delta, no
  peer copy exists to orphan); reverse-synth
  accept → forward family marked → forward emits at 2 s (same
  transient-seed carve-out); refused close
  → master's ordinary-timeout emission semantics bit-identical.
- **Observability:** `tcp_close_seq_rejected` visible via the worker
  statistics surface (production build); the rate-limited structured
  record fires at the configured rate cap and never per-packet.
- **Layout:** `size_of::<TcpSeqAnchor>() == 40` compile-time assertion;
  `SessionEntry` growth accounted in the slab sizing comment.

Integration / smoke (loss userspace cluster, `make cluster-deploy` +
`apply-cos-config.sh` baseline):

- iperf3 v4+v6 through the cluster (172.16.80.200 path); mid-stream blind
  out-of-window RST spray at 1,000 pkt/s from an off-path namespace —
  session survives, counter bumps, no Close delta on the peer (`show
  chassis cluster sessions` on the standby retains the flow).
- In-window RST (crafted at the observed seq from an on-path tap in the
  test harness) → normal teardown: 2 s reap, exactly one Close delta,
  standby copy deleted — legitimate-teardown parity with master.
- Legit FIN teardown of an idle SSH flow → accepted via leg 1/leg 3,
  30 s closing window, no regression vs master's teardown timing.
- Failover during a blind spray (`make test-failover` shape): the
  surviving node's imported entries refuse the spray; no standby-copy
  deletion; the flow continues; entries linger to ordinary timeout
  (documented residual, asserted as such).
- SNAT pool-port stability: a SNAT'd flow under blind spray keeps its
  translated source across the spray (no demote → no reap → no re-seed →
  no port swap — the issue's verifier trace inverted into a test).
- Minimum-frame performance gate: small-frame flood (target class
  ≈37 Mpps at 25 Gbit/s; `iperf3 -l 64` as a proxy, gated on pps not
  bandwidth) with and without the gate — per-packet anchor cost measured
  and within the §8 budget.

---

## 10. Out of scope (explicitly)

- Junos general per-packet sequence check (`no-sequence-check` enforcement,
  #2008 M9 / #2078) — the wscale-aware data-plane window check on *every*
  segment. Bigger, throughput-sensitive, asymmetric-routing-hostile;
  separate issue. (Named honestly: xpf lacks this Junos-DEFAULT check;
  this plan closes only the RST/FIN demote DoS.)
- Option B (`rst-sequence-check` drop + challenge-ACK parity) — deferred
  until Option A's anchor accuracy is proven in the field (§4).

### 10.5 Phase 2 (SEPARATE RESEARCH TRACK): HA-wire anchor carriage

Phase 1 (this plan) closes the issue and its HA teeth with no wire change:
a blind close can mark only inside the acceptance window
(~1/2^12–1/2^14 per blind packet), and every mark was validated against
observed flow state — the 1-packet-anytime cluster kill is dead. What
Phase 1 does NOT restore is the 2 s fast-reap for synced flows after
failover — imported entries refuse closes until churn (the §2
absorbing-state residual, bounded, delivery-safe, accepted). Phase 2 —
carrying a trusted anchor on the HA wire so a post-failover node inherits
a validated baseline — is a real protocol in its own right, and six
rounds of hostile review (r6-r12) showed it keeps unfolding: every
transport, freshness, ordering, identity, or ownership-term answer
exposed the next layer. It is therefore split to its own research track:
the accumulated design state and every open protocol question are
collected in `docs/research/6461-blind-rst/phase2-brief.md` (payload
shape, per-direction bundles, coordinator sequencing, owner authority
during overlap, connection/stream readiness, cross-node clock
normalization, wire-mark emission trigger, version namespacing,
capacity/flush accounting — eight open questions, plus the recommended
smaller alternative: owner-side validation only, with post-failover
closes forwarded to the owner for validation instead of importing
anchors). Phase 2 is NOT required for this issue's fix to be correct or
safe; it is an optimization for a bounded residual.

### 10.6 The excised machinery (v9.x → v10 terminal cut) — disposition

Rounds 13–82 built a lifecycle protocol on top of the gate: typed
`DirectHold`/`GroupHold` NAT hold tokens with clone distribution, a
durable coordinator-owned escrow, import-transaction receipts,
RG-incarnation identity tails on session INSTALL/Open AND DELETE, a
capability-negotiated repair/reset protocol (RESET_GEN/RESET_ACK,
RESYNC_REQUEST, JOURNAL_END/JOURNAL_ACK), incarnation-fenced Close
application, predecessor vectors, mint tokens with preflight/promotion
linearization, drain generations with transfer CAS, double-buffered
cohort roots with selector flips, floor sync with digest ACKs, and a
family-clock TTL sweep. Every one of those mechanisms is CUT. Each was
introduced to serve one of the customers below; with the customers
re-scoped, no mechanism has a remaining consumer in this plan. The
review history (rounds 13–82, all findings in this layer) is preserved
on this branch as the design record if any customer is re-attempted.

#### 10.6.1 #6522 — the pre-existing NAT release bug (own issue; NOT shipped here)

Verified on master (round-12 Codex 1): every expired session calls
`release_source_nat_allocation` unconditionally
(`worker/loop_body/mod.rs:1491-1498` → `nat/allocator.rs:1318`
`release_flow`), and the allocation carries NO replica refcount —
locally-born forwards replicate to every sibling worker
(`poll_descriptor/mod.rs:2612, :2918` `replicate_session_upsert`), so an
unobserving sibling's AGE-reap can free the live worker's translated port
on master today. This is a real pre-existing bug with its own tracking
issue (#6522). It is NOT shipped by this plan: the holder-lifetime
machinery the plan grew for it is exactly the protocol that 70 rounds
proved non-convergent in plan-doc form, and the bug is orthogonal to this
issue's gate — Part A creates no replicas, changes no reap/release
ordering, and REDUCES reap rate (refused closes never reap early), so it
neither fixes nor worsens #6522. **Recommendation: drive #6522 as its own
`/engineer` effort with the minimal fix first** (a per-allocation replica
refcount or an owner-only release rule — the refcount is a local
allocator change, not a protocol), pulling from the v9.x design record on
this branch only if the minimal fix proves insufficient.

#### 10.6.2 Pre-existing lifecycle races (follow-up candidates, documented in §7)

- **Transient-purge/Open provenance-integrity (v10.9.0, round-92 Codex
  1):** the non-owner purge path lets a LATER clean-miss packet install
  an identity-less fresh flow and emit a latest-generation-wins Open
  that overwrites the peer's authoritative family — a spoofed non-close
  first packet with the victim's translated tuple drives it on master
  TODAY (no closing flags involved), and v10.11.0 keeps the plan's
  dispatch here packet-for-packet master-identical (the v10.4.1
  same-dispatch re-entry, which had collapsed the class from two
  packets to one, is retracted). The fix is sync-layer identity (fenced
  provenance on Open/Close deltas, or close-aware + provenance-aware
  purge) — Phase-2-adjacent (§10.5) and in any case its own issue;
  this plan's gate neither worsens nor can see the class (the driving
  packet is not a close). Tracked as #6599.
- **Import-window reservation race (v10.9.0, round-92 Codex 2):** the
  shared-publish → worker-upsert → P1-reservation ordering leaves a
  window where a local allocation can claim P1 first; the reservation
  refusal is not propagated. Pre-existing, packet-class-agnostic;
  candidate fix: propagate the reservation failure into the import
  outcome. Tracked as #6600.
- Stale queued Close delta key-deleting a reinstalled same-key entry
  (delta application is not identity-fenced) — pre-existing; Part A
  reduces Close-delta volume and adds no delta classes.
- Old-owner Close emission during the publish-before-command retag
  window — pre-existing; unchanged.
- Ownership promote (`SyncImport`→`SharedPromote`) computed and applied
  at resolve time for non-closing packets, before filter/TTL commit —
  pre-existing master timing; the v9.x commit-arm restructure is cut
  with the machinery (the probation suppression in §5.5 covers the only
  NEW chain this plan would otherwise introduce).
- **Pending-neighbor buffered stale-decision transmit (v10.2.0):**
  master's retry transmits the buffered NAT/egress decision even when
  the entry expired or was transient-purged during the ARP wait
  (`neighbor_dispatch.rs:272, :310, :344, :369`; `promote.rs:167`) —
  pre-existing; this plan preserves master's retry byte-for-byte. The
  never-transmit-stale hardening is the follow-up: the correct shape is
  the typed resolve outcome (`LocalFamily{forward, matched}` /
  `ResolvedWithoutLocalBacking` / genuine miss) plus a family-covering,
  cumulatively-bounded hold that round-84 sketched — NOT the
  v10.1 re-resolve/blanket-hold design, which generated four BLOCKERs
  of local machinery for zero gate benefit.
- **Seed-lifecycle completion (v10.4.0):** the transient-seed
  zero-producer (accepted close marks, 2 s reap, no Close delta —
  HA-safe: no peer copy exists), the stale-alias trace (seed reaps
  never remove the install-published shared/DNAT aliases), and the
  stub-metadata gap (seed-born flows keep policy-0/timeout-None
  metadata for life) are all pre-existing master behavior. Their
  completion is a follow-up effort whose design notes round 86
  produced: count/reserve the admission slot AT seed admission (seed
  removal balancing; delaying only Open emission until confirmation is
  safe — Codex r86 finding 2's prescription); a compare-and-transition
  publication matching session_id + NAT + expected origin before
  arming publication/Open (finding 3); a process-local collision-free
  alias-owner token with serialized conditional publication/deletion —
  `session_id` as allocated today is NOT collision-free cross-node
  (worker/counter namespacing at `session/mod.rs:766`, import-adopted
  ids at `install.rs:324`, bulk-export zero ids at `ha/export.rs:143`)
  and check/delete has no linearization point (`shared_ops.rs:960`,
  `checksum.rs:246`, `xpf_maps.h:508`); zero must mean "no new
  seed-cleanup authority", never unconditional fallback (finding 4);
  and admitted-metadata preservation (or atomic replace-and-recompute
  at confirmation) for the stub-metadata gap (finding 6). The
  v10.2.0/v10.3.0 attempt at the simple version of this completion
  generated all four BLOCKERs — do not retry it without the full
  design.
---

## 11. Open questions for the convergence round (v10.11.0)

1. **The terminal cut itself:** Part A (the gate) + the wire-free
   Part-B rules (closing-never-promote ×2, constructor gating with
   probation + local-only probation reap, normative mark-creation with
   master's emission gate unchanged, the site-9 typed-outcome gate with
   the `ResolvedWithoutLocalBacking` cold/miss re-entry, the 2b
   scope/identity discipline, the
   reverse-hit family reciprocity check, the propagation-target
   reciprocity gate) close the issue and its HA teeth. The machinery is
   cut, not hidden (§10.6); the seed-lifecycle gaps are documented
   pre-existing (§7 races e-g, §10.6.2), not fixed. Is any part of the
   ISSUE's actual harm — firewall-state kill, SNAT mid-flow port swap,
   HA standby propagation — left unaddressed? Trace it, or the cut
   stands.
2. **The two retreats (round-84-accepted, round-86-for-decision):**
   (a) master's buffered-decision retry is byte-identical (round-85
   Codex accepted); (b) the seed lifecycle is byte-identical — no
   flip/Open/id-guarded cleanup; every gap it has is pre-existing on
   master (transient-seed zero-producer is HA-safe by construction: no
   peer copy exists), and the v10.2.0/v10.3.0 completion attempt
   produced round-86's four BLOCKERs (admission bypass, publication
   overwrite, id collisions + TOCTOU, stub metadata) — the same unfold
   pattern as rounds 13-82. Does any reviewer hold that the seed-class
   completion MUST ship in THIS plan despite (i) every gap being
   pre-existing, (ii) the zero-producer case carrying no HA consequence,
   and (iii) two reviewed attempts producing cascades? Trace the
   ISSUE-class harm, or the retreats stand.
3. **Round-86/87/88 fold verification:** (a) `ResolvedWithoutLocalBacking`
   re-enters the cold/miss pipeline from the packet (as if the resolve
   had returned `None`) — is the sole-decision rule airtight across
   install, publication, buffering, replay, AND the slow-path
   reinjection epilogue (`poll_descriptor/mod.rs:5126` →
   `slow_path.rs:199`)? Is the DNAT port-remap case
   (`destination.rs:699`; the address-only classifier at `promote.rs:32`)
   safe under full re-entry? (b) propagation-target reciprocity
   (direction-aware) — is the wrong-mark trace on the unrelated
   occupant B dead in both directions, with positive coverage for
   SNAT/hairpin/NPTv6/NAT64 families? (c) the `account_packet` wording
   (counters unchanged; anchor rides the distinct post-admission hook)
   — consistent everywhere now (§5.2, §5.8, §7)? (d) the probation
   deferred refresh (round-88) — is any pre-commit refresh/requeue
   path left for a probation entry (lookup, `touch_if_stale`, promote,
   materialize refresh), and does the commit-hook clear+refresh cover
   every admission arm? (e) the v10.11.0 end-state: the RWoLB path is
   master-verbatim except the close-aware purge gate (closes never
   purge; unconditional retention) — is any close-class state mutation
   left on peer-synced provenance; does master-verbatim keep the #6599
   class packet-for-packet identical (no plan-introduced acceleration);
   does the in-place overdue-K adopt close the pin without the
   split-brain; and is the documented #6600 retention interaction
   (bounded extension inside a pre-existing broken state) honestly
   bounded?

4. **The emission posture:** master's `expire.rs:342-350` gate is
   UNCHANGED; the additions are the normative mark-creation rules, rule
   5, the reverse-synth forward-family mark, the site-9 producer-
   survival rule, the family-identity checks, and the transient-seed
   carve-out (pre-existing, HA-safe by construction). Any remaining
   zero-producer or duplicate-producer trace OUTSIDE the carve-out?
5. **Attack-surface arithmetic (restated):** ~1/2^12 (cap) to ~1/2^14
   (floor) per blind packet. (Confirmed by round-83, round-84, AND
   round-86 Codex recomputation: 393,219 ≈ 1/10,923; 655,355 ≈ 1/6,554.)
6. **The re-scope:** #6522 to its own `/engineer` effort; the §10.6.2
   races and seed-lifecycle completion (with the round-86 design notes:
   count-at-admission, compare-and-transition publication, process-local
   collision-free alias-owner token with serialized conditional
   deletion, admitted-metadata preservation) as follow-up candidates;
   Phase 2 on its own track; and the round-92 re-scopes — #6599
   (transient-purge/Open provenance-integrity) and #6600 (import-window
   reservation race) — both PRE-EXISTING master exposures that no demote
   gate can see (neither driving packet carries closing flags). Does
   anything further MUST ship in this
   plan for the issue's fix to be safe? Trace required.
