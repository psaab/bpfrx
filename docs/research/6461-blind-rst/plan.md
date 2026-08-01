# #6461 — blind off-path TCP RST/FIN demotes a live session with no sequence validation

**Status: DRAFT v10.38.0 — THE TERMINAL CUT, round-122 folds (Codex
r122's 8B/1H/1M: the admission rule is now PER-ARM and reconciled with
§5.2's pre-existing wire-commit semantics — the in-place arm applies at
the postblock (the `pending_tx_prepared` push IS the admission), the
fallback request arm carries an optional authority payload on the
`PendingForwardRequest` and applies at the request's dispatch-admission
success (the redirect-inbox overflow/build-failure discards report via
the mandatory API and SKIP the apply — §5.2's mandatory no-learn
stands); the v10.37.0 "TX-pipeline admission" redefinition is
superseded, and the walk-the-anchor trace dies twice (geometry checks
are hoisted before every apply; a blind attacker cannot chain slides
without feedback; an overrun only produces fail-closed legit-close
refusals). The precedence drain topology is corrected — INLINE
current-binding invalidation at the install's own dispatch
(invalidate-BEFORE-cache ordering, so descriptor N's fresh S2 cache is
never evicted by a delayed drain), post-batch sibling fan-out (the
existing SSOT), and the loop-top all-binding command drain. The
invalidated family is COMPLETE (reverse_canonical added — reply
matching accepts both reverse shapes, both separately indexed); the OLD
family is captured at REMOVE time (LocalDelivery removes K before
invoking the installer); `refresh_for_ha_transition`'s reindex joins
the producer list; the buffer capacity is fixed-inline with a
saturation→whole-cache-flush fallback (the FlushFlowCaches precedent).
The site-2c adoption takes S2's trusted lifecycle bits and preserves
ONLY probation + the absolute deadline (K-alive→S2-RST never
resurrects alive; K-closing→S2-alive never transfers stale close
authority). The family-id transport is completed:
`MaterializeReport.family_id`, the promote's `SessionUpdate` carries
BOTH the incoming family id AND the incoming expected_fwd_id (the
replacement branch seeds `fwd_companion_id` from it — never blindly
zeroes; the shared-reverse-S2-over-K path keeps its family proof), a
successful zero-wire-id upsert surfaces its final minted id, every
promotion sources `closing`/`reset` from the LIVE post-transition
entry (never raw flags, never `observed_tcp_flags`), and the
SharedPromote republication reads the final entry's fields back. The
accepted site-2b close RE-PUBLISHES the forward shared row's close
state INDEPENDENT of the reverse install's success (the cross-worker
stale-alive-F hole is closed). The accounting fallback covers every
Local identity-agreeing refusal that forwards without R (the
non-closing OPENING-proof refusal added). Round-122: Codex NO
(8B/1H/1M — folded this revision; r121-8 RESOLVED); AGY r120 dispatched
(attempt 7, compact prompt); SMR r121 YES (fold verification,
v10.37.0). Round-121: Codex NO (6B/3H/2M — folded v10.37.0;
r120-6/7/8/11/12/13 RESOLVED); AGY r119 attempt 6: headless
command-permission denial (six attempts documented); SMR r121 YES.
Round-120: Codex NO (11B/1H/1M/1L — folded
v10.36.0; r119-8/9 RESOLVED); AGY r119: five dispatch attempts —
two non-review content faults, two headless command-permission denials,
one off-topic CLI-documentation response (infra per protocol; a sixth
attempt runs on v10.36.0); SMR r120 YES (fold verification).
Round-119: Codex NO (6B/1H/1M/1L — folded
v10.35.0; r118-3/6/7/8/9 RESOLVED); AGY r118 infra (documented
retries); SMR r119 YES (fold verification, v10.34.0).
Round-118: Codex NO (4B/3H/1M/1L — folded v10.34.0;
r117-7 RESOLVED); AGY r117 two infra failures (non-review content;
headless command-permission denial — re-dispatched with the proven
framing); SMR r118 YES (fold verification
+ 1M folded v10.33.1). Round-117: Codex NO (3B/3H/1M —
folded v10.33.0); AGY r116 SOUND (no findings); SMR r117 YES
(fold verification). Round-116: Codex NO
(4B/2H/2M — the state-keyed proof rule was the round's real
correction); AGY r115 UNSOUND (2 substantive findings, folded v10.31.1);
SMR r116 YES (fold verification). Ship
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
no-baseline) close can never mark, never reaps early FROM THE GATE'S
OWN EFFECTS (mark/refresh/re-queue — master's independent flag-agnostic
purge of a transient-purge-class entry still runs, v10.19.0 round-102
Codex 9), never emits a Close
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
  values up to 86,400 s) instead of the 2 s/30 s fast reap — UNLESS
  master's own flag-agnostic transient purge removes the entry first
  (a purge-class hit is deleted by master machinery on both versions,
  not by the gate; v10.19.0, round-102 Codex 9). Delivery is
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
  unless master's own flag-agnostic purge removes the entry first
  (the purge-class exemption, v10.21.0 round-104 Codex 8) —
  a table-pressure cost, never a broken connection. Aggregate version
  (round-2 Codex): a both-direction path-switch can stall an anchor
  permanently (§5.2); many flows stalling after one path event linger to
  their established timeouts — bounded, self-healing as flows churn.
- Cost (stated whole, v10): **49 B** of anchor/proof state on
  `SessionEntry` — 40 B `TcpSeqAnchor` + 1 B `probation` + 8 B
  `fwd_companion_id` (v10.34.0, round-118 Codex 2 — the forward entry's
  STABLE `session_id`, renamed from the v10.33.0 epoch form; still a
  plain `u64` with 0 = UNBOUND — `alloc_session_id` starts at 1 and
  guards the wrap, `session/mod.rs:784-789`, so the sentinel
  is free and `Option<u64>`'s 16 B tag+pad is avoided; no wire leases,
  no incarnation ids, no scheduling
  state — those were machinery and are gone) on the uniform slab
  (UDP/ICMP entries carry it unused; 49 × 131,072 = 6,422,528 B ≈
  6.1 MiB per worker at the 131,072 cap, ≈ 36.7 MiB at 6 workers —
  the one consistent figure, v10.33.0 round-117 Codex 6) PLUS the
  per-binding flow-cache token: one additive `Option<MatchedToken>`
  (~96 B — 40 B `SessionKey`, `key.rs:9-17`, + 44 B `NatDecision`,
  `nat/mod.rs:90-103`, + 8 B stable id + orientation/source/transition
  bytes; the
  `Option` niche-fills on the source enum) on `FlowCacheEntry`,
  4,096 entries per binding ≈ +384 KiB per binding (owned per binding,
  not per worker). No Go sidecar. Per-packet: one
  TCP-header view compute (seq/ack/wnd/flags/seg_len) plus ≤2
  plausibility-gated `u32` stores per committed TCP data packet, a
  companion table probe on closing-flag segments (which already take
  the full slow path), AND the cache identity-check probe(s) on every
  session-backed cache hit — one canonical probe for a forward-direction
  binding, two for a reverse-direction binding (v10.36.0 — the
  "closing-only" phrasing here predated the identity check; §8 carries
  the full accounting).

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
2 s fast reap (same purge-class exemption, v10.21.0). That is a table-pressure cost, never a broken connection.

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
| 2c | **reactive shared materialize** — `materialize_shared_session_hit` (`session_glue/mod.rs:1092-1118`) threads the current packet's `tcp_flags` into `upsert_synced_with_origin` (seeds at `install.rs:399-400`) | wire packet flags on a shared-map hit | gate the flag seed with the validator; an imported entry has no anchor → no-baseline → refuse → install the copy **alive** (`closing=false, reset=false`) at the bounded probation timeout (§5.6) — UNLESS the existing entry is overdue, in which case the materialize is skipped wholesale (`OverdueSkipped`, §5.8 contract); re-materialization against an existing probation entry atomically ADOPTS the shared S2 decision/metadata while preserving only the probation deadline/flag — no decision split-brain, no clock restart (§5.6, v10.7.0) |
| 3 | `install.rs:179-180` primary miss installs | creating packet flags | unreachable for bare closes on TRANSIT dispositions (#4400) and LocalDelivery caches TCP only with SYN (`local_delivery.rs:20`). The actual residual: a SYN|RST/SYN|FIN new-flow packet passes the #4400 guard (it has SYN, `session_admission.rs:82-87`) and seeds closing/reset from raw flags — a self-anchoring invented-tuple entry (attacker kills only a flow it created — no victim impact, master parity); malformed SYN+close combos are screen-owned where screened. **Provenance bound (v10.15.0, rounds 89-98 Codex):** the invented-tuple harmlessness holds ONLY when the tuple is genuinely new in this dispatch; when the tuple carries peer-synced provenance (the transient-purge class or `ReplacedSyncedLocal` displacement) it is a REAL victim's — a closing-flagged packet on the transient-purge class purges and dispatches EXACTLY as master (the close-aware gate line is retracted v10.15.0; the master's-own follow-through is the documented #6599-family exposure, §7) and never displaces the synced victim (`ReplacedSyncedLocal`: deliver locally, no install) — §5.6 site-3 supplement |
| 4 | HA wire re-import — eventstream `UpsertSynced` → `upsert_synced_with_origin` (no packet exists) | peer delta | validation-free by design (the peer validated before reaping and emitting the Close); distinct from site 2c, which HAS a packet |
| 5 | tunnel `UpsertLocal` (`tunnel.rs:563-615` → `session_glue/mod.rs:786-800`) | locally generated packets (firewall-originated tunnel TX) | trusted-local class, documented; not wire-attacker-controllable. Inbound tunnel closes land on site 1 with whatever anchor the inbound stream built — none if the flow is outbound-only → refuse-demote; local blast radius |
| 6 | fabric-return reverse seed (`cluster_peer_return_fast_path` install) — **REMOVED on master by #6478; the row below is the branch-base analysis, retained for the record** | fabric-ingress packet flags | bare closes already excluded (#4453); SYN|ACK|RST/FIN combos pass the guards (`fabric.rs:404`) and seed raw flags — an unvalidated constructor, harmless-by-class (the seed is `is_reverse` → silent at reap; the non-owner's forward import validates closes at site 1 with no anchor in Phase 1 → refuse → no mark). The seed bypasses the commit hooks so it carries no anchor — a later close on it is REFUSED (missing-forward/no-baseline, §5.1); documented. On current master the site no longer exists: #6478 deleted the fast path and its seed install, so the residual is closed by deletion |
| 7 | CLI/control deletes, GC/reaper, screens/SYN-cookie | — | consumers / unaffected |
| 8 | **forward-wire immutable match** — `find_forward_wire_match_with_origin` (`lookup.rs:258-293` via `shared_ops.rs:614-628`): NAT64 forward direction, hairpin, non-bijective NAT | wire packet on the forward-wire tuple | The match itself never marks (cloned decision/metadata — no `&mut`, today or after). But it is not demote-free: a promotable-origin forward-wire hit reaches `maybe_promote_synced_session` → `update_session`, which marks closing/reset from the packet's flags on master — gated by §5.5's rule 5 like every other promote (closing packets never promote → never reach `update_session`). The anchor for these flows advances from the reverse (mutable alias) direction only; pre-existing forward-direction accounting/refresh asymmetry (NAT64) is out of scope — filed as a follow-up candidate |
| 9 | **MissingNeighbor disposition arm** — `poll_descriptor/mod.rs:4034-4798`: a packet (HIT or MISS) whose disposition is MissingNeighbor reaches the common arm, which runs seed-only NAT derivation/allocation (:4680, :4745), metadata/counters, and installs `MissingNeighborSeed(..., meta.tcp_flags)` at :4787 — `install_with_protocol_with_origin` `remove_entry`s any existing key (`install.rs:140`) and seeds `closing`/`reset`/timeout from the raw flags (`install.rs:179-180`) | any closing-flagged packet with a cold next hop; the #4400 guard at :1642-1650 covers only the ForwardCandidate/MissingNeighbor MISS path | **gated by typed provenance (v10.4.1, rounds 83-87 Codex):** the arm branches on the resolve outcome AT THE ARM HEAD — before ANY seed-only work (NAT/NPT derivation or allocation, metadata, counters, install, rollback, publication): `ExistingResolved` (a live local or shared resolve-time entry backs the resolve — incl. a validator-REFUSED close, a 2b REFUSE, or an accepted marked close) buffers the packet with the RESOLVER's stored decision and does NOTHING else (allocator state, metadata, counters, install, publication all untouched — an unowned `live_by_flow` allocation can never leak, `nat/source.rs:1548`); the retracted `ResolvedWithoutLocalBacking` outcome is replaced by master's own split plus corrected outcome naming (v10.13.0, rounds 95-96 Codex): a purged packet with a WARM next hop forwards on the retained lookup (`session_glue/mod.rs:1194-1196`) with no install; a purged packet with a COLD next hop is `SeedEligible` and takes master's own seed transaction (merge-keeps-P1 purge-aftermath included — pre-existing, §7; the transient seed cannot emit Open, `entry.rs:272-274`); the ForwardFlow install + Open happen on a later genuine clean miss, exactly as master; the arm-head outcomes are `ExistingResolved` (live backing, buffer-only) / `PurgedRetained` / `SeedEligible`, with `SeedInstalled`/`SeedRefused` as RESULTS (install can refuse at capacity, `install.rs:123-125`; NAT64 drops earlier, `poll_descriptor/mod.rs:4634-4656`); a closing-flagged packet purges EXACTLY as master (v10.15.0 — the close-aware gate is retracted, round-98 Codex 1-3); `SeedInstalled` (genuine top-level miss, #4400-passed) runs the full seed transaction as today; `SeedRefused` (miss, refused) drops as today. The gated verdict is terminal across dispatch; a live/marked entry can never be replaced by a transient raw-flags seed; the accepted close's sole producer survives (§5.5/§5.6) |

---

## 3.1 Master drift since the citation base (v10.5.1; verified `023f17a606d8` → `fff7a4ab5`; second window `fff7a4ab5` → `b4605ea9d` verified v10.34.0)

origin/master advanced 19 commits while this plan iterated (plus 82
more in the second window). Re-verified
this round; **no design rule in §5–§9 changes**. Implementation
(`/engineer 6461`) branches from the then-current master and applies
these deltas:

| Change on master | Consequence for this plan |
|---|---|
| **Second window (`fff7a4ab5` → `b4605ea9d`, v10.34.0; the loop_body correction v10.35.0, round-119 Codex 8):** #6614 VRF session scope (doc-guard test only), #6603 DHCP-relay reply binding, #6608/#6592 atomic validation-forwarding (coordinator `ha_state`/`reconcile`/`snapshot`, `types/runtime_view`), #6604 config app-match, plus dhcprelay + canary-test tooling | The session-table files are untouched (`userspace-dp/src/session/`, `afxdp/flow_cache.rs`, `afxdp/poll_descriptor/flow_cache_hit.rs`, `nat/mod.rs`, `afxdp/shared_ops.rs`, `afxdp/session_glue/`, `afxdp/ha/session_import.rs`, `afxdp/worker/mod.rs` — verified by `git diff --name-only`). **CORRECTION:** the window DOES rewrite `afxdp/worker/loop_body/mod.rs` (+342/−13): `reap_expired_sessions` is called at branch-base `:825` and defined at branch-base `:1481` (`:1481-1521` cited block) → master definition at `:1615` — the §5.6/§5.8/§9 reap citations are branch-base and shift at `/engineer` time. The coordinator/runtime-view work is the publication side, not the session table. No design rule changes |
| **#6478** (`7b7119db1` + docs `fff7a4ab5`) removed `cluster_peer_return_fast_path`, its reverse-seed install, and the #4453 bare-close guard (`fabric.rs:389-492`, the call at `poll_descriptor/mod.rs:928`) | Site 6 no longer exists — its residual is closed by deletion. §3's fast-path bullet, the #4453 bullet, site row 6, and the §5/§5.6/§7 fabric-seed mentions are branch-base record. Post-#6478, fabric-ingress return traffic WITH a live session takes the ordinary HIT path (site-1 gate applies); SESSIONLESS fabric-ingress packets take the ordinary MISS path (master `poll_descriptor/mod.rs:941-959`), where #4400 guards bare closes — covered either way (round-90 Codex 5 corrected an earlier overstatement that all such traffic runs site-1 HIT accounting) |
| **#6432** wrapped the MissingNeighbor arm in the `poll_stages::StageOutcome` ownership enum (arm head now `poll_descriptor/mod.rs:4015`; seed install `:4792`/`:4816`) | Site 9's "branch on the resolve outcome AT THE ARM HEAD" composes: the typed resolve-outcome branch becomes the arm's first StageOutcome-producing stage. No rule change |
| **#6433** extracted the flow-cache seed path | Editorial; the §5.6 constructor sites are unchanged |
| **#6458** added the fabric zone-stamp owner-RG gate (`gate_fabric_zone_override_on_owner_rg`, master `fabric.rs:289-307`; the worktree's `fabric.rs:331` is `redirect_via_fabric_if_needed`, a different function) | §5.4's "no transport-based authority" bullet stands verbatim — the stamp proves even less post-#6458 |
| **#6474** re-NATs outbound ICMP errors through SNAT | Orthogonal (ICMP error path, not TCP closing); shifted `poll_descriptor/mod.rs` line numbers |
| **#6473** flipped inbound NAT to static-first (static NAT now evaluated before DNAT rules) | Non-fatal for this plan: the clean-miss install dispatch (the purged class's ForwardFlow install point, v10.11.0 — the cold path's transient seed install is master's own and unchanged, round-102 Codex 7) derives DNAT/routing/zone/policy/SNAT fresh from the packet against current config through the full pipeline, so the reorder is composed automatically (round-89 Codex 4 confirmed) |
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
normal timeout FOR THE GATE'S OWN EFFECTS — master's independent
flag-agnostic purge of a transient-purge-class entry still runs,
v10.20.0 round-103 Codex 7 — exactly as if the RST had been lost in transit — a
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

`SessionEntry` gains (49 B total — the 40 B `TcpSeqAnchor` shown below +
1 B `probation` + 8 B `fwd_companion_id`, v10.34.0 round-118 Codex 2;
plain POD, worker-owned, no serde, no HA
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
(The shown anchor struct is exactly 40 B — the full 49 B per-entry delta adds
`probation` and `fwd_companion_id` OUTSIDE it, v10.34.0 round-118 Codex 2 —
round-4 Codex 4a + round-5 Codex
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
  not move the anchor (mandatory, not best-effort). **The per-arm apply
  points are exact (v10.38.0, round-122 Codex 1):** on the cache-hit
  path, the IN-PLACE rewrite arm applies at the postblock
  (`!recycle_now` after the `pending_tx_prepared` push,
  `flow_cache_hit.rs:444-497`, `:549-552` — the push is the admission;
  nothing between it and the TX loop drops); the FALLBACK request arm
  carries an optional authority payload on the
  `PendingForwardRequest` (the validated handle + the seg summary +
  the identity — the rare arm: cross-binding or in-place failure) and
  the apply fires at the REQUEST's dispatch-admission success, with
  the redirect-inbox overflow / build-failure discards reporting via
  the mandatory API and SKIPPING the apply (the §5.2 no-learn rule,
  unchanged); the v10.37.0 "TX-pipeline admission" redefinition is
  SUPERSEDED — it conflicted with this section's wire-commit semantics
  (round-122 Codex 1's contradiction trace: plan §5.2/§9 always
  prohibited learning on the overflow path). With geometry hoisted
  BEFORE every apply point, the round-122 walk-the-anchor trace dies
  twice: attacker-chosen geometry never reaches an apply (the
  geometric check fires first), and the residual load-driven overflow
  neither reports success to a blind attacker nor moves the anchor —
  and even a landed-then-dropped sample cannot be CHAINED without
  feedback (an off-path attacker never learns which guess succeeded;
  each slide requires the previous one to have landed), while an
  anchor overrun from dropped samples can only push the window PAST
  the peer's real position, which turns a later legitimate close into
  a REFUSAL — fail-closed, bounded lingering, the §2 posture.
  **Selective
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
  anchor and never drives post-borrow state on the retry path** (no
  anchor update, no probation clear, no promote ON THE RETRY PATH —
  the retry has no `SessionTable`; the establishment promote already
  fired at the ARRIVAL dispatch's lookup phase, before any buffering
  decision — master's in-borrow timing modulo the borrow boundary,
  v10.29.0 round-113 Codex 2/4; the anchor update and probation clear
  still wait for the
  next SUCCESSFULLY COMMITTED unbuffered non-close whose effective
  transition is NEITHER `OverdueSkipped` NOR `UpsertRefused`
  (v10.30.0, round-114 Codex 7 — a closing packet never updates or
  clears, and a packet failing final admission updates nothing),
  v10.27.0, round-110 Codex 2). The consequence is a documented residual, not a channel: a
  flow whose traffic is mostly buffered (long ARP stalls) lets its
  anchor lag the stream — later closes soft-refuse and the entry idles
  out on its ordinary timeout, the same bounded class as the
  unobserved-stretch residual (§2), always fail-toward-refuse (a
  skipped update can never walk or poison an anchor). A buffered
  SYN-ACK promotes at its arrival lookup phase (master's in-borrow
  timing, v10.29.0) — no packet lingers OPENING for want of a promote;
  the earlier "delivers without its promote" framing is retracted.
  (ii) **the buffered stale-decision transmit window is
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
  RETRACTED to the master split (below, v10.11.0/v10.13.0).
  (iv) **`ResolvedWithoutLocalBacking` is MASTER-SPLIT (v10.13.0 —
  the re-entry is RETRACTED, round-94 Codex 1-3):** when the
  resolve-time transient purge fires, master's own machinery keeps the
  packet in the HIT branch on the retained lookup
  (`session_glue/mod.rs:1194-1196` — `resolved = hit.lookup.clone()`),
  and this plan keeps that dispatch master-split with no DISPATCH
  delta (v10.15.0 — the close-retained marker and its cache
  suppression are retracted, round-98 Codex 1-3; the ONE deliberate
  remaining delta is the demote gate's refusal of the closing-mark on
  anchorless peer-synced entries upstream of the purge, with the
  replica-lifetime cost documented below — round-99 Codex 2 /
  round-100 Codex 5):
  with a WARM next
  hop the packet forwards on the retained decision with no install;
  with a COLD next hop it takes master's own MissingNeighbor seed
  transaction (derive/allocate P2, install the transient
  `MissingNeighborSeed`, publish, buffer — v10.13.0, round-96 Codex 1:
  master's actual merge keeps the retained P1 translation —
  `NatDecision::merge` prefers fields already set, `nat/mod.rs:123-133`
  — so the seed/buffer carry P1 while the allocator owns P2, and an
  install-refusal rollback mismatches P1/P2 and leaks P2,
  `poll_descriptor/mod.rs:4890-4909`, `allocator.rs:1398-1404`. That is
  master's PRE-EXISTING purge-aftermath released-tuple reuse family
  (warm-path forward micro-window, cold-path merge-keeps-P1,
  rollback mismatch leak, reinjection P1) — the plan asserts PARITY,
  not correctness, for the purged non-close dispatch and documents the
  family in §7; the transient seed cannot emit Open,
  `entry.rs:272-274`). The retained decision is the single decision
  object for this packet's consumers (the v10.4.0 P1/P2 split and the
  blanket-clear DNAT-erasure risks both arose from the plan's OWN
  intermediate re-derivation shapes, never from master; master's
  outer/pending split on the ordinary seed path is pre-existing,
  round-95 Codex 7). A LATER packet's genuine clean miss installs the
  ForwardFlow with a fresh current-config derivation — the round-87
  correctness property lands at the install, where it matters: no
  stale retained decision is ever installed.
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
  The purge DECISION and subsequent dispatch are master-identical
  (v10.15.0 — the close-aware
  purge gate, the close-retained marker, and the cache suppression
  are all retracted, round-98 Codex 1-3; §5.6 site-3 supplement
  carries the retraction rationale; the 'FULL MASTER PARITY' phrasing
  corrected to this exact scope v10.22.0, round-105 Codex 7) with ONE
  deliberate exception,
  stated exactly (round-99 Codex 2): the local lookup runs BEFORE the
  purge decision (`shared_ops.rs:594-635`,
  `session_glue/mod.rs:1157-1196`), so master's close marks the
  matched entry and propagates the shortened lifetime to its
  companion before the purge — and the demote gate REFUSES that mark
  on an anchorless peer-synced entry (the gate's purpose on a HIT).
  The purge then deletes only the matched local key + forward shared
  aliases (`promote.rs:181-207`, `shared_ops.rs:960-1013`), not the
  local reverse companion, which HA import fans to every worker
  (`session_import.rs:104-115`, `:187-223`): master leaves the
  current-worker reverse replica closing (2 s/30 s); the plan leaves
  it on its ordinary peer-synced trajectory. That replica-lifetime
  delta is the §2 absorbing-state residual (imported entries refuse
  closes and linger to their inactivity timeout) applied to this
  path — it lengthens stale/conflicted-P1 companion exposure for the
  #6599/#6600 class and is documented and tested as a real Part-A
  delta, not asserted away.
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
- **`account_packet` keeps #2501 counter PLACEMENT and gains one
  additive `-> bool` charged return (v10.37.0, round-120/121 Codex
  11 — the "UNCHANGED/no signature change" phrasing is corrected):
  #2501
  counter placement is untouched (`account_packet` keeps counting
  attempted forwards at `flow_cache_hit.rs:312` /
  `poll_descriptor/mod.rs:3497` — RT_FLOW volume semantics; the
  slow-path call PRECEDES build/output-filter/CoS failures, which is
  why it cannot host the anchor). The anchor's update hooks are the
  per-disposition FINAL-ADMISSION apply points of §5.2 (two call
  classes: the cache-hit commit arm and the slow-path commit arms),
  fed by the same seg view; the only `account_packet` delta is the
  charged/missed boolean the capacity-corner fallback consumes.
  **The apply hook has NO missing-forward fallback (round-83
  Codex, core-gate note):** unlike
  `account_packet`'s tolerant reverse hop (`session/mod.rs:1205`), a
  missing canonical forward entry means the hook is a NO-OP — updates
  land only on the one canonical store (validation refuses regardless,
  §5.1).
- **`lookup_with_origin` does NO anchor updates:** the lookup path
  validates and marks only. Closing segments never update (rule 1);
  committed non-close packets update at the dispatch arms above —
  EXCEPT on an `OverdueSkipped` or `UpsertRefused` effective
  transition (the anchor commit hook is suppressed for both,
  v10.28.0, round-112 Codex 4).
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
     4,096-byte frame ceiling, ≥ ~1/2^20). The proof is KNOWLEDGE OF THE
     ACK POSITION, not the SYN bit (v10.33.0, round-117 Codex 3 — the
     public SYN bit contributes no entropy): ANY ACK-bearing segment
     (SYN-ACK or an exact-proving ACK/PSH-ACK) whose ack proves this
     way authenticates the WHOLE segment (the exact ISN knowledge is
     cryptographic-strength evidence the sender is the real peer) → both
     its seq and ack adopt trusted (fast server abort validates), and it
     drives the establishment promote (rule 5). The conjunction with
     the closing rules is explicit (v10.34.0, round-118 Codex 6): a
     CLOSING exact-proving segment (SYN-ACK+FIN/RST, FIN-ACK, RST-ACK)
     supplies READ-ONLY validation EVIDENCE for §5.4 — it NEVER adopts
     anchor state and NEVER establishment-promotes (rules 1/5 dominate:
     closing packets do not learn and do not promote); the proof's
     adopt/promote effects apply to NON-CLOSING segments only. **Not
     windowed** (a
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
   tuple+NAT reuse needs no generation token FOR THE CLOSE MARK (scoped
   v10.34.0, round-118 Codex 1): when tuple AND
   translation are identical, the two generations are
   packet-indistinguishable at the firewall — a close arriving on the
   old reply tuple is indistinguishable from the replacement's own
   close, so the re-probed anchor IS
   the flow's anchor for validation and the mark is justified; the
   anchor-LEARNING hop is the stronger-action path and DOES require a
   generation discriminator (the `fwd_companion_id` binding, §5.6/§5.8
   — learned samples write the state that future close validations
   trust, so they bind to the stable session id). A forward-hit match
   (site 1) needs no check (the
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
     entry ages on its pre-attack trajectory FOR THE GATE'S OWN EFFECTS
     (mark/refresh/re-queue; master's independent flag-agnostic purge of
     a transient-purge-class entry still runs — v10.20.0, round-103
     Codex 7).

`update_session` (site 2): **a closing-flagged packet never reaches this
path at all (rule 5 — the ownership promote is skipped wholesale)**, so
there is no partial-promote transaction to specify: no origin flip, no
Close-authority arming, no self-heal suppression, no refresh question. A
non-closing promoting packet's ownership promote keeps MASTER's timing
(resolve-time, `promote.rs:86-107`) — the v9.x commit-arm restructure is
cut (§10.6); the probation suppression below is the only new promote
rule. **Probation entries additionally SUPPRESS ownership promotion, Open
emission, and replication until a committed non-close packet clears the
flag** (never when the effective transition is `OverdueSkipped`,
v10.26.1, round-109 AGY 2) (the refused-close → probation-zombie → blind-promote chain,
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
(`shared_ops.rs:857-865`) holds the `forward_match` in hand. **A
reverse synth against an OPENING forward entry must pass the strong
OPENING proof — keyed on the FORWARD ENTRY'S STATE, not the packet's
flags (v10.31.0, round-115 Codex 1; corrected v10.32.0, round-116
Codex 1):** the synth installer treats every non-initial-SYN
TCP packet as established at install (`install.rs:157-180`,
`established = !(PROTO_TCP && is_initial_syn)`) — WITHOUT any proof —
so an unproven spoofed reverse packet (SYN-ACK OR a bare ACK/PSH-ACK)
that misses the normal lookup and matches the forward NAT entry would
synthesize an ESTABLISHED
reverse entry and pin the OPENING forward half through companion
retention (`expire.rs:296-320`, `:468-523`) — the exact
bare-reverse-ACK pin normal lookup explicitly prevents
(`lookup.rs:129-146`, `tcp_flags.rs:83-107`). The rule: a NON-CLOSING
reverse synth against an OPENING forward entry runs the strong
OPENING proof regardless of the driving packet's flags — and the
proof is KNOWLEDGE OF THE ACK POSITION, not the SYN bit (v10.33.0,
round-117 Codex 3): ANY ACK-bearing segment whose ack exact-proves
the immutable SYN interval has the same off-path resistance (the
public SYN bit contributes no entropy), so a SYN-ACK OR an
ACK/PSH-ACK that exact-proves the interval is accepted; an
out-of-interval or non-ACK packet SKIPS the install entirely (the
site-2b refuse precedent: `created=false, install_failed=true`, no
cache insert, the packet still forwarded, the next legitimate packet
re-synthesizes). The asymmetric-SYN-ACK-path repair case is covered:
without this, repeated legitimate reverse ACKs would neither install
R nor establish/touch F, and F could expire on its OPENING clock
losing the live NAT mapping. When the forward entry is
already ESTABLISHED (incl. a #3152 pickup or an import), the synth
keeps master's behavior verbatim (no proof required — the pickup
preservation; an already-established forward has no OPENING proof
interval and the legitimate-repair case must not be rejected, both
stated). The complete (scope, state, flags) table (v10.33.0,
round-117 Codex 4): **(Local, OPENING, non-closing)** → the proof is
required (an exact-proving ACK-bearing segment accepted; anything
else skips the install); **(Local, ESTABLISHED, non-closing)** →
master verbatim; **(Shared, any, non-closing)** → master verbatim
install (the shared row carries no `established`/OPENING timing
state, `worker/mod.rs:375-401`, `shared_ops.rs:638-665` — the synth
installs per master's installer semantics with the anchor UNTRUSTED
per the absorbing-state rule; treating Shared as proof-gated would
change master's non-closing repair behavior, and treating it as
established-by-proof-exemption is safe here because the imported
class's closes already refuse until churn, §2); **(any, any,
closing)** → the §5.4 close validation (plus the round-115/116
rules). **The match
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
prior decision's, `shared_ops.rs:897`). **A `Shared` match refuses
CLOSE VALIDATION even when the same canonical key is locally occupied**
(scoped v10.34.0, round-118 Codex 6 — the refuse is the CLOSE path:
the local entry is a
different flow generation; a NON-CLOSING Shared match installs
master-verbatim per the (scope, state, flags) table above — the two
statements compose, they do not conflict), and any identity
disagreement refuses.
When the current packet is
closing-flagged, validate it (§5.4) against the FORWARD entry's anchor
first (the cross-direction legs cover a reverse-direction
close — `ack_hi(fwd)` pins the reverse stream's position). A LOCAL forward
entry carries its anchor; a SHARED `ForwardSessionMatch` carries only
key/decision/metadata (`entry.rs:209`, `shared_ops.rs:638-665`) → no
baseline → refuse. (The closing-SYN-ACK corner stated, v10.31.1,
round-115 AGY 1; scoped to the forward entry's state v10.34.0,
round-118 Codex 6: AGAINST AN OPENING forward entry a closing-flagged
SYN-ACK at site 2b first runs the
round-115 strong OPENING proof, then the §5.4 close validation; a
proven closing SYN-ACK on an OPENING forward entry marks the forward
family closing/reset per the accept rule — the entry's `established`
flag is NEVER set by a closing packet (rule 5), so the marked entry
is the never-established forward, which is the sole producer and
reaps at 2 s/30 s with the Close delta; the companion retention can
defer the reverse's reap only while the forward is live and only up
to the Hold ceiling — stated, bounded; an UNPROVEN closing SYN-ACK
skips the install entirely per the round-115 fold, so no zombie class
arises from blind sprays. AGAINST AN ESTABLISHED forward entry no
OPENING interval exists — the §5.4 close validation runs directly
against the trusted anchor, and the proof rules of §5.2 are not
engaged.) The accept/refuse split:

- **Accept** → install with `closing`/`reset` seeded as today, AND the
  mark is applied to the FORWARD family in the same resolve — and a
  PROOF-PASSING non-closing synth (SYN-ACK or exact-proving
  ACK/PSH-ACK, v10.33.0 round-117 Codex 3) additionally applies the
  forward
  companion's flag-only establishment update (v10.32.0, round-116
  Codex 5: the synth installs/publishes only the reverse entry and
  the ownership promote is ineffective for `ReverseFlow`,
  `shared_ops.rs:824-895`, `session_glue/mod.rs:1313-1344`, so without
  this the matched forward entry would never establish here; the
  update is the `session/mod.rs:1243-1252` companion semantics —
  `established` flag only, the absolute opening deadline preserved).
  A capacity-REFUSED reverse install (`install.rs:123-125`) still
  applies the forward update (the proof passed; the reverse entry
  re-synths on the next packet) — and SYMMETRICALLY (v10.33.0,
  round-117 Codex 5): an ACCEPTED close still marks the forward
  family even when the reverse install refused (the forward mutation
  — the close mark on accept, the flag-only establishment on
  proof-pass — is explicitly INDEPENDENT of the reverse install's
  success boolean; the publication still rides `installed`, but the
  forward mutation does not). A proof-passing, install-refused
  packet contributes NO anchor sample (no entry exists to hang it
  on — the commit token requires an installed entry). Two capacity-
  corner completions (v10.34.0, round-118 Codex 4; completed v10.35.0,
  round-119 Codex 6/7; extended v10.36.0, round-120 Codex 9/10): FIRST,
  a LATER
  reverse packet against the now-marked (closing) forward
  entry retries the synth master-verbatim — and that synth computes ONE
  EFFECTIVE INHERITED SEED STATE from the matched forward family's
  sticky state: the effective flags are the driving packet's flags
  OR'd with the family's close bits (RST when the family has `reset`,
  else FIN when it has only `closing`), and that ONE effective value
  drives EVERY output — the installer's
  `established`/`closing`/`reset`/timeout/`observed_tcp_flags`
  computation (`install.rs:157-180`, `:194-200`), the shared publish,
  and the replication (`shared_ops.rs:857-892`), so the sibling's
  receiver reconstructs the SAME closing state
  (`session_glue/commands/upsert_synced.rs:64-79`,
  `install.rs:382-400`) — inheriting only the local booleans would
  leave the established timeout and an alive sibling replica (the
  divergence trace). The merge applies to EVERY synth against a
  marked family (round-120 Codex 9): a non-closing retry AND a
  close-flagged retry alike — an RST-marked family followed by an
  accepted FIN yields `closing`+`reset` on the new reverse (the 2 s
  clock, never a FIN-only 30 s one whose liveness would retain the
  RST-marked forward past its deadline through `expire.rs:296-320`,
  `:468-523`), and FIN→RST merges identically. The same close-bit
  merge governs the sibling's shared-hit MATERIALIZATION (round-120
  Codex 10: `session_glue/mod.rs:1092-1115` reconstructs from the new
  packet's raw flags today, ignoring `replica.tcp_flags` — a bare ACK
  in the publish→replication window would rebuild an ALIVE entry from
  a published RST/FIN row): the materialize seeds its close state from
  the REPLICA'S stored (trusted-by-propagation) close bits ONLY, plus
  the current packet's close bits ONLY when the current close itself
  VALIDATED under §5.4 — at site 2c every current close is refused (no
  anchor), so in practice the seed is exactly the replica's close bits
  (v10.37.0, round-121 Codex 6: a naive `raw | replica` merge would
  let a BLIND current RST upgrade an alive or FIN-only replica to
  reset/2 s — the merge is NOT naive); raw packet flags
  still drive screens/cache/accounting. AND the materialize-then-
  promote publication carries the entry's EFFECTIVE STORED state, not
  the packet's raw flags (v10.37.0, round-121 Codex 7:
  `maybe_promote_synced_session`'s single raw `tcp_flags` input drives
  both the `SessionUpdate` and the republished/replicated row today,
  `session_glue/mod.rs:1235-1252`, `session_glue/promote.rs:99-138` —
  a bare ACK could materialize a closing replica correctly and
  immediately republish it ACK-only for another worker; under the
  rule, raw flags control promote ELIGIBILITY while the effective
  stored state controls the update and the publication).
  The (Local, ESTABLISHED, non-closing) →
  master-verbatim table row is correspondingly read as "the matched
  forward family is not closing-marked" (a closing-marked family runs
  this inheritance instead). Without
  the inheritance the retry would install a NON-closing reverse with
  the full established timeout whose liveness then retains the marked
  forward past its 2 s/30 s deadline via companion retention,
  `expire.rs:296-320`, `:468-523`, postponing the forward's Close
  emission indefinitely under continued reverse traffic — with the
  inheritance the late reverse is born on the family's closing clock,
  which is exactly master's semantics for straggler traffic on a
  closing flow. SECOND, the accepted close packet's own accounting
  (reshaped v10.36.0, round-120 Codex 11/12 — the full
  producer/carrier/consumer chain is the §5.8 `Site2bOutcome` +
  `Option<ValidatedTarget>` + hoisted fallback field +
  `account_packet -> bool` + mutually exclusive chokepoint branch;
  the earlier in-resolution direct charge is RETRACTED: resolution/
  site-2b receives no packet length or DSCP,
  `session_glue/mod.rs:1124-1143`,
  `shared_ops.rs:824-842`, and master's accounting runs later, only
  for forwarding dispositions, `poll_descriptor/mod.rs:3478-3503` —
  charging at resolution would count packets later denied or dropped
  and would skip the `observed_tcp_flags` fold; and the one-charge
  invariant is scoped to the accounting-eligible forwarded
  dispositions):
  on the install-refused path `account_packet` probes the absent
  reverse key and returns `false`
  (`session/mod.rs:1177-1210`), so the close-accept path carries an
  identity-bound FALLBACK TARGET — the validated forward handle (the
  carried-handle mechanics above) — from the accept to master's
  existing accounting chokepoint (`poll_descriptor/mod.rs:3478-3503`);
  the fallback fires ONLY when the reverse-key probe missed for
  this packet, and its producer classes are EXACTLY the Local
  identity-agreeing set (v10.37.0, round-121 Codex 10; completed
  v10.38.0, round-122 Codex 9): (i) an accepted close whose reverse install
  capacity-refused, (ii) a LOCAL identity-agreeing
  `ValidatorRefused` close — that packet is forwarded and skips the
  reverse install, so `account_packet` misses R and returns before
  deriving F; without the fallback F loses the reverse bytes/packets
  and the `observed_tcp_flags` that feed the Close harvest
  (`expire.rs:358-371`) — AND (iii) a LOCAL identity-agreeing
  NON-CLOSING OPENING-proof refusal (the proof-failing ACK/PSH-ACK is
  forwarded without installing R; the same accounting miss applies).
  Every Local identity-agreeing refusal that forwards without R
  carries the fallback;
  Shared-scope and identity-mismatch refusals
  NEVER produce a fallback target (no identity-agreeing forward
  exists to charge). The charge uses
  the re-validated forward entry's `rev` counters with
  the `observed_tcp_flags` fold — the install-success path is
  unchanged (the reverse-entry probe folds onto the forward entry's
  `rev` by the same derivation), so both paths end with exactly one
  `rev` charge on F at master's own chokepoint with master's own
  inputs. AND the cross-worker closure (v10.38.0, round-122 Codex 8):
  the accepted-close path RE-PUBLISHES the forward family's close
  state to the shared row (and the replication) INDEPENDENT of the
  reverse install's success — publication rode `installed` today
  (`shared_ops.rs:857-892`), so a capacity-refused reverse install
  would leave the stale ALIVE shared F for another worker to match
  and synthesize/publish an alive R from (defeating the inheritance
  and the companion-lifetime bound, `expire.rs:296-320`, `:468-523`);
  the re-publish rides the forward entry's identity (the carried
  handle), so the cross-worker view of the family flips to closing
  with the mark, not at the 2 s reap. A SYN-ACK+FIN/RST validates the
  close (§5.4) but NEVER establishment-promotes (rule 5 — the
  conjunction stated). The mark itself: the
  sequential same-worker writes are ORDERED FOR THE INHERITANCE
  (v10.37.0, round-121 Codex 9 — the v9 "install the reverse
  companion, then re-probe and mark" order predated the inheritance;
  the re-probe is now PRE-install): re-probe the local forward entry
  FIRST (identity agreement AND the `closing`/`reset` snapshot), the
  synth computes the effective inherited seed from that snapshot, the
  reverse installs WITH the inherited state, and the forward mark
  lands last — the pair remains indivisible to any reader
  (worker-owned table, no cross-worker observer). The pre-install
  source is complete: a LOCAL match snapshots the forward's
  `closing`/`reset` at the identity re-probe, and a SHARED match reads
  the shared row's carried `tcp_flags` close bits — the across-scopes
  wrapper currently DISCARDS `SyncedSessionEntry.tcp_flags`
  (`shared_ops.rs:638-665`), so the `ForwardSessionMatch` gains the
  forward family's close state alongside the id (`entry.rs:208-213`);
  the "every synth against a marked family" rule is thereby
  implementable for both scopes
  (the `forward_match` in hand
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
(unless the existing entry is overdue — the materialize is then
skipped wholesale, `OverdueSkipped`, §5.8 contract; v10.27.1,
round-111 Codex 2) (`closing=false, reset=false`) but at the **probationary opening-window
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
deadline — the upsert runs (the ordinary remove+reinstall path, which
rebuilds the indexes and transitions the presence-based counted class
correctly across any orientation change, `install.rs:434-447` —
unlike the retracted in-place write, round-96 Codex 5), installing
S2's decision and metadata
wholesale, while from K only `probation=true`, the alive `closing=false,
reset=false` state, and the timing carry over — and the carried timing
is the MINIMUM absolute deadline (v10.8.0, round-91 Codex 4):
`min(K.last_seen_ns.saturating_add(K.expires_after_ns),
now_ns.saturating_add(S2's own candidate from
metadata.inactivity_timeout_ns, install.rs:382))` — saturating
throughout (v10.16.0, round-99 Codex 6; the wheel derives its target
with `saturating_add`, `expire.rs:50-57`) — K's 20 s
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
K forever). The rule (v10.14.0, round-97 Codex 2 — the in-place adopt AND the
remove-locally shape are both retracted): a materialize against an
overdue probation entry SKIPS the upsert wholesale — no
remove/recreate, no restamp, no re-queue, NO REMOVAL (the v10.13.0
remove-locally shape ran pre-admission, destroying probation on a
filtered packet and breaking the commit-hook clear path; the v10.12.0
in-place adopt needed an atomic reindex
(`session/mod.rs:1627-1663`), a counted-class transition
(`install.rs:434-447`, `session/mod.rs:1782-1821`, `:901-941`), and an
authority-safe origin (`entry.rs:242-269`, `shared_ops.rs:897-916`) —
all machinery to keep alive an entry that is already due) — K keeps
its existing wheel slot and the GC reaps it on schedule; the packet
forwards with the materialized S2 decision in hand. The S1/S2
split-brain window is bounded by the GC lag (sub-tick to one pass)
and stated. And the commit-hook clear+refresh NEVER applies to an
overdue probation entry (an overdue entry reaps on schedule even if a
non-close packet commits against it first — otherwise the commit
would refresh the stale S1 for a full ordinary timeout, round-94
Codex 5's residual). "Overdue" means D ≤ `now_ns`; at D == `now_ns`
strict expiry has not yet occurred (`expire.rs:166-168`), so the
skip+no-refresh rule is a deliberate one-instant shortening, stated
(round-97 Codex 8). The §9 test asserts: no upsert, no removal, no
re-queue, no commit-refresh on overdue entries, decision delivery
with S2, and the GC reaping K on schedule under one-per-tick
pressure. Wording correction: the preserved deadline is
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
(a committed non-close packet whose effective transition is not
`OverdueSkipped`, v10.27.0) clears probation and applies the
ordinary refresh. A non-probation existing entry takes today's upsert
unchanged. The probation entry carries
an explicit `probation: bool` that (a) suppresses ownership promotion,
Open emission, and replication (§5.5), and (b) clears on the first
COMMITTED non-close packet whose effective transition is NOT
  `OverdueSkipped`
(the explicit overdue guard, v10.26.0 round-109 Codex 4), which also
refreshes the entry to its
ordinary established timeout. **The clear+refresh runs at the MATCHED
entry's own commit arm — the entry the packet hit — independent of the
anchor's reverse→forward hop** (the probation flag lives on the
materialized entry, which may be a reverse-key entry; wiring the clear
through the anchor hook would clear the wrong store and strand a live
flow on 20 s probation churn). Unlike site 2b the install cannot be
skipped EXCEPT by the overdue rule (the packet needs its decision and
the entry must own the flow going forward — so the seed is suppressed
instead; an overdue entry's materialize IS skipped wholesale per the
contract, v10.26.0 round-109 Codex 4). **A probation entry's
reap is LOCAL-ONLY (v10.1.0, round-83 Codex 2; alias amendment
v10.15.0, round-98 Codex 5):** `ExpiredSession`
carries the probation flag, and a probation expiry removes ONLY the
worker's local table entry PLUS invalidates the flow-cache entries
for the entry's FULL alias set (v10.16.0, round-99 Codex 4 — the
complete set, since lookup accepts reverse-translated aliases for
reverse entries and forward-wire aliases for forward entries, and
reply matching accepts reverse-wire/reverse-canonical tuples,
`lookup.rs:62-100`, `:222-250`, `:253-315`, `key.rs:19-26`,
`flow_cache.rs:1105-1120`'s invalidation is exact-key only): the
canonical key, the reverse companion
`reverse_session_key(key, decision.nat)`, the reverse-translated
aliases, the forward-wire aliases, and the reply-match tuples — all
derived from the entry's own decision/metadata at reap. And because
an S1→S2 adoption can change NAT/orientation while `ExpiredSession`
carries only the final S2 identity (`entry.rs:337-343`), EVERY
adoption additionally invalidates the PRIOR identity's full alias set
AT ADOPT TIME (the adopt has both identities in hand) — a cached S1
alias can never survive its own adoption. The invalidation lifecycle
(v10.17.0, round-100 Codex 4; the displaced-identity SET and the
mechanical timing v10.18.0, round-101 Codex 3/4): caches are
per-binding and exact-key
(`flow_cache.rs:203-218`, `:1105-1120`), descriptor processing owns
only the current binding and processes a whole RX batch
(`poll_descriptor/mod.rs:110-131`), and the reap path iterates ALL
bindings (`worker/loop_body/mod.rs:1467-1520`). **The displaced-identity
set:** one transition can simultaneously shadow a differently-keyed
query-side placeholder AND replace a canonical predecessor, and the
existing structures discard both (`ResolvedSessionLookup` carries no
shadowed-local identity, `shared_ops.rs:522-560`; the placeholder
substitution discards the placeholder's key/decision,
`shared_ops.rs:602-628`; the upsert discards `_previous`,
`install.rs:295-322`) — so every site-2c transition result carries a
BOUNDED SET of displaced identities: the new S2 alias family PLUS any
removed canonical predecessor's full old alias family PLUS any
shadowed placeholder's key family (the complete semantics — the
report fields, the refusal-class carriage, the
dedup proof, and the invalidation timing — live in the §5.8 contract
SSOT, v10.19.0-v10.24.0; this paragraph is the §5.6 summary).
**Timing:** the current binding's cache invalidation of the displaced
set runs IMMEDIATELY after resolution and BEFORE every early exit,
the cache-insert point, and the next descriptor (materialization has
no cache handle, `session_glue/mod.rs:1092-1143` — the invalidation
runs at the poller, which owns the binding and the batch,
`poll_descriptor/mod.rs:110-131`); every transition in the batch is
accumulated; the SIBLING fan-out runs once per batch at the
`poll_binding` level over `left + right` (`worker/lifecycle.rs:53-55`,
`:209-225`) BEFORE the next RX batch — explicitly NOT via the reap
routine (which includes the current binding and does NAT/BPF teardown,
`worker/loop_body/mod.rs:1481-1521`; v10.19.0, round-102 Codex 5) — so
no same-batch descriptor is missed and no freshly inserted correct S2
entry is evicted where old and new aliases overlap,
`poll_descriptor/mod.rs:3900-3959`. NO Close delta (as
before), NO
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
established refresh (only when the effective transition is not
`OverdueSkipped`, v10.26.1, round-109 AGY 2) (stamp `last_seen_ns`, recompute the ordinary
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
victim as a fresh self-authenticating flow. **The transient-purge path
is master-identical except the demote gate's own refusal (v10.15.0 —
the close-aware purge gate, the close-retained marker, and the cache
suppression are ALL retracted,
round-98 Codex 1-3; the "FULL MASTER PARITY" phrasing is corrected
v10.20.0, round-103 Codex 6 — only the purge DECISION and the
subsequent dispatch have parity; the local lookup runs BEFORE the
purge decision, so the gate's refusal of the closing-mark on an
anchorless peer-synced entry remains a deliberate documented delta,
§5.2 (iv)):** the site-3
invented-tuple harmlessness holds ONLY when the tuple is genuinely new
in this dispatch, and the honest terminal position for the
transient-purge class is that NO packet-level rule survives review
here. Six rounds (93-98) established that every deviation from master
on this path opens another layer of identity/lifecycle defects: the
close-aware retention needs a marker; the marker needs an
identity-safe lifecycle (shared lookup returns an unlocked clone,
`shared_ops.rs:482-505`; generation check and publication are
separate, `session_import.rs:42-60`; publication blindly replaces,
`shared_ops.rs:897-958`), must survive the worker-replica topology
(import fans to every worker, `session_import.rs:215-223`; the purge
removes the global row plus only the CURRENT worker's local row,
`promote.rs:167-207`, `shared_ops.rs:960-1013`), and must fence the
pre-existing ACK cache (a cached descriptor is consumed before
session resolution and HA import never invalidates,
`poll_descriptor/mod.rs:298-327`, `session_import.rs:115-223`). That
machinery IS the #6599 sync-identity fix in disguise, and it does not
belong in this plan. Accordingly: a closing packet on the
transient-purge class purges and dispatches EXACTLY as master
(flag-agnostic purge, retained-lookup forward, master's seed
transaction when cold — including the pre-existing purge-aftermath
family, §7), and the close-on-purged-provenance kill chain (close #1
purges; a SYN-bearing close #2 — WITH a warm next hop or a lapsed
transient seed, since a live cold seed captures the follow-up,
`shared_ops.rs:594-613`, round-102 Codex 7 — clean-misses and
FreshPrimary-installs
with closing seeded + Open, overwriting the peer's family) is
master's own behavior, documented in §7 as part of the #6599 class —
the harm vector is the identity-less Open, not the demote. The
`ReplacedSyncedLocal` skip STAYS (it is self-contained, has been
confirmed sound every round since 91, and displaces nothing): a
closing-flagged packet SKIPS the displacement —
`take_synced_local` never runs, the synced victim survives — and the
packet delivers locally without a cached session (the #4539
decline-delivery precedent; LocalDelivery consumes no SNAT
allocation, `poll_descriptor/mod.rs:1967`).
The victim flow's next legitimate NON-close packets dispatch
the master split: the first purges and — warm — forwards with the retained
lookup (no derivation/allocation/install — v10.11.0); a follow-up
cache-eligible packet may cache-hit (master's own behavior,
v10.17.0), and the ForwardFlow install with Open happens on the next
cache-missing packet's genuine clean miss — master's sequence
exactly. A genuinely-new
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
entry ages on its pre-refusal trajectory for the gate's own effects
(mark/refresh/re-queue — the scoping of v10.17.0/v10.18.0, round-100
Codex 6 + round-101 Codex 7); master's independent flag-agnostic purge
of a transient-purge-class entry is not a gate effect and still runs.
Ordinary
data/ACK packets continue to refresh normally through the unchanged
non-close path — with the §5.6 probation exception: a probation entry is
refreshed ONLY by a committed non-close packet at its commit hook
(never on an `OverdueSkipped` effective transition, v10.27.0) (and a
pre-admission materialize against it preserves its deadline while
adopting the shared decision/metadata, §5.6).

### 5.8 Signature/signature-shape changes (all crate-internal)

- `SessionEntry` gains the 40 B `TcpSeqAnchor` (§5.1) + `probation: bool`
  + the 8 B `fwd_companion_id` (v10.34.0, round-118 Codex 2 — the
  forward entry's STABLE `session_id`; a plain `u64` with 0 = UNBOUND —
  `alloc_session_id` never emits 0, `session/mod.rs:784-789` — so the
  sentinel costs nothing and `Option<u64>`'s 16 B tag+pad is avoided)
  (§5.6) — POD, `Copy`, no serde, never on the HA wire (the sync
  install/upsert paths zero/default both fields exactly as they do
  `established`-class local state today).
- `ForwardSessionMatch` gains the matched entry's `session_id` AND
  the forward family's close state (`closing`/`reset`)
  (`entry.rs:208-213`; v10.34.0, round-118 Codex 7; the close state
  v10.37.0, round-121 Codex 9 — the site-2b
  reactive synth's binding producer and inheritance source; a Local
  match carries the exact matched id + the pre-install re-probe
  snapshot; a Shared match reads the shared row's carried
  `tcp_flags` close bits AND the shared row's `session_id` as the
  expectation — the across-scopes wrapper discards both
  today, `shared_ops.rs:638-665`; the materialize-adopt of that
  shared forward adopts the same wire id (the r119-5a completion), so
  the expectation verifies once the forward materializes locally; a
  legacy zero-id row synthesizes expectation 0 (UNBOUND)).
- The reverse entry's `fwd_companion_id` stores the EXPECTED family
  id, verified PER HOP (v10.37.0, round-121 Codex 5 — the expectation
  IS the binding; there is no promote-time bind step): the install/
  upsert paths gain the expectation input (`SessionInstall` and the
  synced constructors carry it, `ctx.rs:27-49`,
  `session_glue/commands/upsert_synced.rs:64-79`); every
  reverse→forward hop compares the probed forward's id against the
  stored expectation plus key+NAT — a match writes the anchor sample,
  a mismatch or a 0 expectation suppresses. `SyncedSessionEntry` gains
  `expected_fwd_id: u64` stamped at synthesis from the forward row's
  id (`shared_ops.rs:750-785`; in-memory + worker-command carriage
  only, no wire change; the tunnel `UpsertLocal` class carries 0 →
  permanent UNBOUND, round-120 Codex 8).
- `MatchedToken` (v10.33.0/v10.34.0, §5.6): `{ key: SessionKey, nat:
  NatDecision, is_reverse: bool, session_id: u64, source: MatchSource,
  transition: Option<TokenTransition> }` — 96 B, the `Option` niche-
  filling on `MatchSource`; carried by the resolution result, the
  per-descriptor `matched_token` slot, and the cache entry.
- The commit-side carrier (v10.35.0, round-119 Codex 1/2; the
  two-handle shape + the postblock v10.36.0, round-120 Codex 1/2): the
  early identity check resolves the canonical slab HANDLE (plus the
  matched-reverse handle for a reverse-direction binding); the
  handle(s) ride
  the descriptor's existing commit scratch (`Copy`, no borrow
  crossing); every authority mutation re-validates at its own apply
  point (`entries.get` + primary-key/identity compare — the codebase's
  own stale-handle guard pattern). The ANCHOR apply's final-admission
  point is the COMMON SUCCESS-ONLY POSTBLOCK (`!recycle_now` at
  `flow_cache_hit.rs:549-552`; both success arms converge there); a
  construction failure keeps `recycle_now` set and recycles without
  the apply. AND every session-table install/upsert/overwrite at key K
  invalidates K's exact-query-key flow-cache slot (round-120 Codex 3 —
  the precedence-winner rule; the existing helper
  `flow_cache.rs:1105-1120` + the sibling fan-out accumulator).
- The capacity-corner accounting fallback (v10.35.0, round-119 Codex
  7): the close-accept path carries the validated forward handle as a
  fallback target to master's accounting chokepoint
  (`poll_descriptor/mod.rs:3478-3503`); it fires only when the
  reverse-key probe was absent, charging real length/DSCP/disposition
  with the `observed_tcp_flags` fold.
- The import breadcrumb (v10.35.0, round-119 Codex 3) is SUPERSEDED by
  the carried expected id (v10.36.0, round-120 Codex 4) and the
  promote-time bind is SUPERSEDED by per-hop verification (v10.37.0,
  round-121 Codex 5): FIFO
  adjacency is not a family proof (prewarm enqueues all forwards then
  all reverses, `shared_ops.rs:345-418`; singletons queue
  independently, `session_glue/mod.rs:838-848`), so the reverse entry
  carries `expected_fwd_id` stamped at synthesis from the forward
  row's id; the expectation is stored in `fwd_companion_id` at install
  and every hop verifies the probed forward's id against it (never
  the occupant; nothing extra happens at promote).
- `update_session` gains the identity-replacement branch (v10.35.0,
  round-119 Codex 4; the discriminator v10.37.0, round-121 Codex 4 —
  the `(nat, is_reverse)` compare is REPLACED because an exact
  tuple/NAT reincarnation has identical values yet is the ABA case):
  the `SessionUpdate` gains the incoming family id (the promote/synced
  callers pass the synced row's / shared entry's `session_id`,
  `ctx.rs:62-70`,
  `session_glue/promote.rs:99-107`; a LOCAL real-traffic refresh
  caller passes the entry's OWN current id — always equal, always the
  in-place branch, so the hot refresh path is unchanged); the update
  compares it against
  the stored `session_id` — EQUAL (plus key) is a same-family refresh:
  update in place, id and authority state preserved (a legitimate
  NAT/orientation refresh rides the existing reindex,
  `session/mod.rs:1344-1463`); DIFFERENT — or an incoming 0, which
  fails closed — is a different-family replacement and runs
  `remove_entry` + FULL INSTALL
  semantics — id re-mint or adopt the incoming non-zero id, anchor
  zeroed (absorbing), gated
  `closing`/`reset`/`established` seed from the update's flags,
  `probation` cleared, `fwd_companion_id` zeroed — so none of K's
  authority/lifecycle state rides onto S2.
- The id replication-invariance completions (v10.35.0, round-119 Codex
  5): the SharedPromote shared-replica republication
  (`session_glue/promote.rs:116-138`), the local-origin shared
  publishes, and the HA bulk export (`ha/export.rs:143-165`) populate
  the entry's REAL `session_id` (the #5212 wire field already exists —
  behavior completion, not a format change); a zero wire id on a
  re-import ALWAYS fresh-mints (v10.36.0, round-120 Codex 6 — the
  preserve-on-zero clause retracted: no same-incarnation evidence rides
  the command, `upsert_synced.rs:64-79`).
  `SyncedSessionEntry` gains `expected_fwd_id: u64` (v10.36.0,
  round-120 Codex 4 — stamped at reverse synthesis from the forward
  row's id, `shared_ops.rs:750-785`; in-memory + worker-command
  carriage only, no wire change; the tunnel `UpsertLocal` class carries
  0 → UNBOUND-absorbing, round-120 Codex 8).
  `alloc_session_id` gains the skip-on-collision wrap guard
  (round-119 Codex 9) and the hi-word gains a node-discriminator bit
  (`(worker_id & 0x7FFF) << 49 | (node_id & 1) << 48`; #6311 pulled
  in, round-119 Codex 5b) with the producer threaded explicitly
  (v10.36.0, round-120 Codex 7): `set_worker_id(worker_id)` becomes
  `set_identity(worker_id, node_id)` (`session/mod.rs:766-789`), the
  PHYSICAL node id read from `/etc/xpf/node-id` (0 standalone — NOT
  role state, which flips at failover), threaded through worker setup
  (`worker/loop_body/setup.rs:131-135`). No
  production consumer decodes the hi word — the only `id >> 48`
  decoders are the test assertions (`session/tests.rs:366-374`,
  `:394-448`), which migrate with the new layout.
- The site-2b installer gains the effective-flags inheritance
  (v10.35.0, round-119 Codex 6; extended v10.36.0, round-120 Codex
  9/10): a synth against a closing-marked
  forward family computes the effective flags (driving packet's flags
  OR the family close bits) and that ONE value drives the installer's
  timeout/`closing`/`reset`/`observed_tcp_flags` computation AND the
  publish/replication — for EVERY synth against a marked family,
  including close-flagged retries (RST→FIN and FIN→RST both merge to
  the family's `closing`+`reset`, so a late FIN against an RST-marked
  family is born on the 2 s clock, never the 30 s one). The same
  close-bit merge governs the sibling's shared-hit MATERIALIZATION
  (`session_glue/mod.rs:1092-1115` uses the new packet's raw flags
  today): the materialize merges the replica's carried `tcp_flags`
  close bits over the packet's raw flags, so a published closing/reset
  replica can never be reconstructed alive by a bare-ACK
  materialization in the publish→replication window; raw packet flags
  still drive screens/cache/accounting.
- The capacity-corner accounting chain (v10.36.0, round-120 Codex
  11/12 — full producer/carrier/consumer): the site-2b return becomes
  a typed `Site2bOutcome ::= Installed | ValidatorRefused |
  CapacityRefused` (replacing the bare `bool`,
  `shared_ops.rs:824-895` — validator refusal and accepted capacity
  refusal are distinguishable); the close-accept path produces
  `Option<ValidatedTarget { handle, key, nat, id }>` — `Some` ONLY on
  an accepted close whose reverse install capacity-refused; the
  resolution shape gains the optional fallback field
  (`shared_ops.rs:563-578`); the poller initializes it `None` per
  descriptor and hoists it past the `resolved.decision` reduction
  (`poll_descriptor/mod.rs:509`, `:883`, the `install_failed`
  precedent); `account_packet` gains a `-> bool` charged return
  (additive); the master's accounting chokepoint
  (`poll_descriptor/mod.rs:3478-3503`) fires the fallback ONLY when
  `account_packet` returned `false` AND the fallback is `Some` AND
  the handle re-validates — mutually exclusive by construction — and
  the "exactly one `rev` charge" invariant is scoped to
  accounting-eligible forwarded dispositions
  (`ForwardCandidate | FabricRedirect`): LocalDelivery, host-denial,
  MissingNeighbor, and earlier exits charge nothing on either path
  (master parity).
- `tcp_seg_view()` (§5.3) — new helper in `frame/tcp.rs`.
- `close_seq_plausible()` (§5.4) — new pure function in `session/`.
- `account_packet` keeps #2501 counter placement and gains one
  additive `-> bool` charged return (v10.37.0, round-120/121 Codex 11 —
  the "UNCHANGED" wording is corrected): counters stay exactly where
  #2501 put them
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
  preserving only `last_seen_ns`/`expires_after_ns`/`probation` (the
  preserved list SHRUNK v10.38.0, round-122 Codex 4: the adopted
  entry's `closing`/`reset` come from S2's trusted replica bits — the
  exact-seed rule — NEVER carried over from K: K-alive→S2-RST must not
  resurrect S2 alive, and K-closing→S2-alive must not transfer stale
  close authority across identities; the current upsert derives
  timeout/closing/reset entirely from the supplied flags,
  `install.rs:382-400`, so the adopt passes S2's effective seed as
  those flags) (v10.7.0, round-89 Codex 2 + round-90 Codex 3 — §5.6).
- The materialize/promote family-id transport (v10.38.0, round-122
  Codex 5/6/7): the `MaterializeReport` gains `family_id: u64` (the
  shared entry's id — materialization consumes `resolved.shared_entry`,
  `session_glue/mod.rs:1092-1119`, and the report previously carried
  no family id); the promote's `SessionUpdate` carries BOTH the
  incoming family id (= the report's `family_id`) AND, for a reverse
  entry, the incoming `expected_fwd_id` (the shared reverse row's
  stamped expectation) — the different-family replacement branch
  seeds `fwd_companion_id` from the update's expectation (a forward's
  is 0), never blindly zeroes it (the shared-reverse-S2 → refused-over-
  K → promote path keeps its family proof, `install.rs:310-315`,
  `session_glue/mod.rs:1235-1252`, `promote.rs:99-107`); a successful
  zero-wire-id upsert surfaces its final freshly minted id on its
  outcome so downstream classification never reads a stale table id;
  and EVERY promotion sources the final trusted `closing`/`reset` from
  the LIVE post-transition entry (in hand at promote — not from the
  report, not from raw flags, and NOT `observed_tcp_flags`, which
  accounting deliberately ORs refused raw closes into,
  `session/mod.rs:1177-1210`) and publishes THAT, so a probation-
  delayed promote of a closing replica can never republish it
  ACK-only; raw flags govern promote eligibility/accounting only. The
  SharedPromote republication reads the final entry's fields back
  (expectation included) rather than constructing the replica from
  its arguments (`promote.rs:116-140`).
- The transient-purge DECISION and dispatch are master-identical
  (v10.15.0, round-98 Codex 1-3 — the close-aware gate, the
  close-retained marker, and
  the marker-conditioned cache suppression are all retracted: the
  marker's identity-safe lifecycle, cross-worker topology, and
  pre-existing-cache fencing requirements ARE the #6599 sync-identity
  fix in disguise and do not belong in this plan; the 'FULL MASTER
  PARITY' phrasing is corrected v10.21.0, round-104 Codex 7 — the
  lookup marks and propagates before the purge decision,
  `lookup.rs:105-128`, `:198-218`, `session_glue/mod.rs:1157-1197`,
  so the gate's refusal on anchorless peer-synced entries remains the
  deliberate documented delta, §5.2 (iv)). The
  `ReplacedSyncedLocal` constructor branches on closing flags BEFORE
  `take_synced_local` (v10.8.0, rounds 89-91 Codex, confirmed sound
  every round since — §5.6 site-3
  supplement): a closing-flagged packet (SYN-bearing included, which
  #4400 does not reject) purges EXACTLY as master (v10.15.0 — the
  close-aware retention is retracted, round-98 Codex 1-3;
  flag-agnostic purge, retained-lookup forward, master's seed
  transaction when cold) and never displaces
  the synced victim (`ReplacedSyncedLocal` — deliver locally, no
  install). The purged-packet dispatch itself is MASTER-SPLIT
  (v10.13.0, rounds 94-96 Codex — the v10.4.1 re-entry is retracted):
  the packet continues the HIT branch on the retained lookup
  (`session_glue/mod.rs:1194-1196`) — warm next hop: forward, no
  install, master's own cache behavior (a purged pure-ACK remains
  cache-eligible and is inserted normally, `flow_cache.rs:352-394`,
  `poll_descriptor/mod.rs:3900-3959` — full parity, v10.15.0); cold:
  master's own seed transaction; the ForwardFlow install/Open happen
  on the next cache-missing packet's genuine clean-miss dispatch with
  a fresh derivation (master's sequence exactly, v10.17.0).
- Expiry/HA: the probation deadline fence (v10.6.0, round-89 Codex 3 —
  §5.6) touches `expire.rs`'s retention gate (probation bypass) and
  `refresh_for_ha_transition` (deadline preserved); companion
  propagation skips probation targets (v10.7.0, round-90 Codex 4) and
  the accepted-mark rule skips a probation MATCHED entry (v10.8.0,
  round-91 Codex 3).
- **`MaterializeReport` / `OverdueSkipped` — the full normative
  contract (v10.25.0, rounds 98-108 Codex; this bullet is the SSOT —
  every earlier summary paragraph is superseded):**
  - **Fields (v10.21.0, round-104 Codex 1 — two FIELDS, no precedence
    question):** the validation verdict and the transition result are
    SEPARATE fields, because a closing shared materialization is
    validator-refused AND independently adopts / skips / fails:
    `validation: Option<CloseValidation> ::= None |
    Accepted | Refused` (the site-2c close-validator verdict — present
    only when the driving packet was closing-flagged) and
    `transition: TransitionResult ::= None | Installed |
    AdoptedPreservingDeadline | UpsertRefused | OverdueSkipped`
    (defined in `session_glue/`). `(Refused, Installed)` is the
    site-2c refuse-install (the alive probation entry IS installed and
    CAN displace a canonical predecessor; the displaced set carries
    that family). `UpsertRefused` — the synced upsert's
    NON-PEER-PREDECESSOR refusal (`install.rs:310-315`; the capacity
    refusal belongs to the FRESH-install path, `install.rs:123-125`,
    not to the synced upsert, which has no capacity check): at the
    failed-upsert instant the local row is NOT replaced (the non-peer
    predecessor survives unmodified AT THAT INSTANT — the same
    resolve's promotion attempt MAY still overwrite/publish/replicate
    it, `promote.rs:99-139`, and the ordinary allowed accounting can
    mutate its counters/flags, `session/mod.rs:1177-1210`), the
    dispatch carries S2's decision for forwarding (the DECISION is
    forwarding-only), and `UpsertRefused` gates the SAME authority
    consumers as `OverdueSkipped` (teardown/cache/commit — the table
    state and the dispatch's decision identity diverge, so a teardown
    under S2's identity would delete the predecessor's family,
    `session_glue/mod.rs:477-581`); the note that today's materializer
    ignores the upsert's false and returns S2 anyway
    (`session_glue/mod.rs:1098-1119`) is what the outcome makes
    explicit.
  - **Producer (v10.24.0, round-107 Codex 1 — valid BY CONSTRUCTION):**
    `materialize_shared_session_hit`
    (`session_glue/mod.rs:1092-1121`) returns
    `(SessionLookup, MaterializeReport)` where
    `MaterializeReport { site: Option<MaterializeSite>,
    validation: Option<CloseValidation>,
    transition: TransitionResult, displaced: DisplacedSet,
    effective_transition: Option<TransitionResult> }` (v10.27.1,
    round-110 AGY 1/3 — the field is in the declaration with its
    explicit `Option` type: `transition`'s `None` is the
    `TransitionResult` enum variant, while `effective_transition`'s
    unset state is `Option::None`; `MaterializeReport::NONE` sets
    `transition = TransitionResult::None` and
    `effective_transition = None`). **The total invariant (normative,
    v10.28.0, round-112 Codex 3):** `site=None →
    effective_transition=None`; legal site-2c `T →
    effective_transition=Some(T)`; invalid site-2c →
    `Some(OverdueSkipped)`; `Some(TransitionResult::None)` never
    occurs (the effective value is either unset or a real
    transition); and the refusal promotion gate is site-qualified
    (a malformed `site=None, validation=Some(Refused)` report follows
    master's own dispatch and never reaches the site-2c gates).
    §9 tests the invariant. The
    materialize computes the validation verdict (from the packet +
    anchor) and the overdue check (from K's timing) BEFORE calling the
    state-changing upsert (`install.rs:310-322`, `:345-400` may remove
    K, install S2, seed flags, rebuild indexes) and selects the
    transition action from the verdict+overdue decision first —
    out-of-product combinations are UNREACHABLE because the producer
    cannot create them (no normalize-after that could not undo
    mutations). The report is available BEFORE the promotion attempt
    (`session_glue/mod.rs:1235-1253` runs immediately after
    materialization; `promote.rs:99-139`), and the promotion path
    gains an explicit gate: `report.effective_transition ==
    Some(OverdueSkipped)`
    suppresses the promote and the commit-time refresh INDEPENDENTLY
    of K's probation flag (`promote.rs:86-107` gates only on
    origin/disposition today), and a `(report.site == Some(Site2c) &&
    validation == Some(Refused))` report suppresses the promote per
    §5.5's rule 5 (the refusal gate is site-qualified, v10.29.0,
    round-113 Codex 6 — a malformed `site=None, validation=
    Some(Refused)` report follows master's own dispatch and never
    reaches the site-2c gates).
    `site` is the materialization discriminator (`Some(Site2c)` only
    from the site-2c materialize; `None` on every non-materializing
    path) — consumers can therefore distinguish an erroneous site-2c
    `(None, None)` from a valid local hit. The producer additionally
    writes ONE derived `effective_transition` (v10.26.0, round-109
    Codex 2): the validated transition after the by-construction
    invariant — every consumer, INCLUDING the pre-resolved-result
    promotion, reads the effective transition, never the raw fields
    (an invalid `(Some(Site2c), Accepted, Installed)` would otherwise
    satisfy neither the transition gate nor the rule-5 gate and could
    reach promotion, `promote.rs:86-139`; the effective transition of
    an invalid site-2c report is `OverdueSkipped`).
  - **Fields:** `ResolvedFlowSessionDecision`
    (`shared_ops.rs:563-578`) gains the whole
    `report: MaterializeReport`, initialized `MaterializeReport::NONE`
    (site None, validation None, transition None, displaced empty,
    effective_transition None — v10.27.0, round-110 Codex 1) at
    BOTH constructors (`session_glue/mod.rs:1254-1261` and
    `:1330-1344`) and set from the materializer's OUT report. There is
    NO separate `displaced` field anywhere else.
  - **The legal Phase-1 product (normative):** `(None, None)` for
    non-materializing paths; `(None, T)` for a non-close site-2c
    materialization; `(Refused, T)` for a closing site-2c
    materialization, with `T ∈ {Installed, AdoptedPreservingDeadline,
    UpsertRefused, OverdueSkipped}`. `Accepted` has NO Phase-1
    producer (every site-2c close refuses, §5.6); site 2b is OUTSIDE
    the report entirely and retains its existing install-outcome
    booleans (`reverse_installed`/`install_failed` report
    INSTALLATION SUCCESS ONLY — validator refusal and
    accepted-but-capacity-refused both surface as
    `reverse_installed=false, install_failed=true`,
    `shared_ops.rs:824-895`, `session_glue/mod.rs:1264-1284`,
    `:1330-1344`). The consumer-side fail-closed fallback applies ONLY
    to `Some(Site2c)` reports (v10.24.0, round-107 Codex 2): a
    site-2c report whose combination is outside the legal product
    (unreachable by construction) is read as `OverdueSkipped`; an
    impossible `site=None` report follows master's own dispatch —
    treating it as `OverdueSkipped` would force a purged retained
    lookup's MissingNeighbor into the buffer-only arm and replay a
    RELEASED tuple (`poll_descriptor/mod.rs:5057-5068`,
    `neighbor_dispatch.rs:272-292`).
  - **Carriage:** the poller reads `resolved.report` at the
    `install_failed` hoist (`poll_descriptor/mod.rs:509`) and stores
    it on the per-descriptor dispatch context that survives the
    `resolved.decision` reduction (`:883`); consumers read the
    dispatch context — and EVERY consumer read of the transition is
    `report.effective_transition` (v10.27.0, round-110 Codex 1:
    promotion, the poller carriage, the MissingNeighbor composition,
    the teardown guards, the cache-insert suppression, and the commit
    hooks all name the derived field, never the raw `transition`;
    `effective_transition` is a carried struct field initialized in
    `NONE` and written by the producer). The pre-hoist policy-counter fallback
    (`poll_descriptor/mod.rs:487-509`, `lookup.rs:345-354`) attributes
    the packet to the SURVIVING entry's rule when S2 lacks a bound
    counter — master's own fallback semantics, explicitly ACCEPTED
    for the divergent transitions (telemetry-only; stated exactly:
    `bound_policy_counter_for` deliberately does not mirror
    forward-wire matching, `lookup.rs:335-354`, so on a forward-wire
    placeholder substitution, `shared_ops.rs:614-626`, it can miss
    the survivor and use S2's positional counter instead — still
    telemetry-only, no authority change).
  - **Consumers (five, normative — the establishment promote was the
    sixth only in v10.29.x and is REMOVED in v10.30.0 via the
    round-114 Codex 1 mutual-exclusion proof in bullet (vi) below):
    (i) the terminal teardown at
    ALL THREE sites (`poll_descriptor/mod.rs:698-714`, `:768-784`,
    `:824-840`) is SKIPPED for `OverdueSkipped` AND for `UpsertRefused`
    (for the skip the dispatch installed and changed nothing; for the
    refusal the surviving non-peer predecessor and S2's identity
    diverge — in both cases teardown would otherwise derive
    companions, remove state, release NAT, and publish deletes under
    S2's identity, `session_glue/mod.rs:477-581`); (ii) the anchor
    commit hook does NOT write; (iii) the flow-cache insert
    (`:3900-3959`) is suppressed; (iv) the probation clear+refresh
    NEVER fires on an overdue entry; the commit-time refresh checks
    `report.effective_transition == Some(OverdueSkipped)` AND —
    independently, because an overdue probation entry can be reached
    through an ordinary LOCAL hit that never materializes (the
    canonical packet finds K locally, no `shared_entry`, no
    materialization, `MaterializeReport::NONE`,
    `shared_ops.rs:594-635`, `session_glue/mod.rs:1092-1121`;
    reachable because expiry is strict and the GC is periodic,
    `expire.rs:130-168`) — the commit hook ALSO checks the MATCHED
    ENTRY directly: `entry.probation &&
    entry.last_seen_ns.saturating_add(entry.expires_after_ns) <=
    now_ns` suppresses the clear+refresh on ANY path (v10.28.0,
    round-112 Codex 1; the phase-shifted direct-local-hit regression
    is in §9). The matched-entry identity is alias-safe AND
    replacement-safe (v10.30.0, round-114 Codex 2/3): the commit hook
    receives an OPTIONAL identity-bound matched-session token — a
    NAMED struct (v10.33.0, round-117 Codex 1; the discriminator and
    the provenance split v10.34.0, round-118 Codex 2/3):
    `MatchedToken { key: SessionKey /*canonical*/, nat: NatDecision,
    is_reverse: bool, session_id: u64, source: MatchSource,
    transition: Option<TokenTransition> }` — the identity discriminator
    is the STABLE `session_id` (write-once, `session/mod.rs:460-470`;
    promotion preserves it, so a pure ownership promote no longer
    spuriously evicts live cache entries the way an epoch discriminator
    would; a NAT/orientation-changing `update_session` still mismatches
    on those fields and evicts, and a same-key replacement mints a
    distinct id and evicts) — with ORTHOGONAL provenance fields
    (round-118 Codex 3: source and transition are different axes — a
    shared forward-wire hit can materialize and then promote before the
    final token is constructed, `shared_ops.rs:614-635`,
    `session_glue/mod.rs:1194-1254`, so a single enum either lost the
    forward-wire marker or left the final-token semantics undefined):
    `source: MatchSource ::= Canonical | ReverseTranslated |
    ForwardWire | FreshInstall` is set at the MATCH and is STICKY
    (never overwritten by a later transition — the forward-wire
    class's no-anchor-learn rule reads `source == ForwardWire`
    regardless of a subsequent materialize/promote), and
    `transition: Option<TokenTransition> ::= Materialized | Promoted`
    records the final transition outcome (the final-identity fields
    come from the promote/materialize OUT, the v10.31.0
    final-post-promotion-identity rule) — the tuple-only type could
    not encode the source, and resolution discards it when a
    `ForwardSessionMatch` becomes a canonical lookup,
    `entry.rs:208-213`, `lookup.rs:253-292`,
    `shared_ops.rs:507-560`) — a DISTINCT field, never
    a replacement of the packet-query key
    (`FlowCacheEntry.key`/`flow.forward_key` must stay the query key:
    hashing, lookup, and dedup all use it, `flow_cache.rs:578-581`,
    `:962-989`, `:1046-1065`). Producers (v10.31.0, round-115 Codex
    2/3 — EVERY successful install/adopt path returns its FINAL
    token): the lookup return carries the token (the lookup resolves
    the alias and captures the canonical `actual_key`, `lookup.rs:62-68`,
    `:85-102`, `:194-219`,
    today discarded on return); the fresh ForwardFlow install gains an
    OUT token (it returns only `bool` and creates its epoch internally
    today, `install.rs:139-152`, `poll_descriptor/mod.rs:2449-2458`)
    — and ONE per-descriptor `matched_token` slot (v10.32.0,
    round-116 Codex 3) on the dispatch context carries it from the
    producer to the cache construction: initialized EMPTY per
    descriptor, set from EITHER the final resolved token (hit/
    materialize paths) OR the fresh forward install's OUT (the
    fresh-miss path has no `ResolvedFlowSessionDecision`,
    `poll_descriptor/mod.rs:2449-2458`, `:3900-3959`), and a later
    reverse-companion install's token NEVER overwrites it;
    the reverse synthesis returns it (currently `(SessionLookup,
    bool)`, `shared_ops.rs:824-895`); the forward-wire match carries
    the MATCHED entry's stable id (`lookup.rs:258-292`, `entry.rs:208-213`);
    the materialize returns the installed identity; a FORWARD-WIRE
    match's token carries `source = ForwardWire` (the no-anchor-learn
    marker — v10.32.0,
    round-116 Codex 6: that class's anchors advance from the reverse
    mutable-alias direction only — the commit hook's anchor write is
    suppressed for forward-wire-produced tokens while the
    clear/refresh/mutation semantics stay; the resolution currently
    collapses a forward-wire hit into ordinary `Canonical` resolution
    without retaining a source discriminator, `lookup.rs:253-292`,
    `shared_ops.rs:507-560`, `:594-635`, so the token carries the
    match source explicitly — and the source field is STICKY across a
    later materialize/promote transition, v10.34.0 round-118 Codex 3);
    and the RESOLVED
    RESULT carries the FINAL post-promotion identity (the promotion
    can change NAT/orientation — and advances the node-local
    `install_epoch`, which the token no longer carries,
    `session/mod.rs:1344-1397` — and runs before the resolved result is
    constructed, `session_glue/mod.rs:1157-1261` — the promote's OUT
    reports the final identity (key/NAT/orientation + the PRESERVED
    stable id) and the constructor uses THAT, so the
    current packet's commit hook and newly cached entry never fail
    their own validation). The resolution result and the
    flow-cache entry each gain the optional field (§6's
    'no FlowCacheEntry change' claim is corrected — the field is
    additive and cache-internal; the footprint is stated in §8); the
    poller hoists it past the
    `resolved.decision` reduction (`poll_descriptor/mod.rs:509`,
    `:883`). Purged/sessionless resolves carry `None`. The commit
    hook (and the cache-hit re-probe) runs a DEDICATED ATOMIC
    compare-then-mutate helper (v10.31.0, round-115 Codex 4): FIRST
    compare (canonical key, NAT, orientation, stable id), mutate only on
    agreement — the plain `lookup_with_origin` mutates close state,
    timestamps, timeout, companion state, and the wheel before
    returning (`lookup.rs:105-218`), and the existing
    `touch_if_stale` (`flow_cache_hit.rs:295-301`,
    `session/mod.rs:1118-1133`) is covered by the same guard. The
    cache-hit ORDERING is specified (v10.32.0, round-116 Codex 4): an
    identity-ONLY check runs immediately after the existing cache
    validity evaluation (which ends around `flow_cache_hit.rs:133`)
    and BEFORE any cached-decision consumer (TTL handling,
    filter/policy counters, policers, logs, reject synthesis, the
    terminal drop — `:94-180`, `:189-271`) — a mismatch EVICTS and
    falls through to a fresh resolution there (never double-accounts,
    never consumes a stale decision); the commit-side mechanics are
    the CARRIED VALIDATED HANDLE (v10.35.0, round-119 Codex 1/2 — the
    v10.34.0 "rides master's `touch_if_stale`/`account_packet` borrows"
    phrasing is RETRACTED: those helpers encapsulate their borrows,
    return `()`, and take neither token nor segment view,
    `session/mod.rs:1118-1133`, `:1177-1210`; and their first probe is
    the exact-key `record_by_key[_mut]`, `:1022-1064`, which a
    reverse-translated or forward-wire query key may MISS): the early
    identity check at `flow_cache_hit.rs:~133` resolves the token's
    canonical key to the slab HANDLE and validates identity
    (key+NAT+orientation+id); the handle — a `Copy` slab index, no
    borrow crosses anything — rides the descriptor's existing commit
    scratch; EVERY authority mutation (the probation clear, the
    promote-at-commit, and the anchor apply) re-validates the handle
    at its own apply point (`entries.get(handle)` + the primary-key
    and identity compare — an L1 array index and ~93 B of compares,
    NO re-hash probe — the stale-handle/primary-key guard pattern is
    the codebase's own, `install.rs:127-138`) and mutates only on
    agreement (the two-handle shape, v10.36.0 round-120 Codex 2: one
    handle cannot cover a reverse-direction hit — the matched entry R
    hosts the probation/identity operations while the anchor and the
    close mark target F; the carrier holds `family_handle` (canonical
    forward) plus, when the token's orientation is reverse,
    `matched_handle` (the matched reverse entry) — the family hop's
    second lookup exists on master, `session/mod.rs:1183-1205`, so a
    reverse-direction check resolves both, a forward-direction check
    one; AND `family_handle` is an OPTION, v10.37.0 round-121 Codex 8:
    a reverse whose stored expectation is 0 (UNBOUND-absorbing — the
    tunnel class, a Shared synth, a refused-forward import) has NO
    trustworthy forward to resolve, so `family_handle = None` and ALL
    forward-family authority (the anchor hop, the close mark) is
    suppressed while the matched-R operations proceed — never an
    occupant capture; a non-zero expectation resolves the derived
    forward key and sets `family_handle = Some` ONLY when the probed
    entry's id equals the stored expectation (plus key+NAT) — a
    per-hop verification, not a bind). The ANCHOR APPLY runs at the COMMON SUCCESS-ONLY POSTBLOCK
    (v10.36.0, round-120 Codex 1 — the v10.35.0 ":507-548 success arm"
    named only the fallback request arm; the dominant in-place rewrite
    arm enqueues `pending_tx_prepared` and clears `recycle_now` at
    `:444-497`, SKIPPING the fallback block): both success arms
    converge on the `recycle_now` flag, so the apply runs iff
    `!recycle_now` at the recycle point (`:549-552`) — a packet whose
    rewrite/request construction FAILED on both arms still has
    `recycle_now` set, is recycled WITHOUT the apply, and never
    advances the trusted anchor. The per-arm admission rule (v10.38.0,
    round-122 Codex 1 — the v10.37.0 "TX-pipeline admission"
    redefinition is SUPERSEDED; §5.2's wire-commit semantics always
    outranked it): the IN-PLACE arm's apply runs at the postblock (the
    `pending_tx_prepared` push IS the admission — nothing between it
    and the TX loop drops); the FALLBACK request arm carries an
    optional authority payload (validated handle + seg summary +
    identity) on the `PendingForwardRequest`, and the apply fires at
    the request's dispatch-admission success — the redirect-inbox
    overflow and build-failure discards report via the mandatory API
    (`umem/mod.rs:1290`) and SKIP the apply (§5.2's mandatory
    no-learn, unchanged; the dispatch paths,
    `worker/lifecycle.rs:209-281`, `tx/dispatch/mod.rs:512-573`,
    `:1378-1397`, `umem/mod.rs:1257-1321`). With geometry hoisted
    before every apply point, an attacker-chosen-geometry packet never
    reaches an apply; a landed-then-dropped sample cannot be CHAINED
    (a blind attacker never learns which guess landed, and each
    continuity slide requires the previous one); and an overrun can
    only turn a later legitimate close into a fail-closed refusal
    (bounded lingering, §2).
    `touch_if_stale`/`account_packet` at `:295-317` stay
    MASTER-VERBATIM (#2501 telemetry, not authority state).
    Same-worker single-threaded, no
    expire/GC pass interleaves within one descriptor's processing (the
    reap runs per loop body, `worker/loop_body/mod.rs:1481-1521`
    branch-base / `:1615` master), so a validated handle cannot go
    stale mid-packet — the re-validation is the belt, not the
    suspenders. The early identity check is the added hash probe per
    session-backed hit — ONE for a forward-direction binding, TWO for
    a reverse-direction binding (the canonical probe plus the
    matched-reverse probe, the latter same-key with master's own
    `:295-317` reverse probes, hence warm) — probing the token's
    CANONICAL key:
    same-key and warm with master's `touch_if_stale` probe ONLY for a
    plain non-translated forward hit; reverse and translated hits probe
    a distinct canonical key (`FlowCacheEntry.key` stays the packet
    query key, `flow_cache.rs:578-585`; the translated/forward-wire
    indexes are distinct, `lookup.rs:62-102`, `:253-292`), with
    `account_packet`'s forward-derive re-touching that line warm later
    in the same hit. The consumers between the check and the commit
    region (`:137-290`: TTL/TE, filter counters, policers, logs, BA
    reclassify) never touch the session table (verified by inspection),
    and master's own `:295-317` calls update only timing/counters —
    never key/NAT/id identity fields (round-120 Codex 2's confirming
    trace) — so the identity established at the early check still
    holds at the apply points. AND the precedence rule (v10.36.0,
    round-120 Codex 3; the full-family shape + producers v10.37.0,
    round-121 Codex 2/3): validating the cached BACKING entry does not
    prove it is still the query's current resolution WINNER (a direct
    primary entry at the query key outranks a reverse-translated
    alias, `lookup.rs:62-68`; an ordinary local match outranks
    forward-wire/shared, `shared_ops.rs:602-635`; a worker
    `UpsertSynced` installs WITHOUT flow-cache invalidation,
    `session_glue/commands/upsert_synced.rs:64-120`) — so EVERY
    session-table install/upsert/overwrite invalidates the COMPLETE
    accepted-query alias FAMILY of the affected identity — old AND new
    (canonical, reverse companion, reverse-translated, reverse-wire,
    and forward-wire query aliases, the site-2c displaced-family set,
    `session/mod.rs:1895-1948`; the consumers,
    `lookup.rs:62-68`, `:222-250`, `:253-320`) — exact-key-only
    invalidation (`flow_cache.rs:1105-1120`) would leave a stale
    descriptor active on a NEWLY-outranked alias Q. The producer/
    carrier mechanics are specified (round-121 Codex 3; the carrier
    made concrete v10.37.0; the drain topology corrected v10.38.0,
    round-122 Codex 2 — `poll_binding` regains control only AFTER the
    whole RX batch returns, `poll_descriptor/mod.rs:110-131`,
    `worker/lifecycle.rs:209-225`, so a poll-binding-level "before the
    next descriptor" drain cannot happen): the `SessionTable` gains a
    drainable
    `pending_invalidations` buffer (the `drain_deltas` precedent,
    `session/mod.rs:1676-1690` — the table owns the buffer and the
    install/upsert/overwrite paths push the affected alias family into
    it, so the `bool`-returning sites keep their signatures); the
    drain runs at THREE points: (i) INLINE, current-binding — the
    descriptor's own dispatch drains the buffer to the CURRENT
    binding's caches immediately after any install/upsert/overwrite
    within that descriptor's processing (the dispatch owns the binding
    context), and the invalidation is ordered BEFORE the descriptor's
    own cache construction (a delayed new-family invalidation can
    never evict the descriptor's freshly cached S2 — the
    invalidate-first-then-cache order is asserted, §9); (ii)
    POST-BATCH, sibling bindings — the `WorkerScratch` accumulator
    fans out to the sibling caches after the batch (the existing SSOT,
    v10.22.0); (iii) LOOP-TOP, command path — the worker-command
    installs (`UpsertSynced`/`UpsertLocal`,
    `session_glue/mod.rs:649-705`, `worker/loop_body/mod.rs:682-717`)
    accumulate into the same table-side buffer during the command
    drain, and the worker fans the buffer across ALL of its bindings
    (left+right, `worker/lifecycle.rs:53-55`) at loop top AFTER the
    command drain and BEFORE the next RX batch (command-rate-bounded,
    never packet-rate). The invalidated FAMILY is complete (v10.38.0,
    round-122 Codex 3): canonical, reverse-canonical (the companion),
    reverse-wire, reverse-translated, AND forward-wire query aliases —
    reply matching accepts both reverse shapes (`key.rs:19-26`) and
    both are separately indexed (`session/mod.rs:1920-1933`) and
    consumed (`lookup.rs:222-250`); the buffer records the OLD family
    at REMOVE time (`remove_entry`/`take_synced_local` push the
    predecessor's family — LocalDelivery removes K before invoking the
    installer, `local_delivery.rs:90-105`, `lookup.rs:407-418`, so
    installer-only instrumentation would miss the old family) AND the
    NEW family at install; `refresh_for_ha_transition`'s reindex
    (`session/mod.rs:1627-1666`) joins the producer list (HA
    refresh/demote re-keys indexes without an upsert). The capacity
    contract (round-122 Codex 3, zero-allocation reconciliation): the
    buffer is a fixed inline capacity sized for the per-batch maximum
    (one descriptor can install BOTH F and R,
    `poll_descriptor/mod.rs:2449-2458`, `:2777-2787` — two families per
    descriptor; the batch bound is the descriptor count × 2 families ×
    the alias count; the command path is bounded by the command-batch
    size); on saturation the buffer sets the binding's flush-pending
    flag and the drain performs a whole-cache flush for the affected
    binding (the `FlushFlowCaches` precedent — rare, bounded, no
    allocation). A precedence-changing install
    can
    never leave an old descriptor forwarding the prior winner's
    decision, and the identity check retains the backing-identity
    guard for the non-precedence ABA cases. The ordering promise is scoped to
    FORWARDING/POLICY effects (v10.33.0, round-117 Codex 7):
    `lookup_counted`'s bookkeeping — LRU promote, `hits += 1`, the
    `last_used_epoch` activity stamp, the `observed_bytes` add
    (`flow_cache.rs:1023-1039`) — fires before the identity check
    exactly as it fires before master's neighbor-MAC/owner-RG validity
    checks, and an identity mismatch takes the MASTER VALIDITY-FAILURE
    PATH VERBATIM (`invalidate_slot` + `FallThrough`,
    `flow_cache_hit.rs:115-133`) — the same eviction + fall-through a
    stale-neighbor-MAC or stale-owner-RG hit takes today — so
    hit/miss/byte telemetry moves bit-identically to a master validity
    failure; the ONLY new behavior is which packets fail the gate, and
    the exact guarantee is that no cached-decision CONSUMER runs (the
    slow path re-resolves and re-inserts once). §9 pins the telemetry
    shape with a crafted-mismatch test. The `None` class (purged/
    sessionless) keeps master's query-key `touch_if_stale` refresh
    behavior, and every authority mutation (probation clear, anchor
    write, promote) requires `Some(token)` with identity agreement. The
    token binds the FAMILY (v10.31.0, round-115 Codex 5; the epoch
    source made precise v10.31.1, round-115 AGY 2; the ABA gap closed
    v10.32.0, round-116 Codex 2; the discriminator swapped to the
    STABLE session id v10.34.0, round-118 Codex 1/2/7/9): the
    reverse→forward `account_packet`-style hop derives a forward key
    and mutates whichever entry currently occupies it
    (`session/mod.rs:1177-1205`), so the hop RE-VERIFIES the forward
    entry's identity (key AND NAT AND stable session id) before writing
    the anchor sample — the reverse entry gains
    `fwd_companion_id: u64` with 0 = UNBOUND (v10.34.0 — the forward
    entry's STABLE `session_id`, #4915/#5212, NOT the node-local
    `install_epoch`: the id is write-once for a SAME-FAMILY refresh,
    never re-stamped
    (`session/mod.rs:460-470`), is ADOPTED from the wire on import
    (`install.rs:322-351`), and survives promotion/refresh untouched
    (no `session_id` write exists in `session/mod.rs:1344-1432` or
    `:1642-1720`), so the binding needs NO transition-maintenance rule
    — the v10.33.0 "atomic epoch update on F-side transitions" clause
    is REMOVED (unimplementable, round-118 Codex 2: each sibling's
    upsert regenerates a LOCAL epoch,
    `session_glue/commands/upsert_synced.rs:64-79`,
    `install.rs:322-351`, so an epoch binding mismatches forever after
    replication). The id's own replication invariance is COMPLETED
    (v10.35.0, round-119 Codex 5 — the field exists on the wire since
    #5212; three paths currently ZERO it and are completed to populate
    the entry's real id — a behavior completion of #5212, no wire
    FORMAT change, rolling-upgrade safe because a zero from an
    old-version peer still falls back to a fresh local mint): the
    SharedPromote shared-replica republication
    (`session_glue/promote.rs:116-138` — the "this shared replica needs
    no id" comment predates the binding's need), the local-origin
    shared publish (#5212's "leave this 0" classes), and the HA bulk
    export (`ha/export.rs:143-165`). AND a zero wire id on a re-import
    ALWAYS fresh-mints (v10.36.0, round-120 Codex 6 — the v10.35.0
    preserve-on-zero clause is RETRACTED: the upsert removes the
    predecessor before selecting the id, `install.rs:295-344`, and the
    command carries no same-incarnation evidence,
    `upsert_synced.rs:64-79`; a legacy peer's new same-key/NAT
    incarnation must never inherit K's id — the flip evicts stale
    cached tokens and leaves imported reverses UNBOUND-absorbing,
    fail-closed, and unreachable in a same-version pair because every
    current path populates the real id). 0 is unambiguous:
    `alloc_session_id` starts its counter at 1 and guards the wrap —
    the guard becomes a SKIP (`session/mod.rs:784-789`, v10.35.0
    round-119 Codex 9: the mask + `low == 0 → 1` map would emit the
    same low id at counters 2^48 and 2^48+1 — the skip advances past
    the collision; 2^48 ids/worker is process-lifetime-unreachable
    regardless), and
    the upsert path states "0 is never a real id... the sentinel is
    unambiguous" (`install.rs:322-351`). The id hi-word gains a
    node-discriminator bit (v10.35.0, round-119 Codex 5b — #6311
    pulled in as the cheapest sound hardening:
    `session_id_worker_hi` becomes `(worker_id & 0x7FFF) << 49 |
    (node_id & 1) << 48`, `session/mod.rs:766-789`; adoption is
    format-agnostic so mixed-version pairs keep working — an old-peer
    id adopts verbatim, it simply may collide, which the next sentence
    bounds). The residual collision surface is stated with its threat
    scope: the id never appears in any packet (it is internal state,
    not an attacker-reachable field), so a collision is an ACCIDENT,
    not an attacker target; colliding requires the same canonical key
    AND the same translation AND the same (worker, node, counter)
    value — and the consequence is anchor samples from a
    packet-indistinguishable same-wire-tuple incarnation landing on
    the replacement's anchor, which grants an off-path attacker
    nothing (the sample still had to pass the in-window/proof gate);
    the restart-collision window (re-adopted pre-restart ids vs
    post-restart fresh mints at the same counter value) is residual
    and churns out — the persisted/boot-epoch discriminator is the
    #6311 follow-up, §10. The
    binding producers are EXACTLY these three, and the stored value is
    the EXPECTED family id, verified PER HOP against the probed
    forward entry — there is NO separate bind step (v10.36.0's
    promote-time bind is SUPERSEDED v10.37.0, round-121 Codex 5: the
    expectation IS the binding — every reverse→forward hop compares
    the probed forward entry's id against the STORED expectation plus
    key+NAT, a match writes the anchor sample, a mismatch suppresses;
    nothing is ever learned from the occupant, so the round-118
    lazy-bind and round-119 K-capture traces both stay dead, and a
    refused-then-later-successful forward import starts passing the
    moment the real family (carrying the expected id, adopted from the
    populated wire field) arrives. UNBOUND (`0`) is ABSORBING: a
    zero expectation never verifies, so the hop always suppresses —
    no lazy bind, no rebind, no promote-time step): (a) the positional
    fresh-flow reverse install carries the forward entry's id
    EXPLICITLY (the positional `install_with_protocol_with_origin`
    path, `poll_descriptor/mod.rs:2449-2458`, `:2777-2787`, gains the
    forward-id parameter — `SessionInstall` is not present on that
    path, `ctx.rs:8-17`); (b) the site-2b reactive synth against a
    LOCAL match carries the matched forward entry's id on the
    `ForwardSessionMatch` (`entry.rs:208-213` gains it — the type
    carries only key/decision/metadata today) with the identity
    re-probe before install; a SHARED match carries the shared row's
    `session_id` as the expectation (the across-scopes wrapper gains
    it; the materialize-adopt of that shared forward adopts the same
    wire id, so the expectation verifies once the forward materializes
    locally; a legacy zero-id row → 0 = UNBOUND); (c) an
    HA-IMPORTED reverse carries the EXPECTED forward id ON THE
    SYNTHESIZED ENTRY ITSELF: every reverse `SyncedSessionEntry` is
    built FROM its forward row (`synthesized_synced_reverse_entry`,
    `shared_ops.rs:750-785`), the forward row's id is in hand at that
    exact point and is discarded today (`session_id: 0` on the
    reverse), so the reverse entry gains `expected_fwd_id: u64`
    stamped from the forward row's id at synthesis — covering the
    direct import, the activation prewarm, and the singleton paths
    uniformly because all three synthesize the reverse from the
    forward row (in-memory shared entry + worker-command carriage
    only; the reverse never rides the cross-node wire as a separate
    record, so no wire change); the reverse's LOCAL install copies the
    carried expectation into `fwd_companion_id` (the install/upsert
    paths gain the expectation input — `SessionInstall` and the synced
    upsert/materialize constructors carry it, `ctx.rs:27-49`,
    `session_glue/commands/upsert_synced.rs:64-79`; this answers the
    round-121 Codex 5 storage question: the expectation lives in the
    SAME 8 B field, there is no second slot), and every later hop
    verifies against it. The reverse SharedPromote/positional/site-2b
    reverse-row constructions are covered by (a)/(b) — they carry the
    producer's id directly. The local
    GRE tunnel path is the one class with NO real id to carry
    (v10.36.0, round-120 Codex 8: `tunnel.rs:563-615` constructs F/R
    with `session_id: 0` before any worker entry exists, publishes
    first `:691-730`, and only then queues `UpsertLocal` to every
    worker `:732-745`, where each worker's table independently mints
    on zero — there is no single real id at publish time and no
    cross-worker allocator): tunnel-path reverses carry
    expectation 0 → permanent UNBOUND (fail-closed: these are
    firewall-local tunnel-endpoint flows; reverse-direction anchor
    learning is suppressed and reverse-direction closes refuse until
    churn — the imported-class posture of §2 — while forward-direction
    learning and validation ride the direct canonical hit). A standby
    runs no hops, so nothing verifies
    there; the first
    reverse hit on the newly-active node hops and verifies, and an
    adopted-id forward keeps its id across its own later promote, so
    the expectation survives); an absent forward, a reciprocity mismatch,
    or an id mismatch
    suppresses the hop (fail-closed: reverse-direction
    anchor learning is suppressed, reverse-direction closes refuse —
    the imported-class posture of §2 — while forward-direction learning
    and validation ride the direct canonical hit and are unaffected).
    AND the identity-replacement rule (v10.35.0, round-119 Codex 4;
    the discriminator is the CARRIED STABLE ID, v10.37.0, round-121
    Codex 4 — the v10.36.0 `(nat, is_reverse)` snapshot compare is
    REPLACED: an exact tuple/NAT reincarnation has identical nat and
    orientation yet is the ABA case the id exists to distinguish):
    the `SessionUpdate` gains the incoming family id (the promote/
    update caller passes the synced row's or the shared entry's
    `session_id`, `ctx.rs:62-70`,
    `session_glue/promote.rs:99-107`) and the update compares it
    against the stored `session_id` — EQUAL ids (plus key) mean the
    same incarnation: update in place, id and authority state
    preserved (a legitimate NAT/orientation refresh rides the existing
    reindex, `session/mod.rs:1344-1463`); DIFFERENT ids — or an
    incoming id of 0, which must fail closed — mean a different-family
    replacement: `remove_entry` + FULL INSTALL semantics (id re-mint
    or adopt the incoming non-zero id, anchor zeroed (absorbing),
    gated `closing`/`reset`/`established` seed from the update's
    flags, `probation` cleared, `fwd_companion_id` zeroed) — K's
    anchor, sticky state, and companion binding NEVER ride onto S2
    (a later close can never
    validate against K's anchor); the re-mint/adopt propagates to the
    sibling through the now-populated wire id (above), keeping the
    sibling's expectation consistent. The reverse entry
    does NOT otherwise store the forward entry's id,
    `install.rs:152`, and a same-key+NAT replacement K2 mints a
    DISTINCT id (#4915: "a reused 5-tuple gets a distinct id",
    `install.rs:139-152` — now true on EVERY path including the
    overwrite, per the re-mint rule), so the id compare is what stops R1's
    sample landing on K2 — in the stale-R1/replacement-K2 state, R1's sample
    can never land on K2. (§5.5's "exact tuple+NAT reuse needs no
    generation token" statement is qualified, round-116 Codex 2, scoped
    v10.34.0 round-118 Codex 1: the
    reciprocity identity check stands for the CLOSE mark-propagation
    target — a packet on a tuple+NAT-identical replacement's reply tuple
    is indistinguishable from that generation's own close — while the
    anchor-LEARNING hop requires the id binding.) A token MISMATCH at the cache-hit path
    EVICTS the descriptor and falls through to a fresh resolution
    (round-115 Codex 6 — suppression alone would leave a stale active
    descriptor forwarding while the replacement never refreshes;
    `flow_cache.rs:962-1021`, `:767-780`); the intentional `None`
    (purged/sessionless) parity class stays distinct and keeps
    master's behavior. The replacement races this guards against: a
    same-key synced upsert removes/reinstalls with a new
    local epoch AND (for a non-zero wire id) a NEW adopted or freshly
    allocated stable id (`install.rs:310-351`), `update_session` can
    change NAT/orientation while retaining the key (and re-stamps the
    node-local epoch, which the token no longer carries — the
    NAT/orientation fields catch that race)
    (`session/mod.rs:1344-1397`), and worker `UpsertSynced` performs
    that replacement WITHOUT flow-cache invalidation
    (`session_glue/commands/upsert_synced.rs:64-120`), while cache
    lookup validates config/FIB/RG stamps, not session identity
    (`flow_cache.rs:991-1021`). §9 tests canonical, translated,
    cache-alias, sessionless `None`, same-key-replacement-mismatch,
    and mismatch-evict-and-fall-through hits
    (not only the
    probation flag, round-108 Codex 3); (v) the ownership promote is
    suppressed by the explicit `report.effective_transition ==
    Some(OverdueSkipped)`
    gate AND by the rule-5 `(report.site == Some(Site2c) &&
    validation == Some(Refused))` gate (the
    §5.5 probation flag on K is the third, independent suppression —
    K remains installed); (vi) the ESTABLISHMENT promote is REMOVED
    from the report consumers (v10.30.0, round-114 Codex 1 — the
    v10.29.x consumer-gating was unnecessary, and the carrier-free
    proof is the mutual exclusion: an establishment candidate is a
    LOCAL REVERSE hit (`is_syn_ack && entry.metadata.is_reverse`,
    `lookup.rs:129-149`), while the fabric-placeholder substitution
    that feeds the site-2c materialize machinery requires
    `!is_reverse` (`is_fabric_wire_placeholder`,
    `shared_ops.rs:583-590`), and a live local non-placeholder hit
    wins over the shared map (no materialize runs) — so a dispatch
    with an establishment candidate NEVER produces an
    `OverdueSkipped`/`UpsertRefused` report, and a dispatch producing
    one never has an establishment candidate; §9 tests the exclusion).
    The promote therefore needs no report — its own gates (the §5.5
    proof gate, rule 5's closing check, the probation flag on the
    matched entry) are all available at its lookup-phase fire point.
    Accounting is an explicitly ALLOWED
    consumer (#2501 semantics, `poll_descriptor/mod.rs:3494-3503`,
    `session/mod.rs:1177-1210`); delivery/buffering/replay/
    reinjection/telemetry consume S2 (the buffer stores S2's decision
    and the retry consumes it without another SessionTable lookup,
    `:5057-5068`, `neighbor_dispatch.rs:272-405`); the deferred RST
    teardown cannot engage (`session_glue/mod.rs:863-875`).
  - **Composition (normative, part of the MissingNeighbor outcome
    list below):** an `effective_transition ∈ {OverdueSkipped,
    UpsertRefused}`
    (both exist only on `Some(Site2c)` reports) with a MissingNeighbor
    disposition takes the live-backed `ExistingResolved` buffer-only
    arm — NEVER the common seed block
    (`poll_descriptor/mod.rs:4662-4829`; on `UpsertRefused` the
    promotion no-ops for a non-ForwardCandidate, `promote.rs:86-90`,
    leaving the non-peer predecessor installed, and without the
    composition the common arm could seed-transact a raw-flags
    `MissingNeighborSeed` that replaces the predecessor via
    `install.rs:139`).
  - **The displaced-identity set (producer + carrier):** the set
    lives ONLY inside `MaterializeReport.displaced` — a small INLINE
    fixed-capacity array (capacity 3 identity families SUFFICE per
    dispatch, round-105 Codex 3's uniqueness proof: the shadowed
    placeholder P, the canonical predecessor K, and the newly
    installed S2 are the only families; the promote step's preimage
    DEDUPLICATES into them — after a successful upsert the preimage
    IS the installed S2, and after a refused upsert it is K; the
    proof's precise form, round-106 Codex 3: promotion CAN change
    NAT/orientation — `update_session` detects/reindexes/overwrites
    those fields, `session/mod.rs:1344-1348`, `:1373-1381`,
    `:1393-1396` — so K's pre-image family and the resulting S2
    family are BOTH separately recorded members of the same
    ≤3-family set). The set DEDUPLICATES by alias-family inputs (key,
    NAT decision, orientation) — a repeat contribution merges.
    Producers, each contributing at most one family per transition
    (v10.26.0, round-109 Codex 1 — the post-state S2 family is a
    FIRST-CLASS producer, without which a no-P/no-predecessor
    `(Refused, Installed)` would produce an empty set and a surviving
    older cache entry would keep serving the tuple: FIN/RST skips the
    cache lookup, `flow_cache.rs:352-358`, so a close can materialize
    S2 while an older cache entry survives, and the following ACK
    consults the cache before session resolution,
    `poll_descriptor/mod.rs:298-327`; the invalidation is exact-key,
    `flow_cache.rs:1105-1120`): the NEW S2 alias family, added by the
    materialize/upsert on ANY successful install/adopt (the
    materializer has S2 in hand, `session_glue/mod.rs:1098-1119`) and
    by a successful promotion (which can contribute both the preimage
    K and the resulting S2 — total capacity remains 3);
    the placeholder substitution (`shared_ops.rs:602-628`, an OUT
    parameter — and the placeholder identity is STAGED, committed to
    the set only on the site-2c materialization branch, DISCARDED for
    the purge path and the non-materializing callers,
    `icmp_embed/nat_match_v4.rs:78-95`, `nat_match_v6.rs:100-125`,
    `return_resolution.rs:20-28` — the substitution runs BEFORE the
    `keep_transient` decision, `session_glue/mod.rs:1157-1197`, so an
    unstaged OUT would invalidate P's cache family on a purge-class
    close where P survives, changing master's cache behavior); the
    upsert's previously-discarded `_previous` (`install.rs:295-322`,
    an OUT parameter); and the promote preimage (captured INSIDE
    `update_session` immediately before the overwrite,
    `session/mod.rs:1344-1348`, `:1393-1396`, threaded outward through
    `promote_synced_with_origin`, `:1673-1675`, and
    `maybe_promote_synced_session`, `promote.rs:71-140`, replacing
    today's bool → bool → metadata chain). On `UpsertRefused` the
    surviving non-peer predecessor K rides the set ONLY when a later
    promote actually overwrites it — an upsert refusal with a no-op
    promote displaces nothing (K survives intact; its aliases stay
    valid; the set is EMPTY in that case, as is an `OverdueSkipped`
    with no shadowed placeholder).
  - **Invalidation timing (the realizable API; the SINGLE drain
    description, v10.25.0, round-108 Codex 1):** the CURRENT-binding
    drain consumes exactly the CURRENT descriptor's
    `report.displaced` — the poller invalidates that inline set in
    the current binding's cache immediately after the descriptor's
    resolution, before every early exit, the cache insert, and the
    next descriptor (descriptor processing owns only the current
    binding, `poll_descriptor/mod.rs:110-131`) — so descriptor 2
    never re-invalidates descriptor 1's freshly inserted S2 alias.
    The `WorkerScratch` batch accumulator (preallocated,
    `with_capacity`, `worker/scratch.rs:19-32`; 3 families × the
    64-descriptor batch, `afxdp/mod.rs:278-281`) accumulates the UNION
    of the per-descriptor sets across the batch and feeds ONLY the
    sibling fan-out: once per batch at the `poll_binding` level over
    `left + right` (`worker/lifecycle.rs:53-55`, `:209-225`) BEFORE
    the next RX batch — never per-descriptor, and explicitly NOT via
    the reap routine (`worker/loop_body/mod.rs:1481-1521` includes
    the current binding and does NAT/BPF teardown).
  - **The probation reap** invalidates the flow cache for the FULL
    alias set of the final identity (canonical, reverse companion
    `reverse_session_key(key, decision.nat)`, reverse-translated
    aliases, forward-wire aliases, reply-match tuples — `lookup.rs:
    62-100`/`:222-250`/`:253-315`, `key.rs:19-26`), with each prior
    identity's set already invalidated at its adopt/replace time.
- **MissingNeighbor dispatch typed outcomes (v10.4.1, rounds 83-87
  Codex):** the
  disposition arm branches
  AT THE ARM HEAD on the resolve outcome — `ExistingResolved` (a live
  local or shared resolve-time entry backs the resolve: buffer with the
  resolver's stored decision; no seed-only NAT/NPT derivation or
  allocation, metadata, counters, install, rollback, or publication
  runs),
  the retracted `ResolvedWithoutLocalBacking` outcome is replaced by
  MASTER'S OWN split (v10.12.0, round-95 Codex 1 — the v10.11.0
  "ExistingResolved-with-retained-decision, buffer-only" classification
  was wrong for the cold-neighbor case: the purge RELEASED P1, so
  buffering the retained decision would replay a released tuple without
  reacquiring it): a purged packet with a WARM next hop forwards on
  the retained lookup (`session_glue/mod.rs:1194-1196`) with no
  install — master's exact behavior; a purged packet with a COLD next
  hop takes master's own seed transaction (derive/allocate P2, install
  the transient `MissingNeighborSeed`, publish, buffer,
  `poll_descriptor/mod.rs:4662`, `:4745-4761`, `:4780-4795`) — with
  master's own merge-keeps-P1 purge-aftermath behavior (round-96
  Codex 1: `NatDecision::merge` prefers existing fields,
  `nat/mod.rs:123-133`, so the retained P1 translation survives the
  P2 merge — a pre-existing released-tuple reuse family, parity not
  correctness, §7); the transient seed cannot emit Open
  (`entry.rs:272-274`, `install.rs:225-260`), and nothing live remains
  for a raw-flags seed to replace (the r83-87 `ExistingResolved`
  buffer-only rule stays scoped to LIVE backing). Outcome naming
  (round-96 Codex 7): the arm-head provenance outcomes are
  `ExistingResolved` / `PurgedRetained` / `SeedEligible` — install can
  still refuse at capacity (`install.rs:123-125`) and NAT64 drops
  before the seed block (`poll_descriptor/mod.rs:4634-4656`), so
  `SeedInstalled`/`SeedRefused` are RESULTS, not arm-head outcomes.
  An `effective_transition ∈ {OverdueSkipped, UpsertRefused}` (the
  contract bullet above — both exist only on `report.site ==
  Some(Site2c)`, v10.26.0 round-109 Codex 3; an impossible
  `site=None` report follows master's own dispatch) COMPOSES to the
  live-backed `ExistingResolved` buffer-only
  arm regardless of the disposition's eligibility — it never enters
  the seed block (normative, v10.19.0, round-102 Codex 2;
  UpsertRefused added v10.21.0 round-104 Codex 2, propagated here
  v10.22.0 round-105 Codex 2). A
  genuine clean miss on a LATER packet installs the ForwardFlow with
  Open exactly as master. Closing packets take the purge EXACTLY as
  master (v10.15.0 — the close-aware gate is retracted, round-98
  Codex 1-3),
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
  (rule 1), never promotes (rule 5), and on refuse mutates nothing
  (gate-effects scope: no mark/refresh/re-queue; master's own purge is
  not a gate effect — v10.19.0, round-102 Codex 9).
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
  semantics apply unchanged FOR THE GATE'S OWN EFFECTS (a purged
  entry is removed by master's own flag-agnostic purge on both
  versions — no emission either way, master-identical; v10.19.0,
  round-102 Codex 9) (locally-born entries emit at natural reap;
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
  reservation); the v10.6.0-v10.14.0 RWoLB constructor shapes and the
  close-aware purge gate/marker line are ALL retracted (v10.15.0 —
  the purge decision and dispatch are master-identical, §5.6 site-3
  supplement), so no
  probation entry
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
  call, §5.2 — the COMMON SUCCESS-ONLY POSTBLOCK, `!recycle_now` at
  `flow_cache_hit.rs:549-552`, where both the in-place (`:444-497`) and
  fallback (`:498-548`) arms converge, v10.36.0 round-120 Codex 1) is
  one
  8-byte read + ≤2 gated stores against the CARRIED validated handle
  (an L1 slab index + identity compare, no re-hash, v10.35.0 round-119
  Codex 2; TWO carried handles for a reverse-direction binding,
  round-120 Codex 2); closing segments add one table probe on a
  path that already takes the full slow path; EVERY session-backed cache
  hit adds the identity probe(s) — ONE canonical probe for a
  forward-direction binding, TWO for a reverse-direction binding (the
  canonical probe + the matched-reverse probe); the canonical probe is
  same-key with the
  two probes master already does later on the hit path
  (`touch_if_stale`/`account_packet`, `:295-317`) only for a plain
  non-translated forward hit, plus L1 compares of
  the ~93 B token fields (v10.33.1, SMR r118). `SessionEntry` grows 49 B
  (v10.34.0: 40 B anchor + 1 B probation + 8 B `fwd_companion_id`)
  — slab is uniform, UDP/ICMP entries carry it unused.
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
    v10.11.0 retracts the plan's first divergence (the v10.4.1
    same-dispatch re-entry had collapsed the class from two packets to
    one, round-93 Codex 1) and v10.15.0 retracts the second (the
    close-aware purge-gate line, round-98 Codex 1-3) — with both
    retractions the plan's dispatch here is packet-for-packet
    master-identical, closing packets included; the ONE remaining
    delta is the demote gate's pre-purge refusal (§5.2 (iv)). It is NOT the issue's
    blind-close class, stated precisely (v10.16.0, round-99 Codex 5):
    the harm flows through the identity-less Open overwrite (the sync
    layer), and the chain's state creation is CONSTRUCTOR-side — the
    follow-up packet (SYN or SYN|close) hits a clean miss and seeds a
    FreshPrimary entry (site 3), where a closing flag only accelerates
    the fresh entry's own reap; the demote gate engages on live
    anchor-carrying entries and a fresh constructor seed is out of its
    scope. (The conceded chain needs a warm next hop or a lapsed seed
    for packet two to clean-miss; with a cold next hop packet two hits
    the transient seed instead — stated, round-99 Codex 5.) No
    sequence validation applies to a SYN
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
    #6600. With the close-aware gate retracted (v10.15.0, round-98
    Codex 1-3), the plan changes nothing in the purge DECISION or
    dispatch on this path: master's
    flag-agnostic purge self-cleans a conflicted row on any packet,
    closing packets included (the one deliberate delta remains the
    demote gate's refusal upstream of the purge — the conflicted
    companion replica then lingers on its ordinary trajectory instead
    of the 2 s/30 s closing window, the §2 absorbing-state residual
    applied here, round-100 Codex 5); every retention-extension concern
    from rounds 93-97 (the no-deadline shared row, the cache corner,
    the RG-activation crossover) attached to the retention and is
    dissolved with it. The pre-existing corners remain documented for
    the record: the purge-aftermath released-tuple reuse family
    (warm-path forward in the same dispatch that released P1; the
    cold seed transaction's `NatDecision::merge` keeping P1's fields
    over the fresh P2, `nat/mod.rs:123-133`; the install-refusal
    rollback P1/P2 mismatch leak, `poll_descriptor/mod.rs:4890-4909`,
    `allocator.rs:1398-1404`; the reinjection epilogue consuming the
    retained P1, `poll_descriptor/mod.rs:5126-5138`); the RG-activation
    crossover (a conflicted row whose RG activates locally stops
    matching the purge predicate, so the next non-close
    materializes/promotes it with the conflicted P1,
    `promote.rs:48-59`, `:99-139`, `session/mod.rs:1480-1530`); the
    conflicted state is reachable via EITHER the #6600 import race OR
    the #6522 unrefcounted sibling release
    (`allocator.rs:742-745`, `:1318-1332`, `:1664-1674`,
    `worker/loop_body/mod.rs:1490-1505`); and master's own ACK-first
    flow-cache pin of a just-released tuple (no idle TTL,
    `flow_cache.rs:767-780`). All pre-existing; the ownership/identity
    fence is #6522/#6599/#6600 scope.
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
| Performance regression | LOW-MED | 49 B/entry slab growth (v10.34.0: 40 B anchor + 1 B probation + 8 B `fwd_companion_id` — the stable session id, renamed from the epoch form round-118 Codex 2, same 8 B; 49 × 131,072 = 6,422,528 B ≈ 6.1 MiB/worker at cap, ≈ 36.7 MiB at 6 workers) plus the cache's optional token field (~96 B `Option<MatchedToken>` — 40 B `SessionKey` (`key.rs:9-17`) + 44 B `NatDecision` (`nat/mod.rs:90-103`) + 8 B stable id + orientation/source/transition bytes, the `Option` niche-filling on the source enum — on the ~96 B entry × the 4,096-entry cache PER BINDING, ≈ +384 KiB per binding, owned per binding not per worker — `flow_cache.rs:5-14`, `:201-224`, `worker/flow_cache_state.rs:26-35`, `worker/mod.rs:196-201`; the ~doubled entry width and the larger four-way set scan are noted and gated by the §9 `size_of` assertions + measurement); one TCP-header view compute (seq/ack/wnd/flags/seg_len) + ≤2 gated stores per committed TCP data packet (closing segments skip updates entirely); one extra probe per closing segment; PLUS the session-table identity probe(s) per session-backed cache hit (v10.33.1 SMR r118; mechanics corrected v10.36.0 round-120 Codex 1/2/3: the early identity-only check at `flow_cache_hit.rs:~133` resolves and CARRIES the validated slab handle(s) in the descriptor's commit scratch — ONE canonical probe for a forward-direction binding, TWO for a reverse-direction binding (the canonical probe + the matched-reverse probe, the latter warm against master's own `:295-317` reverse probes); same-key/warm with master's `touch_if_stale`/`account_packet` probes ONLY for a plain non-translated forward hit; every authority mutation re-validates its carried handle at its own apply point — an L1 slab index + ~93 B of compares, NO re-hash; the anchor apply runs at the COMMON SUCCESS-ONLY POSTBLOCK (`!recycle_now` at `:549-552` — both the in-place `:444-497` and fallback `:498-548` arms converge there), so a construction-failed recycled packet never advances the trusted anchor; and every install/upsert/overwrite at key K invalidates K's exact-query-key cache slot so a precedence-changing install never leaves a stale descriptor forwarding the prior winner). Must be measured at minimum-frame rates (§9) — the 23 Gbit/s MTU-sized iperf run alone is insufficient (≈37 Mpps at 25 Gbit/s small-frame is the real gate; `iperf3 -l 64` is a proxy, not a demonstrated line-rate generator — gate on pps, not bandwidth). |
| Architectural mismatch | LOW | No new subsystem; anchors at the existing #2501/#3706 chokepoints; #4400-style always-on gate. No pipeline restructure. No distributed protocol. |
| HA / rolling upgrade | LOW | No wire change; mixed-version pair behaves as same-version (a pre-upgrade node keeps master's demote behavior for its own table; the upgraded node simply refuses blind demotes on its own). Pre-upgrade and imported entries sit in the absorbing zero-trust state — closes refuse until churn (strictly more conservative than master; bounded lingering, §2; Phase 2 §10.5 closes it for synced flows). The replica no-Close invariant + the SharedPromote refuse trace are regression-tested. |
| Pending-neighbor behavior | LOW | Master's buffered-decision retry is UNCHANGED (v10.2.0 retreat): no re-resolution, no hold, no new drop class, no stale-transmit change — the admitted-close delivery is master-parity, and the pre-existing stale-decision window is documented (§7 race d, follow-up §10.6.2). Buffered packets never move the anchor — a fail-toward-refuse residual (anchors lag behind long ARP stalls; closes soft-refuse; entries idle out normally), never a walk/poison channel. |
| Dispatch-path provenance | LOW-MED | The MissingNeighbor arm branches on typed resolve outcomes at the arm head (round-83 Codex 1 + round-84 Codex 1): `ExistingResolved` preserves the resolver decision and allocator state exactly (no seed-only work runs); `SeedInstalled`/`SeedRefused` are today's miss paths. Risk is confined to the hit-with-cold-neighbor corner (previously the live entry was replaced by a raw-flags seed — master's unguarded demote path); unit-tested for refused and accepted closes and for the no-allocation-leak case. |
| Probation reap locality | LOW | A probation expiry is local-only (round-83 Codex 2): no NAT release, no BPF family-key delete. Strictly safer than master's born-dying materialized copy (which runs the full cleanup at 2 s — the #6522 class); the owner entry's own reap is the family's authoritative cleanup event. |
| Seed class | LOW | Master's seed lifecycle is UNCHANGED (v10.4.0 — the second retreat): no flip, no flip-time accounting, no id-guarded cleanup. The zero-producer transient-seed case is HA-safe by construction (no peer copy exists); the stale-alias and stub-metadata gaps are pre-existing master behavior, documented (§7 races e-g) with a §10.6.2 completion follow-up. |
| Merge collision | LOW | `FlowCacheEntry` gains one additive cache-internal field (the `Option<MatchedToken>`, §5.8/§8 — no wire, no serde, no public API; v10.33.0, round-117 Codex 6). The anchor apply hooks are local to the commit arms; `SessionInstall`/`SessionUpdate` gains are crate-internal. |

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
  later committed non-close packet (with a non-OverdueSkipped
  effective transition) may promote it; the then-promoted
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
  build-failure) skip updates; a COMMITTED packet updates exactly once
  UNLESS the effective transition is `OverdueSkipped` or
  `UpsertRefused` (the anchor commit hook is suppressed for both,
  v10.28.0, round-112 Codex 4).
- **Constructor gating:** site 2b accept → the forward family marked
  and the companion installed with the inherited seed — EXCEPT the
  capacity-refused case, where the forward mark still lands and no
  reverse installs (the re-synth retry carries the inheritance,
  v10.34.0/v10.36.0; the "every accept installs" phrasing is corrected,
  v10.37.0 round-121 Codex 11) — exactly one producer on the forward
  entry in both cases;
  #4380 retention semantics asserted, not an idealized 2 s whole-flow
  reap); site 2b refuse → NO install (`created=false,
  install_failed=true`, no cache insert, packet still forwarded, next
  reply re-synthesizes and revalidates); site 2c refuse → install ALIVE
  (or skip wholesale when the existing entry is overdue —
  `OverdueSkipped`, v10.27.1)
  at the probation timeout with its close state seeded FROM THE
  REPLICA'S stored close bits (the round-121 Codex 6 seed rule — a
  closing/reset replica yields a closing/reset materialization even
  though the current close was refused; the blanket
  `closing=false, reset=false` phrasing is corrected, round-121 Codex
  11); site 2c
  with a non-close attacker packet → untrusted samples only.
- **Materialize preservation + retention fence (v10.7.0, rounds 89-90
  Codex):** (a) with a probation entry K installed (refused-close
  materialize), a second packet that reaches
  `materialize_shared_session_hit` for the same canonical key BEFORE
  any admission (placeholder/shared coexistence per
  `session_glue/tests.rs:704`) — the upsert ADOPTS the shared S2
  decision/metadata wholesale while K's immutable deadline and probation
  flag carry over and the close state comes from S2's TRUSTED REPLICA
  BITS (v10.38.0, round-122 Codex 4 — the alive-flags carry-over is
  corrected: K-alive→S2-RST must not resurrect S2 alive;
  K-closing→S2-alive must not transfer stale close authority): assert the entry's decision and
  metadata equal S2's (no S1/S2 split-brain — include a fixture where
  S2's `ForwardingResolution`/metadata differ from K's), assert the
  adopted `closing`/`reset` equal S2's replica bits in both
  directions, assert the
  absolute deadline is `min(K's preserved deadline, now + S2's own
  candidate)` in the §5.6 encoding (`last_seen_ns = now_ns`,
  `expires_after_ns = D.saturating_sub(now_ns)`, wheel sum re-derives
  D) — cover BOTH K-wins and S2-wins fixtures (round-92 Codex 3); the
  OVERDUE-K fixture (D ≤ now at adopt time): the upsert is SKIPPED
  wholesale (v10.14.0 — no remove/recreate, no restamp, no re-queue,
  NO removal — the v10.13.0 remove-locally ran pre-admission and broke
  the commit-hook clear path; the v10.12.0 in-place adopt needed
  machinery to keep alive an already-due entry): assert K's timing,
  probation, and closing/reset fields are bit-identical (the #2501
  accounting fields — counters, observed_tos, observed_tcp_flags — MAY
  advance on the forwarded packet, the explicitly-allowed consumer,
  round-100 Codex 3), the packet forwards with the materialized S2
  decision, the commit-hook clear+refresh NEVER fires on an overdue
  entry (no S1-for-a-full-timeout resurrection, round-94 Codex 5),
  the GC reaps K on its existing wheel slot under one-per-tick
  pressure ahead of the phase-shifted GC (round-93 Codex 3's pin
  trace), and the S1/S2 divergence is bounded by the GC lag; and
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
- **Invalidation lifecycle (v10.18.0, round-101 Codex 3/4):** the
  displaced-identity SET (new S2 family + any removed canonical
  predecessor's old family + any shadowed placeholder's key family;
  EMPTY only for an `OverdueSkipped` with no shadowed placeholder OR
  an `UpsertRefused` whose promotion no-ops (v10.24.0, round-107
  Codex 4: the v10.21.0 text said `UpsertRefused` necessarily records
  K — wrong: with no shadowed P, an upsert refusal on non-peer K
  (`install.rs:310-315`) plus a no-op promote (non-ForwardCandidate,
  `promote.rs:86-90`) displaces NOTHING, and K's aliases remain valid;
  K's family enters the set ONLY when the promote actually overwrites
  it) — and a no-predecessor
  `(Refused, Installed)` successfully installs the probation S2 and
  therefore carries the new S2 family) is asserted
  across: (i)
  initial probation construction with a pre-existing fabric-wire
  placeholder cache entry (`shared_ops.rs:594-628`,
  `session_glue/tests.rs:704-759`); (ii) a simultaneous
  placeholder-shadow + canonical-predecessor replacement (two
  displaced identities in one transition); (iii) the same-batch case
  (descriptor 2 must not consume a descriptor-1-displaced alias —
  current-binding invalidation runs after resolution and before every
  early exit, the cache insert, and the next descriptor); (iv) the
  sibling-binding fan-out (once per batch, current binding excluded);
  (v) a multi-transition batch (accumulated sets); (vi) the
  new-current-S2-survives case (the fan-out must not evict a freshly
  inserted S2 entry where old and new aliases overlap); (vii) a
  `(Refused, Installed)` WITH a canonical predecessor (the set carries the
  predecessor's family); (viii) an `UpsertRefused` (non-peer
  predecessor, `install.rs:310-315`) — assert the predecessor survives
  unmodified AT THE FAILED-UPSERT INSTANT (the recorded same-resolve
  promotion attempt and the allowed accounting may still mutate it —
  the fixture asserts the RESULTING state, round-105 Codex 4 /
  round-106 Codex 4), the dispatch forwards with S2, and the
  teardown/cache/
  commit consumers are all gated; (ix) the upsert-refused→promotion
  case (the promote records its displacement into the inline set);
  (ix-a) the valid-BY-CONSTRUCTION ordering (v10.25.0, round-108
  Codex 3 — supersedes the producer-normalization test): the
  materialize computes the verdict and the overdue check BEFORE the
  state-changing upsert, so an out-of-product combination is
  unreachable — assert the upsert is never called on a skipped path;
  the consumer-side fail-closed read applies ONLY to `Some(Site2c)`
  reports, and a `site=None` report follows master's own dispatch
  (regression: a purged retained lookup with a MissingNeighbor
  disposition takes master's seed transaction, never the buffer-only
  arm); (ix-b) `UpsertRefused +
  MissingNeighbor` never enters the seed block (which would replace K
  via `install.rs:139`); (ix-c) the P+K+S2 maximum-cardinality case
  and a full 64-descriptor/192-family batch; (ix-c9) the site-2b
  proof matrix and token regressions (v10.32.0, round-116 Codex 5/8;
  the ACK-knowledge proof v10.33.0, round-117 Codex 3/4):
  the OPENING/ESTABLISHED-forward matrix (a non-closing reverse synth
  against an OPENING forward requires the proof — a SYN-ACK OR an
  ACK/PSH-ACK whose ack exact-proves the immutable SYN interval is
  accepted; an out-of-interval or non-ACK packet skips the install;
  against an ESTABLISHED forward,
  master's behavior verbatim; the Shared rows install master-verbatim
  with the anchor UNTRUSTED); the proof-pass forward companion
  flag-only establishment update (absolute opening deadline
  preserved) and the capacity-refused reverse install still applying
  the forward update; the SYN-ACK+FIN/RST conjunction (validates the
  close, never establishment-promotes); the token carriage cases
  (canonical, translated, forward-wire with the no-anchor-learn
  marker, fresh-install and final-promotion tokens, reverse/forward
  ABA via the recorded companion id); the early identity-only
  check on a cached terminal decision (mismatch evicts before any
  cached-decision consumer) and the `None`-class touch parity;
  (ix-d0) the
  phase-shifted DIRECT-LOCAL-HIT overdue regression (v10.28.0,
  round-112 Codex 1): probation K installed; K crosses its deadline
  ahead of the periodic GC; a canonical packet finds K LOCALLY (no
  `shared_entry`, no materialization — `MaterializeReport::NONE`); a
  committed non-close must NOT clear/restamp K — the commit hook's
  direct matched-entry test (`entry.probation &&
  last_seen_ns.saturating_add(expires_after_ns) <= now_ns`)
  suppresses the clear+refresh, and K reaps on schedule; (ix-d) the r109-1
  end-to-end stale-cache regression (v10.27.0, round-110 Codex 3):
  pre-seed an OLD cache descriptor for the tuple; process a
  cache-ineligible close (FIN/RST bypasses the lookup,
  `flow_cache.rs:352-358`) that installs S2 with no P and no
  predecessor; assert the following ACK misses the old descriptor on
  the current AND sibling bindings (the ACK consults the cache before
  session resolution, `poll_descriptor/mod.rs:298-327`;
  exact-key invalidation, `flow_cache.rs:1105-1120`);
  (x) an overdue skip WITH a shadowed placeholder (the placeholder's
  identity is in the set, so a later ACK cannot refresh it from
  cache, `flow_cache_hit.rs:295-317`).
- **OverdueSkipped propagation (v10.17.0, round-100 Codex 2/3):** the
  report is initialized `MaterializeReport::NONE` on every resolve
  path and set from the materializer's OUT report (all four
  transitions, not only the overdue skip — v10.24.0, round-107
  Codex 6); the poller hoists it at
  `poll_descriptor/mod.rs:509` and carries it past the `:883`
  reduction; assert each of the FIVE consumers honors it (teardown
  suppressed at all three sites — `:698-714`, `:768-784`, `:824-840`;
  no anchor write; no cache insert; no clear+refresh; no ownership
  promote) — the establishment promote is NOT a report consumer
  (v10.30.0, round-114 Codex 1: the mutual exclusion — an
  establishment candidate is a local reverse hit, the placeholder
  substitution requires `!is_reverse`, `shared_ops.rs:583-590` — so
  no dispatch ever has both; §9 asserts the exclusion directly) and
  the MissingNeighbor composition lands on the live-backed
  ExistingResolved buffer-only arm with NOTHING derived/allocated/
  installed/published (`:4662-4829` untouched); accounting still runs
  (#2501 semantics on the packet query tuple).
- **Pre-purge companion delta (v10.16.0, round-99 Codex 2):** a close
  on an anchorless peer-synced translated-forward entry: the demote
  gate refuses the mark (no closing/reset, no propagation) AND the
  flag-agnostic purge proceeds exactly as master — assert the local
  reverse companion survives on its ordinary peer-synced trajectory
  (NOT the 2 s/30 s closing window master would have set), the
  documented absorbing-state delta for this path.
- **Transient-purge master parity (v10.15.0, round-98 Codex 1-3):**
  a closing packet on the transient-purge class purges and dispatches
  EXACTLY as master — assert the purge runs flag-agnostic
  (`promote.rs:48-59`), the packet forwards on the retained lookup
  (`session_glue/mod.rs:1194-1196`), the cold case runs master's seed
  transaction, the close-on-purged-provenance chain is master's own
  behavior (a SYN-bearing follow-up close clean-misses and
  FreshPrimary-installs with closing seeded + Open — the clean miss
  requires a WARM next hop or a lapsed transient seed; a live cold
  seed captures the follow-up, `shared_ops.rs:594-613`, round-102/103
  Codex — the #6599-class exposure, documented §7,
  NOT a plan-introduced change), and the `ReplacedSyncedLocal` close
  skip still displaces nothing (`take_synced_local` never runs, the
  synced victim survives, the packet delivers locally).
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
  probation clears exactly once AT THE MATCHED ENTRY (never on an
  `OverdueSkipped` effective transition — the explicit overdue guard,
  v10.26.0) (forward-key AND
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
  pre-refusal expiry trajectory is bit-identical FOR THE GATE'S OWN
  EFFECTS (mark/refresh/re-queue — v10.18.0, round-101 Codex 7;
  master's independent flag-agnostic purge of a transient-purge-class
  entry is not a gate effect and still runs).
- **Pending-neighbor (v10.2.0 posture):** master's buffered-decision
  retry is byte-identical (an admitted close transmits on the buffered
  decision even after an interim expiry — delivery parity); a buffered
  packet NEVER moves the anchor, NEVER clears probation, and never
  RE-runs the establishment promote on the retry path (the promote
  already fired at the arrival dispatch's lookup phase — master's
  timing, v10.29.0, round-113 Codex 2/4; the anchor update and
  probation clear wait for the next SUCCESSFULLY COMMITTED unbuffered
  non-close whose effective transition is NEITHER `OverdueSkipped`
  NOR `UpsertRefused`, v10.30.0 round-114 Codex 7 / round-115
  Codex 8);
  a buffered SYN-ACK promotes AT ITS LOOKUP-PHASE post-borrow point
  (v10.29.0, round-113 Codex 2/4 — the v10.28.0 admission-point
  framing is RETRACTED: the pending-queue enqueue is not a
  commit-to-deliver point — an inserted packet can time out
  untransmitted, `neighbor_dispatch.rs:208-232`, and can still fail
  frame access, output-filter/CoS, rewrite, or target dispatch after
  resolution, `:294-325`, `:344-404`; and no producer/carrier exists
  for an enqueue-time apply, `shared_ops.rs:563-578`,
  `poll_descriptor/mod.rs:883`, `:5017-5069`): the §5.5 post-borrow
  establishment promote fires during the arrival dispatch's lookup
  phase, AFTER the borrow ends and BEFORE any disposition/buffering
  decision — master's in-borrow timing (`lookup.rs:129-149`,
  `:173-218`) preserved modulo the borrow boundary, plus the proof
  gate. A cold-neighbor SYN-ACK therefore promotes at arrival exactly
  as master's does (master's promote also fires at lookup, before
  buffering), the forward half never lingers OPENING
  (`session/mod.rs:2135`), and the retry path never re-runs anything
  (unchanged). Master's pre-filter timing is kept: a filter-dropped
  but PROVEN SYN-ACK can promote (master-identical; stated) — with
  the pre-filter split stated exactly (v10.30.0, round-114 Codex 5):
  the pre-filter proof may change ONLY `established`/timing; anchor
  samples adopt ONLY at a successful commit hook (the commit-point
  discipline is unchanged). The promote's apply on the matched
  reverse entry is the FULL transaction, atomic (v10.30.0, round-114
  Codex 4): set `established`, recompute the established/per-app
  timeout, `last_seen_ns = now_ns`, and re-queue the canonical wheel
  key — master sets the flag BEFORE selecting its timeout and pushes
  the wheel (`lookup.rs:146-171`, `:214-218`), so a flag-only move
  would strand the entry on its freshly computed OPENING deadline.
  The forward companion correctly remains flag-only with its absolute
  opening deadline unchanged
  (`session/mod.rs:1243-1252`).
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
  class is MASTER-SPLIT with FULL cache parity (v10.17.0, rounds
  95-100 Codex): with a WARM next hop the purged packet forwards on
  the retained lookup (`session_glue/mod.rs:1194-1196`) — assert NO
  derivation, NO allocation, NO install, NO publication, NO seed, and
  master's own cache behavior (a purged pure-ACK is cache-eligible and
  inserted normally, `flow_cache.rs:352-394`,
  `poll_descriptor/mod.rs:3900-3959`; a follow-up cache-eligible
  packet cache-hits before session resolution, `:298-327` — the
  ForwardFlow install then happens on the next cache-MISSING packet,
  not necessarily packet two; the v10.13-14 suppression shapes are
  retracted, rounds 97-98); with a COLD next hop the packet runs
  master's own seed
  transaction — assert the seed carries master's merge semantics
  (`NatDecision::merge` prefers the retained P1 fields,
  `nat/mod.rs:123-133` — the purge-aftermath released-tuple family is
  pre-existing and documented, §7; assert the transient seed emits NO
  Open, `entry.rs:272-274`), and assert the capacity-refusal rollback
  behavior matches master (including its pre-existing P1/P2 mismatch
  leak, `poll_descriptor/mod.rs:4890-4909` — documented, not
  silently fixed); a LATER genuine clean miss installs the ForwardFlow
  with Open exactly as master: `P2 != P1`,
  current-rule-no-longer-matches yields no translation, the DNAT
  same-address port remap (`destination.rs:699`) is preserved by the
  full fresh derivation, the deterministic persistent reacquire
  (`allocator.rs:1265`) still reacquires `P1`, and the capacity
  rollback at THAT dispatch uses the FRESH `P2`
  (`poll_descriptor/mod.rs:4890` → `nat/source.rs:781`) — the
  round-86/87 correctness tests all run at THIS dispatch, where the
  install happens; the upstream-equivalence assertion is packet-count
  parity for the #6599 class (warm: install on packet two on both;
  cold: transient seeds only on both — and with the purge-path
  retraction the close→ACK cold corner has NO delta at all: both
  versions run the same seed transaction on the current packet's raw
  flags, `poll_descriptor/mod.rs:4787-4795`,
  `install.rs:179-180`, and a following ACK hits the local seed
  first, `shared_ops.rs:594-613` — the earlier 300 s-vs-2 s/30 s
  delta text was a retracted-shape artifact, round-101 Codex 5); (d) a
  genuine top-level
  MISS with a bare
  close still drops at the #4400 guard before the arm (`SeedRefused`);
  (e) a miss with SYN|close combo on a genuinely-new tuple still seeds
  from raw flags (`SeedInstalled`, site-3 residual, self-anchoring
  invented tuple) — and the same SYN|close under peer-synced provenance
  purges and dispatches EXACTLY as master (v10.15.0 — the close-aware
  gate is retracted; the master's-own FreshPrimary/Open follow-through
  is the documented #6599-family exposure, §7 — the clean miss
  requires a WARM next hop or a lapsed transient seed; a live cold
  seed captures the follow-up, `shared_ops.rs:594-613`, round-102
  Codex 7) and
  never displaces a synced local victim (the `ReplacedSyncedLocal`
  skip stands, v10.8.0);
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
- **The purged class is MASTER-SPLIT (v10.13.0 — the v10.4.1
  re-entry is retracted, rounds 94-96 Codex):** the purged packet
  continues the HIT-branch dispatch on the retained lookup
  (`session_glue/mod.rs:1194-1196`) — warm next hop: forward, no
  install, master's own cache behavior (a purged pure-ACK is cached
  normally — full parity, v10.15.0); cold next hop: master's own seed transaction
  (transient, no Open; master's merge-keeps-P1 purge-aftermath is
  pre-existing and documented, §7); the next cache-missing packet's
  genuine clean-miss dispatch installs the
  seed/aliases with the OWNED `P2` and later cleanup releases
  `P2` (no collision with `P1`'s new owner, no leak);
  current-rule-no-longer-matches case — no translation; DNAT
  same-address port remap (`K.dst:443 → same-IP:8443`,
  `destination.rs:699`) is preserved by full derivation (never stranded
  on the stored decision's stale value); persistent deterministic
  reacquire (`allocator.rs:1265`) still reacquires `P1` through the
  allocator (the owned path); the clean-miss dispatch keeps one
  decision object across install, publication, buffering, replay, and
  reinjection (no P1/P2 split at THE INSTALL, `poll_descriptor/mod.rs:5126`
  → `slow_path.rs:199`; master's outer/pending split on the ordinary
  seed path is pre-existing, round-95 Codex 7).
- **Site-2b scope + identity (round-84 Codex 4; scoped v10.34.0,
  round-118 Codex 6):** a `Shared` match
  refuses CLOSE VALIDATION even when the same canonical key is locally
  occupied (a NON-CLOSING Shared match installs master-verbatim — both
  halves asserted); a Local
  match whose re-probed entry disagrees on key or NAT decision refuses
  (the `K/NAT1` shared-alias vs `K/NAT2` local-replacement wrong-flow
  trace); a Local identity-agreeing match validates and marks the
  forward family in the same resolve.
- **Companion-id binding (v10.34.0, round-118 Codex 1/2/7/9; the
  carried expected id v10.36.0, round-120 Codex 4/5/6/7/8; the per-hop
  verify v10.37.0, round-121 Codex 4/5/8/9):** the
  positional fresh-flow reverse install records the forward entry's
  `session_id`; the site-2b Local-match synth records the matched id
  and a Shared-match synth records the SHARED ROW's id (the
  materialize-adopt adopts the same wire id, so the expectation
  verifies once the forward materializes locally; a legacy zero-id row
  → UNBOUND); an HA-imported reverse carries
  `expected_fwd_id` stamped at synthesis from the forward row's id
  (direct import, prewarm, AND singleton paths — all synthesize the
  reverse from the forward row, `shared_ops.rs:750-785`); the
  expectation sits in `fwd_companion_id` and EVERY reverse→forward hop
  verifies the probed forward's id against it plus key+NAT — there is
  NO bind step (a refused forward import leaves the
  local stranger's id ≠ expected → the hop suppresses; the real
  family's later arrival starts verifying immediately); the tunnel
  `UpsertLocal`
  class carries 0 → permanent UNBOUND; a zero-expectation entry
  NEVER verifies on any hop (the stale-R1/stranger-K2 ABA case:
  R1's anchor sample never lands on K2 — K2 minted a distinct id) and
  NEVER rebinds after a mismatch; a stored expectation survives the
  forward
  entry's promotion/refresh and replication unchanged (id write-once
  for same-family refreshes; the promote-republication + local-origin
  publish + bulk-export paths populate the real id; a zero wire id
  ALWAYS fresh-mints — the flip evicts stale tokens, fail-closed);
  the different-family overwrite (the CARRIED incoming id ≠ the stored
  id, or incoming 0) runs remove+install semantics — re-minted/adopted
  id,
  zeroed anchor, gated seed, cleared probation/companion binding (a
  stale K-bound reverse then mismatches S2, and no close validates
  against K's leftover anchor); reverse-direction anchor learning on a
  zero-expectation entry is
  suppressed while forward-direction learning rides the direct
  canonical hit (fail-closed, bounded lingering, §2 posture).
- **Cache precedence + the success postblock (v10.36.0, round-120
  Codex 1/2/3):** an install/upsert/overwrite at key K while a
  descriptor is cached for K → the slot is invalidated and the next
  packet re-resolves (the direct-primary-outranks-alias trace); a
  reverse-direction committed packet applies its anchor sample through
  the TWO carried handles (R for the matched-entry operations, F for
  the anchor), each re-validated at its apply point; the anchor apply
  fires iff `!recycle_now` — a crafted construction-failure packet
  (both arms decline) recycles with ZERO anchor movement; the in-place
  arm (dominant) and the fallback arm both apply.
- **Capacity-corner family state (v10.34.0, round-118 Codex 4;
  v10.35.0 round-119 Codex 6/7; v10.36.0 round-120 Codex 9/10/11/12):**
  an
  accepted close with a capacity-refused reverse install still marks
  the forward family; a LATER reverse synth against the
  marked (closing) forward — NON-CLOSING OR CLOSE-FLAGGED (RST→FIN and
  FIN→RST retries alike) — installs the reverse entry with ONE
  EFFECTIVE INHERITED SEED STATE (the driving packet's flags OR'd with
  the family close bits) driving the timeout/`closing`/`reset`/
  `observed_tcp_flags` computation AND the publish/replication, so the
  sibling reconstructs the same closing state (never born non-closing
  with the established timeout — the companion-retention postponement
  trace); the sibling's shared-hit MATERIALIZATION merges the
  replica's carried close bits over the packet's raw flags (a
  published closing/reset replica is never reconstructed alive by a
  bare-ACK materialization in the publish→replication window); the
  accepted close packet's accounting lands exactly one
  `rev` charge on the forward entry on BOTH install outcomes on
  accounting-eligible forwarded dispositions, at
  master's own chokepoint (`poll_descriptor/mod.rs:3478-3503`) with
  master's own inputs (length/DSCP/disposition), via the carried
  identity-bound fallback target on the install-refused path (typed
  `Site2bOutcome` distinguishes validator refusal from capacity
  refusal; `account_packet -> bool`; the fallback fires only on a
  missed reverse probe — mutually exclusive).
- **Reverse-hit family identity (round-85 Codex 4):** a close
  direct-hitting a separated stale reverse `R1/NAT1` with a replacement
  forward `K/NAT2` present: reciprocity fails (NAT1 ≠ NAT2) →
  REFUSE-DEMOTE — no validation, no mark, no propagation, no Close, no
  fan-out; the orphan reverse ages out `is_reverse`-silent; exact
  tuple+NAT reuse validates the CLOSE (packet-indistinguishable
  generations need no token FOR THE CLOSE MARK — scoped v10.34.0; the
  anchor-learning hop still requires the id binding); a forward-hit
  close propagates only to the reciprocated
  companion.
- **Probation local-only reap (round-83 Codex 2; alias amendment
  v10.15.0, round-98 Codex 5):** a probation expiry
  removes only the local table entry AND invalidates the flow-cache
  entries for the entry's FULL alias set (canonical, reverse
  companion, reverse-translated aliases, forward-wire aliases, and
  reply-match tuples — `lookup.rs:62-100`/`:222-250`/`:253-315`,
  `key.rs:19-26`; exact-key invalidation, `flow_cache.rs:1105-1120`),
  and every adoption invalidates the PRIOR identity's full alias set
  at adopt time (round-99 Codex 4) — assert NO `release_flow` call, NO
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
  → master's ordinary-timeout emission semantics bit-identical for the
  gate's own effects (the purge path is master-identical, v10.19.0).
- **Observability:** `tcp_close_seq_rejected` visible via the worker
  statistics surface (production build); the rate-limited structured
  record fires at the configured rate cap and never per-packet.
- **Layout (v10.34.0, round-118 Codex 8 — exact where advertised,
  bounded where not):** compile-time `size_of`
  gates: `size_of::<TcpSeqAnchor>() == 40` (exact);
  `size_of::<MatchedToken>() == 96` AND
  `size_of::<Option<MatchedToken>>() == 96` (BOTH exact — the
  niche-fill on `MatchSource` is asserted, not assumed);
  `SessionEntry` delta ≤ 56 B (49 B nominal + align-8 tail padding —
  the advertised 49 B/6.1 MiB-per-worker figure is the nominal; the
  WORST CASE at the bound is 56 × 131,072 = 7,340,032 B ≈ 7.0 MiB per
  worker, ≈ 42 MiB at 6 workers, stated so the bound and the headline
  cannot diverge silently); `FlowCacheEntry` delta ≤ 104 B (96 B
  niche-filled, 104 B if the niche does not fill — worst case 104 ×
  4,096 = +416 KiB per binding); `SessionEntry` growth accounted in
  the slab sizing comment.
- **Cache identity-mismatch telemetry (v10.33.0, round-117 Codex 7):**
  a crafted packet whose cached binding fails the identity check
  produces ZERO cached-decision consumer effects (no TTL handling, no
  filter/policy counter, no policer, no log, no reject synthesis, no
  terminal drop), exactly one `invalidate_slot` + `FallThrough`, one
  slow-path re-resolution and re-insert, and hit/miss/byte telemetry
  deltas bit-identical to a master validity failure (stale-neighbor-MAC
  hit) — the identity check adds WHICH packets fail the gate, never a
  new accounting shape.

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
failover — imported entries refuse closes until churn OR until master's
own flag-agnostic purge removes them first (never 'never reap early'
without that exemption — v10.21.0, round-104 Codex 8; same scope at
the 'reduces reap rate' claim below, round-105 Codex 6) (the §2
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
ordering, and REDUCES reap rate (refused closes never reap early FROM
THE GATE'S OWN EFFECTS — master's independent flag-agnostic purge of a
transient-purge-class entry still deletes the row,
`promote.rs:48-59`, `:167-207`; v10.23.0, round-106 Codex 6), so it
neither fixes nor worsens #6522. **Recommendation: drive #6522 as its own
`/engineer` effort with the minimal fix first** (a per-allocation replica
refcount or an owner-only release rule — the refcount is a local
allocator change, not a protocol), pulling from the v9.x design record on
this branch only if the minimal fix proves insufficient.

#### 10.6.2 Pre-existing lifecycle races (follow-up candidates, documented in §7)

- **Transient-purge/Open provenance-integrity (v10.9.0, round-92 Codex
  1):** the non-owner purge path lets a LATER clean-miss packet install
  an identity-less fresh flow and emit a latest-generation-wins Open
  that overwrites the peer's authoritative family — a spoofed first
  packet with the victim's translated tuple drives it on master
  TODAY (the driving packet is a SYN; a SYN-bearing CLOSE variant —
  close purges, SYN|close clean-misses and installs with closing
  seeded + Open — is the same class with a closing second packet,
  warm-or-lapsed-seed only, v10.16.0 round-99 Codex 5), and v10.15.0
  keeps the plan's dispatch here packet-for-packet master-identical
  (the v10.4.1 same-dispatch re-entry, which had collapsed the class
  from two packets to one, is retracted). The fix is sync-layer
  identity (fenced provenance on Open/Close deltas, or
  provenance-aware purge) — Phase-2-adjacent (§10.5) and in any case
  its own issue; this plan's gate leaves the class's Open-overwrite
  mechanism master-identical but DOES engage on the first close's
  pre-purge lookup — the deliberate delta (refusing the mark on the
  anchorless entry) LENGTHENS the conflicted companion's exposure on
  its ordinary trajectory where master would have set the 2 s/30 s
  closing window (rounds 99-102 Codex; §5.2 (iv)); the harm's
  mechanism is the later constructor-side Open, which no demote gate
  can reach. Tracked as #6599.
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

## 11. Open questions for the convergence round (v10.37.0)

1. **The terminal cut itself:** Part A (the gate) + the wire-free
   Part-B rules (closing-never-promote ×2, constructor gating with
   probation + local-only probation reap, normative mark-creation with
   master's emission gate unchanged, the site-9 typed-outcome gate (the v10.4.1 re-entry
   retracted to master-verbatim at v10.11.0), the 2b
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
3. **Round-86..99 fold verification:** (a) the purged class dispatches
   MASTER-SPLIT with full cache parity (v10.15.0): warm — retained-
   lookup forward, no install, master's own cache behavior; cold —
   master's own seed transaction (merge-keeps-P1 included, documented
   pre-existing); the ForwardFlow install lands on the later clean
   miss with a fresh derivation. (The v10.4.1 same-dispatch re-entry this question once
   referenced is retracted — the sole-decision and DNAT port-remap
   concerns it addressed now land at the clean-miss install, §5.2 (iv).)
   (b) propagation-target reciprocity
   (direction-aware) — is the wrong-mark trace on the unrelated
   occupant B dead in both directions, with positive coverage for
   SNAT/hairpin/NPTv6/NAT64 families? (c) the `account_packet` wording
   (counters/flags advance per the pre-existing #2501 accounting —
   on a purge-dispatched close exactly as master, the round-95 Codex 6
   telemetry-only note; the anchor rides the distinct post-admission
   hook) — consistent everywhere now (§5.2, §5.8, §7, §9)? (d) the probation
   deferred refresh (round-88) — is any pre-commit refresh/requeue
   path left for a probation entry (lookup, `touch_if_stale`, promote,
   materialize refresh), and does the commit-hook clear+refresh cover
   every admission arm? (e) the v10.37.0 end-state: the state-keyed
   2b proof, the per-hop verified expectation (no bind step), the
   two-handle carrier with the Optional family handle, the early
   identity check, the full-family precedence invalidation with its
   two drains, and the §9 matrix — is any
   producer path or consumer ordering still two-readable?

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
   reservation race) — both PRE-EXISTING master exposures; the demote
   gate engages on the first close's pre-purge lookup (the deliberate
   documented refusal delta) but cannot prevent the constructor-side
   Open that carries the harm (v10.16.0, round-99 Codex 5; round-101
   Codex 6). Does
   anything further MUST ship in this
   plan for the issue's fix to be safe? Trace required.
