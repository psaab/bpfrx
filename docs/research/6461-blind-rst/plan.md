# #6461 — blind off-path TCP RST/FIN demotes a live session with no sequence validation

**Status: DRAFT v1 — pending adversarial plan review**

Research branch: `research/6461-blind-rst`. Plan-only deliverable; no
production code is changed by this branch. Implementation begins only after
manual approval via `/engineer 6461`.

---

## 1. Issue framing

A single blind off-path TCP RST or FIN whose 5-tuple matches a live session
permanently demotes that session to the 2 s (RST) / 30 s (FIN) reaper window.
There is no sequence-number validation anywhere on the session-HIT path:

- `userspace-dp/src/session/lookup.rs:105-128` — every lookup computes
  `do_close = is_tcp && is_closing(tcp_flags)` and, on a FIN/RST-bearing
  segment, sets `entry.closing = true` (sticky, #3489) and
  `entry.reset |= has_rst(...)` (sticky, #3046). `SessionEntry` carries no
  sequence state at all.
- `lookup.rs:151-156` — every subsequent hit (including the attack packet
  itself) recomputes `expires_after_ns` to `TCP_RST_TIMEOUT_NS` (2 s) or
  `TCP_CLOSING_TIMEOUT_NS` (30 s).
- `userspace-dp/src/session/mod.rs:1232-1278`
  (`propagate_tcp_state_to_companion`, #4109) — the close is mirrored onto the
  forward/reverse companion entry, so both halves reap together.
- The session-miss path is already guarded (#4400
  `strict_syn_check_drops_new_flow`): a bare RST/FIN never *seeds* a session.
  The vulnerability is strictly the HIT path.

Attack trace: the attacker knows or guesses a 5-tuple (well-known services,
observable/shared segments, SNAT pools with predictable port allocation) and
sends one RST or FIN. The entry flips to closing+reset stickily; the first
≥2 s idle gap (routine for SSH/BGP/IKE/management flows) reaps it; the wheel
expiry emits a Close `SessionDelta` (`session/expire.rs:346-377`), which the
Go eventstream turns into an HA session-sync delete that also kills the
standby copy. The next real packet is a session miss and must re-seed; per
the verifier, a SNAT'd flow's re-seed can allocate a *new* pool port,
changing the translated source mid-connection and killing the endpoint TCP
state even if the endpoints themselves ignored the RST (modern stacks do,
per RFC 5961). Repeating the RST keeps the flow dead indefinitely.

The design question the issue poses: **what does Junos actually do here, and
what xpf behavior closes the DoS without breaking legitimate teardowns**
(asymmetric routing, RST after idle, half-open edges)?

### What Junos actually does (researched, sources below)

- **Default RST handling**: on a tuple-matching RST, Junos sets the session
  to time out **2 seconds** later — xpf's `TCP_RST_TIMEOUT_NS = 2s` (#3046)
  is exact Junos-default parity. `set security flow tcp-session
  rst-invalidate-session` (off by default) makes teardown *immediate*.
  `fin-invalidate-session` is the FIN analogue.
- **Default sequence check**: Junos *does* window-based TCP sequence checking
  by default ("monitors the sequence numbers in TCP segments ... detects the
  window scale ... if the device detects a sequence number outside this
  range, it drops the packet"); `no-sequence-check` disables it. xpf parses
  `no-sequence-check` today but enforces nothing (#2008 M9 / #2078 — the
  commit-time warning says "the userspace dataplane has no TCP state
  machine").
- **RST-specific check**: `set security flow tcp-session
  rst-sequence-check` (off by default) verifies the RST's sequence number
  "matches the previous sequence number for a packet in that session or is
  the next higher number incrementally"; on mismatch Junos **drops the
  packet and sends the host a TCP ACK with the correct sequence number** —
  i.e. the RFC 5961 §3.2 challenge-ACK shape, implemented by the middlebox.

So the honest parity story: xpf today == Junos *default* (2 s reap, no RST
seq validation). The issue class is robustness-DoS hardening, not a parity
failure — and Junos's own answer to this exact attack is an opt-in knob.

### RFC 5961 §3 (the endpoint-side mitigation shape)

- §3.2 (RST): in synchronized states, a RST with `SEG.SEQ` completely outside
  `[RCV.NXT, RCV.NXT + RCV.WND]` is silently dropped; an in-window but
  non-exact RST elicits a rate-limited challenge ACK and the connection
  survives; only `SEG.SEQ == RCV.NXT` aborts.
- §3.3 (SYN): same shape for stray SYNs.
- §3.4 (data/ACK): ACK-number plausibility checks, challenge ACK on
  implausible values.

A middlebox cannot know either endpoint's exact `RCV.NXT` and cannot
implement exact-match abort. The middlebox-feasible subset is the *outer*
rule: refuse to act on a closing segment whose sequence placement is
implausible given observed flow state. That is exactly Junos's
`rst-sequence-check` ("previous sequence number or next higher
incrementally") and is the shape this plan adopts — but applied only to the
firewall's own *state demotion*, not (in v1) to packet delivery.

Sources:
- <https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-rst-invalidate-session.html>
- <https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-no-sequence-check.html>
- <https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-rst-sequence-check.html>
- <https://www.juniper.net/documentation/us/en/software/junos/flow-packet-processing/topics/topic-map/security-tcp-session-checks.html>
- RFC 5961 §3.2/§3.3/§3.4.

---

## 2. Honest scope/value framing

What the fix buys, at absolute scale:

- Removes a **single-packet, off-path, no-infrastructure** kill of any
  chosen TCP flow through the firewall (plus its HA standby copy, plus a
  SNAT pool-port mid-flow swap). Today the attack costs the attacker one
  packet per ~2 s and works on the first guess that lands the tuple.
- After the fix, the attacker must place `SEG.SEQ` inside a tracked window
  whose floor is 128 KiB (64 KiB back-slack + 64 KiB forward floor) out of
  2^32 — a ≥32768× reduction per guess for a fresh baseline — *and* the
  endpoints themselves still apply their own RFC 5961 checks, so the
  residual only re-opens the firewall-state demote, not the connection.
- Cost: ~16 bytes of new per-session state (TCP only), two `u32` max-stores
  per TCP packet on the flow-cache hit path (on a cache entry the hit path
  already mutates for byte accounting), one 8-byte TCP-header read per
  slow-path TCP segment, and a branch only on closing-flag segments (which
  already bypass the flow cache and take the full slow path).

What the fix does **not** buy: protection against an on-path attacker (who
observes sequence numbers and wins regardless — out of threat model), or
against a determined off-path flood that includes an in-window guess (the
firewall demote can still be forced with enough tries; the endpoint stays
protected by its own RFC 5961 handling, and a flood of that size is a
different, screen-visible attack class). It also does not implement Junos's
general per-packet data-plane sequence check (see §10, out of scope).

*If reviewers conclude the residual attack surface or the blast radius does
not justify the churn (new per-entry state, three marking sites, flow-cache
layout change), PLAN-KILL is an acceptable verdict — the parity argument
(xpf == Junos default today) is honest and is documented in §1.*

---

## 3. What's already shipped / partially batched

- **#3046** — sticky `reset` flag + 2 s RST reap (Junos parity).
- **#3152** — OPENING/ESTABLISHED half-open state machine; mid-stream pickup
  seeds ESTABLISHED from a non-SYN first packet (asymmetric-routing
  preservation). Any seq-validation design must keep mid-stream pickup
  working — a pickup session has a baseline from its first observed packet,
  so this composes.
- **#3489** — sticky `closing` in `update_session` (write path).
- **#4109** — F16/F17 companion propagation
  (`propagate_tcp_state_to_companion`): a close marked on one half is
  mirrored onto the other. Validation placed *before* the mark is inherited
  by the companion for free.
- **#4400** — `strict_syn_check_drops_new_flow`: bare RST/FIN dropped on
  session MISS (never seeds). Applied unconditionally, no config knob — the
  precedent for always-on hardening on this boundary.
- **#4453** — same predicate excludes bare RST/FIN from the fabric return
  fast path.
- **#4539/#4487/#2151** — host-inbound LocalDelivery caches a session only
  off the handshake; declined non-SYN first packets are still delivered to
  the local stack.
- **#2008 M9 / #2078** — `set security flow tcp-session no-sequence-check`
  parsed, explicitly *unenforced* (commit-time warning "config-only parity").
  Junos knob namespace already exists; `rst-sequence-check`,
  `rst-invalidate-session`, `fin-invalidate-session` are *not* in the xpf
  schema today.
- **Flow cache** (`afxdp/flow_cache.rs`): `packet_eligible` admits only UDP
  and TCP pure-ACK (`is_ack_only` = `(flags & 0x17) == 0x10`; PSH/URG
  ignored). **Every FIN/RST segment bypasses the cache and transits the slow
  path** — that is why one RST reaches `lookup_with_origin` every time, and
  also why the session entry alone cannot see bulk-transfer sequence
  progress (§5, tracking design).
- **#6457 (in flight, adjacent worktree)** — flow-cache delete/invalidate on
  session reap. This plan adds fields to `FlowCacheEntry`; merge order must
  be coordinated (either order works; the layouts are independent but the
  same file is touched).
- **TCP reply builders** (`afxdp/frame/tcp.rs`): `build_reject_rst_frame`,
  SYN-cookie builders, and `parse_tcp_reply_source` (seq/ack extraction)
  already exist — relevant only to the v2 drop+challenge-ACK option (§4,
  Option B).

### Legitimate teardown callers (complete inventory — the "do not break" list)

1. **Endpoint FIN/RST on the HIT path** — `lookup_with_origin`
   (`session/lookup.rs:105-128`) via
   `session_glue::resolve_flow_session_decision` →
   `lookup_session_across_scopes` (`afxdp/shared_ops.rs:594`). The packet's
   `tcp_flags` come from `meta.tcp_flags`; **the shim meta carries no
   seq/ack** (`UserspaceDpMeta` has flags/ports/addrs/offsets only).
2. **HA shared-promote with a real packet** — `maybe_promote_synced_session`
   (`afxdp/session_glue/promote.rs:99`) → `promote_synced_with_origin` →
   `update_session` (`session/mod.rs:1398-1412`), which re-marks
   `closing`/`reset` from the promoting packet's flags (#3489 stickiness).
3. **Materialize-on-shared-hit** — `materialize_shared_session_hit`
   (`afxdp/session_glue/mod.rs:1092-1122`) → `upsert_synced_with_origin`
   (`session/install.rs:399-400`), which *seeds* `closing`/`reset` from the
   current packet's flags at replica-install time.
4. **HA wire re-import** — `UpsertSynced` command →
   `upsert_synced_with_origin` with `entry.tcp_flags` carried from the wire
   producer. No packet exists to validate; this path must stay
   validation-free (the *originating* node validated before it reaped and
   emitted the Close; a re-import of close state is authoritative).
5. **CLI / control deletes** — `clear security flow session`,
   `DeleteSynced`, policy-delete sweeps: explicit deletes, unaffected.
6. **GC/reaper** — `expire_stale_entries_ha` (`session/expire.rs`): consumes
   `closing`/`reset` to pick the reap window; emits the Close delta + RT_FLOW
   harvest. Consumes, never marks.
7. **Screens / SYN-cookie** — `screen/mod.rs` `is_closing` uses are
   cookie-validation only; not a teardown-marking site.

Validation must gate sites 1–3 (packet-driven marking) and must **not** gate
site 4 (wire-driven re-import). Sites 5–7 are untouched.

---

## 4. Multiple path options

### Option A — sequence-window demote gate, state-only (RECOMMENDED)

Track per-direction sequence progress; gate **only** the
`closing`/`reset` demotion (and its companion propagation) on the closing
segment's sequence placement. The packet itself is always forwarded
unchanged — endpoint teardown delivery is never blocked, so no legitimate
teardown can be broken by the firewall; the worst failure is a *refused
demote* (entry idles out on its normal timeout, exactly as if the RST had
been lost in transit — a condition #3046 already tolerates by design).

- Always-on (no config knob), mirroring the #4400 precedent: the gate can
  only make the firewall *more* conservative about killing state, never
  less, so there is no legitimate configuration that needs it off.
- Fail-open whenever no baseline exists (HA-synced entries never locally
  observed, site 4 re-imports): demote exactly as today. The active node,
  which sees the traffic, is the validating node — a standby copy dying via
  the peer's Close delta is the *correct* propagation of a validated close.

### Option B — Junos `rst-sequence-check` parity (drop + challenge ACK)

Implement Junos's exact knob: out-of-window RST is **dropped** and the
firewall emits a corrective ACK toward the RST's destination (the
`parse_tcp_reply_source` / reply-builder machinery exists). Off by default
behind a new `set security flow tcp-session rst-sequence-check` leaf
(Junos-accurate default), or on by default with a disable leaf.

- Pros: also shields pre-RFC-5961 endpoints; Junos-shape parity; the
  challenge ACK actively proves liveness (a real peer answers, a blind
  attacker cannot).
- Cons: the firewall now *originates* TCP segments mid-flow (new failure
  modes: challenge-ACK storms need rate limiting; spoofed-source interplay
  with uRPF downstream; TX budget on the hot path); a *stale-baseline false
  refuse* now blackholes a legitimate RST (delivery blocked) — the exact
  breakage the issue forbids; bigger surface (config schema + compiler +
  docs + reply path). Rejected for v1; viable follow-up once Option A's
  tracking proves accurate in the field.

### Option C — bidirectional-confirmation teardown (no sequence state)

Demote a FIN only after FIN-class flags are seen in *both* directions;
demote a RST only after... a RST is normally one-directional (RFC 793: a
RST elicits no response), so bidirectional confirmation would *never*
fast-reap a legitimate one-way RST — the #3046 fast-reap dies and
RST-churn workloads (scans, abort-heavy apps) hold dead entries for the
full established/OPENING window. Rejected: trades the DoS for a session-
table-pressure regression. (The FIN half of the idea is subsumed by Option
A's fail-open: an unverifiable FIN simply doesn't demote early, which is
the same end state with less machinery.)

### Option D — status quo + documentation (PLAN-KILL flavor)

xpf already matches Junos default; the honest class is robustness-DoS;
Junos ships its own mitigation off-by-default. If the review concludes the
attack's preconditions (tuple knowledge) plus the endpoint-side RFC 5961
ubiquity make the residual acceptable, close as won't-fix with the analysis
documented. Presented for completeness; not recommended — the issue's teeth
(firewall-state kill + SNAT port swap + HA propagation) apply *even when
both endpoints are RFC 5961-immune*, which is precisely the modern-stack
case where the endpoint argument is strongest.

---

## 5. Concrete design (Option A)

### 5.1 New tracking state

`SessionEntry` (TCP sessions only meaningful; zero-cost for others), 16 B:

```rust
/// #6461: per-direction sequence/ack progress, used ONLY to validate
/// FIN/RST demotion. Node-local derived state — NOT carried on the HA
/// session-sync wire (same precedent as `established`, #3152). Wrapping
/// (RFC 1982) serial arithmetic throughout.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TcpSeqTrack {
    /// max(seq + seg_len) seen in this entry's direction; valid iff
    /// `flags & TRACK_SEQ_VALID`. seg_len = payload + SYN + FIN bits.
    seq_hi: u32,
    /// max ack number seen on ACK-bearing segments in this direction;
    /// valid iff `flags & TRACK_ACK_VALID`. A→B acks bound the *reverse*
    /// direction's current sequence position (A's RCV.NXT), which is the
    /// only baseline available for a direction this node never observed
    /// (asymmetric routing).
    ack_hi: u32,
    /// Last advertised raw window (16-bit wire value, unscaled — wscale
    /// lives in SYN options this node usually never saw). Used only as an
    /// input to the forward-slack clamp, never trusted as the true window.
    wnd: u16,
    flags: u8, // bit0 seq valid, bit1 ack valid
    _pad: u8,
}
```

`FlowCacheEntry` (per-direction by construction — the cache key is the
packet's direction tuple): add `tcp_seq_hi: u32, tcp_ack_hi: u32` (8 B),
updated on the hit path (§5.3). The cache entry covers exactly the phase
the session entry cannot see (bulk transfer served from the cache).

### 5.2 Tracking update sites

1. **`lookup_with_origin`** (slow path): when `is_tcp`, update the matched
   entry's track from the current segment *before* the closing decision
   (wrapping-max for seq_hi/ack_hi; store wnd). The entry is already
   mutably borrowed; the segment's seq/ack must be threaded in (§5.5
   signature change).
2. **Flow-cache hit path** (`lookup_counted` / `stage_flow_cache_hit`):
   when `meta.protocol == PROTO_TCP`, read the 8 bytes at
   `frame[meta.l4_offset + 4 .. + 12]` → `(seq, ack)`;
   `seg_len = (meta.pkt_len - meta.payload_offset) + has_syn + has_fin`
   (all from meta — no new walking); two wrapping-max stores on the cache
   entry the hit path already mutates for `observed_bytes`. No allocation,
   no atomic, same cacheline.
3. **Install sites** (`session/install.rs`): seed the track from the
   creating packet when one exists (local miss / ForwardCandidate /
   materialize-on-hit — all have the frame at the call site); seed
   empty (fail-open) for wire-driven imports.

### 5.3 The validation rule (single SSOT)

```rust
/// #6461: RFC 5961 §3.2-inspired middlebox gate. A FIN/RST demotes only
/// when its sequence placement is plausible given tracked flow state.
/// Fail-open (returns true) whenever no baseline exists — a standby /
/// re-imported entry must not invent a stricter policy than the active
/// node's.
fn close_seq_plausible(track2: &TcpSeqTrack2Dir, dir_is_reverse: bool,
                       seq: u32, ack: u32, flags: u8) -> bool;
```

For a closing segment in direction D (opposite direction O):

1. **OPENING session** (`!established`): baselines are the handshake ISNs
   (forward SYN seeded `seq_hi = isn+1` at install). Accept iff
   `(ACK set && seq_distance(ack, seq_hi(D')) small)` or `seq == seq_hi(D)`
   — i.e. RFC 5961's SYN-SENT-state rule (validate the ACK field) plus the
   self-abort case. Missing baseline → fail-open.
2. **ESTABLISHED, D observed** (`TRACK_SEQ_VALID` on D): accept iff
   `seq ∈ [seq_hi(D) − BACK_SLACK, seq_hi(D) + FWD_SLACK]` where
   - `BACK_SLACK = 64 KiB` (covers reordered keepalives/retransmits; a real
     RST is generated at `SND.NXT`, never far behind);
   - `FWD_SLACK = clamp(wnd(O), 64 KiB, 4 MiB)` — bounds in-flight data
     between the last observed segment and the abort. The raw 16-bit `wnd`
     *understates* the true window when wscale is in play; the 4 MiB cap
     keeps a blind guess at ≤ ~1/1024 of the sequence space, and a refuse
     is always soft (§4 Option A failure mode).
   - The effective `seq_hi(D)` is the wrapping-max of the session-entry
     track and the flow-cache-entry track for D (the union is fresh to the
     last packet in both cacheable and non-cacheable flows).
3. **ESTABLISHED, D never observed, O observed** (asymmetric): accept iff
   `seq ∈ [ack_hi(O) − BACK_SLACK, ack_hi(O) + FWD_SLACK]` — O's ACK stream
   pins D's current send position (A's RCV.NXT for B's data).
4. **Neither direction observed** (synced import, no local traffic):
   fail-open (demote as today).
5. All comparisons via `wrapping_sub` serial arithmetic (RFC 1982); the
   window test is `seq.wrapping_sub(lo) <= (hi - lo)` — branchless.

A refused demote leaves `closing`/`reset` untouched, still refreshes
`last_seen_ns` (the packet *is* flow activity), and increments a
worker-owned `tcp_close_seq_rejected: u64` counter (+ `debug_log!` one-shot
per session transition, never per-packet Info).

### 5.4 Where the verdict is applied

- `lookup.rs:105-128` — compute `do_close` as today, then
  `do_close &= close_seq_plausible(...)` before marking. Companion
  propagation (#4109) fires only on a validated mark → inherits the gate.
- `update_session` (`mod.rs:1398-1412`) — same conjunction for the
  write-path sticky marks; the seq/ack of the triggering packet is threaded
  through `SessionUpdate` (site 2 in §3). Wire-driven callers (no packet)
  pass a "no packet" sentinel → skip validation (site 4 stays open).
- `materialize_shared_session_hit` — validate the current packet *before*
  `upsert_synced_with_origin`; on refuse, materialize with `closing =
  false` seed regardless of the packet's flags (the replica must not be
  born dying).

### 5.5 Signature changes (all crate-internal)

- `lookup_with_origin(key, now_ns, tcp_flags)` → gains a
  `seg: TcpSegView` (Copy struct: `seq, ack, wnd, valid`) —
  `Option<(u32,u32,u16)>` in disguise; `None` for the ICMP-embedded lookups
  (`icmp_embed/*` pass `tcp_flags = 0` today → `is_closing` false →
  validation never fires; they pass `TcpSegView::NONE`).
- `SessionUpdate` + `SessionInstall` gain the same `seg` field.
- New helper `afxdp/frame/tcp.rs::tcp_seq_ack_wnd(frame, meta)
  -> Option<TcpSegView>` using the ext-aware `frame_l4_offset` walker —
  called **only** on TCP segments reaching the session slow path (never on
  the cache-hit fast path, which reads its 8 bytes inline from meta
  offsets).
- `resolve_flow_session_decision` / `lookup_session_across_scopes` thread
  `seg` plus the cache-track union hint (read by the `poll_descriptor`
  caller, which owns `flow_state.flow_cache`).

### 5.6 What does NOT change

- Packet forwarding: a refused RST/FIN is forwarded exactly as today. No
  packet is dropped by this work; no challenge ACK is generated (v2,
  Option B).
- HA wire format, shared-map schema, `SessionSyncRequest`: no change
  (track is node-local derived state, `established`-precedent).
- The 2 s/30 s reap windows, the wheel, the Close-delta/RT_FLOW harvest:
  consumers of the marks, untouched.
- The #4400/#4453 miss-path guards: untouched.
- Config schema: no new leaf in v1 (see §10 for the deferred knob work).

---

## 6. Public API preservation

No public API exists to preserve: `SessionTable`, `lookup_with_origin`,
`update_session`, `upsert_synced_with_origin`, `FlowCacheEntry` are all
`pub(crate)`/`pub(super)`. gRPC/REST/CLI surfaces unchanged. HA sync wire
unchanged (rolling-upgrade safe by construction: no wire field added or
reinterpreted). The `UserspaceDpMeta` shim layout is unchanged — no
`make generate`, no kernel-verifier gate.

---

## 7. Hidden invariants the change must preserve

- **Side-effect ordering**: in `lookup_with_origin`, the track update must
  land *before* the closing decision reads it (same `&mut` borrow); the
  `push_to_wheel` and companion propagation ordering after the borrow ends
  is unchanged.
- **Stickiness contracts**: `closing` (#3489), `reset` (#3046),
  `established` (#3152) remain monotone within an entry's life. The gate
  only *withholds* a mark; it never clears one. A validated close followed
  by a refused close must leave the 2 s/30 s selection exactly as #3046
  specified (`reset |= has_rst` ordering vs timeout selection).
- **Hot-path allocation/atomic rules**: zero new allocations; zero new
  atomics; two `u32` wrapping-max stores per TCP cache hit on an entry
  already dirtied for counters. FlowCacheEntry stays `Copy`-compatible and
  its per-worker single-threaded ownership is unchanged.
- **Borrow shape**: the cache-track union hint must be read *before*
  `resolve_flow_session_decision` borrows `sessions` (poll_descriptor owns
  both; pass by value). No new cross-`&mut` aliasing.
- **HA portability**: synced entries import with an empty track (fail-open)
  — a standby must not apply a stricter gate than the active node that owns
  the baseline. On failover the first locally-observed segments build the
  baseline; teardowns before that behave exactly as today.
- **Serial arithmetic**: every comparison RFC 1982 wrapping; a `const _:
  () = assert!` pins `BACK_SLACK + FWD_SLACK_MAX < 2^31` so the window test
  can never straddle the serial midpoint.
- **Flow-cache invalidation**: a reaped session's cache slot is invalidated
  (#6457, adjacent) — the cache-side track dies with the flow; no stale
  baseline can outlive the session it described.
- **`icmp_embed` lookups**: pass `TcpSegView::NONE` + flags 0 — behavior
  byte-identical.

---

## 8. Risk assessment

| Class | Verdict | Notes |
|---|---|---|
| Behavioral regression | MED | Mitigated by design: gate only *withholds* demotion, never blocks delivery; fail-open on missing baseline. Residuals: (a) refused legit RST on a wildly mis-tracked baseline → entry idles ≤ established timeout (Junos-default 2 s reap degraded for that flow only); (b) tuple-reuse block for the lingering window — pre-existing semantics for flows that die silently today. |
| Lifetime / borrow-checker | LOW | All new state is `Copy` POD inside existing owned entries; no new borrows across module boundaries; signature threading is mechanical. |
| Performance regression | LOW | Slow path: one 8-byte header read per TCP segment that already transits it. Fast path: two max-stores + one 8-byte read per TCP packet on an already-mutated cache entry — measurable only by the perf rig; expected inside noise, must be confirmed (§9). |
| Architectural mismatch | LOW | No new subsystem; follows the `established` (#3152) node-local-state precedent and the #4400 always-on-gate precedent. Not a #961/#946-Phase-2 dead-end: no pipeline restructure. |
| HA / rolling upgrade | LOW | No wire change; mixed-version peers behave as today (old peer = ungated, new peer = gated; each node gates only its own packet-driven marks). |
| Merge collision | LOW-MED | #6457 (flowcache-delete-invalidate) touches `flow_cache.rs`; coordinate merge order. |

---

## 9. Test plan

Unit (cargo, `userspace-dp/src/session/` + `afxdp/`):

- Validator truth table: ESTABLISHED with fresh baseline (accept in-window
  RST/FIN, refuse low/high out-of-window, refuse far-future), serial-wrap
  edges (baseline near 2^32−1), asymmetric (ack-derived window only),
  OPENING (ack==isn+1 accept, wrong-ack refuse, missing-baseline fail-open),
  no-baseline fail-open, SYN-bearing closing segments.
- Table level: install → data segments build track → blind RST
  out-of-window → entry *not* closing, `tcp_close_seq_rejected` bumped,
  `expires_after_ns` unchanged; in-window RST → closing + 2 s selection +
  companion inherited; refused FIN leaves 300 s established window;
  `update_session` promote path gated identically; materialize-on-hit with
  refused RST seeds `closing=false`.
- Cache tracking: hit-path max-update monotonicity, PSH+ACK segments
  update, union hint read.
- Existing suites must stay green: `make test-rust` (full cargo suite) and
  `make test-go` (30 Go packages — no Go change expected, run anyway).

Smoke (loss userspace cluster, lock protocol per CLAUDE.md):

- `make cluster-deploy` + re-apply CoS.
- Baseline: `iperf3 -P 16 -t 30 -p 5203` → 172.16.80.200 ≥ 23 Gbit/s
  (fast-path cost check — compare against pre-change run; also exercises
  the cache-track path at rate).
- Attack negative test: long-lived SSH + iperf3 flow trust→untrust; from an
  off-path host inject tuple-matching RST/FIN with random seq (scapy) →
  flow survives, `show security flow session` still shows the session
  established (not closing), flow continues at line rate.
- Legit-teardown positive test: capture the live seq (tcpdump on the
  receiver), craft an in-window RST → session demotes/reaps (2 s) exactly
  as today; normal Ctrl-C / socket-close teardown of iperf3 and SSH behaves
  identically to master.
- HA: `make test-failover` (mandatory — session-sync/failover adjacency),
  verify standby copy survives the blind-RST run and dies only on the
  validated-close run.

---

## 10. Out of scope (explicitly)

- Junos general per-packet sequence check (`no-sequence-check` enforcement,
  #2008 M9 / #2078) — the data-plane window check on *every* segment.
  Bigger, throughput-sensitive, asymmetric-routing-hostile; separate issue.
- Option B (drop + challenge-ACK, `rst-sequence-check` leaf) and the
  `rst-invalidate-session` / `fin-invalidate-session` knobs (immediate
  teardown) — deferred until Option A's tracking accuracy is proven in the
  field.
- Per-session refused-close rate limiting (attack-escalation latch) —
  follow-up if field data shows flood-forcing of the window.
- SYN-segment validation (RFC 5961 §3.3) — different attack class
  (session desync, not teardown); no demote path consumes SYN today.
- Any change to reap windows, wheel, deltas, RT_FLOW, or the Go control
  plane.

---

## 11. Open questions for adversarial review

1. **Baseline freshness for cacheable flows.** The plan's core claim is
   that session-entry track ∪ flow-cache-entry track is fresh to the last
   packet. Is there any TCP path that forwards packets while *bypassing
   both* (e.g. fabric-egress TX of a peer-resolved flow, tunnel-encap
   paths, LocalDelivery replies)? A bypass that serves bulk data makes the
   baseline stale and turns legit-RST refuse from rare to routine. If such
   a path exists and cannot be cheaply tracked, does the design hold?
2. **The 4 MiB forward-slack cap** vs wscale-blindness: on a 10–25 Gbps
   flow with a large scaled window, in-flight data at abort time can exceed
   4 MiB, so a legit RST falls outside `[seq_hi − 64K, seq_hi + 4M]` and
   the demote is refused (soft-fail: entry lingers ≤300 s, tuple busy).
   Is that residual acceptable, or should the cap be raised (cost: blind-
   guess probability) / derived differently?
3. **HA replica-close edge**: in split-RG active/active, a blind RST
   ingressing the *non-owner* node can demote that node's materialized
   replica (no local baseline → fail-open). If the replica's reap emits a
   Close delta that the *owner* honors against its authoritative entry,
   the attack survives Option A via the HA path. Is the replica→owner
   Close propagation gated (by origin/ownership/install-generation, cf.
   #2170 `DeletesStaleIgnored`), or is this a real hole the plan must also
   close (e.g. replicas with peer-synced origins never emit Close deltas)?
4. **OPENING validation strictness**: requiring `ack == client_isn+1` for a
   reverse RST|ACK matches RFC 5961's SYN-SENT rule, but real stacks send
   connection-refused RSTs with varying seq/ack placements (seq=0 vs
   seq=ack). Is the planned rule (ack-derived OR seq-derived, fail-open on
   missing baseline) tight enough to matter and loose enough to never
   refuse a real refused-connection RST?
5. **Always-on vs Junos-knob parity**: the plan recommends no config leaf
   (gate only withholds demotion; #4400 precedent). Reviewers: is there
   *any* deployment shape (full asymmetry with one-way visibility and no
   ACK visibility — e.g. blind forwarding of a one-way stream) where
   fail-open doesn't cover and the gate refuses a legit teardown? If yes,
   is a `no-rst-sequence-gate` escape leaf warranted despite the doctrine?
6. **Should a refused close still refresh `last_seen_ns`?** Plan says yes
   (the packet is flow activity; refusing the refresh would let an attacker
   idle-out the entry — a weaker but real demote). Counter-argument: an
   out-of-window RST is *not* evidence the flow is alive, and Junos's
   default reap is activity-driven. Which reading is correct for the
   30 s FIN window in particular?
7. **The cache-entry tracking** adds 8 B/entry and two stores/packet to the
   hottest structure in the dataplane. Is the §9 perf-rig check sufficient
   evidence, or should the tracking be compile-gated on TCP-only (it is)
   and measured with `perf` on the 6-queue mlx5 rig before merge?
