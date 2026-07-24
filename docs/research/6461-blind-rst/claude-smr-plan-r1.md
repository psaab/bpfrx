# Claude SMR hostile plan review — round 1 — #6461 blind-RST demote gate

Reviewer: Claude (SMR pass, adversarial by design). Scope: plan v1
(`docs/research/6461-blind-rst/plan.md` @ c676ac96b), Codex r1 verdict
(PLAN NO, 12 findings), AGY r1 partial coverage (Q1–Q7 across three runs).
Every claim below was re-verified against the code in this worktree; nothing
is taken on reviewer authority.

**Verdict: PLAN NO (v1 must be redesigned, not patched).** Codex's six
blockers are largely valid; two are fatal design errors that I should have
caught in drafting. AGY contributed one real coverage finding (fabric-return
fast path), one arithmetic catch, one refuted claim (fragment cache
pollution), and a wrong severity call on the HA edge.

## 1. Confirmed fatal: the tracker is attacker-writable (Codex B1)

Plan §5.2 site 1 says the track is updated "before the closing decision"
and the cache-path update is unconditional. Both are circular
authentication: a RST with `SEQ=X` advances `seq_hi` to `X` and then passes
its own window; even with validate-before-update ordering, an ACK-only
poison packet (cache-eligible, `flow_cache.rs:352-375`) pre-positions the
anchor for a following RST. Success probability returns to ~50% per attempt
pair. **Required v2 change:** (a) validation always reads the pre-packet
anchor; (b) ordinary anchor updates are themselves plausibility-gated — a
sample is accepted only within `[anchor − BACK, anchor + FWD]` of the
current anchor, so the anchor can only slide, never jump. Residual: an
attacker can walk the anchor with a contiguous fake-data stream at a cost
of ~window/MSS packets — but that capability is strictly stronger than the
demote attack (it is blind data injection, which RFC 5961 data-checks and
the endpoint's own reassembly already govern), so the firewall ceases to
be the weakest link, which is the design goal.

## 2. Confirmed fatal: two-packet reverse-NAT constructor bypass (Codex B2)

Verified end to end. A blind RST on the reverse tuple of a live SNAT/DNAT
session: miss in `lookup_session_across_scopes`, hit in
`lookup_forward_nat_across_scopes`, then
`install_reverse_session_from_forward_match` (`session_glue/mod.rs:1262-1284`
→ `shared_ops.rs:857-865`) calls `install_with_protocol_with_origin` with
the attacker's `tcp_flags`, seeding `closing=true, reset=true`
(`install.rs:399-400`) — all inside `resolve_flow_session_decision`
(`poll_descriptor/mod.rs:412`), long before the #4400 bare-close guard
(`poll_descriptor/mod.rs:1634-1644`), which only covers the
ForwardCandidate/MissingNeighbor new-flow install sites. A second
closing-flag packet on the same tuple hits the born-dying reverse entry and
`propagate_tcp_state_to_companion` (`lookup.rs:204-212` → `mod.rs:1254-1268`)
marks the live forward companion. Two packets, full kill chain (reap →
Close delta → HA standby copy → SNAT pool-port re-seed). Plan §3's
inventory called install.rs:179 "only reachable with SYN+FIN" and missed
that the reverse-synth feeds install.rs:399-400 from the wire. **Required
v2 change:** the close seed at every packet-derived constructor is gated by
the same validator, using the best available cross-baseline — for the
reverse-synth that is the `forward_match` entry's own track (in hand at the
call site). A refused close installs the entry ALIVE (`closing=false`); the
forward companion is never marked from an unvalidated seed. Note the flip
side: a *legit* one-way RST on this path must still seed closing after
validation, else the #3046 2s fast-reap is silently lost for reverse-synth
flows.

## 3. Confirmed: RFC 1982 merge is undefined past 2^31 (Codex B3)

At 25 Gbit/s the cache-side and session-side high-waters diverge past 2^31
in <1s; `wrapping-max` across them is not a total order. **Required v2
change:** one authoritative anchor store, no cross-store merge. See §5
below — the store already exists.

## 4. Confirmed with consequences: `account_packet` is the chokepoint (Codex B4)

Verified: the flow-cache hit path calls `sessions.account_packet` per
packet (`flow_cache_hit.rs:312-317`), and the slow-path forward build calls
it for every ForwardCandidate/FabricRedirect packet
(`poll_descriptor/mod.rs:3494-3503`). Plan v1's premise "bulk cache traffic
cannot update durable session state" is false. This collapses the worst
part of v1: **no `FlowCacheEntry` fields, no cache-hit tracking update, no
union merge** — the anchor lives only on the session entry and is updated
in `account_packet`, which already folds both directions onto the canonical
forward entry (`mod.rs:1177-1211`). Codex findings #12's
`FlowCacheEntry`-layout and cacheline concerns are moot.

## 5. Architectural correction (SMR addition): single two-direction anchor on the forward entry

Because `account_packet` already hops reverse→forward, the canonical
FORWARD entry can hold the full two-direction track:
`{fwd_seq_hi, fwd_ack_hi, rev_seq_hi, rev_ack_hi, fwd_wnd, rev_wnd, validity bits}`
(~20-24 B on `SessionEntry`; ~3 MiB/worker at the 131072 cap — stated
honestly in v2 §2, not waved). A close in direction D validates against
`window(seq_hi(D)) ∪ window(ack_hi(O))` — all four values in ONE store.
The borrow problem v1 never specified (validate inside the matched entry's
`&mut` while needing the companion's track) resolves by moving the close
marking into the existing post-borrow propagation phase
(`propagate_tcp_state_to_companion` already re-probes the companion):
compute `do_close` in-borrow (flag check only), end borrow, resolve the
forward entry, validate against pre-packet anchors, then mark BOTH entries
on accept only. Cost: one extra table probe on closing segments only.

## 6. Confirmed: seg_len formula invalid (Codex B5)

`meta.pkt_len - meta.payload_offset` breaks on native GRE (`gre.rs:680-698`
stamps `pkt_len` as inner L3 length while offsets include the synthetic
Ethernet header) and counts Ethernet padding as sequence space. v2 must
derive payload length from IP-declared lengths with frame clamping —
`tcp_segment_consumed_len` (`frame/tcp.rs:388-452`) is the in-repo
canonical pattern, and the read must use the ACTIVE frame (`packet_frame`,
not `raw_frame`, per `flow_cache_hit.rs:65-103`).

## 7. HA edge: gated, and AGY's "Hole" call is wrong (Codex B8 mostly right)

- The actual gate is Rust-side: `expire.rs:342-345` emits Close deltas only
  for non-peer-synced, non-reverse, non-seed origins; `SharedMaterialize`/
  `SyncImport`/`WorkerLocalImport` are all `is_peer_synced()`
  (`entry.rs:245-250`). A non-owner replica's reap emits nothing.
- AGY's "hole" (promote flips origin → future reaps emit) is gated by
  ownership: `maybe_promote_synced_session` fires only when the resolved
  disposition is `ForwardCandidate` (`promote.rs:86-90`), and
  `enforce_session_ha_resolution` yields `HAInactive`→fabric-redirect on a
  node that does not own the RG. A node that promotes IS the legitimate
  forwarder; its later Close is correct. AGY's conditional ("if
  ForwardCandidate") is exactly the ownership condition, so the hole is
  notional.
- Codex's escalation stands, though: the Go side has no origin/generation
  protection for decoded closes (gen-zero deletes apply unconditionally),
  so the Rust gate is the ONLY barrier. v2 must name it as a load-bearing
  invariant and add the exact regression test
  (`SharedMaterialize + reset + FabricRedirect + stale-ceiling reap` →
  no delta, no owner deletion).

## 8. Refuted: AGY's fragment cache-pollution claim

AGY claimed crafted non-first fragments reach the cache with garbage
ports/flags and could poison the anchor. False: `parse_session_flow_from_bytes`
refuses non-first fragments (`frame/inspect.rs:1455-1470`, #2344) — they
are flowless, produce no SessionFlow, no session lookup, no cache insert,
no `account_packet`. The shim does NOT gate fragments in meta, but the
userspace flow parser does. Fragments cannot drive demotes or pollute
anchors; no shim `meta_flags` bit is needed. (Pre-existing oddity — the
shim stamps garbage ports in meta for fragments — is neutralized at the
same chokepoint.) Codex's fragment sub-point in B6 is the correct framing:
fragments are a tracking *gap* (no seq info), not a pollution vector, and
the gap is harmless because fragments cannot carry a verifiable close.

## 9. Legit-RST model: Codex B9 is right, adopt the union rule

RFC 9293 §3.5.2 and the repo's own `build_reject_rst_frame`
(`frame/tcp.rs:328-385`) agree: a reset for a CLOSED TCB (peer restart,
state loss) carries `SEQ=SEG.ACK` — the *opposite* direction's ack
position, potentially far behind `seq_hi(D)`. Validating only against
`seq_hi(D)` refuses that canonical reset. The union acceptance
`window(seq_hi(D)) ∪ window(ack_hi(O))` covers it and subsumes v1's
asymmetric rule 3. OPENING must acknowledge `SEG.LEN` (TFO/SYN-with-data),
not blindly ISN+1 — again the `tcp_segment_consumed_len` pattern.

## 10. Arithmetic honesty (AGY Q2 + Codex B7)

- `wnd` is u16 (≤65535), so `clamp(wnd, 64KiB, 4MiB)` returns the floor
  forever — the 4 MiB cap was dead on arrival. Effective acceptance
  interval with the dead clamp ≈ 128 KiB; blind-spray success ≈ 1/32768
  per guess, ~33 s expected at 1000 pps. v2 must state the window as a
  designed constant (back 64 KiB + fwd 64 KiB baseline, possibly a
  wnd-multiple with a cap) and quote attack cost in packets AND time at a
  stated pps, and must quantify the legit-refuse case: 64 KiB of
  outstanding data at abort time = 21 µs at 25 Gbit/s, so fast-path aborts
  with large in-flight will soft-refuse — accepted residual, stated.
- §2's "≥32768×" and §5's 4 MiB mechanics contradicted each other; both
  get rewritten.

## 11. `last_seen` on refused closes: flip the plan (Codex B11)

Codex is right: refreshing `last_seen_ns` on a refused close hands the
attacker a pinning primitive (keeps the entry and any SNAT reservation
alive indefinitely with refused packets) and lets post-close refused
packets extend the 2s/30s window forever. Not refreshing does NOT
accelerate natural expiry — my open question 6 had it backwards. v2: a
refused close performs no `last_seen` refresh and no wheel re-queue; the
entry ages on its prior activity. (Data/ACK packets still refresh normally;
only the refused close itself is inert.)

## 12. Junos framing corrections (Codex B10)

- `rst-invalidate-session` IS already in the xpf schema and compiler
  (`pkg/config/schema_security.go:796-800`,
  `compiler_security_flow.go:515-532`) — v1 §3 claimed it is absent; fix.
- The parity claim must be narrowed: on RSTs specifically, xpf == Junos
  default (2 s reap, no RST-specific validation; Junos's stricter
  previous/next-seq RST check is the off-by-default knob). But Junos's
  DEFAULT general sequence check (wscale-aware, drops out-of-window
  segments) has no xpf equivalent at all — that is a broader parity gap,
  explicitly out of scope, and must be named as such rather than implied
  away by "xpf == Junos default".

## 13. What survives review from v1

- The gated-not-dropped posture (never block delivery; soft-fail = linger)
  remains the right first step — AGY Q7 independently argues A-first for
  the same reasons; Codex's "challenge/proof mechanism is more credible"
  is noted but is v2-follow-up scope, not a reason to start with packet
  drops on a stale-baseline-sensitive middlebox.
- Fail-open on missing baseline (HA-imported entries) stands.
- The three-sites-plus-constructors inventory (now corrected to include the
  reverse-synth and the tunnel UpsertLocal trusted-local class) is the
  right shape once install-time seeding is gated centrally.

## Required for v2 (checklist)

1. Single two-direction anchor on the forward SessionEntry; updates only in
   `account_packet` (+install seeding); plausibility-gated slides;
   validation on pre-packet anchor; marking moved to the post-borrow
   propagation phase.
2. Union acceptance `window(seq_hi(D)) ∪ window(ack_hi(O))`; OPENING via
   SEG.LEN-aware ack check; fail-open only on missing baseline.
3. Constructor gating at install for ALL packet-derived closing seeds
   (reverse-synth validates against the in-hand forward track; refused →
   born alive; #4400 path unchanged; tunnel UpsertLocal documented
   trusted-local; wire upserts no-packet).
4. IP-declared-length seg_len, active-frame reads, GRE/VLAN/ext correctness
   via the existing `frame/tcp.rs` pattern; fragments documented flowless.
5. Refused close = no mark, no `last_seen` refresh, no wheel re-queue, plus
   the `tcp_close_seq_rejected` counter.
6. Honest arithmetic §2/§7 (128 KiB window, spray cost in packets+time,
   soft-refuse residual at line rate).
7. Junos framing fix (schema correction + narrowed parity claim).
8. HA invariant named + exact regression test; Go-side origin-blindness
   documented as the reason the Rust gate is load-bearing.
9. Test plan adds: ACK-then-RST poisoning, reverse-NAT two-packet bypass
   (RED on v1 semantics, GREEN on v2), restart-RST (SEQ=SEG.ACK) acceptance,
   GRE seg_len, exotic-ext residual, refused-close non-refresh,
   closing-window non-extension, HA no-Close invariant.
