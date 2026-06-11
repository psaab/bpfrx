# #1865 — Operator-visible WireGuard telemetry (plan)

Revision: v2 (round-1 reviews folded)
Issue: #1865 (#1703 S6 adjacency; refs #1736 #1434 #1873)
Branch: research/1865-wg-telemetry
Status: awaiting round-2 review (Codex + AGY + Claude SMR)

Round-1 verdicts: Codex PLAN-NEEDS-MAJOR-REVISION (codex-plan-r1.md),
AGY PLAN-NEEDS-MAJOR-REVISION (agy-plan-r1.md), Claude SMR
PLAN-NEEDS-MINOR-REVISION (claude-smr-plan-r1.md). v2 deltas:

- **Keepalive counter added** (Codex F1 + SMR F1, independent
  convergence): authenticated zero-length transport records currently
  exit `try_decap` through `MalformedInner` (engine.rs:887→933→1036);
  a peer with `persistent_keepalive` would emit steady false-alarm
  "malformed" drops. v2 adds `decap_keepalives`, classified after the
  replay gate and before the inner parse, all external behavior
  unchanged (§3.3 #17).
- **created-vs-sent honesty** (Codex F2 + SMR F2): handshake build
  counters renamed `*_created`; BOTH send sites instrumented,
  including the discarded `let _ = wg_send_to(...)` response send at
  wg_control.rs:466; `hs_initiation_build_failures` added for the
  `if let Ok` -discarded `create_initiation` errors at
  wg_control.rs:427 (Codex F3).
- **Absolute handshake timestamp** (AGY F2+F3 + Codex F5 + SMR F3):
  `last_handshake_age_secs` replaced by `last_handshake_unix_secs`
  (u64; 0 = never — unambiguous, no Option/pointer needed),
  monotonic→wall converted at snapshot time via the existing
  `monotonic_timestamp_to_datetime` helper; Prometheus exposes
  `..._last_handshake_time_seconds`, PromQL computes age.
- **Hex pubkey** (AGY F4 + Codex F6 + SMR F4): `peer_pubkey_hex`,
  matching `wg_peer_pubkey_hex` house convention; no base64 dep.
- **Name fallback** (Codex F4 + SMR F6): status rows fall back to the
  snapshot row-label convention, last resort `wg-endpoint-<id>`;
  never drop a row.
- **Explicit exclusions** (Codex F3): zero-length UDP datagrams are
  consumed by the `Ok(_) => break` arm at wg_control.rs:197 before
  any type dispatch — documented as excluded (no counter), so
  `rx_unknown_type` fires only on type bytes ∉ {1,2,3,4}.
- **Tests tightened** (Codex F5 + SMR F5): populated round-trip
  fixtures BOTH sides; parity-pin overpromise replaced by a Go
  emitter label-set test; hot-path claim re-phrased (Codex F7);
  non-transactional multi-counter snapshots documented.
- **AGY finding 1 REFUTED** (stale-TUN via missing `logical_ifindex`
  in `wg_identity_unchanged`): TUN-attachment changes are handled by
  the #1872 `attachment_changed` stale-prune in
  `spawn_wg_control_threads` (coordinator/mod.rs:566-595 — `attach_ok`
  checks `ep.logical_ifindex == entry.spawned_ifindex` AND the
  resolved name), which stops + respawns the thread on the new TUN
  while deliberately preserving the engine and its sessions (#1866
  D5). Adding `logical_ifindex` to `wg_identity_unchanged` would
  REBUILD the engine and kill live transport sessions on a mere
  rename — a regression against #1866 D5. Codex's independent
  lifecycle audit confirms ("attachment changes are pruned at
  coordinator/mod.rs:570"). Not a telemetry defect; no plan change.

Reviewers: PLAN-KILL is an acceptable outcome. If you believe the
telemetry surface is wrong (wrong keying, wrong cardinality, wrong
layer), kill the plan rather than patching it.

## 1. Problem

The S2a WireGuard datapath has ZERO operator-visible telemetry. Every
drop diagnostic is `debug_log!`-gated (compiled out in release):

- `coordinator/wg_control.rs:470,478,485,505,511,539,563` — initiation/
  response/cookie/transport/unknown-type/oversize-inner/encap drops are
  all `debug_log!` only.
- `frame/wg.rs:85-91` — the transit-egress MTU guard literally carries
  the comment "wg_mtu_drops would be incremented on a real counter
  store here; ... Telemetry consolidation is on the engine in a
  follow-up." This plan is that follow-up.
- The engine (`wg/engine.rs`) returns rich error enums (`EncapError` 5
  variants, `DecapError` 10 variants, `HandshakeError` 9 variants,
  `FramingError` 5 variants) and every single one is dropped on the
  floor at the call sites in release builds.

The only release-visible signals are `RecentExceptions` (bind/TUN/send
errno strings) and traffic-level observation.

Why this matters (the #1736 receipts): the P1/P6 no-handshake debugging
in the S2b interop campaign burned hours precisely because of this gap.
The v4-initiation `sendto = EINVAL` bug was silent — every initiation
toward a configured v4 endpoint failed and NOTHING counted it; it took
strace to find. The v4-mapped MTU-guard blackhole dropped every
1409..=1425-byte inner packet silently — pings passed, full-MSS TCP
moved zero bytes; it took tcpdump on both ends plus the KERNEL PEER's
`wg show` as oracle. An operator running a real tunnel does not have a
cooperating kernel peer to interrogate. Both bugs would have been
one-glance diagnoses with `encap_mtu_drops` / `handshake_send_errors`
counters.

Adjacent context:
- #1872 added teardown/respawn transition LOGS but no counters.
- #1873: `tunnel_endpoint_id` is POSITIONAL — add/remove of one tunnel
  renumbers the others. Telemetry keying must be robust against this
  (see §4 keying decision and §7 R2).
- #1434 (S6) owns multi-tunnel + the full CLI surface
  (`show security wireguard public-key`, key generation).

## 2. Current code inventory (verified on origin/master 6a11c52f5)

Datapath shape (S2a): ALL WG RX (handshake + transport decap) happens
on the per-tunnel control thread (`wg_control_loop`) via a kernel UDP
socket — slow path. Encap has two sites: the control thread's TUN-read
loop (primary; slow path) and `frame/wg.rs::wg_encap_frame` (transit
AF_XDP egress; worker context but rarely hit, and it already does two
heap allocations per packet). **No new code runs on the non-WG forward
path under any path option below.**

Error/drop sites that need counting (exhaustive walk):

| Site | Today | Reasons available |
|---|---|---|
| `engine.try_decap` | Err → debug_log at wg_control.rs:505 | `DecapError`: MalformedHeader, UnknownSession, ShortRecord, CounterRejectAfterMessages, CryptoFailed, ReplayDuplicate, ReplayOutOfWindow, MalformedInner, AllowedIpsViolation, BufferTooSmall |
| `engine.try_encap` | Err → debug_log (control) / `None` (frame/wg.rs) | `EncapError`: UnknownPeer, NoSession, BufferTooSmall, CryptoFailed, RekeyRequired. NOTE: the unconfirmed-responder egress gate (engine.rs:720) is folded into `NoSession` — AGY r2 on #1736 requires it be DISTINGUISHABLE |
| `consume_initiation_create_response` | Err → debug_log :470 | `HandshakeError` incl. `Framing(Mac1Mismatch)`, UnknownInitiator, Crypto, IndexExhausted |
| `consume_response` | Err → debug_log :478 | `HandshakeError`: NoPendingHandshake, ReceiverIndexMismatch, Crypto, Framing(...) |
| `create_initiation` Ok / send | send err → exception only | initiations-sent count missing |
| cookie (type 3) | debug_log :485 (S7) | fixed reason |
| unknown type / runt datagram | debug_log :511 | fixed reason |
| MTU guard (control egress) | debug_log :539 | fixed reason |
| MTU guard (transit egress, frame/wg.rs:85) | silent `None` | fixed reason |
| socket send errors (handshake + transport) | exception ring only | count + keep exception |
| TUN write errors | exception ring only | count + keep exception |
| responder-no-endpoint TUN drain (wg_control.rs:247) | silent | fixed reason |
| successful decap/encap | nothing | packets + bytes, both directions |
| handshake completions | nothing | by role (initiator = `consume_response` Ok; responder = `consume_initiation_create_response` Ok) |
| session confirmed (`mark_confirmed`) | nothing | gauge + transition stamp |

Counters the ISSUE asks for that have NO increment site today (must
NOT be invented): TAI64N-replay rejects (S1 explicitly does not enforce
per-peer TAI64N anti-replay yet — handshake_session.rs:452-457) and
under-load rate-limit rejects (cookie/MAC2 is S7). The plan reserves
the reason names but ships no dead counters; they ride with responder
hardening.

Status plumbing precedent (#1769/#1771/#1782 neighbor-resolver family —
the wire-additive template this plan copies mechanically):
Rust atomics → `coordinator/status.rs` accessor →
`server/helpers.rs` (fills `ProcessStatus`) →
`protocol/control.rs` serde `default` fields →
fixture `userspace-dp/tests/fixtures/protocol_wire_v1.json`
(regen via `XPF_PROTOCOL_WIRE_REGEN=1`, key-absent pins in
`protocol/tests.rs`) → `pkg/dataplane/userspace/protocol.go` →
`pkg/api/metrics.go` descriptors + `metrics_userspace.go` emitters →
`metrics_descriptor_coverage_test.go` pedantic-registry canary.

## 3. Design decisions

### 3.1 Where counters live: on the `WgEngine` (per-engine struct of relaxed atomics)

A `WgCounters` struct (all `AtomicU64`, `Ordering::Relaxed`) owned by
`WgEngine`, created in `WgEngine::new`. Rationale:

- One engine == one tunnel (S2a) == the natural aggregation unit. The
  engine `Arc` is shared by the control thread, the transit-egress
  worker path, and the coordinator — every increment site can reach it
  without new plumbing.
- Engine-internal increments at the `try_encap`/`try_decap`/
  `consume_*` return boundaries cover BOTH encap sites and BOTH
  consume sites automatically — no per-call-site drift. The
  wg_control.rs:521 comment already promises exactly this
  ("telemetry is consolidated on the engine, not per call site").
- Counters survive the control thread's #1872 teardown/respawn
  tombstone cycle (the engine Arc outlives the thread).
- `populate_wg_engines` reuses the engine Arc when
  `wg_identity_unchanged` — counters survive unrelated commits for
  free. An identity-CHANGING commit rebuilds the engine and resets
  counters to zero; Prometheus `rate()` tolerates monotonic resets and
  the reset itself is a faithful signal that the crypto identity (and
  therefore all sessions) was rebuilt. We deliberately do NOT carry
  counters across a rebuild: under #1873's positional renumbering,
  `prev_state.wg_engines.get(&id)` at a SHIFTED id is a *different
  tunnel*, and inheriting its counters would misattribute (§7 R2).
- Call-site-only counters (the rows in §2 that fire before/outside the
  engine: MTU guards, send/TUN errors, cookie/unknown-type, responder
  drain) increment through the same struct via a public accessor
  (`engine.counters()`).

Hot-path cost, phrased precisely (Codex r1 F7): **no new allocation
and no non-WG branch cost.** Non-WG traffic is untouched (the WG
branch is gated at `tunnel_endpoint_id != 0`, frame/mod.rs:264). For
WG traffic the additions are relaxed `fetch_add`s on paths that are
either control-thread slow path or the transit path in frame/wg.rs —
which ALREADY heap-allocates twice per packet (frame/wg.rs:97,111),
a pre-existing style-guide deviation this plan neither fixes nor
worsens (out of scope; noted so the claim is honest rather than
"hot-path compliant").

### 3.2 Keying / cardinality: per-TUNNEL rows keyed by tunnel NAME

`ProcessStatus` gains `wg_tunnels: Vec<WgTunnelStatus>`
(`skip_serializing_if = "Vec::is_empty"` — non-WG deployments are
wire-byte-identical, same invariant discipline as #1621/#1635).

Each row carries identification + state + flat counters:

- `tunnel` (string, the wgN interface name from `ifindex_to_name`) —
  the PRIMARY key. Stable across commits; robust against #1873 id
  renumbering. This is also the only Prometheus label. Missing-name
  fallback (Codex r1 F4 / SMR F6): reuse the snapshot row-label
  convention (`linux_name`, else `interface`, mirroring
  `wg_tombstone_respawn_coherent` at coordinator/mod.rs:827-831),
  last resort `wg-endpoint-<id>` — a row is NEVER dropped for a
  missing name (broken bring-up is exactly when telemetry matters).
- `tunnel_endpoint_id` (u16, informational cross-ref; documented as
  unstable per #1873 — never used as a join key by consumers).
- `listen_port` (u16), `peer_pubkey_hex` (hex — matches the
  `wg_peer_pubkey_hex` house convention on the config/snapshot wire
  (protocol/snapshot.rs:361, protocol.go:310) and the value the
  operator configured into xpf; no base64 dependency. The divergence
  from `wg show`'s base64 rendering is noted in CLI help/docs).
- `session_confirmed` (bool — `peer_has_confirmed_session`).
- `last_handshake_unix_secs` (u64 epoch seconds; **0 = never** — see
  §3.3 State. Replaces v1's age-secs field: an age gauge churns every
  scrape and a Go `uint64,omitempty` mirror would conflate
  "0 seconds ago" with "never" (AGY r1 F2+F3, Codex r1 F5, SMR F3)).
- ~29 flat `u64` counter fields (§3.3). Flat named fields with serde
  `default`, matching house wire style (no maps/enums on the wire).

Per-PEER rows are NOT in scope: S2a is single-peer-per-tunnel, so
per-tunnel == per-peer today; the multi-peer split is #1434 S6 work and
the wire shape stays additive for it (S6 adds `peers: Vec<...>` inside
the row when it lands).

Cardinality: bounded by configured WG tunnels (today: 1; S6: small
config-bounded N). No per-flow, per-session, or per-source state.

### 3.3 Counter inventory (exact, every one has a live increment site)

Handshake (per tunnel):
1. `hs_initiations_created` — `create_initiation` Ok
   (engine-internal). NOT named "sent": the UDP send happens later in
   `drive_initiation` (wg_control.rs:427-435) and can fail — the
   #1736 EINVAL fingerprint becomes `created↑ + send_errors↑ +
   completions flat`.
2. `hs_initiation_build_failures` — `create_initiation` Err, all
   variants folded (today discarded by the `if let Ok` at
   wg_control.rs:427). Engine-internal.
3. `hs_responses_created` — `consume_initiation_create_response` Ok
   (responder accepted msg1, built msg2, installed the unconfirmed
   session — handshake_session.rs:517). This single increment site is
   ALSO the responder-completion event; the Prometheus completions
   metric emits it under `role="responder"` (no second counter, no
   double count).
4. `hs_completions_initiator` — `consume_response` Ok.
5. `hs_rx_drops_mac1_mismatch` — `Framing(Mac1Mismatch)` from either
   consume path.
6. `hs_rx_drops_malformed` — `Framing(WrongLength|BadType|BadNoiseLen
   |OutputTooSmall)`.
7. `hs_rx_drops_crypto` — `Crypto | Internal`.
8. `hs_rx_drops_unknown_peer` — `UnknownInitiator | UnknownPeer`.
9. `hs_rx_drops_stale_response` — `NoPendingHandshake |
   ReceiverIndexMismatch`.
10. `hs_rx_drops_index_exhausted` — `IndexExhausted` (expected ~never).
11. `hs_rx_cookie_unsupported` — type-3 datagrams (S7 placeholder).
12. `rx_unknown_type` — type byte ∉ {1,2,3,4}. Explicit exclusion:
    zero-length UDP datagrams never reach dispatch (`Ok(_) => break`
    at wg_control.rs:197 consumes them before any type read), so the
    `datagram.first() == None` arm is unreachable for counting
    purposes and runts are NOT counted — documented, not invented.
13. `hs_send_errors` — initiation AND response `wg_send_to` Err at
    BOTH call sites (the response send at wg_control.rs:466 is
    currently `let _ =` -discarded and must be routed through this
    counter; exception-ring entries retained).
14. `hs_requests_armed` — `request_handshake` returned true (the
    NoSession worker→control edge; ties an encap drop burst to the
    re-init it triggered).

Transport decap (engine-internal in `try_decap`):
15. `decap_packets`, 16. `decap_bytes` (inner-IP bytes, `outcome.len`).
17. `decap_keepalives` — authenticated ZERO-length transport records
    (WG persistent keepalives: `pad_to_16(0) == 0`, snow yields
    `n == 0`). Classified after the replay gate and BEFORE the inner
    parse; all external behavior unchanged (still no TUN write, still
    `Err` to the caller, still `authenticated=false` at the dispatch
    site). Without this counter a keepalive peer emits steady
    `decap_drops_malformed_inner` false alarms — the exact
    trust-destroying noise this plan exists to kill.
18. `decap_drops_malformed_header` (MalformedHeader | ShortRecord —
    both "structurally bogus record").
19. `decap_drops_unknown_session` (UnknownSession).
20. `decap_drops_counter_ceiling` (CounterRejectAfterMessages).
21. `decap_drops_crypto` (CryptoFailed).
22. `decap_drops_replay` (ReplayDuplicate | ReplayOutOfWindow).
23. `decap_drops_allowed_ips` (AllowedIpsViolation).
24. `decap_drops_malformed_inner` (MalformedInner, n > 0 only — the
    keepalive class is peeled off in #17).
25. `decap_drops_buffer` (BufferTooSmall — expected ~never; a nonzero
    value means a sizing bug).

Transport encap (engine-internal in `try_encap`, plus call-site MTU):
26. `encap_packets`, 27. `encap_bytes` (inner-IP bytes — symmetric
    with decap so the pair is comparable).
28. `encap_drops_no_session` (NoSession from the no-current-session
    arm ONLY).
29. `encap_drops_unconfirmed` (NoSession from the `is_confirmed()`
    gate arm — the AGY-r2-mandated distinction. Implementation:
    increment a different counter inside `try_encap` before returning
    the same `EncapError::NoSession`; the error enum and every caller
    contract stay untouched).
30. `encap_drops_rekey_required` (RekeyRequired — nonce ceiling).
31. `encap_drops_other` (UnknownPeer | CryptoFailed | BufferTooSmall —
    all "should never happen" classes, folded; split later if ever
    nonzero).
32. `encap_mtu_drops` — call-site, BOTH guards (wg_control.rs
    `encap_and_send` + frame/wg.rs `wg_encap_frame`). The #1736
    blackhole counter.
33. `transport_send_errors` — encap'd datagram `wg_send_to` Err.
34. `tun_write_errors` — decap'd inner `tun.write_all` Err.
35. `tun_rx_drops_no_endpoint` — responder-without-endpoint TUN drain.

State (not counters): `session_confirmed` bool;
`last_handshake_complete_ns` AtomicU64 stamped (monotonic
`monotonic_nanos` domain) at the two completion sites (#3, #4),
converted at status-snapshot time to `last_handshake_unix_secs` (u64
wall-clock epoch seconds; **0 = never** — unambiguous without
Option/pointer plumbing, since epoch 0 is not a reachable handshake
time) via the existing `monotonic_timestamp_to_datetime` helper (the
worker-heartbeat conversion, coordinator/status.rs:414-429). An NTP
step skews the DISPLAYED wall time but fences nothing (#1792 lesson:
the stored stamp stays monotonic).

Snapshot coherence note (Codex r1): the status poll reads each atomic
independently while the control thread increments — multi-counter
reads are NOT transactional (e.g. `decap_packets` may be one ahead of
`decap_bytes` within a snapshot). Documented on the accessor; fine
for observability counters, same posture as every existing counter
family.

Reserved (NOT shipped — no increment site): tai64n-replay,
rate-limited. Documented in the module doc as riding with responder
hardening.

### 3.4 Prometheus surface (Go side)

New descriptors in `pkg/api/metrics.go`, emitted from a new
`emitWireguardTelemetry` in `metrics_userspace.go` (wired into
`collectUserspaceStatus`), label `{tunnel}` (+ a small fixed enum
label where it collapses descriptor count):

- `xpf_userspace_wg_handshakes_completed_total{tunnel,role}` —
  role="initiator" ← #4 `hs_completions_initiator`;
  role="responder" ← #3 `hs_responses_created` (single increment
  site; no double count).
- `xpf_userspace_wg_handshake_initiations_created_total{tunnel}`
- `xpf_userspace_wg_handshake_initiation_build_failures_total{tunnel}`
- `xpf_userspace_wg_handshake_rx_drops_total{tunnel,reason}` (reasons:
  mac1_mismatch, malformed, crypto, unknown_peer, stale_response,
  index_exhausted, cookie_unsupported, unknown_type)
- `xpf_userspace_wg_handshake_requests_armed_total{tunnel}`
- `xpf_userspace_wg_transport_packets_total{tunnel,direction}` (encap/decap)
- `xpf_userspace_wg_transport_bytes_total{tunnel,direction}`
- `xpf_userspace_wg_keepalives_received_total{tunnel}`
- `xpf_userspace_wg_transport_drops_total{tunnel,direction,reason}`
  (decap: malformed_header, unknown_session, counter_ceiling, crypto,
  replay, allowed_ips, malformed_inner, buffer; encap: no_session,
  unconfirmed, rekey_required, mtu, other)
- `xpf_userspace_wg_send_errors_total{tunnel,kind}` (handshake,
  transport, tun_write, tun_rx_no_endpoint)
- `xpf_userspace_wg_session_confirmed{tunnel}` gauge (0/1)
- `xpf_userspace_wg_last_handshake_time_seconds{tunnel}` gauge —
  absolute epoch seconds (AGY r1 F3: an age gauge churns every scrape
  and compresses poorly; PromQL computes age as
  `time() - xpf_userspace_wg_last_handshake_time_seconds`). Emitted
  only when nonzero (never-handshaked emits no series).

All series emitted per configured tunnel (zeros emitted, not omitted —
"0 drops" is a real signal, per the #1771 §2.6 convention), EXCEPT the
never-handshaked age gauge. `descriptorCoverageDP`'s fake
`ProcessStatus` gains a populated `WgTunnels` row so the #1726
pedantic-registry canary actually exercises the family (the lesson
from the zone/policy families at metrics_descriptor_coverage_test.go:48).

## 4. Paths

### Path A — counters + status DTO + Prometheus (no CLI)

Everything in §3. Exposure is Prometheus + the raw status JSON
(`xpfd` debug surfaces). `show security wireguard` deferred to #1434
S6 wholesale.

- (+) Smallest blast radius; no cmdtree/grpc/cli changes.
- (−) The #1736 pain story is an operator at a CLI. Junos operators
  type `show security ...` first; Prometheus second. Leaves the
  primary UX gap open and #1434 S6 is not scheduled.

### Path B — Path A + minimal `show security wireguard` (RECOMMENDED)

Adds the operational command on top of A, following the
`show system buffers` pattern exactly (cmdtree node + local CLI
handler + gRPC server handler, both reading the SAME
`dpuserspace.ProcessStatus.WgTunnels` — no new RPC, no proto change):

- `pkg/cmdtree/tree.go`: `show security wireguard` node (Desc:
  "Show WireGuard tunnel status"), child `detail`.
- `pkg/cli/cli_show_security_wireguard.go` (new, per the
  module/aspect-file layout rule): summary renders per tunnel —
  interface, listen port, peer key, configured endpoint, session
  state, latest handshake, transfer (encap/decap pkts+bytes), total
  drops; `detail` adds the full per-reason drop table (the
  one-glance view for the #1736 class of failures).
- `pkg/grpcapi/server_show_security_wireguard.go`: same rendering for
  the remote CLI (mirrors `server_show_system_buffers` flow).

Scope guard: this is a STATUS command only. Key generation,
public-key display sourced from config, and multi-tunnel selection
arguments remain #1434.

- (+) Closes the actual operator gap the issue narrates; mechanical
  (~3 files + tests) on a proven pattern; both CLIs covered.
- (−) Touches the operational tree → larger review surface; partial
  overlap with #1434's eventual command (mitigated: #1434 extends
  this node rather than conflicting — `public-key`/`generate` are
  sibling leaves).

### Path C — Path A/B + bounded drop-EVENT ring

A per-engine ring of the last N (64) drop events with timestamp /
reason / peer endpoint / counter value, surfaced like
`recent_exceptions`.

- (+) Answers "WHICH endpoint sent the garbage" without tcpdump.
- (−) Wire + status-size growth; allocation and formatting on drop
  paths (a hostile flood formats strings); `RecentExceptions` already
  covers the errno class; counters cover the rate class. Poor
  cost/benefit now. **Offered for explicit kill** — recommend
  deferring until a live incident shows counters alone insufficient.

Recommendation: **Path B**, commits structured A-first (Rust counters →
wire → Go DTO → Prometheus → CLI) so the CLI commit is separable if
review stalls it.

## 5. Wire-additive discipline (mandatory checklist)

1. `protocol/control.rs`: `WgTunnelStatus` struct + `wg_tunnels` field,
   serde `default` + `skip_serializing_if = "Vec::is_empty"`. The
   explicit `ProcessStatus` initializer at server/lifecycle.rs:73 uses
   struct-literal + defaults — verify the new field is covered (Codex
   r1 F5).
2. Key-absent pins (Rust `protocol/tests.rs`): pre-#1865 payload with
   the key absent decodes to empty vec; a default `ProcessStatus`
   serializes byte-identical to pre-#1865 (the §3.2 invariant).
3. POPULATED round-trip pins BOTH sides (Codex r1 F5: the fixture
   canary has a residual gap for optional populated fields,
   protocol/tests.rs:1060): a `WgTunnelStatus` with every field
   nonzero round-trips Rust→JSON→Rust and unmarshals identically in
   Go.
4. Fixture: `XPF_PROTOCOL_WIRE_REGEN=1 cargo test --bin
   xpf-userspace-dp` regen + manual diff review of
   `tests/fixtures/protocol_wire_v1.json`.
5. `pkg/dataplane/userspace/protocol.go`: mirrored struct, json tags
   identical to the serde renames (grep BOTH sides per
   feedback_wire_protocol_both_sides).
6. Go-side key-absent pin: old JSON without `wg_tunnels` unmarshals to
   nil slice; emitter skips cleanly.
7. `pkg/api`: descriptors + Describe() + emitter + canary fixture row.

## 6. Tests

Rust (wg module, plain debug + release):
- Full IK handshake between two engines → assert
  initiations_created=1, responses_created=1, completions both roles,
  last_handshake stamp set, session_confirmed transitions after first
  decap.
- Authenticated zero-length transport record (keepalive) →
  `decap_keepalives` increments, `decap_drops_malformed_inner` does
  NOT, replay window advanced, behavior otherwise unchanged (still
  Err to the caller).
- `create_initiation` toward an unknown peer →
  `hs_initiation_build_failures`.
- MAC1-corrupted initiation → `hs_rx_drops_mac1_mismatch` (the
  wrong-key-peer case used in live validation).
- Replayed counter → `decap_drops_replay`; AllowedIPs-violating inner
  → `decap_drops_allowed_ips`; truncated record →
  `decap_drops_malformed_header`.
- Unconfirmed responder egress → `encap_drops_unconfirmed` (NOT
  `encap_drops_no_session`) and error still `NoSession` (caller
  contract pinned).
- Counter survival across `reconcile_peers` with unchanged identity
  (engine reuse path).
- wg_control loop-level: MTU-oversize inner → `encap_mtu_drops`
  (pure-function guard already unit-tested; counter assert rides the
  existing tests).
- Wire round-trip + key-absent pins (§5).

Go:
- Emitter unit test: populated `WgTunnels` row → assert the FULL
  expected series set with exact label values (the reason label list
  is compile-visible in the emitter; the wire itself is flat named
  u64 fields, so cross-language drift is structurally impossible
  without an explicit two-sided field addition — v1's "parity-pin
  test" promise was unguardable theater and is dropped, SMR F5).
- Descriptor-coverage canary (extended fixture row).
- protocol.go unmarshal pin (absent + populated).

Live (loss cluster, Phase 2): deploy → bring up interop peer via
`test/incus/wg-interop.sh` provision/configure → assert (a) handshake
counters move on bring-up, (b) transport pkts/bytes move under iperf3
through the tunnel, (c) wrong-key peer → mac1_mismatch increments,
(d) `show security wireguard` renders (Path B), (e) Prometheus scrape
carries the family. Re-apply CoS after deploy.

## 7. Risks

- **R1 — wire bloat / status-poll cost.** ~30 u64 + 3 strings per
  configured tunnel, only when WG is configured; empty-vec skip keeps
  non-WG deployments byte-identical. Status poll is 1/s; negligible.
- **R2 — #1873 id instability.** Mitigated by name-keying (§3.2) and
  by NOT inheriting counters across engine rebuilds. Residual: an
  id-shift commit resets the shifted tunnel's counters (alongside its
  sessions, which #1873 already resets) — visible as a counter reset,
  which is itself diagnostic. Fixing the renumbering is #1873, not
  this issue.
- **R3 — reason-enum drift between Rust and Go.** Mitigated by the
  parity-pin test (§6) and by folding only stable classes.
- **R4 — hot-path regression.** No non-WG path is touched; transit
  encap adds 2 relaxed fetch_adds to a path with 2 heap allocations.
  Gate: `cargo build --release` + the existing perf posture; no
  flamegraph gate needed at this cost class (consistent with how the
  #1769 resolver counters shipped).
- **R5 — counter semantics under respawn.** Control-thread respawn
  (#1872 tombstone) keeps the engine Arc → counters continuous. A
  spawn-FAILED window drops TUN traffic invisibly to these counters
  (nothing is reading the TUN) — that window is already covered by
  RecentExceptions + #1872 transition logs; documented, not counted.

## 8. Docs

- `userspace-dp/src/afxdp/wg/mod.rs` module doc: telemetry section
  (what is counted where, reset semantics, reserved reasons).
- `docs/wireguard-interop.md` + `docs/wg-interop-runbook.md`: replace
  the "peer `wg show` is the primary oracle" guidance with the local
  counters as primary oracle (peer-side stays as cross-check).
- `docs/config-schema.md`: NOT touched (no config leaf).
- cmdtree/CLI docs (Path B): command reference entry.

## 9. Out of scope

- TAI64N anti-replay + under-load rate limiting (responder hardening;
  reasons reserved).
- Cookie/MAC2 (S7), rekey/retry timers (S5), multi-tunnel + key
  management CLI (#1434), tunnel-id stabilization (#1873).
- Drop-event ring (Path C, unless reviewers overrule).
- Per-peer rows (S6 multi-peer).
- Latent gap noted during the keepalive analysis (SMR r1 F1), NOT
  fixed here: an authenticated keepalive currently exits `try_decap`
  via `Err`, so `dispatch_inbound` returns `authenticated=false` and
  keepalives neither refresh endpoint-learning nor count as
  authentication for roaming purposes (wg_control.rs:181-195). A
  keepalive-only roaming peer would not be re-learned until its next
  data/handshake packet. File as a follow-up issue at /engineer time;
  changing it is behavior, not telemetry.
- The pre-existing per-packet allocations on the transit encap path
  (frame/wg.rs:97,111) — noted in §3.1, untouched.

## 10. Deliverable

Phase 2 (`/engineer`) PR closing #1865: Rust `WgCounters` + increment
sites + status plumbing + wire-additive `wg_tunnels` + Go DTO +
Prometheus family (+ Path B CLI command), tests per §6, live evidence
per §6, docs per §8. Logical commits in dependency order (counters →
wire → Go → Prometheus → CLI).

## 11. Decision asked of reviewers

Round-1 resolutions (all three reviewers answered; unanimous):

1. Path A vs B vs C → **Path B**, Path C killed (Codex: "too broad";
   AGY: kill, allocation/formatting on drop paths violates
   latency-first; SMR: defer/kill).
2. Keying → per-tunnel rows keyed by name, id informational,
   unanimous (now with the F4/F6 missing-name fallback).
3. Inventory → unanimous yes on `encap_drops_other` folding and the
   counter-only unconfirmed split; Codex+SMR additions (keepalives,
   build-failures, response-send instrumentation, runt exclusion)
   folded into §3.3.
4. No-carry-across-rebuild → unanimous yes.
5. Bytes → inner-IP both directions, unanimous; v2 documents that
   these are logical tunnel payload bytes and will NOT match a kernel
   peer's `wg show` transfer numbers (which include WG overhead).

Round-2 question: any objection to the v2-specific choices —
`last_handshake_unix_secs` with 0-as-never (vs Option/pointer), and
the keepalive counter being classified inside `try_decap` with
unchanged external behavior?
