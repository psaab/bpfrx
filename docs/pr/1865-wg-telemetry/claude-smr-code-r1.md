# PR #1876 (#1865 WG telemetry) — Claude SMR hostile code review, round 1

Reviewer: Claude SMR. Contract: hostile, full-function-body reads
(feedback_verify_whole_function_body), worked trace mandatory.

## Verdict: MERGE-READY (one cosmetic fix applied during review)

## Worked trace A — one full handshake + first round-trip (xpf initiator)

1. `wg_control_loop` bring-up → `drive_initiation` →
   `engine.create_initiation` (counting wrapper,
   handshake_session.rs tail impl) → `create_initiation_inner` Ok ⇒
   `hs_initiations_created` 0→1; `hs_initiation_build_failures`
   stays 0; `last_handshake_complete_ns` stays 0 (creation ≠
   completion — pinned by the framed-handshake test).
2. `wg_send_to` Ok ⇒ no counter. (EINVAL variant: `hs_send_errors`
   0→1 + exception ring — the #1736 fingerprint
   `created↑ + send_errors↑ + completions flat`.)
3. Peer msg2 arrives → `dispatch_inbound` type 2 →
   `consume_response` wrapper → inner Ok ⇒
   `hs_completions_initiator` 0→1 AND
   `record_handshake_complete(monotonic_now_ns())` ⇒ stamp > 0
   (max(1) guard); `authenticated=true` → endpoint learning
   unchanged from pre-PR behavior.
4. TUN read → `encap_and_send`: MTU guard passes (no counter) →
   `try_encap`: peer found → session present (initiator role,
   pre-confirmed) → confirmation gate passes → bounds pass → counter
   consumed → `write_message` Ok ⇒ `encap_packets` 0→1,
   `encap_bytes` += inner len (un-padded — pinned). `wg_send_to` Ok.
5. Peer transport record → `dispatch_inbound` type 4 → `try_decap`:
   `parse_data_header` Ok → ceiling pass → demux hit → tag-length
   pass → precheck pass → AEAD Ok (n>0) → `mark_confirmed` (no-op
   for initiator role) → `check_and_update` Accept → n>0 (keepalive
   peel not taken) → inner parse + AllowedIPs Ok ⇒ `decap_packets`
   0→1, `decap_bytes` += inner_len → TUN write Ok (no counter).
6. Status poll → `wg_tunnel_statuses`: row keyed by name; stamp ≠ 0 ⇒
   monotonic→wall conversion (stamp-0 guard NOT taken);
   `session_confirmed=true`; Prometheus emits
   `handshakes_completed{role=initiator}=1`,
   `transport_packets{encap}=1,{decap}=1`, all drop reasons = 0
   (emitted — 0 is a real signal), `last_handshake_time_seconds`
   present.

## Worked trace B — one dropped packet (replayed transport record)

Peer replays the identical datagram → `try_decap`: header/ceiling/
demux/tag/precheck pass (precheck window may or may not catch — both
arms counted identically) → AEAD Ok (stateless transport re-decrypts)
→ `mark_confirmed` no-op → `check_and_update` ⇒ `Repeat` → `out[..n]`
wiped → `Err(count_decap_err(ReplayDuplicate))` ⇒
`decap_drops_replay` 0→1, exactly one counter, no packet/byte
movement, `authenticated=false` (no endpoint learn). Prometheus:
`transport_drops{direction=decap,reason=replay}=1`.

Replayed KEEPALIVE corner: the replay gate fires BEFORE the n==0
peel, so a replayed keepalive counts `replay`, not a second
`keepalive` — pinned by
`zero_length_record_counts_keepalive_not_malformed_inner`.

## Full-body audit of every counted function

- `try_encap` (engine.rs): 8 return paths — UnknownPeer→other(mapper),
  no-session(inline), unconfirmed(inline, same wire error),
  BufferTooSmall ×2→other(mapper), RekeyRequired(mapper),
  encode-header BufferTooSmall(mapper), CryptoFailed(mapper),
  success(packets+bytes). No path uncounted; the two inline NoSession
  arms cannot reach the mapper (mapper's NoSession arm is defensive
  and documented). No double count.
- `try_decap`: 12 return paths — MalformedHeader, ceiling,
  UnknownSession, ShortRecord, BufferTooSmall, precheck
  OutOfWindow, CryptoFailed, Repeat, post-AEAD OutOfWindow (all
  mapper), keepalive (inline, deliberately NOT a drop counter),
  closure Err (single mapper site), success. Every post-AEAD error
  path retains the `out` wipe contract (keepalive returns with n==0 —
  nothing to wipe).
- Handshake wrappers: single increment per outcome; responder
  completion = `hs_responses_created` (one site, role-mapped at emit;
  no double count by construction).
- Call sites: both MTU guards hit the SAME `encap_mtu_drops`
  (frame/wg.rs fetches the engine before its guard — verified
  ordering at frame/wg.rs:53 vs :85); the previously discarded
  responder msg2 send error now counted + exception-ringed;
  cookie/unknown-type/runt semantics match the plan (runt excluded
  with rationale, not fictionally counted).

## Findings

1. **COSMETIC (fixed in-review)**: `FormatWireguardStatus` printed the
   keepalive line twice in detail view (conditional summary line +
   unconditional detail line). Summary form now suppressed when
   `detail` — tests re-run green.
2. **Noted, acceptable**: `peer_endpoint` shows the CONFIGURED
   endpoint only (learned endpoint is control-thread-local) —
   documented on the wire struct and rendered as
   "(responder-only; learned at runtime)" when empty.
3. **Noted, acceptable**: encap of a zero-length inner counts
   `encap_packets` with 0 bytes — unreachable in production until S5
   sends keepalives; semantics will be "keepalives sent count as
   packets", consistent with kernel wg.

## Wire / Prometheus / CLI audit

- serde renames vs Go json tags compared field-by-field — identical
  (35 counters + 6 identity/state fields). Empty-vec skip invariant
  pinned on both sides; `protocol_wire_v1.json` unchanged by
  construction (skip-if-empty default) — the populated pins close the
  fixture's optional-field gap exactly as Codex plan-r1 F5 required.
- Emitter label arities match descriptor variable-label lists; the
  series-set test pins all 37 populated series + the 36-series
  zeroed emission with the gauge absent.
- CLI prefix resolution: "w" uniquely resolves to wireguard among the
  security children; nil-cfg allowlist extended (status-only command).

MERGE-READY.
