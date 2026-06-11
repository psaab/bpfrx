# #1865 plan v1 — Claude SMR hostile review, round 1

Reviewer: Claude SMR (domain: WG protocol internals, Rust dataplane,
CPU/atomics, observability modeling). Contract: hostile, quoted-line
evidence, no rubber-stamp.

## Verdict: PLAN-NEEDS-MINOR-REVISION

The architecture (engine-owned relaxed-atomic counters, name-keyed
per-tunnel rows, additive wire, Path B) is sound and matches the code.
But the counter inventory has one MISSING counter that would turn a
healthy steady-state into operator-visible false alarms (F1 —
keepalives), one semantically dishonest counter name (F2), one Go-side
wire ambiguity (F3), and three smaller defects. None are
architecture-killers; all are v2 fixes.

## F1 (MAJOR — inventory gap): WG keepalives will count as `decap_drops_malformed_inner`

WG persistent keepalives are transport records with a ZERO-length
plaintext. Trace through `try_decap` (engine.rs):

- `pad_to_16(0) == 0`, so a keepalive's ciphertext is tag-only;
  `read_message` yields `n == 0`.
- `mark_confirmed()` fires (engine.rs:887) and the replay window
  updates — correct per spec, the keepalive authenticates.
- Then `inner_src_ip(&out[..0])` → `pkt.first()` is `None` →
  `Err(DecapError::MalformedInner)` (engine.rs:934, 1089).

So TODAY every keepalive from a kernel peer is functionally absorbed
(confirmation + replay update happen) but EXITS through the
MalformedInner error arm. Under plan v1 §3.3 #23 a peer with
`persistent_keepalive 25` produces a steady ~2.4 drops/min of
`decap_drops_malformed_inner` forever — indistinguishable from a
real malformed-inner attack, on the exact counter family this plan
exists to make trustworthy. **Required fix**: classify `n == 0` as a
new counter `decap_keepalives` (incremented after the replay gate,
before the inner-parse closure) and keep the external behavior
otherwise IDENTICAL (still no TUN write, still returns an error to
the caller, still `authenticated=false` at the dispatch site —
behavior changes are out of scope). Note for the record: the
dispatch-site consequence that an authenticated keepalive does NOT
refresh endpoint-learning (wg_control.rs:181-195) is a latent
roaming gap — file as a follow-up observation in the plan §9, do not
fix here.

## F2 (MEDIUM — dishonest name): `hs_initiations_sent` increments at *creation*, not send

Plan §3.3 #1 counts at `create_initiation` Ok (engine-internal), but
the send happens later in `drive_initiation` (wg_control.rs:427-435)
and can fail — the #1736 EINVAL bug was EXACTLY "created fine, send
failed silently". Counting creation under a `_sent` name re-creates
the ambiguity the counter exists to kill. Fix: rename to
`hs_initiations_created` (engine-internal) and keep `hs_send_errors`
(call-site). The EINVAL fingerprint becomes
`created↑ + send_errors↑ + completions flat` — unambiguous. Same
treatment for `hs_responses_sent` → `hs_responses_created`; and note
the response send at wg_control.rs:466 is currently
`let _ = wg_send_to(...)` — the plan must explicitly route that
discard into `hs_send_errors`, else responder-side send failures stay
invisible (the responder mirror of the EINVAL class).

## F3 (MEDIUM — wire ambiguity): `last_handshake_age_secs` zero-vs-absent on the Go side

Plan §3.2 says "field omitted when no handshake has ever completed."
On the Rust side an `Option<u64>` + `skip_serializing_if` works, but
the Go mirror as `uint64` + `omitempty` cannot round-trip the
distinction (a handshake 0 seconds ago re-marshals as absent), and a
plain `uint64` zero-default makes "never" read as "right now" —
operator-facing falsehood. Fix: ship the pair
`has_completed_handshake bool` + `last_handshake_age_secs u64`
(both serde `default`), and gate the Prometheus age gauge on the
bool. Boring and unambiguous beats clever.

## F4 (LOW): pubkey rendering — use HEX, not base64

Plan §3.2 picks base64 "matching `wg show`". The xpf wire + config
surface already standardizes HEX: `wg_peer_pubkey_hex`
(protocol/snapshot.rs:361, protocol.go:310). The operator configured
hex into xpf; showing base64 forces a mental re-encode and adds a
base64 dependency userspace-dp doesn't currently carry (no base64
crate in Cargo.toml). Emit hex; mention the divergence from `wg show`
in the CLI help/docs.

## F5 (LOW): cross-language "parity-pin test" is overpromised

§6 claims a test "so a Rust-side reason addition fails the Go
build/test". The wire carries FLAT named u64 fields, so Go↔Rust drift
is already impossible without an explicit field addition on both
sides (the existing fixture + key-absent pins catch shape drift). The
only "enum" is the Go emitter's label mapping, which is a
compile-visible explicit list. Replace the parity-pin promise with:
(a) the wire fixture diff, (b) a Go emitter test asserting the full
label set. Don't ship a test that pretends to guard something
structurally unguardable.

## F6 (LOW): status-row name fallback unspecified

`wg_tunnel_statuses()` keys rows by `ifindex_to_name` lookup, but
`spawn_one_wg_control_thread` (coordinator/mod.rs:681-688) shows the
lookup can MISS (it early-returns). A WG endpoint whose ifindex has
no name yet would silently vanish from telemetry — during exactly the
broken-bring-up windows operators need it. Fix: fall back to the
snapshot row's `linux_name`/`interface` label convention used by
`wg_tombstone_respawn_coherent` (coordinator/mod.rs:827-831), or as a
last resort `wg-endpoint-<id>`; never drop the row.

## Answers to §11 questions

1. **Path B** — agreed. The #1736 narrative is a CLI-first operator
   story; the buffers pattern makes it mechanical. Path C: agree
   defer/kill — `RecentExceptions` covers the errno class and the
   flood-formatting cost is real.
2. **Name keying** — agreed, with F6's fallback. Keep
   `tunnel_endpoint_id` informational-only; Prometheus label =
   tunnel name only.
3. **Inventory** — F1's `decap_keepalives` is REQUIRED. Folding
   `encap_drops_other` is acceptable (all three classes are
   structurally-impossible-unless-bug). Counter-only
   unconfirmed/no_session split: yes — preserving
   `EncapError::NoSession` for both arms keeps every caller contract
   (wg_control NoSession→request_handshake, frame/wg.rs same) intact;
   a new variant would force both call sites to match it identically
   anyway.
4. **No-carry-across-rebuild** — agreed. Under #1873 renumbering,
   same-id inheritance would attribute tunnel A's history to tunnel
   B. Resets are honest and `rate()` -safe.
5. **Bytes** — inner-IP bytes both directions, agreed (symmetric and
   what an operator compares against end-host counters). Document
   that it excludes WG+outer overhead, so it will NOT match the
   kernel peer's `wg show` transfer numbers.

## Hot-path audit (independent check)

Verified: no non-WG path touches any new code — `frame/mod.rs` only
enters the WG branch when `tunnel_endpoint_id != 0` and mode ==
"wireguard" (frame/wg.rs:14-19), and `wg_encap_frame` already does
two `vec![]` allocations per packet (frame/wg.rs:97,111), so two
relaxed `fetch_add`s are noise. All other increment sites are the
control thread. Status assembly is the existing 1/s poll. Compliant
with docs/engineering-style.md.

## Wire-compat audit

The `Vec::is_empty` skip + serde `default` + fixture-regen +
key-absent pins plan matches the #1621/#1635/#1782 discipline. One
addition required: the byte-identical-when-empty assertion must be an
explicit test (a default `ProcessStatus` with no WG config serializes
with NO `wg_tunnels` key), not just prose — plan §5 item 2 says this;
hold the implementation to it.
