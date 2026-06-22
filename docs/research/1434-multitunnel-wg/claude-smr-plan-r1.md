# Claude SMR — HOSTILE plan-review r1 — #1434 multi-peer WireGuard

Reviewing `docs/research/1434-multitunnel-wg/plan.md` @ commit f86f1a9ef
(+ in-flight §6 edits). Posture: try to KILL the plan, not bless it. Verified
against origin/master HEAD cf9ccd3ac and the pinned snow 0.10.0 source.

## Verdict: PLAN-READY for B1; B2 PLAN-READY (de-risked, may ride B1's PR)

with the findings below folded. No BLOCKER. One MAJOR self-catch (already
corrected), three MINORs, two NITs.

---

## Findings

### MAJOR-1 (SELF-CATCH, already corrected in §6.3) — B2-i fallback rested on a FALSE premise
DRAFT-v1 §6.3 claimed "snow's Builder cannot set PSK mid-handshake" and
proposed a conservative rebuild-and-re-read-msg1 fallback (B2-i). That premise
is FALSE for the pinned version. Evidence:
- `snow-0.10.0/src/handshakestate.rs:457` — `pub fn set_psk(&mut self,
  location, key)` exists and is callable mid-handshake.
- `snow-0.10.0/src/params/patterns.rs:533-545` — `apply_psk_modifier(2)`
  pushes `Token::Psk(2)` onto the SECOND message's token list, so the PSK is
  mixed during `write_message(msg2)` (the responder's reply), AFTER
  `read_message(msg1)` (`handshakestate.rs:262-266`, `396-401`).
So the responder can `read_message(msg1)` → `get_remote_static` → `set_psk(2,
peer_psk)` → `write_message(msg2)`. Cleaner than B2-i, no double-read.
**Impact:** B2 is meaningfully LESS risky than the draft implied — the only
remaining B2 cost is a per-peer engine field + plumbing + secret hygiene, not a
snow protocol-ordering problem. **Resolution:** §6.1/§6.3/§10 rewritten to the
`set_psk` path (B2-ii) and to note B2 may ride B1's PR. This is exactly the
SMR-soft-pass-then-correct pattern the discipline warns about — caught here by
reading the dependency source, not the issue prose.

### MINOR-1 — `show security wireguard` may render only ONE peer today
§5.7 correctly says the CLI reads from the dataplane STATUS
(`FormatWireguardStatus`), not config. But the plan must CONFIRM the status row
+ renderer already iterate N peers. If the per-peer telemetry (`coordinator/
status.rs`, `FormatWireguardStatus`) is shaped one-peer-per-tunnel, then
multi-peer is configurable + forwards but is INVISIBLE in the CLI — a poor
operator experience and arguably an incomplete B1. **Action:** round-1
deliverable for `/engineer` — verify the status/CLI peer cardinality; if
single-peer, either widen it in B1 or file a tight follow-on. Do not ship B1
claiming "operator can configure N peers" if the operator cannot SEE them.

### MINOR-2 — outer-family / MTU is asserted tunnel-level but two sites sniff a scalar endpoint
§5.4 and §5.7 correctly flag `tunnels.go:93` (outer-family sniff) and
`pkg/routing/tunnel.go:1152` (outer-MTU) both read the scalar `WgEndpoint`. The
plan's resolution ("one family per WG interface, commit-reject mixed") is
sound (one UDP socket = one family), but the plan must make this a HARD
commit-time check, not just documentation — otherwise an operator configures a
v4 peer + a v6 peer, the second silently mis-sizes MTU / mis-sniffs family, and
forwarding half-breaks. **Action:** §5.5 should list "mixed-endpoint-family =
commit reject" as a named validator, not leave it as a §5.6b open decision.
Promote it from "decide" to "do".

### MINOR-3 — zero-peer reject is left open; pick it now
§5.5/§5.6c leaves "zero-peer reject vs allow" undecided. A WG tunnel with zero
peers can never handshake; `reconcile_peers(&[])` is valid-but-useless (empty
PeerTable). Leaving it open invites an `/engineer` coin-flip. **Recommendation
to lock:** REJECT zero-peer at commit with a clear message ("wireguard tunnel
<if> has no peer"). This matches "a WG tunnel needs at least one peer to be
meaningful" and gives the operator immediate feedback. (Counter-argument: a
responder-only tunnel that learns peers dynamically — but xpf has no dynamic
peer learning, peers are config-static, so zero-peer is always a mistake.)

### NIT-1 — Path B (map) dismissal is correct but understates one more cost
§4 Path B rejection is sound. Add: a map ALSO breaks the wire FIXTURE
stability (non-deterministic JSON key order on serialize unless sorted), which
the plan would have to special-case anyway. This is one more vote for Path A;
the slice serializes in a stable order for free once sorted by pubkey.

### NIT-2 — fixture: pin the SORT in the dual-peer fixture
§7.1 adds a two-peer fixture. Ensure the two peers in that fixture are authored
OUT of pubkey-sorted order in the SOURCE config but appear SORTED in the
golden JSON — so the fixture actually exercises the §5.4 sort-by-pubkey
determinism guarantee, not just "two peers happen to round-trip". Otherwise the
HA-determinism property is untested.

---

## Claims I tried to break and could NOT (plan holds)

- **Engine is genuinely multi-peer.** Confirmed: `WgEngineConfig.peers: Vec`
  (engine.rs:190), `PeerTable.peer_index_by_pubkey` + AllowedIPs LPM
  (engine.rs:244-252), `reconcile_peers(&[WgPeerConfig])` (engine.rs:507) with
  per-pubkey Arc reuse, removed-peer session/pending drain, atomic ArcSwap
  publish. Not overstated.
- **`populate_wg_engines` is the sole collapse.** Confirmed: wg.rs:48-72 is the
  only `peers: vec![peer]`. The control thread / frame/wg.rs / status all key on
  endpoint id and iterate the engine's PeerTable, which is already N-peer.
- **HA config-sync is config TEXT.** Confirmed `sync_conn.go:566` "QueueConfig
  sends the full config text". No new sync wire format; determinism is the only
  requirement, handled by sort-by-pubkey.
- **ConfigSnapshot not persisted.** Confirmed no marshal-to-disk site in pkg/;
  snapshot is transient over the control socket. No on-disk migration.
- **Fixture regen path.** Confirmed `XPF_PROTOCOL_WIRE_REGEN=1` in
  `protocol/tests.rs:1063-1196`.
- **B1 needs no shim / no lab.** Confirmed: B1 feeds the already-multi-peer
  engine more peers; it touches no `userspace-xdp` shim (the single listen port
  is unchanged — Axis A's shim steering is NOT in play for multi-peer-one-port),
  no hot path beyond the engine's existing PeerTable lookup. `make test` +
  `cargo test` are the right gates. Live multi-peer handshake = #1703 lab.
- **Two-axis disambiguation is real and load-bearing.** The prior
  `research/1434-wireguard-multitunnel` plan is Axis A (shim multi-port). This
  plan is Axis B (multi-peer-one-port). They do not overlap; this plan does not
  re-do or contradict the prior one.

## Recommendation
Fold MINOR-1/2/3 (confirm CLI peer cardinality; promote mixed-family to a hard
validator; lock zero-peer=reject) and NIT-2 (sort-exercising fixture) into the
plan, then PLAN-READY. B1 is the headline driveable-now slice; B2 (per-peer
PSK) is de-risked by the `set_psk` finding and may ride B1's PR, splitting only
if secret hygiene (R3) proves heavy. Interop lab → #1703.
