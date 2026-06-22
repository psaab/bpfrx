# Codex — HOSTILE plan-review r1 — #1434 multi-peer WireGuard

Codex (codex-rescue, gpt-5.x) hostile plan-review of
`docs/research/1434-multitunnel-wg/plan.md`, read-only from the worktree
`.claude/worktrees/1434-multipeer` @ branch research/1434-multitunnel-wg.
Source dive across engine.rs, handshake_session.rs, forwarding_build/wg.rs,
frame/wg.rs, coordinator/{wg_control,tunnel_supervision,status}.rs, wg/timers.rs,
wg/peer.rs, snow-0.10.0, pkg/config/*, pkg/dataplane/userspace/*,
pkg/routing/tunnel.go, pkg/cluster/sync_conn.go, pkg/configstore/*.

Transcript: `/tmp/.../tasks/bvk8q79xz.output` (tool trail). The synthesized
verdict below is reconstructed from Codex's captured reasoning checkpoints
(the codex-rescue companion infra-dropped the final result fetch — a known
flake; the reasoning trail is complete and unambiguous).

## Verdict: PLAN-READY after folding the egress re-scope (no fatal kill)

The plan's central design claim ("engine already multi-peer; blocker is the Go
config + wire DTO") is HALF right and the plan as originally drafted understated
the dataplane work. Codex independently surfaced the SAME egress gap the SMR
hot-path audit found, plus the timer + control-thread sites. The gap is a SCOPE
correction, not a fatal flaw — the per-peer state already exists on `Peer`.

## Findings (severity-tagged)

### BLOCKER-class design gap (now folded → §5.0 / §5.0.1) — egress is single-peer
Codex: "a more fundamental egress issue: `try_encap` requires a caller-supplied
peer pubkey" → "blocker-level design gap: the plan's hub-and-spoke example needs
egress peer [selection]". Confirmed by my read:
- `frame/wg.rs:108` `try_encap(&endpoint.wg_peer_pubkey,…)` + scalar endpoint.
- `coordinator/wg_control.rs:303` + `wg/timers.rs:250` both use
  `engine.first_peer_pubkey()` (engine.rs:443 = `peers.first()`).
- `wg/timers.rs:107` explicitly: "Per-ENGINE (single peer in S2a); per-peer
  generalization rides with #1434/S6".
So encap peer-selection, the WG control-thread TUN egress + endpoint roaming,
AND the keepalive/rekey timers are all single-peer. RX/decap is the only
multi-peer-ready path. **Folded:** §5.0.1 inventory table + B1b re-scoped to the
full egress generalization; B1a explicitly marked PARTIAL (RX-multi / TX-peer[0]).
This is "blocker for the FEATURE as the issue describes it", resolved by the
re-scope — NOT a reason to kill the plan.

### MAJOR (was a draft risk, now confirmed RESOLVED) — PSK ordering
Codex: "The PSK check came out mostly in the plan's favor: snow 0.10.0 has
`set_psk`, and both snow patterns [confirm Psk(2) at msg2]". Agrees with the SMR
MAJOR-1 self-catch. §6.3 stands.

### MAJOR (folded) — migration sweep incomplete in the draft
Codex: "the Rust runtime has additional scalar [migration] sites" beyond the
draft's list; "the plan's own migration sweep is better than its earlier 'one
Rust line' claim, but it still [missed sites]". The missed Rust sites
(status.rs:707, wg_control.rs:303, timers.rs:250, frame/wg.rs:108) are now ALL
enumerated in §5.0.1 + §5.8. Go sweep "largely checks out" (the §5.7 list incl.
pkg/routing/tunnel.go:1152).

### CONFIRMED (plan holds)
- Engine peer table is genuinely vectorized (`WgEngineConfig.peers: Vec`,
  PeerTable, `reconcile_peers`). NOT overstated.
- `reconcile_peers` is only called from `WgEngine::new` in production
  (engine.rs:389) — live per-commit peer add/remove goes through engine REBUILD,
  not in-place reconcile. Folded as a NOTE in §5.0.1 (acceptable for B1: a
  config change re-handshakes, TAI64N-seeded).
- HA config-sync queues full config TEXT (sync_conn.go) → no new sync format.
- ConfigSnapshot not persisted to disk (configstore stores config text/db, not
  the transient snapshot) → no on-disk migration. Plan's R1 holds.
- Fixture regen via `XPF_PROTOCOL_WIRE_REGEN=1` in protocol/tests.rs. Correct.
- Parser uses ordered child slices; `namedInstances` normalizes both AST shapes
  → Path A schema/compiler approach (vrrp-group model) is sound.

### MINOR — status `peer_has_confirmed_session` is per-pubkey
Codex: "the source has a per-pubkey `peer_has_confirmed_session`" — so the
per-peer status row (§5.8) has the data available per peer; just widen the DTO.
Consistent with the plan.

## Recommendation
PLAN-READY. The egress re-scope (§5.0.1) is the load-bearing correction and is
now in the plan. B1a (config + RX + status) is genuinely lab-free but PARTIAL;
B1b (egress generalization) completes the feature and is lab-recommended;
recommend B1a+B1b in one PR. B2 (PSK) de-risked via `set_psk`. No fatal flaw.
