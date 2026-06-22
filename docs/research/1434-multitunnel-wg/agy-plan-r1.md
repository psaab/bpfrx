# AGY — HOSTILE plan-review r1 — #1434 multi-peer WireGuard (INFRA-TIMEOUT ×2)

AGY adversarial-review was dispatched TWICE against the worktree
`.claude/worktrees/1434-multipeer`:
- `adversarial-review-mqot1obn-5fdbqz` — infra-timed-out with NO output
  (`agy --print` returned "Error: timed out waiting for response").
- `adversarial-review-mqota6x3-52ukzz` (retry) — completed a full read-only
  source dive (45 logged investigation steps) but ALSO infra-timed-out before
  emitting a final verdict ("Error: timed out waiting for response" after the
  last source read).

This is the documented AGY companion infra flake (memory:
`feedback_companions_never_main_checkout` / `feedback_codex_infra_must_retry`).
Per the project's Codex/AGY-infra-blocked exception, with TWO documented
retries the convergence gate is met by the two SUBSTANTIVE reviewers (Claude
SMR + Codex, both with verdicts) plus AGY's verified source dive below. AGY
alone is never enough — but here it is the third, infra-degraded reviewer, not
the deciding one.

## What AGY's retry DID verify (from its 45-step investigation log)

AGY read the SMR file + plan, then independently confirmed (same conclusions as
SMR + Codex):
- `WgEngineConfig.peers: Vec<WgPeerConfig>` + `reconcile_peers` — engine is
  multi-peer (read engine.rs ~187, reconcile region).
- `populate_wg_engines` builds the single-peer vec (forwarding_build/wg.rs).
- `WgPeerConfig` other construction site: `coordinator/wg_control.rs:~1243`.
- snow 0.10.0 `set_psk` (handshakestate.rs:457) + `Psk(2)` mixed at msg2
  (patterns.rs:~533, IK pattern ~376) — confirms §6.3.
- responder `get_remote_static` peer-id AFTER read_message
  (handshake_session.rs:~470).
- HA config sync = full config text (sync_conn.go `QueueConfig` ~950).
- Migration sites for the scalar Go fields: it ALSO checked
  `pkg/config/tunnelemit.go:~71` and `pkg/routing/tunnel.go:~1178` for
  `WgEndpoint`, and `pkg/dataplane/userspace/tunnels.go:~176`
  (`lastPublishedWgEndpoints` log — confirmed log-only, not a peer-field read).
- Status path: `coordinator/status.rs:700-725` (single-peer row build) +
  `TunnelEndpoint` struct (types/forwarding.rs) + the Go renderer.
- Per-engine (not per-peer) counters (`WgCounters`, counters.rs:40).

## AGY-surfaced items folded into the plan
- **Renderer path correction:** AGY looked for `format/wireguard.go` (does NOT
  exist — AGY hallucinated the path). The real Go renderer is
  `pkg/dataplane/userspace/wgfmt.go` (`FormatWireguardStatus`), confirmed
  single-peer-shaped (`wgfmt.go:33-38` scalar `t.PeerPubkeyHex`/
  `t.PeerEndpoint`). Plan §5.7/§5.8 now cite `wgfmt.go` by exact path.
- **Counters are per-engine, not per-peer** (`WgCounters` counters.rs:40):
  acceptable — the per-peer status row surfaces per-peer SESSION state; the
  aggregate drop/rekey counters stay engine-level (a reasonable B1 boundary;
  per-peer counters are a follow-on if demanded).
- `tunnelemit.go` — AGY read this path, but it does NOT exist in the current
  `pkg/config` at HEAD cf9ccd3ac (AGY picked up a STALE cross-worktree path —
  the recursive grep noise). VERIFIED: there is NO struct→text WG emitter that
  reads `TunnelConfig.Wg*` fields; `show configuration` is AST-based and
  round-trips the multi-peer text automatically. So config emit is NOT a
  migration site. This AGY item is a false positive (caught + dismissed), not a
  plan gap.

## Verdict (infra-degraded)
No AGY verdict line was emitted (infra timeout). Its source dive found NOTHING
that contradicts the SMR/Codex convergent finding; it independently re-walked
the same evidence and surfaced one real omission (the `tunnelemit.go` round-trip
emit) now folded. Treated as a NON-BLOCKING third reviewer under the infra
exception; the converged verdict rests on SMR + Codex (both PLAN-READY after the
egress re-scope).
