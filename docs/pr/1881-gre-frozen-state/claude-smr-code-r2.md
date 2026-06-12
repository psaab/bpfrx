# #1881 implementation — Claude SMR review round 2 (delta: Codex r1 fix)

Scope: commit b2f5560fa (defer-prune attachment-drift fix) on top of
my r1 MERGE-READY.

## Self-critique of the original defer prune

Codex r1 was right and both AGY and I missed it: I copied the #1866
WG prune shape ("removal propagation") without re-deriving the stale
predicate for GRE. For WG the defer-window justification was UDP port
release (removal-only is the port-relevant case); for GRE the
spawn-baked identity is the TUN ATTACHMENT, so the defer prune must
cover attachment drift too — the armed-path closure for that window
(the rotation gate) depends on a forwarding rotation that the defer
branch never performs.

## Hostile pass over the fix

1. **Equivalence to pass-2**: pass-2 prunes on id-absent / mode-flip /
   `logical_ifindex`+name drift vs `self.forwarding`; the defer prune
   now does the same vs the snapshot ROW with the
   linux_name-fallback label — the same label rule as
   `forwarding_build/interfaces.rs` and
   `local_tunnel_tombstone_respawn_coherent`. Matches.
2. **Over-pruning under #1884**: because the Go side currently
   recreates anchors on every tunnel commit, a defer apply that
   touches tunnels will carry NEW ifindexes and prune ALL GRE entries
   as `attachment_changed_deferred`. CORRECT, not over-pruning: the
   old fd is attached to a netdev the Go side just deleted — the
   reader is dead either way, and the deferred bring-up respawns.
   Once #1884 ships reuse-in-place, ifindexes stop drifting and
   unchanged entries survive defers.
3. **Keep case**: a row identical to the spawned attachment yields
   `None` → entry survives (pinned by the extended test's
   same-snapshot assertion).
4. **Ordering**: unpublish (store #1, live-only minus stale) before
   stop+join — unchanged discipline.

## Verdict

**MERGE-READY** at b2f5560fa from the SMR seat.
