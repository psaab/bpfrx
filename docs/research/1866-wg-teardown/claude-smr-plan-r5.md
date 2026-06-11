# #1866 plan review — Claude SMR (hostile), round 5

Reviewer: Claude (domain SMR). Target: plan.md v5 @ 3b7aeaabf.

## Round-4 resolution check

Codex r4's attachment omission is closed: the entry records
`spawned_ifindex` + `spawned_tunnel_name`; apply-time stale =
engine-ptr-differs OR attachment-differs (also closing the pre-existing
D5 rename gap, now in §4b with tests 6d/6e); the sweep coherence tuple
adds interface/linux_name/ifindex. Re-ran the rename-under-defer
sequence against v5: the tombstone's recorded attachment (wg0) differs
from the stored snapshot row (wg1) ⇒ sweep skips; at the deferred
bring-up the apply-time stale prune sees attachment-differs ⇒ stop+join
⇒ respawn attached to wg1 with the SAME engine Arc (TAI64N + live
sessions preserved — the restart is attachment-only, engine state is
untouched, so S2a §4.2 reload stability holds).

## Round-5 questions (§11)

1. **Attachment completeness.** I enumerated every parameter the
   `wg_control_loop` closure captures at spawn (mod.rs:545-560):
   `tunnel_name` (attachment — covered), `tunnel_endpoint_id` (map key),
   `engine` Arc (ptr — covered), `listen_port` (crypto tuple — covered),
   `peer_endpoint` (crypto tuple — covered), `recent_exceptions`/`stop`
   (infrastructure, not config). Nothing escapes both checks. One
   implementation note for /engineer: at respawn, the tunnel name is
   re-resolved from `forwarding.ifindex_to_name`; if resolution fails
   (no entry), skip the respawn exactly as the apply-time spawn loop
   `continue`s today — never spawn with a stale cached name.
2. **Remaining incoherent-spawn sequences.** Creation sites unchanged
   (apply-time + the doubly-guarded sweep); with crypto identity AND
   attachment both checked against the latest accepted snapshot, every
   spawn parameter is snapshot-coherent at creation time. The only
   residual is master's bounded live-thread-through-defer-window
   behavior for parameters that DIDN'T change — by definition coherent.
3. **Anything else.** No. Five rounds in, each fix has strictly narrowed
   the new code's authority; the defect inventory is D1-D5, all closed
   or pinned; scope unchanged (no counters, no TUN delete, no wire
   changes); sequencing after #1868 stands.

## Verdict

**PLAN-READY.**
