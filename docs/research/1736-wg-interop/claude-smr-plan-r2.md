# Claude SMR hostile plan review — #1736 S2b, round 2

Reviewer: Claude (domain SMR). Target: plan.md v2 + the round-1 fold.

## Verdict: PLAN-READY

Hostile re-verification, not a rubber stamp. Checks performed this round:

1. **P4a/P4b kernel semantics** — re-derived from wireguard-linux: both
   `keep_key_fresh()` sites gate on `i_am_the_initiator`; expired-keypair
   send path stages + initiates; the initiator confirms a fresh session
   immediately via staged-data-or-keepalive on handshake completion
   (`wg_packet_send_keepalive` fallback). Codex r2 confirmed the same with
   source citations. The plan's >1 s-gap-files-issue rule covers the
   "ms-scale is empirical, not protocol-guaranteed" caveat.
2. **P5 fragment math** — AGY r2 closed my residual <8 B-trailing-fragment
   worry with arithmetic: WG outer UDP payload is 16-byte structured
   (16 B data header + 16 k ciphertext+tag), first-fragment payload is a
   multiple of 8 (1480 @ MTU 1500), so the second fragment payload is a
   non-empty multiple of 8 → `parse_l4` never fails on it → it always
   reaches the `is_local_destination` fallback (lib.rs:567-579). Expected
   clean-success default stands.
3. **P6 TAI64N** — found and fixed my own v2 error this round: `tai64n.rs`
   derives timestamps from `SystemTime` (wall clock), so post-restart
   initiations are normally ACCEPTED without a peer flush; the negative
   control is observe-and-record, and the runbook flush stays
   unconditional per the issue text. AGY r2 independently flagged the same
   expectation. Plan v3 carries the corrected P6.
4. **Secondary suppression** — `compiler.go:161` node-specific group
   expansion + `/etc/xpf/node-id` (daemon.go:365) verified by Codex r2;
   fail-closed escape hatch (groups-expansion gap = blocking finding)
   retained.
5. **No reviewer writes** — worktree clean except my own plan edits (AGY
   write-during-review pattern did not recur).

Residual risks are all empirical-by-design (the harness is the
instrument): the unconfirmed-egress window size, the fragment-path
outcome, iperf3-through-TUN baseline. Each has a defined pass/record/file
rule. Nothing left that re-planning can resolve cheaper than running it.

Convergence: Codex r2 PLAN-READY (task-mq91oljl-e4d97u), AGY r2 PLAN-READY
(adversarial-review-mq91if0w-zxjm2r, r1 PLAN-KILL revoked), Claude SMR r2
PLAN-READY. 3-of-3.
