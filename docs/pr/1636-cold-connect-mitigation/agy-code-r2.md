# AGY adversarial code review — round 2 (#1636)

Job ID: `adversarial-review-mpq2jl5d-sqd223`. Re-review of the round-1
fixes (transcribed from the AGY companion job result; the brain-folder
artifact path is reused across runs).

## Verdict: MERGE-READY — all four fixes verified correct, complete, no new defect

AGY independently ran both suites in the clean worktree:
- Go `pkg/daemon`: 100% PASS (step-0 + runtime-disable tunables).
- Rust `userspace-dp`: 1534 PASS, 0 FAILED.

### 1. AGY #4 log storm — FIXED
`compute_pending_neigh_timeout_ns` gates the fallback `eprintln!` behind a
process-static `AtomicBool IN_FALLBACK`: `swap(true)` prints only on the
false→true transition; `store(false)` on the success path re-arms so a
later revert logs exactly once again. "Correct, complete, operationally
sound. No race conditions or deadlocks; thread-safety fully guaranteed."

### 2. AGY #3 post-start leak + Codex Med #5 runtime-disable restore — FIXED
The `else if len(prior.neighRetrans) > 0` branch in
`host_tunables_daemon.go` restores neigh retrans on runtime userspace-dp
disable and clears the capture map (no double-restore on stop; clean
re-capture on re-enable). The observed-value-only post-start limitation is
documented and matches the netdev_budget contract. "Correct, complete,
operationally sound." `TestApplyStep0_RuntimeDisable_RestoresNeighRetrans`
passes.

### 3. Codex High #1 tunnel-route wrong-RG — FIXED
`queue_warm_pass` `continue`s on `route.tunnel_endpoint_id != 0` for both
families; a tunnel route can never be enqueued for warming on the underlay
egress RG. "Correct, complete, operationally sound."
`queue_warm_pass_skips_tunnel_routes` asserts the bypass.

### 4. Codex Med #4 stale probe after stop — FIXED
`neighbor_warmer_loop` re-checks `stop.load()` immediately after
`recv_timeout` and bails before any side effect (no `trigger_kernel_arp_probe`,
no `last_probed` insert). Raw-socket calls are isolated and shielded once
stop is raised. "Correct, complete, operationally sound."
`warmer_exits_on_disconnect` confirms clean exit on channel disconnect.

## Summary
All four fixes are "fully correct, complete, and optimal. No new defects,
thread races, or resource leaks have been introduced. The implementation
direction is safe and operationally resilient." Wire protocol confirmed
clean in round 1.
