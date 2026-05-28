# Claude SMR code review — round 2 (#1636)

Branch `fix/1636-cold-connect-mitigation` after the 4-way review fixes.
Reviewers in round 1: Claude SMR (MERGE-READY), Codex (6 findings: 2 High,
3 Med, 1 Low), AGY adversarial (5 findings, no KILL, wire-protocol clean),
Copilot (4 findings). This round records the disposition + verifies the
fixes.

## Fixes applied (all build + test clean)

- **Codex High #1 — tunnel route gated on wrong RG**: route entries with
  `tunnel_endpoint_id != 0` are now skipped in `queue_warm_pass`.
  Forwarding gates tunnel traffic on the tunnel endpoint's RG
  (`owner_rg_for_resolution`), not the underlay egress RG; gating via
  `owner_rg_for_flow(egress)` could warm a standby tunnel RG. Tunnels are
  also out of warm scope per the plan. Test:
  `queue_warm_pass_skips_tunnel_routes`.
- **Codex Med #4 — stale probe after stop**: `neighbor_warmer_loop`
  re-checks `stop` immediately after `recv_timeout` returns an item, so a
  tearing-down dataplane fires no stray probe.
- **Codex Med #5 / AGY #3 — Go neigh retrans not restored on runtime
  disable**: `applyStep0TunablesWith` now restores neigh retrans + clears
  captures in the `!userspaceDP` branch when captures exist. Test:
  `TestApplyStep0_RuntimeDisable_RestoresNeighRetrans`.
- **Codex Low #6 / Copilot #2 / AGY #4 — log storm**: the option-D
  fallback warning is now transition-gated via a process-static AtomicBool
  (fires once on entering fallback, re-arms on recovery), so an
  un-applied-B host does not flood stderr per snapshot.
- **Copilot #1 — on_link_up dead code**: removed the unwired helper + its
  test and documented the deferral (no link-state RTM_NEWLINK monitor to
  call it; the RG-promote clear + 5s self-heal cover the case).
- **Copilot #3/#4 — docstring drift (≤250 vs 300 threshold)**: the
  ForwardingState field doc and `compute_pending_neigh_timeout_ns`
  docstring now reference `NEIGH_RETRANS_FAST_THRESHOLD_MS` and explain
  the jiffy-rounding rationale.

## Rejected (with rationale)

- **Codex High #2** (forced warm lost when the 4096-slot queue is full of
  stale items): requires 4096 in-flight items; the warmer drains each in
  microseconds and a realistic FRR snapshot enqueues dozens. The forced
  path also stamps `last_warm_sweep_ns`, so the next ordinary sweep
  recovers. Not a practical defect.
- **Codex Med #3** (promotion warms all active RGs, not just activated):
  already-resolved neighbors are skipped (`already_resolved`), so
  re-warming an unrelated already-active RG is a no-op. Broader than
  strictly necessary but harmless; per-RG correctness is preserved.
- **AGY #1** (coordinator-side silent poison skip in
  `on_rg_promote_active` / clears): a poisoned `last_probed_at` is already
  surfaced — the worker holds it with `.expect()`, so poison kills the
  worker, breaks the channel, and the producer's next `try_send` bumps
  `warm_disconnected` + the once-only operator log. A coordinator-side
  panic-on-poison would crash the control plane (worse) and is
  inconsistent with the coordinator's established `if let Ok` mutex
  discipline (apply_manager_neighbors, stop_inner).
- **AGY #2** (generation / per-key rate-limit race): the rate-limit key is
  `(ifindex, hop)`. A snapshot that *changes* a next-hop produces a
  *different* key (not rate-limited); a same-key re-warm targets the
  identical neighbor and is correct. The 5s window self-heals a transient
  miss. No incorrect-warm or missed-warm results.
- **AGY #5** (transient 800ms drop on manual sysctl revert): a single
  snapshot-interval window that only occurs when an admin manually reverts
  the sysctl; inherent to per-snapshot recompute and bounded.

## Cluster re-validation (post-fix binary)
- Cold connect: ~1.016s median (10 runs) — unchanged, as expected (fixes
  are HA/telemetry/lifecycle hardening, not the hot path).
- Smoke matrix: Pass A reverse v4 7.72 / v6 6.69 Gbps; Pass B per-class
  reverse healthy; no regression.
- make test-failover: **13 passed, 0 failed** on re-run (the earlier 3
  "fw0 not primary after manual failover" were a 5s-wait settling flake;
  the cluster converges to fw0-primary for all RGs).
- Warm telemetry `xpf_userspace_neighbor_warm_{drops,disconnected}_total`
  = 0/0 on both nodes through the full failover cycle.

## Verdict: MERGE-READY
1534 Rust tests pass; Go api + daemon tunable tests pass; clippy clean.
All High/Medium findings fixed or rejected with worked rationale; wire
protocol confirmed clean by AGY. The remaining rejects are bounded,
documented, and do not affect the per-RG HA invariant or correctness.
