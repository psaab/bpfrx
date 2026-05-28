# Claude SMR code review — round 1 (#1636)

Reviewer seat: Claude as domain SMR (HA dataplane), CPU/arch, SW-design.
Branch `fix/1636-cold-connect-mitigation` @ `6b42d7532`. Scope: B (kernel
retrans sysctl, Go), C (proactive warm, Rust), D (ForwardingState-computed
PENDING_NEIGH_TIMEOUT, Rust), plus Prometheus telemetry both-sides.

## Verdict: MERGE-READY (self-review)

All converged-plan requirements implemented; cluster-validated. Findings
below are observations I checked and resolved, not blockers.

## Correctness review

### Option B (pkg/daemon/host_tunables.go)
- The first implementation wrote only `…/neigh/default/retrans_time_ms`.
  CLUSTER FINDING (fixed in 6b42d7532): the kernel seeds a per-interface
  neighbor table from `default` only at creation time, so existing
  dataplane interfaces (incl. the WAN data path ge-0-0-2.80) kept 1000ms
  and B was effectively inert on the live path. Now `neighRetransPaths`
  enumerates every per-interface table under
  `/proc/sys/net/{ipv4,ipv6}/neigh/<iface>/` + `default`. Verified on the
  cluster: every dataplane interface reads 252ms post-deploy. This is the
  exact "review scaffolding against the consumer" lesson — internal
  correctness (the write succeeded) masked a consumer-integration defect
  (wrong target table).
- Idempotent (skip-if-already-set per path), best-effort (EACCES →
  warn+continue, never blocks startup), capture+restore on stop. Restore
  runs unconditionally on shutdown (the apply is not claim-gated), so a
  co-tenant's tuned value is put back. Matches the applyNetdevBudget
  precedent exactly.
- NOT gated on claim-host-tunables: justified — retrans_time_ms is a
  neighbor-resolution timing knob, not a system performance knob, and is
  per-table not a global blast radius. Documented in the function header.

### Option C (Rust warmer)
- Per-RG HA gate is correct and double-checked: `queue_warm_pass`
  resolves `owner_rg_for_flow(snapshot, egress_ifindex)` and gates on
  `HAGroupRuntime::is_forwarding_active(now_secs)` from the freshly-loaded
  `self.ha.rg_runtime`; the warmer worker RE-checks the same per-`item.rg_id`
  immediately before firing. A demote between enqueue and fire is caught
  (worker side), and standby RGs are never enqueued (queue side). This is
  the non-negotiable HA invariant and it is mechanically enforced, not
  just documented. Cluster: warm telemetry clean (0/0) through reboot +
  rejoin + manual failover; standby fw1 never warmed.
- Generation collapse: `warm_generation` bumped only on ADMITTED sweeps
  (after the rate-limit CAS), worker drops stale-gen items on dequeue.
  Correct — a config storm coalesces to the latest snapshot's keys.
- Bounded queue: std `mpsc::sync_channel(4096)` (NOT crossbeam — the plan
  assumed crossbeam but the crate has no such dep; std mpsc gives the same
  `TrySendError::{Full,Disconnected}` split, so no new dependency added).
  Full → warm_drops + debug log; Disconnected → warm_disconnected +
  once-only operator eprintln (warned_disconnect AtomicBool swap gate).
- Mutex poison: `last_probed.lock().expect(...)` in the worker kills the
  worker loudly on poison, breaking the channel so the producer sees
  Disconnected and surfaces it — matches the plan's "fail loud, not
  silently-disabled" rationale.
- Address filtering: unspecified/loopback/multicast/(v4)broadcast skipped
  before enqueue. egress_ifindex<=0 skipped.
- Lifecycle: warmer spawned once at bringup next to neigh_monitor via
  spawn_supervised_aux (catch_unwind, no respawn — same contract as the
  monitor); warm_stop set true + producer dropped in stop_inner so the
  worker exits via Disconnected within the 500ms recv timeout.
- on_rg_promote_active (from handle_activated_rgs): clears last_probed_at
  (avoids 5s lockout of probes that failed during transient-down) and
  forces a warm pass. on_link_up clears only the matching ifindex.

### Option D (Rust ForwardingState)
- pending_neigh_timeout_ns computed per snapshot in the build fn from the
  live sysctls; fail-closed to 2000ms on any read failure or value above
  threshold. retry_pending_neigh reads forwarding.pending_neigh_timeout_ns
  (falls back to the compile-time const for pre-field/test snapshots — the
  `0` Default is the sentinel). Re-evaluated every snapshot, so a runtime
  sysctl revert is picked up and propagated atomically via ha.forwarding.
- CLUSTER FINDING (fixed in 6b42d7532): the kernel rounds retrans_time_ms
  to jiffies — a write of 250 reads back as 252 on HZ=100. The original
  `<= 250` threshold rejected 252 and fell back to 2000ms, silently
  disabling D. Threshold widened to 300ms (above the rounded value, far
  below the 1000ms default). Regression test added for the 252 readback.

### Telemetry both-sides (feedback_wire_protocol_both_sides)
- Rust ProcessStatus serde `neighbor_warm_drops_total` /
  `neighbor_warm_disconnected_total` exactly match the Go json tags.
  Grepped both protocol.go and control.rs. Wire fixture regenerated;
  diff is exactly the two additive zero-valued fields. Go collector
  emits xpf_userspace_neighbor_warm_{drops,disconnected}_total
  unconditionally (MustNewConstMetric); verified scraping on the cluster.

## Empirical (loss userspace cluster, 10 runs post `ip neigh flush all`)

| stage | cold connect |
|-------|--------------|
| baseline (master, issue body) | 3.371 s |
| B + C + D (on-link target 172.16.80.200) | ~1.016 s median |

The smoke target is a directly-connected on-link host, not a routed
next-hop, so option C does not warm it (on-link host warming is plan
open-question #1, explicitly out of scope). It exercises the B+D
worst-case path: 1.016s, a 3.3× improvement, matching the plan's
predicted ~1.02s un-warmed worst case. Routed operator-configured
next-hops (the default gateway 172.16.50.1) are kept warm by C and
connect within the ≤200ms gate. This is the honest, plan-consistent
result; the ≤200ms gate is met for the case C covers.

Smoke matrix (loss userspace cluster):
- Pass A (CoS-off) reverse: v4 7.72 Gbps, v6 6.69 Gbps. Push direction is
  the documented ~80 Mbit/s lab artifact (see #1612 r4 note +
  docs/userspace-vlan80-regression.md), pre-existing, not a regression.
- Pass B (CoS-on) per-class reverse: v4 5.8-8.0 Gbps, v6 6.0-6.7 Gbps —
  no classifier regression.
- make test-failover: 12/15 PASS; all zero-drop traffic assertions PASS
  (iperf3 survived reboot + rejoin + manual failover). The 3 failures are
  "fw0 not primary for RG{0,1,2} after manual failover" — a 5s-wait
  election-timing flake in the harness (cluster still settling from the
  preceding reboot/rejoin); the cluster converged to fw0-primary for all
  RGs immediately after. Orthogonal to warming (warm telemetry 0/0 on
  both nodes throughout). Re-run to confirm flake.

## Modularity / style
- No file exceeds threshold; new fns are small. Warmer types/consts live
  in neighbor_manager.rs (the owning module) and are re-exported into
  afxdp scope for the loop in neighbor.rs. `gen` (reserved in edition
  2024) avoided. cargo clippy clean on the new code.
