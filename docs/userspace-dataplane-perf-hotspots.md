## Userspace Dataplane Perf Hotspots

Date: 2026-04-15

This note captures the current userspace dataplane CPU-cut work that restored post-CoS throughput, the validation used for it, and the remaining hotspots that still need targeted work.

Follow-up tracker: `#678`

### Validation Baseline

Validation command:

```bash
./scripts/userspace-perf-compare.sh --duration 8 --parallel 12
```

Validated live on the `loss` HA userspace cluster with binary-only helper rollouts that preserved `/etc/xpf/xpf.conf` and `/etc/xpf/.configdb`.

Current measured result on the validated helper build:

- IPv4: about `23.0 Gbps`
- IPv6: about `22.8 Gbps`

Representative steady-state sample:

- IPv4 intervals: `22.82, 23.34, 23.12, 23.01, 23.01, 23.12, 22.87, 22.86`
- IPv6 intervals: `21.21, 22.82, 23.03, 22.96, 23.14, 23.09, 23.04, 22.87`

### What This Perf Slice Changed

These cuts are all aimed at keeping the no-CoS and lightly-classified fast path close to the earlier userspace forwarding baseline.

- prequalified interface and `lo0` filter references so the packet hot path no longer pays per-packet string lookup overhead
- replaced linear protocol/DSCP matching with bitmap checks
- replaced generic port-range vector scans with specialized `any` / single-port / single-range / compact-set matchers
- precomputed ingress logical-interface resolution so packet forwarding no longer scans interfaces to map `(bind_ifindex, vlan)` to the logical unit
- skipped CoS TX-selection evaluation entirely when neither CoS nor TX-selection-capable filters are present for the packet family
- skipped ingress TX-selection reevaluation when the ingress filter cannot influence `forwarding-class` or `dscp_rewrite`
- reduced pending-forward request overhead by collapsing mutually exclusive frame payload storage
- removed duplicate `expected_ports` / `target_binding_index` recomputation on the flow-cache fast-path fallback into `PendingForwardRequest`
- optimized the common IPv6 single-address NAT checksum-adjust path to avoid repeated word-array materialization
- kept direct-TX as the dominant forwarded path, with copy-path fallback remaining at zero in the validated steady state

### Current Hotspots

These are the remaining first-order symbols from the validated steady-state perf sample.

IPv4:

- `poll_binding`: about `13.4%`
- `enqueue_pending_forwards`: about `4.3%`
- `mlx5e_xsk_skb_from_cqe_linear`: about `4.6%`

IPv6:

- `poll_binding`: about `13.3%`
- `enqueue_pending_forwards`: about `3.7%`
- `apply_nat_ipv6`: about `3.2%`

Interpretation:

- `poll_binding` is still the largest userspace bucket and is now the main place to keep cutting CPU.
- `enqueue_pending_forwards` is smaller than before, but it is still materially visible and still worth tightening.
- `apply_nat_ipv6` is no longer catastrophic, but it is still one of the remaining IPv6-specific costs.

### What Looks Left

The next work should stay narrow and perf-driven.

1. Split `poll_binding` into a colder orchestration shell and a smaller packet hot path.
2. Reduce request-build work that still happens before a frame is known to need the generic pending-forward path.
3. Keep shrinking `enqueue_pending_forwards`, especially the generic cross-binding and fallback work that still executes before direct-TX enqueue.
4. Continue cutting IPv6 NAT overhead only behind live perf confirmation.

More concrete next steps:

- move more one-time per-binding/per-family decisions out of `poll_binding`
- reduce temporary object construction on the session-hit and flow-cache-hit paths
- continue pushing more packets into the direct descriptor/in-place rewrite path before they ever become generic pending-forward requests
- revisit IPv6 NAT checksum and address rewrite work with targeted microbench plus live cluster perf, not speculative rewrites

### Rejected Or Rolled Back Experiments

These were tested and intentionally not kept.

- `RUSTFLAGS='-C target-cpu=native'` helper builds: hurt live throughput badly on the validated cluster
- adaptive idle-binding poll skipping: did not reduce the real `poll_binding` cost enough and hurt measured throughput
- over-aggressive `authoritative_forward_ports()` shortcutting: reduced the symbol share but hurt effective IPv4 throughput
- one direct-index `apply_nat_ipv6()` rewrite attempt: built and ran, but lowered IPv6 throughput and was rolled back

The rule for the remaining work should stay the same: keep only changes that survive live HA-cluster validation, not just local benchmarks or cleaner-looking code.
