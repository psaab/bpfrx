# Dataplane Decision: DPDK vs VPP

Date: 2026-03-02
Status: Active
Scope: bpfrx dataplane strategy

## Decision Summary

For this project today, **DPDK is the better next dataplane path than VPP**.

Why:
- There is already a substantial in-tree DPDK dataplane (`dpdk_worker/*` + `pkg/dataplane/dpdk/*`) that mirrors bpfrx semantics.
- The current architecture (Go control plane + compiler + dataplane interface) already supports DPDK as a backend.
- VPP would require a large custom plugin effort to preserve bpfrx-specific behavior (zone policy, screen checks, HA/failover semantics), plus operational model changes.

When VPP could become better:
- If product direction prioritizes very high-end encrypted throughput (especially IPsec/WireGuard) at 40/100G scale over short-term delivery and architectural continuity.

## Current Repo Reality

### eBPF/XDP-TC path (primary)
- Production path with broad feature coverage and HA behavior implemented around existing bpfrx design.

### DPDK path (secondary backend, in-tree)
- Implemented worker pipeline in C (`parse -> filter -> screen -> zone -> conntrack -> policy -> nat -> nat64 -> forward`).
- Go backend exists and is wired through `dataplane.DataPlane`.
- DPDK worker builds cleanly with current tree.

Known DPDK gaps visible in code:
- `pkg/dataplane/dpdk/dpdk_cgo.go`
  - `SetAppRange` / `ClearAppRanges`: TODO
  - `SetSessionV4` / `SetSessionV6`: TODO
  - `SetNPTv6Rule`: TODO
  - `SetMirrorConfig` / `ClearMirrorConfigs`: no-op today
- `pkg/dataplane/dpdk/fib.go`
  - ifindex -> DPDK `port_id` mapping still TODO

### VPP path
- No in-tree VPP dataplane implementation exists.
- Existing assessment doc is extensive, but implementation would still start from zero in this repo.

## What Matters Most for bpfrx

1. Preserve Junos-like behavior:
- Zone-pair policy semantics, NAT behavior, screens, session model, CLI/runtime parity.

2. Preserve HA behavior:
- VRRP/RETH failover behavior, fabric forwarding logic, session sync expectations.

3. Minimize control-plane churn:
- Existing FRR/strongSwan/networkd integration is already coupled to current architecture.

4. Ship incrementally:
- Continue improving throughput/reliability without a multi-quarter rewrite.

DPDK aligns better with these constraints than VPP right now.

## Option Comparison

### Option A: Continue DPDK backend evolution (recommended)

Pros:
- Reuses existing bpfrx pipeline model and compiler outputs.
- Lowest migration risk from current eBPF behavior.
- In-tree code already implemented and testable.
- Single project-owned control plane model remains intact.

Cons:
- Still custom dataplane code to maintain.
- Less built-in ecosystem than VPP for some advanced services.
- Requires finishing remaining TODOs for full parity.

Effort profile:
- Incremental and bounded; most work is finishing known TODOs and behavior parity.

### Option B: Build VPP backend now (not recommended now)

Pros:
- Strong high-end packet processing and mature routing dataplane framework.
- Potential major upside for high-throughput encrypted workloads.

Cons:
- Large initial implementation cost in this repo.
- Would require custom logic/plugins to preserve bpfrx semantics.
- Operational model complexity (VPP lifecycle, Linux CP integration, API/version coupling).
- Higher risk to HA and behavior parity during migration.

Effort profile:
- Multi-phase rewrite/integration project with significant validation burden.

## Recommendation

### Primary recommendation
- **Invest in completing and hardening the DPDK backend first.**

### Explicit non-recommendation (for now)
- Do **not** start a full VPP dataplane migration now.

### Revisit trigger for VPP
Re-open VPP if all are true:
- DPDK backend is functionally complete/parity-acceptable.
- Throughput goals materially exceed what eBPF+DPDK path can deliver on target hardware.
- Encrypted tunnel throughput becomes a primary product driver.
- Team is willing to own VPP integration and long-term plugin/API maintenance.

## Execution Plan (DPDK-first)

1. Close known DPDK functional gaps:
- Implement app range support
- Implement session write APIs
- Implement NPTv6 support
- Implement mirror config or explicitly mark unsupported end-to-end
- Fix deterministic `ifindex -> port_id` mapping

2. Add parity test matrix:
- eBPF vs DPDK behavior tests for NAT, policy, failover-critical flows, counters, and CLI-visible state.

3. Performance and stability gates:
- Define baseline/target for single-stream and multi-stream throughput, failover recovery behavior, and long-duration soak.

4. Only after 1-3:
- Decide whether VPP is still needed for next performance envelope.

## Related Docs

- DPDK architecture plan: `docs/dpdk-dataplane.md`
- VPP assessment: `docs/vpp-dataplane-assessment.md`
- Performance context: `docs/optimizations.md`
- HA behavior context: `docs/active-active-new-connections.md`
