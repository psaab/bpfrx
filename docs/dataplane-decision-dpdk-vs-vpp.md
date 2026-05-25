# Dataplane Decision: DPDK vs VPP

> **Status: Retired.** The DPDK dataplane is retired under
> umbrella issue #1525. The userspace AF_XDP dataplane
> (`userspace-dp/`) is the primary/default backend. Migrate with
> `set system dataplane-type userspace`, or simply omit
> `system dataplane-type` (userspace is the default). See
> [`userspace-dp/README.md`](../userspace-dp/README.md) for the
> active design.

## Current State (2026-05)

- DPDK is retired under #1525. There is no in-tree dataplane
  competition between DPDK and VPP today; the userspace AF_XDP
  dataplane (`userspace-dp/`) is the primary/default backend, and
  the legacy eBPF dataplane is being retired in parallel under
  #1373.
- The DPDK source under `dpdk_worker/` and `pkg/dataplane/dpdk/`
  remains in-tree until Phase 3 of #1525 deletes it. Commit-time
  rejection of `set system dataplane-type dpdk` is planned in
  Phase 1 (#1526; not yet on master). Per #1525, builds with
  `-tags dpdk` are not supported for production.
- VPP was never implemented in xpf. There is no current plan to
  add a VPP backend. If one becomes interesting in the future, a
  fresh decision document will be filed at that time; the section
  below captures the trigger we would use to make that call.

## Revisit Trigger for VPP

Re-open VPP assessment if all are true:

- Encrypted tunnel (IPsec / WireGuard) throughput becomes a
  primary product driver. When kernel WireGuard/XFRM performs
  crypto, userspace-dp's AF_XDP socket on the physical NIC
  cannot see inner payloads of kernel-managed tunnels — it only
  observes the outer encrypted packets. xpf can still hook
  decrypted traffic via TC BPF on the post-crypto interface
  (e.g. `wgN` or an XFRM interface), or via XDP on a veth on
  the decrypted side, but both add per-packet cost relative to
  VPP's userspace-crypto pipeline. VPP terminates crypto in
  userspace and avoids the underlay/inner-packet split entirely.
- Throughput goals materially exceed what the userspace AF_XDP
  backend can deliver on target hardware.
- Team is willing to own VPP integration and long-term plugin /
  API maintenance.

## Related (Active) Documents

- Active userspace dataplane design:
  [`userspace-dp/README.md`](../userspace-dp/README.md).
- Retirement umbrella: #1525.
- VPP architectural reference (kept as historical analysis, not
  current direction): [`vpp-dataplane-assessment.md`](vpp-dataplane-assessment.md).

---

## [Retired] Historical Decision

> **Retired** — preserved for reference only. The text below was
> the active decision as of 2026-03-02 when DPDK was a live
> in-tree backend candidate. It does NOT reflect current
> direction. The DPDK dataplane is retired under #1525; see the
> banner at the top of this file for the active path.

Date: 2026-03-02
Status: Active (at the time)
Scope: xpf dataplane strategy

### Decision Summary

For this project today, **DPDK is the better next dataplane path than VPP**.

Why:
- There is already a substantial in-tree DPDK dataplane (`dpdk_worker/*` + `pkg/dataplane/dpdk/*`) that mirrors xpf semantics.
- The current architecture (Go control plane + compiler + dataplane interface) already supports DPDK as a backend.
- VPP would require a large custom plugin effort to preserve xpf-specific behavior (zone policy, screen checks, HA/failover semantics), plus operational model changes.

When VPP could become better:
- If product direction prioritizes very high-end encrypted throughput (especially IPsec/WireGuard) at 40/100G scale over short-term delivery and architectural continuity.

### Current Repo Reality

#### eBPF/XDP-TC path (primary)
- Production path with broad feature coverage and HA behavior implemented around existing xpf design.

#### DPDK path (secondary backend, in-tree)
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

#### VPP path
- No in-tree VPP dataplane implementation exists.
- Existing assessment doc is extensive, but implementation would still start from zero in this repo.

### What Matters Most for xpf

1. Preserve Junos-like behavior:
- Zone-pair policy semantics, NAT behavior, screens, session model, CLI/runtime parity.

2. Preserve HA behavior:
- VRRP/RETH failover behavior, fabric forwarding logic, session sync expectations.

3. Minimize control-plane churn:
- Existing FRR/strongSwan/networkd integration is already coupled to current architecture.

4. Ship incrementally:
- Continue improving throughput/reliability without a multi-quarter rewrite.

DPDK aligns better with these constraints than VPP right now.

### Option Comparison

#### Option A: Continue DPDK backend evolution (recommended)

Pros:
- Reuses existing xpf pipeline model and compiler outputs.
- Lowest migration risk from current eBPF behavior.
- In-tree code already implemented and testable.
- Single project-owned control plane model remains intact.

Cons:
- Still custom dataplane code to maintain.
- Less built-in ecosystem than VPP for some advanced services.
- Requires finishing remaining TODOs for full parity.

Effort profile:
- Incremental and bounded; most work is finishing known TODOs and behavior parity.

#### Option B: Build VPP backend now (not recommended now)

Pros:
- Strong high-end packet processing and mature routing dataplane framework.
- Potential major upside for high-throughput encrypted workloads.

Cons:
- Large initial implementation cost in this repo.
- Would require custom logic/plugins to preserve xpf semantics.
- Operational model complexity (VPP lifecycle, Linux CP integration, API/version coupling).
- Higher risk to HA and behavior parity during migration.

Effort profile:
- Multi-phase rewrite/integration project with significant validation burden.

### Recommendation

#### Primary recommendation
- **Invest in completing and hardening the DPDK backend first.**

#### Explicit non-recommendation (for now)
- Do **not** start a full VPP dataplane migration now.

#### Revisit trigger for VPP
Re-open VPP if all are true:
- DPDK backend is functionally complete/parity-acceptable.
- Throughput goals materially exceed what eBPF+DPDK path can deliver on target hardware.
- Encrypted tunnel throughput becomes a primary product driver.
- Team is willing to own VPP integration and long-term plugin/API maintenance.

### Execution Plan (DPDK-first)

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

### Related Docs (as written 2026-03-02; some are now retired)

- DPDK architecture plan: `docs/dpdk-dataplane.md` (now retired —
  see retirement banner at top of that file).
- VPP assessment: `docs/vpp-dataplane-assessment.md` (kept as
  historical analysis; not current direction).
- Performance context: `docs/optimizations.md`.
- HA behavior context: `docs/active-active-new-connections.md`.
