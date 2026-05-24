# Userspace Dataplane: Current Capability Gate

This document tracks the current admission boundary on `master` for the Rust
AF_XDP userspace dataplane. It is not a full bug tracker and it is not a
historical branch plan. For active debugging entry points, use
[`userspace-debug-map.md`](userspace-debug-map.md).

Last updated: 2026-05-22

## Deprecation Context

Issue #1373 retires the legacy eBPF dataplane in staged phases. The Rust
AF_XDP userspace dataplane is now the effective runtime default when
`system dataplane-type` is omitted, and it remains the primary target for
dataplane development and routine validation. No BPF source, bpf2go bindings,
loader code, test targets, or CLI surfaces are removed in this phase. The
legacy eBPF dataplane remains present only for explicit compatibility and
regression use while the source-removal blockers close. Explicit
`system dataplane-type ebpf` is accepted only with a compile warning; it is not
the omitted/default dataplane path.

DPDK is not part of the userspace retirement path. It remains a separately
supported DPDK-build backend, but #1475 confines its root `DataPlane`
dependency to `pkg/dataplane/dpdk` and the `cmd/xpfd/main.go` registration
import until that backend gets its own migration off the legacy interface.
Non-`-tags dpdk` binaries reject DPDK startup explicitly instead of admitting a
no-op stub dataplane.

## Implemented In The Current Runtime

These capabilities exist in the current Rust userspace dataplane code path:

| Feature | Current state | Notes |
|---------|---------------|-------|
| Stateful forwarding | Implemented | Per-worker sessions plus shared session tables |
| Zone + global policies | Implemented | Address and application terms are pre-expanded by the daemon |
| Policy schedulers | Implemented; live HA evidence captured | Scheduled-policy `scheduler_name` and `inactive` bits are published in userspace snapshots, old helper protocol mismatches disarm forwarding, missing policy-scheduler references are commit errors, and Rust hit counters survive active/inactive snapshot rebuilds by stable rule ID. The 2026-05-19 #1378 live artifact set is accepted by `test/incus/policy_scheduler_validate.py` for `lan->wan/scheduled-allow`. |
| Application matching | Implemented | Protocol + port terms, including expanded multi-term apps |
| Source NAT (interface mode) | Implemented | IPv4 and IPv6 egress interface rewrite |
| Source NAT (pool mode) | Implemented with scoped caveats | IPv4/IPv6 pool address and port allocation. Global `source address-persistent` uses the documented userspace-v1 SHA-256 source-IP hash and is stable only within the AF_XDP backend, pool family, pool order, and pool size. Legacy eBPF and current DPDK use C-word IPv4 modulo / IPv6 lane-XOR selection, so new-flow pool address parity is not promised across retained backend transitions. Pool-mode rules with missing pools, empty pools, invalid port ranges, malformed addresses, no address for the packet family, or exhausted live translated tuples fail closed at the `poll_descriptor.rs` source-NAT call sites before session creation or forwarding, with recent-exception reasons such as `source_nat_pool_missing`, `source_nat_pool_empty`, `source_nat_pool_invalid_port_range`, and `source_nat_pool_exhausted`. Per-pool `persistent-nat` now has snapshot fields and runtime lease reuse keyed by source tuple `(protocol, source IP, source port)` to translated tuple. The lease table is bounded in helper memory, survives compatible in-process snapshot refreshes, and expires after the configured inactivity timeout once no live flow uses the lease. It does not consult Go `PersistentNATTable` and does not survive helper restart. The closed #1449 contract gates HA behavior explicitly: HA configs that reference persistent source-NAT pools are not admitted because leases are not synchronized, and status reports `userspace persistent-nat source pool leases are not HA-synchronized`. Userspace status, CLI summary, and Prometheus expose live-flow, used-port, persistent-lease, allocation, reuse, and exhaustion counters for admitted non-HA pools. |
| Destination NAT | Implemented | Pre-expanded tuple snapshots from Go |
| Static NAT | Implemented | Bidirectional 1:1 translation |
| NAT64 | Implemented | Forward and reverse translation with reverse-session state |
| NPTv6 | Implemented | Stateless prefix translation |
| Firewall filters | Implemented | Filter snapshots and evaluation in Rust |
| Flow export | Implemented | Userspace flow export snapshot and runtime |
| Three-color policers | Implemented with caveats | srTCM/trTCM runtime, forwarding-path and flow-cache-hit metering, red drops for `then discard`, status/CLI/Prometheus counters, and compatible in-process snapshot continuity. Unsupported color-aware, non-`discard`, and malformed snapshots now fail closed in Rust if they bypass Go admission. Sharded state, HA/restart continuity decision, full non-drop action propagation, and integration evidence remain production hardening work, not active feature-gap blockers. |
| TCP MSS clamping | Implemented | Flow snapshot fields are delivered and used in Rust |
| Embedded ICMP NAT reversal | Implemented | Includes reverse-session repair paths |
| Configurable session timeouts | Implemented | Snapshot-driven timeouts in `session.rs` |
| VLAN handling | Implemented | Ingress VLAN tracking and egress tagging |
| Route and neighbor lookup | Implemented | Per-table routes, neighbor cache, next-table support |
| HA state ingestion | Implemented | Helper receives RG active/watchdog state |
| Session delta export | Implemented | Rust helper exports open/close deltas back to Go |

## Gated Or Evidence-Only Before BPF Source Removal

These are the remaining explicit configuration gates, plus the runtime-admitted
features that still need operator evidence before BPF source removal. The
explicit gates live in
[`pkg/dataplane/userspace/manager.go`](../pkg/dataplane/userspace/manager.go).

| Feature/config shape | Userspace status | Tracker / disposition |
|----------------------|-------------|--------------------|
| Unsupported policy shapes | Gated | Address/application expansion must succeed for userspace |
| Screen behavior requiring SYN cookies | Supported; final source-removal evidence, if required, belongs with #1477 | Closed feature-gap; #1477 final validation |
| HA with per-pool source NAT `persistent-nat` | Gated | Closed/documented contract: helper-memory persistent-NAT leases are not HA-synchronized, so HA configs that reference persistent source-NAT pools are not admitted |
| Port mirroring | Supported; final source-removal evidence, if required, belongs with #1477 | Closed feature-gap; #1477 final validation |

Port mirroring now has snapshot/wire plumbing plus a bounded runtime slice
that samples and queues discardable full-L2 mirror clones with drop counters.
Runtime coverage includes the pending-forward path, self-target flow-cache
mirror surface, deferred neighbor-resolution retry path, CoS-bound reserve
handling, and mirror-specific counter attribution. The
`deriveUserspaceCapabilities()` gate has been removed; #1376 is closed for the
feature-gap audit. If source removal needs final mirror-fidelity and
pressure-survival artifacts, they belong with the #1477 validation set for the
exact removal candidate.

## Features That Still Use A Mixed Boundary

These are not "missing", but they are not pure userspace forwarding either:

| Area | Current boundary |
|------|------------------|
| SYN cookie flood protection | Userspace now publishes a snapshot key when cluster-synced root encrypted-password material exists, mints/validates cookies against the Unix wall-clock epoch, sends bounded SYN-ACK and validated-ACK RST replies through the AF_XDP TX path, and reports challenge/no-secret/SYN-ACK/ACK-RST/budget/valid/invalid/bypass counters. Active SYN-cookie screen profiles require that secret material at userspace capability admission; missing secret material also fails closed at runtime. #1374 is closed for the feature-gap audit; any final live HA/flood proof belongs with #1477. |
| Kernel-owned traffic (ARP, local delivery, management, some non-IP) | cpumap or kernel pass-through from XDP |
| GRE / ESP / explicit early filters | Live kernel-owned/tunnel-control cases use cpumap or pass-through; degraded helper/XSK states pass only proven local/control traffic and drop non-local transit |
| IPsec / XFRM handling | Userspace detects and punts to kernel/slow-path as needed |
| DataPlane control-plane contract | Userspace manager no longer embeds the legacy `dataplane.DataPlane`; a userspace `LegacyDataPlaneAdapter` owns old-interface compatibility while callers migrate. Operator metadata reads in API/gRPC/CLI/daemon now use `LastApplyResult()` instead of `LastCompileResult()`, with a canary preventing those surfaces from regressing to compile-result metadata. GC and HA session sync now use `SessionStore`/`Telemetry`. The manager still holds a named eBPF shim manager for XDP/map bootstrap state, and API/gRPC/CLI session/counter readers plus daemon control paths still need to move fully to domain interfaces; tracked by the #1451 removal-phase migration |
| DPDK backend | Separately supported backend outside userspace source-removal scope. Its current root `DataPlane` dependency is pinned as a backend-local #1475 exception until DPDK migrates to runtime/domain interfaces or gets a separate retirement decision. |
| Dataplane event logging | Session open/close/update are emitted by userspace. Policy-deny, screen-drop, logged routing-instance filter hits, non-PBR input filter logs, output filter logs, cached output-filter hits, and lo0 filter logs now enqueue RT_FLOW frames through the non-blocking Rust event-stream producer with existing per-event rate-limit/loss accounting. Go decode/status handling feeds raw userspace RT_FLOW frames through the same `EventReader.ProcessRawEvent` syslog/local-log path as eBPF, with a deterministic UDP syslog fanout harness for policy deny, screen drop, and filter log. Policy-deny events now carry the snapshot's compiled numeric policy ID; filter-log events carry filter/term/action identity from the matched compiled term. #1379 is closed for the feature-gap audit; any final live cluster syslog proof belongs with #1477 if the source-removal candidate requires it. |
| `show system buffers` | Userspace helper-status rendering covers AF_XDP UMEM/TX capacity, CoS queued-byte capacity, helper-published session-table and flow-cache capacity, active-session footer, neighbor counts, and worker queue pressure counters. The Phase 5 denominator decision is explicit: session-table and flow-cache values become fill percentages only from Rust-owned helper fields; neighbor-cache entries remain counters until Rust owns a bounded neighbor-cache capacity. Formatter tests pin that dynamic counts cannot move into the utilization table without real denominators. |

## Current Retirement Work After Feature-Gap Closeout

The original #1374-#1381 feature-gap audit is closed. The remaining #1373 work
is no longer "implement missing userspace feature parity"; it is the removal
phase that migrates or deletes the legacy eBPF runtime surfaces safely.

#1377 is also closed for source-NAT pool retirement. Its SNAT follow-ups
#1448, #1449, and #1450 are closed as documented contracts: helper restart
resets helper-local persistent-NAT leases, HA configurations with persistent
source-NAT pools are gated because leases are not synchronized, and new-flow
pool-address parity is not promised across retained backend changes.

The current tracked removal work is:

| Issue | Removal-phase role |
|-------|--------------------|
| #1451 | Migrate remaining API, gRPC, CLI, status, metrics, session, GC, cluster, daemon-control, and userspace shim callers away from the legacy eBPF-shaped `dataplane.DataPlane` surface before deleting source/generated artifacts. |
| #1473 / #1493 | Runtime fallback, shim-only generation, and userspace shim loader/bootstrap are split from legacy `xdp_main_prog` / `loadAllObjects()` so the retained shim can remain while legacy XDP/TC programs are removed. |
| #1476 | Remove legacy BPF source, generated artifacts, and build hooks after the migration blockers close, while preserving the retained AF_XDP userspace shim path. |
| #1477 | Publish final userspace-only validation artifacts for the exact source-removal candidate, including cluster, screen/flood, CoS, HA, and fallback-proof evidence. |

#1474 is closed: omitted `system dataplane-type` selects userspace, and
explicit `system dataplane-type ebpf` emits an operator-visible compile warning
while legacy source removal is staged.

Recommended dependency order:

1. #1451 first, because it defines the runtime and operator interface boundary
   that every source-removal slice depends on.
2. Keep the #1473/#1493/#1494 retained-shim boundary pinned while #1451
   finishes moving remaining runtime/operator surfaces off legacy bridges.
3. #1476 after #1451 and #1473 close, as the auditable source/generated-artifact
   removal PR.
4. #1477 on the exact #1476 candidate, so the final validation artifacts match
   the code that removes the legacy eBPF path.

## What This Document Does Not Mean

A feature being "implemented" here means the runtime has code for it. It does
not guarantee:

- that every configuration shape using the feature is currently admitted
- that every path is already hardened for HA failover
- that current performance is at parity with the legacy dataplane
- that there are no active correctness bugs in the forwarding path

Those are separate questions. Use:

- [`userspace-ha-validation.md`](userspace-ha-validation.md)
- [`userspace-perf-compare.md`](userspace-perf-compare.md)
- [`userspace-debug-map.md`](userspace-debug-map.md)

## Actual Fallback Mechanisms

There are two distinct fallback boundaries:

1. **Compile-time / reconcile-time gate**
   - The Go manager chooses the userspace runtime path by default. Explicit
     legacy eBPF selection can still use `xdp_main_prog` while #1373 source
     removal is staged, but config compile emits a deprecation warning for
     that explicit selection.
   - The Go manager keeps `xdp_userspace_prog` as the userspace-mode
     XDP entry. Capability gates disarm helper forwarding rather than
     swapping userspace runtime traffic into `xdp_main_prog`.

2. **Runtime XDP decision**
   - Even when `xdp_userspace_prog` is active, the XDP shim can still:
     - redirect to AF_XDP
     - send kernel-owned traffic to cpumap / kernel
     - pass proven local/control traffic while helper/XSK is degraded
     - drop degraded non-local transit in both compat and strict modes
     - count those drops as `transit_drop` in `degraded_path_counters`; the
       pinned BPF map keeps the internal compatibility name
       `userspace_fallback_stats` until the mixed-version boundary is retired

## Priority Work

The highest-value remaining work on current `master` is:

1. complete #1451's runtime-surface migration so source removal no longer
   depends on legacy `dataplane.DataPlane` callers.
2. complete #1473's userspace XDP shim split.
3. land #1476 only after those blockers close, then attach the #1477
   userspace-only validation artifact set to the exact source-removal
   candidate.
4. continue correctness and performance hardening on the active AF_XDP fast path

Keep #1377, #1448, #1449, and #1450 closed. SNAT helper-restart reset
behavior, HA persistent-lease gating, and cross-backend selector divergence
remain documented userspace contract limits, not active #1373/#1451 blockers.
