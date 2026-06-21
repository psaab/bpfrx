# Userspace Dataplane: Current Capability Gate

This document tracks the current admission boundary on `master` for the Rust
AF_XDP userspace dataplane. It is not a full bug tracker and it is not a
historical branch plan. For active debugging entry points, use
[`userspace-debug-map.md`](userspace-debug-map.md).

Last updated: 2026-05-29

## Deprecation Context

Issue #1373 retired the legacy eBPF dataplane; the staged retirement is
complete. The Rust AF_XDP userspace dataplane is the only runtime forwarding
path and the effective default when `system dataplane-type` is omitted. The
#1476 source-removal phase deleted the legacy BPF source (`bpf/xdp/*.c`,
`bpf/tc/*.c`), the bpf2go bindings, and the legacy loader targets; the only
retained eBPF artifacts are the userspace XDP shim and the shared
`bpf/headers/*.h` map/struct bootstrap. Explicit `system dataplane-type ebpf`
is hard-rejected: the strict commit validator returns `ErrEBPFDataplaneRetired`
and the runtime factory returns `ErrEBPFBackendRetired`. The parser still
accepts the `ebpf` token so that `load merge`/`load override` of a
pre-retirement config does not syntax-error during a rolling upgrade, but
`commit check` then fails and the remediation is
`set system dataplane-type userspace`.

DPDK is retired (#1525). The DPDK backend, `dpdk_worker/`, and
`pkg/dataplane/dpdk/` are removed in #1527/#1528. The historical
`#1475` policy that confined DPDK's root `DataPlane` dependency to
`pkg/dataplane/dpdk` and the `cmd/xpfd/main.go` registration import
applied pre-retirement; this document focuses on the userspace
AF_XDP dataplane retirement gate, not DPDK.

## Implemented In The Current Runtime

These capabilities exist in the current Rust userspace dataplane code path:

| Feature | Current state | Notes |
|---------|---------------|-------|
| Stateful forwarding | Implemented | Per-worker sessions plus shared session tables |
| Zone + global policies | Implemented | Address and application terms are pre-expanded by the daemon |
| Policy schedulers | Implemented; live HA evidence captured | Scheduled-policy `scheduler_name` and `inactive` bits are published in userspace snapshots, old helper protocol mismatches disarm forwarding, missing policy-scheduler references are commit errors, and Rust hit counters survive active/inactive snapshot rebuilds by stable rule ID. The 2026-05-19 #1378 live artifact set is accepted by `test/incus/policy_scheduler_validate.py` for `lan->wan/scheduled-allow`. |
| Application matching | Implemented | Protocol + port terms, including expanded multi-term apps |
| Source NAT (interface mode) | Implemented | IPv4 and IPv6 egress interface rewrite |
| Source NAT (pool mode) | Implemented with scoped caveats | IPv4/IPv6 pool address and port allocation. Global `source address-persistent` uses the documented userspace-v1 SHA-256 source-IP hash and is stable only within the AF_XDP backend, pool family, pool order, and pool size. Legacy eBPF uses C-word IPv4 modulo / IPv6 lane-XOR selection (DPDK retired #1525), so new-flow pool address parity is not promised across retained backend transitions. Pool-mode rules with missing pools, empty pools, invalid port ranges, malformed addresses, no address for the packet family, or exhausted live translated tuples fail-closed at the `poll_descriptor.rs` source-NAT call sites before session creation or forwarding, with recent-exception reasons such as `source_nat_pool_missing`, `source_nat_pool_empty`, `source_nat_pool_invalid_port_range`, and `source_nat_pool_exhausted`. Per-pool `persistent-nat` now has snapshot fields and runtime lease reuse keyed by source tuple `(protocol, source IP, source port)` to translated tuple. Persistent source-NAT is a required helper-protocol gate: committing a persistent-NAT config against a helper whose `ConfigSnapshotProtocolVersion` is below the requirement disarms forwarding and ABORTS the commit (`ErrPersistentSourceNATProtocolIncompatible`, same required-gate class as the policy scheduler; #2138). An already-persisted or peer-synced persistent-NAT config is still admitted on a too-old helper (lenient-load #1960): the boot apply uses the void `applyConfig` wrapper (logs `Warn`, swallows) and the peer config-sync receiver logs `Error` and returns, both disarming the helper rather than bricking the node — only the operator-facing commit path surfaces the abort. The lease table is bounded in helper memory, survives compatible in-process snapshot refreshes, and expires after the configured inactivity timeout once no live flow uses the lease. It does not consult Go `PersistentNATTable` and does not survive helper restart. The closed #1449 contract gates HA behavior explicitly: HA configs that reference persistent source-NAT pools are not admitted because leases are not synchronized, and status reports `userspace persistent-nat source pool leases are not HA-synchronized`. Userspace status, CLI summary, and Prometheus expose live-flow, used-port, persistent-lease, allocation, reuse, and exhaustion counters for admitted non-HA pools. |
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

## Remaining Explicit Configuration Gates

These are the explicit configuration gates that still hold after the
feature-gap closeout. The earlier source-removal evidence caveats are
retrospective: the #1373 feature-gap audit (#1374-#1381) and the #1477
final-validation artifact set are closed. The explicit gates live in
[`pkg/dataplane/userspace/manager.go`](../pkg/dataplane/userspace/manager.go).

| Feature/config shape | Userspace status | Tracker / disposition |
|----------------------|-------------|--------------------|
| Unsupported policy shapes | Gated | Address/application expansion must succeed for userspace. #2124: an application term whose protocol the matcher cannot represent (sctp/esp/ah/vrrp/igmp/pim/egp now parse and are canonicalized to their IANA number; anything else, or a malformed port, is unrepresentable) fails the capability gate (`expandUserspacePolicyApplications` -> `ForwardingSupported=false`, refuse-to-arm) rather than collapsing the rule to match-any. On a failed expansion the daemon emits a reserved `__unsupported__` sentinel term so the Rust matcher rejects the whole snapshot via `SnapshotIntegrityError` (keeping the previous good state) — an action-agnostic fail-closed that never turns a permit into match-any nor a deny into a pass, closing the publish-before-disarm window. |
| Screen behavior requiring SYN cookies | Supported | Closed feature-gap (#1374); #1477 final validation closed |
| HA with per-pool source NAT `persistent-nat` | Gated | Closed/documented contract: helper-memory persistent-NAT leases are not HA-synchronized, so HA configs that reference persistent source-NAT pools are not admitted |
| Port mirroring | Supported | Closed feature-gap (#1376); #1477 final validation closed |

Port mirroring now has snapshot/wire plumbing plus a bounded runtime slice
that samples and queues discardable full-L2 mirror clones with drop counters.
Runtime coverage includes the pending-forward path, self-target flow-cache
mirror surface, deferred neighbor-resolution retry path, CoS-bound reserve
handling, and mirror-specific counter attribution. The
`deriveUserspaceCapabilities()` gate has been removed; #1376 is closed for the
feature-gap audit, and the #1477 final-validation artifact set is closed.
Any further mirror-fidelity and pressure-survival work is production hardening,
not a retirement blocker.

## Features That Still Use A Mixed Boundary

These are not "missing", but they are not pure userspace forwarding either:

| Area | Current boundary |
|------|------------------|
| SYN cookie flood protection | Userspace now publishes a snapshot key when cluster-synced root encrypted-password material exists, mints/validates cookies against the Unix wall-clock epoch, sends bounded SYN-ACK and validated-ACK RST replies through the AF_XDP TX path, and reports challenge/no-secret/SYN-ACK/ACK-RST/budget/valid/invalid/bypass counters. Active SYN-cookie screen profiles require that secret material at userspace capability admission; missing secret material also fails closed at runtime. #1374 is closed for the feature-gap audit; the final live HA/flood proof was delivered with the closed #1477 validation set. |
| Kernel-owned traffic (ARP, local delivery, management, some non-IP) | cpumap or kernel pass-through from XDP |
| GRE / ESP / explicit early filters | Live kernel-owned/tunnel-control cases use cpumap or pass-through; degraded helper/XSK states pass only proven local/control traffic and drop non-local transit |
| IPsec / XFRM handling | Userspace detects and punts to kernel/slow-path as needed |
| DataPlane control-plane contract | Userspace manager no longer embeds the legacy `dataplane.DataPlane`; a userspace `LegacyDataPlaneAdapter` owns old-interface compatibility. Operator metadata reads in API/gRPC/CLI/daemon now use `LastApplyResult()` instead of `LastCompileResult()`, with a canary preventing those surfaces from regressing to compile-result metadata. GC and HA session sync use `SessionStore`/`Telemetry`. The manager still holds a named userspace shim manager for XDP/map bootstrap state. API/gRPC/CLI session/counter readers plus daemon control paths still name root `pkg/dataplane` session/counter types (e.g. `SessionKey`, `CounterValue`); those imports are tracked as the intentional, documented allowlist in `pkg/dataplane/retirement_boundary_canary_test.go` and move to a domain package as that type-relocation work continues. This is post-retirement interface cleanup, not a retirement blocker |
| DPDK backend | Retired in #1525. The historical #1475 backend-local exception for its root `DataPlane` dependency applied pre-retirement; #1527 removes the registration import and #1528 deletes the package. |
| Dataplane event logging | Session open/close/update are emitted by userspace. Policy-deny, screen-drop, logged routing-instance filter hits, non-PBR input filter logs, output filter logs, cached output-filter hits, and lo0 filter logs now enqueue RT_FLOW frames through the non-blocking Rust event-stream producer with existing per-event rate-limit/loss accounting. Go decode/status handling feeds raw userspace RT_FLOW frames through the same `EventReader.ProcessRawEvent` syslog/local-log path as eBPF, with a deterministic UDP syslog fanout harness for policy deny, screen drop, and filter log. Policy-deny events now carry the snapshot's compiled numeric policy ID; filter-log events carry filter/term/action identity from the matched compiled term. #1379 is closed for the feature-gap audit; the final live cluster syslog proof was delivered in the closed #1477 validation set. |
| `show system buffers` | Userspace helper-status rendering covers AF_XDP UMEM/TX capacity, CoS queued-byte capacity, helper-published session-table and flow-cache capacity, active-session footer, neighbor counts, and worker queue pressure counters. The Phase 5 denominator decision is explicit: session-table and flow-cache values become fill percentages only from Rust-owned helper fields; neighbor-cache entries remain counters until Rust owns a bounded neighbor-cache capacity. Formatter tests pin that dynamic counts cannot move into the utilization table without real denominators. |

## Retirement History (closed)

The #1373 eBPF retirement is complete. This section is a record of the closed
removal phases, not pending work.

The #1374-#1381 feature-gap audit is closed. #1377 closed source-NAT pool
retirement; its SNAT follow-ups #1448, #1449, and #1450 are closed as
documented contracts: helper restart resets helper-local persistent-NAT
leases, HA configurations with persistent source-NAT pools are gated because
leases are not synchronized, and new-flow pool-address parity is not promised.

| Issue | Removal phase (closed) |
|-------|--------------------|
| #1451 | Closed the eBPF-retirement removal-phase blocker: the userspace manager no longer embeds the legacy `dataplane.DataPlane`, runtime backend selection and forwarding are off the legacy surface, and the operator surfaces moved to apply-result metadata + `SessionStore`/`Telemetry`. Remaining root `pkg/dataplane` session/counter *type* imports in API/gRPC/CLI/daemon are the documented canary allowlist (`retirement_boundary_canary_test.go`) and are post-retirement interface cleanup, not a retirement blocker. |
| #1473 / #1493 | Split shim-only generation and the userspace shim loader/bootstrap from the legacy in-kernel forwarding loader so the retained shim survives while the legacy XDP/TC programs were removed. |
| #1476 | Removed legacy BPF source, generated artifacts, and build hooks, preserving the retained AF_XDP userspace shim path. |
| #1477 | Published the final userspace-only validation artifact set (cluster, screen/flood, CoS, HA, degraded-path evidence). |

#1474 is closed: omitted `system dataplane-type` selects userspace, and
explicit `system dataplane-type ebpf` is now hard-rejected (commit-time
`ErrEBPFDataplaneRetired`, runtime `ErrEBPFBackendRetired`); the
deprecation-warning surface that preceded the hard reject is gone.

The current canonical fallback contract is in the "Actual Fallback Mechanisms"
section below, which already reflects the post-#1476 hard reject.

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
   - The Go manager chooses the userspace runtime path by default.
     Explicit legacy eBPF selection (`set system dataplane-type ebpf`)
     was retired in #1476: the strict commit validator now hard-rejects
     it with `ErrEBPFDataplaneRetired`, and the runtime factory returns
     `ErrEBPFBackendRetired`. The deprecation-warning surface that
     preceded the hard reject is gone.
   - The Go manager keeps `xdp_userspace_prog` as the userspace-mode
     XDP entry. Capability gates disarm helper forwarding rather than
     swapping userspace runtime traffic into the (now-deleted)
     `xdp_main_prog`.

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

The #1373 retirement (including the #1451 removal-phase blocker, the
#1473/#1493 userspace XDP shim split, the #1476 source removal, and the
#1477 validation artifact set) is complete. Residual root `pkg/dataplane`
session/counter *type* imports in the operator surfaces are post-retirement
interface cleanup tracked by the canary allowlist, not a retirement blocker.
The highest-value remaining work on `master` is correctness, operational
hardening, and performance optimization on the active AF_XDP userspace
forwarding path — for example CoS regression work (#1614) and cold-path
hardening (#1608).

Keep #1377, #1448, #1449, and #1450 closed. SNAT helper-restart reset
behavior, HA persistent-lease gating, and cross-backend selector divergence
remain documented userspace contract limits, not active #1373/#1451 blockers.
