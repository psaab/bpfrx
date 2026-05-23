# #1373 Retire eBPF Dataplane Blocker Plans

Status: closeout and removal-plan bundle for #1373. The original #1374-#1381
feature-gap plans are kept here as design history and documented runtime
contracts, but those feature-gap blockers are closed. Current removal work is
tracked by #1451 and the removal-phase child issues below.

## Feature Gap Closeout Index

| Issue | Plan | Retirement state | Notes |
|---|---|---|---|
| #1374 SYN cookie flood protection | [plan-1374-syn-cookies.md](plan-1374-syn-cookies.md) | Closed | Runtime challenge/ACK/cache/counters, root-auth-derived snapshot key, bounded SYN-ACK/RST TX, status counters, and gate removal landed; final source-removal evidence rolls into #1477 if required. |
| #1375 three-color policers | [plan-1375-three-color-policers.md](plan-1375-three-color-policers.md) | Closed | Color-blind `then discard` runtime plus compatible snapshot continuity landed; future hardening is production follow-up work, not an active feature-gap blocker. |
| #1376 port mirroring | [plan-1376-port-mirroring.md](plan-1376-port-mirroring.md) | Closed | Snapshot/wire plus bounded runtime admission landed; final mirror-fidelity evidence rolls into #1477 if required. |
| #1377 persistent SNAT pool address selection | [plan-1377-snat-pools.md](plan-1377-snat-pools.md) | Closed | Userspace-v1 selector, unusable-pool fail-closed runtime, helper-local persistent-NAT lease reuse, per-pool allocator sharing, and allocator counters landed. #1448, #1449, and #1450 are closed documented contracts for helper restart reset, HA admission gating, and backend-specific selector behavior. |
| #1378 policy schedulers | [plan-1378-policy-schedulers.md](plan-1378-policy-schedulers.md) | Closed | Closed by live HA artifact capture accepted by `policy_scheduler_validate.py`; no known #1378 runtime or evidence gap remains. |
| #1379 dataplane events | [plan-1379-dataplane-events.md](plan-1379-dataplane-events.md) | Closed | Policy-deny, screen-drop, PBR filter logs, non-PBR input/output/lo0 filter logs, cached input-log replay without filter rescans, source-disambiguated FILTER_LOG syslog, and deterministic fanout coverage landed. |
| #1380 userspace buffer/status parity | [plan-1380-userspace-buffers.md](plan-1380-userspace-buffers.md) | Closed | Helper-status rendering is active; Rust-owned session-table and flow-cache denominators are helper-published, while neighbor entries remain counters until Rust owns a bounded neighbor-cache capacity. |
| #1381 DataPlane split | [plan.md](plan.md) | Closed | The blocking userspace-apply/interface split closed; the broader source-removal migration continues under #1451. |

## Current Removal Work

| Issue | Scope |
|---|---|
| #1451 | Migrate remaining legacy eBPF-shaped runtime and operator surfaces before source/generated artifact deletion. |
| #1473 | Split the retained userspace XDP shim from legacy `xdp_main_prog` fallback. |
| #1493 | Split userspace shim loader/bootstrap from the legacy `loadAllObjects()` path. |
| #1494 | Pin the retained userspace shim boundary with source/object/manager canaries before source deletion. |
| #1476 | Remove legacy BPF source, generated artifacts, and build hooks after the blockers close. |
| #1477 | Publish final userspace-only validation artifacts for the exact source-removal candidate. |

#1474 is closed: omitted `system dataplane-type` selects userspace, while
explicit `system dataplane-type ebpf` remains temporary warned compatibility
until legacy source removal.

## Removal-Phase Dependency

The source-removal order is now explicit:

1. #1494 canary: merge the retained userspace XDP shim boundary canaries.
2. #1493 loader split: remove userspace startup's dependency on the legacy
   `loadAllObjects()` graph.
3. #1451 surface shrink: finish moving runtime/operator callers off the legacy
   eBPF-shaped `dataplane.DataPlane` bridge.
4. #1476 deletion: remove legacy source, generated artifacts, and stale build
   hooks using [source-removal-manifest-1476.md](source-removal-manifest-1476.md).
5. #1477 final evidence: publish validation artifacts for the exact deletion
   candidate.

#1451 remains the common migration umbrella. The userspace manager no longer
embeds the old `DataPlane` interface directly, and a userspace legacy adapter
owns the compatibility boundary while unmigrated callers move to domain
interfaces. #1380 is a Phase 5 CLI/observability cleanup item, now closed for
the current helper schema; it does not block the source-removal gate by itself.

## #1451 Runtime Boundary Canaries

`pkg/dataplane/retirement_boundary_canary_test.go` pins the current retirement
boundary for #1451. It discovers every top-level `cmd/*` and `pkg/*`
production Go package except `pkg/dataplane` itself, then fails if a new direct
`github.com/psaab/xpf/pkg/dataplane` import appears outside the allowlist below,
or if a listed bridge disappears without shrinking this documentation.

The same canary also keeps operator packages away from direct BPF artifacts:
they may not import `github.com/cilium/ebpf`, and the DPDK backend import stays
limited to `cmd/xpfd/main.go` for backend registration. Daemon startup must keep
owning `dataplane.RuntimeDataPlane` and must call
`dataplane.NewRuntimeDataPlane`, not `dataplane.NewDataPlane`. This is a
production-code canary; `_test.go` files may still import lower-level helpers
when they need backend fixtures for regression coverage.

## #1475 DPDK Backend Policy

DPDK remains a separately supported backend for DPDK-specific binaries, but it
is explicitly outside the eBPF source-removal path until it migrates off the
root `DataPlane` interface. The current DPDK implementation still satisfies
both `dataplane.DataPlane` and `dataplane.RuntimeDataPlane`; that is a
backend-local compatibility exception, not a reason for userspace retirement
work to grow new dependencies on the legacy BPF-shaped surface.

The allowed production boundary is narrow:

- `pkg/dataplane/dpdk` may import root `pkg/dataplane` types and helpers while
  it owns the DPDK compatibility bridge.
- `cmd/xpfd/main.go` may keep the blank DPDK import for backend registration.
- No other production `cmd/*` or `pkg/*` package may import
  `pkg/dataplane/dpdk`.
- The only allowed DPDK import of `github.com/cilium/ebpf` is the existing
  `pkg/dataplane/dpdk/manager.go` adapter for the legacy `Map(string)
  *ebpf.Map` method. Adding more eBPF artifact imports to DPDK requires an
  explicit backend-policy update.

The default non-DPDK build keeps the package present so registration and tests
compile, but `system dataplane-type dpdk` does not silently start a stub
dataplane: `pkg/dataplane/dpdk` returns a clear startup error unless the daemon
binary was built with `-tags dpdk` and libdpdk support. Config validation still
accepts `dpdk` as a valid backend name and rejects unknown backend names before
daemon startup.

The #1475 canaries in `pkg/dataplane/retirement_boundary_canary_test.go` enforce
the import boundary above and require this policy text to stay present. DPDK
builds remain blocked on migrating away from root `DataPlane`; userspace-only
production source removal must not depend on solving that DPDK migration in the
same PR.

## #1473 Userspace XDP Shim Build Split

The retained Rust userspace XDP shim is still required for the AF_XDP userspace
runtime, but its generation path is now explicit and separate from the legacy
XDP/TC dataplane bpf2go batch:

- `make generate-userspace-xdp` rebuilds only
  `pkg/dataplane/userspace_xdp_bpfel.o` through the
  `pkg/dataplane/build-userspace-xdp.sh` go:generate directive.
- `make build-userspace-xdp` is an alias for the shim-only generation target.
- `make generate` remains the full compatibility target: legacy XDP/TC bpf2go
  artifacts plus the retained userspace shim.
- `make generate-legacy-bpf` regenerates legacy XDP/TC bpf2go artifacts while
  skipping the retained shim.

The userspace shim target must not depend on legacy `xdp_main` or TC program
generation. `pkg/dataplane/retirement_boundary_canary_test.go` reads the
Makefile and fails if `generate-userspace-xdp` gains legacy bpf2go tokens,
recursive Make dependencies, or the broad `./pkg/dataplane/...` generate path.
This keeps the retained shim visible without implying that deleting legacy
dataplane program generation is blocked by the shim itself.

## #1493 Userspace Shim Loader Split

Normal AF_XDP userspace startup now enters `LoadUserspaceShim()` and
`CompileUserspaceShim()` instead of the legacy `Manager.Load()` /
`loadAllObjects()` path. The shim loader loads only the retained Rust
`xdp_userspace_prog` object plus explicit pinned compatibility maps used by the
userspace runtime and old operational bridges: `userspace_*`, `dnat_table`,
`dnat_table_v6`, `sessions`, `sessions_v6`, FIB/HA/fabric maps,
`session_id_gen`, and telemetry counter maps. It does not load
`xdp_main_prog`, legacy XDP tail-call programs, TC programs, `xdp_progs`, or
`tc_progs`.

The shim keeps `dnat_table` and `dnat_table_v6` at the legacy 10M-entry,
`BPF_F_NO_PREALLOC` contract so a legacy-to-shim restart can reuse existing
pins instead of silently wiping active SNAT-return state. If any required
compatibility map is incompatible, the shim loader fails closed with the
offending pin path and does not mutate pinned state; the operator must run an
explicit teardown or migration outside normal startup. The operator runbook is
[`docs/operations/userspace-shim-pin-recovery.md`](../../operations/userspace-shim-pin-recovery.md):
drain traffic, stop `xpfd`, inspect the pinned map, remove only the
incompatible pin path named in the error, restart `xpfd`, and verify the map was
recreated. Removing a stateful compatibility pin resets that map's dataplane
state, so the loader never retries by deleting a map pin or the whole BPF pin
tree. During userspace shim compile, any pinned legacy `tc_*` links are detached
and unpinned before the retained XDP shim is attached; TC programs are not part
of the userspace runtime and must not survive as stale egress hooks from a
previous legacy boot. Legacy-only map pins (`xdp_progs`, `tc_progs`, and
`policer_states`) are removed during userspace shim startup, while compatibility
stateful maps such as `sessions`, `sessions_v6`, `dnat_table`, and
`dnat_table_v6` are preserved.

The remaining compatibility bridge is config compilation metadata and Linux
interface setup: userspace still runs the shared config compiler, but through a
shim compile adapter that no-ops legacy dataplane map writes and attaches only
the userspace XDP shim. Legacy direct callers outside the runtime adapter remain
tracked under #1451.

### Allowlisted Legacy Bridges

These files are the current production direct-import allowlist for root
`pkg/dataplane`. New migration PRs should remove entries from this table as
surfaces move to domain interfaces such as `RuntimeDataPlane`, `SessionStore`,
`Telemetry`, or package-local accessor interfaces. Adding a new entry means
#1451 is moving backward and requires an explicit design reason.

| File | Current blocker |
|---|---|
| `cmd/xpfd/main.go` | Backend selection, cleanup, and backend registration still cross the root package. |
| `pkg/api/handlers.go` | REST handlers still reference legacy dataplane counters and types. |
| `pkg/api/handlers_sessions.go` | REST session reads still use legacy session types. |
| `pkg/api/metrics.go` | Prometheus telemetry still reads legacy counters and metadata. |
| `pkg/cli/cli.go` | Embedded CLI construction still stores the legacy bridge. |
| `pkg/cli/cli_clear.go` | Clear commands still delete legacy session entries. |
| `pkg/cli/cli_show_flow.go` | Flow display still uses legacy session keys and values. |
| `pkg/cli/cli_show_nat.go` | NAT display still uses legacy NAT/session metadata. |
| `pkg/cli/cli_show_security.go` | Security display still uses legacy counters and filter types. |
| `pkg/cluster/sync.go` | Session sync still installs sessions through the legacy bridge. |
| `pkg/cluster/sync_bulk.go` | Bulk sync still serializes legacy session entries. |
| `pkg/cluster/sync_conn.go` | Sync connection code still references legacy session types. |
| `pkg/cluster/sync_protocol.go` | Wire protocol still carries legacy session records. |
| `pkg/conntrack/gc.go` | GC compatibility construction still adapts legacy sessions. |
| `pkg/daemon/daemon.go` | Daemon owns `RuntimeDataPlane` and exposes `legacyDP()` for unmigrated callers. |
| `pkg/daemon/daemon_apply.go` | Apply path still adapts legacy compile/apply metadata. |
| `pkg/daemon/daemon_flow.go` | Flow logging still formats legacy dataplane counters. |
| `pkg/daemon/daemon_ha.go` | HA state updates still call legacy bridge methods. |
| `pkg/daemon/daemon_ha_fabric.go` | Fabric HA updates still call legacy bridge methods. |
| `pkg/daemon/daemon_ha_userspace.go` | Userspace HA control still crosses the legacy bridge. |
| `pkg/daemon/daemon_run.go` | Runtime wiring still passes `legacyDP()` to unmigrated services. |
| `pkg/grpcapi/apply_result.go` | gRPC apply metadata still adapts legacy apply results. |
| `pkg/grpcapi/server.go` | gRPC server construction still stores the legacy bridge. |
| `pkg/grpcapi/server_helpers.go` | gRPC helpers still format legacy dataplane types and bridge runtime accessors. |
| `pkg/grpcapi/server_sessions.go` | gRPC session RPCs still use legacy session types. |
| `pkg/grpcapi/server_show.go` | gRPC show dispatcher still reaches legacy dataplane state. |
| `pkg/grpcapi/server_show_cluster_text.go` | Cluster text output still reads legacy dataplane state. |
| `pkg/grpcapi/server_show_flow.go` | Flow text output still uses legacy session keys and values. |
| `pkg/grpcapi/server_show_nat.go` | NAT text output still uses legacy NAT/session metadata. |
| `pkg/grpcapi/server_show_policies_text.go` | Policy text output still uses legacy counters. |
| `pkg/grpcapi/server_show_security_text.go` | Security text output still uses legacy counters and filter types. |
| `pkg/grpcapi/server_show_status.go` | Status output still reads legacy dataplane state. |
| `pkg/grpcapi/server_show_zones.go` | Zone output still uses legacy dataplane types. |
| `pkg/logging/ringbuf.go` | Event reader still consumes the legacy `EventSource`. |

### Safe-Delete Blockers

- `pkg/dataplane.DataPlane` is still load-bearing for API, gRPC, CLI, status,
  logging, cluster session sync, conntrack GC, daemon HA, daemon flow, and
  daemon apply bridges listed above. `pkg/monitoriface` now uses a
  package-local `RuntimeDataPlane`/`CounterReader` shape; CLI and gRPC adapt
  their wider dataplane fields before entering the monitor-interface package.
- Omitted `system dataplane-type` now resolves to the userspace runtime path.
  Explicit `system dataplane-type ebpf` remains available only as a temporary
  compatibility setting until source removal, and config compile emits a
  deprecation warning when it is selected.
- `pkg/dataplane/userspace.LegacyDataPlaneAdapter` is still required because
  userspace runtime construction returns a legacy-compatible adapter while
  unmigrated operator services consume old session, telemetry, and control
  methods. The userspace `Manager` itself must not implement `DataPlane`.
- DPDK still implements both `DataPlane` and `RuntimeDataPlane`. That
  compatibility is intentionally confined to `pkg/dataplane/dpdk`, with the
  only direct DPDK backend import outside the package being the blank
  registration import in `cmd/xpfd/main.go`. Non-`-tags dpdk` binaries fail
  DPDK startup explicitly rather than running a no-op stub.
- Legacy BPF source and generated artifacts are not safe to delete in #1451
  canary work: `bpf/`, `pkg/dataplane/*_bpfel.go`,
  `pkg/dataplane/*_bpfel.o`, and the legacy side of the `Makefile generate`
  path remain tied to the explicit eBPF backend until #1476 removes that
  backend source. They are no longer required by normal userspace startup.
- Retained userspace XDP shim artifacts are tracked separately:
  `pkg/dataplane/userspace_xdp_bpfel.o` and
  `pkg/dataplane/build-userspace-xdp.sh` remain required for userspace runtime
  startup, but `make generate-userspace-xdp` rebuilds them without legacy
  `xdp_main` or TC dataplane program generation.

## Phase 1/2 Smoke Gates

Use [smoke-gates.md](smoke-gates.md) for the repeatable Phase 1/2 operator
checklist: CoS-off IPv4/IPv6 push and reverse, screen/flood baseline,
CoS-on 5200..5211 class sweeps, 6200..6211 TCP echo probes, and the
existing HA Makefile gates.

## #1477 Final Artifact Contract

Use [final-validation/README.md](final-validation/README.md) for the final
source-removal candidate artifact layout. The structural checker at
`test/incus/retire_ebpf_artifact_schema.py` verifies that the evidence bundle is
complete, consistently named, and tied to the exact 40-character candidate SHA;
it does not replace live-result review.

## Shared Non-Goals

- Do not remove `bpf/` in these blocker implementation PRs; that remains #1373
  Phase 4.
- Do not rewrite unrelated dataplane behavior while adding parity for the
  missing features.
- Do not use the DPDK worker as a correctness reference when it conflicts with
  the reviewed userspace-dp contract.
