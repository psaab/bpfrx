# pkg/dataplane

> Deprecation notice (#1373): the legacy eBPF backend in this package is being
> retired in favor of the Rust AF_XDP userspace dataplane. Phase 1 updates
> active docs and migration targeting only; no BPF source, loader code, or
> bindings are removed in this phase.

Abstract dataplane interface plus the legacy eBPF backend. Compiles the typed
config from `pkg/config` into BPF-map entries (zones, policies, NAT,
filters, applications), attaches the 14 BPF programs (9 XDP + 5 TC), and
exposes session iteration to GC, the CLI, and the metrics surface.

Pluggable: eBPF/DPDK legacy backends register through `RegisterBackend` for
the old `DataPlane` surface. Runtime backends register through
`RegisterRuntimeBackend`; the daemon uses `NewRuntimeDataPlane` so userspace
AF_XDP starts through the runtime path. During the #1381 migration, the
userspace runtime constructor returns `LegacyDataPlaneAdapter`: the userspace
`Manager` itself still does not implement the BPF-shaped `DataPlane`, but
daemon status, CLI, and cluster-sync callers that have not moved to domain
interfaces still receive a temporary compatibility handle.

The userspace backend's status wire format is mirrored here for CLI/API
consumers. CoS queue status includes queue-scoped drain-phase counters so
operators can separate guarantee bytes, surplus bytes, and non-exact bytes
sent while exact queues were still backlogged.

## Entry points

- `DataPlane` — `dataplane.go`. Legacy BPF-shaped interface kept for the
  eBPF/DPDK compiler and compatibility adapters. New daemon-facing code should
  not add methods here.
- `RuntimeDataPlane`, `ConfigSink`, `SessionStore`, `Telemetry`,
  `HAController`, and `LinkController` — `apply.go` and `session_store.go`.
  These are the split-domain interfaces used by daemon startup and runtime
  subsystems. `ConfigSink.ApplyConfig` is the daemon's apply-time
  compile/config entry point; userspace AF_XDP does not need to implement the
  legacy BPF-shaped `Compile` method just to receive committed config.
- `NewRuntimeDataPlane(dpType)` — `dataplane.go`. Runtime-domain constructor
  used by `pkg/daemon`; userspace registers only on this path. The current
  userspace constructor returns a compatibility adapter around `*userspace.Manager`
  until the remaining status/session-sync callers stop requiring `DataPlane`.
- `Manager` — `loader.go`. eBPF implementation.
- `New() *Manager` — `loader.go`.
- `Compile(cfg *config.Config) (*CompileResult, error)` — multi-phase
  lowering to BPF map entries. Phases live in `compiler.go`: zone IDs,
  screen profile IDs, zones, address book, applications, policies,
  NAT, static NAT, NAT64 prefixes, NPTv6, screen profiles, default
  policy, flow timeouts, firewall filters, flow config, port
  mirroring.
- `CompileResult` — `compiler.go`. Zone/policy/NAT/app IDs, compiled
  policy-scheduler rule slots, and the per-interface networkd configs.
- Session iteration: `IterateSessions`, `BatchIterateSessions`,
  `IterateSessionsV6`, `BatchIterateSessionsV6`.
- Session domain adapters: `SessionStoreOf`, `TelemetryOf`, and
  `NewDataPlaneSessionStore`. The generic `DataPlane` adapter preserves the
  batch-iteration fast path and centralizes cluster/GC companion ownership:
  cluster-synced forward installs create reverse and DNAT companions and roll
  back session writes if companion creation fails. Iteration callers that
  already have the session value must delete through `DeleteKnown*` or
  `DeleteBatchKnown*` so reverse/DNAT cleanup uses the authoritative
  iterator value, preserves persistent-NAT bindings, and keeps the batched
  map-delete fast path. `DeleteWithCompanions*` is retained for key-only
  HA delete messages.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/api`, `pkg/grpcapi`, `pkg/conntrack`.

## Dependencies

`appid`, `config`, `networkd`.

## BPF verifier and kernel constraints

These are the project's recurring traps. Read CLAUDE.md for the
authoritative list; quick recap:

- Branch merges lose packet range — re-read `ctx->data` / `ctx->data_end`
  after any branch.
- 512-byte combined stack across call frames — push large locals into
  scratch maps; mark big helpers `__noinline`.
- Variable-offset packet pointers lose range when `var_off` is wide
  (0xffff). Use a constant offset from a validated pointer.
- Mask `meta->l3_offset` (u16) with `& 0x3F` before packet-pointer
  arithmetic so the verifier can track the range (commit `66833c5`).
- `__u16` causes sign-extension (`smin=-32768`) — fails for packet-pointer
  math.
- Pointer bitwise OR is rejected (`if (sv4 || sv6)` where both are
  pointers triggers a compiler `|=` on pointer registers). Use separate
  null checks.
- xdp_zone fails the verifier on kernel 6.12 (NAT64 complexity); passes
  on 6.18+.

## SR-IOV / driver constraints

- iavf (VF) has no native XDP — generic mode only, ~16% CPU loss.
  i40e/ice on the PF have native XDP.
- `bpf_redirect_map` requires `ndo_xdp_xmit` on the target. Mixing native
  + generic interfaces in a redirect set silently drops.
- Workaround: per-interface `redirect_capable` flag in `bpf/xdp/xdp_forward.c`.
  Non-native interfaces fall back to `XDP_PASS` (kernel forwarding).
- The lab uses PF passthrough (i40e) on the WAN interface; all other
  interfaces are virtio with native XDP. Per-VF passthrough would need
  generic XDP and hit the iavf cliff.

## Byte order

Use `binary.NativeEndian.Uint32(ip4)` for `__be32` BPF fields, **not**
`BigEndian`. cilium/ebpf serializes map values in native endian; the IP
bytes are already in network order on the wire.
