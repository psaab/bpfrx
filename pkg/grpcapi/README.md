# pkg/grpcapi

gRPC server. Implements ~48 RPCs spanning config lifecycle (enter, set,
delete, commit, rollback, history), operational queries (sessions,
routes, NAT, IPsec, DHCP, VRRP, …), diagnostics (ping, traceroute as
server-streaming), monitoring (drops, interface), mutations (clear), and
tab completion. The wire schema is `proto/xpf/v1`.

## Entry points

- `Server` — `server.go`.
- `Config` — `server.go`. Dependency injection point.
- `NewServer(addr string, cfg Config) *Server` — `server.go`.
- `Run(ctx context.Context) error` — `server.go`. Starts the listener
  and blocks until the context is cancelled.
- Tab completion: `Complete` RPC, backed by `pkg/cmdtree`.

## Callers

`cmd/xpfd` (instantiates and runs); `cmd/cli` (consumes); HTTP REST
bridge in `pkg/api`.

## Dependencies

`cluster`, `config`, `configstore`, `conntrack`, `dataplane`, `dhcp`,
`dhcpserver`, `feeds`, `frr`, `ipsec`, `logging`, `fwdstatus`, `ra`,
`routing`, `rpm`, `vrrp`, plus most of the rest of `pkg/`.

The dataplane dependency is intentionally narrow: `Config.DP` and
`Server.dp` are typed against the unexported `grpcRuntime`
interface declared in `runtime.go`, **not** the full
`dataplane.DataPlane`. `grpcRuntime` lists exactly the methods the
gRPC handlers invoke via `s.dp.*` (counters, session-read,
session-clear, map-stats, persistent-NAT) and is a strict subset
of `dataplane.DataPlane`, so any concrete dataplane that satisfies
the legacy interface also satisfies `grpcRuntime`. The userspace-
specific provider capabilities (`Status`, `SetForwardingArmed`,
`SetQueueState`, `SetBindingState`, `InjectPacket`) live on named
provider interfaces (`userspaceStatusProvider`,
`userspaceControlProvider`) in the same file; the gRPC server
probes them via type assertion on `s.dp`. Cursor-based session
pagination uses the `sessionCursorIterator` probe, also in
`runtime.go`. This is the boundary that the #1373 eBPF retirement
narrows; see `docs/pr/1373-retire-ebpf-dataplane/README.md` and
`docs/pr/1516-grpcapi-migration/plan.md` for the migration
contract.

## Gotchas

- Configure mode is **exclusive on the secondary node** in cluster mode.
  Primary (RG0 master) is the config authority; the secondary rejects
  `EnterConfigure` until it's promoted.
- `peerSessionID()` is extracted from the gRPC peer credentials and used
  to distinguish exclusive vs. shared configure sessions. A session ID is
  required for any commit.
- `CommitFn` (passed in by the daemon) holds the apply semaphore across
  `Commit()` and the dataplane apply. This is the same primitive `pkg/cli`
  uses; concurrent operator commits serialize via that semaphore (#846).
- Tab completion (`Complete` RPC) and `?` help come from `pkg/cmdtree` —
  add commands there once and they show up in every CLI surface.
- Server-streaming RPCs (Ping, Traceroute, MonitorPacketDrop,
  MonitorInterface) must drain on client disconnect; cancel the context
  to free buffered output.
