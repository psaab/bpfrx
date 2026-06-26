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
- Session show and clear share ONE matcher: `ClearSessions` builds the
  same `sessionFilter` (`buildSessionFilter` + `matchV4/matchV6`) the
  `GetSessions` path uses (#1827 PR-3). Do not add a filter dimension
  to one path only — and remember key ports are network byte order
  (`ntohs` before comparing) and unresolvable zone/pool names must
  fail the RPC, not silently widen/void the clear. The
  `source-nat-pool` filter matches the TRANSLATED source
  (`SessFlagSNAT` + `NATSrcIP` in the pool's address set via
  `config.SourceNATPoolNets`).
- `MatchPolicies` is a THIN adapter over the single shared policy simulator
  `pkg/policymatch` (#3042) — the same matcher the REST `/security/match`
  handler and the CLI `show security match-policies` / `test policy` commands
  use. It validates inputs, then delegates to `policymatch.Match`, which
  replicates the runtime evaluator (zone-pair → global → configured
  `default-policy`, predefined apps, multi-level application-sets, literal
  CIDRs, `any-ipv4`/`any-ipv6`, source/destination exclusion, and the live
  feed overlay via `FeedOverlayFn`). The pre-#3042 hand-written matcher
  scanned only zone-pair policies and hard-coded `deny (default)`, so the
  diagnostic could report the OPPOSITE of what the dataplane enforces. The
  request gained a `source_port` field so source-port-constrained app terms
  are simulated.
- The `test policy` operational command (local `pkg/cli` + remote `cmd/cli`
  → ShowText `test-policy:` topic → `showTestPolicy`) carries the same
  source-port input (#3107). The topic adds a `srcport=` key alongside the
  existing `port=` (destination) key; `showTestPolicy` parses it via the
  shared `policymatch.ParsePort` (so empty = unspecified / match any source
  port, and a malformed/out-of-range value reports `invalid source-port`
  instead of silently coercing to the 0 wildcard, the #3116 contract) and
  threads it into `policymatch.Query.SrcPort`. Without it a
  source-port-constrained application was overmatched: the CLI could report a
  PERMIT a real packet from another source port would never receive.
- Server-streaming RPCs (Ping, Traceroute, MonitorPacketDrop,
  MonitorInterface) must drain on client disconnect; cancel the context
  to free buffered output.
- Request-path external commands (ps, df, ss, journalctl, chronyc,
  ntpq, timedatectl, tail, ip neigh flush, systemctl power actions)
  must go through the bounded helpers in `exec_timeout.go` (#1805):
  `outputTimeout` / `combinedOutputTimeout` / `runTimeout` (15s timeout
  + 5s WaitDelay, mirroring the apply-path contract in
  `pkg/daemon/exec_timeout.go`, #1794 — not importable here because
  pkg/daemon imports this package). Do not add raw `exec.Command` calls
  in handlers: a wedged binary pins the handler goroutine and its gRPC
  stream. Power actions take `context.Background()` (client disconnect
  must not cancel a confirmed reboot); everything else derives from the
  request ctx. Request-controlled `tail -n N` is additionally clamped
  via `clampTailLines` — a time bound alone does not cap response bytes.
  The streaming Ping/Traceroute diags size their budget from the request
  instead of the 15s constant (#1819): `pingExecTimeout` (count × 1s +
  15s slack, 30s floor) and `diagTracerouteTimeout` (60s, aligned with
  the HTTP path), both capped at the 150s `diagExecCeiling`; the same
  formulas live in `pkg/api/exec_timeout.go` for the REST siblings, and
  `streamDiagCmd` kills the child promptly when a stream send fails.
  The argv builders (`buildPingArgv`/`buildTracerouteArgv`) place the
  user-supplied target after a `--` end-of-options separator so a
  `-`-prefixed target is an operand, not a flag (option-confusion
  hardening, #2084).
- Policy text views (`server_show_policies_text.go`) must render BOTH
  zone-pair AND global policies (#3059). `showPoliciesHitCount` and
  `showPoliciesDetail` loop `cfg.Security.Policies` and then append a
  global section from `cfg.Security.GlobalPolicies` with from/to zone
  `"*"`. Global counter IDs CONTINUE from the zone-pair loop —
  `policySetID*dataplane.MaxRulesPerPolicy + i` where `policySetID ==
  len(cfg.Security.Policies)` after the zone-pair loop — so global hit
  counters stay aligned with the dataplane and match the gRPC detail
  view, CLI, Prometheus collector, REST inventory (#3045/#3050), and
  structured `GetPolicies`. A `from-zone`/`to-zone` filter selects
  zone-pair policies only, so the global section is suppressed when a
  filter is set. Omitting globals from any one surface is the #3059 /
  #3045 class of blind-spot bug.
- Request-supplied numeric fields are signed on the wire and must be
  range-checked before they index/slice/size anything (#2282). `Complete`
  rejects a negative `pos` with `InvalidArgument` before slicing
  `line[:pos]` — without the guard `int(-1) < len(line)` passed and
  `line[:-1]` panicked the handler goroutine (`pos > len` is already safe
  because the slice is then skipped). `GetNATPoolStats` computes the
  port-pool size `(portHigh-portLow+1) * len(addresses)` in int64 and
  saturates to int32 via `clampInt32` before assigning the int32 proto
  fields — a bare cast wrapped negative for a large pool (~40k addresses
  over the default 64512-port window) and corrupted the
  `avail = total - used` display.
