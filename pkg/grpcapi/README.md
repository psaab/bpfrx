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
- `RunFabricListener(ctx, addr, vrfDevice)` — `server.go`. Supervises the
  network-exposed peer-proxy listener (see trust boundary below). Blocks
  until ctx is cancelled; the caller starts it **once** and the retry
  supervision is internal (#5047).
- Tab completion: `Complete` RPC, backed by `pkg/cmdtree`.

## Trust boundary (loopback-only, #5035)

The primary listener started by `Run` installs **no** authentication or
TLS — only the connection-scoped config-lock lifecycle owner
(`configLockStatsHandler`, a gRPC `stats.Handler`; #5849) — so every RPC
(including destructive `SystemAction` zeroize/reboot/halt/power-off and
Commit/Delete/Rollback) is inherently trusted. That trust holds only if
the listener is loopback-bound.

**Config-session identity (#5849).** The config lock / candidate DB is a
per-CLIENT-CONNECTION resource. Each config RPC keys its session by
`connSessionID(ctx)` — an **unguessable, connection-scoped id** allocated
in `configLockStatsHandler.TagConn` (crypto/rand), NOT the reusable peer
address. The lock is auto-released **exactly once** on `ConnEnd` (a
per-connection `sync.Once`, plus the store's holder check), never on a
per-RPC cancellation: a client cancelling one unrelated read, or a request
deadline expiring, no longer discards the connection's staged candidate or
steals its lock. Explicit `ExitConfigure` (immediate) and the store's
bounded idle-lease reclaim (`reclaimStaleLockLocked`, #4476) remain as
backstops for a connection whose `ConnEnd` notification is lost. The same
`stats.Handler` is installed on the fabric listener for a uniform lifecycle
(a no-op there — the fabric allowlist never admits config RPCs). `Run` therefore clamps a non-loopback `--grpc-addr`
(`0.0.0.0`, a routable address, or the `:port` wildcard) back to a
same-family loopback (`clampGRPCBindToLoopback`) and warns, mirroring the
web-management (#4903) and cluster-bind (#4928) doctrine. There is no
auth mode that unlocks a non-loopback bind here: the intentionally
network-exposed gRPC surface is the **separate** fabric listener
(`RunFabricListener`), which authenticates (#4107) and allowlists (#4122)
every call.

### Peer hop markers are a listener capability, not a header (#5883)

Two internal metadata keys bound cluster forwarding to one hop:
`x-peer-forwarded` (session clear, summary/zone-pair fan-out, system-action
proxying) and `xpf-no-peer` (chassis-forwarding and `MonitorInterface`
proxies). Every handler that reads one uses it to **suppress** work.

They used to be read straight off incoming metadata by presence, which made
them caller-settable: any client that could reach a listener could claim to
be a forwarded peer request and have the node skip the peer half of a
cluster-wide operation while still returning success — a clear that reports
it cleared the cluster and did not.

The trust is now a property of **which listener received the call**, and a
listener decides it:

- the **fabric** listener is the only one a peer dials. Its chain is
  `fabricAuth -> fabricAllowlist -> peerMarker(trust=true)`, in that order,
  so #4107 auth and the #4122 allowlist both accept the call before the
  header is promoted into an in-process context value;
- the **loopback** listener installs `peerMarker(trust=false)`. No peer
  dials it, so an inbound marker there is forged by definition: it is
  stripped and nothing is promoted.

Both listeners then **strip** the reserved keys, so a handler that reaches
for the raw header finds nothing. That is not belt-and-braces — a site in
`server_sessions.go` did exactly that instead of calling the helper, and
stripping is what stops the next one from re-opening the hole.
`reservedPeerMetadataKeys` is the single source of truth for both the strip
and the promote, pinned by `TestReservedPeerMetadataKeysAreComplete`.

The absent-capability default is `false` for both markers, which is the safe
direction: false means *do the peer work*, so a stripped or forged header can
only cause more work to be attempted, never less.

The marker still rides an ordinary metadata header on the wire between nodes
— that is the only channel there is. What changed is that a header is
evidence only when the listener that received it is one a peer could have
dialed.

### Fabric-listener supervision (#5047)

`RunFabricListener` is a supervised loop, not a one-shot. A transient
bind failure or a later `Serve` fault used to be **terminal** — the
listener returned/blocked forever and the peer-proxy surface (monitor,
peer-show, proxied-failover) was permanently lost until the whole
cluster-comms lifecycle restarted, with no fallback on a single-fabric
deployment. It now re-binds and re-serves on any fault with a bounded
exponential backoff (100 ms → 5 s cap, reset after a `Serve` that stayed
up ≥ 30 s) while ctx is live, so a persistent bind failure keeps retrying
at the cap without spinning. The expected graceful-shutdown signals
(ctx cancel, `grpc.ErrServerStopped`) exit cleanly and are never retried,
and neither the supervisor nor its `Serve` worker outlives ctx. Per-bind
up/down health is published via `FabricListenerUp(addr)` /
`FabricListenerHealth()` and logged at Info/Warn on transitions (retry
ticks are Debug).

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
- **Commit error-code contract (#5742).** `Commit` / `CommitConfirmed`
  classify the callback error structurally via `commitApplyStatus`, keying
  off whether the daemon returned the committed config alongside it:
  a **non-fatal tail-reconcile / ordinary dataplane-apply** error (networkd
  write, Kea restart, IPsec reload, interface reconcile, non-abort apply —
  the daemon commits+arms the config and returns it *with* the error) →
  `codes.Unavailable` (transient, **retryable**; the config was accepted and
  self-heals on the next commit/feed retry, #5646). A true **config-validation
  / compile-reject** (compiler/schema reject, `compileErrorMustAbortApply`
  fail-closed gate, device-map preflight, bootstrap refusal, pre-promotion
  persistence — no config committed, `nil` returned) → `codes.InvalidArgument`
  (fix the config). `context.Canceled` / `DeadlineExceeded` are preserved and
  take precedence. The human-readable message is unchanged; only the code
  distinguishes "retry" from "fix your config". Unclassifiable errors fail
  safe to `InvalidArgument`.
- **Zeroize goes through the apply gate AND stops xpfd (#5281).** The
  `SystemAction{zeroize}` handler does NOT call `performZeroizeWipe`
  directly. It routes through `ZeroizeFn` (wired by the daemon to
  `factoryReset`), which takes the SAME apply semaphore `CommitFn` uses
  and enters a **terminal reset generation** before erasing, so a
  concurrent in-flight apply is drained and no later commit / HA-sync /
  reconcile re-creates the erased `.configdb` SSOT or re-renders the wiped
  secrets (frr.conf / swanctl PSKs / Kea / login accounts). On a
  fully-successful wipe the handler then schedules `scheduleStopDaemon`
  (`systemctl stop xpfd` after a 1 s grace, mirroring the local
  `request system zeroize` CLI path in `pkg/cli`) so the daemon does not
  keep running with the pre-wipe in-memory `ActiveConfig`. The sequence is
  strictly **gate → wipe → stop**, fail-CLOSED: a wipe that does not
  complete returns `Internal` and does **not** stop the daemon (stopping a
  half-wiped box would strand prior-tenant secrets on disk). The `#4108`
  action-journal write still happens BEFORE the wipe. `ZeroizeFn` is nil
  only in a NoDataplane / no-daemon build, where the handler falls back to
  an ungated direct wipe (there is no running reconcile loop to race).
- **The interactive console shares ONE wipe primitive (#5890).** The
  in-process console `request system zeroize` (`pkg/cli`) previously ran
  its OWN partial wipe (`zeroizeConfigState`: config DB + archive only),
  which LEFT `tls/`, the rendered service configs (frr/swanctl/kea), and
  the provisioned login accounts (shadow/authorized_keys/`sudoers.d/xpf-*`)
  on disk — secret residue on a re-tenanted device. The console now
  DELEGATES to the exported `PerformZeroizeWipe(configDir, configBase)` —
  the SAME primitive `runZeroize` runs — so both paths erase an IDENTICAL
  single-source-of-truth OWNED-artifact set and cannot diverge again. The
  console keeps its own root resolution (`cli.zeroizeConfigRoot`, #5554/
  #5684) and daemon stop. **The console also runs the wipe THROUGH the
  daemon's coordinated factory-reset transaction (#5871).** It does not dial
  gRPC (it is in-process); instead the daemon wires the SAME `factoryReset`
  gate it wires into the gRPC server as `ZeroizeFn` into the CLI via
  `cli.SetFactoryResetFn(d.factoryReset)`, and `cli.performConsoleZeroize`
  routes the wipe closure through it. So the console wipe now takes
  `d.applySem` and enters the terminal reset generation BEFORE erasing —
  identical fencing to the gRPC path — closing the pre-#5871 window where an
  ungated console wipe let a concurrent commit / HA-sync / reconcile re-create
  the just-erased `.configdb` SSOT or re-render the wiped secrets. When the
  CLI is spawned OUTSIDE the daemon (offline recovery / unit test)
  `factoryResetFn` is nil and the console falls back to the ungated direct
  wipe (no reconcile loop is running to race), mirroring `runZeroize`'s
  `zeroizeFn==nil` fallback. The rendered/BPF/networkd leg targets in
  `performZeroizeWipe` are package vars so the full primitive is hermetically
  testable end-to-end (no real `/etc`) — production paths unchanged.
- **Zeroize erases the CONFIGURED config root, not a hardcoded `/etc/xpf`
  (#5280).** `runZeroize` resolves the config root from
  `configstore.Store.ConfigPath()` — the daemon's `-config` path, the SAME
  file the store loads from and persists the `.configdb` SSOT / rollback
  slots / `.config.journal` to — and threads `filepath.Dir/Base` of it into
  the `performZeroizeWipe(configDir, configBase)` primitive. A daemon
  started with a non-default `-config` (e.g. `/srv/xpf/site.conf`) therefore
  erases `/srv/xpf`, not `/etc/xpf`; the pre-fix wipe hardcoded `/etc/xpf`
  and left the real root's secrets on disk while reporting a clean reset.
  Resolution runs BEFORE the apply gate and is fail-CLOSED: if the store /
  config path is undeterminable, `runZeroize` returns an error (surfaced as
  `Internal`) rather than wiping the wrong path or nothing — it never
  enters the terminal reset generation on an unknown root. Only the
  config-root leg is parameterized; the rendered-config (frr/swanctl/kea),
  login-account, config-archive, BPF-pin and networkd legs live at fixed
  system paths independent of `-config`. `defaultConfigDir` /
  `defaultConfigBase` remain only as the documented standard-appliance
  default and the RED-on-revert reference, not as the wipe target.
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
- `GetSessionsResponse.total` is the EXACT count of filter-matching
  (forward-only) sessions — never the old `-1` sentinel (#5034 /
  C175-HC-073). `setSessionsTotal` uses the lightweight `SessionCount()`
  when unfiltered and a count-only scan (`IterateSessions`/`…V6` +
  `matchV4`/`matchV6`, no enrichment/allocation) when filtered, matching the
  legacy path's `idx` total. Both `matchV4`/`matchV6` and `SessionCount`
  skip reverse entries, so `total` counts unique forward sessions, not raw
  map entries. It is the whole-table total, independent of the returned
  page's size (`len(sessions)` undercounts once a page/limit caps the
  result), so a consumer — including a cluster peer's session detail —
  renders a meaningful "Total sessions". A count-scan iterator error fails
  the RPC (`Internal`) rather than reporting a partial under-count (#2469).
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
  are simulated. #3104: `MatchPolicies` and the `test policy` ShowText surface
  thread live per-scheduler active-state (`s.policyInactiveFn()` →
  `policymatch.Query.PolicyInactiveFn`, sourced from the same
  `Manager.PolicySchedulerActiveState` the #3062 policy-detail display uses) so
  a scheduler-inactive policy is skipped like the runtime. #3414: `policyInactiveFn()`
  is now ALWAYS non-nil — with no live state (no provider / early boot) it binds
  a nil state map, which fails closed so scheduled policies are simulated as
  INACTIVE (matching the dataplane's nil-state => dropped) rather than certified
  as-if-active.
- #3375: the response `action` is rendered through the shared SSOT
  `policymatch.Result.DisplayAction()` for EVERY verdict, so the gRPC and REST
  surfaces can never diverge. Before #3375 gRPC returned a BLANK `action` for
  two security-sensitive verdicts where REST returned an explicit string: a
  `to-zone junos-host` query that matched no host-bound policy (now
  `policymatch.HostInboundActionString` — `host-inbound (local delivery subject
  to host-inbound-traffic service admission — a zone with no
  host-inbound-traffic stanza denies by default; transit/global/default policy
  NOT applied)`, with `host_inbound_unmatched` set; the pre-#3627 wording said
  `local delivery proceeds`, which read as an admit even for a no-stanza
  default-deny zone, #3405), and the no-active-config case (now `deny (default)` instead of an empty
  response). The response also gained a typed `default_used` bit — the
  machine-readable form of the ` (default)` suffix on `action`, set when no
  policy matched and `action` is the configured default-policy (including the
  no-config fail-closed deny), and false for a concrete match and for
  `host_inbound_unmatched` (which has no default-policy fallback). The REST
  `MatchPoliciesResult` carries the same `default_used` JSON field. The CLI
  `show security match-policies` renders its own multi-line, self-describing
  host-inbound block, so it never showed a blank verdict and is unchanged.
- #3627 M06: the response echoes the queried zone pair on
  `queried_from_zone`/`queried_to_zone` (proto fields 13/14) for EVERY answer —
  positive match, no-match/default, and host-inbound. Before #3627 the queried
  zones surfaced only indirectly via the #3331 `from_zone`/`to_zone`, which are
  the matched policy's declared SCOPE and are set ONLY on a positive match; a
  negative/default or host-inbound answer omitted them entirely, so a stored
  diagnostic could not prove which zone pair was tested without a copy of the
  request. The queried echo is the query context, DISTINCT from the matched
  scope (for a wildcard-zone or global match the two can differ). The REST
  `MatchPoliciesResult` carries the same `queried_from_zone`/`queried_to_zone`
  JSON fields.
- #3668: on a MATCH the response also carries `source_address_excluded` /
  `destination_address_excluded` (proto fields 15/16) and the stable `rule_id`
  (proto field 17), mirroring the inventory `PolicyRule` (fields 13/14/18). The
  exclusion flags report whether the matched policy carries Junos
  `source-address-excluded` / `destination-address-excluded` — the rule matches
  every address EXCEPT those in `src_addresses`/`dst_addresses`. The shared
  matcher (`matchAddr`) already inverts the address test correctly for the
  excluded side; the flag is what stops a positive verdict from reading
  BACKWARDS (before #3668 a hit against a source OUTSIDE an excluded set printed
  the excluded list as if it caused the match — unsafe for a Junos-style
  negated-address audit). `rule_id` is the stable `<from>-><to>/<name>` identity
  the inventory `GetPolicies`, the snapshot, and the event path share
  (`dpuserspace.StablePolicyRuleID`); a matched GLOBAL policy uses
  `junos-global->junos-global/<name>` exactly like the inventory global rows, so
  a simulator hit joins to the inventory / logs / tests even after a policy
  reorder shifts the numeric `policy_id`. All three are additive, set only on a
  positive match. The REST `MatchPoliciesResult` carries the same
  `source_address_excluded`/`destination_address_excluded`/`rule_id` JSON
  fields, and both CLI renderers annotate the exclusion as
  `Source addresses (except): ...` plus a `Rule ID:` line.
- #3685 M05/M06: on a MATCH the response also carries the policy `description`
  (proto field 18) and the scheduler binding `scheduler_name` (field 19) /
  effective-active flag `scheduler_active` (field 20). `description` (M05) is the
  matched policy's `description` text, the same field the inventory
  (`GetPolicies`) and the local `show security match-policies` result carry over
  the SAME `policymatch.Result`; a match verdict without it was weaker than the
  inventory / CLI answer (descriptions often hold ticket / change-control
  context). `scheduler_name` (M06) mirrors the inventory `PolicyRule` scheduler
  binding (#3624); `scheduler_active` is the explicit effective-active flag. A
  positive match is by construction currently active — `s.policyInactiveFn()` is
  fail-closed (#3414) and SKIPS a scheduler-inactive rule before it can match —
  so a matched scheduled policy always reports `scheduler_active=true`; it names
  the gate admitting the rule right now. All three are additive, set only on a
  positive match, and both scheduler fields are omitted for a non-scheduled
  policy. The REST `MatchPoliciesResult` carries the same
  `description`/`scheduler_name`/`scheduler_active` JSON fields.
- #3627 B1a: a `to-zone junos-host` query also carries the structured
  `host_inbound` message (proto field 21, `HostInboundAdmission`) — WHICH
  host-inbound-traffic system-service / protocol token admits the host-bound
  tuple, or that the box denies / globally accepts / cannot classify it. It is
  populated from the shared `policymatch.Result.HostInbound`
  (`dataplane/userspace.HostInboundAdmission`), the SAME classifier the local
  CLI `show security match-policies` host-inbound line renders (the merged
  #4352) and the REST `host_inbound` JSON object carries, so the three surfaces
  cannot drift (#3375). Fields: `status`
  (`HOST_INBOUND_ADMISSION_STATUS_{TOKEN_ADMIT,GLOBAL_ACCEPT,DENIED,INDETERMINATE}`;
  the `NOT_COMPUTED` zero value is rendered as an omitted message), `token` and
  `kind` (`system-services` / `protocols`, set only for `TOKEN_ADMIT`), and
  `description` (the one-line CLI explanation so a client renders the same
  sentence without re-deriving it). `hostInboundStatusToProto` maps the Go
  classifier enum to the proto enum explicitly, so a future reordering of either
  fails to compile rather than mislabel a verdict. The classifier reads the same
  structured token->tuple SSOT the kernel-nft builder renders from
  (`config.HostInboundServiceMatch` / `HostInboundProtocolMatch`), so a reported
  token can never claim a port the box does not open. Present ONLY for a
  host-bound query — on both the `host_inbound_unmatched` verdict and a matched
  `to-zone junos-host` policy (the host-inbound gate is a separate admission
  stage); OMITTED for every transit / global / default / content-rejected
  verdict. It is additional context and never changes `matched` /
  `host_inbound_unmatched`.
- #3685 M04: the gRPC-text `test policy` renderer (`server_show_firewall.go`,
  the remote `cli` backend) prints the policy ID, the global match scope, and
  the description for a GLOBAL match, mirroring `show security match-policies`.
  Before #3685 the global branch printed only `Policy:`/`Action:`, dropping the
  ID (session-table / audit join key when a global name collides with a
  zone-pair name), the scope, and the description — the gRPC-text sibling of the
  local request-path gap tracked in #3674 (`pkg/cli/cli_request.go`, a distinct
  renderer). The zone-pair branch already printed the from/to zones.
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
- **MonitorInterface peer proxy — one-hop bound (#5497).** For a RETH (or
  a peer-owned physical member) `MonitorInterface` may forward the stream
  to the cluster peer (`proxyMonitorInterface` → `dialPeer`). Two invariants
  keep this to a single hop, so one management stream stays O(1) in
  server/client resources: (1) it proxies a locally-present RETH ONLY when
  the peer ACTUALLY owns the RG — `!IsLocalPrimary(rg) && IsPeerPrimary(rg)`
  (`decideMonitorProxy`), never merely because the local node is not primary;
  during both-secondary / election / sync-hold / disabled / peer-lost NEITHER
  node is primary, so it serves locally instead. (2) The proxy stamps the
  `xpf-no-peer` hop marker on the outgoing context (the chassis-forwarding
  convention); a request arriving WITH that marker is served locally / reported
  not-found and NEVER re-proxied. Before #5497 the trigger was `!IsLocalPrimary`
  alone with no marker, so two non-primary nodes proxied to each other in an
  A→B→A loop that stormed connections/streams/goroutines. `IsPeerPrimary` lives
  on `cluster.Manager` (reads the heartbeat-advertised peer RG state; false when
  the peer is not alive). The marker only ever SUPPRESSES a second hop, so it
  cannot be spoofed to reach data a client could not otherwise reach.
- **Bounded shutdown (#4910).** Both listeners stop through
  `stopGRPCServer` (`server.go`): `GracefulStop` runs in a goroutine and,
  if active RPCs have not finished within `grpcStopTimeout`, `Stop()`
  force-closes the connections. This is required because `MonitorInterface`
  streams forever off only its client `stream.Context()` — a client
  holding that stream open during shutdown would otherwise block
  `GracefulStop`, and therefore `Run` / `RunFabricListener`, indefinitely
  (a stuck daemon stop / failover / restart). `Run`'s serve+shutdown loop
  is factored into `serveUntilDone(ctx, srv, lis)` so the bounded-stop path
  is exercisable over an in-memory listener. A normal, RPC-idle shutdown
  (or one where every client has disconnected) returns as soon as
  `GracefulStop` completes — the timeout is only a backstop.
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
  `streamDiagCmd` must also reap the child on the scanner-error path
  (#5060): a combined-output line larger than the scanner token cap
  yields `bufio.ErrTooLong`, and — exactly as on the send-failure path —
  the scan goroutine must `cancel()` + `pr.Close()` before the waiter
  returns, or exec.Cmd's internal copy goroutine stays wedged in
  `pw.Write` (WaitDelay closes only the exec-owned OS pipes, not this
  `io.Pipe`) and the RPC leaks past the deadline. The cleanup is a
  `defer` so it fires on every scanner exit; the per-line token is a
  deliberate `Scanner.Buffer` cap (`diagScanMaxToken`), and each
  operator-supplied field (target/source/routing-instance) is bounded at
  `maxDiagArgLen` at the RPC boundary so a multi-kilobyte argument is
  rejected with `InvalidArgument` before it can reach exec.
  The argv builders (`buildPingArgv`/`buildTracerouteArgv`) place the
  user-supplied target after a `--` end-of-options separator so a
  `-`-prefixed target is an operand, not a flag (option-confusion
  hardening, #2084).
  Per-job deadlines are necessary but NOT sufficient: without an
  aggregate bound a request flood holds hundreds of processes/FDs/
  goroutines/streams at once and starves the control plane. So Ping and
  Traceroute first take a slot from the process-wide
  `diagcmd.DefaultLimiter` (`MaxConcurrentDiagnostics = 4`) via the
  `diagLimiter` package var — SHARED with the REST ping/traceroute
  handlers, so one aggregate cap covers BOTH surfaces (#5057). Acquire is
  fail-fast: when the cap is reached the RPC returns
  `codes.ResourceExhausted` immediately (no queue, no wait) and the slot
  is released via `defer` on every path (success, exec error, ctx
  timeout/cancel). `streamDiagCmd` is called through the `streamDiag`
  package-var seam so a test can inject a fake slow diagnostic and assert
  the cap without real subprocesses.
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
  #3045 class of blind-spot bug. A scoped global (#3148 `match
  from-zone`/`to-zone`) carries its narrowing (#3286): the text
  `policies-hit-count` From/To columns and the `policies-detail` `Source
  zone:`/`Destination zone:` lines show the configured zone for a scoped
  global (group still `*`), and structured `GetPolicies` populates the
  per-rule `match_from_zone`/`match_to_zone` proto fields (empty for an
  unscoped global). Showing the group `*`/`*` but dropping the per-rule
  scope is the #3286 blind spot. #4344: `showPoliciesHitCount`,
  `showPoliciesDetail`, and structured `GetPolicies` read every per-rule
  counter (zone-pair, global, and the default-policy sentinel row) through
  the shared `dpuserspace.NewPolicyCounterReader` bulk snapshot — one brief
  dataplane lock for the whole set — instead of a per-policy
  `ReadPolicyCounters` loop; the reader falls back to the per-policy read
  for a dataplane without the bulk snapshot, so the rendered values are
  identical. A static canary in the test package forbids a direct per-rule
  `ReadPolicyCounters` call in these files.
- `GetZones` enumerates security zones (`ZoneInfo`). The host-inbound
  admission set is surfaced distinctly (#3328): `host_inbound_configured`
  is the dataplane posture bit (mirrors `ZoneSnapshot.HostInboundConfigured`,
  #3070/#3362/#3405). Post-#3405 EVERY configured security zone is
  host-inbound ENFORCING (Junos default-deny parity), so this bit is `true`
  for every zone the RPC returns — it reports the dataplane truth, not
  config shape. A zone with NO `host-inbound-traffic` stanza default-DENIES
  host-bound traffic exactly like an explicit empty stanza; there is no
  admit-all posture for a configured zone. The admitted set lives in
  `host_inbound_system_services` / `host_inbound_protocols` (empty =
  deny-all; split so a service is distinguishable from a routing protocol);
  `interface_host_inbound` (repeated `InterfaceHostInbound`) carries
  per-interface overrides (#3362), the effective set being the union of
  the zone-level set and the override. The legacy `host_inbound_services`
  flattened list (services + protocols) is kept as a back-compat alias.
  The split projection is the SSOT-shared `ZoneConfig.SortedInterfaceHostInboundRefs`
  iteration the REST `GET /api/v1/security/zones` handler also uses. Before
  #3653 the bit was re-derived from config shape and reported `false` for a
  no-stanza zone — the pre-#3405 "false = admit-all" reading, the OPPOSITE
  of the runtime default-deny, so a controller read the management plane as
  open when it is fail-closed. (Global ICMP/ND/PMTUD accepts and lifeline
  interfaces fxp0/em0/fab* still bypass the per-zone host-inbound deny.)
  Before #3328 this RPC exposed only the flattened list and no `configured`
  flag at all.
- `GetScreen` enumerates the configured screen profiles. `ScreenInfo`
  carries `name`, the `checks` string list, and a `map<string,int64>
  thresholds`. The `checks` list and thresholds come from the shared
  `config.ScreenChecks` / `config.ScreenThresholds` helpers — the same
  single source of truth the REST `GET /api/v1/security/screen` handler
  uses (#3327). Before #3327 this RPC and the REST handler each carried a
  byte-identical copy of the helper that omitted `port-scan`, `ip-sweep`,
  `limit-session-source`, `limit-session-destination`, and
  `icmp-fragment` (all enforced by `pkg/dataplane/userspace/screens.go`)
  and exposed no thresholds — under-reporting active enforcement to a
  structured-state consumer. The `checks` set is kept a superset of the
  dataplane-enforced set; the duplicated-helper drift mechanism is gone.
- `GetEvents` returns recent security events (`EventEntry`) from the
  `pkg/logging` ring buffer. As of #3337 the entry carries the full RT_FLOW
  forensic record so a SIEM can reproduce the CLI close line: beyond the
  5-tuple / zones / policy ID it maps the resolved zone names, policy name,
  application name, ingress interface, close reason, the reverse counters,
  and the additive forensic block — `nat_src_addr`, `nat_dst_addr`,
  `session_id`, `elapsed_time`, `created` (+`created_nanos`),
  `egress_ifindex`, `ingress_ifindex`, `tos`, `tcp_control_bits`, and
  `reason` (proto field numbers 21-31, additive — no renumber). Before
  #3337 the proto stopped at `close_reason` (field 20) and dropped the NAT
  tuples, session ID, timing, ifIndexes, and CoS bits the `EventRecord`
  already held, and REST/SSE dropped even the policy/app/zone-name/reverse
  fields gRPC exposed. The `time` field now formats `RFC3339Nano`
  (sub-second) so high-rate events keep ordering; the REST/SSE surfaces
  mirror the same fields via the shared `eventEntryFromRecord` mapper. The
  zone filter (`zone` + `has_zone`) and out-of-range rejection are unchanged
  (#3334/#3338).
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
- Request-supplied tokens that are interpolated into an operational
  shell-out must be validated at the boundary (#4588). `GetBGPStatus`
  (`server_routing.go`) parses a neighbor IP out of `req.Type`
  (`received-routes:<ip>` / `advertised-routes:<ip>` / `neighbor:<ip>`) and
  hands it to the `pkg/frr` `GetBGPNeighbor*` wrappers, which concatenate it
  into a `vtysh -c "show bgp neighbor <ip> …"` command. Because the local
  gRPC listener is UNAUTHENTICATED, the handler rejects a non-parseable IP
  with `codes.InvalidArgument` (`net.ParseIP`) before it reaches vtysh — a
  newline-bearing token would otherwise become a second raw FRR CLI command
  (`vtysh -c` splits on newlines) with no commit-audit trail. `req.Type ==
  "neighbor"` and `neighbor:` with an empty ip stay legal (they select every
  neighbor). The `pkg/frr` wrappers re-validate as the load-bearing belt;
  see `pkg/frr/README.md` "#4588".
