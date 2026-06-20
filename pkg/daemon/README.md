# pkg/daemon

Daemon lifecycle and orchestration. Loads the configured dataplane backend,
applies compiled config to all subsystems (routing, NAT, DHCP, cluster, ...),
handles signals
(SIGHUP reload, SIGTERM shutdown), and wires the commit-atomicity
semaphore (#846) so `Store.Commit()` and `applyConfig()` always run
together.

This is the package `cmd/xpfd` instantiates. It depends on essentially
every other internal package.

The daemon stores dataplane backends behind `dataplane.RuntimeDataPlane` and
uses the split config, HA/fabric, sessions, telemetry, and link-cycle domains.
Legacy `dataplane.DataPlane` access is isolated behind `legacyDP()` for
callers that still need legacy eBPF compatibility while their domain adapters
are completed (DPDK retired #1525). Userspace currently reaches those old callers through
`userspace.LegacyDataPlaneAdapter`; the userspace `Manager` remains a
runtime-domain type, and the adapter is only the transition boundary for
status, CLI, and cluster-sync paths that still call `legacyDP()`.

Dataplane construction in `daemon_run.go` goes through
`buildRuntimeDataPlane()`: omitted `system dataplane-type` and explicit
`userspace` select `userspace.Boot()` directly, while explicit `ebpf` still
falls through `dataplane.NewRuntimeDataPlane()` so the legacy rollback path
and retired-DPDK sentinel handling stay unchanged.

Config apply uses the runtime `ConfigSink.ApplyConfig` path. This is required
for userspace AF_XDP, which is intentionally not exposed as a legacy
`DataPlane`; apply-time callers must not reintroduce `legacyDP().Compile` as
the primary compile/apply gate.

## Entry points

- `Daemon` — `daemon.go`.
- `Options` — `daemon.go`. `ConfigPath`, `NoDataplane`, `APIAddr`,
  `GRPCAddr`, `Version`.
- `New(opts Options) (*Daemon, error)` — `daemon.go`. Fails when the
  config store cannot be constructed (#1893 fail-closed: unusable
  `.configdb` means no boot, not a delayed nil-deref panic).
- `CompileHealth` — `daemon.go`. Snapshot of the most recent compile
  outcome; `pkg/api` consumes it for the `/health` endpoint.

## Cluster mode

Detected by the presence of `/etc/xpf/node-id` (contents `0` or `1`).
Absent → standalone. Cluster mode triggers the bondless-RETH naming
convention (`fxp0`, `em0`, `ge-{0,7}-0-X`).

## Interface management

`enumerateAndRenameInterfaces()` runs at startup (in `linksetup.go`),
writes `.link` files for every PCI-enumerated NIC, and assigns vSRX names
based on PCI bus order plus the cluster node ID. RETH members match by
`OriginalName=` (PCI kernel name), not `MACAddress=` — the MAC alternates
between physical and virtual at boot, and `ensureRethLinkOriginalName()`
auto-fixes stale `.link` files.

Any interface not declared in the active config is brought down and given
`ActivationPolicy=always-down` in networkd — EXCEPT the #1922 protected set
(see below).

## Bootstrap mode + management lifeline (#1922)

`bootstrap.go` implements the SAFE-BOOTSTRAP daemon state so the daemon can
never lock an operator out of a remote box it manages.

- **Five-case boot predicate** (`computeBootClass`, computed once in `Run`
  after `Store.Load` + `bootstrapFromFile`): fresh / never-committed →
  **bootstrap**; valid `active.json` / clean day-0 import /
  operator-committed-empty → **normal**; corrupt/too-new → fail-safe (already
  fatal via #1917 D1). The **HA-node guard** keys on `/etc/xpf/node-id` FILE
  presence (NOT the config-derived `clusterMode`): a node-id node always
  resolves NOT-bootstrap.
- **Fail-closed on compile failure (#1960):** a PRESENT, previously-committed
  `active.json` that is valid JSON but no longer COMPILES (even through the
  tolerant `compileTreeLenient` path) is the dangerous tuple
  `ActiveConfig()==nil` + `EverCommitted()==true`. Without a guard, that
  tuple resolves to **normal** and runs the positional claim-all rename on a
  box whose intended config is unknown. `Store.Load` now tags this error with
  `configstore.ErrConfigCompile`; `Run` classifies it via `classifyLoadError`,
  logs it loudly (Error), SKIPS `bootstrapFromFile` (so the text `xpf.conf` is
  not blind-imported over the broken DB), and passes `configCompileFailed=true`
  to `computeBootClass`, which forces **bootstrap** — overriding even the
  HA-node guard. The control plane stays up so the operator can recover
  in-band. A daemon hard-exit is deliberately NOT used (it would also strand
  mgmt). Distinct from `ErrConfigDBUnreadable` (#1917 D1, which IS a fatal exit
  because the bytes themselves cannot be read).
  - **Why mgmt stays reachable — freeze in last-known-good, not a wipe.** This
    path does NOT run the `enterBootstrapMode()` teardown (which removes the
    `10-xpf-*` `.network`/`.link` files, clears the FRR managed section, and
    tears down the dataplane); that teardown is reserved for confirmed-commit
    rollback. On a previously-committed box the last-good networkd + FRR state
    therefore persists untouched, so the box stays reachable at its EXISTING
    management address (rather than dropping to bootstrap fxp0-DHCP and
    possibly changing the IP out from under a connected operator) while the
    config is fixed. That is a deliberate choice: the only thing the box must
    NOT do on an uncompilable config is the *new* takeover (positional
    claim-all / fresh apply), which bootstrap suppresses. The lifeline/protected
    set govern the rename + apply sweeps and the fresh-install case; they are
    not what keeps a *previously* managed box reachable here.
    - **Transit is still fail-closed** — do not read "freeze" as "the firewall
      keeps forwarding." Bootstrap mode suppresses `enableForwarding` and the
      dataplane arm (`dp.Start`), so the daemon itself forwards no transit in
      this state. A cold reboot therefore carries NO transit until the operator
      commits a compilable config; only a daemon *restart* that leaves an
      already-armed dataplane process running keeps enforcing the
      last-known-good policy in the interim. Either way no traffic is forwarded
      under an unknown/no policy — what persists is interface identity + mgmt
      reachability, not unpoliced forwarding.
  - **In-band recovery is real (not just "repair the DB").** On compile failure
    `Store.Load` keeps `compiled` nil (the fail-closed signal) but retains the
    parsed-but-broken tree as the active tree and loads the on-disk rollback
    history. So `configure` clones the broken config into the candidate (the
    operator can `show`/edit the offending stanza), `rollback N` /
    `show | compare rollback N` reach prior good configs, and a
    `commit confirmed` of either promotes a working config. Repairing/removing
    the on-disk DB remains the out-of-band fallback.
  - **FRR managed section is cleared on a compile-failed boot unless forwarding
    is genuinely live (#1993).** `frr` is an independent service that starts from
    its persisted `frr.conf` (the managed section from the last good
    `applyConfig`), which freeze-in-last-known-good leaves intact. On a
    compile-failed boot where the dataplane is unarmed (no transit), FRR would
    otherwise still form peerings and advertise the last-good prefixes — peers
    route transit to this node's physical IPs and it blackholes them rather than
    failing over to the HA partner. To close that cross-daemon gap, the
    compile-failure boot path calls
    `clearFRRForFailClosedBoot(configCompileFailed)` immediately after the FRR
    manager is constructed (`d.frr = frr.New()`).
    - **The preserve decision requires LIVE FORWARDING, not just pins.** Pins on
      `/sys/fs/bpf/xpf/links` prove only that an XDP link is *attached*, not that
      forwarding is *live*: a graceful hitless shutdown (`dp.Close()` →
      helper `Close()` → `stopLocked` disables `ctrl.enabled`; the BPF `Close()`
      deliberately leaves pinned maps/links for the next daemon to reuse) leaves
      the pins in place while forwarding is STOPPED. A pin-only guard would read
      "pins exist" and wrongly preserve FRR on a graceful restart, recreating the
      blackhole. The decision is therefore two stages: (1) **pins are a cheap
      pre-filter** — no `xdp_*` pins (e.g. a cold reboot cleared the bpffs tmpfs)
      ⇒ no surviving dataplane ⇒ CLEAR, skipping the socket probe (a pin-probe
      *error* does not preserve; it falls through to stage 2); (2) **the
      authoritative signal** is a lightweight one-shot status query against any
      PRE-EXISTING helper on its control socket
      (`dpuserspace.ProbeForwardingArmed` → `ProcessStatus.Enabled &&
      ForwardingArmed`, the same pair the runtime gates forwarding on). FRR is
      preserved **only** when that probe says forwarding is live. Every other
      outcome — socket missing / connect-refused / timeout / `Enabled=false` /
      `ForwardingArmed=false` / probe error — **clears** (fail toward fail-over:
      an unarmed/unknown helper is not forwarding). The control-socket path is
      resolved the same way the runtime Manager resolves it
      (`DefaultControlSocketPath` → `deriveUserspaceConfig`); a compile-failed
      boot has a nil active config, so it uses the default path (matching a
      surviving helper from a default-config deployment), and a custom-path
      deployment falls back to the default → probe finds nothing → clears
      (safe direction). Both the pin pre-filter
      (`failClosedBootHasPinnedXDPLinks`) and the armed probe
      (`failClosedBootForwardingArmed`) are package-var seams so the decision is
      unit-tested without a real helper; the pure decision is
      `failClosedBootShouldClearFRR`.
    - When the decision is CLEAR, `d.frr.Clear()` strips ONLY the managed
      section and reloads FRR. Dropping those peerings makes upstream/peers fail
      over to the HA partner instead of blackholing transit. This is the SAME
      primitive `enterBootstrapMode()` uses, but it deliberately runs *only* the
      FRR-clear step — NOT the `.network`/`.link` removal or link-cycle — so
      freeze-in-last-known-good MANAGEMENT reachability (the existing mgmt IP) is
      preserved. Normal/fresh-install boots remain byte-identical, and it is
      fully reversible: the first compilable `commit confirmed` (or a cluster
      `SyncApply`) re-renders FRR via `applyFRRConfig` and re-installs the
      managed section. A degraded reload (`ErrFRRReloadDegraded`) is logged, not
      fatal — `Clear()` has already written the empty managed section to disk, so
      a later FRR restart converges. The VIP/RETH data path already failed over
      before this fix because #1960 suppresses this node's VRRP/cluster.
    - **Residual (cross-daemon ordering):** FRR is an independent systemd
      service and may advertise last-good prefixes from its OWN start before
      xpfd reaches the clear. The clear collapses that window once the peerings
      drop (peer hold-down then carries transit on the partner). A unit-ordering
      change (`xpfd` clears FRR before FRR forms peerings) would shrink the
      window further but is a separable follow-up, not required for the Go fix.
- **Bootstrap mode** (`d.bootstrapMode` atomic): runs gRPC/REST/CLI normally
  but SUPPRESSES interface takeover ACTIONS — the full rename loop, host
  tunables, `enableForwarding`, dataplane arm (`dp.Start`), the boot-time
  `applyConfig`, and the #2079 NAT pool-alarm monitor start (#2114: the
  monitor samples `d.dp`, which is still nil-able on a bootstrap-exit arm
  failure, so it must not run during the bootstrap window). Managers are
  still constructed (so the exit reconcile wires every subsystem). A plain
  first `commit` is REFUSED — the operator must `commit confirmed`. Exit is
  one-way, on the first non-empty config apply (confirmed commit OR cluster
  `SyncApply`); `runBootstrapExitStartup` then runs the deferred startup
  takeover (including starting the NAT pool-alarm monitor on a successful
  arm) before the reconcile.
- **PCI-keyed lifeline** (`setupBootstrapLifeline`): in bootstrap mode the
  daemon detects the default-route mgmt NIC (v4 then v6, else refuse +
  console), records its PCI+MAC to `/etc/xpf/lifeline-interface` (keyed by
  PCI, survives rename/restart/rollback), and — only if that NIC is
  enumeration index 0 — renames just it to fxp0 and snapshots its addressing
  into the bootstrap `.network`.
- **Protected set** (`resolveProtectedInterfaces` →
  `dataplane.SetProtectedInterfaceResolver`): fxp0 + the lifeline NIC + an
  explicit `system management-interface` leaf are NEVER marked Unmanaged /
  always-down / address-stripped, even on an empty/absent/rolled-back config.
  An explicit non-fxp0 leaf narrows fxp0 off the auto-protection.
- **First-commit rollback** (`enterBootstrapMode`): a timed-out first
  `commit confirmed` stops+discards the NAT pool-alarm monitor (#2114 — so
  no sampler survives to race a later re-arm's `d.dp = nil` write; the
  monitor is rebuilt fresh on a corrected re-arm because it is not
  restartable after `Stop`), removes the takeover `.network` files (keeping
  the lifeline + `.link` files), clears the FRR managed section, and
  detaches the dataplane — instead of applying an empty config — and the
  store persists the never-committed marker so a restart re-enters
  bootstrap.

## Notable gotchas

- ISSU (in-service software upgrade) preserves sessions across the upgrade
  by handing the BPF map FDs to the new daemon and timing the cutover
  against HA failover.
- CoS configuration is wiped on every cluster deploy. Re-apply with
  `test/incus/apply-cos-config.sh` after `cluster-setup.sh deploy`. (See
  CLAUDE.md.)
- `commitFn` and `commitConfirmedFn` are passed to `pkg/cli` and
  `pkg/grpcapi`; they hold the apply semaphore across the commit + apply
  pair so concurrent committers serialize.
- FRR reload runs with a 15 s context timeout to keep `systemctl reload
  frr` from hanging. The systemd unit has `TimeoutStopSec=20` as a safety
  net.
- HA fail-closed shutdown clears `rg_active` and watchdog state through the
  runtime HA controller under one daemon-owned deadline. Controller
  implementations may have their own RPC deadlines, but daemon shutdown does
  not wait past the outer deadline for those calls to return.
- lo0 input filters (`interfaces lo0 unit 0 family inet[6] filter input
  <name>`) lock down host-bound/control-plane traffic via an nftables table
  `inet xpf_lo0`. `daemon_nft.go:applyLo0Filter` builds the table with
  `buildLo0FilterPayload` and feeds it to `nft -f -`. nft parses an `-f -`
  payload **atomically** — a syntax error on any line rejects the ENTIRE
  payload (the filter then fails OPEN, logging only a `slog.Warn`). The
  payload MUST therefore reset the prior table with the valid atomic idiom:
  `table inet xpf_lo0` (create-if-absent, no body — idempotent) +
  `flush table inet xpf_lo0` + the redefined table. Do NOT use
  `flush ruleset inet xpf_lo0`: `flush ruleset` takes at most an OPTIONAL
  family (`flush ruleset [<family>]`), never a table name — appending one is
  an nft parse error that silently dropped the whole filter (#2069).
  `TestLo0FilterPayloadNftParses` parse-checks the real payload with
  `nft -c -f -` when nft is on PATH.

## RPM + ip-monitoring wiring (#1827)

- `daemon_rpm.go` — config-hash-gated RPM probe lifecycle
  (`reconcileRPM`, applyConfigLocked step 17b): probes + probe-pin
  rules re-apply only when the rendered RPM stanza (or RETH map, or
  the HA gating filter result) changed, so unrelated commits never
  wipe probe state. Also owns the §4.4 HA gating scope
  (`filterRPMForHAGating`).
- `daemon_ipmon.go` — `assembleFRRConfig` (the SOLE `frr.FullConfig`
  constructor, shared by the full apply path and the routes-only
  actuator) + `actuateRouteOverlay` (FRR re-render → snapshot publish
  via `PublishRouteOverlaySnapshot` → `BumpFIBGeneration` ONLY after
  publish success, under `applySem`). The ip-monitoring engine lives
  in `pkg/ipmon`; RG transitions re-evaluate gating via
  `reconcileIPMonGating` from `reconcileRGState`.
