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
- **Cancellable apply at coarse boundaries (#2926, follow-up to #2914/#2868).**
  `applyConfigLocked(ctx, cfg)` checks `ctx.Err()` at three phase boundaries and
  returns the ctx error at the next one rather than completing the netlink + FRR
  reload + Rust control-socket sync: **C1** before the netlink reconcile phase
  (step 0), **C2** before the dataplane apply / Rust sync push (step 2), and
  **C3** before the FRR reload (step 3). The checks sit only at boundaries where
  bailing leaves a consistent, restart-recoverable state — each major
  side-effecting phase (and the RETH MAC / VIP / worker-rebind sequence between
  C2 and C3) runs to completion once started, so the apply is never interrupted
  mid-phase; on the next boot the boot-time apply re-runs the whole pipeline
  against the active config, so a skipped tail converges. The cancellation
  signal is a **dedicated daemon-stop** context (`applyCancelCtx` →
  `d.applyCancelContext`), *not* the request/commit context: a daemon stop
  aborts an in-flight commit/remediation apply (the eventengine remediation path
  that #2914 made cancellable only at the pre-semaphore wait), but a mere request
  cancellation (HTTP/gRPC client disconnect) is deliberately ignored after
  `store.Commit` — aborting a promoted commit on a still-running daemon would
  leave the store ahead of the dataplane/FRR with no automatic re-apply to
  converge. The boot / DHCP / feed applies (`applyConfig`) and the
  confirmed-rollback re-apply (`executeConfirmedRollback`) pass a non-cancellable
  `context.Background()` so they always complete.
  - **Wiring (the part that makes this actually fire on `systemctl stop`).**
    `applyCancelCtx` deliberately does **not** return `d.daemonCtx`. In
    production `cmd/xpfd` passes `context.Background()` into `Run`, and that
    `context.Background()` is what `d.daemonCtx` holds — it is never cancelled
    (the signal-cancellable context is a *local* `ctx` created later by
    `signal.NotifyContext`). Returning `d.daemonCtx` would make C1/C2/C3 dead
    code on a real stop. Instead `Run` creates `d.applyCancelContext` as a
    **child of the SIGTERM/SIGINT signal context** (right after
    `signal.NotifyContext`), so a real `systemctl stop xpfd` cancels it, and the
    next coarse boundary observes `ctx.Err() != nil` and bails. `d.daemonCtx`
    stays the (uncancelled) parent of the long-lived background goroutines —
    flow-export/IPFIX relays, RPM probe-pin retry, the policy scheduler, cluster
    comms, and the `dp.Start` dataplane runtime. Those are torn down
    **explicitly** in the shutdown sequence, and the orderly teardown
    (`logFinalStats` through `dp.Telemetry`, the HA `rg_active` clear through
    `dp.HA()`, `dp.Teardown`) still needs the dataplane runtime live while it
    runs — which is why the apply-abort signal is isolated from `d.daemonCtx`
    rather than cancelling it. `Run` cancels `d.applyCancelContext` at the very
    start of the shutdown sequence (before the explicit subsystem teardown), and
    the teardown itself performs no `applyConfigLocked`, so the cancel aborts
    only a genuinely in-flight commit/remediation apply, never the shutdown's own
    cleanup.
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
  `buildLo0FilterPayload` and feeds it to `nft -f -` (via the `nftApplyPayload`
  seam). nft parses an `-f -` payload **atomically** — a syntax error on any
  line rejects the ENTIRE payload (the kernel keeps the PREVIOUS table
  untouched, not a half-applied ruleset). The payload MUST therefore reset the
  prior table with the valid atomic idiom: `table inet xpf_lo0`
  (create-if-absent, no body — idempotent) + `flush table inet xpf_lo0` + the
  redefined table. Do NOT use `flush ruleset inet xpf_lo0`: `flush ruleset`
  takes at most an OPTIONAL family (`flush ruleset [<family>]`), never a table
  name — appending one is an nft parse error that silently dropped the whole
  filter (#2069). `TestLo0FilterPayloadNftParses` parse-checks the real payload
  with `nft -c -f -` when nft is on PATH.
  **Distinct hook-input priority (#3364):** `xpf_lo0` registers `type filter
  hook input priority 0` (`nftLo0FilterPriority`) and `xpf_hostinbound`
  registers the same hook at `priority 10` (`nftHostInboundPriority`). Two base
  chains on the SAME hook at an IDENTICAL priority have implementation-defined
  inter-chain evaluation order, so which chain's reject/log/counter fires for a
  packet both match would be order-dependent (a `drop` stays terminal regardless,
  so this was never a permit bypass — only an observability/determinism gap). The
  spread makes `xpf_lo0` evaluate STRICTLY BEFORE `xpf_hostinbound`: the lo0.0
  input filter is the operator's explicit, named, RE-wide control-plane firewall
  (authoritative accept/reject/discard verdicts), so it takes observable
  precedence over the coarser zone host-inbound default-deny backstop — the Junos
  lo0-filter-then-zone ordering. `nft_chain_priority_test.go`
  (`TestNftLocalDeliveryChainsDistinctPriority` /
  `TestNftLocalDeliveryPriorityConstantsOrdered`) pins
  `nftLo0FilterPriority < nftHostInboundPriority` and goes RED if the two are
  equalized.
  **Fail-closed (#3392, mirroring host-inbound #3333):** `applyLo0Filter`
  RETURNS the apply/teardown error instead of swallowing it at WARN, and
  `applyConfigLocked` joins it (`lo0Err`) into the commit result alongside
  `networkdErr`/`dhcpServerErr`/`hostInboundErr`, so a committed lo0 filter that
  did not reach the kernel reports commit FAILURE rather than silent success.
  The teardown (no filter bound) uses the idempotent `add table; delete table`
  payload via `nftDeleteTable` (universal verbs — NOT the unpinned `nft
  destroy`), so the benign absent-table case is a no-op while a genuine teardown
  failure (stale filter left in the kernel) still surfaces. Boot / DHCP
  re-applies go through `applyConfig`, which only LOGS the error, so a transient
  nft failure cannot brick startup; the next clean commit re-renders. Tests:
  `lo0_filter_test.go` (apply/teardown failure-surfaced fail-on-revert,
  success-no-error, idempotent add+delete teardown) and
  `daemon_apply_runtime_test.go:TestApplyConfigLockedSurfacesLo0Failure` (the
  commit-level `errors.Join` wiring proof).
  **Per-term disposition mirrors userspace (#3427):** `nftRuleFromTerm` maps a
  term's `then` action to the kernel verdict the SAME way the userspace lo0
  evaluator does (`pkg/dataplane/userspace/filters.go` `NextTerm =
  (term.NextTerm || term.Action == "") && term.RoutingInstance == ""`). A term
  with NO terminating action is a Junos FALL-THROUGH (explicit `then next term`
  or a modifier-only term carrying only count/log/forwarding-class/dscp): it
  emits NO rule (the kernel chain mirrors no counters/log, so the term has no
  enforcement effect) and the subsequent terms run. The pre-fix code mapped an
  empty action to a terminating `accept`, which SHADOWED every later
  discard/reject term — a control-plane fail-OPEN diverging from userspace
  (`from protocol tcp then next term` followed by `from destination-port 22 then
  discard` accepted SSH at term 1, leaving the drop unreachable). A
  `routing-instance` (PBR) term is explicitly NOT a fall-through: userspace sets
  `continue_term=false` when `routing_instance` is non-empty and the evaluator
  TERMINATES the matched term, returning its action — the empty-action
  placeholder `Accept` — so the packet is ACCEPTED. The kernel lo0 input chain
  cannot perform route-selection, but the filter VERDICT is accept, so it emits
  a TERMINATING `accept` (mirroring userspace); it must NOT be skipped, because a
  skip lets a later deny term match and OVER-DROP legitimate host traffic on the
  kernel-primary lo0 chain. Userspace stays authoritative for the actual
  route-selection. Pinned by `TestNftRuleFromTermFallThroughNoBareAccept`,
  `TestNftRuleFromTermRoutingInstanceTerminatesAccept`, the end-to-end
  `TestLo0PayloadFallThroughDoesNotShadowDiscard`, and
  `TestLo0PayloadRoutingInstanceTerminatesAcceptNoOverDrop` (the over-drop
  counterexample).

  **Address / prefix-list lowering mirrors userspace (#3433):**
  `nftRuleFromTerm` lowers each direction's `source-address` /
  `destination-address` + `source-prefix-list` / `destination-prefix-list`
  scope through the SHARED userspace resolver
  (`dpuserspace.ResolveFilterPrefixListAddrs`) so the kernel mirror uses the
  EXACT empty-set / except / positive-wins / `any`-no-constraint semantics of
  the userspace matcher (`filters.go` + `userspace-dp` `filter/engine/matching.rs`
  `nets_match_v4/v6`). `nftAddrPredicate` then family-filters the resolved set
  for the chain's family and renders the predicate. The replaced raw string
  concatenation diverged on every one of these shapes (codex-094 H01-H05/H09):
  a positive literal `any` is no constraint (match ALL, NOT the unloadable
  `ip saddr any`); a constrained-but-empty POSITIVE scope (defined-empty or
  lenient-unresolved prefix-list, all-malformed literal, or a wrong-family
  literal such as a v4 CIDR in an inet6 filter) matches NOTHING — the rule is
  SKIPPED (a term that matches nothing has no enforcement), fail-CLOSED rather
  than the pre-fix "no predicate -> match ALL sources" fail-OPEN; an empty
  EXCEPT scope is match-all (no predicate); a non-empty except is the nft
  negated set `saddr != { ... }`; and a leniently-loaded MIXED positive+except
  in one direction is positive-wins (the except side is dropped, never folded —
  mirroring `resolvePrefixListAddrs`, hard-rejected at commit by #3359). A
  malformed or wrong-family literal is also an operator-visible commit error
  (`validateFilterAddressLiteralsStrict`, lenient-downgraded on the peer-sync /
  load path — #1960 no-brick). Pinned by `TestNftRuleFromTermAddressSemantics3433`,
  `TestNftRuleFromTermWrongFamilyMatchesNothing`, and (config side)
  `firewall_address_literal_3433_test.go`.

  **ICMP type/code lowering mirrors userspace (#3483):** `nftRuleFromTerm`
  renders `icmp-type` and `icmp-code` as INDEPENDENT predicates, each gated
  only on its own value list — `icmp[v6] type <set>` when `len(ICMPTypes) > 0`
  and `icmp[v6] code <set>` when `len(ICMPCodes) > 0` (family selects `icmp`
  vs `icmpv6`). This matches both userspace projections: `filters.go` emits
  `ICMPCodes` gated only on `len > 0`, and the Rust matcher tests
  `icmp_code_match_enabled` in a block separate from `icmp_type_match_enabled`.
  The pre-fix nft mirror nested the code predicate inside
  `if len(term.ICMPTypes) > 0`, so a code-only term (`from protocol icmp
  icmp-code 4 then discard`, no `icmp-type`) dropped the code match on the
  kernel lo0 path — the kernel mirror then matched BROADER than userspace (a
  `discard` dropped ALL ICMP fail-closed-over-broad, an `accept` admitted ALL
  ICMP fail-open). Pinned by `TestNftRuleFromTermICMPCodeOnly` (v4 + v6 +
  multi-value, code-only) and `TestNftRuleFromTermICMPTypeCode`.

  **Protocol / DSCP lowering normalizes through the shared resolvers (#3436):**
  `nftRuleFromTerm` resolves each `from protocol` token through the shared
  `appid.ProtocolNumber` SSOT (the same resolver the commit gate
  `filterProtocolResolvable` and the userspace matcher `ip_proto.rs` use) and
  emits the NUMERIC nft `l4proto` token (`meta l4proto 47`, set form
  `meta l4proto { 47, 6, 50 }`). It resolves each `dscp` / `traffic-class` token
  through the `dataplane.DSCPValues` SSOT (case-insensitive, numeric 0..63
  pass-through) and emits the numeric `ip[6] dscp` value. The pre-fix code
  emitted both tokens RAW (codex-094 H08/M01): nft does not share the Junos
  alias table — `meta l4proto junos-gre` / `junos-tcp-any` / `ipip` is a parse
  error that rejects the whole atomically-loaded lo0 table (legitimate commit
  broken) or, on the lenient/peer-sync path, leaves the kernel mirror absent
  while userspace stays armed. Likewise nft's DSCP names are lowercase only and
  do not cover every xpf code point — an upper-case `EF` (accepted
  case-insensitively at commit) and `be` (best-effort, which has NO nft name)
  both failed the atomic load. Emitting numeric values is unconditionally
  nft-safe and matches the SAME protocol / code point as userspace. An
  unresolvable token cannot reach a committed config (the commit gate rejects
  it); on the lenient path an unresolvable protocol is dropped with a warning
  (mirroring the tcp-flags lowering) and an unresolvable DSCP token falls back
  to its lower-cased form. Pinned by `TestNftRuleFromTermProtocolAliases`,
  `TestNftRuleFromTermProtocolMultiAliasSet`, `TestNftRuleFromTermDSCP`, and
  `TestNftRuleFromTermDSCPNamesAndCase`.
- host-inbound-traffic (`security zones <z> host-inbound-traffic`) is the
  PRIMARY kernel enforcement for host-bound traffic to a firewall interface IP
  / VRRP VIP (SSH, ping, OSPF/BGP to the box — #3070). Such traffic is shunted
  to the kernel by the XDP shim before reaching userspace-dp, so
  `daemon_nft.go:applyHostInboundFilter` builds an `inet xpf_hostinbound`
  table (same atomic flush idiom as lo0) via `buildHostInboundFilterPayload`,
  consuming `userspace.BuildZoneHostInboundViews(cfg)`. The chain registers
  `type filter hook input priority 10` (`nftHostInboundPriority`) — DISTINCT from
  the `xpf_lo0` chain's `priority 0` so this host-inbound backstop evaluates
  AFTER the operator's explicit lo0 input filter rather than at an
  implementation-defined order relative to it (#3364, see the lo0 bullet). Per
  host-inbound-CONFIGURED zone it accepts the listed system-services/protocols
  to that zone's addresses and DROPs the rest; the userspace-dp LocalDelivery
  check (`forwarding/host_inbound.rs`) is the secondary path for the XSK-reaching
  subset. **Address sources (#3172, #3224):** the per-zone destination address
  set is the de-duplicated union of (a) the live interface snapshot
  (`buildInterfaceSnapshots` -> `AddrList(FAMILY_ALL)`), which carries BOTH static
  `family inet[6] address` config leaves AND DHCP/DHCPv6-learned kernel addresses
  (the snapshot does no scope/flag/dynamic filtering, so a DHCP-addressed WAN's
  learned address IS scoped — the #3224 fail-open premise does not reproduce), and
  (b) RETH VRRP VIPs resolved from config (so the deny is scoped on the backup
  node too, where the VIP is not yet live). SLAAC is not a separate case: xpfd sets
  `IPv6AcceptRA=no` on every managed interface (`pkg/networkd`), so DHCPv6 is the
  only IPv6 dynamic path and the live snapshot captures it. **Refresh:** the chain
  is rebuilt on every commit and on every DHCP/DHCPv6 lease change on a dataplane
  interface (`onDHCPAddressChange` → `dhcpLeaseChangeRequiresRecompile` →
  `applyConfig` → `applyHostInboundFilter`), so a renewed/flapped lease re-scopes
  the deny within one reconcile rather than staying fail-open until the next
  commit. **Lifeline safety:** a zone with NO stanza emits no deny (admit-all);
  management/cluster-control interfaces (fxp0 / em0 / fab*) are excluded from
  the address sets so a host-inbound deny can never strand management or break
  HA; `ct state established,related` and IPv6 ND + v4/v6 PMTUD control messages
  are accepted before any deny; a configured zone that resolves to zero
  recognized matches fails OPEN (no deny) rather than locking the zone out.
  Token→nft mapping (`hostInboundServiceMatches`/`hostInboundProtocolMatches`)
  mirrors the Rust classifier and must stay in sync. **ident-reset (#3310):**
  `system-services ident-reset` is NOT a plain admit — Junos actively RESETS
  inbound ident (auth/TCP-113) probes. Its nft verdict
  (`hostInboundServiceAction`) is `reject with tcp reset` (the first `reject`
  rule in `xpf_hostinbound`), emitted before the catch-all drop, so the kernel
  synthesizes an RFC-correct RST and 113 is NEVER opened to the host. `all` /
  `any-service` precedence wins (a fully-open zone admits 113 and emits no
  ident-reset reject). The Rust AF_XDP secondary path does NOT reset — it simply
  drops 113 (the classifier ident-reset arm contributes nothing to the admit
  set), a documented divergence on the near-nonexistent DNAT/static-NAT-to-113
  path. Tests: `host_inbound_nft_test.go` (accept-listed / deny-rest
  fail-on-revert, no-stanza-no-deny, lifeline-never-denied, `all`-opens-zone,
  ident-reset emits-reset / `all`-suppresses-reset / nft-parse-check),
  `host_inbound_parity_test.go` (ident-reset reject-verdict parity).
  **Counted drops + scrape (#3361):** each per-zone/family catch-all drop is
  `<fam> daddr <addrs> counter name "<n>" drop`, where `<n>` =
  `nftables.HostInboundDenyCounterName(zone, family)` (encoding
  `xpfhi_<family>_<len>_<zone>`, reversible even when the zone name contains
  `_`/`-`). The `<zone>` segment is passed through `sanitizeNftIdent` (maps any
  byte outside the bare-safe nft set `[A-Za-z0-9_.-]` to `_`, length-preserving),
  because the counter is emitted both as a REFERENCE (above, quoted — nft accepts
  it) AND as a DECLARATION. **The DECLARATION is emitted UNQUOTED
  (`counter <n> { }`, #3578):** nft v1.1.6 rejects a quoted name in declaration
  position (`counter "<n>" { }` → `syntax error, unexpected quoted string`),
  which previously aborted the whole atomic `nft -f` load so the host-inbound
  chain never installed. For an exotic zone name carrying nft-unsafe bytes
  (commit blocks only `/`) the sanitized form is what surfaces as the Prometheus
  zone label, and two such zones can collide onto one counter (metric
  aggregation only — DROP rules stay per `(zone, daddr)`). The named counter
  objects are declared at the top of the table body,
  so the table now uses an `add table` / `delete table` / recreate idiom instead
  of lo0's plain `flush table`: `flush` keeps named objects, so redeclaring the
  counters on the next commit would collide ("File exists"). delete+recreate also
  drops a stale counter for a zone that no longer enforces. A consequence is that
  these counters reset to zero on every table rebuild (every commit + every
  DHCP/DHCPv6 address change that re-renders the chain); Prometheus `rate()` reset
  detection handles this. `pkg/nftables.ReadHostInboundDenyCounters()` reads the
  counters back via netlink (no nft shell-out) and the API collector
  (`pkg/api/metrics_counters.go:collectHostInboundKernelDenies`) exports them as
  `xpf_host_inbound_kernel_denies_total{zone,family}` (REST aggregate
  `host_inbound_kernel_denies`). This is the PRIMARY host-inbound enforcement
  path and is DISTINCT from the userspace-dp `xpf_host_inbound_denies_total`
  (`GlobalCtrHostInboundDeny`, #3326) — they are not double counts. Before #3361
  these kernel drops were uncounted and `host_inbound_denies` stayed 0 even while
  the firewall was actively denying control-plane traffic.

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
