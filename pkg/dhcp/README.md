# pkg/dhcp

DHCPv4 and DHCPv6 clients. Acquires and renews leases on firewall
interfaces and (DHCPv6) delegated prefixes. Persists DUIDs across
restarts so the same client identifier returns to the same lease.
DUID files are DurableState (#1894): `fsatomic.WriteFileDurable`, so a
power cut cannot silently change the client identity across reboot.

## Entry points

- `Manager` — `dhcp.go`.
- `New(stateDir string, onAddressChange, onGatewayChange func()) (*Manager, error)`
  — `dhcp.go`. The `onAddressChange` callback fires (debounced 2 s)
  when any client's lease **content** changes — address, gateway, DNS,
  or delegated prefixes; not on a content-identical renewal (#1777).
  The `onGatewayChange` callback (#1844, nil-able) fires —
  undebounced, always outside `m.mu` — on gateway-relevant lease
  state changes only: first lease committed, gateway delta on a
  commit (strictly narrower than `onAddressChange`), or lease-record
  removal in `finishClient` (every terminal client exit). It is an
  immutable constructor argument, never a setter — client goroutines
  read it outside `m.mu`, so mutation on a live manager would be a
  data race. Consumer: the ip-monitoring engine's
  `NotifyNextHopChange` (interface-typed preferred-route next-hops).
- `Lease` — `dhcp.go`. Result of one DHCP negotiation.
- `DelegatedPrefix` — `dhcp.go`. From DHCPv6 PD.
- `ClientSpec` — `reconcile.go`. One desired client derived from
  config (interface, family, options). Config identity only — never
  lease/address state.
- `Reconcile(specs []ClientSpec)` — `reconcile.go`. Converge running
  clients with the desired set (#1793): start missing clients, stop
  removed ones, restart clients whose option identity changed. Called
  by the daemon on every config apply.
- `Start(ctx context.Context, ifaceName string, af AddressFamily)` —
  `dhcp.go`. Spawn a per-interface client goroutine.
- `Renew(ifaceName string) error` — `dhcp.go`.
- `StopAll()` — `dhcp.go`.
- `DelegatedPrefixes() []DelegatedPrefix` — `dhcp.go`.

## Reconcile lifecycle (#1793)

The daemon calls `reconcileDHCPClients` from `applyConfigLocked` on
every commit/apply, so enabling `family inet { dhcp; }` / `family inet6
{ dhcpv6; }` on a running daemon starts a client, and deleting the
stanza stops it — Junos apply-on-commit semantics, not boot-time-only.
The DHCP `Manager` is created lazily on first need; a startup config
without DHCP no longer disables DHCP for the daemon's lifetime.

- **Diff key is config identity**: (interface, family, client options
  including DHCPv6 `stateless` and DUID type), captured as a
  fingerprint when the client starts. An option change on the same
  (interface, family) stops the old client and starts a new one
  (options are read at goroutine start, so a restart is required).
- **Never keyed on lease state**: lease changes fire `onAddressChange`,
  which re-enters the daemon's `applyConfig` and thus `Reconcile`. If
  the diff observed lease/address state, every lease event would
  restart its client and loop forever. There is a regression test
  proving a lease change does not restart clients
  (`TestReconcileLeaseChangeDoesNotRestart`).
- **Stop semantics**: an explicit stop cancels the client's context,
  stops renewals, and removes the leased address from the interface.
  No protocol RELEASE is sent — matching interface-deconfiguration
  behavior elsewhere in the daemon.
- **Registry hygiene**: the run goroutine deregisters itself (and
  cleans residual lease/address state) in a defer on every exit path —
  cancellation, DHCPv4 max-retransmissions, DHCPv6 link-local abort —
  so a dead client can never permanently block a future `Start` for
  the same key.

## Renewal semantics (#1777, RFC wire renewal #2994)

> Wire behavior (#2994): T1/T2 now run the RFC-correct renewal exchange,
> not a full re-acquisition. At T1 the v4 client sends a unicast
> RENEWING `DHCPREQUEST` to the granting server (ciaddr = held address,
> no DISCOVER) and the v6 client sends a `RENEW` echoing the held IA_NA /
> IA_PD with the server's DUID; at T2 the v4 client broadcasts a
> REBINDING `DHCPREQUEST` and the v6 client multicasts a `REBIND` (no
> server DUID). Only lease expiry (both renew and rebind failed) falls
> back to a full DISCOVER / SOLICIT. This supersedes the pre-#2994
> force-DORA / Rapid-Solicit-at-every-T1 behavior (the old #1832 review
> note), which broadcast a fresh server-selection every renewal and
> could move the lease to a different server, churn the address (and
> therefore interface-DDNS / FRR routes / ip-monitoring), and double the
> WAN DHCP traffic.

Acquisition and renewal share one commit path, `commitLease`
(`commit.go`): remove the old address if the server moved us, apply the
new address, store the lease (and DHCPv6 delegated prefixes), and fire
the debounced `onAddressChange` callback when content changed.

- **Successful T1 renew / T2 rebind is committed**, and the run loop
  returns to the T1 wait with timers recomputed from the renewed
  lease. Pre-#1777 the renewal result was dead-assigned and the loop
  re-entered a full DORA / Solicit, discarding the renewal (changed
  DNS, delegated prefixes) and doubling the DHCP traffic.
- **Wire renewal (#2994)**: the run loop drives an
  `acquire → renew → rebind → re-acquire` exchange-mode state machine
  (`dhcpExchangeMode` in `dhcp.go`; wire builders `buildV4RenewRequest`
  / `v4RenewDest` / `buildV6RenewMessage` in `renew.go`). The server
  identifier (v4 option 54) and server DUID (v6) are captured on the
  granting reply and stored on the (unexported) `Lease.serverID` /
  `Lease.v6ServerDUID` fields so a later RENEW can target the original
  server. DHCPv6 stateless mode has no binding, so every refresh stays
  an Information-Request regardless of mode.
- **Timeout falls through, NAK abandons (#3956)**: a renew *timeout*
  (no reply) at T1 falls through to the T2 rebind; a second timeout (or
  a failure to apply the renewed address) falls back to full
  re-acquisition, retaining the old lease and address until then
  (`docs/dns-ownership.md`). A DHCPNAK is different — it is an explicit
  lease REVOCATION (the server reassigned the address or the client
  changed subnets). Per RFC 2131 §4.4.5 a NAK in the RENEWING *or*
  REBINDING state deconfigures the interface immediately
  (`abandonLeaseAfterNAK`: remove the kernel address, drop the lease
  record, fire `onGatewayChange`, then `scheduleRecompile`) and returns
  to INIT — a fresh DISCOVER with no prior lease — rather than keeping
  the revoked address until T2. The `scheduleRecompile` is what makes
  "immediately" cover the FRR default/classless routes too, not just the
  kernel address: those routes are re-rendered only by `applyConfig`
  (#4874 A2). `doDHCPv4` wraps the sentinel `errDHCPNAK` on a NAK reply so the
  run loop distinguishes the two via `errors.Is`. A malformed/unmatched
  timeout renew is therefore still fail-safe (degrades to the previous
  full-acquisition path), and an explicit revocation is honored at once.
- **Address moves are re-acquisition-equivalent**: if a renewal returns
  a different address, the old one is removed and the new one applied
  via the same netlink mechanisms the fresh-acquisition path uses.
- **Content-unchanged renewals are silent**: the callback re-enters the
  daemon's `applyConfig` (full recompile) and thus `Reconcile`; firing
  it on every T1 interval would recompile the dataplane periodically
  for nothing. `Reconcile` keys on config identity (never lease state),
  so a fire is never a restart-loop hazard — only recompile churn.
  An IA_PD reply with **no prefixes** (silence) retains previously
  delegated prefixes and does not count as a change (the #1844
  anti-outage rule). A prefix returned with **valid-lifetime 0** is an
  RFC 8415 §12.1 *withdrawal*, not silence: `reconcileDelegatedPDs`
  removes it from the held set per-prefix (`(prior \ withdrawn) ∪ live`,
  never a blunt clear-all) so it is neither stored nor re-advertised, and
  fires the recompile so the RA sender drops it (#4874 B). See the
  zero-lifetime IA_PD note under Gotchas.
- The decision logic is concentrated in `commitLease` / `renewalTimers`
  / `leaseContentChanged` / `delegatedPrefixesChanged` and pinned by
  `commit_test.go`. The run-loop state machine itself (the
  acquire→renew→rebind→re-acquire transitions and lease preservation)
  is exercised through the `doV4ExchangeForTest` / `doV6ExchangeForTest`
  / `afterForTest` / `waitLinkLocalForTest` seams (#2994), which replace
  the real socket exchange and the 30 s T1 wait so a test drives the
  real `runDHCPv4` / `runDHCPv6` without traffic — see `renew_test.go`.
  The wire builders (`buildV4RenewRequest`, `v4RenewDest`,
  `buildV6RenewMessage`) are pure and unit-tested directly.

## Callers

`pkg/daemon` (lifecycle: `reconcileDHCPClients` in
`daemon_dhcp.go`, invoked from `applyConfigLocked` step 7b and once at
startup after dataplane load).

## Dependencies

External only: `github.com/insomniacslk/dhcp`, `github.com/vishvananda/netlink`.

## Gotchas

- Each DHCP client uses `context.Background()`, not the daemon context.
  On graceful SIGTERM the daemon exits without calling `StopAll()`,
  intentionally leaving the lease in place so the next daemon process
  reuses it (no DAD storm, no DHCP renew at startup). Only an explicit
  stop — `Reconcile` removal/option change, `Renew`, `StopAll` —
  cancels a client.
- The lease-change callback is debounced 2 seconds to avoid floods during
  config apply.
- DUID is cached per-interface in the state directory with type hints
  (`duid-ll`, `duid-llt`).
- The DHCP client owns the address. `pkg/networkd` deliberately skips
  address reconciliation on DHCP-marked interfaces.
- DHCP-learned default routes go into FRR with admin distance 200 — lower
  priority than static routes, so a configured static default wins.
- **DHCPv6 IA_NA holds one address, selected deterministically** (#4383):
  a reply may carry multiple IAADDR options within an IA_NA (and multiple
  IA_NA options), but xpf's `Lease` model installs a single `/128`.
  `selectIANAAddress` (`dhcp.go`) chooses one — it skips any IAADDR whose
  valid-lifetime is 0 (an expired/declined address, RFC 8415 §12.1;
  ties into F-264), then prefers the longest preferred-lifetime,
  tie-broken by first-seen (option order). `lease.LeaseTime` is paired
  with the CHOSEN address's own valid-lifetime, never a stale value from
  a different IAADDR. This replaced a last-wins overwrite that installed
  whichever address enumerated last. Pinned by `dhcpv6_iana_test.go`.
- **DHCPv6 zero-valid-lifetime IA_PD is a withdrawal, not a lease** (#4874
  B, RFC 8415 §12.1). Symmetric to the IA_NA skip above:
  `extractDelegatedPrefixes` partitions a reply's prefixes into *live*
  (valid-lifetime > 0) and *withdrawn* (valid-lifetime 0); the withdrawn
  ones are never stored or re-advertised. Before the fix a server that
  revoked an IA_PD by returning it with valid-lifetime 0 (while renewing
  the IA_NA) had the zeroed prefix stored, kept by
  `DelegatedPrefixesForRA`, and re-advertised at the RA sender's 30-day
  valid / 7-day preferred defaults. `reconcileDelegatedPDs` applies
  per-prefix withdrawal semantics — `(prior \ withdrawn) ∪ live`, an
  absent/empty IA_PD stays on the retain path (silence ≠ withdrawal), a
  co-held prefix the reply merely omitted is retained — and the run loop
  updates `committedPDs` to the reconciled set so the next RENEW does not
  echo the withdrawn prefix and invite a re-grant. On acquire, a reply
  that yields no IA_NA address and no *live* prefix (only withdrawn PDs)
  is an acquisition failure and is retried, never settled into an empty
  1h lease — counted regardless of `wantNA` so a PD-only client cannot
  fall through. Pinned by `dhcp_lease_expiry_4874_test.go`.
- **RFC 3442 classless static routes (option 121 / legacy 249, #4118).**
  `leaseFromACKv4` parses option 121 (the standard `ClasslessStaticRoute`
  accessor) and falls back to the legacy Microsoft option 249 (raw
  `GenericOptionCode(249)` decoded with the identical
  `{mask-length, significant-prefix-octets, gateway}` encoding). Per RFC
  3442 **precedence, option 121/249 SUPERSEDES option 3**: when it is
  present the client MUST ignore the option-3 Router default entirely.
  The `0.0.0.0/0` entry (if any) in the option supplies `lease.Gateway`
  (so every existing gateway consumer — FRR default route, neighbor
  resolution, ip-monitoring next-hop — is unchanged); every more-specific
  route lands on `lease.ClasslessRoutes`. When option 121/249 is absent
  the client falls back to option 3 exactly as before. The classless
  routes are programmed through the same paths as the default route:
  `collectDHCPRoutes` emits one `frr.DHCPRoute` per route (with a
  non-empty `Destination`), `renderDHCPDefaults` writes
  `ip route <dest> <gw> [<iface>] 200` — and the static-default
  suppression applies ONLY to the default route, never to the
  more-specific classless routes — and `applyMgmtVRFRoutes` installs them
  into the management VRF table (999) via netlink. `leaseContentChanged`
  diffs `ClasslessRoutes`, so the routes are withdrawn/re-installed in
  lock-step with the lease on renew/expiry, like the default route. For
  the management VRF the withdrawal is enforced by a full RECONCILE, not
  an append-only apply (#5108): every route xpf installs in table 999 is
  stamped `RTPROT_DHCP`, and each `applyMgmtVRFRoutes` run lists the
  xpf-owned routes already in the table and `RouteDel`s any whose
  destination is no longer in the current desired set — including the
  empty-desired case (management lease disabled, or option-121 route
  withdrawn), which the pre-#5108 early-return skipped, leaving a stale
  route that could blackhole management traffic to a prior DHCP router.
  The delete is scoped to `RTPROT_DHCP` so operator routes in the VRF are
  never touched.
- **Lease records are NOT expired by the wall clock.** During a
  *timeout-driven* failed re-acquisition (T2 rebind timed out, fresh
  DORA in progress) the lease record and the kernel address
  intentionally persist until replaced — consumers (FRR DHCP routes,
  ip-monitoring resolved next-hops) keep the last-known gateway. This
  deliberately diverges from RFC 2131 §4.4.5 for the *timeout* case (an
  expired lease should stop being used). An explicit **DHCPNAK is
  honored** (#3956): it deconfigures immediately via
  `abandonLeaseAfterNAK` — see "Timeout falls through, NAK abandons"
  above. **Coupling rule (#1844, extended #4874 A2):** any lease-record
  removal (the NAK path, the `finishClient` max-retransmission/terminal
  exit, and, if clock expiry is ever implemented, that path too) MUST
  route through a path that fires **both** `onGatewayChange` AND
  `scheduleRecompile` (`finishClient` and `abandonLeaseAfterNAK` both do).
  `onGatewayChange` alone only marks the ip-monitoring overlay dirty; the
  base DHCP default/classless routes (from `Leases()`) and the v6 RA
  prefix (from `DelegatedPrefixesForRA()`) are re-rendered ONLY by
  `applyConfig`, which the debounced `scheduleRecompile` drives — so
  without it a terminal exit removes the address but leaves the FRR route
  + RA prefix stale until an unrelated commit (indefinitely on the
  `finishClient` max-retransmission exit, which does not run from an
  `applyConfig`). The ctx.Done cancellation exits already delete the
  record inline and are re-rendered by their surrounding `applyConfig`
  (Reconcile) or the following re-acquire (Renew), so `finishClient`
  fires the recompile only when a lease record actually remained.
- **Degenerate subnet mask is refused (#4101, untrusted input).**
  `leaseFromACKv4` validates option 1 after `net.IPMask.Size()`: a zero
  mask (`0.0.0.0` → `Size()` returns `ones=0`) or a non-contiguous mask
  (`255.255.0.255` → `(0,0)`) is rejected with an error instead of
  producing a `YourIP/0` lease. Without the guard the kernel would install
  an on-link `0.0.0.0/0` connected route on the DHCP interface and
  blackhole/hijack all IPv4 forwarding — a rogue or broken server could
  force this with a single crafted ACK. The rejection propagates through
  `v4Exchange` → `runDHCPv4`, which retries a fresh DISCOVER on acquire (no
  address ever installed) or falls through to T2/expiry keeping the current
  valid lease on renew/rebind. A missing option 1 still falls back to `/24`;
  only a *present-but-degenerate* mask is refused. Valid prefixes including
  `/31` and `/32` (point-to-point / host leases) are accepted.
