# pkg/dhcp

DHCPv4 and DHCPv6 clients. Acquires and renews leases on firewall
interfaces and (DHCPv6) delegated prefixes. Persists DUIDs across
restarts so the same client identifier returns to the same lease.

## Entry points

- `Manager` — `dhcp.go`.
- `New(stateDir string, onAddressChange func()) (*Manager, error)` —
  `dhcp.go`. The `onAddressChange` callback fires (debounced 2 s)
  when any client's lease changes.
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
