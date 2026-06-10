# pkg/dhcpserver

Manages Kea DHCPv4/v6 server config and lifecycle. Generates
`/etc/kea/kea-dhcp{4,6}.conf` from the typed config and reloads the
`kea-dhcp{4,6}-server` units via systemd.

## Entry points

- `Manager` — `dhcpserver.go`.
- `New()` — `dhcpserver.go`.
- `Apply(cfg *config.DHCPServerConfig) error` — `dhcpserver.go`.
  Authoritative reconcile (#1778): for each configured family it
  regenerates the Kea config and restarts the unit; for each
  unconfigured family (including `cfg == nil`) it stops the unit if
  `systemctl is-active` reports it active — even if a PREVIOUS xpfd
  instance started it — and removes the generated config.
  **Fail-closed:** restart failures (and failures to stop an active
  unit that left the config) are returned, so a commit surfaces
  "DHCP server failed" instead of silently succeeding with no
  service.
- `Clear()` — `dhcpserver.go`. Stops both Kea units if systemd
  reports them active and removes config files. Void signature for
  the VRRP-transition callers (`pkg/daemon` HA path); stop failures
  are logged at Warn. Commit-path callers use `Apply(nil)` to get the
  error.
- `IsRunning()` — `dhcpserver.go`. Queries systemd unit state
  (authoritative; survives daemon restarts).
- `Lease` — `dhcpserver.go`. Surfaced to the CLI for `show dhcp
  server leases`.
- `NewManagerForTesting(...)` — `test_seams.go`. Injectable
  `systemctl` seams + config paths, per the `pkg/dhcp/test_seams.go`
  convention.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config` only.

## Gotchas

- Config is regenerated fully on every `Apply()` (no diff). The Kea config
  schema is JSON-based, so this is cheap.
- If the typed config drops the DHCP server entirely, `Apply()` stops the
  service and removes the config file. Running Kea processes are not
  killed via SIGKILL — systemd manages the lifecycle.
- The manager keeps NO process-local running state (#1778). All
  start/stop decisions reconcile against `systemctl is-active`, so a
  stale Kea left over from a previous daemon is stopped on the first
  `Apply`/`Clear` after restart. Every `systemctl` shell-out is
  bounded by a 15s timeout (#1794).
- Commit semantics: in standalone mode `pkg/daemon` calls `Apply`
  unconditionally on every config apply and surfaces its error
  through the commit (fail-closed); the boot path logs the error and
  continues, so an unavailable Kea binary cannot brick daemon boot.
  In cluster mode start/stop with DHCP config present is owned by
  the VRRP MASTER/BACKUP transitions; the apply path only reconciles
  the no-DHCP-config case (stale-unit cleanup, warn-only).
- Lease queries read Kea's CSV lease backends directly:
  `/var/lib/kea/kea-leases4.csv` and `kea-leases6.csv`. No control
  channel / socket call. Missing files yield an empty list, not an
  error.
