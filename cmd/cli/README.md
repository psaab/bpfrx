# cmd/cli

Standalone Junos-style CLI client. Connects to xpfd's gRPC API and runs
the same readline / tab-completion / `?`-help experience as the
daemon-local CLI.

## Entry

`main.go` parses flags, dials the gRPC API, and hands control to the
shared `pkg/cli` engine.

## Flags

- `-addr` — gRPC server address. Default `127.0.0.1:50051`.
- `-c "<command>"` — single-command, non-interactive mode. Exits with
  the command's status. Useful for scripted operations.

## Tab completion

Driven by the gRPC `Complete` RPC, which lowers the same `pkg/cmdtree`
tree the daemon uses. Adding a command in `pkg/cmdtree/tree.go` shows up
here and in the daemon-local CLI without changes here.

## `show` command layout

The remote-CLI `show` umbrella was historically one ~2100-line
`show.go` grab-bag. It is split by feature family into sibling files in
this package (#4660) so local-vs-remote parity review is tractable
per feature. `show.go` keeps only the top-level `handleShow` dispatcher,
the config-mode `handleConfigShow`, and the shared text-proxy helpers
(`showText` / `showTextFiltered` / `showSystemInfo`). The per-feature
handlers live in:

- `show_security.go` — `show security` zones / policies / screen /
  match-policies / statistics / log / vrrp / ike / ipsec renderers.
- `show_flow.go` — `show security flow session` parse + render + summary,
  plus flow statistics.
- `show_nat.go` — `show security nat` source / destination renderers.
- `show_interfaces.go` — `show interfaces`.
- `show_protocols.go` — `show protocols` ospf / bgp / bfd / rip / isis.
- `show_system.go` — `show system` commit / rollback / uptime / ...
- `show_services.go` — `show services` rpm / ip-monitoring / app-id / ddns.
- `show_dhcp.go` — `show dhcp` leases / client-identifier.

The split is pure code motion. All handlers moved verbatim; the gRPC
call sequences and the text-proxy fallthrough are preserved so the
remote CLI output stays bit-identical to before.

## Operational notes

- Output streams over gRPC. There's no separate SSH / Telnet layer —
  authentication is by gRPC peer credentials.
- `| match <pattern>` filtering is client-side; the server sends full
  output. (Junos pipes are simulated this way.)
- Some lab VMs have a stale `/usr/local/sbin/cli` that shadows the
  current `/usr/local/bin/cli` via `PATH`. If a deploy looks correct
  but the CLI behavior is stale, delete the `sbin` copy.
