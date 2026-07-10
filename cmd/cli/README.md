# cmd/cli

Standalone Junos-style CLI client. Connects to xpfd's gRPC API and runs
the same readline / tab-completion / `?`-help experience as the
daemon-local CLI.

## Entry

`main.go` parses flags, dials the gRPC API (see `dialOpts`), and hands
control to the shared `pkg/cli` engine.

The dial raises the client `MaxCallRecvMsgSize` to
`configstore.MaxConfigSize` + 1 MiB of framing headroom
(`maxConfigRecvBytes`), so a `show configuration` for a config up to the
store's 16 MiB ceiling can be displayed. grpc-Go's 4 MiB default receive
cap would otherwise truncate a large config with `ResourceExhausted`
(#5321). Tracking the store const keeps the two bounds from drifting.

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

## Interactive loop & signals

The interactive session runs two goroutines against one `ctl`:

- the **main loop** (`main.go`) reads a line, dispatches it, and owns all
  configuration-mode transitions — `configure` enters, `exit`/`quit` and
  EOF (Ctrl-D) leave;
- the **SIGINT goroutine** (`runSignalLoop`) handles Ctrl-C: it cancels a
  running command, and on a second Ctrl-C within 2 s tears the session
  down, issuing `ExitConfigure` first if still in configuration mode so
  the daemon-side config lock is released.

Both goroutines touch `ctl.configMode`, so it is an `atomic.Bool`
accessed only via `Load`/`Store` (#5053). A plain `bool` let the SIGINT
read race the main loop's write; a Ctrl-C landing during a mode
transition could observe stale state and skip the `ExitConfigure`
cleanup. The teardown paths that run without a cancellable command
context (SIGINT, EOF, and the post-loop exit) call `ExitConfigure`
through `exitConfigureBounded`, whose context is time-bounded
(`exitConfigureTimeout`) so a wedged daemon cannot hang Ctrl-C cleanup
or block process exit.

## Operational notes

- Output streams over gRPC. There's no separate SSH / Telnet layer —
  authentication is by gRPC peer credentials.
- `| match <pattern>` filtering is client-side; the server sends full
  output. (Junos pipes are simulated this way.)
- Some lab VMs have a stale `/usr/local/sbin/cli` that shadows the
  current `/usr/local/bin/cli` via `PATH`. If a deploy looks correct
  but the CLI behavior is stale, delete the `sbin` copy.
