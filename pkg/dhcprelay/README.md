# pkg/dhcprelay

RFC 3046 DHCPv4 relay agent. Forwards DHCP between clients on local
interfaces and remote servers, inserting Option 82 with `circuit-id` set
to the interface name.

## Entry points

- `Manager` — `relay.go`.
- `NewManager()` — `relay.go`.
- `Apply(ctx context.Context, cfg *config.DHCPRelayConfig)` — `relay.go`. Starts/stops per-interface relay
  goroutines.
- `Stats()` — `relay.go`. Per-interface counters.
- `RelayStats` — `relay.go`.

## Callers

`pkg/daemon`.

## Dependencies

`pkg/config` only.

## Socket / lifecycle model (#1915)

- **Per-interface listener on `0.0.0.0:67`.** Each interface in a relay
  group gets its own client-facing UDP listener bound to the wildcard
  `0.0.0.0:67`. Multiple listeners coexist via `SO_REUSEADDR` +
  `SO_REUSEPORT` set **before** `bind(2)` (idiomatic
  `net.ListenConfig.Control`, mirroring `pkg/cluster` `vrfListenConfig`).
  Without REUSEPORT the second interface's bind would fail `EADDRINUSE`
  and only the first interface would be served.
- **`SO_BINDTODEVICE` is a hard invariant on every client listener.** The
  kernel discards BINDTODEVICE-mismatched sockets *before* the REUSEPORT
  load-balancing fanout, so each listener only receives its own
  interface's ingress traffic — REUSEPORT does **not** cause duplicate or
  cross-interface relaying. A client listener without BINDTODEVICE would
  join the REUSEPORT group unfiltered and steal other interfaces' packets.
- **`SO_BROADCAST` on the client listener** so broadcast OFFER/ACK replies
  to `255.255.255.255:68` are delivered (Linux returns `EACCES` on a
  limited-broadcast `sendto` without it). The server conn (bound to
  `giaddr:0`) sets none of these — it has a unique ephemeral port.
- **Bounded, deterministic `Stop()`.** Reads use the blocking
  `net.PacketConn.ReadFrom`; a close-on-cancel watcher (started after both
  conns exist) closes BOTH conns when the relay context is cancelled, so a
  blocked read returns `net.ErrClosed` immediately. The server-response
  goroutine is tracked with a `WaitGroup` and joined before the relay's
  `done` channel closes, so `Stop()` (and the `Stop()` inside `Apply()`) is
  a true join with no packet-dependent wait and no goroutine leak across
  `Apply`/`Stop` cycles. Both loops cancel the shared context on exit so a
  one-sided error cannot wedge the join.
- **Startup readiness retry.** `Apply` runs once at daemon boot. If an
  interface is not yet ready (no IPv4 address, or a dynamic VLAN/tunnel not
  yet created), the relay retries resolving the interface + giaddr on a
  bounded, `ctx`-cancelable interval instead of dying permanently. The
  interface is re-looked-up every attempt (no stale cached index).

## Gotchas

- The interface must have an IPv4 address — that's what fills `giaddr`. If
  it is missing at boot the relay retries (see above) rather than failing.
- Option 82 sub-option 1 (`circuit-id`) is set to the interface name; on
  the reply path it's stripped before forwarding to the client.
- Server addresses must be **literal IPs**. `Apply()` calls
  `net.ParseIP` and rejects hostnames; there is no DNS resolution
  path. To target a hostname, the operator must resolve it externally
  and put the IP in the config.
- **Kea / dhcp-relay coexistence on `:67`.** The Kea DHCP server
  (`pkg/dhcpserver`) and this relay are operationally mutually exclusive on
  a given interface's `:67` — Kea does not set REUSEPORT/BINDTODEVICE, so
  configuring both to bind the same port leaves one failing to bind. A
  commit-check that rejects this is a deferred follow-up.
- **VRRP-Backup duplicate relay (HA).** On a chassis cluster, a relay
  running on a VRRP **Backup** node also receives segment broadcasts and
  would relay duplicate requests. DHCP tolerates this (servers dedupe on
  xid + chaddr; clients dedupe offers), so it is an acceptable interim;
  suppressing forwarding on Backup is a deferred follow-up gated on
  `make test-failover`.
