# pkg/dhcprelay

RFC 3046 DHCPv4 relay agent. Forwards DHCP between clients on local
interfaces and remote servers, inserting Option 82 with `circuit-id` set
to the interface name.

## Entry points

- `Manager` — `relay.go`.
- `NewManager()` — `relay.go`.
- `Apply(ctx context.Context, cfg *config.DHCPRelayConfig)` — `relay.go`.
  Reconciles per-interface relay goroutines to the desired config (start
  added, stop removed, restart changed, leave unchanged). Called at boot
  AND on every day-2 commit (#2348). A nil `cfg` stops all relays.
- `Stats()` — `relay.go`. Per-interface counters.
- `RelayStats` — `relay.go`.

## Callers

`pkg/daemon`.

## Dependencies

`pkg/config`, `github.com/insomniacslk/dhcp`, and `golang.org/x/sys/unix`
(the last for the AF_PACKET raw-L2 reply socket — see "Reply delivery
model" below). No dependency on other `pkg/*` packages.

## Relayed client message types

The client→server forwarding loop (`runRelay`, gated by
`clientRequestRelayable`) relays every client-originated BOOTREQUEST that
carries server-bound options, per RFC 2131 §3.4:

| Message type | Relayed | Notes |
|--------------|---------|-------|
| `DISCOVER` | yes | lease acquisition |
| `REQUEST` | yes | lease selection / renewal / rebinding |
| `INFORM` | yes (#2153) | client already holds an address, asks only for supplemental parameters (DNS/domain/NTP) |
| `DECLINE` | no | broadcast by the client on address conflict (RFC 2131 §4.4); not relayed (out of scope for #2153) |
| `RELEASE` | no | unicast by the client to its bound server; no relay-agent obligation |
| server reply types (`OFFER`/`ACK`/`NAK`) | n/a | not client-originated; the client→server gate never sees them. The reverse server→client path (`handleServerResponses`) forwards `OFFER` and `ACK` only — see the reply matrix below |

The `INFORM` reply (a server-issued `ACK` with no `yiaddr` but a real
`ciaddr`) is delivered by the matrix below via the "flag clear, `yiaddr==0`,
real `ciaddr`" UDP-unicast row — the client already owns and ARP-answers for
its address.

## Reply delivery model (#2076)

Server replies (OFFER/ACK) are delivered to clients honoring the RFC 2131
§4.1 broadcast flag:

| Condition | Delivery |
|-----------|----------|
| `overrides always-broadcast` set | broadcast `255.255.255.255:68` (operator override wins) |
| broadcast flag **set** | broadcast `255.255.255.255:68` |
| flag **clear**, real `yiaddr` | **raw-L2 unicast** to `chaddr` + `yiaddr` |
| flag **clear**, `yiaddr==0`, real `ciaddr` | UDP-unicast to `ciaddr` (client already owns the IP) |
| flag **clear**, no `yiaddr`/`ciaddr` | broadcast (nothing routable) |
| raw-L2 path unavailable/fails | broadcast fallback (always works) |

**Why raw L2 (`l2send_linux.go`).** A client in SELECTING/REQUESTING that
clears the broadcast flag has **not yet configured** the offered address,
so it will not answer ARP for `yiaddr`. A normal UDP `WriteTo(yiaddr)`
forces the kernel to ARP-resolve `yiaddr`, the ARP goes unanswered, and the
reply is silently dropped — the client never acquires a lease. The relay
therefore builds a full Ethernet+IPv4+UDP frame addressed to the client's
`chaddr` and sends it on an `AF_PACKET`/`SOCK_RAW` socket (the
`pkg/cluster/garp.go` hand-roll pattern). The IPv4 source is the **saved
giaddr** (the same address the server saw in the relayed request); the IPv4
header checksum is computed and the UDP checksum is 0 (legal for IPv4 per
RFC 768).

- **`CAP_NET_RAW` dependency.** The AF_PACKET socket needs `CAP_NET_RAW`,
  already held by the root daemon (same as `pkg/vrrp`, `pkg/lldp`,
  `pkg/cluster/garp.go`). If the socket cannot be opened (e.g. a future
  hardened unit without the cap), the relay logs once and falls back to
  broadcast — it **never regresses to undeliverable**.
- **Guards → broadcast fallback.** Non-Ethernet `htype`, a non-6-byte
  `chaddr`, an over-MTU reply (`20 + 8 + len(payload) > iface.MTU` — the raw
  path cannot fragment), or any `Sendto` error fall back to broadcast.
- **Per-send interface re-resolution.** The ifindex + source MAC are
  re-resolved from `net.InterfaceByName` on every send (`garp.go`
  precedent), so a link flap / dynamic recreate / VRRP `programRethMAC` MAC
  change does not leave a stale ifindex or source MAC. VLAN sub-interface
  egress uses the same netdev index the listener is bound to (the kernel
  applies the `.N` 802.1Q tag).
- **Counters.** `Stats()` exposes a per-reason breakdown
  (`RepliesL2Unicast`, `RepliesUnicastCiaddr`, `RepliesBroadcastFlag1`,
  `RepliesBroadcastForced`, `RepliesBroadcastNoTarget`,
  `RepliesBroadcastL2Fallback`). **`RepliesBroadcastL2Fallback` is the one
  to alert on** — it means the raw-L2 path failed (CAP_NET_RAW, driver, or
  MTU) and the relay degraded to broadcast. `show ... dhcp-relay` prints
  this breakdown.

### `overrides always-broadcast` config

```
set forwarding-options dhcp-relay group <g> overrides always-broadcast
```

Mirrors the Junos knob: forces every reply to broadcast even for
flag-clear clients (the raw-L2 socket is not opened at all when set). This
is the operator escape hatch for environments where the L2 path is
undesirable. Both the block form (`overrides { always-broadcast; }`) and
the flat-set form compile to `DHCPRelayGroup.AlwaysBroadcast`; the flat-set
inline-interface consumer treats `overrides` as a property boundary so it
is not swallowed into the interface list (#2076 / dual-AST harness case
`forwarding-options-dhcp-relay-overrides`).

### IPv6 / DHCPv6 parity

There is **no DHCPv6 relay agent** in the codebase, and DHCPv6 (RFC 8415)
does not have this bug class: it has no BOOTP broadcast flag — clients use a
link-local source and the relay replies to that link-local unicast (or
`ff02::1:2`), so there is no "reply to an unconfigured global address via
ND" failure mode. This fix is strictly DHCPv4.

### HA / VRRP-Backup duplicate delivery

Before #2076, a relay running on a VRRP **Backup** node sent a duplicate
flag-clear reply that was harmlessly lost on ARP failure. Now that the
flag-clear path actually delivers (raw L2 to `chaddr`), a flag-clear client
may receive duplicate OFFER/ACK from both nodes. DHCP clients dedupe on
`xid` + `chaddr`, so this is tolerable; a single node never double-delivers
(L2 success and broadcast are mutually exclusive per reply). Suppressing
relay forwarding on a VRRP-Backup node remains a deferred follow-up (see
below). Changes touching this path must pass `make test-failover`.

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
- **Day-2 reconcile (#2348).** `Apply` is invoked at boot (`daemon_run.go`)
  AND on every commit through `daemon.reconcileDHCPRelay` in the
  `applyConfigLocked` pipeline (`daemon_apply.go`, step 16c) — the relay
  Manager is created at boot regardless of whether a relay was configured
  then, so a relay added later starts and a relay removed later stops.
  `Apply` diffs the desired set (`computeDesired`) against the running
  `relays` map **per interface** and:
  - starts an interface present in desired but not running;
  - stops (bounded `cancel()`+`<-done`) an interface running but no longer
    desired (or when the whole block is deleted: a nil `cfg` stops all);
  - restarts an interface whose **spec changed** — a `relaySpec` is the
    resolved server list (config order) plus the `always-broadcast` flag;
    a change in either tears the old session down and binds a fresh one;
  - leaves an unchanged interface's session running untouched (idempotent —
    a no-op commit causes **no churn**, no socket reopen).
  The stop/restart teardown reuses the same `Stop()` mechanism (the #2347
  supervisor + #1915 close-on-cancel + `WaitGroup` join), and the old
  listener is fully closed before any replacement binds, so a restart never
  races `EADDRINUSE` and never hangs. The teardown joins run **outside**
  `m.mu` so a blocked relay's `<-done` does not stall `Stats()` or a
  concurrent `Apply`.
- **Startup readiness retry.** When `Apply` starts a relay (boot or a day-2
  add) and the interface is not yet ready (no IPv4 address, or a dynamic
  VLAN/tunnel not yet created), the relay retries resolving the interface +
  giaddr on a bounded, `ctx`-cancelable interval instead of dying
  permanently. The interface is re-looked-up every attempt (no stale cached
  index).
- **ifindex-drift detection (#2347).** `SO_BINDTODEVICE` pins the client
  listener to the interface's kernel **ifindex** at `bind(2)`. If the
  interface is deleted+recreated or renamed at runtime under unchanged config
  (VLAN delete/recreate, tunnel rebuild, device reset) it gets a NEW ifindex
  and the kernel stops delivering DHCP client requests to the stale-bound
  socket — the relay goes permanently **deaf** on that segment until a daemon
  restart. (Note: the raw-L2 reply path is unaffected — it re-resolves the
  ifindex per send; only the listener is at risk.) Each per-interface relay is
  now a **supervisor**: `runRelay` runs one `runRelaySession` under a child
  context and rebuilds it when the session tears down due to drift.
  `runRelaySession` captures the live ifindex when it opens the listener and
  runs a periodic (`ifindexCheckInterval`, 5s) watcher that re-resolves the
  name to the live ifindex; on a real, differing index it records drift and
  cancels the **session** context, reusing the existing #1915 close-on-cancel
  + `WaitGroup` teardown (no new teardown path, no `EADDRINUSE` — the stale
  socket is fully closed before the rebind, no `Stop()`-hang risk). The probe
  is **tolerant**: a resolve failure is treated as "no drift" so a transient
  netlink hiccup or mid-rename window never tears down a working listener, and
  it is **idempotent** (unchanged ifindex => no rebind). A failed baseline
  capture (`boundIfindex==0`) adopts the first real reading as the baseline
  rather than triggering a spurious rebind. Drift detection is per-interface,
  so a rebind on one segment never drops relays on the others. This mirrors
  the #2294 VRRP instance-restart-on-ifindex-drift fix for the relay listener.

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
  `make test-failover`. Note (#2076): the Backup's duplicate *reply* to a
  flag-clear client now actually delivers (raw L2) instead of being lost on
  ARP failure — see "HA / VRRP-Backup duplicate delivery" above.
