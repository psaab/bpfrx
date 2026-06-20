# pkg/lldp

IEEE 802.1AB Link Layer Discovery Protocol. Sends periodic LLDP frames
out unmanaged interfaces, receives neighbor announcements, and ages
entries by TTL.

## Entry points

- `Manager` — `lldp.go`.
- `Neighbor` — `lldp.go`. Chassis ID, port ID, TTL, system name and
  description.
- `New()` — `lldp.go`.
- `Apply(ctx context.Context, cfg *LLDPConfig)` — `lldp.go`.
- `Stop()` — `lldp.go`.
- `Neighbors()` — `lldp.go`. Snapshot consumed by `show lldp
  neighbors`.

## Callers

`pkg/daemon`, `pkg/grpcapi`, `pkg/cli`.

## Dependencies

Standard library + `golang.org/x/sys/unix`. No internal `pkg/*` imports.

## Socket lifecycle (#2035)

- Each enabled interface gets one `ifSession` (`lldp.go`) holding a bound
  RX `AF_PACKET` socket and a reused TX `AF_PACKET` socket. Sessions are
  created in `Apply()` and tracked on the `Manager`.
- The RX socket has **no `SO_RCVTIMEO`**: `rxLoop` blocks in `Recvfrom`
  indefinitely. `Stop()` (which runs on the daemon shutdown critical
  path, just before VRRP resignation) cancels the context, then
  `close()`s every session — `shutdown(SHUT_RDWR)` + `close` — which
  unblocks the parked `Recvfrom` immediately. This removed a 0–2s
  read-timeout tail from shutdown. Ordering is load-bearing:
  cancel → close fds → `wg.Wait()` (never wait before closing).
- The TX socket is opened once per interface in `newIfSession` and reused
  for every periodic advertisement (was previously opened+closed per
  frame).
- Construction goes through the `newIfSessionFn` seam so `socket_test.go`
  can inject a `socketpair(2)`-backed session and assert `Stop()` returns
  promptly with a parked RX goroutine, without `CAP_NET_RAW`.
- A socket setup / `CAP_NET_RAW` failure now surfaces at `Apply()` time
  (logged once, interface skipped) instead of silently per-frame.

## Gotchas

- Uses AF_PACKET raw sockets — the daemon needs `CAP_NET_RAW`. Without
  it, session setup fails at `Apply()` time, the interface is skipped,
  and the neighbor table stays empty for it.
- TTL countdown is per-neighbor; expired entries auto-purge from the
  `Neighbors()` snapshot.
- The neighbor map is RWMutex-guarded. `Neighbors()` returns a copy, not
  a reference, so callers can iterate without holding the lock.
