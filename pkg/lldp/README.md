# pkg/lldp

IEEE 802.1AB Link Layer Discovery Protocol. Sends periodic LLDP frames
out unmanaged interfaces, receives neighbor announcements, and ages
entries by TTL.

## Entry points

- `Manager` — `lldp.go`.
- `Neighbor` — `lldp.go`. Chassis ID, port ID, TTL, system name and
  description.
- `New()` — `lldp.go`.
- `Apply(ctx context.Context, cfg *LLDPConfig)` — `lldp.go`. Reconcile-shaped:
  `Stop()`s the current generation before starting the new one, so calling it
  repeatedly is idempotent. A nil/disabled/empty config stops the service.
- `Stop()` — `lldp.go`.
- `Running()` — `lldp.go`. Reports whether a live generation has at least one
  active interface session. Used by the daemon's day-2 reconcile (#2372) and
  its tests to observe the start/stop transition.
- `ApplyCount()` — `lldp.go`. Number of `Apply()` calls. Test seam for the
  day-2 reconcile diff-guard (#2372) — an unrelated commit must not re-`Apply`.
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
- `rxLoop` treats `EINTR`/`EAGAIN`/`EWOULDBLOCK` from `Recvfrom` as
  transient and retries immediately — a signal forwarded through the Go
  runtime must not silently terminate neighbor discovery on a long-running
  daemon. On any **other** recv error it distinguishes shutdown from an
  operational fault: if the context is cancelled it is the expected
  `Stop()` close-to-unblock and the loop returns; otherwise (the context
  is still live, e.g. the interface flapped down — `ENETDOWN`) the loop
  **backs off `rxErrorBackoff` (1s) and retries** rather than exiting.
  Nothing restarts `rxLoop` within a generation — it lives only for the life
  of the `Apply()` that started it (a config change re-`Apply()`s, which
  `Stop()`s the old generation and starts a fresh one) — so a permanent exit
  on a transient flap would silently kill neighbor discovery until the next
  `protocols lldp` commit or a daemon restart (the pre-`#2040` behavior; the
  old timeout-poll loop survived flaps by continuing). The
  backoff is interruptible: a concurrent `Stop()` cancels the context and
  the loop returns promptly instead of sleeping out the delay, and the
  closed fd makes any parked `Recvfrom` return so `Stop()` stays bounded.
- The TX socket is opened once per interface in `newIfSession` and reused
  for every periodic advertisement (was previously opened+closed per
  frame).
- Construction goes through the `newIfSessionFn` seam so `socket_test.go`
  can inject a `socketpair(2)`-backed session and assert `Stop()` returns
  promptly with a parked RX goroutine, without `CAP_NET_RAW`.
- A socket setup / `CAP_NET_RAW` failure now surfaces at `Apply()` time
  (logged once, interface skipped) instead of silently per-frame.

## Day-2 reconcile (#2372)

The daemon owns the manager and reconciles it on every commit, not just at
boot. `Daemon.reconcileLLDP` (`pkg/daemon/daemon_apply.go`) is the single
source of truth: `daemon_run.go` calls it at boot and `applyConfigLocked`
calls it on every commit. An interface-set, `transmit-interval`, or
`hold-multiplier` change takes effect on commit without a daemon restart, and
a disabled/empty stanza `Stop()`s the running service.

Two properties keep this safe (#2372 review findings 3 + 6):

- **Construct-once.** The `Manager` is created exactly once, at boot
  (`daemon_run.go`, unconditionally — mirroring `dhcpRelay`), so the
  `d.lldpMgr` pointer is written before any handler runs. `reconcileLLDP`
  only ever calls `Apply()`/`Stop()` on it and NEVER reassigns the pointer.
  The `show lldp neighbors` gRPC/CLI handlers read `d.lldpMgr` lock-free on a
  handler goroutine, so a day-2 reassignment would be a data race on the
  pointer field — construct-once eliminates the write entirely. (A daemon that
  never enables LLDP allocates the manager but no sockets/goroutines.)
- **Change-guarded.** `Apply()` unconditionally `Stop()`s the current
  generation (closing every socket, joining goroutines, and wiping the
  neighbor table) before rebuilding. So `reconcileLLDP` compares the new
  effective LLDP config (`effectiveLLDPConfig`) against the last-applied one
  and calls `Apply()`/`Stop()` only when it actually changed. An unrelated
  day-2 commit (e.g. a firewall-policy change) therefore leaves a healthy LLDP
  generation untouched — `show lldp neighbors` does not blank and sockets do
  not churn. This matches the diff discipline of the adjacent
  `reconcileDHCPRelay` (#2348).

## Gotchas

- Uses AF_PACKET raw sockets — the daemon needs `CAP_NET_RAW`. Without
  it, session setup fails at `Apply()` time, the interface is skipped,
  and the neighbor table stays empty for it.
- TTL countdown is per-neighbor; expired entries auto-purge from the
  `Neighbors()` snapshot.
- The neighbor map is RWMutex-guarded. `Neighbors()` returns a copy, not
  a reference, so callers can iterate without holding the lock.
- `ParseTLVs` counts a mandatory TLV (Chassis ID, Port ID, TTL) as
  present only once its value parsed into a valid identifier — a non-empty
  Chassis/Port ID, a full 2-byte TTL. A truncated mandatory TLV (subtype
  byte alone, a MAC-subtype Chassis ID short of its 6-byte address, or a
  TTL under 2 bytes) leaves the corresponding flag unset, so the frame is
  rejected rather than cached under an empty `ifname//` key with TTL 0
  (#2551). A valid 2-byte TTL of 0 is a legitimate shutdown advert and is
  still accepted (the gate is "the TLV parsed", not "TTL != 0").
