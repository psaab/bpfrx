# #1658 — neigh_monitor netlink socket SO_RCVBUF bump

Status: DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)

## Issue framing

`neigh_monitor_thread` in `userspace-dp/src/afxdp/neighbor.rs` creates a
`NETLINK_ROUTE` `SOCK_RAW` socket, binds it to the `RTNLGRP_NEIGH`
multicast group, and sets **only** `SO_RCVTIMEO` (`:506`). It never sets
`SO_RCVBUF`, so the socket uses the kernel default receive buffer
(`net.core.rmem_default`, 208 KB unless raised). Under a burst of
`RTM_NEWNEIGH`/`RTM_DELNEIGH` multicast notifications (HA failover, large
neighbor churn) that default can overflow → the kernel sets the socket's
`sk_err` and `recv()` returns `ENOBUFS`. The steady-state loop
(`:526-556`) treats any `recv() <= 0` as `continue` with **no errno
inspection**, so the overflow is silently swallowed. Because the only
full reconcile (`initial_neighbor_dump`) runs once at startup, a dropped
`RTM_NEWNEIGH`/`DELNEIGH` can leave `dynamic_neighbors` permanently
out of sync with the kernel neighbor table.

## Scope (isolated, preventive only)

This PR sets a larger `SO_RCVBUF` on the monitor socket at creation
time, before the steady-state loop. That is the **preventive** half of
#1648's section 5.E. The **recovery** half (errno inspection on `recv()`
+ socket recreation/resync, gated on Gate-R measurement that ENOBUFS
actually occurs) is **explicitly out of scope** and stays in #1648 so
the two changes do not collide. This PR touches only `neighbor.rs`.

If reviewers conclude the buffer bump is unjustified or that the Go-side
`tuneSocketBuffers` already covers it, NEEDS-MINOR / KILL is an
acceptable verdict.

## Buffer size + setsockopt choice

### Size: 4 MiB requested

Each neighbor event netlink message is small (~80-200 B with the
`ndmsg` header + `NDA_DST`/`NDA_LLADDR`/`NDA_CACHEINFO` attributes). A
4 MiB receive buffer holds on the order of 20k-50k queued events, which
comfortably absorbs a full neighbor-table churn burst (a cluster RETH
failover re-resolves at most a few hundred neighbors; a large L2 domain
flush is thousands). 4 MiB is the same order as typical netlink-monitor
tooling (`ip monitor` uses ~1 MiB; routing daemons use 1-8 MiB). We pick
4 MiB as a conservative headroom choice with negligible memory cost
(one socket, charged once).

### setsockopt: SO_RCVBUFFORCE primary, SO_RCVBUF fallback

- Plain `SO_RCVBUF` is **clamped to `net.core.rmem_max`** by the kernel.
  The kernel also **doubles** the supplied value (bookkeeping overhead),
  so a 4 MiB request becomes an 8 MiB internal value capped at
  `2 * rmem_max`.
- `SO_RCVBUFFORCE` bypasses the `rmem_max` clamp but requires
  `CAP_NET_ADMIN`.

xpfd (and therefore the spawned `xpf-userspace-dp` helper) runs as
**root** — the systemd unit `test/incus/xpfd.service` has no `User=` and
no capability drop, so `CAP_NET_ADMIN` is held. `SO_RCVBUFFORCE` is
therefore the robust, self-contained choice: it makes the 4 MiB
guarantee independent of the ambient `rmem_max` sysctl.

Relationship to the existing Go-side tuning: `tuneSocketBuffers()`
(`pkg/dataplane/userspace/process.go:139`) already raises
`net.core.rmem_max`/`rmem_default` to 64 MiB before launching the helper
(for the AF_XDP copy-mode XSK sockets). That means even a plain
`SO_RCVBUF(4 MiB)` would *currently* succeed unclamped. But that is a
cross-process ordering dependency on a sysctl set for a different
purpose; relying on it for the netlink monitor is fragile. We use
`SO_RCVBUFFORCE` so the monitor's buffer guarantee does not silently
regress if that Go-side tuning is ever changed, scoped, or the helper is
launched standalone in a test harness. If `SO_RCVBUFFORCE` fails
(e.g. helper somehow lacks `CAP_NET_ADMIN`), we fall back to plain
`SO_RCVBUF` so a capability-restricted environment still gets the
rmem_max-clamped best effort rather than the raw default.

### Error handling

The surrounding code ignores the `SO_RCVTIMEO` setsockopt return. We do
NOT replicate that here — per the issue's own framing ("don't silently
ignore the return like the surrounding code does"). We check both
returns:

- `SO_RCVBUFFORCE` failure → log via `eprintln!("neigh_monitor: ...")`
  and fall through to `SO_RCVBUF`.
- `SO_RCVBUF` failure (only reached if FORCE also failed) → log a
  warning. Non-fatal: the monitor still works with the default buffer,
  just without the burst headroom. Crashing the monitor over a buffer
  tuning failure would be worse than running with the default.

This is a best-effort tuning knob (overflow policy table: "Path not
found / best-effort cleanup → warn + continue"), so a setsockopt failure
is logged-and-continue, not fatal.

## Concrete design

Insert immediately after the `bind()` success and before/alongside the
existing `SO_RCVTIMEO` block (creation-time, on the SAME `fd` the
steady-state loop uses — there is only one fd in this function;
`initial_neighbor_dump(fd, ...)` and the loop both use it):

```rust
// Enlarge the receive buffer so a burst of RTM_NEWNEIGH/DELNEIGH
// multicast notifications (HA failover, large neighbor churn) does not
// overflow the default rcvbuf and drop adverts (which would silently
// desync dynamic_neighbors — the full dump is startup-only). #1658.
//
// SO_RCVBUFFORCE bypasses net.core.rmem_max and requires CAP_NET_ADMIN,
// which xpfd/the helper hold (run as root). Fall back to plain
// SO_RCVBUF (clamped to rmem_max) if FORCE is unavailable.
const NEIGH_RCVBUF_BYTES: libc::c_int = 4 * 1024 * 1024; // 4 MiB
let forced = unsafe {
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_RCVBUFFORCE,
        &NEIGH_RCVBUF_BYTES as *const libc::c_int as *const libc::c_void,
        core::mem::size_of::<libc::c_int>() as libc::socklen_t,
    )
};
if forced < 0 {
    eprintln!(
        "neigh_monitor: SO_RCVBUFFORCE({NEIGH_RCVBUF_BYTES}) failed, \
         falling back to SO_RCVBUF"
    );
    let set = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &NEIGH_RCVBUF_BYTES as *const libc::c_int as *const libc::c_void,
            core::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if set < 0 {
        eprintln!(
            "neigh_monitor: SO_RCVBUF({NEIGH_RCVBUF_BYTES}) also failed; \
             using kernel default receive buffer"
        );
    }
}
```

(Final wording / ordering relative to the `SO_RCVTIMEO` block decided
during implementation; placement is after `bind()` succeeds, before
`initial_neighbor_dump`.)

## Test plan

A pure socket-option change on a raw netlink fd is hard to fully
unit-test, but the size constant and the setsockopt/getsockopt contract
can be pinned:

1. **Compile-time guard** on the constant — `const _: () =
   assert!(NEIGH_RCVBUF_BYTES >= 1 << 20)` (≥ 1 MiB) so a future edit
   can't silently shrink it below the burst-absorbing floor. (Module
   const, so it must live at module scope or be re-derived in the test;
   see below.)
2. **getsockopt readback test** — create a `NETLINK_ROUTE` socket in the
   test, apply the same `SO_RCVBUFFORCE`/`SO_RCVBUF` logic via a small
   extracted helper `set_neigh_rcvbuf(fd) -> io::Result<()>` /
   `-> bool`, then `getsockopt(SO_RCVBUF)` and assert the readback is
   `>= NEIGH_RCVBUF_BYTES` (the kernel doubles, so readback is ~2× the
   request; assert `>= requested`, not `== requested`). The test runs as
   whatever user `cargo test` runs as — if not root, `SO_RCVBUFFORCE`
   fails and we fall back to `SO_RCVBUF` clamped to the runner's
   `rmem_max`; in that case assert `readback >= min(requested,
   2*rmem_max)` OR simply that the helper returned without erroring and
   readback > default. The test asserts the **return is checked**
   (helper returns a status) and the buffer grew above the 208 KB
   default when permitted. Mark `#[ignore]`-free but tolerant of the
   non-root clamp.
3. **5/5 flake** on the new test.
4. `cargo build` clean, full `cargo test --release`.
5. Go suite unaffected (no Go change) — run `go test ./...` for the
   userspace package as a sanity check.
6. Smoke (v4+v6 × push+reverse × CoS off/on) — **owned by the PARENT**
   per the cluster rule; this agent does not deploy.

### Extracted-helper decision

To make (2) testable without standing up the whole monitor thread, the
setsockopt logic is factored into a free fn
`set_neigh_monitor_rcvbuf(fd: RawFd) -> bool` (true if the buffer was
enlarged beyond best-effort, i.e. at least one setsockopt succeeded).
`neigh_monitor_thread` calls it on its fd. The helper is `pub(super)` or
private-with-`#[cfg(test)]`-reachable so the colocated `mod tests` can
drive it on an independent socket. This keeps the production call site a
one-liner and gives the test a real fd to read back.

## Hidden invariants preserved

- Same single fd used by `initial_neighbor_dump` and the steady-state
  loop — buffer set once, before either runs.
- No change to the parse loop, the generation counter, or the stop flag.
- No new allocation on any path (one stack `c_int`).
- Setsockopt placement does not change `SO_RCVTIMEO` behavior (both are
  independent SOL_SOCKET options on the same fd).

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Adds a socket option; no control-flow change to parse/dump/loop. |
| Lifetime / borrow | LOW | Stack `c_int`, raw fd, no borrows. |
| Performance | LOW | One extra setsockopt at thread start; zero hot-path cost. Larger buffer = bounded extra kernel memory (≤ 8 MiB doubled). |
| Architectural mismatch | LOW | Matches issue scope exactly; preventive-only, recovery deferred to #1648. |

## Out of scope (explicitly)

- ENOBUFS errno inspection on `recv()` (#1648 5.E recovery half).
- Socket recreation / resync on overflow (#1648 5.E).
- Periodic re-dump / reconcile of `dynamic_neighbors` (separate concern).
- Making the size operator-configurable (no evidence it needs tuning).
- Touching the ICMP probe sockets' setsockopt calls (`:48/:81/:97`).

## Open questions for adversarial review

1. Is 4 MiB justified, or over/under-sized? Each event is ~80-200 B; is
   the 20k-50k-event headroom right for the worst-case churn (full L2
   flush on a large domain)? Should it be 1 MiB or 8 MiB instead?
2. Is `SO_RCVBUFFORCE` the right primary, given the Go side already
   raises `rmem_max` to 64 MiB? Or does the cross-process sysctl make
   plain `SO_RCVBUF` sufficient and `SO_RCVBUFFORCE` an unnecessary
   capability dependency? (If the helper is ever de-privileged,
   `SO_RCVBUFFORCE` would log-fail every start — is that acceptable
   noise vs. the fallback?)
3. Does the kernel actually drop netlink multicast and return ENOBUFS on
   rcvbuf overflow for `NETLINK_ROUTE` SOCK_RAW, or does it block / use a
   different mechanism? (Verify the premise: netlink overflow sets
   `NETLINK_OVERRUN`/`ENOBUFS` on the next `recvmsg`.) If the premise is
   wrong, the buffer bump is theater.
4. Is the getsockopt-readback test sound given the non-root cargo-test
   environment, where `SO_RCVBUFFORCE` fails and the fallback is clamped
   to the runner's `rmem_max`? Will it flake on CI hosts with a small
   `rmem_max`?
5. Should the setsockopt failure be fatal (return from the thread)
   instead of logged-and-continue? The monitor with a default buffer is
   still functional; argument for/against crashing.
