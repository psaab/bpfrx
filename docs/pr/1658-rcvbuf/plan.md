# #1658 — neigh_monitor netlink socket SO_RCVBUF bump

Status: v2 — Codex PLAN-NEEDS-MAJOR (task-mpraz4ey-2t7j92) + AGY PLAN-READY
(review-mprazbiq-ikscx2) + Claude SMR. v2 incorporates all Codex/AGY
findings; ready for implementation.

## Reviewer dispositions (v1 → v2)

- **Codex #1 / AGY #1 — ENOBUFS premise correct.** Verified: netlink
  multicast overflow calls `netlink_overrun()` → sets `sk->sk_err =
  ENOBUFS`; next `recvmsg()` returns -1/ENOBUFS. The `recv()<=0 ->
  continue` at `:528` silently swallows it. NOT a kill. Kept.
- **Codex #2 — 4 MiB under-justified.** FIXED: explicit burst target
  stated below (survive ~20k queued events ≈ a full large-L2-domain
  neighbor flush while the thread is stalled up to the 500 ms
  SO_RCVTIMEO tick). AGY #2 independently endorses 4 MiB and notes
  1/128 KiB would *shrink* below the 208 KiB default.
- **Codex #3 vs AGY #3 — FORCE-first vs RCVBUF-first (reviewers
  disagree).** RESOLVED toward FORCE-first: AGY verified the helper
  holds CAP_NET_ADMIN (root, needs it for AF_XDP/BPF), so FORCE has no
  added dependency cost in production, and it makes the 4 MiB guarantee
  self-contained rather than dependent on the cross-process `rmem_max`
  bump (which Go swallows on failure). Codex's substantive concern was
  observability ("noisy failure for little benefit" + #4 "setsockopt
  return is insufficient"); both are addressed by the runtime
  getsockopt readback + effective-size log added in v2. FORCE failure
  is logged once at start, not noisy. Keep FORCE primary, RCVBUF
  fallback.
- **Codex #4 — checking setsockopt return is insufficient (clamp is
  silent).** FIXED: v2 adds a `getsockopt(SO_RCVBUF)` readback after
  the set and logs the effective size + which option succeeded, so an
  operator can see whether the preventive buffer is actually active.
- **Codex #5 / AGY #4 — readback test flaky under non-root /
  rmem_max.** FIXED + verified on this host: cargo-test here runs as
  **uid 1000 (non-root)** and `rmem_max == 4194304` (exactly 4 MiB).
  Requesting 4 MiB non-root would clamp to exactly `rmem_max` (kernel
  doubles *then* clamps), so a `>= 2*requested` assert would FAIL. v2
  test requests a small 256 KiB (well below any realistic `rmem_max`),
  reads `/proc/sys/net/core/rmem_max`, and asserts
  `readback >= min(2*256KiB, rmem_max)` with a graceful fallback if
  `rmem_max` is unreadable. AGY corrected my v1 formula: non-root clamp
  is `min(2*req, rmem_max)`, NOT `2*rmem_max`.
- **Codex #6 / AGY #5 — logged-continue not fatal.** Kept; both agree.
- **Codex #7 / AGY #7 — same single fd, set before dump.** AGY verified
  exactly one fd in `neigh_monitor_thread` (`:471`), placement after
  `bind()` (`:492`) and before `initial_neighbor_dump` (`:514`). Kept.
- **AGY codegen nit — promote const to a stack local before taking
  `&`.** Applied: bind `let rcvbuf_val: libc::c_int = ...;` and pass
  `&rcvbuf_val`.

---

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

### Size: 4 MiB requested — explicit burst target

**Burst target: survive ~20,000 queued neighbor notifications while the
monitor thread is stalled up to one 500 ms `SO_RCVTIMEO` tick** (the
worst-case latency between `recv()` calls, since the loop blocks up to
500 ms per iteration). That covers a full large-L2-domain neighbor-table
flush (a cluster RETH failover re-resolves a few hundred neighbors; a
domain-wide flush is low thousands), with headroom.

Sizing note (Codex #2): receive-buffer accounting charges skb
`truesize`, not just the nlmsg payload, so the per-event cost is larger
than the 80-200 B wire size. Using a conservative ~200 B *effective*
charge per small event, 4 MiB ≈ 20k events of headroom; with realistic
truesize inflation it is still many thousands — comfortably above the
burst target. 4 MiB is the same order as `ip monitor` / routing-daemon
netlink buffers (1-8 MiB). `SO_RCVBUF` is an upper bound on dynamically
allocated `sk_buff` memory, so idle cost is ~0; only a real burst
materializes the memory, capped at the doubled value (≤ 8 MiB).

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

Logic is extracted into a free helper so the readback can be unit-tested
on an independent socket (see test plan). The helper sets FORCE first,
falls back to plain `SO_RCVBUF`, then does a `getsockopt` readback and
logs the *effective* buffer (addresses Codex #4 — a plain `SO_RCVBUF`
can return success while silently clamping, so the setsockopt return is
not enough; the readback is the ground truth).

```rust
const NEIGH_RCVBUF_BYTES: libc::c_int = 4 * 1024 * 1024; // 4 MiB, #1658

const _: () = assert!(NEIGH_RCVBUF_BYTES >= (1 << 20)); // ≥1 MiB floor

/// Enlarge the netlink monitor receive buffer so an RTM_NEWNEIGH/
/// DELNEIGH multicast burst does not overflow the default rcvbuf and
/// silently drop adverts (which would desync dynamic_neighbors — the
/// full dump is startup-only). Best-effort: logs and continues on
/// failure. Returns the effective rcvbuf bytes read back via getsockopt
/// (the kernel doubles the request and may clamp to rmem_max).
fn set_neigh_monitor_rcvbuf(fd: RawFd, request: libc::c_int) -> libc::c_int {
    // Promote to a stack local so &-of-const is well-defined (AGY nit).
    let want: libc::c_int = request;
    // SO_RCVBUFFORCE bypasses net.core.rmem_max; needs CAP_NET_ADMIN,
    // held because xpfd/the helper run as root for AF_XDP/BPF. Make the
    // 4 MiB guarantee self-contained rather than depend on the Go-side
    // tuneSocketBuffers() rmem_max bump (cross-process, swallowed on
    // failure). Fall back to plain SO_RCVBUF (rmem_max-clamped).
    let forced = unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE,
            &want as *const _ as *const libc::c_void,
            core::mem::size_of::<libc::c_int>() as libc::socklen_t)
    };
    let mut via = "SO_RCVBUFFORCE";
    if forced < 0 {
        let err = std::io::Error::last_os_error();
        let set = unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
                &want as *const _ as *const libc::c_void,
                core::mem::size_of::<libc::c_int>() as libc::socklen_t)
        };
        via = "SO_RCVBUF";
        if set < 0 {
            eprintln!("neigh_monitor: SO_RCVBUFFORCE({want}) and \
                SO_RCVBUF({want}) both failed (force: {err}, set: {}); \
                using kernel default receive buffer",
                std::io::Error::last_os_error());
            via = "default";
        }
    }
    // Read back the effective size (Codex #4: setsockopt return alone
    // hides the silent rmem_max clamp on the SO_RCVBUF fallback path).
    let mut eff: libc::c_int = 0;
    let mut len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
            &mut eff as *mut _ as *mut libc::c_void, &mut len)
    };
    if rc == 0 {
        eprintln!("neigh_monitor: rcvbuf set via {via}: requested \
            {want}, effective {eff} bytes");
    }
    eff
}
```

Call site in `neigh_monitor_thread`, after `bind()` succeeds and before
the existing `SO_RCVTIMEO` block / `initial_neighbor_dump`:

```rust
set_neigh_monitor_rcvbuf(fd, NEIGH_RCVBUF_BYTES);
```

(`RawFd` import / exact log wording finalized during implementation.)

## Test plan

A pure socket-option change on a raw netlink fd is hard to fully
unit-test, but the size constant and the setsockopt/getsockopt contract
can be pinned:

1. **Compile-time guard** on the constant —
   `const _: () = assert!(NEIGH_RCVBUF_BYTES >= (1 << 20))` (≥ 1 MiB)
   at module scope, so a future edit can't silently shrink it below the
   burst-absorbing floor (runs on every `cargo build`, not just test).
2. **getsockopt readback test (flake-proof, verified on this host).**
   The test creates its own `NETLINK_ROUTE` `SOCK_RAW` socket and calls
   `set_neigh_monitor_rcvbuf(fd, TEST_REQ)` with **`TEST_REQ =
   256 * 1024`** — deliberately small, well below any realistic
   `rmem_max`, so it does not depend on root. The helper returns the
   `getsockopt` readback. Expected floor:
   - kernel doubles the request, then (non-root) clamps to `rmem_max`:
     `expected = min(2*TEST_REQ, rmem_max)` (AGY #4 — the clamp is
     `rmem_max`, NOT `2*rmem_max`).
   - read `/proc/sys/net/core/rmem_max`; if unreadable, fall back to
     asserting `readback >= TEST_REQ` (still true in every case since
     `TEST_REQ < rmem_max` on any sane host and the kernel never
     returns *less* than the doubled-or-clamped value, both ≥ TEST_REQ
     when TEST_REQ ≤ rmem_max).
   Concretely: `assert!(readback >= min(2*TEST_REQ, rmem_max))`. On this
   host (uid 1000 non-root, `rmem_max == 4194304`): `2*256K = 512K <
   4 MiB` → no clamp → readback `== 512K` → passes. The test also
   asserts the helper **returned a value** (return is checked, not
   silently dropped like the surrounding `recv()`), satisfying the
   "don't ignore the return" contract. No `#[ignore]`; tolerant of both
   root and non-root.
   - A second assertion proves the buffer actually grew above the
     208 KB default: `assert!(readback > 212992 || rmem_max <= TEST_REQ)`
     (the `||` guards the pathological tiny-rmem_max CI host).
3. **5/5 flake** on the new test.
4. `cargo build` clean (also exercises the `const _: ()` guard), full
   `cargo test --release`.
5. Go suite unaffected (no Go change) — `go test ./...` sanity check.
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
