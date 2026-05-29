# AGY adversarial-review r3 — #1648 (on plan v3.1)

Job: adversarial-review-mpqn25qc-6ejm3r. **Verdict: PLAN-NEEDS-REVISION.**

## 1. The Missing Third Window (Config-Reload & ISSU Reconcile) — VERIFIED COUNTER-EXAMPLE
v3.1 §3 claimed "No third window … config-reload does NOT respawn [the monitor]".
This is FALSE. Verified trace:
1. `reconcile` (`reconcile/mod.rs:98`) calls `teardown::tear_down(self)`.
2. `tear_down` (`reconcile/teardown.rs:28`) calls `coord.stop_inner(false)`.
3. `stop_inner` (`coordinator/mod.rs:199`) does `self.neighbors.monitor_stop.take()`
   → sets it to `None`.
4. `bring_up_workers` (`bringup.rs:330`) then sees `monitor_stop.is_none()` →
   spawns a **brand-new** neigh-monitor thread.
5. The new thread runs `initial_neighbor_dump` again (`neighbor.rs:514`).
**Impact:** every config-reload / ISSU reconcile is a fresh H-0 window. Cold
flows during a commit hit the seq=0 multicast-drop → ~1.7s. Config-reload is far
more frequent than daemon restart, raising H-0/5.A.2 production-relevance
independent of failover.

## 2. Infinite busy-loop on persistent socket errno
Steady-state loop (`neighbor.rs:528`) and dump loop (`neighbor.rs:407-414`) treat
`recv() <= 0` / non-WouldBlock errors as `continue` with no errno inspection. On
EBADF/EINVAL/persistent error the thread spins at 100% CPU. The monitor must
inspect errno; on persistent error, break/close/log/recreate.

## 3. 5.E ENOBUFS resync must RECREATE the socket, not reuse it
Re-running `initial_neighbor_dump` on the same congested socket risks: stale
unread multicast polluting the dump parser, the dump request/replies dropped by
the same overflow, persistent ENOBUFS inside the dump loop. 5.E must: close the
corrupted socket → open+bind+subscribe a fresh one → dump on the clean socket.

## 4. Silent CAP_NET_RAW failure in trigger_kernel_arp_probe
`trigger_kernel_arp_probe` (`neighbor.rs:36-118`) opens SOCK_RAW; if
CAP_NET_RAW is dropped (hardened containers), `fd < 0` → silent return → cold
resolution never fires, no operator signal. Log on EACCES/EPERM + document the
capability requirement.

## 5. Zero-tolerance kill bar — ENDORSED
"Highly measurable and structurally sound. TCP_TIMEOUT_INIT (initial RTO) is 1s,
a dropped SYN causes a >1000ms spike that stands clear of the 0.6-3.7ms
steady-state variance. Combined with daemon-side counter A, immune to
false-negatives from minor background load."

## Recommendation
PLAN-NEEDS-REVISION: incorporate Window-3 (config-reload/ISSU), correct 5.E to
socket-recreation, add persistent-errno bounds to prevent the busy loop, and
address the silent CAP_NET_RAW failure mode.
