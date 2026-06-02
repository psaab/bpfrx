# Codex hostile plan-review — #1748 r1

Session: CODEX_COMPANION_SESSION_ID=research-1748-r1-1780378053
Verdict: **PLAN-READY (kill correct)**

## Findings (verbatim)

I could not falsify the kill.

- **Wall A stands.** Current mainline `xsk_rcv_check()` requires the socket
  device and `queue_id` to match `xdp->rxq`, and both generic and zero-copy XSK
  receive paths call it before delivery. The local XDP shim encodes the same
  constraint: `select_userspace_queue()` returns the ingress RX queue and
  explicitly says redirecting to another queue strands packets
  (`userspace-xdp/src/lib.rs:1364`). CPUMAP does not bypass this; its secondary
  XDP run still has an `xdp.rxq`, with queue index unresolved in the source
  path checked.

- **Wall B stands.** No cross-worker live-flow migration path exists.
  `WorkerCommand` has HA/session upsert/delete, owner-RG commands, local shaped
  TX enqueue, and shared-slot vacate, but no migrate/rehome/freeze/import
  command (`userspace-dp/src/afxdp/types/runtime.rs:215`).
  `apply_worker_commands()` only handles those commands
  (`userspace-dp/src/afxdp/session_glue/mod.rs:440`). The flow cache is
  explicitly designed for "no shared atomics and no cross-worker cache-line
  traffic" (`flow_cache.rs:143`). MQFQ/CoS state is bucketed queue state inside
  `FlowFairState`, not a clean per-flow object that can be moved independently
  (`userspace-dp/src/afxdp/types/cos.rs:733`).

- **The floor theorem is not falsified.** For ephemeral ports, static
  tuple-to-queue placement is still multinomial; the project docs state N=6,
  M=6 has E[CoV] ~= 0.87 (`fairness-regimes.md:138`). Codex independently
  exact-enumerated all 6^6 assignments and got E[CoV] = 0.8739659673392799. Any
  reactive scheme that beats that requires moving established flows, which falls
  back into Wall B.

Non-blocking nit: the plan should avoid calling HA both an "independent
blocker" and a "consequence of Wall B." The substance is still correct: HA
double-homing raises the migration bar; it does not rescue #1748.

No files changed.

VERDICT: PLAN-READY (kill correct)
