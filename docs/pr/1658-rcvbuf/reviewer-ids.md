# #1658 reviewer task IDs

## Plan review (round 1)
- Codex: task-mpraz4ey-2t7j92 — PLAN-NEEDS-MAJOR (premise confirmed real;
  required burst target, getsockopt readback, flake-proof test,
  FORCE-vs-RCVBUF justification). All findings addressed in plan v2.
- AGY: review-mprazbiq-ikscx2 — PLAN-READY (corrected test clamp formula
  to min(2*req, rmem_max); stack-local promotion nit). Applied in v2.
- Claude SMR: PLAN-READY — verified netlink-overrun ENOBUFS premise,
  reconciled FORCE-vs-RCVBUF split toward FORCE-first (root holds
  CAP_NET_ADMIN) + runtime readback for observability; verified single-fd
  placement.

## Code review (PR)
- Copilot: pending
- Codex: pending
- AGY: pending
- Claude SMR: pending
