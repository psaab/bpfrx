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

## Code review (PR #1664)
- Copilot: MERGE-READY equivalent — reviewed all 3 files, generated no
  comments (clean).
- Codex: task-mprbc0w5-uxkgn4 BLOCKED (sandbox shell failure, no verdict)
  -> retried per feedback_codex_infra_must_retry as task-mprc3t6u-juvstu
  = MERGE-READY (1 minor comment-wording nit on the test docstring,
  applied; not a blocker).
- AGY: review-mprbc8hm-cuiivs — MERGE-READY (item-by-item code-grounded
  verification; independently re-derived the test floor math + errno
  capture correctness).
- Claude SMR: MERGE-READY — verified errno capture ordering (force_err
  before second setsockopt; second last_os_error is the SO_RCVBUF errno,
  no intervening libc call), FFI types, single-fd placement.

4-of-4 clean.
