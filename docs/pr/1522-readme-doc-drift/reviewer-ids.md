# Reviewer task IDs — #1522 README doc-drift sweep

## Plan-review round 1 (v1)

- Codex: (recorded inline in plan; verdict folded into v2)
- AGY: `adversarial-review-mpkub795-6e2gou` — PLAN-NEEDS-MINOR
  - Specific feedback: prune `bpf/xdp/README.md`, `bpf/tc/README.md`,
    `bpf/headers/README.md` from the edit list because #1476 will
    mechanically delete the entire `bpf/` tree.
  - Applied in plan v2.

## Plan-review round 2 (v2)

- Codex: dispatch was queued behind sibling task on the codex
  companion shared session; not collected as a separate task ID.
- AGY: `adversarial-review-mplbvcsb-kxkn6q` — PLAN-READY
  (verified scope, dpdk_worker reframe wording, pkg/logging
  technical accuracy, canary invariants, BLOCKER framing).

## Plan-review round 3 (v3)

After AGY's v2 PLAN-READY, the master rebase exposed that #1528 will
delete the entire `dpdk_worker/` tree (issue body lists
`dpdk_worker/README.md`). Applying the same scope-reduction principle
AGY used in v2 (against `bpf/*/README.md`) prunes
`dpdk_worker/README.md` to leave a 1-file scope:
`pkg/logging/README.md` only. v3 does NOT require re-dispatching plan
review because it is a strict subset of the v2 scope AGY already
approved.

## Code-review rounds (after PR open)

- Copilot: pending
- Codex: pending
- AGY: pending
- Claude SMR: pending
