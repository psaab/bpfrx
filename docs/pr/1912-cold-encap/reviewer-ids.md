# Reviewer task / job IDs — PR #1954 (#1912 cold ENCAP outer next-hop blackhole)

Branch `engineer/1912-cold-encap-outer-nh`, off `origin/master @ 09cd972bc`.
Converged 3-way research plan: `docs/research/1912-cold-encap/plan.md`
(research branch — NOT in this PR).

Design: Option B (cold-path helper). Factor `resolve_tunnel_outer` SSOT, add
`outer_neighbor_ifindex`, rekey the MissingNeighbor arm's outer-hop
side-effects by the OUTER L3 egress ifindex (not the tunnel logical), throttle
the tunnel outer-hop probe + resolver enqueue. R-C/R-E preserved; no wire/HA
change.

## Code review — commit a87b2b8a2 (probe-throttle added after r1)

- Codex r1 code review: `task-mqi50r4s-nqh44m` — NEEDS-WORK
  - Only finding: `git diff --check` whitespace in the `docs/research/`
    plan docs (a Low). RESOLVED — the plan docs were rebased OUT of the PR
    diff (the PR is code-only, 4 files); `git diff --check origin/master..HEAD`
    clean. Core dataplane changes assessed MERGE-READY from source review.
- Antigravity r1 adversarial review: `adversarial-review-mqi50wxh-4nbcfh` —
  NEEDS-WORK (High)
  - High: the kernel ARP probe (`trigger_kernel_arp_probe`, raw-socket
    open/setsockopt/sendto/close) was gated only by `already_probing`
    (`pending_neigh.contains_key`), but tunnel-marked flows are never
    buffered in `pending_neigh` (R-E) and the per-hop neg-cache only arms on
    a `pending_neigh` timeout, so EVERY cold packet of an unresolved
    tunnel-bound flow fired a per-packet probe — a syscall storm under a SYN
    flood. FIXED in `a87b2b8a2`: gate BOTH the probe and the resolver enqueue
    behind the existing per-`(neigh_if, next_hop)` `resolver_enqueue_throttle`
    window (<=1 probe + enqueue per outer key per window).
- Copilot r1 (issue-comment): root cause + fix "correct"; 4 findings.
  - #1 (High) unthrottled probe storm — same as AGY High; FIXED in
    `a87b2b8a2`.
  - #2 (Medium) duplicated resolver-enqueue block — addressed in `e3fd63846`
    (factored `try_enqueue_resolver`).
  - #3 (Medium) missing `#[cold]` — DECLINED: sibling cold-path forwarding
    helpers carry no `#[cold]` in this module; annotating only the two new
    fns would be inconsistent.
  - #4 (Low) fallback-to-tunnel-logical guard — addressed in `e3fd63846`
    (`outer_if_distinct` / `tunnel_without_outer`).
  - Minor (resolved-wins secondary fix) — acknowledged in the PR thread.

## Code review — commit a87b2b8a2 (r2)

- Codex r2 code review: `task-mqi5eud4-s8edmx` — MERGE-READY (no findings)
- Antigravity r2 adversarial review: `adversarial-review-mqi5f1cg-wyckx4` —
  MERGE-READY (no findings; confirmed the <=10 GETs/s-per-key storm bound,
  non-tunnel byte-identity, R-C/R-E, cache bounding, no remaining storm
  vectors)

## Code review — commit e3fd63846 (final; Copilot #2/#4 + helper tests)

- Codex r3 code review: `task-mqi5sh0n-k12q5e` — MERGE-READY (no findings)
  - Verified the neg-cache refactor to `try_enqueue_resolver` is
    behavior-identical, the tunnel probe/enqueue share one throttle window
    (no double-bump / no window reset on a throttled packet), non-tunnel
    byte-identity, R-C/R-E preserved.
- Antigravity r3 adversarial review: `adversarial-review-mqi5snst-o779gr` —
  MERGE-READY (no findings; ran full `cargo test` 2015 passed / 0 failed and
  `go test ./...` green)

## Convergence

Codex + Antigravity both MERGE-READY on the final SHA `e3fd63846` with no
findings. Copilot's 4 findings all addressed (3 fixed, 1 declined with
rationale).

## Remaining gates (parent-coordinated, serialized loss cluster)

- Live loss-cluster repro (`tmp/v1902b.sh` choreography: GRE-to-self, flush
  `ge-0-0-1`, ping while tcpdumping for who-has the outer hop — pass = who-has
  now appears + reply leg recovers within ~1 ping).
- `make test-failover`.

These are NOT run here (the parent coordinates the serialized cluster). Test
status at merge gate: `cargo test --release` green (2014 lib + the 2 new
helper tests = 2015 incl. integration; the intermittent `worker_queue`
`concurrent_recovery` + wg `reconcile_peers_snapshot` failures are pre-existing
parallelism flakes, green in isolation and on clean runs), 5x flake-clean on
all 7 new #1912 tests, `go test ./pkg/dataplane/userspace ./pkg/config` green.
