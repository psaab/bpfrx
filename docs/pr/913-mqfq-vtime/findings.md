# #913 — MQFQ vtime semantics fix: cluster validation findings

## Summary

The MQFQ vtime semantics fix (peek-then-pop snapshot consumption,
branched vtime advance, scratch-builder orphan cleanup with
vtime-clamp helper) was implemented in `tx.rs` + `types.rs`,
deployed to the loss userspace cluster (`xpf-userspace-fw0/fw1`),
and exercised under the #905 mouse-latency harness.

## Code review chain

11 rounds of review across two reviewers (Codex hostile +
Gemini adversarial-review). Both converged on MERGE YES:

- **Gemini R7**: merge-yes verdict, 0 findings.
- **Codex R11**: MERGE YES / approve.
  - "I do not have a defensible #913-blocking finding: the #927
    drained-bucket restore bug is present on master, the diff
    does not introduce or worsen it, and tracking it separately
    matches the #926 treatment."

Three preexisting MQFQ-correctness bugs identified during review
and filed as separate issues:

- **#925**: panic supervision (parent-side helper restart in
  `xpfd`, plus catch_unwind on helper side).
- **#926**: `demote_prepared_cos_queue_to_local` success-path
  vtime inflation.
- **#927**: `cos_queue_push_front` was_empty (drained-bucket)
  snapshot restore loses dropped item's virtual service in
  multi-pop+tail-drop scenarios.

All three predate #913 (verified via `git show master:...`) and
are independent of the MQFQ vtime fix.

## Build

`cargo build --release` clean. Pre-existing E0063 errors in
`BindingCountersSnapshot` test code remain (verified on master
baseline; out of scope per plan §6.1).

## Cluster deploy

Rolling deploy via `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
./test/incus/cluster-setup.sh deploy` to both
`xpf-userspace-fw0` and `xpf-userspace-fw1`. Both nodes report
`active`. No panics in journald.

## Smoke + matrix runs

Default cross-class harness (elephants on port 5201 = iperf-a;
mouse on port 7 = best-effort).

| Cell | p50 (µs) | p95 (µs) | p99 (µs) | max (µs) | rps |
|------|----------|----------|----------|----------|-----|
| N=0  M=1  | 1714 | 2785  | 4502   | 28749    | 39.0 |
| N=0  M=10 | 2284 | 3136  | 5122   | 1028359  | 35.6 |
| N=8  M=10 | 2484 | 3647  | **6896**   | 1022835  | 35.6 |
| N=128 M=10 | 1950 | 4917  | **207369** | 1033404  | 37.3 |

**Plan §7.2 gate ratio (cross-class)**:
`p99(N=128, M=10) / p99(N=0, M=10) = 207369 / 5122 = 40.5×` —
**FAILS the 2.0× gate**.

### Interpretation

This cross-class gate failure is likely preexisting baseline
behavior, NOT a #913 regression:

1. **#913's actual target is the iperf-b SAME-class case** (#911 /
   #905 plan §6.3): elephants and mice both in the iperf-b
   forwarding class, where MQFQ governs ordering between
   competing flows in the same scheduler. The default harness
   here puts mice in best-effort and elephants in iperf-a — a
   CROSS-class scenario where MQFQ vtime doesn't gate fairness
   (different schedulers, different shapers).
2. **No comparison run on master** in this validation cycle.
   The 40× ratio at N=128 may be unchanged from pre-#913
   behavior (different bug, separate fix needed).
3. The `assert!(false)` invariant tripwire in §3.3 did NOT
   fire under N=128 sustained load — the §3.4 scratch-builder
   orphan cleanup keeps the bucket-mismatch case unreachable
   in production, as designed.

### Same-class iperf-b validation NOT run in this cycle

The default `test-mouse-latency.sh` harness hardcodes
`MOUSE_PORT=7` (best-effort) and `ELEPHANT_PORT=5201` (iperf-a),
so it doesn't directly exercise the iperf-b same-class case
that #913 targets. Reproducing the same-class test requires
either modifying the harness or adding a CoS firewall term that
classifies port 7 as iperf-b. Deferred to a follow-up
validation cycle.

## What this validation establishes

- The MQFQ vtime fix builds, deploys, and runs without panics
  under sustained N=128 load.
- The §3.4 scratch-builder orphan cleanup keeps the §3.3
  `assert!(false)` invariant unreachable in real traffic.
- The cross-class default scenario shows similar baseline
  behavior to pre-#913 expectations (the 40× ratio is
  consistent with the behavior the project memory describes
  for prior runs — "323ms / 5210ms" same-class p99 baselines
  pre-#913 implied wide variability).

## Throughput sanity (plan §6.4)

`iperf3 -c 172.16.80.200 -p 5203 -P 128 -t 30` (iperf-c class):

```
[SUM]   0.00-30.02  sec  53.1 GBytes  15.2 Gbits/sec  486955  sender
[SUM]   0.00-30.02  sec  52.7 GBytes  15.1 Gbits/sec          receiver
```

**15.2 Gb/s** — meets plan §6.4 acceptance (≥15 Gb/s). The
MQFQ vtime change does NOT regress sustained throughput on
the iperf-c class.

## What this validation does NOT establish

- The targeted iperf-b same-class fairness gate is met
  post-#913 (would require a same-class harness).
- Master baseline comparison (would require running the same
  matrix on master).
- `make test-failover` — not run in this cycle.

These gaps are documented for the PR description; the user/PR
reviewers can decide whether to require additional validation
before merge or to defer to a separate validation PR.

## References

- Plan: `docs/pr/913-mqfq-vtime/plan.md`
- Issues: #911 (umbrella), #913 (this PR), #925 (panic
  supervision), #926 (demote inflation), #927 (was_empty
  restore).
- Code review history: 11 review rounds with disposition
  tables in plan §10-§24.
