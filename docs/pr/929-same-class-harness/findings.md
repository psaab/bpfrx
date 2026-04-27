# #929 Same-class harness — cluster smoke findings

Smoke + binding-case measurements taken on the loss userspace
cluster (xpf-userspace-fw0/fw1, cluster-userspace-host source,
172.16.80.200 target with port 7 TCP echo) on 2026-04-27.

## Combined-branch deploy

The harness was validated against a combined branch that merges
all four 100E100M sprint streams (sprint/918-flow-cache-4way +
sprint/920-batch-size-l1d + sprint/914-rate-aware +
sprint/929-same-class-harness). `cargo test --release` passed
778/778 tests.

## Throughput sanity (#914 + #920 gates)

- `iperf3 -c 172.16.80.200 -p 5203 -P 12 -t 30` (iperf-c
  shared_exact, the rate-aware-cap path):
  - **23.47 Gb/s sent / 23.46 Gb/s recv**
  - 55 retransmits across 30 s × 12 streams
  - Above the 22 Gbps gate from #914 acceptance ✓

- `iperf3 -c 172.16.80.200 -p 5203 -P 128 -t 30` (high-stress,
  100E equivalent):
  - 16.84 Gb/s sent / 16.71 Gb/s recv
  - 706 k retransmits
  - Per-flow CoV: 12.4 % (median 0.128 Gb/s, max 0.188 Gb/s)
  - Zero CoS admission drops in any queue (`drops:
    flow_share=0 buffer=0 ecn_marked=0` on iperf-a/b/c). The
    retransmits are external (NIC TX or wire-level), not
    daemon-side.

## Mouse-latency tail (#911 / #905 binding case)

| Cell | p50 (ms) | p95 (ms) | p99 (ms) | completed | mpstat |
|---|---|---|---|---|---|
| Idle (N=0, M=10) | 2.56 | 3.34 | **5.87** | 2186 | n/a |
| Cross-class iperf-a (N=128, M=10) | 2.21 | 5.30 | **203.75** | 2187 | n/a |
| **Same-class iperf-b (N=128, M=10)** | 6.46 | 46.63 | **60.64** | 3359 | 53.83 % |

The same-class case is the binding measurement for #911 — the
HOL gate that #913 (shipped) and the four sprint PRs target.
Combined-branch p99 of **60.64 ms** at same-class iperf-b N=128
is **3.4× lower than the cross-class iperf-a N=128 baseline of
203.75 ms** on the same combined binary.

Pre-PR same-class baseline numbers are not in the #905 dataset
(the existing harness only exercised cross-class); the
comparison above is qualitative — same-class behaves
materially better than cross-class once #913 + #918 + #914 +
#920 are all in place. A direct same-class-vs-master comparison
would require deploying master with the new harness for an
A/B run.

## Harness fixes caught during smoke

Two issues required follow-on commits to #929 before the smoke
could complete:

1. **`nc` not in source container.** The v1 preflight used
   `nc -zw1 ${TARGET_V4} ${MOUSE_PORT}` which exited 127
   ("command not found") and aborted every rep before the
   probe ran. v2 uses `bash /dev/tcp` (built-in to bash, works
   in any container).

2. **Echo listener on port 7, not 5212.** v1 of the plan
   assumed the operator would stand up a separate listener
   on 5212 specifically for same-class. The operator's actual
   topology runs a single echo on port 7 for both cross- and
   same-class. v2 same-class fixture overrides port 7's CoS
   classification (best-effort → iperf-b) instead of routing
   to a different port. No second listener required.

Both fixes are in commit 2a0d1d0a.

## Acceptance status

- [x] Smoke (§6.1) produces valid same-class probe.json.
- [x] Regression (§6.2) cross-class baseline unchanged
      (203.75 ms p99 matches #905).
- [ ] E2E matrix (§6.3) — single cell run; full 12-cell matrix
      deferred to post-merge so each Rust stream can be
      validated against the harness independently.
- [x] Gate ratio computable from same-class data
      (60.64 ms / 5.87 ms idle = 10.3× — well below the
      cross-class 35× ratio).
- [x] Documentation (this file).
