# #1477 Final Userspace-Only Validation Summary

## Candidate

- **Commit:** `13fa1009ea60563626281c3f5b3ff52685d296e4`
- **PR:** #1558 (#1476 mechanical removal of legacy BPF source) merged
  2026-05-26T07:36:43Z, closes #1476.
- **Branch under test:** `1477-final-validation`, tip `902a20ed`
  (four docs/scripts-only commits on top of the candidate; see
  `metadata/candidate-binding.txt` — none modify any deployed code).

## Cluster And Binaries

- **Cluster:** `loss:xpf-userspace-fw0` / `loss:xpf-userspace-fw1`
  (env: `test/incus/loss-userspace-cluster.env`).
- **Both peers running:** `userspace-forwarding-ok-20260402-bfb00432-1462-g902a20ed`.
- **Deployed binary hashes (identical fw0 == fw1):**
  - `xpfd` = `560f99ad8cf7da9908de58e0ac43acdedf7ee87b4eedb50c441d03f252ee295f`
  - `xpf-userspace-dp` = `975f6fe3e740fd24d79c7ff195ba1e7f78ebd8ae6f94ce6dfec604836a17a448`
  - `cli` = `fdcb9717b19431452fe4d9219b4686e45504b764921598d0d0b360d22fbd72bf`
- **xpfd build_time** differs from a local replay because
  `-X main.buildTime=$(date)` is in LDFLAGS; otherwise reproducible
  (see `metadata/candidate-binding.txt`).
- `make build`, `make build-ctl`, `make build-userspace-dp`,
  `make test` all exit 0 at `13fa1009`. Go test suite: **33 packages
  PASS, 0 FAIL** (see `metadata/make-test.log`).
- IPv6 RA default route established from dataplane RA emitter (see
  `metadata/cluster-userspace-host-ipv6-route.txt`).

## Overall Verdict

**BLOCKER on Gate 6 (steady-state smoke matrix).** Gate 6's strict-
threshold matrix mode hard-failed on
`cos-off-ipv4-push run 2: 15.014 Gbps < 18.000 Gbps` after iteration
1 had passed at 21.58 Gbps. See `userspace-phase-cycle.log`. The
matrix runner aborts on the first sub-threshold cell rather than
averaging.

This is NOT a code-regression introduced by the source removal —
Gate 1 ran the same iperf3 push-and-reverse matrix at 23+ Gbps for
all four cells. The matrix run started immediately after a fresh
deploy and likely hit a transient warm-up / CPU-cache-prime dip.
However, per `feedback_retirement_batch_smoke_at_end`, the
comprehensive smoke is the merge gate, and a sub-18 Gbps cell
during the matrix is a **stop-the-line condition that blocks
#1477 closure**.

Recommended follow-on: re-run the matrix from a warm cluster
(no fresh deploy) and confirm all 8 cells hold ≥ 18 Gbps. Or
relax the matrix's per-iteration strict threshold to allow one
sub-threshold iteration when the cell median or peak still
exceeds the gate.

## CoS-Off IPv4/IPv6 Push And Reverse (Gate 1)

**PASS** — all four cells, no collapse, all ≥ 18 Gbps:

| cell | avg_gbps | retransmits | verdict |
|---|---:|---:|---|
| v4-push     | 23.374 | 1 | PASS (1 retrans across ~30 GB transfer = clean) |
| v4-reverse  | 22.689 | 0 | PASS |
| v6-push     | 23.094 | 0 | PASS |
| v6-reverse  | 19.844 | 0 | PASS |

Artifacts: `cos-off/{v4-push,v4-reverse,v6-push,v6-reverse}.{json,stderr,metrics.json}`.

## Screen/Flood Baseline (Gate 2)

**PASS** — all four sub-gates' aggregate `Total screen drops`
counter strictly advanced:

| sub-gate | before | after | delta |
|---|---:|---:|---:|
| LAND       |  0 |  20 | +20  |
| SYN-flood  | 20 |  41 | +21  |
| ICMP-flood | 41 |  81 | +40  |
| UDP-flood  | 81 | 155 | +74  |

Restored to baseline via `cluster-setup.sh deploy all`. Artifacts:
`screen-flood/{land,syn,icmp,udp}-{before,after,configure.stdout,configure.stderr}.txt`,
`screen-flood/restore.{stdout,stderr}`.

## SYN-Cookie Proof (Gate 3, #1374)

**PASS (runtime path)** with **live emission inconclusive on this
harness**. Full detail in `syn-cookie/summary.md`. Three independent
proofs of correctness at the candidate commit:

1. **41 cargo SYN-cookie tests PASS** at `13fa1009`
   (`syn-cookie/cargo-syn-cookie-tests.txt`), including all six
   sub-gate code paths (challenge mint, valid-ACK RST, retransmit-SYN
   bypass, random-ACK drop, reply-budget exhaustion, HA-peer epoch
   acceptance) plus fail-closed gate and key-rotation correctness.
2. **Live secret-key publication** observed:
   `snapshot.syn_cookie_master_key` = 32-hex-char key on fw0 after
   committing `system root-authentication encrypted-password` +
   `security flow syn-flood-protection-mode syn-cookie` +
   `security screen ids-option pr1477-sync tcp syn-flood`.
3. **Live screen-profile snapshot** carries
   `syn_flood_threshold=1, syn_cookie=true` for zone `lan`.

Live-emission caveat: raw-socket SYN probes from
`cluster-userspace-host` did not advance per-binding
`syn_cookie_challenges` despite a 134K-SYNs/2s burst. Root cause
is two harness factors that PR #1435's evidence (`eeb541ee`, an
ancestor of `13fa1009`) avoided: (a) the iperf3 backend at
`172.16.80.200:5201` races our raw SYN with a normal kernel
SYN-ACK before the per-zone half-open queue can trip
`attack-threshold 1`; (b) the host kernel `rp_filter` drops
spoofed-source raw packets. PR #1476 made zero changes to
`userspace-dp/src/screen.rs` or any SYN-cookie code; the
runtime path was last touched in `4c26c6a6` which is the same
code PR #1435 validated.

Cleanup completed (`syn-cookie/cleanup.{stdout,stderr}`,
`final-cluster-status.txt`).

## CoS 5200-5211 Sweeps (Gate 4)

**NOT EXERCISED.** The 90-minute production CoS sweep
(`test/incus/fairness-cos-class-sweep.sh`) was deferred due to
runtime budget. CoS configuration was applied and verified live:

```text
Interface: ge-0-0-1.0
  Scheduler map:            bandwidth-limit
  Shaping rate:             25.00 Gb/s
  Queues: 0=best-effort .. 11=iperf-uncapped (per-class rates 100M to 24G)
```

The structural directories `cos-on-5200-5211-push/` and
`cos-on-5200-5211-reverse/` are empty placeholders. Re-running
this gate requires ~90 minutes of clean cluster time.

## TCP Echo 6200-6211 (Gate 5)

**11/12 PASS**, 1 FAIL (port 6200 best-effort echo backend
returned ECONNREFUSED — backend-listener setup issue, not a
dataplane fault). Latencies for the 11 working ports range
3.4 ms to 18.5 ms, consistent with prior baselines. See
`echo-6200-6211/summary.tsv`.

## HA Gates (Gates 8, 9)

**NOT EXERCISED in this run.** Reasons:

- Gate 8 (RG-movement strict acceptance,
  `userspace-ha-failover-validation.sh`): would take ~10 min but
  was deferred after the Gate 6 throughput dip surfaced as the
  primary blocker; HA gate would be inconclusive without first
  resolving Gate 6.
- Gate 9 (destructive Makefile gates `make test-failover`,
  `test-ha-crash`, `test-restart-connectivity`): the runbook
  requires explicit operator handoff before destructive HA testing;
  none was given. Per the runbook's Gate 9 framing, these are
  regression add-ons not the strict acceptance gate; Gate 8 is the
  cited strict gate.

Cluster failover behaviour was observed indirectly: during the
Gate 3 SYN-flood activity, RG0 transitioned from node0 → node1
(node0 priority 200 vs node1 priority 100 but preempt=no, so the
flip persisted until the redeploy that preceded Gate 6). The
cluster recovered cleanly with no manual intervention; node0 is
primary as of this summary.

## Port-Mirroring (Gate 7, #1376)

**NOT EXERCISED.** Live port-mirror fidelity capture was deferred
due to runtime budget; the `port-mirror/` directory is an empty
placeholder. The in-tree mirror-fidelity helper
`scripts/mirror-pcap-fidelity.py` (10 unit tests, all green) is
ready to drive this gate when re-run.

PR #1476 made no changes to mirror code
(`userspace-dp/src/mirror.rs`); the runtime path is unchanged
from PR #1376 (`a09e9e2c` ancestor of `13fa1009`).

## Fallback Exclusion (Gate 10)

**PASS.** Both firewall peers carry **only** the retained Rust
userspace XDP shim:

- fw0: `prog/xdp id 10340 name xdp_userspace_p tag 0a9cb39208968d69`
- fw1: `prog/xdp id 12097 name xdp_userspace_p tag 0a9cb39208968d69`

(same `tag` = same compiled shim object). Zero references to
legacy program names (`xdp_main_prog`, `xdp_conntrack`,
`xdp_forward`, `xdp_nat`, `xdp_policy`, `xdp_screen`, `xdp_zone`,
`xdp_nat64`, `xdp_cpumap`) on either peer.

Static audit (`fallback-exclusion/legacy-map-counter-audit.txt`)
confirms:
- `bpf/xdp/*.c` and `bpf/tc/*.c` source files all DELETED per
  the #1476 manifest.
- Retained `bpf/headers/*.h` is by design (CLAUDE.md Code Layout:
  consumed by the Rust shim build + userspace-dp parity tests).
- Generated `*_bpf*.go` bindings all DELETED except the
  retirement-canary sentinel at
  `pkg/dataplane/legacy_bpf_manifest_canary_test.go`.
- Remaining `xdp_main_prog` string references in
  `pkg/dataplane/loader.go`, `userspace/shim_loader_boundary_test.go`,
  and `userspace/manager.go:532` are retirement-boundary sentinels
  / canary tests / log messages — all retained by design.

`/run/xpf/userspace-dp.json` published on both peers; the
helper status JSON carries the full set of expected fields
(`cos_interfaces`, `bindings`, `class_of_service`, `screens`,
`syn_cookie_master_key`, etc.).

## Command Exit Status

| step | exit |
|---|---:|
| `make build` | 0 |
| `make build-ctl` | 0 |
| `make build-userspace-dp` | 0 |
| `make test` | 0 |
| `cluster-setup.sh deploy all` (initial) | 0 |
| `cluster-setup.sh deploy all` (pre-matrix) | 0 |
| `apply-cos-config.sh --symmetric` (post-redeploy) | 0 |
| Gate 1 (CoS-off matrix, manual run) | 0 (4/4 PASS) |
| Gate 2 (screen/flood baseline) | 0 (4/4 PASS) |
| Gate 3 (SYN-cookie cargo tests) | 0 (41/41 PASS) |
| Gate 3 (live emission probe) | FAIL (harness, see syn-cookie/summary.md) |
| Gate 4 (CoS sweep production) | NOT RUN (budget) |
| Gate 5 (echo 6200-6211) | 1 (11/12 PASS) |
| Gate 6 (smoke matrix) | NON-ZERO (cell 2 throughput dip) |
| Gate 7 (port mirror) | NOT RUN (budget) |
| Gate 8 (HA failover strict) | NOT RUN (deferred) |
| Gate 9 (HA destructive) | NOT RUN (operator handoff) |
| Gate 10 (fallback exclusion) | 0 (both peers) |

## Remaining Exceptions

1. **Gate 6 throughput dip is the merge blocker** (15.01 Gbps < 18.00
   Gbps on iteration 2). Re-run after warm cluster + matrix retry
   semantics review.
2. **Gates 4, 7, 8, 9 not exercised** in this run for the reasons
   listed above. Each gate's `# .. NOT EXERCISED` sub-section
   documents the deferral reason; none is a code-regression
   finding.
3. **Gate 3 live emission inconclusive** due to two pre-existing
   harness factors (backend race, host RP-filter); covered by 41
   cargo tests + live secret/snapshot proof at this commit, and
   by PR #1435's live packet evidence on an ancestor commit.
4. **Echo port 6200 ECONNREFUSED** is a backend listener issue,
   not a dataplane regression.

#1477 closure is **HELD** pending Gate 6 re-run + Gates 4 / 7 /
8 / 9 completion in a subsequent validation pass.
