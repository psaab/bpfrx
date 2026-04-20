# Line-rate investigation — plan

## Problem statement

`iperf3 -c 172.16.80.200 -P 16 -t60 -p 5201` and the `-R` variant
both fall short of line rate on the `loss-userspace` test cluster
(mlx5 25 Gbps):

| Direction | SUM Gbps | % of line | Retransmits |
|-----------|----------|-----------|-------------|
| Forward   | 21.35    | 85 %      | **933**     |
| Reverse   | 19.10    | 76 %      | 0           |

Target: **≥ 24 Gbps (96 % of line) on both directions, ≤ 100
retransmits total across 16 flows over 60 s**. Forwarding must stay
healthy throughout any change we land. **Per-flow fairness** (CoV)
must not regress vs the current Phase 3 MQFQ + D3 baseline.

## Fairness non-regression constraint (FIRST-CLASS)

The preceding PRs (#795, #796, #797) delivered measurable fairness
improvements:

- **Pre-Phase-3 baseline**: mean CoV 54.7 % on `iperf3 -P 12 -t 20
  -p 5203`
- **Post-Phase-3 + D3 (current master)**: mean CoV ~ 38 %, with
  favorable runs under 20 %

That work established byte-rate-fair MQFQ ordering (Phase 3),
mlx5 RSS indirection narrowing (D3), and extensive test pins for
both. Any line-rate fix in this investigation MUST preserve those
gains. Specifically:

1. **CoV is a first-class validation metric**, alongside SUM and
   retransmits. Every validation capture records mean CoV, median
   CoV, per-flow min/max spread — not just aggregate throughput.
2. **If a fix adds throughput at the cost of CoV, it doesn't
   ship.** A 24 Gbps SUM with 60 % CoV is a regression vs 21 Gbps
   SUM with 38 % CoV for the 12-flow test — we'd be trading the
   recent fairness win for throughput. Unacceptable without
   explicit re-prioritization.
3. **The 16-flow test MUST ALSO be measured against the 12-flow
   test** we optimized. 12-flow is the shipped-regression target;
   16-flow is the new requirement. A fix that only helps 16-flow
   and breaks 12-flow is a net loss.
4. **Phase 3 MQFQ pins MUST keep passing** after any change. 13
   `mqfq_*` tests in `userspace-dp/src/afxdp/tx.rs` are load-
   bearing. The `pop_snapshot_stack` bound, the vtime round-trip
   neutrality, the drained-bucket re-anchor — all documented in
   commit history across rounds 1-4 of the Phase 3 review cycle.
5. **D3 knob semantics must keep working.** `rss-indirection
   enable|disable` must still toggle correctly; the allowlist
   must still scope only to userspace-bound mlx5 interfaces.

## Test environment ground truth (measured, not assumed)

- NIC: Mellanox (mlx5_core), 25 Gbps, MTU 1500, 6 RX queues,
  D3 indirection locks traffic to queues 0-3 (4 XDP-bound workers).
- xpfd dataplane: userspace-dp with 4 workers. Flag-off = Phase 3
  MQFQ + D3 (currently merged to master).
- Single-flow ceiling: 6.83 Gbps FWD, 6.14 Gbps REV. At 4 workers,
  ideal P=16 aggregate = 4 × 6.83 = 27.3 Gbps FWD, 4 × 6.14 = 24.6
  Gbps REV. Neither is currently achieved.
- No CoS classifier on port 5201 at the moment (verified via
  `show configuration`). So rate is NOT being artificially limited
  by CoS.

## Hypotheses for the forward-direction gap (21 Gbps / 933 retransmits)

The 933 retransmits are the loudest clue. A healthy pipeline at
steady state has ≤ 10s of retransmits over 60 s. Candidate causes:

**H-FWD-1: TX ring overrun at the dataplane.** When 4 workers each
push ~6 Gbps, the AF_XDP TX ring (sized at 16384 descriptors per
binding) can fill if `sendto()` wakeups or `reap_tx_completions`
lag. Packets get dropped at the ring boundary → TCP retransmit.
Would show up as `tx_errors` or `tx_dropped` on the NIC
interface counter, and as `TX_RING_FULL` drops in the userspace
helper's counters.

**H-FWD-2: Per-worker CPU saturation on a bottleneck worker.** If
RSS puts 5+ flows on one worker, that worker hits ~100 % CPU and
starts dropping. The 933 retransmits could cluster on the
per-flow rates of the busiest worker.

**H-FWD-3: Conntrack / session table miss storm.** On the forward
path, new flows install sessions. If session creation rate is
high (16 flows starting simultaneously), first-packet-drop or
DNS/NAT contention could cause burst retransmits during SYN/early
congestion window. Would show as retransmits concentrated in the
first 1-2 seconds.

**H-FWD-4: CPU thermal / mlx5 fill-ring starvation.** On high-
duration runs (60 s), NIC fill-ring may not be refilled fast
enough. Shows up as `rx_fifo_errors` on the NIC.

## Hypotheses for the reverse-direction gap (19 Gbps / 0 retransmits)

Different shape: lower throughput but ZERO retransmits. That
rules out loss. Candidates:

**H-REV-1: TX-side bottleneck on the firewall's RETURN path.**
Reverse = iperf3 server (172.16.80.200) pushes to client
(10.0.61.102). Return traffic: server → fw ingress (ge-0-0-2.80)
→ fw egress (ge-0-0-1) → client. The fw TX on ge-0-0-1 is the
workers' TX path for the reverse direction. Different MTU,
different ring? Needs verification.

**H-REV-2: mlx5 RX on ge-0-0-2.80 under-provisioned.** If the
VLAN sub-interface ge-0-0-2.80 has fewer RX queues than
ge-0-0-1, the reverse-direction ingress has less parallelism.
Would show in `ethtool -l ge-0-0-2.80` and per-queue counters.

**H-REV-3: Small-ring scratch buffer on redirected path.** With
MQFQ+Phase 3, shared_exact queues still have scratch arrays
(`scratch_local_tx`, `scratch_prepared_tx`) sized at
`TX_BATCH_SIZE` = 256. If the reverse path takes a different code
path (e.g., TC-classified differently), batching may be smaller.

**H-REV-4: TCP flow control on the server side.** iperf3 server's
socket buffers or TCP send queue might cap throughput. That would
be a test-setup artifact, not a firewall issue. Verify by running
the same -R test OUT OF the firewall (direct server-to-client on
the same L2) for a control.

**H-REV-5: Single-flow ceiling dominates the arithmetic.** Single
REV = 6.14; 4 workers × 6.14 = 24.6 theoretical max. 19 actual =
77 % of that. Gap is real but smaller once the single-flow limit
is accounted for.

## Investigation plan (before any code)

Each step produces evidence that closes or keeps a hypothesis. Run
before any fix.

### Step 1: capture NIC + driver counters during both directions

- Reset counters: `ethtool -S <iface> | grep -E 'err|drop|discard' > before`
- Run the P=16 t=60 test
- Capture again, diff
- Interfaces to watch: ge-0-0-1 (client-side), ge-0-0-2 / ge-0-0-2.80
  (server-side). Both directions exercise both ingress and egress
  counters.
- **Expected signal**: H-FWD-1 shows `tx_dropped` or ring-related
  error; H-FWD-4 shows `rx_fifo_errors` or `rx_missed_errors`.

### Step 2: capture per-worker CPU + softirq during the tests

- `mpstat -P ALL 1` on the fw for 65 s during each direction
- Record peak per-CPU %; which CPUs are pinned to the 4 workers?
- **Expected signal**: H-FWD-2 = one CPU at 100 % while others
  < 80 %.

### Step 3: capture xpf-userspace-dp counters pre/post

- `flow_steer_snapshot` via control socket (pre-existing from
  D1'-infra). Plus the CoS-drop counters.
- Run 60 s test.
- Capture after.
- **Expected signal**: H-FWD-1 = `tx_ring_full_drops` or
  equivalent; H-FWD-3 = session-install counters spike; H-REV-3 =
  scratch-rebuild counters.

### Step 4: single-flow direct test WITHOUT the firewall

- `iperf3 -c <server> -P 1 -t 10` directly, bypassing the fw if
  possible. Establishes the true single-flow ceiling.
- If single-flow direct = single-flow via fw, the fw is not the
  bottleneck per flow. H-REV-4 becomes non-primary.

### Step 5: ring size + queue count audit

- `ethtool -g ge-0-0-1` / `ge-0-0-2.80` — current vs max ring size
- `ethtool -l` — combined queue counts
- Compare to D3's indirection — are the same queues both AF_XDP-
  bound AND large enough?

### Step 6: reverse-direction topology walk

- Trace the reverse path: what code path handles server → fw
  ingress on ge-0-0-2.80 → fw egress on ge-0-0-1 → client?
- Is it the same shared_exact / owner-local-exact / surplus path
  as forward?
- Which worker handles the reverse flow? (Hash is of 5-tuple
  regardless of direction; so a symmetric hash + direction ends up
  on different workers.)

## Expected fixes per hypothesis

To be decided AFTER Step 1-6 findings. Premature:

- If H-FWD-1: tune TX ring size, `reap_tx_completions` cadence,
  batch-send timing.
- If H-FWD-2: adjust RSS indirection weights to redistribute
  flows (extend D3), or add flow-to-worker LB (D1' territory).
- If H-FWD-3: pre-install session entries for the flow 5-tuple, or
  batch session installs.
- If H-FWD-4: increase NIC RX buffer size, pin worker to a
  dedicated CPU.
- If H-REV-1: match forward-path TX-ring tuning to reverse path.
- If H-REV-2: bring up additional queues on ge-0-0-2.80 + rebind
  workers.
- If H-REV-3: increase scratch buffer size; measure cache-line cost.

Each fix will be its own PR, each with:
- A Rust/Go HFT-mindset impl (no hot-path alloc, no lock
  contention, atomic where possible, cache-line-aligned contended
  state)
- Measurement: matched 5-run before/after
- Codex adversarial review loop to merge-ready

## Validation at every step

After ANY change that modifies xpfd, before commit:
- `cargo build --release && cargo test --release --bin xpf-userspace-dp`
  → all 735 tests pass, including 13 `mqfq_*` pins
- `make test` (Go)
- Deploy to loss-userspace cluster
- Smoke: `iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5201` — positive
  throughput, 0 retransmits, flag-OFF and flag-ON if D1'-flag is
  relevant
- **Throughput target**: `iperf3 -P 16 -t 60 -p 5201` both
  directions — SUM ≥ pre-change, retransmits ≤ pre-change
- **Fairness target (co-equal with throughput)**:
  - Run `iperf3 -P 16 -t 60 -p 5201 -J` × 5 (both directions).
  - Compute mean SUM, mean CoV, median CoV, per-flow spread, total
    retransmits.
  - **Mean CoV MUST NOT increase** vs pre-change baseline on the
    SAME test.
  - **Also run `iperf3 -P 12 -t 20 -p 5203 -J` × 5** as the
    already-shipped-regression gate. Mean CoV MUST stay at or below
    the current ~38 % baseline on that test.
- Forwarding health: `ping 172.16.80.200` passes during test

If ANY validation regresses (throughput, retransmits, 16-flow CoV,
OR 12-flow CoV): rollback that commit immediately.

## Hard stops

- **Any iperf3 shows 0 Gbps or hangs**: rollback, forwarding is
  broken.
- **Retransmits increase**: something we fixed broke something
  else. Investigate before proceeding.
- **Mean CoV on 16-flow test increases > 5 percentage points**
  from this investigation's pre-change baseline: fairness
  regression, rollback.
- **Mean CoV on 12-flow `-p 5203` test increases > 5 percentage
  points** from the current 38 % master baseline: this investigation
  broke the already-shipped fairness work, rollback.
- **Any `mqfq_*` unit test fails**: the Phase 3 load-bearing
  invariants are broken. Rollback.
- **NIC link drops / systemd service failure**: kill switch.
- **CPU softlockup / kernel oops**: hard rollback, debug offline.

## Out of scope for this effort

- D1' work (flow-to-worker LB). That's a separate multi-week
  design; documented on `pr/785-d1-flow-worker-lb`. If our fixes
  can't close to line rate and the bottleneck is RSS distribution,
  we'll flag it and stop.
- fw1's pre-existing fab0 compile bug. Separate issue.
- Non-iperf3 traffic patterns. Only the two commands the user
  specified are in scope.

## Phasing

Five serialized phases:

1. **Phase A**: plan + adversarial review until both reviewers
   agree (no code).
2. **Phase B**: investigation (steps 1-6 above). Produces an
   updated findings doc naming the root cause(s).
3. **Phase C**: per-finding GitHub issue filed. Scope + fix
   proposal per issue.
4. **Phase D**: one PR per issue. HFT-mindset implementation.
   Adversarial review loop per PR until merge-ready.
5. **Phase E**: final validation — both directions at line rate,
   forwarding stable. Document outcome.

Stop conditions per phase: a phase doesn't start until the prior
one is complete + documented + reviewed.

## Risks

- **Cluster state drift during long investigation**. Mitigation:
  snapshot counters at each step, re-measure baseline between
  sessions.
- **Forwarding break during experimentation**. Mitigation: every
  change gated on the validation checklist; rollback commits
  preserved in branch history.
- **RSS distribution luck**. CoV varies run-to-run because RSS
  hashing 16 flows into 4 bins is stochastic. Mitigation: always
  report 5-run means, not single runs.
- **Unrelated bugs surface during investigation**. If we hit
  fw1's fab0 bug or a D1' infrastructure issue, file a separate
  issue and continue on the main investigation.
