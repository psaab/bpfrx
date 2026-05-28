# Claude SMR plan-review — #1614 v1, round 1

Reviewer: Claude (SMR — network scheduling / shaper semantics / AF_XDP
queue physics / CPU microarchitecture / Junos CoS contract).

Method: hostile-verify. Treat the plan as if the author is wrong until
quoted-line code evidence says otherwise.

Verdict: **NEEDS-MAJOR** — three fatal classes of finding plus several
substantive ones. Plan v2 is achievable; PLAN-KILL is not warranted at
this round.

## Fatal findings

### F1. §3 reading of the current scheduler is WRONG in a way that load-bears the entire Axis A design

The plan asserts in §3:

> "today's exact-class root drain is approximately pro-rata-by-shape
>  (≈19-26% of each shape, scaling with the rate)"

and walks a (shape/109)×18 table that matches the observed data
roughly. The conclusion: the scheduler is "approximately
pro-rata-by-shape WFQ".

This reading is internally inconsistent with the code in
`userspace-dp/src/afxdp/cos/queue_service/mod.rs:589-718`
(`select_exact_cos_guarantee_queue_with_lease_telemetry`). Reading
that function:

- Cursor `exact_guarantee_rr` walks queues in round-robin (line
  600 `start = root.exact_guarantee_rr % queue_count`, line 702
  advances after selection).
- Per-visit budget is `cos_guarantee_quantum_bytes(queue)` which
  IS rate-proportional. So under saturation, higher-rate queues
  *do* get more bytes per visit.

But the cursor advances by exactly 1 queue per selection. So in
saturation, the steady-state per-second throughput per queue is
`quantum × visits_per_sec`, and visits-per-sec is the same for all
runnable queues (since cursor walks them round-robin and they're
all `runnable=true`). That gives **rate-proportional**, not
**pro-rata-by-shape-sum**. The (shape/109)×18 prediction in §3 is
NOT the same calculation as rate × constant-visits — it's
shape/sum-of-shapes × ceiling, which only matches accidentally
because all 10 queues have approximately the same access frequency
and `quantum ∝ rate`.

So the plan's prediction table happens to match the data, but the
proposed Axis A1 design — replacing this with "guarantee-honoring"
two-pass — is solving a problem the scheduler doesn't have in the
shape the plan describes. The actual root cause is more subtle:

**The actual root cause hypothesis (revised)**: the scheduler IS
already rate-proportional via the quantum. Under oversubscription
with 10 exact queues, each queue gets `quantum(rate_i)` per visit
and ~K visits/sec total. The per-queue rate that lands is
`min(quantum × visits_per_sec, rate_i)`. With `visits_per_sec`
limited by root tokens replenishing at `shaping_rate / quantum`,
every queue gets `(rate_i / sum_rates) × shaping_rate`.

For 10 exact classes with sum_rates=105G and shaping_rate=25G,
that gives queue_i = rate_i × 25/105 ≈ 0.238 × rate_i. The data
shows ~0.21 × rate_i on the larger classes (rate cap kicks in
beyond ~3 G per queue). This is consistent with
**rate-proportional-NOT-guarantee-honoring**.

The plan's Axis A1 design (two-pass guarantee-first then surplus)
IS the correct fix for this, but the §3 framing is wrong. Plan v2
must:

- Re-read the code path and fix the §3 description.
- Re-confirm the proposed Pass-1 / Pass-2 separation actually
  solves the rate-proportional-not-guarantee-honoring shortfall.
- Quantify: with Pass-1 honoring guarantees first, what's the
  predicted distribution for the 109-G fixture? Show the math
  per-class.

Severity: HIGH. The plan would proceed with a design that may be
correct but for wrong reasons; if reviewers read §3 and accept the
"pro-rata-by-shape" diagnosis, they're agreeing to a design
narrative that doesn't match the code. We need to re-ground.

### F2. R8 (generator-bottleneck) is unaddressed — empirical baseline may be wrong

The plan acknowledges R8 in §10 but proposes nothing concrete to
rule it out before implementation. This is the same class of
confounder that drove #1611+#1615 to file follow-up issues for
generator infrastructure.

The 109-G simul measurement runs 11 iperf3 processes ON
`loss:cluster-userspace-host`, a 16-CPU virtio incus container.
iperf3 is single-threaded per-process; 11 senders is ~11 CPUs
busy on the generator. Add receiver-side processing on the
firewall-output side, and we may be measuring **generator
saturation** not firewall scheduler behavior.

Concrete check needed BEFORE plan-review proceeds:

```bash
# Reverse direction simul (no scheduler involvement):
for port in 5201..5211; do
  incus exec loss:cluster-userspace-host -- iperf3 -c 172.16.80.200 \
    -P 12 -t 30 -p $port -R --json > /tmp/rev_$port.json &
done
wait
# Compare sum(reverse_aggregate) to sum(push_aggregate). If they're
# both ~20 G, the generator is saturated and the push 18 G isn't
# the firewall ceiling — it's the iperf-mesh CPU ceiling.
```

If this check shows reverse simul-load also caps at ~20 G total,
**the entire plan baseline is wrong** and #1614 needs re-measurement
on a beefier generator (per #1615 in flight). At that point we
might find the actual regression is much smaller than reported,
and Axis A's necessity is unproven.

Plan v2 MUST run this check OR show the reverse-simul number from
prior runs. Without it, we're building on shifting sand.

Severity: HIGH. Could change the entire problem definition.

### F3. ECN-WRED proposal (A3) doesn't address the TX-side buffer drops causing the retransmits

The retransmits come from packets dropped at the CoS admission
gate (admission.rs). The ECN-WRED proposal marks packets BEFORE
the gate fires hard-drop. But the marking only helps if:

- Endpoints honor ECN (TCP_ECN). Most modern Linux endpoints do.
- The signaling round-trip latency lets endpoints reduce cwnd
  fast enough to relieve the queue before tail-drop.

For the iperf3 fixture with 12 streams per class, each stream has
its own cwnd. Marking 1 packet in 100 reduces that 1 stream's
cwnd by some fraction; the other 11 streams in the class continue
at full cwnd. The aggregate queue residence doesn't drop fast
enough — you need to mark ~50% of packets, which is at the
breakdown threshold of standard RED algorithms.

The plan also assumes WRED's `linear ramp from 75% to 100%` is the
right curve. CoDel/PIE algorithms outperform RED in modern
deployments by a measurable margin (RFC 8290, RFC 8033).

Plan v2 should either:
- Use CoDel-style time-based AQM (one-line conceptual change to
  the gate decision: drop/mark when sojourn time > target ~5 ms),
  OR
- Show empirically that RED-style WRED gets retrans below 100/30s
  on the 109-G fixture.

Bare WRED at 75%-100% with no math backing is hand-waving.

Severity: MEDIUM-HIGH. Mechanism may not deliver acceptance criterion 4
(retrans ≤ 100). If it doesn't, A3 has to be ripped out and replaced.

## Substantive findings

### S1. Priority-low min-share at 5% of ceiling is a magic number

§4 A2 sets the default min-share at 5% of `root.shaping_rate_bytes`.
On the 25-G fixture, that's 1.25 G floor for priority-low. Where
does 5% come from? The issue body acceptance criterion 2 says "≥5%
of cluster ceiling". But that's an acceptance gate, not a design
constant. The actual right number depends on what priority-low
*is* — if it's "scavenger traffic", 5% might be too high; if it's
"any non-tagged TCP", 5% might be too low.

Plan v2 must either:
- Justify 5% with a coherent argument (e.g. ≥ 1 priority-low flow
  per RSS queue × min flow throughput ~ N MB/s), OR
- Make it configurable per-queue with a documented default.

Severity: MEDIUM.

### S2. Wire-protocol change (priority_low_min_share_bps) needs the both-sides grep

The plan §4 A2 adds a new field to `CoSInterfaceConfig` on both
Go and Rust sides. Per memory `feedback_wire_protocol_both_sides`,
this needs grep on BOTH protocol.rs AND protocol.go. The plan
mentions this but doesn't enumerate the actual files. From a
quick directory scan: `userspace-dp/src/protocol/` is split (per
recent refactor PRs); `pkg/dataplane/userspace/` likely has the
Go protocol file. Plan v2 should list the exact files and the
exact byte-level wire field name.

Severity: LOW (mechanical, just needs explicit listing).

### S3. The simul-load harness in §11.2 doesn't pin the generator CPU

If R8 holds (the 109-G data isn't generator-bound), the new Pass-C
harness still needs to ensure measurement reproducibility. Add
explicit `taskset`/`incus exec --cpu-allowance` to pin generator
processes to specific CPUs. Otherwise the harness's first run gets
one CPU layout and subsequent runs get others, producing
inconsistent verdicts.

Severity: LOW-MEDIUM.

### S4. §6 (operator warning) needs to land in the Go commit validator with a covering test

Plan §6 is one paragraph. The commit validator chain is:
parser → AST → typed config → commit. Need a unit test in
`pkg/config/cos_test.go` that builds a config with sum > shaping,
runs the validator, and asserts the warning string. Plan v2 must
list this test.

Severity: LOW.

### S5. The Axis B mechanisms aren't sufficient for the §7 acceptance criteria 1

Acceptance criterion 1 says "≥ 90% of shape OR ≥ 90% of pro-rata".
With the 18-G ceiling and 109-G shape sum, NO mechanism short of
raising the ceiling can achieve 90% of shape for the larger classes
(24 G class can't get 21.6 G from an 18-G pipe). So criterion 1
reduces to "≥ 90% of pro-rata-by-rate", which for 24-G class is
0.9 × 18 × (24/105) = 3.7 Gbps — barely above the current 3.62 G.

This means Axis A alone, even if it perfectly fixes guarantee-
honoring for small classes, can ONLY move the small classes
(100m, 1g, 3g) into compliance. Mid-large classes already hit
~90% of pro-rata. Reviewer must agree: Axis A is "fix small
classes + priority-low + retrans"; raising ceiling is Axis B's
job; the §7 criterion 3 (≤10% CoV) is the Axis A test for "is
the scheduler doing it right".

Plan v2 should make this crisper: which acceptance criteria does
each Axis own? Today's plan mixes them.

Severity: MEDIUM.

### S6. The "test failover" check is binary; doesn't measure scheduler-state preservation

`make test-failover` checks for ~60 ms failover. It doesn't check
whether per-queue token-bucket state is preserved across failover.
After takeover, if the secondary chassis starts from cold token
buckets, the first ~100 ms of post-failover traffic gets
mis-scheduled. Plan v2 should add a measurement: per-class
throughput during the 1 s after failover vs steady-state.

Severity: LOW-MEDIUM (likely fine but unverified).

### S7. The plan doesn't address the i40e WAN VLAN tagging path

The data flows through `reth0.80` (VLAN 80 on the i40e PF
passthrough). The 802.1Q priority bits get rewritten by the
ECN/CoS path. Verify in the plan that the rewrite-priority and
admission ordering don't interact badly with VLAN tag insertion.

Severity: LOW.

## What the plan got right

- Two-axis framing is correct and important. Mixing capacity-scaling
  with scheduler-semantics in one mechanism would be a methodology
  failure.
- Kill-chain respect table (§8) is well-structured and credibly
  navigates the closed-issue minefield.
- Deferring Axis B with explicit per-PR plan-review gates is
  disciplined.
- Acceptance criteria are concrete numbers, not "improve
  fairness".
- R6/R8 (own-code-reading and generator-bottleneck) flagged as
  open questions rather than swept under.

## Decision

NEEDS-MAJOR. F1 + F2 + F3 must be addressed in plan v2 before
implementation. F1 changes the design narrative; F2 may change
the entire problem; F3 may force a sub-mechanism redesign.

If plan v2 addresses all three (especially F2 — run the reverse-
simul check FIRST), this should be PLAN-READY-able on round 2.

Author: stop. Address F1+F2+F3 in plan v2. Don't run codex/agy
on plan v1.
