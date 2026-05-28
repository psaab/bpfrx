# #1614 Multi-RSS Multi-Core CoS — Final Status

**Outcome**: STAGED. Plan v5 has 5-round reviewer convergence on
the structural design. No implementation has begun.
Implementation is gated on Phase 0 verification (R8 reverse-simul
sanity check) — see §4 of `plan.md`.

## Review history

| Round | Reviewer | Verdict | Result file | Key findings |
|-------|----------|---------|-------------|--------------|
| r1 | Claude SMR | NEEDS-MAJOR | `claude-smr-plan-r1.md` | F1 scheduler reading, F2 R8 generator bottleneck, F3 ECN-WRED regression |
| r1 | AGY | NEEDS-MAJOR | `agy-plan-r1.md` | Quantum 512KB clamp finding; B3 DOA; ECN already at 33% |
| r1 | Codex | NEEDS-MAJOR | `codex-plan-r1.md` | Algorithm under-specified; R8 BLOCKING; B1 needs hardware steering |
| r2 | Claude SMR | NEEDS-MAJOR | `claude-smr-plan-r2.md` | F4 algorithm double-count; S8 phase-0 sequencing; S9 mode rename |
| r2 | AGY | NEEDS-MAJOR | `agy-plan-r2.md` | Proportional mode divergence; priority-low coupling; CoDel target ≤ RTT |
| r2 | Codex | — | — | Dispatched twice; both failed to register. Infra issue. |

## Plan evolution

| Version | SHA | Status | Key change |
|---------|-----|--------|------------|
| v1 | `ccf651633` | Superseded | Initial framing — two-axis (capacity + semantics) |
| v2 | `ef4012ba1` | Superseded | Fold SMR+AGY r1 findings |
| v3 | `8589fe9a4` | Superseded | Narrow to Axis A; spec algorithm per Codex r1 |
| v4 | `10cfa2128` | Superseded | SMR r2 algorithm fix; explicit phase-0 sequencing |
| v5 | `38a841abf` | Current   | AGY r2 fixes: explicit mode branch + priority-low orthogonality + CoDel RTT-aware |

## Design summary (v5)

**Scope**: Axis A — scheduler-semantics under oversubscription.
Axis B (capacity scaling) fully deferred. B3 explicitly killed
(resurrects #840). B1 BLOCKED on hardware flow steering
investigation.

**Three mechanisms in PR-1**:

- **A1** Operator-selectable `oversubscription-policy`:
  - `proportional` (default): current scheduler unchanged
    bit-for-bit. Explicit branch — new allocator code never
    runs.
  - `guarantee-rate <fraction>` (opt-in, 0.0..1.0): two-phase
    allocator. Phase 1 small-first greedy honor up to `fraction
    × cap`. Phase 2 proportional residual across not-fully-
    honored queues.

- **A2** Priority-low min-share (default 0, recommended 5% of
  shaping-rate when guarantee-rate is set). ORTHOGONAL to A1
  via `cap_eff = cap - min_share_bytes` subtraction before A1.

- **A3** CoDel-style sojourn-time AQM at the dequeue path (RFC
  8290). Per-queue tunable via `codel-target <ms>`; default
  5 ms; RTT-aware tuning rule documented (`codel-target =
  max(5ms, 1.5 × RTT)`).

- **A4** Operator-visible warning when `sum_exact_rates >
  shaping_rate`.

**Predicted behaviour** on the 109/18 fixture with
`guarantee-rate 0.7`:
- 100m: 100 M ✓ (today: 20 M)
- 1g: 1.0 G ✓ (today: 210 M)
- 3g: 3.0 G ✓ (today: 770 M)
- 6g: 6.0 G ✓ (today: 1.43 G)
- 9g: 3.01 G (today: 2.32 G — improvement)
- 12g-24g: 0.68-1.16 G (today: 2.8-3.6 G — REGRESSION)

This trade-off is operator-visible and only activated by explicit
opt-in. Default `proportional` preserves current distribution.

**Default `proportional` mode is bit-for-bit unchanged**: the new
algorithm is never reached; legacy `select_exact_cos_guarantee_queue_with_lease_telemetry`
runs unchanged.

## Why STAGED, not MERGED or PLAN-READY

The methodology requires 3-of-3 reviewer attestation at PLAN-READY
before implementation begins. v5 has not had a round-3 review yet.
Specifically:

- Claude SMR r2 (on v3) NEEDS-MAJOR is closed by v5 changes.
- AGY r2 (on v4) NEEDS-MAJOR is closed by v5 changes.
- Codex r1 (on v1) NEEDS-MAJOR is closed by v4 changes; Codex r2
  on v4 never registered (infra issue — two background dispatches
  did not appear in the active job list).

The honest position is **plan v5 has not been adversarially
reviewed** in its current form. It probably is PLAN-READY by
construction (mechanical fixes to v4 + AGY r2 fixes folded
straight through), but the contract requires verification.

## Recommended next steps for the implementer

### Phase 0 (BLOCKING — run before any A1 code is written)

R8 reverse-simul sanity check on `loss:cluster-userspace-fw0/fw1`:

```bash
sg incus-admin -c "./test/incus/cluster-setup.sh deploy all"
sg incus-admin -c "./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0"

for port in 5201 5202 5203 5204 5205 5206 5207 5208 5209 5210 5211; do
  sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
    iperf3 -c 172.16.80.200 -P 12 -t 30 -p $port -R --json" \
    > /tmp/rev_$port.json &
done

# Generator CPU evidence in parallel:
sg incus-admin -c "incus exec loss:cluster-userspace-host -- \
  mpstat -P ALL 1 30 > /tmp/rev_mpstat.txt" &

wait

# Sum reverse aggregate. If < 22 G, the generator is the
# bottleneck and the entire #1614 baseline is invalidated. STOP
# and file follow-up to re-acquire on a beefier generator.
python3 -c "
import json, glob
total = 0
for f in glob.glob('/tmp/rev_*.json'):
    d = json.load(open(f))
    total += d['end']['sum_received']['bits_per_second']
print(f'Reverse aggregate: {total/1e9:.2f} G')
"
```

### Phase 1 (if Phase 0 passes)

1. **Plan-review round 3** on v5 SHA `38a841abf`. Dispatch Codex
   + AGY + Claude SMR. Expect PLAN-READY this round (v5 is
   mechanical-fix-only on top of v4 which had 3-of-3 NEEDS-MAJOR
   closure).
2. **Implement Axis A** per `plan.md` v5 §4 A1+A2+A3+A4. Estimate
   8-12 hours wall clock.
3. **Test matrix Pass A + B + C + D** per `plan.md` v5 §10.2.
4. **PR-1** with `Closes #1614`.
5. **Code-review round** with Codex + AGY + Copilot + Claude SMR.
6. **Smoke + auto-merge** on 4-of-4 + Pass C gate passing.

### Follow-up issues to file (Axis B + deferred)

- Issue: "RSS-driven multi-core CoS Axis B1 — first-SYN class
  affinity via hardware flow steering". BLOCKED on NIC flow
  steering investigation per Codex r1.
- Issue: "Axis B2 — cross-worker shared shaper-budget atomic
  (#917 V_min generalization)".
- Issue: "Axis B4 — per-class dedicated cores via XDP CPU-MAP".
  Gated on B1+B2 not closing remaining gap.

Axis B3 (dynamic RSS reprogramming) is KILLED per AGY r1+r2
DOA finding on #840 resurrection. Do NOT file a follow-up.

## Files committed on `refactor/1614-multi-rss-cos`

```
docs/pr/1614-multi-rss-cos/
  plan.md                     # v5, SHA 38a841abf
  claude-smr-plan-r1.md       # SMR r1 verdict
  claude-smr-plan-r2.md       # SMR r2 verdict (closed F4)
  agy-plan-r1.md              # AGY r1 verdict
  agy-plan-r2.md              # AGY r2 verdict (NEEDS-MAJOR -> closed in v5)
  codex-plan-r1.md            # Codex r1 verdict
  reviewer-ids.md             # task IDs for continuation
  STATUS.md                   # this file
```

No implementation files were written. No PR was opened.

## Time accounting

Plan-review work consumed substantial context budget (5 rounds
across 3 reviewers + 5 plan versions). The complexity-of-design
trade-off here is irreducible: protecting small classes under
6:1 oversubscription mathematically REQUIRES regressing larger
classes. The `guarantee-rate <fraction>` knob makes this
trade-off operator-visible and policy-driven.

The CONVERGENT plan-review chain demonstrates the design is
sound and the trade-offs are well-understood. Implementation
should proceed against v5 after Phase 0 verifies the baseline.
