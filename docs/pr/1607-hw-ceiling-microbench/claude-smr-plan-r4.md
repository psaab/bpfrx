# Claude SMR plan-review r4 — #1607 v2 patched-round-3

## Verdict: PLAN-READY

After ingesting AGY r3 PLAN-NEEDS-MAJOR (3 axes + 1 hazard) and
verifying each independently, the v2-round-3 patches address all
findings. r4 votes PLAN-READY.

## Adjudication of AGY r3 findings

### Axis 1 — Burst-install contention in `replicate_session_upsert` → AGY RIGHT; v2-r3 patched

Verified at `userspace-dp/src/afxdp/session_glue/mod.rs:573-583`:

```rust
pub(super) fn replicate_session_upsert(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    entry: &SyncedSessionEntry,
) {
    let replica = synced_replica_entry(entry);
    for commands in worker_commands {
        if let Ok(mut pending) = commands.lock() {
            pending.push_back(WorkerCommand::UpsertSynced(replica.clone()));
        }
    }
}
```

Every successful install acquires N (= worker_count) per-worker
Mutexes and clones the replica payload. At 6 workers × 5 M installs/s
× 26 ms = 786 K lock acquisitions in 26 ms ≈ 30 M locks/s aggregated.
This is a real measurement of session-replicate contention, but it's
a BURST profile that distorts the latency histogram for any per-call
latency claim.

AGY's prescription is correct: promote `--cohort=unbounded` to default
so the cold path stays continuous for the full run, and replicate is
bypassed entirely after the 26 ms warm-up. Bounded mode is preserved
as `--cohort=bounded` for diagnostic install-cost measurement, but
not the Scale Target default.

**v2-r3 patch §4.2.0**: Regime A (unbounded) is now default. Regime
B (bounded) is documented as a separate diagnostic measurement.
**CLOSED.**

### Axis 2 — Table B warm-path illusion in bounded mode → AGY RIGHT; v2-r3 patched

In bounded mode, packets 1 through 131 K are cold-path. Packets
131 K+1 through 150 M (the rest of the 30 s run at 5 Mpps) hit the
flow cache. Aggregate Mpps averaged over the whole 30 s reflects
99.9 % warm path — a "throughput number" that's actually steady-state
flow-cache hit rate, not cold-path throughput.

**v2-r3 patch §4.6**: split Table B into:
- Table B1 (warm-path-after-fill, sourced from Regime B bounded) —
  explicitly labeled "warm path"
- Table B2 (cold-saturated, sourced from Regime A unbounded) —
  explicitly labeled "cold path"

**CLOSED.**

### Axis 3 — p9999 statistical starvation in bounded mode → AGY RIGHT; v2-r3 patched

131 K samples × 0.0001 = 13.1 samples in the p9999 bucket. p9999
estimate from 13 samples has ±29 % standard error at 95 % CI — not
useful for the JIT design doc.

Unbounded mode: at 1-in-256 sampling × 150 M packets = 586 K samples
× 0.0001 = 58.6 K p9999 samples. Standard error ±0.4 % — clean.

**v2-r3 patch §4.6**: p9999 column appears in Table A1 (unbounded
default) only; Table A2 (bounded diagnostic) reports only through
p999. **CLOSED.**

### Hazard 1 — clock_gettime VM jitter → AGY RIGHT; v2-r3 patched

On nested-VM CI runners without invariant TSC, vDSO `clock_gettime`
can have ±100 ns jitter per call (hypervisor context-switch). At
1-in-256 sampling the amortized per-packet bias is ~0.4 ns, but the
**per-sample** latency value (which is what feeds the histogram) is
biased by ~100 ns. Publishing those numbers in the Scale Target
table would mislead JIT planning into a higher cold-path budget
than reality.

**v2-r3 patch §4.6**: TSC-only gate. Runs with
`clock_source = clock_gettime` are stored in raw TSVs (for
correctness debugging) but NOT published in the Scale Target table.
The graceful degrade preserves harness operability on CI; the
output policy filters out the noisy regime.

**CLOSED.**

## Remaining nits (non-blocking)

- **N9 (new)**: at unbounded-default, the harness should record (in
  the TSV) `cold_path_dominated_fraction` = (cold_samples /
  total_packets). When ~99.9 % the regime is healthy; when <50 %
  something went wrong (flow cache too large, session-table
  install_rejected path broken, etc.).
- **N10 (new)**: §4.6 Table A2/B1 measurements still need to run.
  Plan ships the harness + default-regime numbers in PR; bounded
  diagnostic numbers can be a follow-up note. Don't block the PR
  on Table A2/B1 if they're slow to populate.

## Self-correction note r3 → r4

r3 votes PLAN-READY post-AGY-r2-patch. AGY r3 pushed back with a
nuanced "burst install distorts latency" argument that I had not
considered: even though Regime B measures the *real* cold-path
including install, the burst profile distorts the per-call latency
in a way that doesn't reflect sustained 100 K new-flows/s production
load. The right resolution is to measure both regimes and label them
clearly, with Regime A (pure policy eval) as the primary JIT-budget
number and Regime B (install + replicate) as a separate concern.

The lesson here is broader: there is no single "cold-path latency"
number for the JIT design doc. The JIT engine optimizes the
policy-eval loop, which is what Regime A measures. Session install
+ replicate is a separate hot-path-burst that the JIT cannot help
with — it requires lock-free replicate (separate refactor track).
v2-r3 acknowledges this by separating the two concerns in the
published tables.

## Domain-specific checks (status post-r3 patch)

All r3 PASS, none regressed.

| Check | Status |
|-------|--------|
| Hot-path allocation rule | PASS |
| Lock ordering / ArcSwap semantics | N/A — no new locks |
| HA sync portability | PASS — no HA-touching code |
| Numerical / counter overflow | PASS |
| Verifier / kernel-API constraints | N/A — userspace-only |
| Wire-protocol both-sides | PENDING IMPLEMENTATION |
| Modularity discipline | PASS |
| Cache-line / false-sharing | PASS |
| Smoke v4+v6 × push+rev × CoS-off+on | Pending Step 6 |
| Session table cohort budget | PASS — dual-regime |
| Splitmix slot pick | PASS |
| Bucket-saturation tail visibility | PASS |
| Flooder host-pinning | PASS |
| TSC-only Scale Target gate | PASS post-r3 |
| Burst-install contention isolated | PASS post-r3 (Regime B isolated) |
| p9999 statistical adequacy | PASS post-r3 (Regime A only) |

Final r4 verdict: **PLAN-READY**.
