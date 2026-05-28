# Claude SMR plan-r1 — #1621 cold-path wire + Prometheus

**Reviewer**: Claude (SMR: wire protocol, Prometheus exposition,
seqlock snapshot semantics, Go-Rust serde correctness)
**Plan doc**: plan.md v1 @ fb3c17d94
**Verdict**: PLAN-NEEDS-MINOR

Three substantive findings + 2 nits. None are KILL-level.

## F1 (MED, §4.2 merge contract) — alias_seen merge is the right shape; first_key merge needs sharper definition

Plan-v1 §4.2 pseudocode for `first_key`:
```rust
if merged.first_key[slot] == 0 {
    merged.first_key[slot] = binding.cold_path.first_key[slot];
} else if binding.cold_path.first_key[slot] != 0
    && binding.cold_path.first_key[slot] != merged.first_key[slot]
{
    merged.alias_seen[slot] = true;
}
```

This is **correct semantically** but the order matters: if binding A's
first_key is 0 and binding B's is K, we set `merged.first_key = K`.
On the NEXT iteration if binding C has L, we detect alias.

But the per-binding `WorkerColdPathCounters.first_key[slot]` itself
may be 0 if NO sample landed in that slot during the window. If
binding A has slot S=K (3 samples) and binding B has slot S=L (no
samples → first_key=0), the merge sees A=K, B=0, and DOESN'T detect
alias — correctly! Because B didn't have an alias to begin with.

So the contract is right. But: the merge's `first_key` semantic on
the published wire is now "first_key seen across ALL bindings owned
by this worker," not the per-binding semantic. The harness §3.4
cross-worker key-set check (per #1612 plan v3.2) compares first_key
across WORKERS, not bindings. The plan should explicitly note this
cross-binding aggregation in the published WorkerRuntimeStatus.

**Recommendation**: add to §4.4 status-path doc-comment that
`cold_path_first_key` is the cross-binding-aggregated first key
per slot, not per-binding. This affects the #1622 harness's
publication gate.

## F2 (MED, §4.5 metric naming) — `cold_path_ns_per_tsc_q32` not exposed

§4.5 lists 8 Prometheus metric families but the calibration multiplier
`cold_path_ns_per_tsc_q32` is conspicuously absent. Without it, the
harness reading /metrics cannot reconstruct the actual ns values from
the bucket counts — bucket boundaries are at `2^(10+i) ns` for
i ∈ [1, 22], so the boundaries are intrinsic to the bucket index,
NOT dependent on q32. But: if a reader wants to validate the
calibration was sane (e.g., "all workers reported the same q32 ±10%"),
they need q32 on the wire AND on /metrics.

**Recommendation**: add a 9th metric:
`xpf_userspace_worker_cold_path_ns_per_tsc_q32{worker_id}` Gauge.
Cardinality cost: 6 series.

## F3 (MED, §4.3 omitempty truth-table) — `cold_path_clock_source = "tsc"` is a NON-EMPTY string but the harness needs to distinguish "set to tsc" from "absent"

Plan-v1 §4.3 says `cold_path_clock_source: String` with `default`.
When a worker hasn't calibrated yet (`ClockSource::Unset`), the
Rust side emits empty string `""`. When calibrated to Tsc, it emits
`"tsc"`. When ClockGettime, it emits `"clock_gettime"`.

`omitempty` in Go drops empty strings from the wire. So an Unset
worker emits the field absent on the wire; an older Go daemon
reading newer JSON sees ColdPathClockSource = "" (Go zero value).

`feedback_wire_protocol_both_sides`: both sides agree on "" = unset.
The harness reads ColdPathClockSource and gates Table publication on
== "tsc". This is correct.

But the truth table for backward compat needs walking:
- New Rust → New Go: clock_source carried correctly.
- Old Rust → New Go: no field, Go sees "" → harness skips worker.
- New Rust → Old Go: Old Go's WorkerRuntimeStatus doesn't know the
  field; serde-default + omitempty means Old Go decodes successfully
  ignoring the field. No issue.
- New Rust Unset worker → New Go: empty string, omitempty omits from
  re-encode if Go re-emits.

All four cases are fine. The plan should walk this in §4.3 explicitly
per `feedback_wire_protocol_both_sides`.

## F4 (NIT, §4.4) — snapshot None handling on contested writer

§4.4 says: "the None case (snapshot retry exhausted) emits empty
fields; operator sees 'no data this scrape, try next' rather than
stale."

That's the right contract. But Prometheus scrape doesn't see "no
data" — it sees an EMPTY array which the emitter loop skips. So
operator queries against `xpf_userspace_worker_cold_path_samples_total`
return no data points for that scrape interval. That's fine but
worth documenting in §4.4: the gauge for `cold_path_clock_source`
also won't appear, which could break operator dashboards that
assume the gauge is always present per worker.

**Recommendation**: §4.4 should suggest the emitter ALWAYS emit a
clock_source gauge with value 0 if the field is empty (so dashboards
distinguish "TSC active" from "no data this scrape"), even when the
rest of the cold_path fields are empty. Trivial cost (6 series
×1 = 6 always-present series).

## F5 (NIT, §4.5 bucket_hi_ns label) — Prometheus convention is `le` (less-than-or-equal) for histogram boundaries

§4.5 uses `bucket_hi_ns` as the label. The Prometheus histogram
convention is `le="N"` where N is the upper inclusive bucket bound
in NATIVE units of the metric. Since our metric is `_ns_bucket`,
the unit is ns, and `le="1024"` etc. fit the convention.

But `bucket_hi_ns` is a more readable label name. The Prometheus
client libraries usually use `le` because PromQL histogram_quantile()
expects it.

**Recommendation**: rename label `bucket_hi_ns` → `le` for PromQL
compatibility with `histogram_quantile(0.99, sum by (le) (...))`.
Strongly correlated with whether ANY consumer uses
histogram_quantile() against this metric — if the harness does its
own math directly off the bucket counter, the label name doesn't
matter. Plan should pick one and justify.

## Verdict — PLAN-NEEDS-MINOR

Findings F1-F3 are MED, F4-F5 are NIT. Should converge to PLAN-READY
in r2 after these are addressed. Codex + AGY independently
verifying welcomed.
