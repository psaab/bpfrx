# Claude SMR plan-review r3 — #1635 cold-path histogram redesign

**Reviewer role**: domain SMR (histogram design / hash collision / aggregation
semantics / Prometheus cardinality / wire-protocol versioning). Hostile-verify of
plan v3.

**Plan under review**: `docs/pr/1635-cold-path-hist-redesign/plan.md` v3 (after AGY
r1 PLAN-NEEDS-MINOR + my own r1 F1-F4 + r2 F5-F7).

**Reviewer convergence state**:
- AGY r1 (adversarial-review-mppsdq37-vz0w2l): PLAN-NEEDS-MINOR with 6 concrete
  remediations (cardinality math error, sparse serialization, hot-path FastMap
  hazard, pivot at 512, slot reuse with zero-out, rename builder_collision).
- Codex r1: lost in shared-session bug; retry task-mppsgess-w6pwan in flight.
- Claude SMR r1: PLAN-NEEDS-MAJOR; r2: PLAN-READY conditional.

## Verdict: **PLAN-READY** (pending Codex r1; v3 cleanly absorbs all AGY + SMR
findings)

---

## Verification of AGY r1 remediations in v3

| AGY r1 item                              | v3 §       | Status |
|------------------------------------------|------------|--------|
| [1.1] Cardinality math + pivot at 512 ns | §2.1, §2.5 | ✅ 48 buckets, pivot at 512 |
| [1.2] Sparse wire serialization          | §2.2.1     | ✅ active-slot-only arrays |
| [1.3] Immediate slot reuse with zero-out | §2.4       | ✅ |
| [1.6] Rename → `builder_collision`       | §2.6       | ✅ end-to-end |
| [1.7] Hot-path FastMap → flat table      | §2.3       | ✅ 1024-byte L1d table |
| [1.9] Slot capacity 256                  | §2.2       | ✅ |

## Verification of my r1 F1-F4 + r2 F5-F7

| SMR finding              | v3 § | Status |
|--------------------------|------|--------|
| r1 F1 stride too wide    | §2.1 | ✅ 16-ns stride retained |
| r1 F2 silent slot-overflow alias | §2.2 | ✅ `overflow_active` gauge; no slot reuses |
| r1 F3 Go silent miscompile | §3 | ✅ version switch + sparse rest-of-zero fallback |
| r1 F4 stale slot remap   | §2.4 | ✅ atomic zero-out on reassignment |
| r2 F5 byte-count math error | §2.2 | ✅ correct: 256 × (48×8 + ~24) = ~99 KB local |
| r2 F6 commit to `_v3` suffix | §2.5 | ✅ |
| r2 F7 example/prose contradiction | §2.4 | ✅ immediate reuse + zero-out clarifies |

## New hostile findings in v3 — none gating, all NIT

### NIT 1: §2.3 zone-id ceiling at 32 is a hidden contract change

The 32×32 flat lookup table caps zone-ids at 32. The current xpf zone-id allocator
(see `pkg/config/zone.go`) is u16 with values up to ~65K but in practice
deployments use 4-20. **However** the plan does not check whether any test fixture
or HA-sync wire encoding writes a zone-id ≥ 32. If yes, those samples silently
drop, the new `zone_id_out_of_range_total` gauge fires, and an operator with a
zone-id-66 test setup sees no cold-path data for that zone with no error visible
unless they explicitly query the new gauge.

**Resolution at impl-time**: grep `pkg/config/zone.go` + `pkg/configstore/` for the
actual zone-id allocation range. If it's truly bounded ≤ 32, leave the const at
32 with a `static_assert!`. If not, raise the ceiling to 64 (cost: 4 KB table)
or 256 (cost: 64 KB table — too large for hot-path L1d).

### NIT 2: §2.3 `record_sample_with_collision_check` adds branch on hot path

The v3 `record_sample_with_collision_check` asserts the caller's `(from, to)`
matches the slot's `first_key`. This adds a branch + a u64 compare on every
record. Cost: ~1 ns on cached. Trade-off: catches builder bugs at sample-time but
adds ~1% to the post-#1622 1-in-1 cold-path budget.

**Resolution**: gate the check behind `#[cfg(debug_assertions)]` or a feature
flag. Release builds skip the check; dev/test builds run it. The
`builder_collision` flag in `WorkerColdPathCounters` remains zero in release;
operators can flip the feature flag temporarily if they suspect a slot-map bug.

### NIT 3: §3.2 (v3 Rust, v1 Go) "no metrics emitted" is operator-confusing

The fallback row says "v1 Go sees no cold-path data, emits nothing". A v1 Go
operator scraping a v3 Rust daemon will see the cold-path family disappear from
their dashboard with no log line explaining why.

**Resolution**: the v3 Rust side emits a deprecation-warning gauge under the v1
name (e.g., `xpf_userspace_worker_cold_path_v1_deprecated{worker_id} = 1`) so
that v1 Go still sees a sentinel series. Marginal cost (1 series per worker per
scrape). Mitigates the silent-data-disappear failure mode.

---

## Decisive summary

v3 cleanly absorbs every AGY r1 + SMR r1/r2 finding. Three new NITs surfaced but
all are impl-time concerns, not plan-blocking. **PLAN-READY** from my seat.

If Codex r1 returns PLAN-NEEDS-MAJOR with a finding outside what AGY + SMR raised,
I reserve the right to revise; otherwise v3 is the implementation target.

---

## Implementation guard-rails (carry into code-review r1)

When the implementation lands I will hostile-verify:
- F1 verification harness exercises the real `bucket_index_for_ns_48` path (not
  a mock).
- Sparse encoding round-trips through serde (write then read, assert equality).
- `record_sample_with_collision_check` is `#[cfg(debug_assertions)]`-gated.
- Zone-id range grep is documented in the PR commit message.
- HA-failover path: snapshot from peer with v3 wire → local Go side decodes
  identically.
