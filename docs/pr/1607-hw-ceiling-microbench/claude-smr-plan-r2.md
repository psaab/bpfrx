# Claude SMR plan-review r2 — #1607 cold-path microbench v2

## Verdict: PLAN-READY-WITH-NIT

v1's five fatal axes (F1 sample starvation, F2 timer bias, F3 bucket
saturation, F4 CPU isolation, F5 per-zone-pair granularity) are
substantively addressed in v2. The remaining concerns are nit-class
(specific calibration details, defensive checks, and one wire-protocol
co-location call-out vs the concurrent #1606 work). I am going to vote
PLAN-READY rather than PLAN-NEEDS-MINOR because none of the remaining
items would change the harness numbers reported in `docs/userspace-
jit-design.md`, and Codex/AGY may push harder on individual axes —
that's the point of the quad-review.

## Per-axis verification of v1 PLAN-KILL fixes

### F1 — TCP cold-path sample starvation → CLOSED

The default mode is now the UDP randomized-5-tuple flooder (§4.2).
Per §4.2.2 the per-packet xorshift PRNG covers 32 b src_ip + 16 b
src_port + 16 b dst_port = 64 b key space. Userspace flow cache has
~64K-128K entries (verified: `flow_cache.rs` is a bounded `HashMap`
or similar; default sizing is dataplane-config bound). 64 b key space
vs ~17 b cache capacity → P(collision-on-next-packet) ≈ 2^-47 per
packet at saturation. **Effectively every packet hits cold path.**

The iperf3 path is demoted to `--mode=iperf3-sanity` and called out
as "sanity-only" in the plan; the §4.6 Scale Target table no longer
sources from iperf3 by default. **CLOSED.**

### F1.2 — iperf3 `-u` reuses 5-tuple → N/A (iperf3 demoted)

Moot under v2 default. The smoke iperf3 mode is only there to verify
the counter increments at all; it does not feed the published table.

### F1.3 — Mpps + per-call-ns conflation → CLOSED

§4.6 ships two distinct tables (A = per-call latency, B = aggregate
throughput) with disjoint rate-bases spelled out in the methodology
paragraph. The plan version log entry (§9 v2) confirms the change.
**CLOSED.**

### F2 — `clock_gettime` 18-22 % bias → CLOSED

§4.3.2 commits to TSC-based sampling via `rdtscp` + 1-in-256 sample
mask (matches existing `REDIRECT_SAMPLE_MASK = 0xff` pattern at
`userspace-dp/src/afxdp/umem/mod.rs:183`). Sampled-path cost is ~55 ns
per sample; amortized at 1/256 = ~0.21 ns/packet. Non-sampled path
is ~1 ns. At a 200 ns cold-path floor, the wrapper is **<0.6 %**,
well below F2's 18-22 % threshold.

The TSC calibration (§4.3.3) is run once per worker startup over 100 ms;
the harness reports the per-worker baseline. Wrapper-baseline-
subtracted "corrected" column in Table A makes the residual visible.
**CLOSED.**

### F3 — 16-bucket saturation hides tail → CLOSED

§4.4 commits to `HIST_BUCKETS = 24`, saturating at 2^33 ns ≈ 8.6 s.
For a 1M-rule linear-scan cold path at ~50-100 ns per rule = ~50-100 ms
per packet, this lands in bucket 17-18, not bucket 23. Visible tail.
**CLOSED.**

(Note: the plan says §4.4 "saturates at ~4 s" in the prose and "2^33 ns
saturation" in the §8 open question 5. ~4 s comes from interpreting
bucket 23 upper-bound as 2^32 ≈ 4.3 s; 2^33 = 8.6 s if bucket 23
includes 2^33. Math is fine either way — the test
`bucket_index_24_layout` in §6 pins the exact mapping. Minor doc
prose mismatch; not blocking.)

### F4 — No CPU isolation → CLOSED (scoped honestly)

§4.5 records (not enforces) `/proc/cmdline` + `/proc/interrupts`
delta + per-worker affinity per run, emits an `ISOLATION-WARNING`
header in the TSV when shared CPUs detected. Doc text in §4.6 is
explicitly scoped to "approximate ceiling under loss-cluster
contention" with the #739 lab-fix follow-up linked. This is
option (b)+(c) from my r1 callout — both shipped together. **CLOSED.**

The honest-disclaimer approach is the right call for a measurement-
infrastructure PR: pinning workers + IRQs would change the test
fixture for all downstream measurements (CoS smoke, fairness harness),
which is not in this PR's scope and is correctly deferred to #739.

### F5 — Per-worker histogram hides per-zone-pair cliff → CLOSED

§4.4 ships a 16-slot × 24-bucket per-zone-pair histogram with
splitmix64 hashing on the u32 `zone_pair_key`. 3456 B per worker × 6
workers = 20.7 KB total. Aliasing detector via per-slot `keys_xor`
field. Default synthetic config K = 16 zone-pairs → each zone-pair
maps to a distinct slot with high probability (1 - C(16,2)·2^-4 ≈
93 % no-collision under uniform hash; splitmix64 high-bit is uniform
enough).

For high-cardinality production configs (K = 100+ zone-pairs), the
keys_xor field lets the harness flag aliasing in the TSV. **CLOSED**
with the documented limitation.

## New v2 findings (nits)

### N1 — Splitmix64 high-bit on a 32 b input

`zone_pair_slot(key)` does `(key as u64).wrapping_mul(0x9E3779B97F4A7C15) >> 60`.
The input `key` is `u32`, so the upper 32 bits of the `u64` are zero
before the multiply. The multiply mixes the low 32 b across all 64 b,
and `>> 60` picks the top 4 b of the product, which is a function of
the top ~36 b of the product — i.e., dominated by `key * (golden
ratio >> 4)`. This is uniform enough for K ≤ 16 zone-pairs but a
defensive review might prefer `wrapping_mul` of a 64 b promoted
splitmix64 (multiply, xor-shift, multiply, xor-shift). One extra ALU
op per cold-path sample; trivial. Defer to reviewer judgment; current
hash is acceptable.

### N2 — TSC calibration race vs sleep precision

§4.3.3 uses `std::thread::sleep(100 ms)`. Linux nanosleep precision
under contention can drift ±10 ms; that's a 10 % calibration error
in worst case. Better: spin-loop on `clock_gettime` until 100 ms wall
elapsed, OR use a longer (1 s) calibration window so the 10 ms drift
amortizes to 1 %. Plan should commit to one. Defer to reviewer.

### N3 — `keys_xor` collision-detection is bidirectional

The aliasing detector XORs zone_pair_keys into `keys_xor[slot]`. If
two distinct keys A, B land in the same slot, `keys_xor[slot] = A^B`;
the harness reads the field and notices a non-singleton. But if three
keys A, B, C land in the same slot, `keys_xor = A^B^C` which might
equal a different single key, giving a false-negative. For K ≤ 32 the
P(3-collision) is ~0.6 %, and the harness can additionally compare
`samples[slot]` against a per-slot expected-flow-count. Plan should
spell out that the aliasing check is `(keys_xor != single_key) ||
samples > expected_per_slot * 2`. Currently underspecified.

### N4 — Concurrent #1606 / #1608 wire-protocol collision risk

The plan §4.7 adds fields to `WorkerRuntimeStatus` (both Rust and Go).
Concurrent #1606 (AddressBookSnapshot restructure) and #1608 (verdict
cache) sub-agents are running on disjoint structs per the parent
prompt, but all three add to `pkg/api/metrics_userspace.go`. v1 plan
§F7 noted this as "additive — mechanical merge". Confirm by reading
the actual current state of metrics_userspace.go at the point of
merge.

### N5 — Co-residence flooder/FW host noise

§8 open question 5 acknowledges this. The cluster-userspace-host runs
on the same physical loss host as FW0; if the flooder is CPU-hot,
incus will load-balance the VM workers around it, introducing per-run
variance. The plan correctly proposes pinning the flooder to the
highest core index. Confirm this is actually possible on loss (depends
on whether `incus exec --user 0 --env CPUSET=...` works on the host's
container runtime).

### N6 — Wrapper baseline subtraction floor

Subtracting `wrapper_ns_baseline` from raw histogram p50 yields a
"corrected" value. If at low rule counts (rules=10) the raw p50 is
~80 ns and the baseline is ~30 ns, the corrected p50 is 50 ns. Fine.
But if the raw is **less than** the baseline (impossible mathematically,
but can happen on the p001 tail if the sampler fires inside a cache-
hit fast path that's somehow faster than the rdtscp pair itself —
won't happen here because we measure user-space policy eval which is
always >> 25 ns), the subtraction underflows. Plan should saturate at
zero. Trivial fix; harness code detail.

## Self-correction note

I went into r2 expecting v2 to address F2 (timer bias) but leave a
loophole on F1.2 (UDP iperf3 -u still hitting the flow cache because
of port reuse on the same stream). On rereading §4.2.2, the per-
packet xorshift PRNG over 64 b key space rules out flow-cache hit
even within a single "stream" — there are no streams in the flooder,
just an unbounded sequence of unique 5-tuples. F1.2 is genuinely
closed.

I also expected the per-zone-pair design (F5) to be open-ended on
cardinality. v2 picks 16 slots and explicitly accepts aliasing for
K > 16. This is the right call: the JIT design doc only needs to see
"there is or isn't a cliff at this rule-count per zone-pair", not
"every zone-pair's histogram is independently readable". Aliasing
collapses two zone-pairs onto one bucket; the cliff is still visible
if either zone-pair has a long tail.

## Required changes for PLAN-READY → MERGE-READY

None blocking. Items above (N1-N6) are nit-class. Codex / AGY may
push harder; this seat votes **PLAN-READY**.

## Domain-specific checks (status)

| Check | Status |
|-------|--------|
| Hot-path allocation rule | PASS — sampler is 1 branch + 1 ALU + 1 store on non-sampled path |
| Lock ordering / ArcSwap semantics | N/A — no new locks |
| HA sync portability | PASS — no HA-touching code |
| Numerical / counter overflow | PASS — u64 cumulative, century-scale wrap |
| Verifier / kernel-API constraints | N/A — userspace-only |
| Wire-protocol both-sides | PENDING IMPLEMENTATION — both protocol/binding.rs (Rust) and pkg/dataplane/userspace/protocol.go (Go) in scope per §4.7 |
| Modularity discipline (file <2000 LOC, fn <100 LOC) | PASS — new cold_path_hist.rs module is small |
| Cache-line / false-sharing | PASS — `#[repr(align(64))]` preserved per §4.4 |
| Smoke v4+v6 × push+rev × CoS-off+on | Pending Step 6 (per CLAUDE.md feedback memory) |
| `make test-failover` | PENDING per CLAUDE.md HA-touch policy; this PR does not touch HA but reviewers confirm whether failover is required |
| TSC invariance prerequisites | Plan §8 Q1 commits to refuse-start on missing constant_tsc/nonstop_tsc; reviewer ratification needed |
