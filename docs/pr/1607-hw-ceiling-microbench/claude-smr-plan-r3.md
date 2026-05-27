# Claude SMR plan-review r3 — #1607 cold-path microbench v2 patched

## Verdict: PLAN-READY

After ingesting AGY r2 PLAN-KILL findings, I retract my r2 PLAN-READY-
WITH-NIT and substituted r3 adjudication. The patched v2 plan now
addresses all four of AGY's fatal axes and both major hazards. The
remaining issues are nit-class.

## Adjudication of AGY r2 PLAN-KILL findings

### Axis 1 — Session table exhaustion → AGY RIGHT; v2 patched

I missed this in r2. Empirically verified in `session/mod.rs`:

- `DEFAULT_MAX_SESSIONS = 131_072` (line 25)
- `DEFAULT_UDP_SESSION_TIMEOUT_NS = 60_000_000_000` (line 28)
- `install_with_protocol_with_origin` returns `false` when full
  (line 666-668)

At 5 Mpps × 30 s = 150 M packets vs 131 K cap and 60 s UDP timeout,
the table fills in ~26 ms and stays full for the remainder of the
run. Subsequent packets bypass session install entirely. v2's
original full-/16 sweep would measure policy eval only with all
install + cross-worker replicate cost skipped — a number that is
materially smaller than the real cold-path cost, which is the very
number #1605 JIT planning needs.

**v2 patch fix in §4.2.0**: default cohort is exactly 131 K unique
5-tuples (`src_ip_span=16384 × src_port_span=8 = 131072`). Session
table fills exactly to capacity in the warm-up phase; every
cold-path sample comes from a real cache miss + policy eval + session
install + replicate. Sample mask drops to 1-in-1 when cohort ≤ 256 K.
**CLOSED.**

### Axis 2 — CoS Flow-Fair 4096 buckets → AGY RIGHT; v2 patched

`COS_FLOW_FAIR_BUCKETS = 4096` (`userspace-dp/src/afxdp/types/cos.rs:115`)
verified. Production typically activates 2-32 buckets; the v1 unbounded
flooder would activate all 4096. CoS-on smoke numbers would be
artificially inflated.

**v2 patch fix in §4.2.0 (CoS interaction)**: default `cos_mode=off`;
CoS sweep uses a 32-stream cohort. Documented limitation. **CLOSED.**

### Axis 3 — Splitmix `>> 60` clustering → AGY PARTIALLY RIGHT; v2 patched

AGY's specific numeric claim
(`[1,3,1,2,0,3,0,1,0,0,2,1,0,2,0,0]` for low-4-bit on K=16 diagonal)
does not reproduce: my independent computation showed `& 0xF` on
diagonal K=16 gives **perfect** distribution
`[0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]` (each slot exactly once).
AGY may have used a different key encoding.

But AGY is RIGHT that the v2-original `>> 60` (high-4-bit) clusters:
diagonal K=16 maps to `[0,1,2,4,5,7,8,10,11,13,14,0,1,3,4,6]` with
slot 0 twice, slot 1 twice, slot 4 twice. 3 slots empty.

**v2 patch fix in §4.3.4**: switched to `& 0xF` (low-4-bit) which is
empirically a perfect bijection for K=16 diagonal AND round-robin.
The Knuth Vol 3 §6.4 argument applies: golden-ratio multiplication
preserves a maximum-period permutation on the low-order bits when
input is a small contiguous integer sequence. **CLOSED.**

### Axis 4 — Bucket saturation prose → AGY RIGHT; v2 patched

Bucket-index math verified by hand:
`b = (54 - clz(ns|1)).max(0).min(23)`. For `ns = 2^32`, clz = 31,
b = 23 → bucket 23. For `ns = 2^33`, clz = 30, b = 24 → clamped to
23. Saturation edge is **2^32 ns ≈ 4.295 s**, not 2^33.

For the 1M-rule worst-case projection (~100 ns/rule × 1M = 100 ms
= 10^8 ns ≈ 2^27 ns), bucket = 54 - 37 = 17. **Visible tail.** The
prose error didn't change which buckets the data lands in — but the
prose claim was wrong and the test was wrong, and the test would
have failed.

**v2 patch fix in §4.4**: corrected prose; saturation edge is 2^32
ns. Visible-tail claim for 1M rules verified at bucket 17. **CLOSED.**

### Hazard 1 — TSC refuse-start → AGY RIGHT; v2 patched

Refusing to start on missing `constant_tsc` / `nonstop_tsc` is the
wrong policy for a measurement PR. KVM nested VMs and many CI
runners legitimately lack these flags. v2 would break CI.

**v2 patch fix in §4.3.3**: graceful degrade to `clock_gettime` with
one-time warning + harness records `clock_source` per run. The
1-in-256 sample mask amortizes the clock_gettime cost to ~0.18 ns /
packet on the degraded path — still well below the cold-path floor.
**CLOSED.**

### Hazard 2 — LAN_HOST/FW0 co-residence → AGY RIGHT; v2 patched

Verified at `test/incus/cluster-setup.sh:245` (`limits.cpu: "4"`)
and `create_lan_host` (no CPU pinning).

**v2 patch fix in §4.5**: `taskset -c <last-2-cores>` pin for the
flooder via the harness script; `FLOODER-PIN-WARNING` when host
has < 4 cores. Doesn't change the test fixture (lab cleanup at
#739 still pending). **CLOSED.**

### Hazard 3 — Concurrent #1606/#1608 wire-protocol → already addressed

All three sub-agents add additive fields to `WorkerRuntimeStatus` /
`pkg/api/metrics_userspace.go`. Each side uses `omitempty` /
`#[serde(default)]`. Merge conflicts are mechanical-additive. v2
plan §4.7 already acknowledged this; no patch needed. **No change.**

## Self-correction for r2 → r3

r2 voted PLAN-READY-WITH-NIT. r2 was wrong about axis 1 — I treated
the session table as "the flooder generates billions of unique
5-tuples → flow cache cannot amortize → every packet is cold path"
without checking what happens when the **session table** fills. AGY
walked the install-side code path and caught that session install
fails fast when full, so the "cold path" measurement degenerates to
"policy eval only with install bypassed". That's a different
measurement than what the JIT design doc needs.

The lesson: cold-path is not a single concept. v1 defined it as
"flow-cache-miss → policy eval". The actual cold path on a new flow
is "flow-cache-miss → policy eval → session install + replicate".
v2 patched §4.2.0 spells out which one is being measured and bounds
the flooder so that both phases run successfully.

I should have caught axis 1 in r2. The miss demonstrates why the
quad-review gate exists: AGY's stricter adversarial framing caught
something Codex (still in flight) and Claude SMR both initially
nodded through.

## Remaining nits (non-blocking)

- **N7 (new)**: at 100 % sampling (sample_mask=1, cohort=131K), the
  per-packet TSC pair overhead is ~55 ns × 131K = ~7.2 ms total
  wrapper cost per run. Negligible vs 30 s run length but worth
  noting in the wrapper-baseline column. The "corrected" Table A
  values subtract per-sample wrapper baseline, so the published
  numbers are correct.
- **N8 (new)**: the harness's `--saturate-table-first` mode (explicit
  AGY-flagged regime) is documented but not in the default smoke
  matrix. Reviewers can opt-in if they want the v1-style
  "install-bypassed" measurement as a contrast number.

## Domain-specific checks (status post-patch)

| Check | Status |
|-------|--------|
| Hot-path allocation rule | PASS — sampler still 1 branch + 1 ALU + 1 store on non-sampled path |
| Lock ordering / ArcSwap semantics | N/A — no new locks |
| HA sync portability | PASS — no HA-touching code |
| Numerical / counter overflow | PASS — u64 cumulative, century-scale wrap |
| Verifier / kernel-API constraints | N/A — userspace-only |
| Wire-protocol both-sides | PENDING IMPLEMENTATION — both protocol/binding.rs (Rust) and pkg/dataplane/userspace/protocol.go (Go) in scope per §4.7 |
| Modularity discipline | PASS — new cold_path_hist.rs module is small |
| Cache-line / false-sharing | PASS — `#[repr(align(64))]` preserved |
| Smoke v4+v6 × push+rev × CoS-off+on | Pending Step 6 |
| `make test-failover` | PENDING — this PR does not touch HA but reviewers confirm |
| TSC graceful degrade tested | PENDING IMPLEMENTATION + unit test |
| Session table cohort bound | PASS — default 131K = `DEFAULT_MAX_SESSIONS` |
| CoS bucket realistic cohort | PASS — default CoS-off; CoS-on cohort = 32 streams |
| Splitmix slot pick uniform | PASS — `& 0xF` empirically verified bijection for K=16 |
| Bucket-saturation tail visibility | PASS — 1M-rule worst case lands at bucket 17 (of 0..23) |
| Flooder host-pinning | PASS — `taskset -c <last-2-cores>` documented |

Final verdict: **PLAN-READY**.
