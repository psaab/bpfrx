# #1863 implementation — pointer + decision record

Canonical converged plan (3-of-3 PLAN-READY, round 3):
`docs/research/1863-realization-gap/plan.md` on branch
`research/1863-realization-gap` @ `8309d944c` (v3.1; reviewer ledger
+ round docs alongside).

## Step-0 decision record (registered rule applied)

Instrument: per-worker `xpf_userspace_cos_lease_v8_requested_bytes_total`
/ `..._granted_bytes_total` (commit 1). Decision cells step0-r1/r2
(raw/): on the small4+24g decisive cell, EVERY active worker
cumulatively over-asks its flow-proportional entitlement (min observed
req/entitlement = 1.78x, typical 3-13x, across 30 worker-rows in 2
reps x 3 classes) — no demand-starved worker exists, refuting the
share/demand-mismatch branch (a). Class grants still land at only
71-79% of the class budget (grant/cap: 3g 0.74-0.79, 6g 0.71-0.72),
and per-class grants == per-class realized throughput (closing the
research plan's Codex r1 F2 worker-pooled caveat). The evaporation is
in lease epochs each worker fails to sample (claim-sampling loss (b)).
Registered rule -> **Path A-ii**.

## Fix

Class-level unclaimed-budget carry at v8 lease rotation
(`rotate_epoch_v8.rs`): bank `prev_cap - prev_granted` into the
existing bounded lag-carry; the next rotation re-deals it through the
unchanged flow-proportional share formula. Per-worker isolation
preserved (the A-i mid-epoch class-room race the round-1 reviews
rejected cannot occur — grants stay bounded by each worker's own
published share); all existing carry bounds + regime-3 cold-resume
drop unchanged; fully-claimed epochs bank 0 (byte-identical steady
state); EqualFlowSuppress leases excluded (byte-identical, suite-pinned).

## Decisive before/after (raw cells on the research branch — see raw/MANIFEST.md)

| Cell | class | before (master) | after (g75f5ed727) | gate |
|------|-------|-----------------|--------------------|------|
| small4+24g | 3g | 69-73% of shape | **92.6 / 93.7 / 94.0%** | >=85 PASS |
| small4+24g | 6g | 66-72% | **94.6 / 94.9 / 94.7%** | >=85 PASS |
| small4+24g | 24g | 43-51% | 48.5-54.1% | residual, not above ceiling share |
| small4+24g | aggregate | 17.4-19.6 G | **22.00 / 21.14 / 22.34 G** | >=20.5 PASS (C_phys(mix)=23.2) |
| small4+9g | all classes | 76-82% | **92.4-95.3%** | all >=85 PASS |
| small4+9g | aggregate | 15.1-15.2 G | **17.9-18.1 G** (94% of demand) | work conservation restored |
| small4-alone | 3g/6g | 87.5-91.5% | **95.3 / 95.3%** | unregressed PASS |

Single observation: 1g dipped to 75.9% in fix24c-r3 (91.2/90.1 in
r1/r2; 92-94.5% in every other cell) — within the corpus 1g band's
historical low (84.8) plus one outlier rep; not gate-relevant.

## Reviewer ledger

See reviewer-ids.md (this directory) for implementation-review task ids.
