# Codex plan-review r2 — #1746
Session: CODEX_COMPANION_SESSION_ID=research-1746-r2

VERDICT: PLAN-READY

Findings (verbatim summary):
1. Naming knot FIXED — default "" maps to `slowest` (current `min`, byte-unchanged); `mean`=Σ/Σ; `ideal-share`=literal share. End-to-end coherent (plan.md:76-86, 267-269, 301-318) with publish_equal_flow_epoch_v8.rs:129.
2. Numeric model FIXED — §4 observed-band 10-flow model: baseline 12.42G/27.7%; mean 1.242G→10.93G/16.7% (−39.83% rel CoV, −11.98% agg); slowest 8.70G (−29.95%). Codex recomputation matches exactly. §10 placeholder removed (superseded by §4).
3. F1 ship-gate is a SOUND mitigation — tests the actual sample-collapse failure mechanism (publish_equal_flow_epoch_v8.rs:62-71, 122-127), not just arithmetic. Valid.
4. MINOR (not kill): plan referenced nonexistent field `rate_bytes_per_epoch`; config has `rate_bytes` (mod.rs:760-763); per-epoch cap derived as new_cap (rotate_epoch_v8.rs:310-312); total_flows at :226-231. Fixed in r2 post-review edit (IdealShare now references new_cap/total_flows + call-order note).
5. AGY kill rebuttal ACCEPTABLE — footgun cost is real (mod.rs:1237-1239 one-directional cap; 0.87G floor identical) but r2 no longer hides it (opt-in + commit warning + F1 gate). "AGY right about structural limits; not right that this forces killing the knob."
