# Codex plan-review r1 — #1746
Session: CODEX_COMPANION_SESSION_ID=research-1746-r1; thread 019e86cc-96eb-7a30-b84a-f2e4350db238

VERDICT: PLAN-NEEDS-MAJOR

Findings (verbatim summary):
1. MAJOR: default/back-compat naming unresolved/contradictory. plan.md:69-75 says ideal-share=current/default byte-unchanged, but source publish_equal_flow_epoch_v8.rs:129 is `min` (clip-to-slowest); plan.md:264-267 says IdealShare preserves the `min`, plan.md:276-280 then says make IdealShare literally scheduler_rate/total_flows; plan.md:421-426 admits unset default and named ideal-share would DIFFER. Not a resolved contract.
2. MAJOR: §10 model numerically inconsistent. plan.md:172-175 says -P12=12 flows; plan.md:193-194 models {1,2,3,4}=10 flows. Weighted mean = 1.242G not "~1.3G". At 1.242G the 1.29G band also clips, so "1-flow+2-flow workers" wrong.
3. NOT A KILL: clip-to-mean computable from existing samples (rotate_epoch_v8.rs:112-149 + publish_equal_flow_epoch_v8.rs:97-101 already have prev_grants[id] + sampled_active_flows_by_worker[id]).
4. NOT A KILL: clip-to-mean is not near-no-op under corrected bands: baseline CoV 27.7%, clip-to-mean@1.242G -> 16.7% CoV (~40% rel reduction), agg 12.42->10.93G. Path C not justified on "too marginal".
5. Telemetry compliant with control-socket rule (plan.md:293-294); prefer sibling info metric over relabeling existing gauge (series identity).

Resolve CLI semantics + replace §10 with consistent 12-flow model before implementation.
