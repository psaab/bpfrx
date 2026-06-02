# AGY adversarial plan-review r1 — #1746
Job: adversarial-review-mpw7a0sc-rrzwbl (succeeded, exit 0). REVIEW-ONLY; both trees verified clean after run.

VERDICT: PLAN-KILL

Rationale (verbatim summary): cap is one-directional (mod.rs:1237 my_share.min(cap)); clip-to-mean/clip-to-slowest destroy aggregate (12% / 30%) and the 0.87G starved floor is identical across ALL policies — freed capacity never reaches starved workers. Confirmed clip-to-mean needs no new sampled data (angle 3) and telemetry is control-socket safe (angle 4). Argues #1748 work-conserving rebalance gives +101% to starved flows / +40.9% aggregate / 0% CoV, so #1746 is a throughput-destroying footgun; kill in favor of #1748.

Claude-SMR rebuttal recorded in claude-smr-plan-r1.md: kill is a DEFAULT-policy objection (plan keeps default unchanged, knobs opt-in + commit warning); AGY's "ideal-share == clip-to-slowest" identity is the fixable Q1 naming defect, not a structural impossibility; #1748-better != #1746-worthless. Downgrade to NEEDS-MAJOR + add a live-measurement ship-gate.
