# Claude SMR hostile plan review — round 1 (plan v1 → v1.1)

Verdict: **PLAN-READY-WITH-FINDINGS** (2 findings, both folded into v1.1
before external dispatch).

## Verification performed (quoted-line, against worktree @ master 2ab3220f0)

- `parseBandwidthLimit` = `parseScaledDecimalUnit(s) / 8`
  (`pkg/config/compiler_protocols.go:842-844`) — "450m = 450 Mbit/s" claim
  in the cookbook one-liner is correct (bits on the wire grammar, bytes/sec
  internally).
- Synthetic-queue admission gate: `contributes_usable_cos_state =
  iface.cos_shaping_rate_bytes_per_sec > 0 || ...`
  (`forwarding_build/cos.rs:380-385`); synthetic queue construction with
  `equal_flow_enforcement: false`, `codel_target_ns: 0`
  (`forwarding_build/cos.rs:392-411`). Plan's §3 decisive fact verified.
- MQFQ eligibility of the synthetic queue: "#1735: every queue that reaches
  this promotion path is on an interface with a `CoSInterfaceRuntime` ...
  so every such queue is ELIGIBLE to run flow-fair MQFQ, exact or not"
  (`cos/admission.rs:509-515`); lazy promotion probe
  `maybe_promote_best_effort` (`cos/queue_ops/push.rs:43-56`). Plan row (b)
  verified — bare shaping-rate DOES get per-flow fairness on a second
  distinct flow.
- Admission ECN covers both queue kinds (per-flow arm on flow-fair,
  aggregate arm on non-flow-fair, `cos/admission.rs:285-303`) — cookbook
  claim "admission ECN" holds for the synthetic queue pre- and
  post-promotion.
- `codel` absent from `pkg/config/schema.go` (grep, zero matches) while
  present in the compiler (`compiler_class_of_service.go:254-261`) —
  the setSchema gap claim verified.
- `equal-flow-enforcement` exact-only non-work-conserving semantics —
  `docs/fairness-regimes.md:583-585, 814-816` as cited. The plan's refusal
  to put it in an SQM default is correct.

## Findings

**F1 (MED, folded):** §6 D2 originally claimed sourcing the synthetic
queue's `codel_target_ns` from the unit was "the entire engine-side
delta". False for `codel-interval`: #1829 §6.2b spec's the interval as a
hardcoded 100 ms const argument to `cos_codel_check`; a config knob
requires a per-queue `codel_interval_ns` runtime field + wire field +
threading. Small, but the plan must own it. **v1.1 adds the honest
engine-delta accounting paragraph.**

**F2 (LOW, folded):** D1's validation leg claimed a fairness result without
pinning the mechanism — if the -P 12 streams hash to a single bucket or
promotion never fires, the leg would "pass" while the cookbook's fairness
claim is unproven. **v1.1 requires an explicit promotion/active-flow
telemetry check (Q5 resolved in the affirmative).**

## Challenges left standing for external reviewers

- Q1 reject-vs-merge for `smart-queueing`+`scheduler-map` — I lean reject
  but a default-fill semantics advocate should attack the precedence
  argument.
- Q4 close-out shape (keep #1828 open vs re-home to #1829 Phase 3).
- Q7 profile default interval for >100 ms WAN RTTs.
- Whether Option C-pure (docs only, no Deliverable 2 ever) is the stronger
  position — i.e., is the gated rider just deferred scope creep?
