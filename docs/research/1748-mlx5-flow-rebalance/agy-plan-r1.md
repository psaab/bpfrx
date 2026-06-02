# AGY adversarial plan-review — #1748 r1

Job: adversarial-review-mpw74e5j-qa2rr9
Verdict: **PLAN-KILL-OVERTURNED** (Wall A ratified; Wall B falsified)

## Summary

AGY ratified Wall A (AF_XDP queue binding / xsk_rcv_check — XDP_REDIRECT path
permanently blocked) but FALSIFIED Wall B with quoted code:

1. **Pre-replication invariant.** Every forwarded session is broadcast to all
   sibling workers on creation via `replicate_session_upsert`
   (`poll_descriptor/mod.rs:1267`, `session_glue/mod.rs:573`). The receiving
   worker re-resolves with LOCAL egress in `handle_upsert_synced`
   (`session_glue/commands/upsert_synced.rs`) and stores a forwarding-ready
   entry. So worker 5 already holds the session before the ntuple rule lands; a
   re-steered packet misses the flow cache once, finds the pre-replicated
   session, refreshes last_seen, and forwards. No duplicate session, conntrack
   stays intact.

2. **Lock-free organic handoff via local GC.** Local expiration
   (`worker/loop_body/mod.rs:668`) does NOT broadcast deletes; worker 2's stale
   copy ages out locally while worker 5's copy stays alive on the new packet
   stream. State shifts with zero locks / zero cross-worker cache traffic.

3. **CoS skip-ramp.** The rate estimator (`cos/fairness.rs:93`) initializes
   observed_bps directly from inst_bps on first sample after idle/creation, so
   the flow's scheduling state converges instantly on worker 5 — no slow EWMA
   ramp.

Conclusion: Wall B was the structural reason #1649 forbade re-steer by fiat;
on its merits the dataplane is already prepared for safe reactive ntuple
re-steer of established flows. Recommends moving #1748 from PLAN-KILL to
PLAN-NEEDS-WORK / PLAN-READY for prototyping Path 2 (ntuple HW re-pin).

VERDICT: PLAN-KILL-OVERTURNED
