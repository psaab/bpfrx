# AGY adversarial plan review — #1913 r2
Job: adversarial-review-mqhoe7jj-jm8mnp  VERDICT: PLAN-READY

All r1 findings confirmed addressed against source @ d23d55022:
1. §2.1 ForwardCandidate/FabricRedirect consumed at mod.rs:1794-1798 (else block :2154-:2826) — never reach :2814. CONFIRMED.
2. MissingNeighbor SNAT-failure continues at :2533/:2564 — table updated. CONFIRMED.
3. §2.6 :238 desc branch uses filtered wrapper => silently drops FabricRedirect (asymmetry, out of scope) + slow_path.rs:61 ForwardCandidate build-failure load-bearing. CONFIRMED.

New-defect pressure tests (all clean):
- UMEM leak: gated frames keep recycle_now=true => recycled at :2852; _from_frame copies (slice borrow), no ownership => no leak.
- Telemetry parity: record_forwarding_disposition (:2803) + dbg.policy_deny/ha_inactive/disposition_other (:2799-2801) run BEFORE the gate => drops stay observable.
- Concurrency: local SessionDecision copies, no shared-state mutation in the gate => no race.
No new defects. r2 correct, robust, ready.
