# AGY hostile plan review - round 1

Target commit: `78891c3242a80b719bebdddc702087c07543e05b`

Reviewer provenance: direct `agy --print` plan-mode invocation. The first
plugin-wrapper attempts did not deliver the prompt correctly and are recorded in
`reviewer-ids.md`; they are not counted as reviews.

## Verbatim verdict

`PLAN-NEEDS-MAJOR`

## Findings

1. **Claimed stale issue-split section (invalid finding).** The reviewer said
   section 7 was copied from the source report and promoted duplicate/refuted
   claims. The reviewed plan has no such section: section 7 is `Hidden
   invariants`, and K003-02, K003-05, K003-12, and K003-C are consistently
   excluded in sections 2.2, 4.2, 5.15, and 10. This finding is verified false
   and requires no plan change.
2. **LoadOverride destructive-command semantics (valid).** Replaying arbitrary
   `delete` or `activate` commands against a fresh empty replacement tree has no
   coherent full-config meaning. The plan must select a restricted artifact
   grammar or reject flat override input.
3. **DDNS history beyond one transition (valid).** One previous updater per
   family cannot recover authority for records left at backend A after an
   uninterrupted A -> B -> C transition. The design must either retain a
   fingerprint-keyed authority catalog or explicitly quarantine older records.

## Required remediation quoted from the review

- Select an exact `LoadOverride` contract rather than leaving F1/F2 unresolved.
- Clarify and design multi-cycle DDNS cleanup authority.
- Keep the disposition matrix authoritative; do not create work for duplicate
  K003-02/K003-05, refuted K003-12, or unactionable K003-C.

## Reviewer summary

The reviewer accepted the 16-claim disposition matrix, existing-issue ownership,
TLS timeout refutation, persisted-tree reachability, RG mismatch, route-map
under-count, VIP race, and the split-workstream recommendation. Its readiness
blockers were the two valid API/state contracts above.
