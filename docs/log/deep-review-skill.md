- **Timestamp**: 2026-09-05 UTC
  - **Action**: Revised deep-review and review-triage around a shared evidence contract after the maintainer's review and request to commit/push. Prioritize consequential behavior across subsystem boundaries, include validation infrastructure and shipped artifacts in scope, separate impact from confidence/verification, and preserve actionable fix acceptance criteria.
  - **File(s)**: `.claude/skills/deep-review/SKILL.md`, `.claude/skills/deep-review/references/review-contract.md`, `.claude/skills/review-triage/SKILL.md`.
  - **Action**: Replaced checkout/model-specific triage assumptions with repository/revision provenance. Made review modes explicit, recent-fix windows independent of tip movement, and run allocation/publication/cleanup safe for concurrent campaigns. Preserved report/watcher filename compatibility and the explicit disposition trail.
  - **Documentation**: This is a workflow-documentation change; firewall behavior and module/operator contracts are unchanged.
  - **Validation**: `git diff --check`; native YAML frontmatter checks for both skills; both Markdown links and six repository references resolved. The Codex skill validator passed review-triage directly and deep-review on a temporary copy omitting only its existing Claude-specific `user-invocable` field, which was checked separately as boolean true. The stock validator does not accept that field; the source skill preserves it.
  - **Validation**: Exercised the documented `ln -T` publication on temporary reports: initial publication succeeded, an existing final and an existing directory were both refused, and the original report/sentinel remained intact. These checks used only owned temporary paths.
  - **Validation**: Coordinator decision walkthrough covered the cases below. This is instruction review, not an independent agent evaluation, empirical defect-recall measurement, or live firewall validation.

| Case | Required result under both skills |
| --- | --- |
| Established supported-behavior defect | MATERIAL with bounded impact, evidence and fix acceptance criteria |
| Candidate disproved by its actual guard | NEG in the reasoned disposition log, excluded from findings |
| Potentially severe issue needing unavailable lab evidence | NEEDS_VALIDATION with potential impact and a named next check |
| Green test using the wrong or stale artifact | VOID execution evidence; no unearned verification |
| Evidence file unchanged but a supporting validator changed | Recheck the dependency and claim at the pinned comparison revision |
| Incomplete fix under a closed issue | Residual with explicit owner/follow-up recommendation, not automatic DUP/FIXED |
| Report from a different or unresolved repository | Reconcile provenance; no automatic fabrication judgment |
| Fix merged but absent from an in-scope release | FIXED in source with delivery/backport milestone still outstanding |

- **Timestamp**: 2026-09-05 04:06 UTC
  - **Action**: Corrected the overcompressed expertise after the maintainer identified the omission. Restored all ten specialist personas and their technical checklists directly in deep-review; made applicable expertise mandatory in assignments, including coordinator-owned work, and added an explicit test/reliability perspective for validation assurance.
  - **File(s)**: `.claude/skills/deep-review/SKILL.md`, `.claude/skills/deep-review/references/review-contract.md`, `.claude/skills/review-triage/SKILL.md`, `docs/log/deep-review-skill.md`.
  - **Action**: Required adversarial defensive analysis of protections, trust boundaries, actual actor influence, prerequisites and implementation assumptions before candidate discovery. Kept it separate from independent refutation, including checks of proposed safety guards and dismissals. Both findings and no-finding coverage retain the relevant analysis and unresolved questions.
  - **Compatibility**: Advanced the shared report contract to `xpf-review-v3` for the required `Adversarial analysis` field. Triage preserves discovery rationale and contrary evidence; v2 and older reports remain usable, with missing analysis reconstructed only from checked evidence rather than rejected for format alone.
  - **Documentation**: Workflow-only correction. No firewall code, product invariants, deployment behavior or live validation changed. The skill-creator guidance informed a targeted restoration, preservation of scope and explicit validation limits; no defect-recall improvement is claimed.
  - **Validation**: Compared the restored A1–A10 profiles with the pre-rewrite skill at `c70b1fbec`; retained each specialist's original technical concerns while preserving the expanded inventory and cross-boundary ownership. `git diff --check`, native YAML checks, two relative Markdown links and six repository references passed. The stock Codex validator passed triage and an exact deep-review copy with only the Claude-specific `user-invocable` field omitted; the source field remains boolean true, and `diff -u` verified that the temporary copy had no other changes.
  - **Validation**: Coordinator instruction walkthrough covered the additional cases below and rechecked the eight earlier disposition cases. These are hypothetical decision checks, not executed firewall scenarios, independent forward-testing or measured discovery recall.

| Correction case | Required discovery and triage behavior |
| --- | --- |
| Configuration semantics cross Go compilation, Rust consumption and cached translation state | Combine A3/A6/A1/A2 expertise as applicable; retain the boundary, real input authority and end-to-end property instead of ending at an area boundary |
| A proposed safety guard is established for only one of the relevant paths or lifecycle states | Do not use its existence alone to justify NEG; check its scope and preserve NEEDS_VALIDATION if the evidence cannot settle the remaining claim |
| An outage follows an ordinary resource or recovery fault | State the fault without inventing an attacker; grade the availability consequence separately from actor identity and verification |
| Source reasoning assumes control of internal state or a compromised peer | Make that assumption and its support explicit; do not present it as ordinary network-participant reachability |
| An assignment produces no finding but leaves an important assumption unchecked | Retain assigned expertise, questions actually checked and the unresolved assumption; do not convert incomplete coverage into verified behavior |
| A v2 report has sufficient checked evidence but lacks the new label | Reconstruct analysis from that evidence, independently assess the claim, and preserve rationale and contrary evidence; do not reject it solely for format |

- **Timestamp**: 2026-09-05 04:16 UTC
  - **Action**: Added explicit Linux kernel/NIC datapath, network protocols/firewall architecture, and high-performance systems coding experts after the maintainer identified that A1/A7 and the original ten profiles did not provide sufficient ownership. Each has technical checks, adversarial questions and evidence expectations across file-area boundaries.
  - **File(s)**: `.claude/skills/deep-review/SKILL.md`, `.claude/skills/deep-review/references/review-contract.md`, `.claude/skills/review-triage/SKILL.md`, `docs/log/deep-review-skill.md`.
  - **Action**: Full reviews assign all three experts; focused/delta reviews assign relevant roles within scope and record non-applicability or coverage gaps. Worklists, worker briefs and reports retain explicit ownership. A1–A10 remain the file-area IDs; these roles do not introduce new CLI flags or require additional agents.
  - **Action**: Extended the shared evidence requirements for kernel/driver/library identity, execution modes, queue/offload configuration, workload-specific cost and scaling, measurement conditions and bottleneck attribution. Triage preserves these limits and does not confuse a static cost bound with a measured speedup or bulk throughput with new-flow capacity.
  - **Documentation**: Skill-creator guidance kept this an additive, scoped correction. The v3 field labels and report/watcher compatibility remain intact. No firewall source, product invariants, runtime settings or live environment changed.
  - **Validation**: `git diff --check`, native metadata validation, two relative Markdown links and ten repository reference paths passed. Existing metadata/invocation settings and all 19 report field labels were checked against HEAD and remain unchanged. The stock Codex validator passed triage directly and deep-review on an exact temporary copy omitting only the preserved Claude-specific `user-invocable` field; `diff -u` confirmed no other normalization.
  - **Validation**: Coordinator instruction walkthrough covered the cases below. This checks assignment, scope and disposition reasoning, not independent forward-testing, live networking behavior or measured defect recall/performance.

| Expert-coverage case | Required result |
| --- | --- |
| Full product review | All three cross-cutting experts have named ownership, scoped contracts and evidence expectations alongside A1–A10 and validation assurance |
| Focused persistence-format review with no kernel/network dependency | Record kernel/network non-applicability; do not expand into a full dataplane campaign, and retain any actually relevant cost/reliability questions |
| Copy-mode evidence is offered for a zero-copy-dependent claim | Retain valid narrower observations; leave the mode-dependent question unresolved until its source/dependency or execution evidence is established |
| Packet transformation crosses NAT, tunnel, routing and policy areas | Assign networking expertise across the whole relevant chain and retain the independent protocol/property oracle, not merely per-file inspection |
| Established-flow throughput is used to claim new-flow capacity or queue fairness | Reject the unsupported generalization while retaining the valid throughput result; require evidence for the distinct workload/property |
| Source establishes a scaling cost but no profiling environment is available | Preserve the bounded static claim and consequential impact reasoning; do not claim a measured bottleneck or speedup |
