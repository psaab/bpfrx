# Research skill: evidence-first investigation

- **Timestamp**: 2026-09-05 UTC
  - **Request**: Implement and push the approved proposal to preserve general
    research while deeply validating external-model code reviews before accepting
    or dismissing findings, retaining GitHub discovery provenance.
  - **Action / files**: Updated `.claude/skills/research/SKILL.md`; added
    `references/review-validation.md` and `references/plan-review.md` beneath it.
    General questions, issues and supplied reports route to relevant investigation
    or planning instructions. The research-only/manual-implementation gate remains.
  - **Action**: Added exhaustive original-claim accounting, linked subclaims,
    competing explanations, primary-source contracts, complete dependency traces,
    valid bounded local evidence, evidence-backed dismissals and unresolved next
    checks. Finding validity is independent of plan approval and issue closure.
  - **Action**: Retained all applicable specialist profiles, explicit Linux kernel/
    NIC, network/firewall and high-performance coding expertise, CPU architecture,
    software design, and independent scrutiny of confirmations and dismissals.
  - **Action**: Preserved the eleven plan concerns and Codex/AGY/Claude SMR review
    gate in a self-contained reference. Actual reviewer identities are required;
    a GPT coordinator cannot invent a Claude pass. Resolved the old skill's
    automatic two-reviewer fallback against its referenced Codex-infrastructure
    feedback: three matching failures require escalation, not inferred approval.
    PLAN-KILL no longer automatically closes a real defect issue.
  - **Action / files**: Advanced
    `.claude/skills/deep-review/references/review-contract.md` to v5; updated
    `.claude/skills/deep-review/SKILL.md` and
    `.claude/skills/review-triage/SKILL.md` for consistent consumers. V3/v4 and older
    reports remain readable without invented identity or dropped valid evidence.
  - **Action**: Generalized actual source/model tags and added
    `validated-by:research`, retaining separate discoverer/validator identities,
    human/unknown attribution, original finding keys and actual issue readback.
    Defined the shared repository filing mutex, lock ownership/order and cross-host
    limits to coordinate research with discovery/triage and prevent duplicate writes.
  - **Action**: Added immutable
    `/tmp/result-<WHOAMI>-research-<RESEARCH_SLUG>-NNN.md` outputs with per-claim
    dispositions, filing ledger, original-report lineage and an explicit derivative
    kind. Triage excludes these even when names contain `-review`; research does
    not create discovery aliases or overwrite processed markers/results.
  - **Design review**: Independent read-only reviewer approved the design and
    refined filing coordination, unknown/human origin, NEG ledger preservation
    and plan/finding separation. The coordinator incorporated those conditions.
  - **Scope**: Skill-creator guidance kept substantial mode-specific detail in
    references and shared evidence/provenance in one contract. No firewall source,
    product invariant, runtime setting, live environment, issue or label was changed.
    The skill documents themselves are the affected module documentation; product
    README changes are not needed for this workflow-only change.
  - **Review revision**: Independent implementation review caught an underspecified
    aggregate PLAN-KILLED gate. Required three-reviewer convergence on rejection
    of the final approach; an individual kill remains dissent. The reviewer
    rechecked that revision and approved it with no outstanding findings.
  - **Validation**: `git diff --check`; native YAML checks; unchanged invocation
    metadata; all eight local Markdown links resolved; all 21 existing per-finding
    field labels preserved. Stock `quick_validate.py` passed triage directly and
    exact temporary research/deep-review copies omitting only their preserved
    Claude-specific invocation field, with byte-for-byte normalization checked.
  - **Validation**: Executed documented model/slug and watcher-selection examples,
    including legacy discovery reports, research names containing `-review`, and
    canonical filing-key bytes. Private filesystem checks confirmed create-if-absent
    hard-link publication, refusal of occupied files/directories, exclusion by a
    held OS mutex, and reacquisition after its owner exits.
  - **Limits**: Naming/selection checks exercise the documented rules, not an
    external watcher. Lock/publication checks exercise local primitives, not live
    GitHub filing or cross-host coordination. No test issues or labels were created;
    no full firewall review, production validation, or measured recall comparison
    was performed.
  - **Independent forward-test**: A fresh-context agent received only the revised
    skill, two synthetic external reviews, and a local in-memory utility contract/
    source fixture. It confirmed record loss despite a wrong line citation,
    refuted a hang using the actual pre-grouping guard, rejected the padding
    proposal without dismissing the real defect, and kept an unsupported
    throughput claim unresolved after identifying its zero-test evidence as VOID.
    It also answered the contract-only buffering tradeoff question without starting
    a plan, implementation, full firewall review or GitHub workflow.
  - **Executed evidence**: The coordinator inspected and reran the agent's
    `python3 -B /tmp/research-work.MfGIfGJgDW/check_batches.py`. All observation
    assertions passed, including controls, guard witnesses, padding counterexample
    and 45 finite input/size scenarios (22 fidelity passes, 23 observed fixture
    contract failures). The latter are the intentionally defective fixture's
    behavior, not failures of this skill change. The fixture worktree stayed clean.
    Input/validation artifacts remain in `/tmp/research-skill-eval.akZ1WVi09Q`;
    agent evidence remains in `/tmp/research-work.MfGIfGJgDW`.
  - **Evaluation limit**: This is one independent synthetic forward-test plus
    coordinator adjudication, not a matched old/new historical evaluation or a
    measured improvement in real-code defect recall.
  - **Publication limit and completion**: The evaluator completed its investigation
    but stalled during report assembly; it reported no tool error or material
    skill ambiguity. The coordinator took over that bounded step, published
    `/tmp/result-gpt-unknown-research-batch-export-reviews-001.md` atomically, and
    verified manifest/header/name agreement, both 21-field finding entries, all
    original finding keys and the filing ledger. This is coordinator-assisted
    report completion, not an unassisted end-to-end pass. No original report,
    prior result or processed marker was overwritten.
