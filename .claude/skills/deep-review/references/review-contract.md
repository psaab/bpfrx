# Shared review contract

Contract version: `xpf-review-v3`. Both `deep-review` and `review-triage`
read this file. Changes to this contract must be reflected in both workflows.
Repository guidance and actual user scope/authorization still apply.

## Impact, confidence, and verification are separate

Assess supported behavior and concrete production consequences, including
security, availability, integrity, recovery, and operator control. State who or
what can reach the behavior, under which configuration/lifecycle conditions, its
blast radius, duration, recovery cost, and the mechanisms that bound it.

| Severity | Consequence to justify |
| --- | --- |
| Critical | Broad, catastrophic loss of protection or integrity with severe operational consequences; explain why High is insufficient |
| High | Substantial loss of required enforcement or isolation, privileged authority, durable configuration integrity, fleet/appliance availability, or HA ownership/recovery |
| Medium | Material but bounded incorrect behavior, availability loss, performance degradation, or operator/API contract failure |
| Low | Limited consequences or maintenance/assurance improvement without demonstrated substantial operational impact |
| Unassessed | Impact cannot yet be bounded; specify the missing information |

These are impact categories, not automatic keyword mappings. An authenticated
configuration operation can cause a High outage. A fail-closed outcome can
strand management or all permitted traffic. A misleading "installed" status can
hide missing protection. Conversely, a visible counter discrepancy is not a High
finding without that consequence. Do not categorically downgrade observability,
HA compatibility, test infrastructure, or authenticated paths.

Confidence describes how strongly evidence supports the precise claim. Grade it
High/Medium/Low and explain the remaining assumptions. Neither model family nor
an unsupported historical success percentage changes the evidence bar.

Verification is one of:

- `EXECUTED`: a valid local test or authorized scenario exercised the claimed
  behavior. Name its scope; a component result alone does not verify the entire
  deployed path.
- `STATIC`: source/contract reasoning establishes a specifically bounded
  property. Record the complete relevant call/type/validation chain and limits.
- `NEEDS_VALIDATION`: evidence is incomplete; identify the next decisive check.
- `VOID`: an attempted check was invalid or did not measure the property.
  Explain the reason and retain the observations.

An unverified potentially severe claim keeps its potential impact visible but
is not presented as a confirmed severe defect. Lack of lab access changes
verification and confidence, not the consequence being investigated. Existing
valid evidence can still support a narrower claim after another check is VOID.

## Dispositions and coverage

Use one `Gate verdict` per candidate:

| Verdict | Required reasoning |
| --- | --- |
| MATERIAL | A consequential defect is established in live supported behavior at the stated verification revision; it survives refutation and deduplication |
| NEEDS_VALIDATION | A credible question remains unresolved; preserve potential impact and the exact next check, including freshness/provenance gaps |
| FIXED | Identify the fixing change and show why it covers this claim; separately retain any in-scope delivery/backport work |
| STALE | Evidence proves the behavior no longer participates in the relevant product; a directory, comment, missing old symbol, or old cap is insufficient |
| DUP | Cite the existing actionable owner and demonstrate that its root cause, affected contract, and acceptance scope cover this claim |
| COHORT | A real, bounded improvement suitable for a tightly related actionable group; justify the consequence and grouping |
| NEG | Refute a specific hypothesis with the actual guarding mechanism or valid contradictory evidence |

NEG belongs in the inspection/disposition log, not the findings list. Distinguish
`inventoried`, `inspected without finding`, `hypothesis refuted`,
`behavior verified`, and `not inspected` in coverage. A negative sentence for
each file is not proof that all its behavior is correct.

Independently check every high-impact MATERIAL and a risk-selected sample of
dismissals (NEG, DUP, STALE, COHORT). Record who checked, the revision, and the
reasoning. An independent reviewer should first evaluate the evidence without
being told the originating model or an expected disposition. If no independent
reviewer is available, identify coordinator self-review honestly.

Deduplicate by the actual corrective work and acceptance scope. The same class
at two independent consumers may need distinct fixes; a single proven root fix
may cover several sites. A shared title, line number, model, closed issue, or
opposite failure direction does not settle this. Preserve distinct surfaces
and reopened residuals even when linking them to an existing owner.

## Adversarial discovery and independent refutation

Use adversarial reasoning to assess the implementation's defensive guarantees,
not merely to argue against findings after discovery. Each source-review
assignment records the following, grounded in the supported product and source:

- **Protection and boundary:** the enforcement, isolation, authority, integrity
  or availability property owed, the assets/principals it protects, and where
  less-trusted data or state acquires authority.
- **Actor and influence:** the relevant network participant, authenticated
  low-privilege user, operator, peer or external service; what it actually
  controls and the configuration/lifecycle prerequisites. Do not silently grant
  administrative access, peer compromise or control of internal state. Distinguish
  deliberate untrusted influence from ordinary faults and operator mistakes.
- **Assumptions to challenge:** where validation, authorization and resource
  limits are enforced; whether all relevant consumers preserve them; and whether
  cached state, alternate paths, version differences, partial failure, restart
  and recovery preserve the same property. Combine relevant domain expertise
  when a guarantee crosses subsystem boundaries.
- **Evidence and limits:** the source-grounded reasoning, actual guard and its
  scope, bounded local evidence where available, plausible consequence, and
  unresolved assumptions with a next check. A threat hypothesis is not a defect
  until the evidence supports it; a guard's existence is not proof of coverage.

Select relevant questions rather than inventing an attacker for every bug.
For a purely reliability finding, record the triggering fault and explain why
an adversarial actor is not required. Review coverage retains the important
questions checked even when no finding results. Do not claim a whole threat
class is covered by one negative test or one inspected entry point.

Independent refutation is a second responsibility: challenge the claimed defect
and challenge proposed dismissals with their actual guards, actor assumptions,
paths and transitions. Keep `Adversarial analysis` separate from
`Refutation attempt` so neither the discovery rationale nor contrary evidence
disappears in triage. These requirements do not authorize exploit construction
or live probes; the defensive scope and evidence rules still apply.

## Behavior and workload selection

Choose relevant rows from the current documented product contract. Resolve
ambiguous semantics explicitly; do not invent invariants while reviewing.
For parity claims, name the reference product/version and authoritative
behavioral source or independent observation.

| Behavior | Boundaries and transitions to account for |
| --- | --- |
| Enforcement | Config syntax/schema -> typed Go -> control wire -> Rust policy/filter/session behavior and kernel host-inbound enforcement; allowed and denied cases |
| Kernel/NIC integration | Actual attach/bind modes, kernel/driver/library interfaces, ring and UMEM ownership, wakeup/progress, offloads, host-stack handoff and device lifecycle |
| Network semantics | Bidirectional protocol/state behavior, fragments, MTU/PMTUD, generated errors, encapsulation and preservation of identity/policy through transformations |
| Apply and persistence | Meaning of commit success, generation publication, partial failure, rollback, cold boot, restart, and retained state |
| Identity and state | Zone/VRF/interface identity through routing, session lookup, translation, cached decisions, and expiry |
| HA | Ownership/fencing, synchronization completeness, failover/rejoin, stale generations, and explicitly supported mixed-version behavior |
| Resource lifecycle | Admission limits before resource commitment; accounting across workers/replicas; ownership and reclamation through normal close, error, cancellation, and recovery |
| Management and delivery | Principal/authorization propagation, secrets, service startup, package/image/upgrade integrity, and management recovery |
| Assurance | Runnable test registration, production-path execution, oracle independence, observations that distinguish failure from missing measurement |

Performance review names the workload: established-flow throughput, connection
rate, concurrent state, tail latency with competing traffic, update/control
latency, or recovery after pressure. Record the offered/achieved load, packet/
flow mix, active workers/queues, configuration, baseline, and relevant resource
accounting. Do not generalize a bulk-throughput result to connection rate, or
quote a generator limit as a measured firewall ceiling.

For kernel/NIC-dependent claims, record the relevant kernel release/configuration,
NIC/driver/firmware and library identity, attach/bind modes, offloads and queue
configuration. Separate observed settings from documented requirements and
unknowns; a result from one mode or driver does not verify another.

For performance claims, identify the operation and cost unit (per packet, flow,
update, worker or peer), relevant cardinalities and contention scope. Execution
evidence includes build/profile settings, CPU/NUMA/queue placement, measurement
window and variability, and relevant work counters or profiles. Use cycles,
allocations, copies, syscalls, cache misses or contention observations where they
can distinguish the proposed cause. Check traffic distribution and generator/
receiver limits before attributing a ceiling to the firewall. Keep established
throughput, new-flow rate, tail latency, update latency and recovery separate;
aggregate throughput does not discharge fairness or per-queue progress. Missing
host/profiling evidence limits a performance claim, not a separately established
correctness defect. Do not require a benchmark to report a proven cost bound,
or present that bound as a measured bottleneck or speedup.

Use deterministic local assertions and existing property/regression tests where
they can establish the contract. A live-system validation plan is not authority
to run it. Read the applicable validation procedure and obtain any missing
authorization before work that changes a shared environment.

## Evidence validity

Every execution claim records:

- Source revision, test-only diff, relevant build options, artifact identity,
  and command/fixture. Identify what actually ran, not only what was built.
- Named tests/scenarios collected and completed, required configuration and
  environment, relevant instrumentation, and expected versus observed behavior.
- Evidence that the production path and observation mechanism were exercised.
  Missing traffic, missing metrics, stale objects, absent prerequisites, skipped
  tests, and empty test selection cannot be interpreted as successful behavior.
- A positive control or other independent witness appropriate to the claim.
  Agreement between two implementations is supplemented by a property each owes
  independently; shared mistakes can agree perfectly.
- Scope and limitations. A component assertion does not alone establish global
  availability, wire enforcement, or multi-node behavior.

Keep raw observations and test-only diffs in owned scratch evidence and include
the decisive excerpts in the report. Do not require exploit payloads or destructive
reproduction to qualify a defensive finding. Where bounded local validation
cannot settle the claim, preserve it as NEEDS_VALIDATION with a scoped next step.

Repository examples to consult when relevant:
`docs/engineering-style.md` (verification and oracle discipline),
`docs/firewall-validation-harness-design.md` (wire-observation validity),
`docs/harness-ledger.md`, `test/incus/HARNESSES.unreached`, and
`docs/userspace-newflow-ceiling.md`. These describe evidence requirements and
known limitations, not proof that their checks have run for this review.

## Freshness and provenance

Reports identify the repository independently of checkout names or model names.
Use the credential-free remote identity plus base SHA; local-only reviews use
an explicit local identity. Never publish embedded credentials or raw environment
dumps. A consumer verifies that it resolved the intended repository and revision.
Wrong-repository evidence or unresolved provenance requires reconciliation, not
an automatic "confabulated" judgment.

Record one immutable comparison SHA for each merge/triage pass. Check the
candidate's evidence and its supporting dependency set: callers, guards, types,
configuration admission, build inclusion, and consumers relevant to the claim.
Recheck affected reasoning and tests after those dependencies change. A quiet
diff of the cited file alone is not a freshness proof. Follow symbol moves
before calling something fixed or retired.

Use durable reports and issue/PR history with recorded freshness and pagination
limits. Historic indexes are leads; refresh the specific issue bodies, fixing
changes, and acceptance criteria that carry a DUP/FIXED decision. A closed issue
is not proof of a complete fix. Offline/partial history is explicitly incomplete.

## Report schema and completion

The final header contains:

- `Review contract: xpf-review-v3`, run ID, repository identity, checkout path.
- Base SHA; comparison repository/ref/SHA and fetch time, or unavailable reason.
- Model identity/family and identity source (or unknown).
- Mode, requested/effective scope, focus, exclusions, review/validation limits.
- Output path and retained evidence location; release target only when in scope.

Every actionable finding or unresolved candidate has these exact labels.
Use "not applicable" with a reason where a field is not relevant:

- `Finding ID`: stable within this run, carried into triage and fix tracking.
- `Title`
- `Severity`: include impact justification and whether it is potential.
- `Confidence`
- `Verification`
- `Gate verdict`
- `Contract`: expected behavior and its documented basis.
- `Adversarial analysis`: protection/trust boundary, actor and actual influence
  (or non-adversarial fault), prerequisites, challenged assumptions and limits.
- `Evidence`: repository-relative file:line at a named SHA and a concise
  excerpt actually read; separate observations from inferences.
- `Probe`: commands/fixtures, build/artifact provenance, observations, controls,
  and limitations, or the reason no execution evidence exists.
- `Trace`: the relevant behavior/dependency chain.
- `Refutation attempt`: candidate guards/callers/assumptions checked and result.
- `HPC/invariant check`: relevant ownership/accounting, concurrency, layout,
  cost unit and scaling dimensions; distinguish source bounds from measured
  cost and retain workload/host evidence or limitations in Probe.
- `Why it matters`: concrete production impact and its bounding factors.
- `Fix direction`: corrective work, affected consumers, regression acceptance
  criterion, and remaining validation.
- `Labels`: include `vsrx-parity` only for grounded parity claims.
- `Dedup note`: owners/history checked, freshness limitations, and why this
  is distinct, a duplicate, or a residual.
- `Verified against comparison revision`: exact SHA, evidence/dependencies
  rechecked, and result; unavailable verification is not a successful check.
- `Remediation status`: confirmed, assigned, fixed-in-source,
  regression-verified, delivered, or pending validation, with evidence/IDs.

A final report includes ranked findings and unresolved high-impact questions,
the inspection/disposition log (including area and cross-cutting expert
ownership, applicability and coverage gaps, adversarial
questions checked and unresolved assumptions), risk worklist, actual coverage,
verification gaps, and counts that reconcile to stable finding IDs. Include
reasons for every drop/downgrade. Do not put NEG in the findings table or count it as a defect.
Report confirmed, unresolved, fixed, duplicate, stale, and cohort counts
separately; count actual issue filings only when IDs exist.

Do not declare all bugs fixed from an empty findings list. Report the behaviors
and conditions checked and those still unknown. Implementation handoff includes
the acceptance criterion and all affected consumers. Source fixes, verified
regression guards, and delivery to an in-scope release are separate milestones.

V2 and older reports remain readable: derive their metadata and map
`Verified against origin/master` to the named comparison revision where
supported. Reconstruct missing adversarial analysis only from evidence actually
checked; do not fabricate it or missing Probe/provenance fields. Mark substantively
incomplete claims NEEDS_VALIDATION; an old format or absent new label is not by
itself a false finding or a reason to discard otherwise sufficient evidence.

## Evaluating changes to this skill

First walk through representative decisions: confirmed defect, refuted candidate,
unavailable validation, stale artifact, changed dependency, closed-owner residual,
wrong repository, and fixed-in-source but undelivered release work. Check that
both discovery and triage preserve the same evidence and limitations.
Also check specialist assignment and adversarial reasoning on a cross-boundary
contract, a guard covering only one relevant path or lifecycle state, and a
reliability fault with no adversarial actor. Verify that a no-finding assignment
retains the important questions checked and its unresolved assumptions. Include
a v2 report with sufficient evidence but no new adversarial-analysis label.
For expert-coverage changes, also walk through a kernel-mode-dependent claim,
a network transformation spanning area boundaries, a throughput-only result used
to claim new-flow capacity, and a focused review where an expert is not relevant.
Verify that missing host evidence bounds the claim without erasing valid static
reasoning, and that expert assignments do not silently expand user scope.

For an empirical quality claim, compare old and revised instructions on held-out
historical review cases using matched scope, model settings, context, and effort.
Keep issue titles, fix explanations, prior dispositions, and expected answers out
of the evaluator's input; use them for independent adjudication afterwards.
Use sanitized local artifacts and respect the user's resource/side-effect limits.

Measure known consequential defects missed, false positives, false dismissals,
verified consequential findings per effort, validation cost, and fix recurrence.
Account for duplicate root causes and incomplete evaluations; do not reward
severity inflation or report volume. Report sample size and uncertainty.
Structural checks or a guided scenario walkthrough are not a measured recall
improvement. Maintain and expand the evaluation cases from demonstrated failures.
