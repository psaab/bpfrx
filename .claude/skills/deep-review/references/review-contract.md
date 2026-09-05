# Shared review contract

Contract version: `xpf-review-v4`. Both `deep-review` and `review-triage`
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

### Model identity and report naming

The model, the agent application, and the report filename are different things.
Record these exact header labels in both the run manifest and final report:

- `MODEL_RAW`: the coordinator's model identifier as reported for the current
  run/turn, including version and suffix, or `unknown` if no exact identifier is
  exposed. Do not turn a broad "based on GPT-5" statement into an exact serving
  model or snapshot. Preserve a reported alias literally and identify it as an
  alias rather than guessing the model behind it.
- `MODEL_SOURCE`: where the identity was actually observed, scoped to this
  run/turn. Distinguish a runtime-reported model, a selected/requested model,
  a known family only, and unavailable/conflicting evidence. A model picker or
  launch selection is not proof of a hidden backend snapshot.
- `MODEL_HOST`: the application running the coordinator (for example `codex`),
  or `unknown`. The host is not the model: GPT can run through another host.
- `WHOAMI`: the filesystem-safe report prefix derived below. It is not the
  output of Unix `whoami`, a free-form alias or a compatibility override.

Use current-run metadata exposed by the active runtime or its run-scoped
configuration. Do not start another agent or change models to discover identity.
Global settings, inherited `MUSE_MODEL`/`ANTHROPIC_MODEL`/`OPENAI_MODEL` values,
installed binaries, old transcripts and existing filenames do not establish the
current model unless independently tied to this run. Codex permits per-turn model
overrides ([official documentation](https://learn.chatgpt.com/docs/app-server#turns));
a saved default alone cannot settle the current identity. Read only relevant
metadata, not credentials, environment dumps or unrelated conversation history.

Derive `WHOAMI` in this order:

1. If `MODEL_RAW` is known, use the full identifier: lowercase it, replace runs
   of characters outside ASCII `a-z`, `0-9`, `.`, `_`, `-` with `-`, and strip
   leading/trailing `.`, `_`, `-`. Preserve version numbers and model suffixes;
   do not apply `cut -d- -f1`, strip GPT versions, or translate provider families.
   Keep the unsanitized identifier in `MODEL_RAW`. If nothing remains after
   sanitization, treat the identity as unresolved instead of inventing a label.
2. If only the model family is established, keep `MODEL_RAW: unknown`, state
   that family and its source in `MODEL_SOURCE`, and use `<family>-unknown`.
   Apply the same safe-name normalization to the family. Known GPT with no exact
   model identifier yields `gpt-unknown`, never `muse-spark` or a guessed GPT ID.
3. If only the host is established, use `<host>-unknown` with the same
   normalization and `MODEL_RAW: unknown`. With neither, use `unknown`.
   An empty normalized family/host is unavailable, not a valid prefix.
   Conflicting evidence must be reported; use only the level actually established.

Naming examples, not defaults or model-selection instructions:

| Observed coordinator identity | `MODEL_RAW` | `WHOAMI` |
| --- | --- | --- |
| Exact runtime identifier `gpt-5.6-sol` | `gpt-5.6-sol` | `gpt-5.6-sol` |
| Exact runtime identifier `gpt-daybreak-blue-latest` | `gpt-daybreak-blue-latest` | `gpt-daybreak-blue-latest` |
| Exact runtime identifier `muse-spark-1.1` | `muse-spark-1.1` | `muse-spark-1.1` |
| GPT family only, running in Codex | `unknown` | `gpt-unknown` |
| Codex host only, model family unavailable | `unknown` | `codex-unknown` |
| No usable identity evidence | `unknown` | `unknown` |

The final prefix identifies the coordinator, not an arbitrarily selected worker.
Record each worker's model/source separately in its assignment evidence; do not
copy the coordinator's identity onto workers or use one worker's model to label
the entire campaign. Record model changes during the campaign with their work
scope and derive the final prefix from the coordinator's identity at publication.

The publication gate compares the derived prefix with `WHOAMI` in the manifest,
header and final basename. An existing report sequence is never evidence of the
current model. Preserve legacy filenames during triage; record identity conflicts
as provenance corrections without rewriting history or discarding valid findings
solely because their original author used the wrong prefix.

### Repository and revision identity

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

## Named reports, issue filing and origin tags

Record `Review name` as human-readable text and `REVIEW_SLUG` as its filename
component. Lowercase the name, replace runs outside ASCII `a-z` and `0-9` with
`-`, and strip leading/trailing `-`. If empty, use the effective mode name and
record that fallback. Choose a short descriptive name at setup; no shell
evaluation of review names or issue titles is permitted.

New reports use `/tmp/<WHOAMI>-review-<REVIEW_SLUG>-NNN.md`. The immutable run ID,
repository and finding IDs establish provenance; the filename alone does not.
Legacy `/tmp/<WHOAMI>-review-NNN.md` reports remain readable and participate in
deduplication. Never publish a second compatibility alias of the same report:
watchers could treat it as new work and file twice.

Every report includes a filing ledger, even in report-only mode:

| Finding ID | Title | Originating model(s) | Gate verdict | Filing status | Issue URL(s) | Origin tags | Notes / last verified |
| --- | --- | --- | --- | --- | --- | --- | --- |

Use `NOT_FILED`, `DRAFTED`, `OPENED_THIS_RUN`, `LINKED_EXISTING`, `FAILED`, or
`CREATE_UNCERTAIN` for filing status. Missing authorization is NOT_FILED with a
reason, not a failed request. OPENED_THIS_RUN requires a confirmed issue number/
URL and readback from the intended repository. Count unique issues opened and
findings covered separately: a cohort issue can cover several Finding IDs.
LINKED_EXISTING is not a new filing. Keep origin-tag verification separate from
issue creation, so a created issue with missing tags is visible as incomplete.

For each finding, record the discovering agent and its evidenced model/source
using the identity rules above. The issue's `model:` label identifies the
discoverer, not the coordinator or independent verifier by default. Unknown
worker identity remains unknown; do not copy the coordinator's model into it.
If one issue groups findings from multiple evidenced models, retain each model
label and the per-finding attribution in its body.

In an authorized issue-filing run:

- Apply `source:deep-review` and `model:<originating-WHOAMI>` to each new issue,
  plus the repository's existing `audit` label where available and relevant
  severity/component labels. The model suffix uses the same safe normalization
  and explicit unknown handling as report identity, but for the discoverer.
  Inspect repository labels first; create missing required origin labels only
  within authorized filing/tagging scope. Do not overwrite unrelated labels or
  silently truncate/substitute a model if label policy or permissions prevent it.
- Include a visible **Review origin** section in the initial issue body:
  source `deep-review`, review name/slug, immutable run ID, repository, base and
  verification SHAs, Finding ID(s), discovering model(s) and evidence sources,
  and coordinator model/source separately. Include the published report basename
  and durable report URL if available; a local `/tmp` path is a locator, not a
  GitHub-accessible evidence link. Include decisive evidence and fix acceptance
  criteria in the issue itself rather than relying on a temporary report.
- Persist the create result in the run ledger immediately, then read back the
  issue body and labels. Record actual URLs and confirmed tag names, or the
  exact pending/failed provenance action. Do not claim labeling succeeded from
  an intended label list. No issue or label mutations occur in report-only mode.
- If creation times out or its result is lost, mark CREATE_UNCERTAIN and search
  the intended repository for the exact run ID and Finding ID(s), checking the
  issue body before retrying. Hold the existing per-report filing lock through
  this reconciliation; an ambiguous response must not produce duplicate issues.
  An empty search result alone does not prove creation failed; unresolved or
  unavailable readback stays CREATE_UNCERTAIN instead of triggering a blind retry.
- For a pre-existing duplicate, link its owner without claiming this review or
  model originated it. Any authorized corroboration/update must preserve the
  original provenance and clearly distinguish rediscovery from initial discovery.

If triage files issues after the original report was published, leave that
report immutable. `/tmp/result-<report-stem>.md` contains the findings,
reasoned dispositions and updated filing ledger as a self-contained filing-status
report, where `report-stem` is the original filename without its final `.md`.
For example, `gpt-5.6-sol-review-ha-failover-001.md` produces
`/tmp/result-gpt-5.6-sol-review-ha-failover-001.md`, not a `.md.md` suffix.
Return both paths and identify the result as the later status snapshot.
Pending filing/tagging actions remain explicit; neither an issue-creation count
nor the triaged marker means provenance tagging or remediation is complete.

## Report schema and completion

The final header contains:

- `Review contract: xpf-review-v4`, run ID, repository identity, checkout path.
- `Review name`, `REVIEW_SLUG`, and filing-status snapshot timestamp.
- Base SHA; comparison repository/ref/SHA and fetch time, or unavailable reason.
- `MODEL_RAW`, `MODEL_SOURCE`, `MODEL_HOST`, `WHOAMI` as defined above;
  worker identities and any coordinator model changes remain separately visible.
- Mode, requested/effective scope, focus, exclusions, review/validation limits.
- Output path and retained evidence location; release target only when in scope.

Every actionable finding or unresolved candidate has these exact labels.
Use "not applicable" with a reason where a field is not relevant:

- `Finding ID`: stable within this run, carried into triage and fix tracking.
- `Title`
- `Discovery origin`: discovering agent, model identifier/source and derived
  originating-WHOAMI; retain distinct contributors when grouping findings.
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
- `Issue tracking`: filing status, actual issue URL(s), whether opened this run
  or linked, verified origin labels and remaining filing/tagging work.

A final report includes ranked findings and unresolved high-impact questions,
the inspection/disposition log (including area and cross-cutting expert
ownership, applicability and coverage gaps, adversarial
questions checked and unresolved assumptions), risk worklist, actual coverage,
verification gaps, and counts that reconcile to stable finding IDs. Include
reasons for every drop/downgrade. Do not put NEG in the findings table or count it as a defect.
Report confirmed, unresolved, fixed, duplicate, stale, and cohort counts
separately; reconcile the filing ledger to actual issue URLs and verified origin
tags. Never infer issue creation from a planned title, draft or recommendation.

Do not declare all bugs fixed from an empty findings list. Report the behaviors
and conditions checked and those still unknown. Implementation handoff includes
the acceptance criterion and all affected consumers. Source fixes, verified
regression guards, and delivery to an in-scope release are separate milestones.

Reports predating these fields, including earlier v3 identity headers, remain
readable: derive their metadata and map `Verified against origin/master` to the
named comparison revision where
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
For identity changes, check full GPT identifiers and versions, a GPT coordinator
with a differently named worker, inherited Muse settings, family-only and wholly
unknown identity, and a conflicting filename/header. A model-prefix mismatch
must not pass publication merely because that prefix has historical reports.
For filing changes, check a report-only run, a new issue, a linked duplicate,
multi-model findings grouped into one issue, a lost create response, missing
label permissions, and triage after immutable report publication. Named and
legacy filenames must both be consumed exactly once without inventing origin.

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
