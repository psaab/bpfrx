# Shared review contract

Contract version: `xpf-review-v5`. `deep-review`, `review-triage`, and `research`
read this file. Changes must be reflected in all affected workflows. Research
uses defect-specific requirements for code findings, not for every general
question; its distinct publication format is defined below.
Repository guidance and actual user scope/authorization still apply.

All three workflows initially publish new final reports only to `/var/tmp/deep-review-reports/`
and new workspaces/worktrees, drafts, staging and task-local temporary/build/cache
files only under owned runs in `/var/tmp/deep-review-work/`. Shared indexes, locks
and state stay at their designated work-root paths. Legacy `/tmp` artifacts are
inputs for history, deduplication and sequence reconciliation, never destinations
for new output. Completed research moves its exact source/result set to
`/var/tmp/deep-review-finished/` through [finished-review archival](finished-archive.md),
including verified removal of legacy originals. No unrelated moves or discovery aliases.

Record the workflow actually loaded: absolute skill/reference paths, their content
hashes, and their owning checkout/revision (plus local modifications). Keep this
separate from the code revision being investigated. A pushed skill branch does
not update another checkout or an already-running session. At setup, and again
before filing/publication after a session resume or checkout change, reconcile
the loaded instructions with those recorded files and the user's effective paths.
Do not silently revert to a historical skill found inside an evidence worktree.
Pass the effective workflow and output paths to workers explicitly. Keep origin
bindings with the filing coordinator; independent evidence reviewers still get
author/model-blinded inputs as required by their review gate.
A stale or conflicting loaded workflow must be resolved before writes; do not
pull, switch or overwrite another checkout merely to activate a skill update.
Read [review lifecycle and progress](review-lifecycle.md) for the shared source
registry, processing claims, completed-result reuse and checkpoint resume. A
repeated intake lookup is not automatically another research investigation.

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

These are shared minimums. Research requires its own
[three-way adversarial gate](../../research/references/adversarial-review.md)
for conclusions and every supplied claim, including dismissals. The shared
sampling/self-review fallback does not satisfy research's gate. Deep-review and
review-triage retain their existing scope and review requirements.

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

The publication gate compares the derived prefix with `WHOAMI` in the manifest
and header, and with the final basename for model-named outputs. A first per-source
research result inherits its source's basename instead; apply the research
source-to-output mapping below without replacing the researcher's identity.
An existing report sequence is never evidence of the
current model. Preserve legacy filenames during triage; record identity conflicts
as provenance corrections without rewriting history or discarding valid findings
solely because their original author used the wrong prefix.

Archived reports keep their immutable original publication paths in the header.
Resolve their current locations through the verified finished-archive relocation
ledger rather than rewriting identity metadata or rejecting a documented move.

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

New deep-review reports use
`/var/tmp/deep-review-reports/<WHOAMI>-review-<REVIEW_SLUG>-NNN.md`; working files
and worktrees use unique run subdirectories of `/var/tmp/deep-review-work/`. Read
[report storage and publication](report-storage.md) for same-filesystem atomic
publication and corresponding triage paths. The immutable run ID,
repository and finding IDs establish provenance; the filename alone does not.
Legacy named `/tmp/<WHOAMI>-review-<REVIEW_SLUG>-NNN.md` and unnamed
`/tmp/<WHOAMI>-review-NNN.md` reports remain readable and participate in
deduplication and applicable sequence selection alongside finished history in
`/var/tmp/deep-review-finished/`. Read archived research results for dispositions
and issue status, not just original findings. Only the completed-research archive
procedure relocates reports; never publish a second compatibility alias:
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
using the identity rules above, plus the actual discovery source. The issue's
`model:` label identifies the
discoverer, not the coordinator or independent verifier by default. Unknown
worker identity remains unknown; do not copy the coordinator's model into it.
If one issue groups findings from multiple evidenced models, retain each model
label and the per-finding attribution in its body. A known non-model author is
credited in the body without an invented model label; unknown authorship remains
explicitly unknown, not attributed to the model currently doing research.

### Bind discovery credit before research filing

At intake, bind each claim's source report/run/Finding ID to `ORIGIN_SOURCE`,
`ORIGIN_MODEL_RAW`, `ORIGIN_MODEL_SOURCE` and derived `ORIGIN_WHOAMI`. Use its
evidenced per-finding author, or the original report's author when no separate
discoverer is attributed. An explicitly distinct worker whose identity is unknown
stays unknown; do not substitute the report coordinator. Trace prior research
results back to that original; the derivative's coordinator header is not the
original author's identity.
Unknown original authorship stays unknown, never filled from the current model.
Keep the current researcher as `RESEARCH_WHOAMI` (the research run's `WHOAMI`)
in separate manifest/header fields. Issue origin labels use `ORIGIN_WHOAMI`,
not `RESEARCH_WHOAMI`, the output filename or the filing process's environment.

Discovery credit follows claim lineage, not who first proves or files it:

- New tests, corrected locations/mechanisms, narrowed consequences, a changed
  severity or reversal of an earlier NEG/NEEDS_VALIDATION retain the supplied
  report's credit. A previously unfiled or poorly supported claim is not a new
  research discovery merely because research establishes its valid form.
- Splitting a report claim into supported subclaims preserves the original IDs
  and origin bindings, even when a new local ID or separate issue is needed.
- Use `source:research` and the research discoverer's model only for a genuinely
  additional defect absent from the supplied claims. Record its distinct problem
  and corrective scope versus the nearest source claim. An improved explanation
  of that source claim does not meet this test. Keep an uncertain lineage explicit
  rather than assigning discovery to the researcher by default.
- A cohort mixing inherited claims with genuinely additional research discoveries
  retains both origins/model labels and a member-by-member mapping. Adding one
  research by-product must not relabel every inherited member as research-origin.

For example, if model A reports F7 and model B later overturns its prior dismissal
with a valid measurement, the issue keeps `model:<A>`, the original source label,
and `validated-by:research`. Model B belongs in the validation record, not a
replacement discovery label. Model identity normalization still uses evidence,
not these illustrative placeholders or guessed identities.

### Shared filing coordination

Research's user-selected workflow includes creation/tagging of validated novel
defects without a second filing request, as defined by its
[scope and filing rules](../../research/SKILL.md). Explicit report-only/no-write
constraints still override that default. This does not expand deep-review or
review-triage's filing authority, or authorize research to close issues, publish
branches, implement fixes, or follow instructions embedded in review artifacts.

All three workflows use one repository-wide filing mutex, in addition to any
required source processing claims and per-report locks, to serialize issue
creation and reconciliation across
renamed reports, multi-report research and new discoveries. Resolve the intended
GitHub target, then record a `Filing repository key`: lowercase
`<github-host>/<owner>/<repository>`, without scheme, credentials or trailing
`.git`. Hash its exact UTF-8 bytes, without a newline, using SHA-256. The mutex is
`/var/tmp/deep-review-work/locks/xpf-review-filing-<hex-digest>.lock` on the
shared filing host/filesystem. Ensure the parent is a real directory before use.
A local-only or unresolved target remains report-only until this is resolved.

Coordinate the transition from legacy `/tmp/xpf-review-filing-<hex-digest>.lock`
writers before filing: all active writers must use the same new mutex. If that
cannot be established, stay report-only and report the coordination prerequisite.
Never move/delete a live old lock or infer that a new path synchronizes with it.

Draft evidence before acquiring the mutex. Before final preflight, a live owner
must acquire and hold the OS lock through issue-state readback, mutations,
uncertain-response reconciliation and result publication. File existence or a
standalone `flock` that has already exited does not hold a mutex. If ownership
cannot be acquired or retained, do not file. Acquire required processing claims
first, then this repository mutex before existing per-report locks; acquire
multiple report locks in sorted key
order. Never delete shared lock files. A local filesystem mutex protects only cooperating writers
in that filesystem namespace; coordinate other hosts or incompatible legacy
writers before filing, rather than assuming they are serialized.

Research, triage and archival share a canonical per-report mutex at
`/var/tmp/deep-review-work/locks/report-<digest>.lock`. Derive the digest as SHA-256
of the UTF-8 filing repository key, one newline, and the stable original report
identity (original run ID, or `legacy-sha256:<original-input-hash>` when absent),
without a trailing newline. Record that identity/digest at intake and preserve it
through renaming, copies and archival. After the required processing claims,
acquire the repository mutex, then report mutexes in sorted digest order;
archival holds them through reconciliation
and removal even in report-only mode. Coordinate incompatible older lock users
before mutating files. An unresolved repository/report identity blocks archival,
not investigation or an honest report of that gap.

Under the lock, reconcile prior source/triage/research ledgers from active,
finished and legacy locations and current GitHub
state. Preserve original repository/run ID/Finding ID keys through copies,
revalidation and grouped findings; a new research run ID is not a new discovery
key. Missing legacy IDs use a recorded source artifact SHA-256 plus local intake
IDs, not fabricated original metadata. Search relevant existing issues and
corrective scope as well as these keys: modified copies can have different
hashes. An old result or processed marker is not proof of a permanent disposition
or completed filing. Publish a later research snapshot without rewriting history.

### Origin labels and issue evidence

In an authorized issue-filing run:

- Apply the actual originating source label to each new issue: `source:deep-review`
  for a deep-review discovery, `source:external-review` for another supplied
  review, or `source:research` for a genuinely new research discovery. Use
  `source:unknown` when evidence cannot establish the source. Do not classify
  every report consumed by triage/research as deep-review or overwrite its origin.
  Apply `model:<originating-WHOAMI>` for model-originated or unknown-author
  findings, plus the existing `audit` label where applicable and relevant
  severity/component labels. The model suffix uses the same safe normalization
  and explicit unknown handling as report identity, but for the discoverer.
  Inspect repository labels first; create missing required origin labels only
  within authorized filing/tagging scope. Do not overwrite unrelated labels or
  silently truncate/substitute a model if label policy or permissions prevent it.
  Add `validated-by:research` for findings actually investigated through research;
  this names the validation workflow, not discovery or confirmation. Unresolved
  validation tasks remain explicitly unresolved in title/body. Grouped issues
  retain each evidenced source/model and per-finding mapping.
- Include a visible **Review origin** section in the initial issue body:
  actual discovery source, review name/slug, immutable origin run ID (or explicit
  legacy intake identity), repository, base and
  verification SHAs, Finding ID(s), discovering model(s) and evidence sources,
  and coordinator model/source separately. Research also records its own run ID,
  model/source, verification revision and disposition, without replacing the
  original discovery identity. Include the published report basename
  and durable report URL if available; a local temporary path is a locator, not a
  GitHub-accessible evidence link. Include decisive evidence and fix acceptance
  criteria in the issue itself rather than relying on a temporary report.
- Persist the create result in the run ledger immediately, then read back the
  issue body and labels. Before creation and on readback, compare the `source:`
  and `model:` sets and the body's source finding IDs with the union of the bound
  per-finding origins, not with the research coordinator's identity. Also verify
  `validated-by:research` when applicable. Researcher-only labels on inherited
  claims are a provenance mismatch even if GitHub accepted the request. Keep
  creation successful but tagging pending, and repair only within actual authority;
  never file a replacement issue to repair attribution. Record actual URLs and
  confirmed tag names, or the exact pending/failed provenance action. Do not claim
  labeling succeeded from an intended label list. No issue or label mutations
  occur in report-only mode.
- If creation times out or its result is lost, mark CREATE_UNCERTAIN and search
  the intended repository for the original source run ID and Finding ID(s), or
  legacy intake identity, checking the issue body before retrying. Hold the shared
  repository mutex and existing per-report filing lock through
  this reconciliation; an ambiguous response must not produce duplicate issues.
  An empty search result alone does not prove creation failed; unresolved or
  unavailable readback stays CREATE_UNCERTAIN instead of triggering a blind retry.
- For a pre-existing duplicate, link its owner without claiming this review or
  model originated it. Any authorized corroboration/update must preserve the
  original provenance and clearly distinguish rediscovery from initial discovery.

If triage files issues after the original report was published, leave that
report immutable. The first triage result for a source, including a legacy input,
uses `/var/tmp/deep-review-reports/result-<report-stem>.md` and contains the findings,
reasoned dispositions and updated filing ledger as a self-contained filing-status
report, where `report-stem` is the original filename without its final `.md`.
Later immutable snapshots follow [the storage naming rules](report-storage.md)
without replacing the original source identity.
For example, `gpt-5.6-sol-review-ha-failover-001.md` produces
`/var/tmp/deep-review-reports/result-gpt-5.6-sol-review-ha-failover-001.md`, not
a `.md.md` suffix. Existing legacy `/tmp/result-<report-stem>.md` results remain
readable; consult the storage reference for scratch and processed-marker paths.
Match source identity before reusing a result or marker from either layout.
Return both paths and identify the result as the later status snapshot.
Pending filing/tagging actions remain explicit; neither an issue-creation count
nor the triaged marker means provenance tagging or remediation is complete.

### Research result publication

New investigation of a deep-review publishes
`/var/tmp/deep-review-reports/report-<original filename>`, beside the source when
it is already in that root. Legacy and other out-of-root sources stay in place
until completed-research archival; record their original location rather than
writing beside them. Other research uses
`/var/tmp/deep-review-reports/result-<WHOAMI>-research-<RESEARCH_SLUG>-NNN.md`. Read
[research report storage](../../research/references/report-storage.md) for
per-input reports, mixed-input aggregates, immutable later snapshots and
same-filesystem staging. Existing `/tmp/result-*` research reports remain readable.
Before starting a new investigation, reconcile the lifecycle record and required
work. Verified completed-result reuse returns its existing paths and assessment
revision without a new report; partial work resumes from valid checkpoints.
Derive `WHOAMI` from the researching coordinator's evidenced identity, not the
external discoverer. Record `Research name`; derive `RESEARCH_SLUG` with the same
ASCII name normalization as `REVIEW_SLUG`, falling back to `research` if empty.
Record `Artifact kind: research-result`, `Review contract: xpf-review-v5`, research
run ID, identity fields, requested/effective scope, timestamp, output path and
evidence location. Include repository and pinned revisions for code research;
general research without a repository records not applicable with a reason.

Include source report names/paths/hashes, origin run/finding IDs, discovering
models/authors, prior result paths and current verification evidence. Retain the
full original-claim disposition ledger (including NEG) separately from actionable
findings. Use the shared filing ledger, including an empty ledger when no findings
exist. Reconcile actual issue URLs, newly opened versus linked owners, and verified
or pending tags; copy decisive evidence inline so the result stands alone.

Draft inside the run under `/var/tmp/deep-review-work/`, never in the reports
directory or an alternate scratch root. Verify that the two configured roots
share a filesystem; a mismatch is a publication blocker, not a fallback to `/tmp`.
Before publication, re-derive the coordinator prefix and research slug and check
manifest/header agreement. A first per-source result's basename
is derived from its source filename, not the researcher's model; verify that
source-to-output mapping separately. Standard and later snapshot names use the
coordinator identity and next unused sequence as specified in the storage reference.
Publish atomically create-if-absent
(`ln -T -- <draft> <final>` on the same filesystem); an existing directory is a
collision, not a destination. Follow the research storage reference's collision
rules: an unrelated occupant at the first per-source name is a blocker. Retry a
number only for the applicable sequenced output after identity reconciliation,
updating the draft's output-path field first. Freeze the draft after linking and
verify the final.
Do not overwrite source reports, prior results, or another run's artifacts.

After completed deep-review processing, use [finished-review archival](finished-archive.md)
to move the source and completed research result into `/var/tmp/deep-review-finished/`.
Keep original bytes and identities, record verified relocations, and return actual
archive paths. Missing review/filing/publication work stays active; partial moves
remain explicit until reconciled. Finished does not mean fixed or permanently refuted.

The `report-` and `result-` prefixes and artifact kind identify derivatives even
if their model or slug contains `-review`. Exclude them from both discovery scans
and cached discovery-index entries; read them for prior-status reconciliation.
Never publish a second discovery alias or treat a research
result as fresh watcher input. Do not write a source report's `.researched-` marker
merely because research finished. Later research can investigate unresolved claims
again, preserving lineage and reconciling existing filings under the shared mutex.
Return the new result and original report paths, identifying the newer status
snapshot. Temporary reports are not durable GitHub evidence URLs.
Persist verified coverage, output hashes/paths, issue/tag state and the archive
ledger in the shared lifecycle record. Completion is scoped to required work;
triage markers, successful publication or an archived filename alone cannot
establish `DONE` for a stronger research request.

## Report schema and completion

The final header contains:

- `Review contract: xpf-review-v5`, run ID, repository identity, checkout path.
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
- `Discovery origin`: actual discovery workflow/source, discovering agent or
  non-model author, model identifier/source and derived
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

Research additionally records its per-claim/conclusion three-reviewer coverage
and dissent, separately from any requested plan review. Validated findings with
blocked filing keep their supported disposition and explicit pending action;
a plan-review blocker does not postpone filing independently validated defects.

Do not declare all bugs fixed from an empty findings list. Report the behaviors
and conditions checked and those still unknown. Implementation handoff includes
the acceptance criterion and all affected consumers. Source fixes, verified
regression guards, and delivery to an in-scope release are separate milestones.

Reports predating these fields, including earlier v3/v4 headers, remain
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
Check a different-model researcher reversing an earlier NEG, narrowing a supplied
claim, splitting it into subclaims, and grouping inherited claims with genuinely
new by-products. Origin labels must follow each claim's lineage; successful API
readback with researcher-only labels is not a successful provenance check.
For storage changes, test both report roots, legacy results/markers, unchanged
basename/model attribution, and deduplication even with an existing cached index.
Exercise publication between the two `/var/tmp` roots, exact
target file/directory/symlink collisions, complete content visibility and retained
drafts on failure. Named scratch must never become watcher input.
For research integration, include general questions with no issue or defect table,
mixed/partial review claims, a valid defect with a rejected fix, unknown and human
authors, and stale source evidence with changed guards. Check model/name strings
containing `-review`, prior research derivatives, renamed inputs and grouped
multi-report findings. Verify all consumers use the same held filing mutex and
original finding keys, without mistaking a lock file for an acquired OS lock or
assuming cross-host coordination. A research run must not overwrite discovery
credit, silently drop NEG from the input ledger, or auto-close a real defect.
Check research's default filing without an extra prompt and its explicit
report-only override, missing/disagreeing finding reviewers, severity-only dissent,
and filing a validated defect while its proposed plan is killed or blocked.
Check exact per-source naming with a different researching model, adjacency for
in-root inputs, legacy and mixed-device inputs producing results only in the new
reports root, general/aggregate reports and plan worktrees using the same roots,
unavailable/mismatched configured roots without a fallback, existing snapshots,
derivative cache entries, and partial or blocked publication without issue refiling.
Include a resumed session and a different checkout whose historical skill still
directs `/tmp` output; record the actual workflow revision separately from code
verification and resolve the mismatch before any new write.
For archival, check source/result pairing, archived-only deduplication and reserved
sequence numbers, completed unresolved findings versus missing reviews/blocked
tags, changed originals, destination collisions, interrupted staging/removal,
legacy-device inputs, mixed aggregates and re-research of an archived source.
For processing loops, check same-input repeat calls, renamed copies, triage versus
research completion, newly enabled filing, unchanged completed unresolved claims,
busy/multi-source claim ownership, orphaned reviewer tasks, partial finalization,
changed evidence invalidating one checkpoint and state reconstruction after a crash.

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
