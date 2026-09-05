---
name: deep-review
description: Review firewall source and validation coverage, prioritize consequential defects, and produce a private evidence-backed report. Supports full, focused, and change-based reviews with isolated worktrees.
user-invocable: true
---

# Deep review

Prioritize consequential defects in supported firewall behavior. Choose review
work using impact, reachability, change history, and uncertainty. Distinguish
inventory coverage, refuted hypotheses, and verified behavior. Preserve unresolved
high-impact questions, and give every confirmed finding an acceptance criterion
for its fix. File counts and finding counts are bookkeeping, not success targets.

Read [the shared review contract](references/review-contract.md) before discovery
or triage. It owns severity, evidence, dispositions, report fields, and completion
criteria for both this skill and `review-triage`.

## Scope and modes

- `/deep-review`: inventory the full live product and prioritize review depth
  across it. Report any inventory items or behaviors not actually inspected.
- `/deep-review --area A3 --focus "config compiler"`: constrain discovery to the
  selected area, reading dependencies needed to assess its contracts.
- `/deep-review focus on zone policies only`: honor the explicit restriction.
  A focus without a restriction changes priority within the selected scope.
- `/deep-review --since <sha>`: review changes from that commit to the pinned
  base, their relevant callers/consumers, and related fix residuals. Validate the
  commit and range; an invalid or ambiguous range is not a full-tree request.
- `--batch-size N`: maximum production files per batch (default 150), not a
  depth target. Split further by contract, complexity, and available context.

Parse arguments as data; never interpolate free-form context into shell code.
Record the effective mode, scope, focus, exclusions, and any user time/effort
limit in the report. Delta and area modes override full-tree instructions.

This is a defensive source review and report workflow. It does not authorize
exploitation, deployments, shared-cluster mutations, source fixes, issue filing,
or messages. Carry forward actual session authorization for separately requested
actions. Use existing tests and bounded local assertions with benign fixtures;
temporary test-only changes belong in owned scratch worktrees and must be
preserved as evidence before cleanup. A required live check without authorization
or prerequisites becomes a named validation task, not an improvised probe.

## 1. Pin the target and allocate the run

1. Discover the repository with `git rev-parse --show-toplevel`. Read
   `AGENTS.md`, `CLAUDE.md`, relevant engineering guidance, and the selected
   modules' current architecture/operator docs. Give each worker the particular
   documents its contracts require; a one-paragraph summary is not a substitute.
2. Record repository identity (credential-free remote identity, or a local
   identity), checkout path, and immutable base SHA. Use the requested revision
   or current HEAD. Do not pull, rebase, or alter the control checkout for review.
3. Resolve the comparison branch from the task or repository's remote default
   branch. Use a branch upstream only when it matches that intended target;
   record its repository, ref, SHA, and fetch time. Refresh remote refs when
   available without moving the base. If comparison is unavailable, record that
   limitation; never claim current-tip verification.
4. Allocate a unique scratch directory with
   `mktemp -d /tmp/review-work.XXXXXXXXXX`. Its unique basename is the run ID.
   Record owned paths in its run manifest. Do not use the future report sequence
   number to allocate shared scratch resources.
5. Record runtime-provided model identity and its source when available.
   Otherwise record `unknown`; installed binaries or another app's settings do
   not identify the active model. Preserve distinct `muse-*` and `claude-*`
   families. Use a filesystem-safe family name only for the final filename.
6. The coordinator creates each detached worker worktree from the pinned base
   under the unique run directory, following `AGENTS.md` ownership rules.
   Before work starts, the worker reports its path, SHA, and assigned scope.
   A pre-existing path is not evidence that it is stale: allocate a new owned
   path rather than forcing removal. All source evidence names its revision.

## 2. Inventory the product and select high-value work

Start from `git ls-files -z`, not a source-extension allowlist. Classify runtime
source, tests/harnesses, schemas, build inputs, package hooks, service units,
deployment scripts, and relevant configuration. Account for generated outputs
through their generators and consumers. Record exclusions with evidence.

Do not infer retirement from a directory name or historical comment. Confirm
current build inclusion, callers, and operational role. The retired eBPF/DPDK
forwarders are historical; the AF_XDP shim, retained shared headers, Go shim
loader, nftables host enforcement, and appliance lifecycle still need assessment.

Keep stable area IDs for ownership and `--area`; refresh actual paths/counts:

| Area | Source responsibility |
| --- | --- |
| A1 | Rust packet path, parser/frame/UMEM, worker/queues/CoS, sessions, policy/filter/screens, control protocol/server/event stream, WireGuard, and `userspace-xdp/` |
| A2 | Rust NAT, NAT64, NPTv6, translation and allocation lifecycle |
| A3 | Go `pkg/config/`, `pkg/cmdtree/`, `pkg/appid/`: schema, parser and compilation |
| A4 | `pkg/configstore/`, `pkg/fsatomic/`: persistence, crypto-at-rest, commit/rollback |
| A5 | `pkg/cluster/`, `pkg/vrrp/`, `pkg/ra/`, `pkg/conntrack/`: HA and synchronization |
| A6 | `pkg/dataplane/` and `pkg/dataplane/userspace/`: shim loading, snapshots, control messages and apply |
| A7 | `pkg/daemon/`, `pkg/nftables/`, `pkg/networkd/`, `pkg/devicemap/`, routing/FRR/IPsec: host enforcement and lifecycle |
| A8 | `pkg/authz/`, `pkg/grpcapi/`, `pkg/api/`, `proto/`: identity, authorization, API contracts |
| A9 | Telemetry, flow export, logging, SNMP, probes, feeds, event automation and monitoring |
| A10 | DHCP/DDNS/services, policy simulator, CLI, `cmd/`, packaging, image/upgrade/deploy/build tooling |

Assign unmapped files explicitly. Test files include Rust `tests.rs`,
`*_tests.rs`, `tests_*`, Go `*_test.go`, Python tests, and shell harnesses;
production and test code may also coexist in one file. Counts alone do not
determine classification.

Build a short ranked worklist: documented behavior/invariant, reachable
operational context, potential impact, recent change or residual, uncertainty,
existing evidence, next useful check, and owner. History informs priority but
does not prove twice-silent code is sound. Reserve review capacity for critical
under-verified behavior and for independent checks of dispositions.

Run a validation-assurance workstream alongside source review. Inspect whether
the relevant tests/harnesses are invoked, exercise production code, have valid
oracles, and can fail. Use `make harness-census` and
`test/incus/HARNESSES.unreached` for registration evidence; neither proves a live
test ran. Prioritize actual missing gates separately from intentional manual
diagnostics. Keep test/harness coverage visible rather than declaring it
low-value supporting material.

## 3. Review contracts, transitions, and specific sites

Assign a reviewer the whole behavior chain even when its files span areas:
configuration -> typed compilation -> wire representation -> runtime consumer ->
cached state and kernel effects. File-batch owners still report inspection
coverage. Contract owners can follow callers, shared types, consumers, and
lifecycle dependencies beyond a batch; name overlap so it is coordinated.

Select relevant cases from the shared contract's behavior and workload matrix.
Use documented semantics as the oracle; surface ambiguity rather than silently
changing product invariants. Compare independent implementations only alongside
an assertion of the property each independently owes.

Pattern censuses are discovery aids, with a ledger of enumerated sites,
languages/syntax covered, checks performed, exclusions, and unknowns. Useful
examples are narrowing conversions, lost config dimensions, unchecked optional
values, and incomplete error handling. Include Rust conversion/optional-value
forms when that language is in scope. A grep with no hits does not discharge a
bug class. Batch reviewers may reuse a specific verified site/invariant at the
same revision, but must not skip an entire pattern by name.

For recent-fix review, record a historical window (previous reviewed SHA,
`--since`, or an explicitly selected set of relevant fixes). Inspect each fix's
own parent-to-fix change, affected contract, sibling consumers, and regression
guard. Do not substitute `base..comparison-tip`: after a fresh checkout that
range may be empty despite many recent fixes. Reassess related dismissed claims
when their supporting assumptions or dependencies changed.

Use bounded assignments and the available concurrency; do not assume a named
agent host/tool is installed. Follow `AGENTS.md` when delegating and give each
worker the run manifest, contract, scope, relevant history, and report location.
Limit simultaneous builds to available resources. Reallocate effort when the
next useful step needs evidence a batch cannot supply. Preserve unfinished work
and its next check; do not manufacture a negative result to complete a checklist.

## 4. Independently verify and reconcile

Refresh the selected comparison ref once for merge and pin that SHA for all
decisions. Apply the shared contract to every candidate, including dependencies
that establish reachability or safety; an unchanged evidence file alone is
insufficient. Independently check high-impact material findings and a
risk-selected sample of NEG/DUP/STALE/COHORT decisions. Log the checks and gaps.

Use prior final reports, durable `docs/reviews/` records, and relevant issue/PR
history as leads. Check repository identity before deduplication. Paginate needed
history, include relevant closed issues and fixing PRs, record freshness/limits,
and search candidate-specific bodies and acceptance criteria. A title match,
a closed issue, or an old report disposition does not decide the new claim.

## 5. Publish the report and hand off fixes

Write one self-contained draft inside the run directory using the shared
contract's header, per-finding fields (including Probe), inspection log, and
counts. Clearly distinguish confirmed findings, unresolved high-impact questions,
verification gaps, and suggested implementation work. A review report is not an
issue filing: say "recommended for filing" unless actual issue IDs exist.

The compatibility output is `/tmp/<family>-review-NNN.md`. Determine the next
number from exact final basenames for that family at publication time. Publish
the complete draft with an atomic create-if-absent operation, such as a hard link
on the same filesystem (`ln -T -- <draft> <final>`), never a replacing copy. On
collision, update the draft's output-path header and retry the next number.
Freeze the draft after linking: a hard link shares its contents with the final.
The target must be the exact final file, never a directory to follow into.
Only complete, immutable finals belong directly under `/tmp/`; scratch and
evidence stay under the unique run directory.

Verify the published report is complete and the artifact references resolve.
Preserve test-only diffs, outputs, manifest, and supporting evidence until
archived or handed off; include the decisive evidence inline so the report does
not depend on a worker checkout. Cleanup only recorded owned worktrees, using
normal `git worktree remove` after preserving evidence. If removal would require
force, retain the path and explain why. Never sweep other runs by glob.

For each actionable finding, provide the expected behavior, fix direction,
regression acceptance criterion, affected consumers, and remaining validation.
Release-oriented runs also track whether a verified source fix has reached the
in-scope release. Further implementation/publication follows the authorized
engineering workflow.

## Maintaining this skill

When revising discovery or triage, use the shared contract's decision walkthrough.
Use its held-out evaluation before claiming improved defect recall. Formatting
validation alone does not establish that improvement. Report which behavioral
checks ran and which claims remain unmeasured.
