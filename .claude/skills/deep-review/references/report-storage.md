# Deep-review storage and atomic publication

Final discovery reports live at
`/var/tmp/deep-review-reports/<WHOAMI>-review-<REVIEW_SLUG>-NNN.md`.
Run workspaces live at `/var/tmp/deep-review-work/review-work.<unique-id>/`;
allocate with `mktemp -d`.
Use subdirectories for worktrees, drafts, manifests, evidence, logs, build outputs,
tool caches and temporary files. Set worker/task-local `TMPDIR` and applicable
build-output overrides there. Do not reuse an occupied run directory or move
other runs' files. Existing reports stay in place during discovery/investigation;
completed research later moves the source and its result to
`/var/tmp/deep-review-finished/` through
[finished-review archival](finished-archive.md). Never relocate unrelated artifacts.

Triage, including new work on legacy inputs, uses an owned
`/var/tmp/deep-review-work/triage-work.<unique-id>/` and publishes
`/var/tmp/deep-review-reports/result-<source-report-stem>.md`. Its processed marker
belongs at `/var/tmp/deep-review-work/state/.researched-<source-report-stem>.md`;
create the state directory if absent. Existing legacy root-`/tmp` results and
markers remain readable; do not overwrite them or create new aliases. Completed
research archival is the only routine relocation of its exact source/result set.
Always reconcile original repository/run/finding keys and prior snapshots across
both layouts. A marker or duplicate copy is not a new discovery or a final verdict.

The first triage result keeps `result-<source-report-stem>.md`. When admitted
revalidation or changed filing/output requirements need a later result, publish
`result-<source-report-stem>-triage-<WHOAMI>-NNN.md` in the reports root. Preserve
the source stem and full evidenced triage coordinator prefix; reconcile sequence
numbers across active, finished and legacy roots and link prior snapshots. Reuse
an existing verified result only when it covers the requested work. An unrelated
occupant at the first-result path is a blocker, not a reason to evade collision
checks with a new name. Sequenced collisions use the next reconciled number and
an updated draft output path; never overwrite a published result.

Shared review/issue indexes belong directly under `/var/tmp/deep-review-work/`;
per-report state and locks use its `state/` and `locks/` subdirectories. Follow
the shared contract's filing-mutex path and migration gate so older workers do
not file under a different lock. Never place shared coordination files inside a
disposable run directory. All research uses these same reports/work roots,
including general questions, legacy inputs and planning. Research of a deep-review
publishes `report-<original filename>` in the reports root, beside inputs already
there; legacy sources stay in place until completed-research archival. See
[research report storage](../../research/references/report-storage.md) for its
workspace, later snapshots and multi-input handling. `/tmp` is read-only legacy
compatibility, never a new write or staging destination for any of these workflows;
archival may remove exact legacy originals after verifying their finished copies.
`report-` and `result-` derivatives are not new discovery inputs.
Use [review lifecycle and progress](review-lifecycle.md) to register verified
source finals, checkpoint research and select `PROCESS`/`RESUME`/skip outcomes.
Its per-source JSON records, not basename markers or cached title matches, track
completed work. Missing registration is recovered by scanning actual source finals.

## Atomic publication

Verify that the report directory is a real directory, not a symlink, and that
the source is this run's complete, frozen draft with the exact proposed final
path in its header. Verify that the work and report directories share a
filesystem, then publish with `ln -T -- <draft> <final>` for atomic
create-if-absent semantics. Both roots are under `/var/tmp`, but distinct mount
points can still invalidate a hard link. If they differ or publication fails,
retain the complete draft and explain the blocker; do not silently relocate
workspace files or copy into a visible, potentially partial final pathname.

An existing file, symlink or directory at the exact final name is a collision,
never an overwrite target or directory to follow into. For a discovery collision,
select the next unused number across active, finished and legacy report roots, update the
draft/manifest output path, and retry. For an existing triage result, reconcile
that result's identity and work before reusing it or publishing an admitted later
snapshot as defined above, without assigning the source a new discovery identity.
Inspect the exact target after any ambiguous failure before retrying.

Verify final bytes and header/path identity after publication. Never edit a
published report or a linked draft. Preserve the draft and evidence under the run
directory; cleanup is limited to recorded owned paths after archival or handoff.

## Regression checks

Run `python3 -B scripts/test_review_storage.py` from the repository root to check
new/legacy dedup discovery, cached-index handling and duplicate title rows.
The tests also run through `make selftest` and use in-memory fixtures; no files
under `/var/tmp` are required. Keep reusable checks in the repository, not only
in temporary workspaces. These tests do not validate watcher configuration or
live publication/filing-lock coordination.
