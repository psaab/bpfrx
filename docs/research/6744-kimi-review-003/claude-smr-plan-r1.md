# Claude SMR hostile plan review - round 1

Target commit: `78891c3242a80b719bebdddc702087c07543e05b`

## Provenance limitation

The Claude Code CLI was invoked against the immutable review worktree but
failed before analysis with `You've hit your monthly spend limit`. No Anthropic
model verdict was produced. To avoid inventing one, this round records the
output of an independent Codex subagent explicitly instructed to apply the
Claude-SMR hostile-review method. This is an **SMR-method fallback**, not an
Anthropic-model verdict. The infrastructure failure and fallback agent ID are
recorded in `reviewer-ids.md`.

## Verbatim fallback verdict

`PLAN-NEEDS-MAJOR`

## Major findings

1. **Persisted-AST handling contradicts the boot contract.** A malformed
   decoded tree is an `ErrConfigDBUnreadable` condition and daemon startup is
   refused. It does not enter compile-failed bootstrap/lifeline mode. The
   structural validator must cover a non-nil root tree, non-nil descendant
   nodes, and non-empty `Keys` slices without confusing a quoted empty key with
   structural corruption.
2. **Empty security identities still widen on the lenient path.** Merely warning
   and relying on Rust is insufficient because `sortDedupZones` drops the empty
   element before snapshot construction and an empty set means wildcard. The
   same AST finding must poison the affected typed policy through
   `LenientContentDropped` (or otherwise reject the whole snapshot) before the
   empty token disappears.
3. **DDNS cleanup authority is lossy after multiple transitions.** One previous
   updater cannot serve an owned record left at A after A -> B -> C. Require a
   fingerprint-keyed in-memory authority catalog with explicit retention,
   restart, credential-lifetime, retry, and garbage-collection rules.
4. **LoadOverride destructive verbs are unresolved.** Define the full-replace
   flat grammar and ordering mechanically; do not delegate `delete`,
   `deactivate`, and `activate` semantics to the implementor.
5. **RG validation has no exact ownership/quarantine model.** A 16-entry Go
   constant already exists, and userspace inventory seeds every configured RG.
   Choose a global 0..15 product limit or define complete reachability. Specify
   strict, lenient, runtime, Go, BPF, and Rust ownership.
6. **Lifecycle action compatibility is incomplete.** REST JSON and protobuf
   currently expose required scalar strings, while the same action feeds SSE,
   gRPC, CLI, filters, and trace. Choose one cross-surface representation and
   test all consumers.
7. **Route-map compatibility wrappers turn an exact guard into an estimate.**
   Use one exact context-aware API at every strict gate and render belt. Do not
   leave safety callers on conservative wrappers that can false-reject or
   under-count.

## Minor findings

1. Mandate the existing address-book union-by-name, first-seen ordering instead
   of leaving duplicate semantics conditional.
2. VIP tests should prove helper atomicity and that no direct map accesses
   remain, not preserve the old check/write seam.
3. Add hostile tests for persisted null children, DDNS A -> B -> C, flat
   override verb ordering, lifecycle gRPC/CLI/filter behavior, and route-map
   false-positive controls.

## Disposition audit

The fallback reviewer agreed that K003-01/03/04/06/07/08/09/11/13/14/15/16 are
live, K003-10 is partial, K003-02 and K003-05 are duplicates, K003-12 is
refuted, and the unpreserved cohort is unactionable. The blockers are plan
design defects, not claim-triage disagreements.
