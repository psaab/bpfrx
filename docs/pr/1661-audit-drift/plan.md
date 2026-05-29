# #1661 item 8 — Refactoring-audit drift fix + CI/check drift guard

**Status:** v2 — incorporates round-1 PLAN-NEEDS-MINOR findings (Codex
provisional + AGY verified + Claude SMR). Pending round-2 confirmation.

### Round-1 review outcome (all three: PLAN-NEEDS-MINOR)
- **Codex** (task-mprdz18l-oa4ntx, sandbox infra-blocked → provisional;
  re-verified task-mpre329g-usqidy): root cause sound; required the make
  recipe to fail on *script* failure, not just `diff` failure.
- **AGY** (review-mprdxwky-cqxgzn, verified run): confirmed script exits 1
  today; confirmed determinism is a total order; flagged (1) recipe
  silently ignores script failure → use `trap` cleanup + `&&` chaining,
  (2) `audit_rust`/`audit_go` don't truly tolerate missing dirs either —
  apply the array guard for symmetry, (3) `|| true` pipeline-precedence
  trap warning, (4) recommended wiring into `make test`.
- **Claude SMR**: independently caught the recipe `set -e` issue; resolved
  open Q4 as standalone (see Decisions).

### Decisions on round-1 findings
- **ADOPT** recipe hardening: `trap 'rm -f "$$tmp"' EXIT` + `&&` chaining +
  `|| ( ...; exit 1 )` error path so a generator failure propagates.
- **ADOPT** the array-guard for `audit_rust`/`audit_go` too (symmetry;
  removes the "happens to exist today" fragility AGY flagged).
- **NOTE** the `|| true` precedence trap in the script comment so a future
  editor doesn't "simplify" into the bug.
- **REJECT** wiring `audit-check` into `make test` (AGY rec) — keep
  standalone. Rationale: coupling drift-detection to the default test gate
  breaks every unrelated PR that legitimately adds/grows a >=1500 LOC file
  until someone regenerates the artifact. That is high-friction churn on a
  *docs* artifact and contradicts the project's low-friction discipline.
  Codex and Claude SMR both favor standalone. The guard is meant to be run
  on demand / in a dedicated lane, not to gate all Go tests.

## Issue framing

`docs/refactoring-audit-current.txt` is a committed generated artifact
(the `wc -l` heatmap of large source files, produced by
`scripts/refactoring-audit.sh`). It has drifted from the tree: it still
lists files deleted in the #1476 (eBPF source removal) and #1525/#1528
(DPDK retirement) chains — concretely `pkg/dataplane/dpdk/dpdk_cgo.go`,
`bpf/xdp/xdp_zone.c`, and `bpf/xdp/xdp_policy.c`. The generator script is
correct; only the committed output is stale. #1661 item 8 asks to:

1. Regenerate the committed artifact.
2. Add a CI/check guard so it cannot silently drift again.

This is scoped to **#1661 item 8 only**. The other seven items (large-file
domain splits) are out of scope and stay open.

## Honest scope / value framing

This is a docs + script + CI hygiene change, not a perf or dataplane
change. The value is: (a) the committed heatmap stops lying about which
files are refactor candidates (it currently points reviewers at deleted
files and hides current candidates like `shared_cos_lease/mod.rs`,
`manager.go`, `wg/engine.rs`, `queue_service/mod.rs`, `maps_sync.go`,
`tree.go`); (b) a guard prevents recurrence. There is no hot-path code
involved. If reviewers conclude the guard is over-engineered or the
churn is not worth it, PLAN-KILL is an acceptable verdict — but the
artifact is demonstrably wrong today and the issue explicitly tags this
a "good first /engineer candidate".

## Root cause (discovered during setup — wider than the issue states)

The issue frames this as "the artifact drifted; regenerate it." That is
true but incomplete. Running `scripts/refactoring-audit.sh` against
current `origin/master` produces the correct output **but exits 1**:

```
$ bash scripts/refactoring-audit.sh >/dev/null; echo $?
1
```

The script has `set -euo pipefail`. Its final stage is
`(audit_rust; audit_go; audit_bpf) | LC_ALL=C sort ...`. `audit_bpf()`
runs `find bpf/xdp bpf/tc -name '*.c' 2>/dev/null`. After #1476 deleted
the BPF C source tree, `bpf/xdp` and `bpf/tc` **do not exist**, so `find`
(here `bfs`) exits 1. The `2>/dev/null` silences the stderr message but
**not** the exit status; under `set -e` inside the subshell the failing
`find` aborts `audit_bpf` and the whole script returns 1 — *after*
having already printed correct output to stdout.

This is why the artifact drifted in the first place: whoever last tried
to regenerate it likely saw a non-zero exit (or a `set -e`-aborted
`make`/redirect) and the regeneration was skipped. A drift guard that
shells out to the script would itself fail on this exit code, not on a
content diff — a false signal. **The script must be fixed to exit 0
when the BPF source dirs are absent** before a guard can be trusted.

## Concrete design

### Part 1 — fix `audit_bpf()` to tolerate missing dirs (script bug)

Guard the `find` so a missing `bpf/xdp` / `bpf/tc` directory is a no-op,
not a `set -e` abort. Minimal, surgical change inside `audit_bpf()`:

```sh
audit_bpf() {
    # bpf/xdp and bpf/tc were deleted in #1476 (eBPF source removal).
    # The dirs may be absent; only audit the ones that still exist so
    # the script stays exit-0 (a non-zero find exit would abort the
    # whole script under `set -e` and silently skip regeneration).
    local dirs=()
    [ -d bpf/xdp ] && dirs+=(bpf/xdp)
    [ -d bpf/tc ] && dirs+=(bpf/tc)
    [ ${#dirs[@]} -eq 0 ] && return 0
    find "${dirs[@]}" -name '*.c' 2>/dev/null \
        | while read -r f; do
            loc=$(wc -l < "$f")
            if [ "$loc" -ge 1500 ]; then
                printf "%s  %5d  %s\n" "$(categorize "$loc")" "$loc" "$f"
            fi
        done
}
```

The same array-guard shape is applied to **`audit_rust` and `audit_go`
too** (round-1 AGY finding): they only pass today because `pkg`, `cmd`,
`userspace-dp/src`, `userspace-xdp/src` happen to exist — a rename or
sparse checkout would make `find` exit 1 and abort the script again.
Guarding all three call sites removes that latent fragility. The script
shebang is `#!/usr/bin/env bash`, so `local dirs=()` arrays are safe (no
POSIX-sh regression). A comment warns against "simplifying" the guard
into `find ... || true | while` — `|` binds tighter than `||`, so
`find || true | while` parses as `find || (true | while)` and the loop
never runs when `find` succeeds (round-1 AGY precedence trap).

### Part 2 — regenerate the committed artifact

```sh
bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt
```

After the Part 1 fix this exits 0. Verified output:
- Removes deleted-file refs: `dpdk_cgo.go`, `xdp_zone.c`, `xdp_policy.c`
  (3 deleted-file lines gone).
- Reflects current LOC and new candidates (e.g.
  `poll_descriptor/mod.rs` 2957, `types.go` 2055, `server_show.go` 2006,
  `shared_cos_lease/mod.rs` 1792, `manager.go` 1784, `wg/engine.rs`
  1725, `queue_service/mod.rs` 1662, `maps_sync.go` 1559, `tree.go`
  1501).

### Part 3 — drift guard (`make audit-check`)

This repo has **no GitHub Actions / CI workflow directory** (only
vendored `xdp-tools` ships its own `.github/workflows`, unrelated). The
established convention for repeatable checks here is **Makefile
targets** (`make generate`, `make proto`, `make test`). So the guard is
a Makefile target, mirroring how generated artifacts are conceptually
guarded:

```make
.PHONY: audit-check
# Drift guard for the committed refactoring heatmap (#1661 item 8).
# Regenerates to a temp file and diffs against the committed artifact;
# fails if they differ OR if the generator itself fails. Run after any
# large-file add/delete/split, then commit the regenerated artifact.
audit-check:
	@tmp=$$(mktemp); \
	trap 'rm -f "$$tmp"' EXIT; \
	bash scripts/refactoring-audit.sh > "$$tmp" && \
	diff -u docs/refactoring-audit-current.txt "$$tmp" || { \
		echo "ERROR: docs/refactoring-audit-current.txt is stale or the audit script failed."; \
		echo "Run: bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt"; \
		exit 1; \
	}; \
	echo "audit-check: refactoring-audit-current.txt is up to date"
```

Recipe design (round-1 finding — Codex + AGY + Claude SMR all flagged):
- `trap 'rm -f "$$tmp"' EXIT` guarantees temp-file cleanup on *every*
  exit path (success, diff-fail, or script-fail) — no leak even when the
  `&&` chain short-circuits.
- The generator runs with `&&` so a non-zero exit from
  `scripts/refactoring-audit.sh` (not just a `diff` mismatch) takes the
  `|| { ...; exit 1; }` failure path. Make invokes recipe shells without
  `set -e`, so a bare `;`-separated chain would let a script failure fall
  through to a spuriously-passing `diff`; the `&&` chain prevents that.

Add `audit-check` to the top `.PHONY` line. It stays **standalone** —
deliberately NOT a dependency of `test`/`all` (see Decisions above).

### Determinism

The script is already deterministic by construction:
- Output is `LC_ALL=C sort -k2,2nr -k3,3` (locale-independent, total
  order: LOC desc then path asc — no ties left to chance).
- No timestamps, no `date`, no host/path-dependent strings, no random
  ordering. Output is pure `wc -l` of a `find`-enumerated, regex-filtered
  set.
- `find` enumeration order does not matter because everything is sorted.

Proven empirically: running the script twice and diffing yields
identical output (`diff` reports no differences). The guard therefore
will not false-positive across runs.

## Hidden invariants this change must preserve

- **Script output format unchanged.** Part 1 only changes *which dirs
  are fed to `find`*; the `printf` format, thresholds (1500/2000), skip
  regex, and sort are untouched. The regenerated artifact differs from
  the committed one only because the tree changed, not because the
  format changed.
- **No new external dependency.** `mktemp`, `diff`, `bash` are already
  assumed by the repo's tooling.
- **Exit semantics.** Script now exits 0 on success (was 1). The guard
  relies on this.

## Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | LOW | docs/script/Make only; no daemon/dataplane code. `audit_bpf` change is additive-defensive. |
| Lifetime / borrow-checker | N/A | No Rust/Go code touched. |
| Performance regression | NONE | Build/runtime untouched. |
| Architectural mismatch | LOW | Guard is a plain Makefile target matching repo convention; no CI system exists to mismatch. |
| Guard false-positive | LOW | Determinism proven by double-run diff; sort is `LC_ALL=C`. |

## Test plan

- `bash scripts/refactoring-audit.sh; echo $?` → 0 (was 1).
- Run script twice → `diff` identical (determinism).
- `grep -E 'dpdk_cgo|xdp_zone|xdp_policy' docs/refactoring-audit-current.txt`
  → no matches.
- `make audit-check` → passes on the regenerated artifact.
- Deliberately corrupt the committed artifact (e.g. `echo junk >>`) →
  `make audit-check` exits non-zero (guard catches drift).
- `shellcheck scripts/refactoring-audit.sh` clean (or no new findings).
- No `go test` / `cargo` needed — no Go/Rust source touched. State this
  explicitly in review notes.

## Out of scope (explicitly)

- #1661 items 1-7 (large-file domain splits) — separate issues.
- Wiring a GitHub Actions workflow — none exists; not introducing one.
- Auto-regenerating the artifact in `make generate` (would couple a docs
  artifact to the build; a check-only guard is the lighter contract).
- Rewriting `docs/refactoring-audit.md` narrative (still accurate).

## Open questions for adversarial review (each may invite PLAN-KILL)

1. **Is fixing `audit_bpf` in scope?** The issue says "regenerate +
   guard". But the script exits 1, so a regenerate-only PR would either
   commit output captured despite a non-zero exit (fragile), or the
   guard would fail on exit code not content. Is the surgical
   `audit_bpf` fix the right call, or should the guard tolerate the
   script's non-zero exit instead? (I argue fix the script: a generator
   that exits non-zero on success is itself a latent bug and the direct
   cause of the drift.)
2. **Makefile target vs CI step:** no `.github/workflows` exists. Is a
   `make audit-check` target the correct convention, or should this PR
   *introduce* a CI workflow? (I argue: match existing convention —
   Makefile — and not invent a CI system this repo doesn't use.)
3. **Determinism normalization:** is double-run diff sufficient proof,
   or is there a hidden ordering source (filesystem `find` order across
   machines, `wc -l` on files with/without trailing newline) that could
   make the guard false-positive on a different host/checkout? Note:
   output is fully sorted, so `find` order is irrelevant; `wc -l` counts
   newlines consistently.
4. **Guard placement:** should `audit-check` be a dependency of `test`
   or `all`, or standalone? (I lean standalone — it's a hygiene check,
   not a build/test gate, and coupling it to `make test` would break CI
   on every legitimate large-file change until the artifact is
   regenerated, which is annoying but arguably the point. Defer to
   reviewers.)
5. **Should the artifact be committed at all,** or `.gitignore`d and
   generated on demand? (Keeping it committed preserves the existing
   contract — `docs/refactoring-audit.md` references it for visibility —
   and the guard is the mechanism that keeps it honest. Removing it
   would be a larger contract change.)
