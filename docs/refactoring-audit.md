# Refactoring Audit

Tracking the modularity-discipline rule from `docs/engineering-style.md`:

- **Files >= 2000 LOC are refactor candidates.**
- Files 1500-1999 LOC are **watch-list** — flag in code review when adding to them.

## How it's measured

`scripts/refactoring-audit.sh` produces a deterministic, sorted list of
`[REFACTOR]` and `[WATCH]` entries. Output is committed to
`docs/refactoring-audit-current.txt` and regenerated periodically (and at
PR time when adding to a flagged file).

LOC is total file LOC for non-test, non-generated files. The script covers
three language families:

- **Go** — `pkg/`, `cmd/`
- **Rust** — `userspace-dp/src/`, `userspace-xdp/src/`
- **BPF C programs** — `bpf/xdp/*.c`, `bpf/tc/*.c` (not headers;
  shared header size is an include-time artifact, not a per-program
  refactor unit). These roots were deleted in #1476 and are currently
  absent; the script tolerates that (a no-op) and will pick them up
  again if the directories ever return.

Test files (`tests.rs`, `*_tests.rs`, `*_test.go`) and generated code
(`*.pb.go`, `*_grpc.pb.go`, `*_bpfel.go`, `*_bpfeb.go`, `zz_generated_*`)
are excluded by name pattern.

BPF C programs appear in the output with the same `[REFACTOR]`/`[WATCH]`
tags, but the refactoring mechanic is different: verifier constraints
(512-byte stack, no unbounded loops) mean splitting means tail-call
decomposition or moving helpers to shared headers, not ordinary function
extraction. `>2000 L` in a single BPF program file is also a verifier
complexity hazard independent of the modularity concern.

This audit deliberately does NOT strip inline `#[cfg(test)] mod tests`
blocks. Earlier `awk` approaches were fragile (the `EOF` keyword bug
silently erased production code following an inline test block, per
Gemini round-1 review of #1208's plan). The #1034 colocated-tests
refactor moved most inline test blocks to `tests.rs` siblings anyway;
remaining inline cases are rare and the modest over-count is
acceptable at the 1500-2000 thresholds.

## Regeneration

```bash
cd $(git rev-parse --show-toplevel)
bash scripts/refactoring-audit.sh > docs/refactoring-audit-current.txt
```

The script sorts deterministically with `LC_ALL=C sort -k2,2nr -k3,3`
(descending LOC, ascending path), emits no timestamps, and tolerates
absent source roots (e.g. `bpf/xdp`/`bpf/tc` after #1476), so repeated
runs produce byte-identical output.

## Drift guard

`make audit-check` (#1661 item 8) regenerates the heatmap to a temp
file and `diff`s it against the committed
`docs/refactoring-audit-current.txt`, failing if they differ or if the
generator itself errors. Run it after any change that adds, deletes, or
resizes a `>=1500` LOC source file, then commit the regenerated artifact
so the two stay in sync. The target is standalone (not wired into `make
test`/`all`) so an unrelated PR is not blocked until the artifact is
refreshed; run it explicitly or in a dedicated CI lane.

## When to refactor a candidate

- A change adds >100 LOC to a `[REFACTOR]`-tier file: split before landing.
- A change pushes a `[WATCH]`-tier file past 2000 LOC: same.
- The file's responsibilities can be cleanly separated into multiple
  cohesive modules: refactor opportunistically.

## When NOT to refactor

- The file is high-touch and the split would create review friction
  that exceeds the modularity gain.
- The file is provably going to be replaced (e.g., a temporary shim
  awaiting a different architecture).
- LOC is dominated by one cohesive function/struct that genuinely
  belongs in one place (e.g., a large schema definition).

In those cases, document the decision in a comment at the top of the
file or in a `docs/pr/` plan and stop arguing about it.

## Historical context

This file replaces an older `refactoring-audit.md` (generated
2026-04-03) that listed individual files with bespoke remediation
notes. That format went stale within weeks of every refactor. The
generated heatmap captures current state automatically.

The 18-PR refactor stream that landed in early 2026 (closing #985,
#988, #986, #1034, #1035, #957) drove most of the userspace-dp Rust
production tree below the 2000 threshold. Since then the tree has moved
on: the legacy `bpf/xdp/*.c` and `bpf/tc/*.c` programs were deleted in
#1476, and `pkg/dataplane/dpdk/dpdk_cgo.go` was deleted with the rest of
the DPDK dataplane in #1525/#1528 — so the old narrative's per-file
candidate lists are no longer current. **Do not read specific file names
out of this section; it is historical.** The committed heatmap is the
single source of truth for which files are `[REFACTOR]`/`[WATCH]` tier.

See `docs/refactoring-audit-current.txt` for the current heatmap, and
run `make audit-check` to confirm it is in sync with the tree.
