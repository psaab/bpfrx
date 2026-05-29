#!/usr/bin/env bash
# Modularity audit (#1208): list files >=1500 LOC, sorted desc with
# category tags ([REFACTOR] for >=2000, [WATCH] for 1500-1999).
#
# Covers: Go (pkg/, cmd/), Rust (userspace-dp/src/, userspace-xdp/src/),
# and BPF C programs (bpf/xdp/*.c, bpf/tc/*.c — NOT headers; header
# size is an include-time artifact, not a per-program refactor unit).
#
# BPF C files have unique verifier constraints (512-byte stack, no
# unbounded loops) so "refactor" means tail-call decomposition or
# moving helpers to shared headers, not ordinary function extraction.
# They are audited separately to make that context visible.
#
# Test files and generated code are excluded by name pattern. We
# deliberately do NOT try to strip inline `#[cfg(test)] mod tests`
# blocks — that approach is fragile (awk range patterns silently
# erase production code that follows the test block, per Gemini
# round-1 finding). The #1034 colocated-tests refactor moved most
# inline test blocks to `tests.rs` siblings anyway; remaining inline
# test blocks are rare and accepting the modest over-count is
# simpler than a brittle stripper.
#
# Run from repo root or anywhere — uses `git rev-parse` to anchor.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

# Skip:
#  - target/, vendor/ (build artifacts)
#  - generated bpf2go output (*_bpfel.go, *_bpfeb.go, also
#    *_x86_bpfel.go via the parent pattern)
#  - generated protobuf (*.pb.go, *_grpc.pb.go)
#  - generated zz_generated_*
#  - relocated/colocated tests (#1034): tests.rs, *_tests.rs, *_test.go
#  - test_support.rs (test-only helpers)
#  - plan retrospectives marked KILLED / WITHDRAWN
#  - findings docs (large evidence artifacts under docs/pr/*/)
#  - lockfiles
SKIP_RE='(^|/)(target|vendor)/'
SKIP_RE+='|/zz_generated'
SKIP_RE+='|_bpfel\.go$|_bpfeb\.go$'
SKIP_RE+='|\.pb\.go$|_grpc\.pb\.go$'
SKIP_RE+='|(^|/)tests\.rs$|_tests\.rs$|_test\.go$'
SKIP_RE+='|(^|/)test_support\.rs$'
# #1208 PR review (Codex MED-3): test_fixtures.rs and test_zone_ids.rs
# are #[cfg(test)] modules (afxdp/mod.rs:94, main.rs:14) — exclude by
# name even though they're under src/.
SKIP_RE+='|(^|/)test_fixtures\.rs$|(^|/)test_zone_ids\.rs$'
SKIP_RE+='|/_KILLED|/_WITHDRAWN'
SKIP_RE+='|docs/pr/[^/]+/findings'
SKIP_RE+='|\.lock$'

categorize() {
    local loc=$1
    if [ "$loc" -ge 2000 ]; then echo "[REFACTOR]"; else echo "[WATCH]   "; fi
}

# Echo the subset of the given paths that are existing directories, one
# per line. Used to avoid feeding a deleted root (e.g. bpf/xdp / bpf/tc
# after #1476) to `find`: under `set -euo pipefail` a `find` on a missing
# path exits non-zero and aborts the script — silencing stderr with
# `2>/dev/null` does NOT suppress the exit status. This was the #1661
# item 8 drift root cause. The audit roots are fixed literal names with
# no whitespace, so the caller can safely word-split the result.
#
# Do NOT rewrite a caller as `find ... || true | while ...`: `|` binds
# tighter than `||`, so that parses as `find || (true | while ...)` and
# the loop never runs on the success path.
audit_existing_dirs() {
    local d
    for d in "$@"; do
        [ -d "$d" ] && printf '%s\n' "$d"
    done
    # Always succeed. The loop's last `[ -d "$d" ] && printf` leaves a
    # non-zero status when the final path is absent; with `set -e` a
    # caller's `dirs=$(audit_existing_dirs ...)` assignment would inherit
    # that status and abort the script — the same class of bug this
    # helper exists to prevent.
    return 0
}

audit_rust() {
    # userspace-xdp/src: Aya/eBPF Rust programs (lib.rs is the sole entry point,
    # currently 1373 L but grows with each new protocol handler).
    #
    # Build the dir list defensively (see audit_existing_dirs): a missing
    # root would make `find` exit non-zero and abort the whole script under
    # `set -e`, which is exactly the drift bug #1661 item 8 fixed.
    local dirs
    dirs=$(audit_existing_dirs userspace-dp/src userspace-xdp/src)
    [ -z "$dirs" ] && return 0
    # shellcheck disable=SC2086 # word-split intentional: $dirs is a
    # newline/space-separated list of validated directory paths.
    find $dirs -name '*.rs' 2>/dev/null \
        | grep -vE "$SKIP_RE" \
        | while read -r f; do
            loc=$(wc -l < "$f")
            if [ "$loc" -ge 1500 ]; then
                printf "%s  %5d  %s\n" "$(categorize "$loc")" "$loc" "$f"
            fi
        done
}

audit_go() {
    local dirs
    dirs=$(audit_existing_dirs pkg cmd)
    [ -z "$dirs" ] && return 0
    # shellcheck disable=SC2086 # see audit_rust.
    find $dirs -name '*.go' 2>/dev/null \
        | grep -vE "$SKIP_RE" \
        | while read -r f; do
            loc=$(wc -l < "$f")
            if [ "$loc" -ge 1500 ]; then
                printf "%s  %5d  %s\n" "$(categorize "$loc")" "$loc" "$f"
            fi
        done
}

# BPF C programs only (not headers — shared headers are include-time artifacts,
# not per-program refactor units). bpf/tc/*.c and bpf/xdp/*.c are each
# loaded as separate BPF programs; >2000 L in one program file is a verifier
# complexity hazard on top of a modularity smell.
#
# #1476 deleted the bpf/xdp and bpf/tc source trees; only bpf/headers
# remains. audit_existing_dirs drops the absent roots so this is a no-op
# instead of a `set -e` abort (the #1661 item 8 drift root cause: the old
# `find bpf/xdp bpf/tc ... 2>/dev/null` silenced the stderr message but
# NOT the non-zero exit, which aborted the script after it had already
# printed correct output — so regeneration was skipped and the committed
# heatmap drifted).
audit_bpf() {
    local dirs
    dirs=$(audit_existing_dirs bpf/xdp bpf/tc)
    [ -z "$dirs" ] && return 0
    # shellcheck disable=SC2086 # see audit_rust.
    find $dirs -name '*.c' 2>/dev/null \
        | while read -r f; do
            loc=$(wc -l < "$f")
            if [ "$loc" -ge 1500 ]; then
                printf "%s  %5d  %s\n" "$(categorize "$loc")" "$loc" "$f"
            fi
        done
}

# LC_ALL=C + multi-key sort: descending LOC (col 2), ascending path (col 3).
# Both reviewers flagged that bare `sort -rn` yields locale-dependent
# tie-breakers — explicit multi-key + LC_ALL=C is reproducible.
(audit_rust; audit_go; audit_bpf) | LC_ALL=C sort -k2,2nr -k3,3
