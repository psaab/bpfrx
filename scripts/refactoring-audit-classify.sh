#!/usr/bin/env bash
# Thin CLI over the audit classifier (#6232), used by the enforcement
# fixtures in pkg/refactoraudit/audit_canary_test.go. It lets the Go
# canary exercise the SAME classifier the generator uses, so the two can
# never drift.
#
# Usage:
#   refactoring-audit-classify.sh classify <path>...
#       Print one line per path: "SKIP <path>" (excluded) or
#       "SOURCE <path>" (counted).
#   refactoring-audit-classify.sh audited <path>...
#       Print one line per path: "AUDITED <path>" (the generator would
#       measure it) or "NOT-AUDITED <path>". This is the classify verdict
#       AND the audited-root/extension test together — the question
#       scripts/refactoring-audit-touched.sh asks of a path out of
#       `git diff` (#7253).
#   refactoring-audit-classify.sh loc <path>
#       Print the raw production LOC the audit would attribute to <path>.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/refactoring-audit-lib.sh
. "$here/refactoring-audit-lib.sh"

cmd="${1:-}"
shift || true
case "$cmd" in
    classify)
        [ "$#" -ge 1 ] || { echo "usage: classify <path>..." >&2; exit 2; }
        for p in "$@"; do
            if audit_is_excluded "$p"; then
                printf 'SKIP %s\n' "$p"
            else
                printf 'SOURCE %s\n' "$p"
            fi
        done
        ;;
    audited)
        [ "$#" -ge 1 ] || { echo "usage: audited <path>..." >&2; exit 2; }
        for p in "$@"; do
            if audit_is_audited_path "$p"; then
                printf 'AUDITED %s\n' "$p"
            else
                printf 'NOT-AUDITED %s\n' "$p"
            fi
        done
        ;;
    loc)
        [ "$#" -eq 1 ] || { echo "usage: loc <path>" >&2; exit 2; }
        audit_loc "$1"
        ;;
    *)
        echo "usage: $(basename "$0") {classify <path>...|audited <path>...|loc <path>}" >&2
        exit 2
        ;;
esac
