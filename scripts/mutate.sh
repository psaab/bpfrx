#!/usr/bin/env bash
# Mutation-testing driver.
#
# Usage: REPO=<worktree> scripts/mutate.sh <spec.tsv> [out.tsv]
#
# Spec is TAB-separated: label <TAB> file <TAB> old <TAB> new
# `old` and `new` use \t and \n escapes (the fields cannot contain literal tabs
# or newlines, and Go source is tab-indented, so escaping is mandatory).
#
# Every cell restores the file afterwards. Commit before running: a harness that
# rewrites files WILL eat uncommitted work.
#
# Scoring lives in mutate-lib.sh so it can be self-tested without a repo; see
# `make test-mutate-lib`.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/mutate-lib.sh
. "$here/mutate-lib.sh"

REPO="${REPO:?set REPO to the worktree to mutate}"
SPEC="${1:?usage: mutate.sh <spec.tsv> [out.tsv]}"
OUT="${2:-$REPO/.mutation-results.tsv}"
WORK="${MUTATE_WORKDIR:-/var/tmp/xpf-mutate-$$}"
# Scratch goes on real disk: /tmp is a 32G tmpfs here and a full one fails the
# build, which a harness keying on FAIL-count scores as an escape.
mkdir -p "$WORK"

# The gates this harness can run. A cell touching a language absent from this
# list is REFUSED rather than scored -- the property the whole design exists for.
CONFIGURED_GATES="${MUTATE_GATES:-go rust}"

# Per-cell wall-clock budget. A HANG is the one void shape that leaves no trace
# in the log AND consumes the budget of every LATER cell -- one contract change
# can be recorded as a screen full of escapes nobody earned (#7611). Bounding
# each cell converts that into a single reportable VOID.
#
# `timeout` rather than trusting go's own -timeout: go's fires per PACKAGE and
# prints the goroutine dump that names the stuck test (which is why the log-side
# detector exists and is the better signal), but nothing bounds a `make` recipe
# that blocks before go starts, and `cargo test` has no default timeout at all.
# This is the outer bound; go's is the informative one.
#
# --kill-after because a process ignoring SIGTERM would otherwise still hang.
MUTATE_CELL_TIMEOUT="${MUTATE_CELL_TIMEOUT:-2400}"

gate_go() { (cd "$REPO" && timeout --kill-after=30s "$MUTATE_CELL_TIMEOUT" make test-go) 2>&1; }
gate_rust() { (cd "$REPO" && timeout --kill-after=30s "$MUTATE_CELL_TIMEOUT" make test-rust) 2>&1; }

printf 'cell\tfile\tlang\tapplied\tbuilt\tcollected\tfailed\tverdict\n' > "$OUT"

while IFS=$'\t' read -r label file old new; do
	[ -z "${label:-}" ] && continue
	case "$label" in \#*) continue ;; esac

	langs=$(mutation_langs_of "$file" | tr '\n' ' ')
	if ! mutation_can_score "$langs" "$CONFIGURED_GATES"; then
		un=$(mutation_uncovered "$langs" "$CONFIGURED_GATES" | tr '\n' ',' | sed 's/,$//')
		printf '%s\t%s\t%s\tNA\tNA\tNA\tNA\tREFUSED(no gate covers: %s)\n' \
			"$label" "$file" "${langs% }" "$un" >> "$OUT"
		echo "[$label] REFUSED - no configured gate covers: $un"
		continue
	fi
	lang="${langs% }"

	orig="$WORK/$(echo "$label" | tr -c 'A-Za-z0-9_.-' '_').orig"
	cp "$REPO/$file" "$orig"

	if ! OLD="$old" NEW="$new" python3 - "$REPO/$file" <<'PY'
import os, sys
p = sys.argv[1]
s = open(p).read()
o = os.environ['OLD'].encode().decode('unicode_escape')
n = os.environ['NEW'].encode().decode('unicode_escape')
if o not in s:
    sys.exit(3)
open(p, 'w').write(s.replace(o, n, 1))
PY
	then
		cp "$orig" "$REPO/$file"
		printf '%s\t%s\t%s\tno\tNA\tNA\tNA\tVOID(mutation text not found)\n' \
			"$label" "$file" "$lang" >> "$OUT"
		echo "[$label] VOID - mutation text not found in $file"
		continue
	fi

	# APPLIED: the edit must be in the tree. A mutation that silently failed to
	# apply looks exactly like a green revert, and green is the answer the
	# measurement wanted.
	applied=yes
	git -C "$REPO" diff --quiet -- "$file" && applied=no

	log="$WORK/cell-$label.log"
	# TIMED OUT: `timeout` exits 124 when it fired. That is the ONLY evidence an
	# externally killed run leaves -- the log just stops -- so it has to be read
	# here and passed to the scorer, which cannot see it.
	ext_timedout=no
	case "$lang" in
	go) gate_go > "$log" ;;
	rust) gate_rust > "$log" ;;
	esac
	# 124 is `timeout`'s "I fired". Read plainly rather than folded into the
	# invocation with `||`: this line decides whether a whole cell is scoreable,
	# and a clever one-liner is the wrong place to be subtly wrong.
	[ $? -eq 124 ] && ext_timedout=yes

	read -r built collected failed verdict < <(mutation_score_log "$lang" "$log" "$applied" "$ext_timedout")
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$label" "$file" "$lang" "$applied" "$built" "$collected" "$failed" "$verdict" >> "$OUT"
	echo "[$label] $verdict (collected=$collected failed=$failed log=$log)"
	# #8213 attribution: this driver gates through `make`, which cannot emit
	# `go test -json`, so its KILLED verdicts are COUNT-based — they say
	# something failed, not that YOUR cell's test failed. If another test in the
	# package was already red, a cell that changed nothing scores KILLED with rc
	# and count in agreement and nothing looking wrong.
	#
	# Said at the point of use rather than in a comment, because the reader who
	# needs it is the one reading this line.
	#
	# DO NOT CLOSE THIS BY MAKING THIS DRIVER EMIT `go test -json`. That is the
	# obvious repair and it is the wrong one: it would NARROW THE GATE. Gating
	# through `make` is why the cell carries `go vet`, the targeted `-race`
	# runs with `-count=2`, and on the Rust side `--release` and
	# `--test-threads=1`. A bare per-package `go test -json` driver buys better
	# attribution and pays for it in coverage — and a narrower gate that agrees
	# with the old one is indistinguishable from a sufficient one until the day
	# it is not.
	#
	# The fix, if one is wanted, is to make the GATE TARGETS emit
	# machine-readable results alongside their normal output, so attribution
	# costs no coverage (#8231). mutation_go_failed_names_json and
	# mutation_verdict_for_target are for a caller that already has such a
	# stream — not an invitation to bypass `make` to produce one.
	if [ "$verdict" = KILLED ]; then
		echo "         ^ count-based: confirm the failing test is the one this cell targets"
	fi

	cp "$orig" "$REPO/$file"
done < "$SPEC"

echo "=== $OUT ==="
column -t -s$'\t' "$OUT"
escaped=$(awk -F'\t' 'NR>1 && $8=="ESCAPED"' "$OUT" | wc -l)
void=$(awk -F'\t' 'NR>1 && $8 ~ /^VOID|^REFUSED/' "$OUT" | wc -l)
echo "escaped=$escaped void_or_refused=$void"
