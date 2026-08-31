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

gate_go() { (cd "$REPO" && make test-go) 2>&1; }
gate_rust() { (cd "$REPO" && make test-rust) 2>&1; }

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
	case "$lang" in
	go) gate_go > "$log" ;;
	rust) gate_rust > "$log" ;;
	esac

	read -r built collected failed verdict < <(mutation_score_log "$lang" "$log" "$applied")
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$label" "$file" "$lang" "$applied" "$built" "$collected" "$failed" "$verdict" >> "$OUT"
	echo "[$label] $verdict (collected=$collected failed=$failed log=$log)"

	cp "$orig" "$REPO/$file"
done < "$SPEC"

echo "=== $OUT ==="
column -t -s$'\t' "$OUT"
escaped=$(awk -F'\t' 'NR>1 && $8=="ESCAPED"' "$OUT" | wc -l)
void=$(awk -F'\t' 'NR>1 && $8 ~ /^VOID|^REFUSED/' "$OUT" | wc -l)
echo "escaped=$escaped void_or_refused=$void"
