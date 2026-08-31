#!/usr/bin/env bash
# Mutation-harness scoring library.
#
# Sourced by scripts/mutate.sh (the driver) and scripts/mutate-selftest.sh (the
# self-test). Every function here is pure text processing over a gate log, so
# the self-test can drive the whole verdict matrix from fixtures without a repo,
# a compiler, or a cluster.
#
# The defects this encodes, each of which has produced a WRONG VERDICT before:
#
#   1. A single-language runner scores every cross-language mutation as an
#      ESCAPE, because nothing it ran could have failed. A cell whose touched
#      files include a language no configured gate covers must be REFUSED, not
#      scored.
#   2. rc != 0 is not "the tests failed". A build break, a panic before
#      collection, and a full disk all produce rc != 0 with no failing test, and
#      a harness that keys on rc scores them as kills; one that keys on "no
#      named FAIL" scores them as escapes. Both are wrong: they are VOID.
#   3. A -race failure has NO `--- FAIL` line. It emits `WARNING: DATA RACE`
#      and a package-level FAIL, so a `^--- FAIL` counter scores a genuine race
#      red as a PASS.

# mutation_lang_of FILE -> go|rust|unknown
mutation_lang_of() {
	case "$1" in
	*.go) printf 'go\n' ;;
	*.rs) printf 'rust\n' ;;
	*) printf 'unknown\n' ;;
	esac
}

# mutation_langs_of FILE... -> sorted unique language set, one per line
mutation_langs_of() {
	local f
	for f in "$@"; do mutation_lang_of "$f"; done | sort -u
}

# mutation_can_score "LANGS" "CONFIGURED" -> 0 if every language in LANGS has a
# configured gate, 1 otherwise. Both arguments are whitespace-separated sets.
#
# This is the refusal gate. It answers "could the gates I am about to run have
# observed this mutation at all", which is a different question from "did any
# test fail".
mutation_can_score() {
	local langs="$1" configured="$2" l c found
	for l in $langs; do
		found=0
		for c in $configured; do
			[ "$l" = "$c" ] && found=1 && break
		done
		[ "$found" = 0 ] && return 1
	done
	return 0
}

# mutation_uncovered "LANGS" "CONFIGURED" -> the languages with no gate
mutation_uncovered() {
	local langs="$1" configured="$2" l c found
	for l in $langs; do
		found=0
		for c in $configured; do
			[ "$l" = "$c" ] && found=1 && break
		done
		[ "$found" = 0 ] && printf '%s\n' "$l"
	done
}

# mutation_infra_broken LOG -> 0 when the run was invalidated by the machine
# rather than by the mutation (full disk is the one that has bitten; it reds
# NAMED tests and reads as a real regression).
mutation_infra_broken() {
	grep -qiE 'no space left on device|cannot allocate memory' "$1"
}

# mutation_go_build_broken / mutation_rust_build_broken LOG
# A Go build break, WITHOUT matching `make`'s own echoed Makefile comments.
#
# `^# ` looks like the header go emits above a package's compile errors, but
# `make test-go` echoes every Makefile comment line in the recipe region, and
# those start with `#` too. Keying on that pattern scored a healthy run as
# VOID(build break) -- which does not produce a false KILLED or ESCAPED, but
# does bury the real verdict. Match a compile DIAGNOSTIC (file.go:line:col:) or
# go's explicit build-failure marker instead; neither appears in prose.
mutation_go_build_broken() {
	grep -qE '\[build failed\]|^[^[:space:]]+\.go:[0-9]+:[0-9]+: ' "$1"
}
mutation_rust_build_broken() {
	grep -qE '^error(\[E[0-9]+\])?:|^error: could not compile' "$1"
}

# mutation_go_collected LOG -> number of PACKAGES the run reported on.
# Deliberately counts package result lines only, never `--- FAIL` lines: mixing
# them makes the collection count move with the failure count, which hides a
# package that failed to build behind another package's extra failures.
mutation_go_collected() { grep -cE '^(ok|FAIL|\?)[[:space:]]' "$1"; }

# mutation_go_failed LOG -> named failing tests, INCLUDING races.
mutation_go_failed() {
	local named races
	named=$(grep -cE '^--- FAIL' "$1")
	races=$(grep -cE '^WARNING: DATA RACE' "$1")
	printf '%s\n' "$((named + races))"
}

mutation_rust_collected() { grep -cE '^test .* \.\.\. ' "$1"; }
mutation_rust_failed() { grep -cE '^test .* \.\.\. FAILED' "$1"; }

# mutation_verdict APPLIED BUILT COLLECTED FAILED INFRA -> verdict string
#
# Order matters. Each earlier condition makes the later numbers meaningless, so
# a harness that checks them in the wrong order reports a confident verdict
# derived from a number it should not have trusted.
mutation_verdict() {
	local applied="$1" built="$2" collected="$3" failed="$4" infra="$5"
	if [ "$infra" = yes ]; then printf 'VOID(infrastructure: disk or memory)\n'; return; fi
	if [ "$applied" != yes ]; then printf 'VOID(mutation not applied)\n'; return; fi
	if [ "$built" != yes ]; then printf 'VOID(build break)\n'; return; fi
	if [ "$collected" -eq 0 ]; then printf 'VOID(no tests collected)\n'; return; fi
	if [ "$failed" -gt 0 ]; then printf 'KILLED\n'; return; fi
	printf 'ESCAPED\n'
}

# mutation_score_log LANG LOG APPLIED -> "BUILT COLLECTED FAILED VERDICT"
mutation_score_log() {
	local lang="$1" log="$2" applied="$3" built collected failed infra
	infra=no
	mutation_infra_broken "$log" && infra=yes
	case "$lang" in
	go)
		built=yes; mutation_go_build_broken "$log" && built=no
		collected=$(mutation_go_collected "$log")
		failed=$(mutation_go_failed "$log")
		;;
	rust)
		built=yes; mutation_rust_build_broken "$log" && built=no
		collected=$(mutation_rust_collected "$log")
		failed=$(mutation_rust_failed "$log")
		;;
	*)
		printf 'no 0 0 REFUSED(no gate covers this language)\n'; return ;;
	esac
	printf '%s %s %s %s\n' "$built" "$collected" "$failed" \
		"$(mutation_verdict "$applied" "$built" "$collected" "$failed" "$infra")"
}
