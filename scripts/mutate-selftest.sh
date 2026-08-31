#!/usr/bin/env bash
# Self-test for the mutation-harness scoring library (scripts/mutate-lib.sh).
#
# Hermetic: fixture logs only. No repo, no compiler, no cluster.
#
# The cell that matters most is the REFUSAL one. A single-language runner scores
# every cross-language mutation as an ESCAPE, because nothing it ran could have
# failed -- and an escape is a claim that the code is untested. The library must
# say "cannot score", never a verdict, for a mutation outside its gates.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/mutate-lib.sh"

fails=0
W="$(mktemp -d "${TMPDIR:-/var/tmp}/xpf-mutate-selftest.XXXXXX")"
trap 'rm -rf "$W"' EXIT

ck() { # ck <desc> <want> <got>
	if [ "$2" = "$3" ]; then
		printf '  ok   %s\n' "$1"
	else
		printf '  FAIL %s\n       want: %s\n       got:  %s\n' "$1" "$2" "$3"
		fails=$((fails + 1))
	fi
}

echo "== language detection =="
ck "go file"      "go"      "$(mutation_lang_of pkg/natshow/source.go)"
ck "rust file"    "rust"    "$(mutation_lang_of userspace-dp/src/session/mod.rs)"
ck "unknown file" "unknown" "$(mutation_lang_of bpf/headers/maps.h)"

echo "== refusal gate (the property this harness exists for) =="
mutation_can_score "go" "go rust" && r=0 || r=1
ck "go cell with both gates configured is scorable" "0" "$r"
mutation_can_score "rust" "go" && r=0 || r=1
ck "RUST cell with only the GO gate configured is NOT scorable" "1" "$r"
ck "uncovered language is named" "rust" "$(mutation_uncovered "rust" "go")"
mutation_can_score "unknown" "go rust" && r=0 || r=1
ck "unknown-language cell is not scorable" "1" "$r"

# The end-to-end refusal: a .rs cell scored by a go-only harness must not
# produce a verdict at all. Before this, it produced ESCAPED.
out="$(mutation_score_log unknown /dev/null yes)"
ck "unscorable cell yields REFUSED, not a verdict" \
	"no 0 0 REFUSED(no gate covers this language)" "$out"

echo "== go scoring =="
cat > "$W/kill.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
--- FAIL: TestSomething (0.01s)
FAIL	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "a named FAIL is a kill" "yes 2 1 KILLED" "$(mutation_score_log go "$W/kill.log" yes)"

cat > "$W/escape.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
ok  	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "no failure with real collection is an escape" "yes 2 0 ESCAPED" \
	"$(mutation_score_log go "$W/escape.log" yes)"

# A build break has rc != 0 and NO named failing test. Keying on rc scores it a
# kill; keying on "no --- FAIL" scores it an escape. It is neither.
cat > "$W/build.log" <<'EOF'
# github.com/psaab/xpf/pkg/natshow
pkg/natshow/source.go:180:5: undefined: armed
FAIL	github.com/psaab/xpf/pkg/natshow [build failed]
EOF
ck "a build break is VOID, not a kill and not an escape" \
	"no 1 0 VOID(build break)" "$(mutation_score_log go "$W/build.log" yes)"

# `make test-go` echoes every Makefile comment in the recipe region, and those
# start with `#`. Keying the build-break detector on `^# ` scored a completely
# healthy run as VOID(build break): not a false kill or escape, but it buries
# the real verdict, which is the same loss. Found by running the harness for
# real, not by reading it.
cat > "$W/make-comments.log" <<'EOF'
# go vet gate scoped to pkg/flowexport (#2224): catches the
# atomic.Uint64-copy regression class (ExportConfig embeds the live
# 1-in-N sampleCounter and must never be copied by value). NOT
# tree-wide yet -- two pre-existing vet diagnostics live outside it.
ok  	github.com/psaab/xpf/pkg/cli	6.409s
ok  	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "make's echoed Makefile comments are NOT a build break" \
	"yes 2 0 ESCAPED" "$(mutation_score_log go "$W/make-comments.log" yes)"

# The complement: a real diagnostic must still register even when the run also
# carries prose, which every `make test-go` log does.
cat > "$W/make-and-break.log" <<'EOF'
# go vet gate scoped to pkg/flowexport (#2224): catches the
pkg/natshow/source.go:180:5: undefined: armed
FAIL	github.com/psaab/xpf/pkg/natshow [build failed]
EOF
ck "a real diagnostic still reads as a build break amid Makefile prose" \
	"no 1 0 VOID(build break)" "$(mutation_score_log go "$W/make-and-break.log" yes)"

# A -race failure emits no `--- FAIL` line at all.
cat > "$W/race.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
WARNING: DATA RACE
Write at 0x00c000180018 by goroutine 12:
FAIL	github.com/psaab/xpf/pkg/cluster	3.1s
EOF
ck "a DATA RACE with no --- FAIL line still scores as a kill" \
	"yes 2 1 KILLED" "$(mutation_score_log go "$W/race.log" yes)"

: > "$W/empty.log"
ck "a run that collected nothing is VOID, not an escape" \
	"yes 0 0 VOID(no tests collected)" "$(mutation_score_log go "$W/empty.log" yes)"

# Collection must not move with the failure count: a package that failed to
# BUILD is hidden if `collected` counts `--- FAIL` lines, because another
# package's extra failures keep the number above zero.
cat > "$W/mixed.log" <<'EOF'
ok  	github.com/psaab/xpf/pkg/cli	6.409s
--- FAIL: TestA (0.01s)
--- FAIL: TestB (0.01s)
FAIL	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "collection counts PACKAGES, not failure lines" "2" \
	"$(mutation_go_collected "$W/mixed.log")"

echo "== infrastructure invalidation =="
cat > "$W/disk.log" <<'EOF'
--- FAIL: TestSomething (0.01s)
    write /tmp/go-build123/b001/x.o: no space left on device
FAIL	github.com/psaab/xpf/pkg/natshow	0.02s
EOF
ck "a full disk is VOID even though it reds a NAMED test" \
	"yes 1 1 VOID(infrastructure: disk or memory)" \
	"$(mutation_score_log go "$W/disk.log" yes)"

echo "== not-applied =="
ck "a mutation that did not apply is VOID, whatever the log says" \
	"yes 2 0 VOID(mutation not applied)" \
	"$(mutation_score_log go "$W/escape.log" no)"

echo "== rust scoring =="
cat > "$W/rust-kill.log" <<'EOF'
test session::tests::reaps_on_time_wait ... FAILED
test session::tests::reaps_on_closing ... ok
EOF
ck "rust named failure is a kill" "yes 2 1 KILLED" \
	"$(mutation_score_log rust "$W/rust-kill.log" yes)"

cat > "$W/rust-build.log" <<'EOF'
error[E0308]: mismatched types
error: could not compile `userspace-dp` (lib test) due to 1 previous error
EOF
ck "rust build break is VOID" "no 0 0 VOID(build break)" \
	"$(mutation_score_log rust "$W/rust-build.log" yes)"

echo
if [ "$fails" -eq 0 ]; then
	echo "mutate-selftest: all checks passed"
else
	echo "mutate-selftest: $fails check(s) FAILED"
	exit 1
fi
