#!/usr/bin/env bash
# #8489: no tracked script may use `git stash` in this repository.
#
# The stash is a property of the REPOSITORY, not of a worktree. Every
# `.claude/wt-*` and `/var/tmp/*` worktree on this box shares one stack while
# several agents run concurrently, so a `push` races every other lane's `pop`
# and `drop` — and neither side gets a signal. A push that exits 0 and creates
# no entry is indistinguishable from a successful one at the call site.
#
# Three incidents have already happened: two bad pops, and one silent loss on
# the write side where the file was reverted in the working tree and the entry
# was never findable.
#
# This guards the TREE rather than the agents. Guidance in
# docs/engineering-style.md covers what a human or an agent should do; this
# stops the harness itself acquiring the hazard, because a script that stashes
# exposes every lane to it at once and without any of them typing the command.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here" || exit 2

pass=0; fail=0
ok(){ pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad(){ fail=$((fail+1)); printf '  FAIL %s\n' "$1"; }

# The subject: tracked shell/python/make sources that invoke the stash.
# `git grep` so untracked scratch files and ignored build output cannot
# contribute; counted with `wc -l` rather than piped through `head`, because a
# truncated listing and an empty one are identical at the point of reading and
# this is an ABSENCE claim.
hits=$(git grep -n -E 'git[[:space:]]+stash' -- \
        '*.sh' '*.py' 'Makefile' '*.mk' 'scripts/*' 'test/*' 2>/dev/null \
        | grep -v 'no-git-stash-selftest.sh' || true)
n=$(printf '%s' "$hits" | grep -c . || true)

if [ "$n" -eq 0 ]; then
  ok "no tracked script invokes git stash"
else
  bad "$n tracked script line(s) invoke git stash — every worktree on this box shares one stack:"
  printf '%s\n' "$hits" | sed 's/^/         /'
fi

# POSITIVE CONTROL. An absence assertion is only worth what the search is worth:
# if the pattern or the pathspec has stopped matching, the count above is zero
# for a reason that has nothing to do with the tree. A sibling command that is
# definitely present must turn up under the SAME pathspec.
ctl=$(git grep -c -E 'git[[:space:]]+diff' -- \
       '*.sh' '*.py' 'Makefile' '*.mk' 'scripts/*' 'test/*' 2>/dev/null \
       | grep -c . || true)
if [ "$ctl" -gt 0 ]; then
  ok "positive control: the same search finds 'git diff' in $ctl file(s)"
else
  bad "positive control FAILED: the search finds no 'git diff' either, so the \
zero above is about the pattern or the pathspec, not about the tree"
fi

printf '\nno-git-stash-selftest: passed=%d failed=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
