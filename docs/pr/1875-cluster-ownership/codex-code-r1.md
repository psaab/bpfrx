**Findings**

1. [with-cluster.sh](/home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster.sh:144): direct shell builtins can break the lock-cell contract. `"$@" 9>&-` executes builtins in the wrapper shell; `with-cluster.sh "p" -- exec sleep 60` replaces the wrapper, closes fd 9, releases the flock immediately, and skips the EXIT trap, leaving stale owner metadata while the command keeps running outside the lock. Reentrant mode also uses `exec "$@"` at [line 53](/home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster.sh:53), so builtin-only commands/functions behave differently from non-reentrant mode. This is a real edge in the advertised arbitrary `<cmd> [args...]` API.

2. [with-cluster.sh](/home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster.sh:58): timeout validation accepts strings Bash later interprets as octal or overflowing signed arithmetic. `XPF_CLUSTER_LOCK_TIMEOUT=08` passes the regex, then `[[ "$TIMEOUT" -gt 0 ]]` at [line 72](/home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster.sh:72) emits an arithmetic error and effectively disables the timeout. Very large values wrap. This violates the “garbage env degrades safely” requirement.

3. [with-cluster-selftest.sh](/home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster-selftest.sh:127): case h does not test what the plan claims. It uses a hand-built `bash -c` env prefix for three `XPF_CLUSTER_*` vars, but does not exercise the actual `cluster-setup.sh` `sg incus-admin -c "${local_env}$(printf '%q ' ...)"` path, the `${!BPFRX_@}/${!XPF_@}` forwarding loop, or `XPF_CLUSTER_SKIP_BUILD`. That leaves the most important deadlock/double-build regression path untested.

4. [with-cluster-selftest.sh](/home/ps/git/bpfrx/.claude/worktrees/1875-engineer-lock/test/incus/with-cluster-selftest.sh:55): case b says it kills the whole cell tree, but `pkill -P "$B_PID"` only targets direct children. It still proves “wrapper death releases the lock” for this fixture, but not the stated whole-tree behavior.

Syntax checks passed. I could not rerun the selftest here because the sandbox is read-only and `mktemp /tmp/xpf-lock-selftest.XXXXXX` fails. `shellcheck` is installed; it only surfaced source-follow noise plus pre-existing warnings in `apply-cos-config.sh`.

VERDICT: NEEDS-CHANGES (findings 1-3)

Codex session ID: 019eb8ce-665f-72d0-a1f8-83a85063ef7a
Resume in Codex: codex resume 019eb8ce-665f-72d0-a1f8-83a85063ef7a
