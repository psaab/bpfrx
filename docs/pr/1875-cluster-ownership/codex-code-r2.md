No blocking findings.

I reviewed the requested delta `280e73a6f16c..b24f28a3fc44`. The fixes address F1-F4: `env --` closes the builtin escape, timeout parsing is base-10 and bounded, case (h) now exercises the real `cluster-setup.sh` sg/env-forwarding shape, and the case (b) comment is corrected.

Caller audit is clean: `cluster-setup.sh` deploy becoming `env -- env XPF_CLUSTER_SKIP_BUILD=1 ...` is fine, `apply-cos-config.sh` passes a script path, and selftest callers use external commands (`bash`, `sg`, `true`, `env`). I found no in-tree caller relying on bare builtins/functions.

Validation:
- `bash -n` passed for both changed scripts.
- `git diff --check 280e73a6f16c..b24f28a3fc44` passed.
- Focused probes confirmed `env -- exec true` returns `127`, nested `env -- env ...` works, and timeout normalization maps `08` to decimal `8` while huge/non-numeric values degrade to `0`.
- I could not rerun the full selftest here because this sandbox is read-only and `mktemp /tmp/...` fails.

Note: the worktree HEAD has advanced past `b24f28a3` to docs/review commits, but there are no code diffs above `b24f28a3` in the relevant files.

VERDICT: MERGE-READY

Codex session ID: 019eb8d7-6d05-75f0-82c0-b18aa6d9c635
Resume in Codex: codex resume 019eb8d7-6d05-75f0-82c0-b18aa6d9c635
