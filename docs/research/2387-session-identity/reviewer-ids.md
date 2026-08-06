# #2387 v6 plan-review reviewer ledger

3-way hostile plan review (Codex + AGY + Claude SMR). Copilot is NOT a research
reviewer (it joins the quad at `/engineer` on the code PR).

This is the **v6** review pass. It reviews the previously-unreviewed "v5 §0"
addendum on `docs/research/2387-vrf-flow-identity/plan.md`, which retracted the
HA-wire cost objection that drove the v4 PLAN-DEFER.

| Round | Reviewer | Location | Verdict |
|---|---|---|---|
| r1 | Claude SMR | `claude-smr-plan-r1.md` | PLAN-NEEDS-REVISION |
| r1 | AGY | `agy-plan-r1.md` | PLAN-NEEDS-REVISION |
| r1 | Codex | `codex-plan-r1.md` | (pending) |

## Companion invocation note (cost me three failed launches)

Both CLIs silently produce EMPTY output when launched wrongly, exit code 0 —
indistinguishable from a real run until you check the byte count.

- `codex exec "<prompt>" < /dev/null` prints the banner and exits with **no
  review**. The working form pipes the prompt on stdin: `cat p.md | codex exec
  --skip-git-repo-check -C <dir> -`.
- `agy -y --cwd <dir>` is **not valid** (`-y`/`--cwd` do not exist); the working
  form is `agy --dangerously-skip-permissions --print-timeout <N>m -p "<prompt>"`
  run from inside the target directory.
- Backgrounding either with `nohup ... &` inside a shell that returns kills the
  child. Use the harness's own background mechanism.

Always smoke `2+2` before trusting an empty result, and always check
`wc -c` on the output file.
