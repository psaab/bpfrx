# Per-change action logs

Write your action log for a piece of work to **`docs/log/<issue>.md`** — one
file per issue or PR — not to the repository-root `_Log.md`.

`_Log.md` is retained as the historical record up to #6874. Do not append to it.

## Why

`_Log.md` was an append-only file that every lane wrote to, so every branch
touched the same trailing region. That makes it an **O(n²) serialization
point**: merging one PR flips every other open PR to CONFLICTING, resolving one
does not help the others, and the next merge re-conflicts all of them. With N
open PRs, merging all N costs on the order of N²/2 union-resolutions.

Measured on a 30-PR board (#6874): after one merge, **19 of 30 open PRs flipped
to CONFLICTING within seconds**, with `_Log.md` the *only* conflicting path on
every branch sampled. A later session merged roughly fifteen PRs and hit the
same conflict on every single one.

Per-issue files remove the class outright: different files, no conflict, and
each change's log lands atomically with its own merge.

## Why NOT a union merge driver

`merge=union` in `.gitattributes` is the obvious one-line alternative and it is
**not safe for this file**. It resolves textually and line-based, so two entries
written in the same minute are silently fused. Measured directly:

    base:   - entry A / - entry B
    lane1:  + - **Timestamp**: 10:00 / Action: lane1 did X / File(s): a.go
    lane2:  + - **Timestamp**: 10:00 / Action: lane2 did Y / File(s): b.go

    result with merge=union:
        - **Timestamp**: 10:00
          - **Action**: lane2 did Y
          - **File(s)**: b.go
          - **Action**: lane1 did X      <- lane1's Timestamp header is GONE
          - **File(s)**: a.go

The shared `- **Timestamp**: 10:00` line aligns, so the two entries collapse
into one malformed entry with two Actions and one header. `git merge` reports
success and exits 0. Nothing downstream notices.

That is worse than the conflict it replaces: a conflict is loud and mechanical,
this is silent and lossy. The union driver is not used here, and should not be
added for this file.

## Format

Same as before — the `CLAUDE.md` logging rules are unchanged in content, only in
destination:

```markdown
- **Timestamp**: 2026-08-27
  - **Action**: what was done, briefly
  - **File(s)**: the files changed
```

One file per issue means the file is short, self-contained, and reviewable in
the same diff as the change it describes.
