---
name: engineer
description: Alias for /triple-review — drive a refactor through the full quad-review methodology (Codex + Antigravity + Claude SMR + Copilot) with plan-review, smoke, and 4-of-4 merge gate.
user_invocable: true
---

# /engineer — alias for /triple-review

`/engineer <issue-number> <one-line scope>` is identical to
`/triple-review <issue-number> <one-line scope>`. Both invocations
run the same quad-review methodology codified in
`.claude/skills/triple-review/SKILL.md`.

When invoked, immediately invoke the `triple-review` skill via
the Skill tool, forwarding the arguments verbatim:

```
Skill({skill: "triple-review", args: "<verbatim args>"})
```

Do not duplicate the methodology here. The single source of
truth is `.claude/skills/triple-review/SKILL.md` — any change
to the methodology (e.g. the Claude SMR gates at Step 3.5 /
Step 8.5, the marker-post protocol, the smoke-runner handoff)
applies to `/engineer` automatically because this skill is a
thin forwarder.
