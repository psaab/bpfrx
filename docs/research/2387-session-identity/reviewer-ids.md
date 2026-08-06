# #2387 v6 plan-review reviewer ledger

3-way hostile plan review (Codex + AGY + Claude SMR). Copilot is NOT a research
reviewer (it joins the quad at `/engineer` on the code PR).

This **v6** pass reviews the previously-unreviewed "v5 §0" addendum on
`docs/research/2387-vrf-flow-identity/plan.md`, which retracted the HA-wire cost
objection that drove the v4 PLAN-DEFER.

| Round | Reviewer | Location | Verdict |
|---|---|---|---|
| r1 | Claude SMR | `claude-smr-plan-r1.md` | PLAN-NEEDS-REVISION |
| r1 | AGY | `agy-plan-r1.md` | PLAN-NEEDS-REVISION |
| r2 | Claude SMR | `claude-smr-plan-r2.md` | PLAN-NEEDS-REVISION |
| r2 | AGY | `agy-plan-r2.md` | PLAN-NEEDS-REVISION |
| r3 | Claude SMR | `claude-smr-plan-r3.md` | PLAN-NEEDS-REVISION |
| r3 | AGY | `agy-plan-r3.md` | **PLAN-KILL** |
| r4 | Claude SMR | `claude-smr-plan-r4.md` | PLAN-NEEDS-REVISION |
| r4 | AGY | `agy-plan-r4.md` | **PLAN-READY** (reversing its own r3 PLAN-KILL) |
| r5 | Claude SMR | `claude-smr-plan-r5.md` | **PLAN-READY** |
| r5 | Codex | `codex-plan-r1.md` | **PLAN-NEEDS-MAJOR-REVISION** (landed late, after the other two converged) |

## Shape of the review — worth recording

Every round after r1 found its defect **in the fix, not in the diagnosis**. The
original analysis (reachability, wire additivity, discriminator symmetry) survived
five revisions unchanged and was independently confirmed by both reviewers. What
kept breaking was each successive remedy:

- v6-r2's Path D → refuted by AGY (live-session domain ids move on an unrelated commit)
- v6-r3's allocate-once interner → refuted by AGY (the tree already has a
  collision-gated pure-function id; the whole apparatus was unnecessary)
- v6-r3's version gate → refuted by SMR **and** AGY independently (steady-state
  predicate, unhandled off→on transition)
- v6-r4's FLUSH-vs-MARK reasoning → SMR argued MARK, AGY rebutted, SMR conceded

Both reviewers reversed a position under argument: AGY from PLAN-KILL to PLAN-READY
once its own finding removed the cost it had priced, and Claude SMR conceded both of
its r4 findings. That two-way movement is the signal the review was adversarial
rather than performative.

## Codex — delivered late, and overturned the convergence

Codex was **not infra-blocked** — it ran and produced output — but it was
**pathologically slow** on this plan. Run 1 was given the full 7-question brief
against v6-r1; it read ~900 KB of source over roughly an hour without reaching a
verdict, by which point the plan was three revisions ahead of the text it was
reviewing. It was terminated and its partial output preserved
(`/tmp/codex-r1-abandoned-stale.out`) rather than folded, since findings against
superseded text are not usable. Run 2 was given a deliberately narrow six-claim
brief against v6-r3, per the project's convention of narrowing the brief for a
repeatedly stalling reviewer.

Per the skill's Codex exception, the research proceeded 2-of-3 (Claude SMR + AGY)
with the retries documented here. Codex's verdict is recorded in
`codex-plan-r1.md` if it lands.

## Companion invocation note — cost me three failed launches

Both CLIs silently produce EMPTY output when launched wrongly, **exit code 0** —
indistinguishable from a real run until you check the byte count.

- `codex exec "<prompt>" < /dev/null` prints the banner and exits with **no review**.
  Working form pipes the prompt on stdin:
  `cat p.md | codex exec --skip-git-repo-check -C <dir> -`
- `agy -y --cwd <dir>` is **not valid** (`-y`/`--cwd` do not exist). Working form:
  `agy --dangerously-skip-permissions --print-timeout <N>m -p "<prompt>"` run from
  inside the target directory.
- Backgrounding either with `nohup ... &` from a shell that returns **kills the
  child**. Use the harness's own background mechanism.

Always smoke `2+2` before trusting an empty result, and always check `wc -c`.

## Post-hoc correction — the 2-of-3 convergence was WRONG

Codex delivered **after** Claude SMR r5 and AGY r4 had both reached PLAN-READY, and it
**overturned that convergence**. This is the single most important entry in this ledger.

Codex found three architecture-level defects both other reviewers missed:

1. **§7a's native-ingress row derived the domain from the RAW PHYSICAL ifindex**, while
   `ifindex_to_routing_instance` is keyed by the **LOGICAL UNIT** ifindex. On a VLAN
   trunk — *this issue's own headline scenario* — both units would have derived the same
   domain, so the widened key would not have discriminated them. **The fix as specified
   would not have fixed the bug**, and would still have passed a test written with two
   physical ports.
2. **`MinCompatHAProtocolVersion` is not vestigial.** My grep was scoped to `pkg/` and
   matched only Go symbol references; the constant is exported as text by `cmd/xpfd` and
   parsed/enforced by `GateMixedBaseSwap`. The real rolling-upgrade blocker is
   `SessionSyncWireVersion = uint16(CurrentHAProtocolVersion)` compared **exact-match**
   by that gate — which no one else spotted.
3. **The version gate has concrete races** (heartbeat vs session-sync start ordering,
   BulkEnd timing, `StopHeartbeat` retaining a stale version, single-node election
   clearing it during takeover).

**Lesson for this project's review discipline:** two reviewers converging is not the
same as a claim being verified, and a *late* reviewer is not a redundant one. Both of the
converged reviewers accepted §7a's ifindex row and the "vestigial constant" claim without
independently checking either — AGY explicitly marked §7a "VERIFIED" in r3. The defect
in (2) traces to a **mis-scoped grep of mine** (`pkg/` only, symbol-only) that both
reviewers then inherited rather than re-derived.

Codex's slowness nearly cost the pass its most important findings: it was terminated once
as stale and proceeded 2-of-3. **The 2-of-3 exception is a real risk, not a free pass.**
