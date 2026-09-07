# 9391 — reachability, two severity downgrades, and the one row that had it

## Two corrections I owe

### 1. `security zones security-zone <z> [description -> screen]` is NOT a security defect

I filed it as SECURITY. Measured:

| spelling | verdict |
|---|---|
| flat-set `set` (CLI-typed) | **REJECTED** — `description` is `scalar: true`, #3332 trailing-token gate |
| braced, `CheckText` (commit) | **REJECTED**, same gate |
| braced, lenient boot / HA sync | accepted, screen dropped, **`slog.Warn` names the leaf and the dropped token** |

An operator cannot reach it by committing, and the one path that accepts it
warns. The SECURITY label is withdrawn.

**My first probe nearly produced a much bigger false claim.** It read
`cfg.Warnings == 0` and I was about to report "the lenient path is silent",
which would have been a systemic finding against #1960's doctrine. That probe
called `CompileConfigLenient` — a lower-level helper that runs no schema
validation at all. Driving `Store.compileTreeLenient`, the function `Load` and
`SyncApply` actually call, shows the warning firing by name. **The instrument
was measuring the wrong layer**, and the size of the claim it would have
supported is exactly why the layer had to be checked.

### 2. Hand-measuring 26 rows was the wrong method

The two rows measured by hand landed on opposite sides of one line:

- `system login user <u> [uid -> class]` — `uid` is untyped, so it is an
  ADMISSION HEAD and the strict walk ADMITS the run. **Operator-reachable.**
- `security zones security-zone <z> [description -> screen]` — `description` is
  `scalar: true`, so #3332 refuses the trailing token. **Lenient-only.**

The register is not homogeneous and the differentiator is the HEAD leaf's
declaration — which the walker can evaluate for every row at once. So the gate
now computes it (`strictAdmitsLeafRun9156`) and labels each row
`{strict-admits}` or `{lenient-only}`.

```
of the 26 differing rows: 1 OPERATOR-REACHABLE, 25 lenient-only
```

**#9391 is far smaller than I filed it.** 25 rows cannot be reached by
committing; they need a config file or an HA sync, and that path warns.

## The one reachable row, and why it nearly stayed invisible

```
security log stream <s> [port -> category]  {flat} {strict-admits}
```

It is in the register **only because the flat-set axis was restored**. The
braced-only gate found 26 rows of which **zero** were operator-reachable, and
missed the one that was. A gate on the wrong axis did not merely under-report —
it reported a population with none of the real signal in it.

### Measured

```
set security log stream s1 host 10.9.9.9
set security log stream s1 port 5514 category rt-flow
  -> commits CLEAN, category dropped
```

`port` is untyped, so the run is admitted and the reader kept only the head.

**The consequence is an INVERSION, not a loss.** `Categories == 0` means ALL
(`pkg/logging/syslog.go`: `return s.Categories == 0 || ...`), so the operator's
NARROWING becomes "export every category" — a collector scoped for one category
receives all of them. **Over-export, not a monitoring blind spot**, and which one
it is decides the severity. Lower than the phrase "security log stream"
suggests. `severity` is lost the same way.

## The gate-evasion the second reader hides

`expandFlatRun` is applied at BOTH readers of the stream body: the compiler and
the strict port check. That is not consistency housekeeping — a mutation showed
it is load-bearing:

```
set security log stream s1 port 5514 host 10.9.9.9 port 99999
  second reader UNexpanded -> compile err = <nil>          GATE EVADED
  second reader expanded   -> "invalid syslog port \"99999\""
```

An invalid syslog port written BEHIND the untyped head reaches the compiler
unchecked, and the compiler then silently keeps the default 514 — which the
gate's own message says is what it exists to prevent.

## Mutation table

Backups from `git show HEAD:<file>`, restores verified with
`git diff --quiet HEAD`, per the rule adopted after the stale-backup incident.

| # | mutation | result | cells red |
|---|---|---|---|
| M1 | revert the compile reader's expansion | **KILLED** | both log-stream cells + the gate |
| M2 | make every row read as operator-reachable | VOID, then **KILLED** | the register — every key's reachability suffix changes, so all 25 report stale |
| M3 | sever the SECOND reader (the strict port check) | **SURVIVED**, then **KILLED** | (rewritten) `TestLogStreamStrictCheckSeesTheSameStatements9391` |

### M3 survived against a cell written to bind it

The first version of that cell drove an out-of-range value on the **head** leaf
— present in the expanded AND the unexpanded set — so severing the second
reader left it green. It asserted the thing it was written for and could not see
it. The rewrite buries the bad value behind the head, which is the only place
the two walks disagree, and carries two controls: the same bad port on the head
must still be rejected, and a valid stream must still compile.

That is the third instrument defect this round, all three found by mutation and
none by reading.
