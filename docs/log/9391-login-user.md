# 9391 (first row) — `system login user <u> [uid -> class]`, and a lost fix in my own gate

- **Issue**: #9391 (row 1 of 27), from the #9156 leaf-run gate
- **Files**: `pkg/config/compiler_system.go`,
  `pkg/config/login_user_flat_run_9391_test.go` (new),
  `pkg/daemon/sudoers_demotion_spelling_9391_test.go` (new),
  `pkg/authz/empty_class_denies_9391_test.go` (new),
  `pkg/config/leaf_run_differential_gate_9156_test.go`

## The direction of failure, established before anything was changed

The brief asked for this first, and the answer is BOTH directions — which is
why "an empty class" was the wrong frame.

### Fresh user, no prior class — FAILS CLOSED

`pkg/authz.PrincipalForUID` returns an UNRESOLVED principal for an empty class
(`Detail: "system login user %s has no class"`, `Class` left `""`), and
`Authorize` denies on `p.Class == ""` before any permission is consulted. There
is no default class anywhere on the path. Measured across all six permissions
with a super-user control in the same run: every one denies, and the denial
names the missing class.

**So this direction is an AVAILABILITY bug, not an authorization one.** Stating
that plainly is worth more than the bigger claim.

### Existing user being DEMOTED — FAILS OPEN, and that is the real finding

The drop is one-directional: `class` is TYPED, so `class <c> uid <n>` is
REJECTED at commit; only `uid <n> class <c>` is admitted, and the swallowed
`class` is lost. Losing it does not produce an empty class when the user
**already has one** — it leaves the OLD class standing.

```
set system login user admin class super-user          (earlier line)
set system login user admin uid 2001 class read-only

  one line      -> class="super-user"     THE DEMOTION IS DROPPED
  separate      -> class="read-only"      (the oracle)
```

Commit reports success. `show configuration | display set` renders the
operator's own `read-only` line back. And:

- `reconcileSudoers` (`daemon_hostauth_apply.go`) keys the passwordless-root
  drop-in on `Class == "super-user"`, so the demoted admin **keeps the
  `xpf-admin` NOPASSWD grant**. That is precisely the #3889 defect — "a demoted
  or deleted admin kept passwordless root sudo forever" — reached again through
  the config layer instead of through the missing revocation branch that #3889
  added.
- `pkg/authz` then evaluates the retained `super-user` class on every gRPC and
  REST call.

**Reachability:** no attacker required. An ordinary operator with `configure`
permission, typing the idiomatic one-line `set`, silently fails to remove
someone's root. The attacker is the person being demoted, and what they need is
to do nothing.

The braced spelling of the same demotion is rejected by #5180's duplicate-block
guard, so this is FLAT-SET only — the CLI-typed form.

## The fix

`expandFlatRun(userInst.node.Children, loginUserSchema9391())`, computed ONCE
and read by both loops in the reader (the `authentication` probe and the
property switch) so they cannot see different sets.

`expandFlatRun` rather than `hoistAndSplitRun8939` **deliberately**: the
stronger helper descends into a container leaf's body, and `authentication` is
one whose packed spelling the #6662 gate exists to REJECT. Lifting out of it
would make the lenient path compile a shape the strict path refuses. A cell
pins that an authored `authentication` block still reaches the reader.

## The second finding: I shipped a claim that was not true

While removing the now-fixed row from #9156's register, the ratchet reported
only ONE stale entry where the arithmetic demanded more. Chasing that showed
that **the two-axis change described in PR #9394 and in commit `7a44a8cdc` did
not land.** What shipped was:

- `gateCompileFlatSet9156` present in the tree with **ZERO call sites**;
- the gate comparing the BRACED axis only;
- the register holding the original 26 UNLABELLED rows.

### How

The mutation harness took a `cp` backup of the gate file at setup time — before
the two-axis work. A later mutant restore ran `cp <backup> <file>`, which
reverted that work silently, and the ratchet extraction was then re-applied on
top of the reverted file.

**The restore verification is structurally incapable of catching this.** I
verify a restore with `diff <file> <backup>` and require them to match — and
"matches the backup" is exactly what a wrongly-reverted file looks like. The
check confirms the revert instead of detecting it. Go does not flag an unused
function, so nothing else objected.

### What changed as a result

- The second axis is re-applied, and **it is now asserted to have RUN**:
  `flatCompared == 0` is a VOID failure and driving it on under half the
  compared containers is an error. A helper that exists is not a helper that is
  CALLED, and that assertion is the difference.
- The register is regenerated with axis labels, 26 rows.
- The one row the braced-only gate could not see is back:
  `security log stream <s> [port -> category] {flat}` — which corrects #9156's
  own probe table, where that container is recorded as "recovered". It is, on
  the braced axis.

Measured now: 26 rows — 24 `{braced+flat}`, 1 `{braced}`, 1 `{flat}`. Neither
axis subsumes the other.

## Cells

| cell | what it binds |
|---|---|
| `TestLoginUserDowngradeIsNotSilentlyDropped9391` | the harmful direction, with the separate-lines oracle |
| `TestLoginUserFreshClassSurvivesTheRun9391` | the fail-closed direction |
| `TestLoginUserClassHeadIsStillRejected9391` | expanding at the READER must not widen the commit gate |
| `TestLoginUserAuthenticationBodyIsUntouched9391` | the bound on the remedy choice (#6662) |
| `TestDemotionSpellingRevokesTheSudoersGrant9391` | the CONSEQUENCE — the spelling drives `reconcileSudoers` end to end, with a genuine super-user as the control and the separate-lines demotion as the oracle |
| `TestEmptyLoginClassIsDeniedNotDefaulted9391` | all six permissions deny on an empty class, with a super-user control |
| the gate's `flatCompared` assertions | the axis cannot go dead again |

`TestDemotionSpellingRevokesTheSudoersGrant9391` is the one that matters: every
cell #3889 wrote constructs `config.LoginUser` values DIRECTLY and never goes
through the compiler, which is exactly why a compiler-layer drop could
resurrect the defect with #3889's own suite green.

## Mutation table

Five mutants, all KILLED (one VOID first, rebuilt).

**The backup discipline changed for this round, because of what happened
above.** Backups are taken from `git show HEAD:<file>` and a restore is
verified with `git diff --quiet HEAD -- pkg/` — the tree must equal the
COMMIT. A `cp` snapshot is a moment, and `diff <file> <snapshot>` is satisfied
by a file that was wrongly reverted TO that snapshot, which is exactly how the
second axis was lost. Comparing against HEAD cannot be satisfied that way,
because HEAD carries the intended state rather than an arbitrary earlier one.

| # | mutation | site | result | cells red |
|---|---|---|---|---|
| M1 | revert the fix — read `userInst.node.Children` in both loops | `compiler_system.go` | **KILLED** | 5 — all three config cells, the sudoers CONSEQUENCE cell, and the #9156 gate |
| M2 | delete the empty-class denial so it falls through to the class evaluator | `pkg/authz/authz.go` | **KILLED** | the authz cell, on all six permissions |
| M3 | grant sudoers on the wrong predicate (`Class == ""` instead of `!= "super-user"`) | `daemon_hostauth_apply.go` | **KILLED** | the sudoers consequence cell |
| M4 | **the exact defect that shipped**: the flat axis silently off | the gate | VOID, then **KILLED** | the new `flatCompared == 0` VOID assertion, naming it |
| M5 | the flat arm RUNS but measures the braced text — vacuous, not absent | the gate helper | **KILLED** | the register: both single-axis rows vanish and the ratchet reports them stale |

**M1 red the gate**, which the braced-only version did not — that is the
second axis doing its job on the container it was blind to.

**M4 is the regression test for the incident.** It reproduces exactly what
shipped — the helper present, the wiring gone — and the assertion added in this
change names it: *"the FLAT-SET axis was never driven. Every verdict above is
the braced axis alone."*

**M5 is the subtler half of the same class.** An axis that runs but measures the
wrong text increments every counter and passes the VOID check. What catches it
is the REGISTER: the two single-axis rows stop differing and the ratchet reports
them stale. The `{flat}` row is the canary, which is one more reason the axis
label belongs in the key rather than in a comment.
