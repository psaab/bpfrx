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

(filled in below)
