# Claude SMR — hostile plan review r1 (#7289 plan v1)

Reviewing my own draft. The instruction for this pass is to be hostile rather
than to synthesize, and the project's history says a first-pass
PLAN-READY-WITH-NITS from this reviewer is a yellow flag. I found one finding
that breaks the plan's spine, so this is not a soft pass.

---

## F1 — CRITICAL. The plan's spine misreads #5679, and the misreading inverts the recommendation.

§3 claims "the codebase has already chosen clause 2's option (c) as its
doctrine for this failure class." The evidence is `daemon_apply_dataplane.go:191`.
Read the whole sentence:

> an identical re-commit / the feed onUpdate retry (#5646, via applyConfigResult)
> re-applies and self-heals **a transient helper / control-socket error**.

**Scoped to TRANSIENT errors.** #7289's one reachable trigger is
`attachUserspaceShimXDP` failing on a driver that refuses the attach
(`compiler_iface.go:191`, and `runPostMutationSteps` exists because of it).
A driver that refuses an XDP attach refuses it again. That failure is
**PERSISTENT**.

Converge-forward against a persistent failure does not converge. It re-drives
Phase 2, re-fails at the attach, and re-drives again — with the host still
diverged the whole time, and now with a retry loop re-issuing 23 netlink writes
against a live box on every attempt.

So the plan's own recommendation does not solve the case it identifies as the
only reachable one. §2 says "low-frequency, high-consequence"; §6 then
prescribes a mechanism that is correct for the frequent-and-transient case and
useless for the reachable one.

**What this does to the option table.** It inverts (b) and (d):

- For a **transient** failure, #5679/#5646 already self-heal when a trigger
  fires. The residual is P1 (idempotence gaps) plus a trigger. Small.
- For a **persistent** failure, the only terminating answer is to stop
  forwarding on stale policy — option (b), unarming into the SHIPPED
  #5275/#7191 barrier, whose #1960 analysis is already done.

(b) is therefore not "the bounded fallback" §6 makes it. It is the answer for
the reachable case, and (c)/(d) is the answer for the unreachable-but-frequent
one. The plan has them backwards.

**Required:** re-derive §5/§6 with the transient/persistent split as the
primary axis. A plan that does not distinguish them is choosing a mechanism by
its elegance rather than by the failure it meets.

## F2 — MAJOR. P3's "no timer" is asserted, not derived, and the pattern it copies does not transfer.

§6 P3 says copy `pkg/daemon/released_nic_tunables.go` — "ownership set,
level-triggered `owned - current`, retry debt dropped only on success, no
timer". That pattern works because its trigger RE-FIRES: an interface leaving
xpf ownership is an event that recurs on the next apply.

The abort has no such event. §4.3 measured the three re-apply triggers (feed
refetch, bringup, DHCP lease) and found none unconditional. So on the box the
issue is about — static addressing, no dynamic feeds — P3 as written has
nothing to fire it, and the plan's own OQ-2 asks the question without answering
it while §6 already assumes the answer.

Either P3 needs a timer (and the "no timer" discipline it cites does not
transfer), or P3 must hook an event that provably recurs. The plan must not
ship the citation as if it were the derivation.

## F3 — MAJOR. P2 is written as new work; most of it is shipped, and the part that is missing is not the part named.

§6 P2 says "Record 'aborted after host mutation, at config generation N'
somewhere that survives the failed apply. Today nothing does."

`recordCompileFailure` (`daemon_health.go:110-128`) already records
`compileFailureCount`, `compileLastError`, `compileLastErrorUnixSec` under a
mutex, escalates at 5 and every 10 thereafter, and is called on the failure
path (`daemon_apply_dataplane.go:175`). So an abort IS recorded and IS
surfaced.

What is NOT recorded is that **host state moved** — `hostMutations` is an
unexported field on `CompileResult` and `ApplyResultFromCompileResult`
(`apply.go:210-229`) does not copy it, so it dies with the CompileResult.

P2 is therefore "thread the existing `hostMutations` into the existing health
record", which is materially smaller than the plan implies — and the plan
overstating it is the kind of error that makes a reviewer discount the rest of
the sizing.

## F4 — MAJOR. The 20/2/3 split counts SITES, but convergence is a property of the SET.

§4.1's "20 sites are already idempotent" is a per-site claim. Convergence after
an abort is a property of the whole phase from an arbitrary prefix (§4.2). Those
are different claims and the plan slides between them.

Concretely: M1 creates the VLAN child and the abort lands before M5/M6 reconcile
its addresses. Re-drive takes the ADOPT branch (`compiler_iface.go:203-207`),
which returns at `:238` — **before** M3. The plan already flags M3 as gap #1.
But it does not check whether the adopt branch also skips anything else the
create path does. If it does, the gap list is incomplete, and a gap list that
is incomplete is worse than no list because it will be trusted.

**Required:** enumerate what the create path does that the adopt path does not,
as a diff of the two branches, rather than naming the one instance found.

## F5 — MODERATE. §4.4 declines clause 1 for a good reason and states it as a stronger result than it is.

"The snapshot must be built from POST-actuation live state … an ordering
diagnosis is not a prescription to swap." Correct, and I believe it. But the
supporting cite is inherited from the stranded plan's r1 6.1 — and
`premise-check.md` §B is an argument that this same plan's "(verified …)"
annotations cannot be trusted. The plan cannot both discount that branch's
verifications and lean on one of them.

**Required:** re-derive the post-actuation constraint directly
(`buildInterfaceSnapshots` reading live child ifindex/MTU/MAC/addrs) or drop
the claim to "reported, not verified".

## F6 — MODERATE. OQ-1 is asked and then not answered, and it is the question that decides the plan.

If P4's ledger boundary is unstable, (d) IS (a) and this plan is proposing the
model it rejects in §5. The plan lists this as an open question for reviewers.
That is an abdication: the author has the mutation inventory and is the person
best placed to test the boundary. Three classes are named; the test is whether
a fourth arrives under pressure. My own read is that the ratchets are already a
heterogeneous bag (ethtool -K, -G, -X, txqlen, rps/xps, accept_ra) held
together by "we did not capture the old value", which is a property of the
CODE, not of the mutation — and properties of the code move.

## What survives

The premise work is sound and is the plan's real contribution: the four
corrections in `premise-check.md`, the 23-site inventory, the nondeterministic
prefix, and the finding that no re-drive engine exists. §5's rejection of (a)
on the nondeterministic-prefix ground is a genuine result and it is the one
piece I could not break.

## VERDICT: PLAN-NEEDS-MAJOR

F1 alone requires the recommendation to be re-derived: the plan prescribes
converge-forward for a failure class that is persistent, where converging
forward does not terminate. F2/F3/F4 are sizing and completeness errors that
would each survive into implementation as a surprise. F5/F6 are argument
hygiene.

v2 must lead with the transient/persistent split, not with the option table.

---

## F4 addendum — the diff v2 owes, computed. The gap list was incomplete.

F4 asked for the create-vs-adopt branch diff rather than the one instance the
plan named. `ensureVLANSubInterface` (`compiler_iface.go:197-275`):

| step | CREATE path | ADOPT path |
|---|---|---|
| provenance check | n/a | `vlanAdoptionRefusal` → hard `errVLANAdoptRefused` (`:210`) |
| bring up | `LinkSetUp`, error **RETURNED** (`:263`) | `LinkSetUp` only if `OperState != OperUp`, error **LOGGED** (`:228-233`) |
| `accept_ra=0` | written, warn-only (`:268`) | **not written at all** |

So there are **two** divergences, not the one the plan lists:

1. **M3 `accept_ra` is create-only** — as the plan says.
2. **`LinkSetUp` is fatal on create and silent on adopt.** This one is worse
   and the plan misses it entirely. An abort between `LinkAdd` and `LinkSetUp`
   leaves a DOWN child. The re-drive takes the adopt branch, nudges it up, and
   **swallows a persistent failure** — returning `created=false, err=nil`. The
   apply reports SUCCESS with the interface still down.

That is converge-forward failing to do either of the two things it promises: it
neither converges nor fails. And it is invisible, because the in-tree comment at
`:224-231` justifies the swallow on the reasoning that "a failed nudge leaves
the child DOWN, so nothing forwards through it and the #6916 harm does not
arise" — which is sound for the steady-state apply it was written for and
false for a re-drive that is supposed to be a convergence guarantee.

**This is the finding that most sharpens F1.** Converge-forward does not merely
fail to terminate against a persistent failure (F1); on this path it terminates
in a FALSE SUCCESS. v2 must treat "the re-drive's own error handling differs
from the first drive's" as a design constraint, not an implementation detail.
