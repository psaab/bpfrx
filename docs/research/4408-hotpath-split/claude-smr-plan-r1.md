# Claude SMR — hostile plan review, #4408 r1

Reviewing `docs/research/4408-hotpath-split/plan.md` r1 (my own draft) against
`origin/master` `dd23119aa`. Adversarial posture: assume the plan is wrong and
try to break it. Six findings, two of them load-bearing.

**VERDICT: PLAN-NEEDS-REVISION → PLAN-READY after folding F1 + F2.**
The design is sound; the *gating methodology* in §7 is broken in two specific,
provable ways, and F1 in particular would have produced a merge-gate that
cannot be satisfied and would have wasted an `/engineer` round discovering it.

---

## F1 (MAJOR) — §7.2 demands parent-RED for a behaviour-preserving refactor. That is incoherent, and it cannot be satisfied.

§7 step 2 says: *"revert each extraction in turn, confirm a named test
assertion fails."*

**Every increment in this plan is behaviour-preserving by construction.**
Increment 1 collapses two byte-identical blocks into one; Increments 3a/3b
re-express the same control flow through `Option`. Reverting any of them
restores *semantically identical* code. **No test will fail on revert — that is
the whole point of the refactor.** The gate as written is unsatisfiable, and an
engineer trying to satisfy it will be pushed toward either (a) declaring a build
break to be RED (explicitly forbidden by
`feedback_red_on_revert_must_be_assertion_not_build_break`) or (b) inventing a
behaviour change to make the test fail — which is the exact failure this
project's gate discipline exists to prevent.

Parent-RED answers *"does a test bind the fix?"*. There is no fix here. The
question that actually needs answering is different: **"is the code I lifted
into the helper genuinely exercised, or did I just relocate dead-ish code that
nothing checks?"** That question is answered by **mutation of the extracted
helper**, not by revert.

**Required replacement for §7.2** — a three-part gate:

- **(a) Body identity.** `git diff --color-moved=dimmed-zebra` shows each
  extracted region as pure motion; the only permitted non-motion edits are the
  `cp1_len`/`cp2_len` → `cp_len` rename and the signature/call sites. Anything
  else must be listed line-by-line in the PR body.
- **(b) Mutation of the extracted helper — proven to fire.** For each extracted
  helper, apply at least one mutation *per distinct behaviour it owns*, and
  record a NAMED failing test for each. Concretely, minimum grid:

  | Helper | Mutation | Must fail |
  |---|---|---|
  | `enqueue_copy_fallback_frame` | delete the `nat64_exthdr_ineligible` attribution | a `tests/enqueue_failure.rs` / NAT64 counter assertion |
  | `enqueue_copy_fallback_frame` | delete the `nat64_frag_dropped` attribution | a distinct named assertion (the #2562 arm) |
  | `enqueue_copy_fallback_frame` | invert `copy_frame_is_oversized` | the oversized drop-and-recycle assertion |
  | `enqueue_copy_fallback_frame` | drop `fallback_to_slow_path = true` on enqueue-Err | the #2208 slow-path-reinject assertion |
  | `refill_waterfill_epoch` | remove the `epoch_boundary` gate on the bitset clear | the #1743-r3 livelock test |
  | `refill_waterfill_epoch` | reset `waterfill_phase2_cursor` in the refill | the #1630-r4 cursor-continuity test |
  | `waterfill_phase1_select` | drop the honored-bit set | the #1732 at-most-once-per-epoch test |
  | `waterfill_phase2_select` | ignore the honored bitset | the descending-residual test |

  Two mutations minimum per helper, because **one fixture binds one match arm**
  (`feedback_one_fixture_binds_one_match_arm`) — the two NAT64 attribution arms
  are separate branches of an `if/else if` and a single mutation proves only
  one. A helper for which **no** mutation produces a named failure is a helper
  whose contents are unbound; that must be reported, not papered over.
- **(c) Negative control on the mutation harness itself**
  (`feedback_prescribed_mutation_needs_a_negative_control`): show one mutation
  that is *expected* not to fail (e.g. reordering two independent counter
  increments) so a reader can tell the grid is measuring the code and not
  simply reporting "everything fails".

## F2 (MAJOR) — the §2c call-edge gate command produces false failures. I verified this against the real binary.

My proposed normalisation strips the Rust symbol hash
(`s/17h[0-9a-f]{16}E?$//`) but **not** the LLVM CGU-hash suffix. Measured on
the actual `dd23119aa` binary: **5 of the 51 baseline edges carry a
`.llvm.<20-digit>` suffix**:

```
…publish_binding_debug_state17h7f010bd79b36908cE.llvm.15104266154738188186
…nat64::nat64_v6_translation_ineligible17h45dae7fd1de716f1E.llvm.17871286219147243839
…VecDeque<T,A>::grow17h1287208c06e60c90E.llvm.17702975328697826035   (×3, distinct Rust hashes)
```

Those `.llvm.N` suffixes are **codegen-unit-content hashes**. Adding a function
to `dispatch/mod.rs` changes that CGU's content, so the suffix changes, so the
gate reports up to 5 spurious "changed call edges" on a diff that is pure
motion. An engineer seeing 5 red edges will either (a) conclude the plan's core
safety claim failed and abandon a correct refactor, or worse (b) learn to
hand-wave the gate's output — which destroys it as evidence for every future
PR.

**Required fix:** strip both suffixes before comparison, and normalise the
`VecDeque::grow` monomorphisation multiplicity:

```bash
… | sed -E 's/\.llvm\.[0-9]+$//; s/17h[0-9a-f]{16}E?$//' | sort -u
```

and state in the PR that the comparison key is the **demangled symbol path
without hashes**, so the gate detects a genuinely *new callee*, not a relabelled
one. Also: resolve the symbol address from `nm` at gate time rather than
hard-coding `0x3a8a00` (my §2c text says this, but the pasted command hard-codes
the address — fix the command to match the text).

## F3 (MINOR, but it is a numeric claim in a doc) — the Increment-1 LOC arithmetic is wrong, in the conservative direction.

§5 Option A says `1074 → ~940` (−134). Measured: arm D is **139 raw lines**
(:819–957), arm E is **125 raw lines** (:1155–1279) = **264 lines removed** from
the function body, replaced by two call sites of roughly 15 lines each. So the
function goes `1074 → ~840`, and the *file* goes `1608 → ~1524` (the ~150-line
helper stays in the file). Combined with Option C′ the function reaches ~730,
not ~824.

Being wrong in the safe direction is still wrong: the plan's §9 "honest
limitation" is calibrated off the ~940 number and should be recomputed. It does
not change the recommendation — ~840 is still ~8× the god-function line — but a
plan that quotes a measured number must quote the right one.

## F4 (MINOR) — the extraction creates a function that violates the very rule the issue cites.

`enqueue_copy_fallback_frame` needs, at minimum: `target_binding`,
`source_frame`, `request`, `expected_ports`, `is_nat64`, `&mut flow_key`,
`dbg`, `counters`, `recent_exceptions`, `ingress_ident`, `forwarding` — **11
parameters**, against `docs/engineering-style.md`'s ">8 parameters is a refactor
cue". The plan should either bundle the invariant-per-request subset into a
by-reference context struct (stack-only, no allocation, so the no-alloc
invariant is untouched) or state plainly that it accepts an 11-param helper as
strictly better than a 264-line duplication. Silently shipping a new
rule-violating signature inside a PR whose justification *is* that rule is the
kind of thing a hostile reviewer should and will flag.

## F5 (MINOR, but it bounds future work) — Phase 1's borrow structure is more fragile than §1a implies, and the plan should say where the floor is.

§1a is correct that all state is on `root`. It does not mention that the Phase-1
body depends on **precise NLL borrow-end points**: `let queue = &mut
root.queues[queue_idx]` (:1104) coexists with reads of the *disjoint* field
`root.tokens` (:1141, :1152), and then `count_park_reason(root, …)` /
`park_cos_queue(root, …)` (:1159–1160) take `&mut root` **whole** — which only
compiles because `queue`'s borrow ends at its last use (:1154). The #1628-r4
comments at :1124 and :1335 document the same hazard for `head`/`kind`.

Extracting Phase 1 *as a whole* preserves this exactly (same body, same `root`
parameter) — so the plan is safe. But the plan should state the **floor**: the
interior of Phase 1 cannot be decomposed further without re-deriving these
interleavings, and a future pass that tries will hit borrowck, not a subtle bug.
Naming the floor now prevents a future `/research` from re-litigating it.

## F6 (MINOR) — "no symbol ⇒ inlined" is an inference, not an observation.

§2b states the waterfill "does not appear as a symbol — fully inlined". What was
observed is *absence from `nm`*. Absence is consistent with inlining into the
sole caller, with ICF merging, and with symbol internalisation. All three lead
to the same operational conclusion (it is not an out-of-line call from the
wrapper), so the plan's use of the fact is sound — but the wording should be
"absent from `nm`; therefore not an out-of-line call from its caller" rather
than asserting the mechanism.

## F7 (NIT) — the de-dup merges two comment sets.

Arm D carries 37 comment lines, arm E 23; the *code* is identical but the
rationales differ (#2208 phrased for the in-place-`None` path vs the
direct-TX-unavailable path). The merged helper must carry **both** rationales,
not whichever one the engineer's editor had open. Worth one line in the plan so
it is a checklist item rather than an accident.

---

## What I tried to break and could not

Stated so the reader can tell this pass was adversarial rather than
confirmatory:

1. **"The interior of `enqueue_pending_forwards` has hidden `continue`s."**
   It does not. `awk 'NR>=589 && NR<=1295' | grep -n
   'continue\|return\|recycle_ingress_frame'` returns 11 hits, **all inside `//`
   comments**. Checked by eye, line by line.
2. **"The export set is bigger than four."** Traced every occurrence of all
   seven interior locals. `copied_source_frame` last reads at :722,
   `mtu_signalled` at :747, `flow_key` at :1223 — all inside. Only
   `build_failed` (:1378), `fallback_to_slow_path` (:1391),
   `retained_source_frame` (:1394/:1399) and `ptb_reply` (:1313) cross. Four.
3. **"Phase 1's `break` and its loop-exhaustion have different successors."**
   They do not — both fall to Phase 2. The `waterfill_phase1_budget_breaks`
   bump that distinguishes them happens *before* the `break`, inside the region
   being extracted.
4. **"`phase2_idx` must escape."** It must not. It is seeded from
   `root.waterfill_phase2_cursor` and written back only on selection (:1368);
   the wrap tail unconditionally zeroes the cursor.
5. **"`trigger_kernel_arp_probe` is in one of these files, so §4 dodges an
   invariant."** It is not: `neighbor.rs:158`, called from
   `neighbor_resolver.rs:771/781/789` and `neighbor.rs:355`. Neither target file
   references it. The plan's "out of scope" claim is correct as verified, not
   as assumed.
6. **"The two copy-fallback arms differ somewhere that matters."** They do not.
   102 normalised lines each, diff = the enclosing `None => match` wrapper only.
   Command is in the plan and rerunnable.

## Where I remain uncomfortable (not a blocker, but the leader should see it)

Increment 1's value rests on a **maintenance** argument (one owner for the NAT64
attribution) rather than a measurable one. That argument is real — #5625 and
#2562 each had to edit two copies — but it is a judgement call, and a reviewer
who weighs churn-in-the-hottest-TX-function higher than duplication-risk could
reasonably land on "not worth it". I would not call that reviewer wrong. The
waterfill half (Increment 3) does not have this weakness: 432 → ~30 with zero
test edits and 18 tests holding the invariants is a clean win by any measure,
and it is the part of this plan I would defend hardest.

**If forced to ship exactly one thing: Increment 3.**
