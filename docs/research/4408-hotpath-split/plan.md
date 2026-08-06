# #4408 — Rust hot-path god-functions: `enqueue_pending_forwards` + waterfill

**Status:** PLAN-READY (r3) on a **narrowed scope** — recommending
**Option B′: the waterfill split ONLY** (Increments 3a + 3b). The dispatch
de-duplication (Increment 1) is **DEFERRED, not rejected**, with its evidence
preserved in §5-A for whoever picks it up. The arm-decomposition shape that
#4404 killed remains explicitly rejected (§5-D).

**Convergence so far (2 reviewers, same conclusion on the narrowed scope).**
Codex returned PLAN-NEEDS-MAJOR on r2: it declined to kill the waterfill split
— *"Its refill, Phase 1, and Phase 2 boundaries are real state-machine
boundaries, and its value survives this review"* — and blocked only Option B's
dispatch half — *"The de-dup is safe, but its benefit is not strong enough to
override the current hottest-path churn and validation gaps."* That is the same
place my own r1 SMR landed unprompted (*"if forced to ship exactly one thing:
Increment 3"*). r3 states the convergence rather than treating the two passes
as disagreeing.

**Round history — read §8a before trusting any gate in this doc.**

| r | What changed | Where the defects were |
|---|---|---|
| r1 | first draft | — |
| r2 | folded 7 SMR findings | **2 load-bearing, both in the GATE**: unsatisfiable parent-RED (F1); call-edge command missing the `.llvm` strip (F2) |
| r3 | narrowed scope; **gate made instance-aware** | **1 load-bearing, again in the GATE**: the inherited Rust-hash strip **over-collapsed** three distinct `VecDeque::grow` monomorphisations into one identity (F8) |

Three consecutive rounds, three gate defects, zero defects found in the refactor
design itself. §8a treats that as evidence, not coincidence.
Base: `origin/master` `dd23119aa7a6ea5bd118b2f788faa1cf68ce7a42`.
Branch: `research/4408-hotpath-split`. No production code touched.

---

## 0. Premise re-measured (all four leader numbers confirmed)

At `dd23119aa`:

| Artifact | Measured | Issue filed at | Leader's screen |
|---|---|---|---|
| `userspace-dp/src/afxdp/tx/dispatch/mod.rs` | **1608** LOC | 1423 | 1608 ✓ |
| `userspace-dp/src/afxdp/cos/queue_service/mod.rs` | **2166** LOC | 2058 | 2166 ✓ |
| `enqueue_pending_forwards` (mod.rs:339–1412) | **1074** LOC, **19 params** | 1131 | 1074 ✓ |
| `select_exact_cos_guarantee_queue_waterfill` (mod.rs:968–1399) | **432** LOC, 4 params | 438 | 432 ✓ |

Both functions violate the `docs/engineering-style.md` "No god functions"
rule (>100 lines, >8 params) by an order of magnitude. `queue_service/mod.rs`
also crosses the 2,000-LOC file threshold.

**The issue's own prescribed fix is already spent.** It says *"outline the
cold segmentation + mirror paths from the hot build path"*. Those are done:

- mirror → `enqueue_sampled_mirror_clone` / `record_mirror_clone_result` (mod.rs:253/268)
- segmentation → `segment_forwarded_tcp_frames_into_prepared` / `_from_frame` (mod.rs:358/393)
- PTB/MTU → `compute_forwarded_egress_ptb` (mod.rs:163), which landed as
  **"#4408 increment 1"** (`c349dce68`, PR #4642)

So this plan is about the **residual**, and it must justify itself on
different grounds than the issue text does.

---

## 1. Q1 — Is this decomposable without a behaviour change?

Two targets, two different honest answers.

### 1a. Waterfill: **NOT entangled. Cleanly separable.** (high confidence)

Every piece of mutable state that crosses a phase boundary lives on **one
object**, `root: &mut CoSInterfaceRuntime`:
`waterfill_pass1_remaining_bytes`, `waterfill_honored_epoch_bits`,
`waterfill_phase2_cursor`, `waterfill_epoch_wrap_pending`,
`waterfill_epoch_start_ns`, `waterfill_epochs`, `exact_guarantee_rr`.

There is **no scratch buffer, no recycle list, and no function-local index
cursor that must survive a split.** The one local that *looks* like a cursor,
`phase2_idx` (mod.rs:1280), is seeded from `root.waterfill_phase2_cursor` and
written back **only** on a Phase-2 selection (:1368); on the no-selection path
it is discarded and the wrap tail resets the cursor to 0. It does not need to
escape a Phase-2 extraction.

Control flow maps **exactly** onto `Option`, with no invented protocol:

| Region | Exits | Maps to |
|---|---|---|
| Refill (:1000–1073) | none — zero `return`/`break`/`continue` | `fn(&mut root, now_ns)` |
| Phase 1 (:1088–1268) | `return Some(sel)`; `break` (budget); loop exhaustion | `Option`; `None` ⇒ Phase 2 |
| Phase 2 (:1280–1387) | `return Some(sel)`; `break` (cursor wrap); loop exhaustion | `Option`; `None` ⇒ wrap tail |
| Wrap tail (:1395–1398) | `None` | stays in orchestrator |

Both of Phase 1's non-selecting exits (`break` on
`phase1_cost > pass1_remaining`, and falling off the end) already converge on
the same successor — Phase 2. Same for Phase 2 → wrap. So `None` is a faithful
encoding, **not** an `ArmOutcome`-style rewrite. The `#1628 site 3`
`waterfill_phase1_budget_breaks` bump happens *before* the `break`, inside the
extracted body, so it is preserved by construction.

**One ordering hazard, called out explicitly:** inside the refill, the order
of (a) `waterfill_epochs` bump, (b) the `epoch_boundary`-gated
`waterfill_honored_epoch_bits = 0`, and (c) `waterfill_epoch_wrap_pending =
false` is the #1743-r3 livelock fix. The refill must be extracted as **one
block**. Do **not** further split it into "compute budget" + "clear bits".

**Where the decomposition floor is (SMR F5).** Phase 1's body depends on
precise NLL borrow-end points: `let queue = &mut root.queues[queue_idx]`
(:1104) coexists with reads of the *disjoint* field `root.tokens` (:1141,
:1152), and then `count_park_reason(root, …)` / `park_cos_queue(root, …)`
(:1159–1160) take `&mut root` **whole** — which compiles only because `queue`'s
borrow ends at its last use (:1154). The #1628-r4 comments at :1124 and :1335
document the same hazard for `head`/`kind`. Extracting Phase 1 *as a whole*
preserves this exactly (same body, same `root` parameter). But the **interior of
Phase 1 cannot be decomposed further** without re-deriving those interleavings;
a future pass that tries will hit borrowck. Naming the floor here so it is not
re-litigated.

### 1b. `enqueue_pending_forwards`: **partly entangled — but the entanglement is confined to the prologue/epilogue, and the interior is already escape-free.**

The genuine entanglement, stated precisely:

- `left` / `ingress_binding` / `right` are three `&mut` views of the binding
  array, and `resolve_pending_forward_target_binding<'a>` **reborrows
  `target_binding` out of them**. While `target_binding` lives,
  `ingress_binding` is mutably borrowed (in the hairpin case `target_binding`
  *is* `ingress_binding`). That is why the explicit `{ }` block at :589–1295
  exists at all — to end the borrow before `apply_shared_recycles` (:1297) and
  the PTB enqueue onto `ingress_binding` (:1353).
- `source_frame: &[u8]` is read through `unsafe { &*ingress_area }`, where
  `ingress_area: *const MmapArea` is captured **before** the loop (:363)
  precisely to dodge that borrow.

That second point is decisive and is why the extraction is expressible: the
raw-pointer escape hatch **already exists in production**, so a helper can take
`target_binding: &mut BindingWorker` *and* `source_frame: &[u8]` with no new
`unsafe` and no lifetime invention. This is the same shape
`segment_forwarded_tcp_frames_into_prepared` and `drain_pending_tx_local_owner`
already use.

**The single-recycle invariant.** Eight recycle sites, all outside the
interior:

| Site | Line | Kind |
|---|---|---|
| Prebuilt: no target binding | 431 | `recycle` + `continue` |
| Prebuilt: enqueue failed | 462 | `recycle` + `continue` |
| Prebuilt: success | 472 | `recycle` + `continue` |
| Live slice returned `None` | 487 | `recycle` + `continue` |
| FabricRedirect, no binding | 551 | `recycle` + `continue` |
| No egress binding | 572 | `recycle` + `continue` |
| Epilogue, build failed | 1395 | `recycle` if `!retained_source_frame` |
| Epilogue, success | 1400 | `recycle` if `!retained_source_frame` |

**Verified by grep: the interior region :589–1295 contains ZERO executable
`continue`, `return`, or `recycle_ingress_frame`** — every hit in that range is
inside a comment:

```bash
awk 'NR>=589 && NR<=1295' userspace-dp/src/afxdp/tx/dispatch/mod.rs \
  | grep -n 'continue\|return\|recycle_ingress_frame'
# → 11 hits, all inside `//` comments
#   (absolute lines 702, 859, 878, 902, 906, 909, 988, 1195, 1213, 1237, 1240)
```

**One executable `break` does exist in the region, at :661 — and a reader
running that grep will not see it, so it is recorded here explicitly rather
than left as an unexplained hole.** It is the `break` inside
`for frame in segmented { … }` (loop opened :641, closed :688):

```rust
record_exception_owned(…);
build_failed = true;
break;              // :661 — exits the inner segmentation loop only
```

It terminates the per-segment loop and resumes at :689
(`copied_source_frame = true;`) **inside the same region**. It is not an escape
from the extraction boundary, and it does not reach any recycle site. Codex
independently confirmed both the 11 comment matches and — via commit
`29defb24d7` — that #2208 replaced four cp1/cp2 `continue`s with flag-setting.

This is not luck. #2208 deliberately converted the interior's bare `continue`s
into `build_failed` / `fallback_to_slow_path` flag sets **so that the epilogue
owns the recycle exactly once** (the comments at :874, :901, :1210, :1233 say so
in as many words). The refactor this issue asks for was, in effect, half-done by
a bug fix three hundred PRs ago.

**Export set of the interior is exactly four values** (verified by tracing every
occurrence of each local):

| Local | Declared | Last read | Escapes? |
|---|---|---|---|
| `copied_source_frame` | 577 | 722 | **no** — dies inside |
| `mtu_signalled` | 587 | 747 | **no** — dies inside |
| `build_failed` | 575 | 1378 | **yes** |
| `fallback_to_slow_path` | 576 | 1391 | **yes** |
| `retained_source_frame` | 578 | 1399 | **yes** |
| `ptb_reply` | 586 | 1313 | **yes** |
| `flow_key` | 588 | 1223 | no — moved in, consumed inside |

Four exports, no control-flow escape. That is the precondition the #4404 kill
found *absent* in `poll_binding_process_descriptor`.

### 1c. The finding the issue got wrong

The issue calls the residual "8+ responsibilities fusing build + segmentation +
WG/GRE + output-filter + CoS". After the mirror/segmentation/PTB outlines
landed, that is **no longer true**. What remains is *one* responsibility —
choose a frame-materialisation strategy and enqueue it — expressed as a 4-way
strategy cascade:

```
in-place UMEM rewrite  →  direct-TX build-into  →  Vec-copy fallback  →  fail
```

Each of those four is a **live per-packet traffic class**: in-place is the
zero-copy same-UMEM common case; direct-TX is the cross-UMEM common case;
Vec-copy is the NAT64 / native-tunnel / non-owner / TX-congestion case. **Splitting
the cascade *arms* into separate outlined functions is exactly the shape #4404
killed** — it forces a per-packet `call` on a real traffic class, which is the
#1697-v1 / #4409(b) failure mode. **This plan does not do that**, and §5
(Option D) rejects it on the record.

### 1d. The strongest seam is a de-duplication, not a hoist

The Vec-copy fallback is written **twice, verbatim**:

- :819–956 — reached when in-place rewrite returned `None`
- :1155–1279 — reached when direct-TX was unavailable

After stripping comment-only lines and indentation and normalising the one
differing local name (`cp1_len` / `cp2_len`), both become **102-line blocks that
agree on 100 of 102 lines**. The two differences are the enclosing
`None => match …` vs a bare `match …` and its closing `},` vs `}`:

*(r1/r2 said "102 identical lines". That was imprecise — 102 lines each,
agreeing on 100. Corrected here rather than left to a reviewer to catch.)*

```bash
cd userspace-dp
sed -n '819,957p'   src/afxdp/tx/dispatch/mod.rs | sed 's/cp1_len/CPLEN/g; s/^[[:space:]]*//' | grep -v '^//' > /tmp/armD.txt
sed -n '1155,1279p' src/afxdp/tx/dispatch/mod.rs | sed 's/cp2_len/CPLEN/g; s/^[[:space:]]*//' | grep -v '^//' > /tmp/armE.txt
diff /tmp/armD.txt /tmp/armE.txt
# 1c1  < None => match if is_nat64 {   ---   > match if is_nat64 {
# 101c101  < },   ---   > }
```

This is a **maintenance hazard, not a cosmetic one**: the NAT64 build-`None`
drop attribution (`nat64_exthdr_ineligible` / `nat64_frag_dropped`, from #5625
and #2562) is implemented **twice**, and both copies must be edited in lockstep
forever. Same for the #2208 oversized/enqueue-fail handling. Collapsing them to
one owner is a defect-class reduction that stands on its own merits even if the
LOC win were zero.

---

## 2. Q2 — Does an extraction risk a codegen regression? (measured, not assumed)

### 2a. The build profile — the #4409(b)/#4404 premise is CORRECT

`userspace-dp/Cargo.toml` has **no `[profile.*]` section**, and there is **no
workspace-root Cargo.toml**. The release build is plain
`cargo build --release` (`Makefile:45`). So the effective profile is the cargo
default: `opt-level=3`, **`lto = false`**, **`codegen-units = 16`**,
`panic = unwind`. The prior kills' premise is accurate and is not being
hand-waved.

**Consequence that cuts in this plan's favour:** the CGU-placement hazard is a
*cross-module-move* hazard. Every extraction in this plan is a **new `fn` in the
same file**, so no item migrates between codegen units. That is a materially
smaller exposure than #6386's sibling-module moves — which shipped anyway
(PR #6392, merged 2026-07-23).

### 2b. Measured ground truth at `dd23119aa` (release binary, built for this doc)

`cargo build --release` → 58 s. `nm -C --size-sort -S target/release/xpf-userspace-dp`:

| Symbol | Present? | Size |
|---|---|---|
| `afxdp::tx::dispatch::enqueue_pending_forwards` | **yes, out-of-line** | `0x6b6a` = **27,498 B** |
| `afxdp::worker::lifecycle::poll_binding` (its caller) | yes | 3,902 B |
| `select_exact_cos_guarantee_queue_waterfill` | **absent from `nm`** | — |
| `queue_service::service_exact_guarantee_queue_direct_with_info` | yes | 24,987 B |
| `queue_service::drain_shaped_tx` | yes | 19,974 B |

Two facts fall out of this, and they change the risk calculus for each half:

1. **The TX dispatch function is *already* an out-of-line call.** It is not
   inlined into `poll_binding`. So a hoist *inside* it cannot introduce a new
   call at the `poll_binding → enqueue_pending_forwards` boundary; the only
   question is the call-edge set **within** the 27,498-byte body — which is
   directly observable (§2c).
2. **The waterfill is not an out-of-line call from its caller.** It is absent
   from `nm` — consistent with inlining into its sole call site (`mod.rs:777`;
   it is a private `fn` carrying `#[inline]`), with ICF merging, or with symbol
   internalisation. All three yield the same operational conclusion, which is
   the only thing this plan relies on (SMR F6 — do not assert the mechanism).
   So the gate for the CoS half is: after the split,
   `select_exact_cos_guarantee_queue_waterfill` and its three new helpers must
   **still not appear** in `nm`, and
   `service_exact_guarantee_queue_direct_with_info` must stay within a stated
   size tolerance.

### 2c. The gate is executable *today* — demonstrated, not proposed

#4404's dispositive gate objection was *"the installed cargo-asm 0.1.16 panics
on these symbols"*. That objection is **obsolete**: #6386/PR #6392 established
the replacement (`objdump`/`nm` call-edge comparison) and shipped it. Both
tools are present on this host. Here is the gate, run against `dd23119aa`:

**r3 redesigned this gate. Read §2c-bis for why the r2 version was wrong.**
The extraction command is now:

```bash
cd userspace-dp/target/release
BIN=xpf-userspace-dp
ADDR=$(nm $BIN | grep -E ' t _ZN.*enqueue_pending_forwards17h[0-9a-f]+E$' | awk '{print $1}')
objdump -d --no-show-raw-insn $BIN \
 | awk -v a="^$ADDR <" '$0 ~ a {f=1} f&&/^$/{if(seen)exit} f{seen=1;print}' \
 | grep -oP 'call\s+[0-9a-f]+ <\K[^>]+' | sed 's/+0x.*//' \
 | sort -u                      # <-- NO normalisation. This is Tier 1.
```

The symbol address is resolved from `nm` at gate time, never hard-coded.

The baseline, with the command above run verbatim against `dd23119aa`, is
**51 raw call edges** out of `enqueue_pending_forwards`, checked in as
`callgraph-baseline-dd23119aa.txt`. They include
`build_forwarded_frame_from_frame`, `build_nat64_forwarded_frame`,
`segment_forwarded_tcp_frames_into_prepared`,
`enqueue_local_request_to_target_or_owner`, `recycle_ingress_frame`,
`apply_shared_recycles`, `handle_forward_build_failure`,
`classify_generated_reply`, `drain_pending_fill`. That set is the **baseline
artifact**; the PR must reproduce it byte-for-byte after the split.

### 2c-bis. Why r2's normalisation was wrong, and what replaced it

r2 normalised with two `sed` rules. **The `.llvm.<N>` strip was correct and
necessary in principle** — 5 of the 51 edges carry a CGU-content hash
(`publish_binding_debug_state`, `nat64_v6_translation_ineligible`, and three
`VecDeque::grow`). **The inherited Rust-hash strip `s/17h[0-9a-f]{16}E?$//` was
a blind spot**: it collapses the three distinct `VecDeque::grow`
monomorphisations into **one** identity, so the gate could not see a change
that swapped one generic instantiation for another. That is the r2 defect
fixed one rule over from the r2 fix.

Measured, and reproducible from the checked-in baseline:

```
distinct `grow` keys, Tier 1 (raw)      : 3
distinct `grow` keys, r2 rule (stripped): 1
```

**Two firsthand stability probes changed the design.** Codex reported a second
binary in which all five `.llvm.` suffixes moved while Rust hashes held. I could
not reproduce that for the change class this refactor belongs to. In a scratch
worktree (built, measured, then deleted — never pushed) I perturbed
`dispatch/mod.rs` twice and re-extracted:

| Probe | Perturbation | Raw 51-edge diff |
|---|---|---|
| P1 | added a dead `#[inline(always)] fn` | **0 lines** (weak — dead-stripped before CGU partitioning) |
| P2 | **moved an existing item within the file** (`copy_frame_is_oversized` → end of file) — the same in-file-motion class as the extraction, and not strippable | **0 lines** |

Neither the Rust hashes **nor** the `.llvm.<N>` suffixes moved. For this change
class the raw set is stable, so **normalising nothing is both the most sensitive
and the empirically-safe choice**. (The probes do not prove `.llvm.` can *never*
move — a cross-module move or a toolchain change plausibly would — which is why
the classifier below exists instead of a blanket strip.)

**Tier 1 (primary gate, must be empty):** raw 51-edge diff. No normalisation.
Distinguishes all three `grow` instances by construction.

**Tier 2 (diagnostic — consulted ONLY when Tier 1 is non-empty, never as an
auto-pass):** classify the failure so a red is actionable rather than
mystifying.

```bash
# 2a: is it CGU relabelling only?
diff <(sed -E 's/\.llvm\.[0-9]+$//' base.txt | sort -u) \
     <(sed -E 's/\.llvm\.[0-9]+$//' new.txt  | sort -u)
#   empty  -> CGU-relabel only. Record it in the PR body with the before/after
#             suffixes. NOT an automatic pass — a reviewer signs it off.
# 2b: same paths, different instantiation? (the `grow` class)
diff <(sed -E 's/\.llvm\.[0-9]+$//; s/17h[0-9a-f]{16}E?$//' base.txt | sort -u) \
     <(sed -E 's/\.llvm\.[0-9]+$//; s/17h[0-9a-f]{16}E?$//' new.txt  | sort -u)
#   empty  -> same callee paths, DIFFERENT monomorphisation. A real signal
#             that needs an explanation, never a shrug.
#   non-empty -> a genuinely new or removed callee. HARD FAIL.
```

**Proof the new rule fixes the blind spot** (rerunnable against the checked-in
baseline; a synthetic swap of one `grow` hash for a *valid lowercase* 16-hex
instantiation):

| Rule | Verdict on an instantiation swap |
|---|---|
| **Tier 1 (r3)** | **DETECTED** |
| r2 rule (both strips) | **MISSED** — blind spot confirmed |

**Negative control** (so the table above is not "everything fails"): a pure
`.llvm.<N>` relabel with no path change is **DETECTED** by Tier 1 and then
**correctly classified** by Tier 2a — the stripped diff vanishes, identifying it
as a relabel rather than a new callee. The two rows discriminate, which is what
makes the grid evidence.

*Method note:* the first attempt at this proof used an **uppercase** synthetic
hash, which the `[0-9a-f]{16}` strip does not match — so it appeared to show the
r2 rule catching the swap when the rule was simply not applying. Recorded because
it is the same self-deceiving-demonstration class the mutation grid in §7.2(c)
guards against.

### 2d. The safety principle that distinguishes this plan from the killed ones

> **This plan makes NO coldness claims and uses NO `#[inline(never)]`.**

#1697-v1, #4409(b) and #4404 all died the same death: they *asserted* a path was
cold, marked it `#[inline(never)]` / `#[cold]`, and the assertion was false
(FLOWLESS is per-packet for fragments; SESSION-MISS is amortised-hot under
deny-flood; the guard wrappers were on the cache-hit fast path). Every helper
extracted here is `#[inline(always)]` and same-module, so the post-inline IR is
by construction the shape it is today, and **no argument about which arm is hot
is load-bearing anywhere in this plan**. Coldness is not claimed, so it cannot
be wrong.

The residual risk after that is second-order — register allocation and stack
frame may still shift even when inlining is preserved. That is what the
throughput smoke leg in §7 is for, and it is stated as a real (if small)
residual, not argued away.

### 2e. The gate must be proven to fire

Per `feedback_guard_must_be_proven_to_fire`: the PR must include a recorded
**negative control** — temporarily flip one extracted helper from
`#[inline(always)]` to `#[inline(never)]`, rebuild, show the call-edge diff
**reports the new edge** (and, for the CoS half, that the helper appears in
`nm`), then revert. A gate nobody has watched fail is not evidence.

---

## 3. What already exists as a behavioural gate (no new test scaffolding needed)

This is where #4408 differs most sharply from #4404, whose kill partly rested on
"manual audit and multi-minute smoke must not be the only protection".

**`enqueue_pending_forwards` is directly unit-tested, at 5+ call sites:**

| File | Tests | LOC | Binds |
|---|---|---|---|
| `tests/enqueue_failure.rs` | 6 | 618 | mirror-clone accounting, Prebuilt fabric-redirect no-binding, **the cp2 Vec-copy fallback explicitly** (`:180`), enqueue-failure recycle |
| `tests/ptb.rs` | 9 | 631 | #2301 egress-MTU PTB end-to-end, oversized-original drop |
| `tests/segmentation.rs` | 13 | 497 | forwarded-TCP segmentation arms |
| `tests/cos_shared_exact.rs` | 6 | 218 | #1598 shared-exact owner policy |
| `tests/shared_recycle.rs` | 6 | 110 | cross-binding post-recycle |

**r3 caveat — this table is a test *inventory*, not a coverage proof.** Codex's
blocking objection to Increment 1 is precisely that the header comment at
`tests/enqueue_failure.rs:180` ("drive `enqueue_pending_forwards` through the
cp2 copy fallback") establishes *intent*, not that a named assertion would fail
if the cp1/cp2 or NAT64-attribution logic changed. Under Option B′ nothing here
is load-bearing — the dispatch half is deferred. When Increment 1 is
un-deferred, the §7.2 deferred grid is what converts this inventory into
coverage, and any cell without a named failing test must be written.

**The waterfill is bound by 18 tests** in `queue_service/tests/waterfill.rs` plus
`tests/refund.rs`, and — critically — **every one of them calls through the
wrapper** `select_exact_cos_guarantee_queue_with_lease_telemetry`, never the
waterfill directly. So a split of the waterfill's interior needs **zero test
edits**, and those 18 tests are the RED-on-revert gate for the fairness state
machine (epoch refill, honored-bitset persistence, phase2-cursor continuity,
#1743 livelock, #1630 residual starvation).

---

## 4. Invariants the plan must preserve, and how

| Invariant | Source | How this plan preserves it |
|---|---|---|
| **No-alloc / zero-copy on the non-NAT64 hot path** | issue | **Trivially held under B′: the TX frame-build path is not opened at all.** No extraction introduces a `Vec`, `clone`, or by-value move of a frame; the waterfill split moves no data (all state is `root` fields threaded by one `&mut`). *(Deferred Increment 1: the in-place and direct-TX arms stay in the cascade; the one extracted arm — Vec-copy fallback — allocates by definition. NAT64's per-packet `Vec` untouched and accepted.)* |
| **Single-recycle invariant** | #2208/#4041 | **Untouched under B′** — no ingress descriptor or TX frame is recycled anywhere in `queue_service`'s waterfill selector. *(Deferred Increment 1: all 8 `recycle_ingress_frame` sites are in the prologue/epilogue, outside the extracted region (§1b); the region contains zero executable `continue`/`return`, and the one `break` at :661 stays inside it; `free_tx_frames.push_front` in the direct-TX arm — the #4041 double-recycle — is likewise untouched.)* |
| **CoS guarantee-guard (shaped-class-held-under-BE-flood, #4246 class)** | issue | The waterfill split threads a single `&mut CoSInterfaceRuntime` through refill → phase1 → phase2 in the original order. No state is copied, snapshotted, or reordered. The #1743-r3 refill ordering is kept as one atomic block (§1a). Bound by the 18 unchanged waterfill tests. |
| **`trigger_kernel_arp_probe` allocation-freedom** | issue | **Out of scope** — it is not in either target function (grep: not in `dispatch/mod.rs` nor `queue_service/mod.rs`). Stated so the reviewer does not assume silent coverage; if the leader wants it re-verified that is a separate, cheap check. |
| **NAT64 drop attribution (#5625 ext-header, #2562 fragment)** | code | **Unchanged under B′** — it stays in two copies (:942–954 and :1264–1276). Fixing that was Increment 1's whole value, and it is deferred. Recorded as a *known, un-remediated* duplication hazard, not as a win this plan delivers. |

---

## 5. Path options, scored

Scoring: **Value** = LOC removed from the god-function + defect-class reduction.
**Risk** = probability of a behavioural or codegen regression that the gates miss.

### Option A — De-duplicate the copy-fallback only (Increment 1) — **DEFERRED in r3**

**Disposition: deferred, NOT rejected.** Codex: *"The de-dup is safe, but its
benefit is not strong enough to override the current hottest-path churn and
validation gaps."* The blocking condition is concrete and satisfiable — the
cp1/cp2 and NAT64-attribution coverage in §7.2's mutation grid must be
demonstrated to exist (or be added) **before** this increment is dispatched, not
asserted from the fact that `tests/enqueue_failure.rs:180` names the cp2 path.
The evidence below is preserved verbatim so whoever picks it up does not
re-derive it.

Extract :819–956 / :1155–1279 into one `#[inline(always)] fn
enqueue_copy_fallback_frame(...) -> (bool /*build_failed*/, bool /*fallback*/)`
in the same module.

- Arm D is **139 raw lines** (:819–957), arm E **125** (:1155–1279) = **264
  removed** from the body, replaced by two call sites of ~15 lines each. So
  `enqueue_pending_forwards` 1074 → **~840** LOC; the *file* 1608 → **~1524**
  (the ~150-line helper stays in it). (SMR F3 — r1 quoted ~940, which was
  simply wrong.)
- Removes a **proven 100-of-102-line duplication** and gives the NAT64
  attribution one owner
- No control-flow change; both call sites already set the same two flags
- `tests/enqueue_failure.rs:180` states it drives the cp2 copy fallback — but
  r3 treats that as a *claim to verify*, not coverage. Codex's blocking
  condition is exactly this: the cp1/cp2 and NAT64-attribution cells of §7.2's
  grid must be **demonstrated**, and any missing cell added, before dispatch.
- **Caveat (SMR F4):** the helper needs ~11 parameters (`target_binding`,
  `source_frame`, `request`, `expected_ports`, `is_nat64`, `&mut flow_key`,
  `dbg`, `counters`, `recent_exceptions`, `ingress_ident`, `forwarding`) —
  itself over the ">8 params" line this issue cites. Either bundle the
  per-request subset into a **by-reference** context struct (stack-only, so the
  no-alloc invariant is untouched) or state in the PR that an 11-param helper is
  accepted as strictly better than a 264-line duplication. Do not ship a new
  rule-violating signature silently inside a PR justified by that rule.

**Value 7 / Risk 2.** Best value-per-risk in the set.

### Option B — A + waterfill 3-way phase split (Increments 1 + 3) — **superseded by B′**

r2's recommendation. Blocked by Codex on its Option-A half only; the waterfill
half survived review intact. Retained here for the scoring comparison.

### Option B′ — waterfill 3-way phase split ONLY (Increments 3a + 3b) ← **RECOMMENDED (r3)**

`refill_waterfill_epoch` (74) + `waterfill_phase1_select` (181) +
`waterfill_phase2_select` (108), all `#[inline(always)]`, same module, with a
~30-LOC orchestrator. **Touches `cos/queue_service/mod.rs` only — the TX
hot-path file is not opened at all**, which is what retires the
"hottest-path churn" objection rather than arguing with it.

- waterfill 432 → **~30** LOC orchestrator + three named, individually
  reviewable phases
- `queue_service/mod.rs` stays ~2166 LOC (a split does not shrink a file) — the
  win is the *function*, not the file. Stated honestly.
- **Zero test edits**; 18 existing tests + `tests/refund.rs` bind the fairness
  state machine, and every one calls through the wrapper
- Exact `Option`-encoded control-flow correspondence (§1a)
- Codex, on r2: *"I would not kill the waterfill split. Its refill, Phase 1, and
  Phase 2 boundaries are real state-machine boundaries, and its value survives
  this review."*

**Value 8 / Risk 3.** (Down from B's 9 because the dispatch de-dup's
defect-class win is deferred out — the risk is unchanged.)

### Option C — B + hoist the whole build region :589–1295 into one helper (Increment 2b)

- `enqueue_pending_forwards` → ~370 LOC + one **~700-LOC** helper (measured
  against the pre-Increment-1 body; after Increment 1 the hoisted region is
  ~440 LOC)
- **Honest objection: this moves the god-function, it does not split it.** The
  700-LOC helper is still a god-function by the same rule. It buys a named
  boundary and an explicit 4-field outcome struct, making the recycle-invariant
  prologue/epilogue readable in isolation — that is a real but modest win.
- ~18-parameter signature; `#[inline(always)]` on a 700-LOC body is unusual and
  is the one place where register-allocation/stack-frame drift is plausible even
  with inlining preserved.

**Value 4 / Risk 6.** **Not recommended.**

### Option C′ — optional add-on: hoist the segmentation dispatch (:590–701)

Extract the `if tcp_segmentation_needed { … }` wrapper (~112 LOC, already
delegating to two extracted helpers) as `#[inline(always)]`, exporting
`copied_source_frame` + `build_failed`.

- `enqueue_pending_forwards` → **~730** LOC when combined with Increment 1
  (corrected per SMR F3; r1 said ~824)
- Bound by `tests/segmentation.rs` (13 tests)
- Weakest of the three: it is pure motion of an already-delegating block

**Value 4 / Risk 3.** Offered as the leader's call; not in the recommendation.

### Option D — Full responsibility split of the 4-way strategy cascade

**REJECTED on the record.** This is the #4404-killed shape: every arm is a live
per-packet traffic class, so outlining them forces per-packet `call`s on real
traffic. Listed here so a future pass does not re-propose it without engaging
§1c.

### Option E — Leave as-is, add tests

**Near-zero value.** The function already has ~40 direct-drive tests (§3);
adding more does not address the modularity defect the issue filed.

---

## 6. Recommended increment sequence (Option B′)

Two commits, one branch, **one file** (`cos/queue_service/mod.rs`).

1. **Increment 3a — `refill_waterfill_epoch`.** One block, unsplit (§1a
   ordering hazard: the `waterfill_epochs` bump / `epoch_boundary`-gated bitset
   clear / `epoch_wrap_pending = false` order is the #1743-r3 livelock fix).
2. **Increment 3b — `waterfill_phase1_select` + `waterfill_phase2_select`.**
   Both return `Option<ExactCoSQueueSelection>`; the wrap tail stays in the
   orchestrator.

**Deferred, with evidence preserved (§5-A):** Increment 1, the dispatch de-dup.
Its release condition is the §7.2 grid's cp1/cp2 + NAT64-attribution cells
being demonstrated to bind. **Not** sequenced: Options C, C′, D.

Sequencing note: Option B′ touches **only** `cos/queue_service/mod.rs` — check
for in-flight PRs against that file before dispatch
(`feedback_screen_for_contradicting_in_flight_pr`). `tx/dispatch/mod.rs` is not
opened, so the TX-side collision surface is zero.

---

## 7. Validation plan

**Must all pass before merge.**

1. `make test-rust` green (the full cargo suite, not a filtered subset; a pipe
   would launder the exit code — `feedback_piped_gate_launders_the_exit_code`).

2. **NOT parent-RED — a mutation grid.** (SMR F1, load-bearing.) Every
   increment here is behaviour-preserving *by construction*: reverting one
   restores semantically identical code, so **no test will fail on revert**.
   Demanding parent-RED would be an unsatisfiable gate that pushes an engineer
   toward calling a build break "RED" (forbidden by
   `feedback_red_on_revert_must_be_assertion_not_build_break`) or toward
   inventing a behaviour change to make something fail. Parent-RED answers *"does
   a test bind the fix?"*; there is no fix. The question that must be answered
   is **"is the lifted code genuinely exercised, or did I relocate code nothing
   checks?"** — and that is answered by mutating the extracted helper.

   **(a) Body identity.** `git diff --color-moved=dimmed-zebra` shows each
   extracted region as pure motion. The only permitted non-motion edits are the
   `cp1_len`/`cp2_len` → `cp_len` rename and the signature/call sites; anything
   else is listed line-by-line in the PR body.

   **(b) Mutation grid — each cell must produce a NAMED failing test.** Two
   mutations minimum per helper, because one fixture binds one match arm
   (`feedback_one_fixture_binds_one_match_arm`):

   **In scope for Option B′:**

   | Helper | Mutation | Must fail |
   |---|---|---|
   | `refill_waterfill_epoch` | remove the `epoch_boundary` gate on the bitset clear | the #1743-r3 livelock test |
   | `refill_waterfill_epoch` | reset `waterfill_phase2_cursor` in the refill | the #1630-r4 cursor-continuity test |
   | `waterfill_phase1_select` | drop the honored-bit set | the #1732 at-most-once-per-epoch test |
   | `waterfill_phase1_select` | charge `send_budget` instead of `phase1_cost` | the #1743-Hunk-B stable-quantum test |
   | `waterfill_phase2_select` | ignore the honored bitset | the descending-residual test |
   | `waterfill_phase2_select` | reset the cursor to 0 on each entry | the #1630-r4 continuity test (a *distinct* assertion from the refill cell above) |

   **Deferred with Increment 1 — this grid IS Codex's release condition for the
   de-dup** (§5-A). Each cell must be demonstrated, and any cell with no named
   failing test must be *added* before that increment is dispatched:

   | Helper | Mutation | Must fail |
   |---|---|---|
   | `enqueue_copy_fallback_frame` | delete the `nat64_exthdr_ineligible` attribution | the #5625 ext-header counter assertion |
   | `enqueue_copy_fallback_frame` | delete the `nat64_frag_dropped` attribution | a *distinct* named assertion (the #2562 arm — separate `else if` branch) |
   | `enqueue_copy_fallback_frame` | invert `copy_frame_is_oversized` | the #2208 oversized drop-and-recycle assertion |
   | `enqueue_copy_fallback_frame` | drop `fallback_to_slow_path = true` on enqueue-`Err` | the #2208 slow-path-reinject assertion |

   A helper for which **no** mutation produces a named failure is a helper whose
   contents are unbound. That must be **reported in the PR body**, not papered
   over — it is a finding about the existing test surface, and the increment
   should not ship until it is either bound or explicitly accepted.

   **(c) Negative control on the grid itself**
   (`feedback_prescribed_mutation_needs_a_negative_control`): record one
   mutation expected *not* to fail — e.g. reordering two independent counter
   increments — so a reader can tell the grid measures the code rather than
   reporting "everything fails".

3. **Codegen gate.** For Option B′ the CoS half is the one that matters; the
   dispatch edge set is a *control* (Option B′ does not open that file, so it
   must be bit-identical — a change there means something unexpected happened).
   - `nm` — `select_exact_cos_guarantee_queue_waterfill` and its three new
     helpers **absent**;
     `service_exact_guarantee_queue_direct_with_info` size within ±2% of
     24,987 B.
   - `objdump` — **Tier 1**: the **51 raw call edges** out of
     `enqueue_pending_forwards` match `callgraph-baseline-dd23119aa.txt`
     byte-for-byte, using the §2c command verbatim (dynamic address, **no**
     normalisation). Any non-empty diff goes to the §2c-bis Tier-2 classifier
     and is written up; it is never auto-passed.
4. **Negative control (§2e)** — recorded evidence that flipping one helper to
   `#[inline(never)]` makes gate 3 **fail**, then reverted.
5. **Throughput smoke** — `make cluster-deploy` + sustained v4 **and** v6 iperf3
   to `172.16.80.200` / `2001:559:8585:80::200`, plus the per-class CoS run
   after re-applying `apply-cos-config.sh` (deploy wipes CoS). This is the leg
   that covers the residual register-allocation risk §2d admits.
   **Scheduled by the leader — this research pass ran no cluster tooling.**

---

## 8. Risk table

| Class | Level | Rationale |
|---|---|---|
| Behavioural regression — dispatch | **N/A under B′** | Increment 1 is deferred; `tx/dispatch/mod.rs` is not opened. (Were it taken: LOW — a de-dup of two blocks agreeing on 100 of 102 lines, no control-flow change, 4-value export set verified, all 8 recycle sites outside the extraction — but gated on the §7.2 deferred grid, which is Codex's blocking condition.) |
| Behavioural regression — waterfill | **LOW-MED** | Fairness invariants are dense (#1743/#1732/#1630/#1628), but all state is on `root` and threaded in original order; refill kept atomic; 18 unchanged tests bind it. MED not LOW because the invariants are subtle enough that a reviewer must actually re-derive the `Option` correspondence rather than trust §1a. |
| Codegen regression | **LOW-MED** | Same-module only (no CGU migration); `#[inline(always)]` throughout; no coldness claim anywhere; executable `nm` + `objdump` gate with a proven-to-fire negative control, plus two firsthand stability probes (§2c-bis) showing the raw edge set unmoved by an in-file item move. Residual: register allocation / stack frame may shift even with inlining preserved — covered only by the smoke leg. |
| Scope mismatch with #4404 kill | **LOW** | §1c rejects the arm-decomposition shape explicitly; §2c retires the "no executable gate" objection with the #6386/PR-6392 methodology. |
| "Refactor does not reach the threshold" | **ACKNOWLEDGED** | B′ does not reduce `enqueue_pending_forwards` at all (stays 1074) and `queue_service/mod.rs` stays ~2166. Only the *function* shrinks, 432 → ~30. §9. |
| **Gate defect (any kind)** | **HIGH — the live risk in this plan** | Three rounds, three gate defects, zero refactor-design defects. See §8a; this is now the dominant risk class and the main argument for shipping small. |

---

## 8a. Three rounds, three gate defects, zero refactor defects

Worth stating plainly because it is the strongest argument in this document,
and it argues for a *smaller* increment rather than a bolder one.

| Round | Defect | Class | Would it have shipped a wrong binary? |
|---|---|---|---|
| r1 → r2 | parent-RED demanded for a behaviour-preserving refactor — **unsatisfiable** | gate | No — it would have blocked a correct refactor, or pushed an engineer to fake a RED |
| r1 → r2 | call-edge command missing the `.llvm.<N>` strip — **up to 5 false failures** on a pure-motion diff | gate | No — but it teaches the reader to hand-wave the gate, which is worse |
| r2 → r3 | inherited Rust-hash strip **collapses 3 `VecDeque::grow` instantiations to 1** — blind to an instantiation swap | gate | **Yes** — this one is a false *negative*. It would have passed a real change |
| any | a defect in the decomposition design itself | — | **None found in three rounds**, by me or by Codex |

Two things follow.

**The gate is the fragile artifact, not the refactor.** The escape-free interior
(§1b), the four-value export set, the `Option` control-flow correspondence
(§1a) and the `root`-only state ownership have all survived adversarial review
unchanged across three rounds and two reviewers. Every correction has landed on
the *instrument*, not the thing being measured. A plan whose measuring apparatus
has been wrong three times running should not be asked to carry a large change.

**Each fix has landed one rule away from the next defect.** r2 fixed the
`.llvm.` noise and inherited a blind spot in the adjacent rule; that is the
literal shape of this failure mode. r3's response is to stop normalising in the
primary key at all (§2c-bis Tier 1) — the sensitivity default — and push all
tolerance into an explicit, reviewer-signed classifier rather than a silent
`sed`. The correction to make next round is therefore most likely in the Tier-2
classifier, and a reviewer should look there first.

This is also why §7.2(c)'s negative control is not ceremony: the first attempt
at r3's own proof used an uppercase synthetic hash that the strip regex never
matched, and *appeared* to vindicate the r2 rule. A demonstration that cannot
fail proves nothing, and this document has now produced one.

## 9. The honest limitation

**Option B′ addresses one of #4408's two targets and leaves the other
untouched.** `enqueue_pending_forwards` stays at **1074 LOC** — the plan no
longer proposes to reduce it at all in this pass. What B′ claims is narrower and
fully supported:

- the **waterfill half is genuinely finished** — 432 → a ~30-LOC orchestrator
  plus three named, individually reviewable phases, with zero test edits and 18
  existing tests holding the fairness invariants;
- the **dispatch half is deferred with its analysis banked** (§5-A): a proven
  100-of-102-line duplication carrying the NAT64 drop attribution in two copies,
  an escape-free interior, and a four-value export set. None of that has to be
  re-derived by whoever picks it up.

`cos/queue_service/mod.rs` also stays at ~2166 LOC — splitting a function does
not shrink a file. The win is the *function*, not the file, and #4408's file
threshold is not met by this plan either.

**Disposition on merge:** re-scope #4408. Close the waterfill half with
evidence; keep the dispatch half open as a narrowly-worded successor whose
release condition is the §7.2 deferred grid — or fold it into #4404's
irreducible-core class if the coverage turns out not to exist. Leaving #4408
open indefinitely against a target this plan no longer proposes to touch is the
outcome to avoid.

**Where this plan is weakest.** Increment 1's value always rested on a
*maintenance* argument (one owner for the NAT64 attribution) rather than a
measurable one. Codex weighed that against hottest-path churn and unverified
coverage and came down against it; my own r1 SMR had already flagged the same
weakness unprompted. Two independent passes landing on the same line is the
reason r3 defers rather than argues. The waterfill split has no equivalent
weakness — and if even it is judged not worth the churn, the correct outcome is
PLAN-KILL of #4408 in full, not a smaller compromise.

---

## 10. Files

- `userspace-dp/src/afxdp/cos/queue_service/mod.rs` — Increments 3a/3b. **The
  only production file Option B′ opens.**
- `userspace-dp/src/afxdp/tx/dispatch/mod.rs` — **not touched** by B′
  (Increment 1 deferred). Its call-edge set is a *control* in §7.3.
- `docs/` — no module-doc change identified: neither
  `pkg/dataplane/README.md` nor `docs/fairness-regimes.md` describes these
  functions' internal structure, and no documented behaviour changes. Per
  CLAUDE.md, stating the reason rather than skipping silently. `_Log.md` gets
  the per-edit entries at `/engineer` time.

## 11. Open questions for the leader

1. **Does the deferred dispatch de-dup get a successor issue, or fold into
   #4404's irreducible-core class?** §9 recommends a successor whose release
   condition is the §7.2 deferred grid, but this is a scoping call, not a
   technical one.
2. **Option C′ (segmentation hoist) is now moot under B′** — it is a
   `tx/dispatch/mod.rs` change and B′ does not open that file. It rides with
   Increment 1 whenever that is un-deferred, or it is dropped. No action needed
   unless the leader wants it revived on its own.
3. Tier-2 of the §2c-bis classifier is the least-exercised part of this gate —
   it has a synthetic proof and a negative control, but no real failure has ever
   run through it. §8a argues that is where the next defect most likely lives.
