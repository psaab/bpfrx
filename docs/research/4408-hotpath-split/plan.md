# #4408 — Rust hot-path god-functions: `enqueue_pending_forwards` + waterfill

**Status:** PLAN-READY (r2) — recommending **Option B** (Increments 1 + 3),
explicitly **rejecting** the arm-decomposition shape that #4404 killed.

r2 folds seven findings from the hostile Claude SMR pass
(`claude-smr-plan-r1.md`), two of them load-bearing: **F1** — r1's §7 demanded
parent-RED for a behaviour-preserving refactor, which is unsatisfiable by
construction and is replaced by a mutation grid; **F2** — r1's call-edge gate
command produced up to 5 false failures because it did not strip LLVM CGU-hash
suffixes (verified against the real binary). Also corrected: the Increment-1
LOC arithmetic (F3), the new helper's parameter count (F4), the Phase-1 borrow
floor (F5), the `nm`-absence wording (F6), and the comment-merge checklist (F7).
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
```

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

After stripping comments and indentation and normalising the one differing
local name (`cp1_len` / `cp2_len`), both normalise to **102 identical lines**.
The only diff is the enclosing `None => match …` vs a bare `match …`:

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

```bash
cd userspace-dp/target/release
BIN=xpf-userspace-dp
ADDR=$(nm $BIN | grep -E ' t _ZN.*enqueue_pending_forwards17h[0-9a-f]+E$' | awk '{print $1}')
objdump -d --no-show-raw-insn $BIN \
 | awk -v a="^$ADDR <" '$0 ~ a {f=1} f&&/^$/{if(seen)exit} f{seen=1;print}' \
 | grep -oP 'call\s+[0-9a-f]+ <\K[^>]+' | sed 's/+0x.*//' \
 | sed -E 's/\.llvm\.[0-9]+$//; s/17h[0-9a-f]{16}E?$//' \
 | sort -u
```

**The two `sed` normalisations are both load-bearing (SMR F2).** The symbol
address is resolved from `nm` at gate time, never hard-coded. And **5 of the 51
baseline edges carry a `.llvm.<20-digit>` CGU-content hash** — measured, not
hypothesised:

```
…publish_binding_debug_state17h7f010bd79b36908cE.llvm.15104266154738188186
…nat64::nat64_v6_translation_ineligible17h45dae7fd1de716f1E.llvm.17871286219147243839
…VecDeque<T,A>::grow17h…E.llvm.17702975328697826035   (×3, distinct Rust hashes)
```

Adding a function to `dispatch/mod.rs` changes that CGU's content, so those
suffixes change. Without the `.llvm.` strip the gate reports up to 5 spurious
"new call edges" on a diff that is pure motion — which would either sink a
correct refactor or, worse, teach the next reader to hand-wave the gate's
output. **The comparison key is the demangled symbol path without hashes**, so
the gate detects a genuinely *new callee*, not a relabelled one.

The baseline, with the command above run verbatim against `dd23119aa`, is
**49 normalised call edges** out of `enqueue_pending_forwards` (51 raw; the
three `VecDeque::grow` monomorphisations collapse to one under normalisation).
They include
`build_forwarded_frame_from_frame`, `build_nat64_forwarded_frame`,
`segment_forwarded_tcp_frames_into_prepared`,
`enqueue_local_request_to_target_or_owner`, `recycle_ingress_frame`,
`apply_shared_recycles`, `handle_forward_build_failure`,
`classify_generated_reply`, `drain_pending_fill`. That set is the **baseline
artifact**; the PR must reproduce it byte-for-byte after the split.

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
| **No-alloc / zero-copy on the non-NAT64 hot path** | issue | No extraction introduces a `Vec`, `clone`, or by-value move of a frame. The in-place and direct-TX arms are **not** extracted (they stay in the cascade). The one extracted arm (Vec-copy fallback) already allocates by definition — that is what it is. NAT64's per-packet `Vec` is untouched and accepted. |
| **Single-recycle invariant** | #2208/#4041 | All 8 `recycle_ingress_frame` sites are in the prologue/epilogue, **outside** every extracted region (§1b table). The extracted regions contain zero `continue`/`return`. `free_tx_frames.push_front` recycling inside the direct-TX arm (the #4041 double-recycle) is likewise untouched. Bound by `tests/enqueue_failure.rs` + `tests/shared_recycle.rs`. |
| **CoS guarantee-guard (shaped-class-held-under-BE-flood, #4246 class)** | issue | The waterfill split threads a single `&mut CoSInterfaceRuntime` through refill → phase1 → phase2 in the original order. No state is copied, snapshotted, or reordered. The #1743-r3 refill ordering is kept as one atomic block (§1a). Bound by the 18 unchanged waterfill tests. |
| **`trigger_kernel_arp_probe` allocation-freedom** | issue | **Out of scope** — it is not in either target function (grep: not in `dispatch/mod.rs` nor `queue_service/mod.rs`). Stated so the reviewer does not assume silent coverage; if the leader wants it re-verified that is a separate, cheap check. |
| **NAT64 drop attribution (#5625 ext-header, #2562 fragment)** | code | *Improved*: today it exists in two copies (:942–954 and :1264–1276); Increment 1 gives it one owner. |

---

## 5. Path options, scored

Scoring: **Value** = LOC removed from the god-function + defect-class reduction.
**Risk** = probability of a behavioural or codegen regression that the gates miss.

### Option A — De-duplicate the copy-fallback only (Increment 1)

Extract :819–956 / :1155–1279 into one `#[inline(always)] fn
enqueue_copy_fallback_frame(...) -> (bool /*build_failed*/, bool /*fallback*/)`
in the same module.

- Arm D is **139 raw lines** (:819–957), arm E **125** (:1155–1279) = **264
  removed** from the body, replaced by two call sites of ~15 lines each. So
  `enqueue_pending_forwards` 1074 → **~840** LOC; the *file* 1608 → **~1524**
  (the ~150-line helper stays in it). (SMR F3 — r1 quoted ~940, which was
  simply wrong.)
- Removes a **proven 102-normalised-line duplication** and gives the NAT64
  attribution one owner
- No control-flow change; both call sites already set the same two flags
- Already covered by `tests/enqueue_failure.rs` (which explicitly drives cp2)
- **Caveat (SMR F4):** the helper needs ~11 parameters (`target_binding`,
  `source_frame`, `request`, `expected_ports`, `is_nat64`, `&mut flow_key`,
  `dbg`, `counters`, `recent_exceptions`, `ingress_ident`, `forwarding`) —
  itself over the ">8 params" line this issue cites. Either bundle the
  per-request subset into a **by-reference** context struct (stack-only, so the
  no-alloc invariant is untouched) or state in the PR that an 11-param helper is
  accepted as strictly better than a 264-line duplication. Do not ship a new
  rule-violating signature silently inside a PR justified by that rule.

**Value 7 / Risk 2.** Best value-per-risk in the set.

### Option B — A + waterfill 3-way phase split (Increments 1 + 3) ← **RECOMMENDED**

Adds: `refill_waterfill_epoch` (74) + `waterfill_phase1_select` (181) +
`waterfill_phase2_select` (108), all `#[inline(always)]`, same module, with a
~30-LOC orchestrator.

- waterfill 432 → **~30** LOC orchestrator + three named, individually
  reviewable phases
- `queue_service/mod.rs` stays ~2166 LOC (a split does not shrink a file) — the
  win is the *function*, not the file. Stated honestly.
- **Zero test edits**; 18 existing tests are the RED-on-revert gate
- Exact `Option`-encoded control-flow correspondence (§1a)

**Value 9 / Risk 3.**

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

## 6. Recommended increment sequence (Option B)

Each increment is a separate commit; the PR is one branch.

1. **Increment 1 — `enqueue_copy_fallback_frame`.** Extract the duplicated
   Vec-copy fallback. Body byte-identical to :819–956 modulo the `cp1_len` →
   `cp_len` rename; both call sites replaced by one call. `#[inline(always)]`,
   same module. Verify with `git diff --color-moved=dimmed-zebra`.
   **Checklist item (SMR F7):** arm D carries 37 comment lines and arm E 23;
   the *code* is identical but the rationales are phrased for different callers
   (in-place-`None` vs direct-TX-unavailable). The merged helper must carry
   **both** rationales, not whichever copy the engineer's editor had open.
2. **Increment 3a — `refill_waterfill_epoch`.** One block, unsplit (§1a hazard).
3. **Increment 3b — `waterfill_phase1_select` + `waterfill_phase2_select`.**
   Both return `Option<ExactCoSQueueSelection>`; the wrap tail stays in the
   orchestrator.

Deliberately **not** sequenced: Options C, C′, D.

Sequencing note: this touches `tx/dispatch/mod.rs` and
`cos/queue_service/mod.rs`. Check for in-flight PRs against either file before
dispatch (`feedback_screen_for_contradicting_in_flight_pr`).

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

   | Helper | Mutation | Must fail |
   |---|---|---|
   | `enqueue_copy_fallback_frame` | delete the `nat64_exthdr_ineligible` attribution | the #5625 ext-header counter assertion |
   | `enqueue_copy_fallback_frame` | delete the `nat64_frag_dropped` attribution | a *distinct* named assertion (the #2562 arm — separate `else if` branch) |
   | `enqueue_copy_fallback_frame` | invert `copy_frame_is_oversized` | the #2208 oversized drop-and-recycle assertion |
   | `enqueue_copy_fallback_frame` | drop `fallback_to_slow_path = true` on enqueue-`Err` | the #2208 slow-path-reinject assertion |
   | `refill_waterfill_epoch` | remove the `epoch_boundary` gate on the bitset clear | the #1743-r3 livelock test |
   | `refill_waterfill_epoch` | reset `waterfill_phase2_cursor` in the refill | the #1630-r4 cursor-continuity test |
   | `waterfill_phase1_select` | drop the honored-bit set | the #1732 at-most-once-per-epoch test |
   | `waterfill_phase2_select` | ignore the honored bitset | the descending-residual test |

   A helper for which **no** mutation produces a named failure is a helper whose
   contents are unbound. That must be **reported in the PR body**, not papered
   over — it is a finding about the existing test surface, and the increment
   should not ship until it is either bound or explicitly accepted.

   **(c) Negative control on the grid itself**
   (`feedback_prescribed_mutation_needs_a_negative_control`): record one
   mutation expected *not* to fail — e.g. reordering two independent counter
   increments — so a reader can tell the grid measures the code rather than
   reporting "everything fails".

3. **Codegen gate, both halves:**
   - `nm` — `select_exact_cos_guarantee_queue_waterfill` and its three new
     helpers **absent**;
     `service_exact_guarantee_queue_direct_with_info` size within ±2% of
     24,987 B.
   - `objdump` — the **49 normalised call edges** out of
     `enqueue_pending_forwards` are unchanged, using the §2c command verbatim
     (dynamic address + both `sed` normalisations).
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
| Behavioural regression — dispatch | **LOW** | Increment 1 is a de-dup of two byte-identical blocks with no control-flow change; 4-value export set verified; all 8 recycle sites outside the extraction; ~40 existing direct-drive tests. |
| Behavioural regression — waterfill | **LOW-MED** | Fairness invariants are dense (#1743/#1732/#1630/#1628), but all state is on `root` and threaded in original order; refill kept atomic; 18 unchanged tests bind it. MED not LOW because the invariants are subtle enough that a reviewer must actually re-derive the `Option` correspondence rather than trust §1a. |
| Codegen regression | **LOW-MED** | Same-module only (no CGU migration); `#[inline(always)]` throughout; no coldness claim anywhere; executable `nm` + `objdump` gate with a proven-to-fire negative control. Residual: register allocation / stack frame may shift even with inlining preserved — covered only by the smoke leg. |
| Scope mismatch with #4404 kill | **LOW** | §1c rejects the arm-decomposition shape explicitly; §2c retires the "no executable gate" objection with the #6386/PR-6392 methodology. |
| "Refactor does not reach the threshold" | **ACKNOWLEDGED** | After Option B, `enqueue_pending_forwards` is still ~840 LOC and `queue_service/mod.rs` is still ~2166 LOC. Neither crosses a threshold. §9. |
| Gate is unsatisfiable / gate cries wolf | **CLOSED in r2** | r1 shipped both defects: an unsatisfiable parent-RED (SMR F1) and a call-edge command with up to 5 false failures (SMR F2). Both replaced with verified-executable gates (§7.2, §2c). Listed here because "the plan's own gate was broken" is exactly the class a reviewer should assume is still present. |

---

## 9. The honest limitation

**Option B does not make #4408 "done" by any LOC threshold.** After it,
`enqueue_pending_forwards` is ~840 LOC — still more than eight times the
`docs/engineering-style.md` god-function line. The plan's claim is narrower and,
I think, more defensible:

- the **waterfill half is genuinely finished** (432 → ~30 orchestrator + three
  named phases), and
- the **dispatch half gets its one provable defect-class win** (a 102-line
  duplication with a two-copy NAT64 drop-attribution hazard), after which the
  residual joins #4404's *irreducible per-packet dispatch core* class.

The right disposition is therefore to ship Option B and then **re-scope #4408**:
close the waterfill half, and either close the dispatch half into the #4404
irreducible-core class or leave a narrowly-worded successor issue. Leaving
#4408 open indefinitely against a target that will never reach a threshold is
the outcome to avoid.

If the leader's judgement is that a ~840-LOC residual makes the whole exercise
not worth the churn, **Increment 3 alone (waterfill) is still worth shipping**
and is the cleanest single deliverable in this plan.

The SMR pass is candid about where Increment 1 is weakest: its value rests on a
**maintenance** argument (one owner for the NAT64 attribution) rather than a
measurable one. That argument is real — #5625 and #2562 each had to edit two
copies — but a reviewer who weighs churn-in-the-hottest-TX-function above
duplication-risk could reasonably land on "not worth it", and that reviewer
would not be wrong. Increment 3 has no such weakness.

---

## 10. Files

- `userspace-dp/src/afxdp/tx/dispatch/mod.rs` — Increment 1
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs` — Increments 3a/3b
- `docs/` — no module-doc change identified: neither
  `pkg/dataplane/README.md` nor `docs/fairness-regimes.md` describes these
  functions' internal structure, and no documented behaviour changes. Per
  CLAUDE.md, stating the reason rather than skipping silently. `_Log.md` gets
  the per-edit entries at `/engineer` time.

## 11. Open questions for the leader

1. Take Option C′ (segmentation hoist, 940 → ~824) or not? Scored 4/3 — a
   genuine call, not a recommendation.
2. On merge, re-scope #4408 per §9 — close-with-evidence on the waterfill half,
   and decide whether the dispatch residual becomes a successor issue or folds
   into #4404's irreducible-core class.
