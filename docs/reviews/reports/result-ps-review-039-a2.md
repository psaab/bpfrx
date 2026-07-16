# Triage result — ps-review-039-a2

- **Subsystem:** NAT (Rust `nat/*.rs` + `nat64.rs`/`nptv6.rs` + Go `pkg/config/compiler_nat.go`) — Paladin per-subsystem **monolith/refactor** audit (A2 batch).
- **Base == master?** YES. Review base `f7014695` is an ancestor of current master and the audited files are byte-identical in size (allocator 1416, source 1389, destination 1088, static 793, mod 297, nat64 2527, nptv6 431, compiler_nat.go 2529, lib.rs 1541 — every LOC count matches the review's inventory exactly).
- **Master SHA:** `95b33d49634d56086269a62a92e213dae7926f88`
- **Repo:** real bpfrx (`psaab/xpf`). All cited symbols/line numbers resolve on `origin/master` (PortAllocatorShared:458, AddressOccupancy:284, PortAllocatorLiveState:258, allocate_translation:686, reserve_flow:1206, match_source_nat_result_for_tuple:996, compileNATSource:1342, validateNPTv6Strict:536). NOT the avacado fork.
- **Outcome counts:** 5 findings → 0 GENUINE-RESIDUAL / 2 NOT-MATERIAL+DUP (A2-1, A2-2) / 1 NOT-MATERIAL+partial-DUP-w/miscite (A2-3) / 2 DELIBERATE-NEGATIVE (A2-4 no-op, A2-5 already-done).

## Framing

Every finding in this file is a **refactor / code-health / modularity proposal**, not a correctness defect. None trace an input→wrong-output path; none are reachable bugs. A2-4 and A2-5 are explicitly authored as NEGATIVE (do-not-split) findings. The three actionable proposals (A2-1/2/3) each self-declare as overlaps of existing open refactor issues. Per review-triage discipline, refactor findings that duplicate tracked modularity backlog are NOT genuine residuals (the residuals schema is for novel reachable bugs). genuineResiduals is therefore empty — the expected result for a hardened subsystem's monolith audit.

## Per-finding disposition

### A2-1 — allocator.rs PortAllocatorShared hot/cold god-struct → NOT-MATERIAL + DUP (#4409)
- **Verified real symbol:** `struct PortAllocatorShared` (allocator.rs:458), `AddressOccupancy` (:284), `PortAllocatorLiveState` (:258) all present exactly as cited; `allocate_translation` at :686, `reserve_flow` at :1206.
- **Why not genuine:** This is a performance-positive *refactor proposal* (split hot bitmap into `#[repr(align(64))]`, keep cold behind Arc/Mutex). It describes a *potential* false-sharing footgun, not a demonstrated wrong-output or measured regression — the review itself gates the whole thing behind "must not regress vs the #2852 Phase-1 baseline" and offers no evidence current layout regresses. No behavior is incorrect; the code is zero-alloc/lock-free on the claim path today.
- **Why DUP:** Verified via `gh` — **#4409 is OPEN**: "refactor: Rust NAT modules — nat/allocator.rs PortAllocator god-struct (926 LOC) + nat/source.rs (1,190) + nat/tests.rs (split per module)". The finding's own dedup note admits "Overlaps #4409 ... Not a duplicate — enriches #4409." It is the same file/same concern already tracked; the extra `#[repr(align)]` detail is a comment on #4409, not a new residual.
- **Severity justification:** N/A as a bug (code health). If pursued it belongs on #4409 as a perf-positive enrichment; no availability/correctness/security exposure.

### A2-2 — source.rs match_source_nat_result_for_tuple 336-LOC god-function → NOT-MATERIAL + DUP (#4409)
- **Verified real symbol:** `match_source_nat_result_for_tuple` at source.rs:996; `no_translation` field (:268) and the three PAT arms reading `tuple_unknown && !rule.no_translation` at :1167/:1219/:1276 all present — confirming the layered #3906/#4074/#4088 logic the finding describes is on master.
- **Why not genuine:** Pure structural-refactor proposal (extract `classify_l4_mode` enum + `allocate_pool_v4/v6`). No bug: the function is correct today, zero-alloc on the cold session-miss path. The finding's own "why it matters" is a *future-regression-risk* argument ("makes the next protocol addition a compile-time match-arm"), i.e. maintainability, not a present defect. `classify_l4_mode` does not exist yet — it is the *proposed* extraction, not a claim of missing behavior.
- **Why DUP:** Same #4409 (OPEN) covers "nat/source.rs (1,190 LOC)". Dedup note admits overlap ("Complements #4409"). Same file/concern already tracked.
- **Severity justification:** N/A as a bug. Belongs on #4409.

### A2-3 — compiler_nat.go 2529-LOC file split → NOT-MATERIAL + partial-DUP #4421 (dedup miscites #4056)
- **Verified real symbol:** `compileNATSource` (:1342), `compileNAT` (:831), `compileNAT64` (:956), `validateNATHostMaskStrict` (:287), `validateNPTv6Strict` (:536) all present; file is 2529 LOC as claimed.
- **Why not genuine:** Explicitly class-(A) MECHANICAL "pure code-motion, no logic change, no behavior change." Compile-time only, no hot path. Splitting a large-but-correct file is code health, never a residual bug.
- **DUP / miscite:** #4421 is OPEN ("Refactor/modularity backlog from audit ... rules.go") — a legitimate umbrella for this Go config-layer split, so partial-DUP holds. **However the dedup note miscites #4056**: I checked — **#4056 is CLOSED and is a *secrets-leak* issue** ("rollback slots / rescue.conf write FULL config incl IKE PSK as 0644 plaintext", fable-161 F-050), NOT a "NAT compile/validate 5-file-scattered" refactor. The finding's claim of "partial overlap with #4056" is a wrong citation. This does not create a residual — the finding itself is still just a mechanical split tracked under #4421 — but the dedup provenance is inaccurate and should not be trusted if filing.
- **Severity justification:** N/A as a bug (Low code-health per the review's own rating). No correctness exposure.

### A2-4 — destination.rs is cohesive, do NOT split → DELIBERATE / NEGATIVE (agreed)
- **Verified:** destination.rs is 1088 LOC on master (under the ~2000 smell threshold); the finding is authored as class-(D) NO-OP.
- **Disposition:** The reviewer recommends *no action* and gives a sound anti-split rationale (splitting exact/prefix would drift the insert-vs-match dedup invariant, #704 class). Nothing to fix, nothing to file. Confirmed correct on master. No residual.

### A2-5 — nat/tests already split per #4409 → ALREADY-DONE (verified) / NEGATIVE (agreed)
- **Verified on master:** monolithic `userspace-dp/src/nat/tests.rs` is **absent** (`git cat-file` → not in origin/master), and the 8 split files exist exactly as listed: `tests_pool.rs`, `tests_destination.rs`, `tests_static.rs`, `tests_l4_match.rs`, `tests_scope.rs`, `tests_source.rs`, `tests_dnat_proto.rs`, `tests_counter.rs`. This is the "tests.rs (split per module)" work referenced in #4409's title — already landed.
- **Disposition:** Reviewer classifies as NO-OP / directly closes the tests-dumping-ground portion of #4409. Ground-truth confirms the split is done. No residual, no further action.

## Bottom line
No novel, reachable, non-dup correctness bug anywhere in this batch. The subsystem is well-hardened (matches the ps-038 "~0 residuals in core scopes" expectation). The two/three actionable refactors are already tracked by open issues #4409 (Rust NAT allocator/source/tests) and #4421 (Go modularity backlog); the negatives (A2-4/A2-5) are correct as authored, with A2-5 verified already-complete on master. Only note worth flagging if the findings are ever filed: A2-3's dedup note cites #4056, which is actually a closed secrets-leak issue, not the NAT-compile-split issue it claims — use #4421 instead.
