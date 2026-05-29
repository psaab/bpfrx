# #1673 — Refresh top-level README after eBPF source-removal closeout

Status: v2 — AGY PLAN-NEEDS-MAJOR findings folded in; Codex sandbox
infra-blocked (3 attempts, `codex-linux-sandbox` cannot spawn);
Claude SMR concurs with AGY's in-scope findings.

## Issue framing

The top-level `README.md` drifted from `master` after the #1373 eBPF
retirement umbrella closed. It still presents legacy eBPF as a
selectable compatibility/regression forwarding backend chosen via an
explicit, *warned* `system dataplane-type ebpf`, and frames the
#1373/#1476 source-removal work as in-flight ("pending #1476", "before
BPF source removal", "during #1373 retirement"). The code now
**hard-rejects** explicit eBPF at both commit time and runtime, the
`bpf/xdp` and `bpf/tc` source trees are gone, and every #1373-family
issue (#1373, #1374-#1381, #1451, #1473, #1476, #1477, #1493) plus the
DPDK retirement (#1525) is CLOSED. `docs/userspace-dataplane-gaps.md`
also contradicts itself: its Deprecation Context (lines 12-20) and
Retirement-Work note (line 117) still say "accepted with a compile
warning", while its Fallback Mechanisms section (lines 151-157)
correctly states #1476 retired it with a hard reject.

This is a **documentation-only** change. No dataplane code, no
control-plane code, no behavior change. The design question for review
is purely framing accuracy:

> Post-#1476, the only runtime dataplane is userspace AF_XDP. The
> *retained* eBPF dependency is the userspace XDP shim
> (`userspace-xdp/`) plus the shared pinned-map bootstrap and
> `bpf/headers/*.h` — NOT a selectable legacy forwarding backend.

## Honest scope/value framing

The value is operator-facing accuracy: the README is the first
document a new operator reads, and it currently tells them they can run
`set system dataplane-type ebpf` (warned) to get the legacy path. That
config now fails `commit check` with `ErrEBPFDataplaneRetired`, and the
runtime factory returns `ErrEBPFBackendRetired`. The drift actively
misleads. There is no perf or churn tradeoff — it is a correctness fix
for prose. If reviewers conclude the rewrite over-corrects or
introduces a *new* inaccuracy, NEEDS-MAJOR/KILL is acceptable; the bar
here is "every retained README claim matches verified code".

## Verified drift (each confirmed against current origin/master)

1. **Hard-reject, not warn.** `pkg/config/compiler.go:37-40`
   (`ErrEBPFDataplaneRetired`, message "the legacy eBPF dataplane
   backend has been retired; use 'set system dataplane-type userspace'
   (see #1373)") + `:372-381` (`validateDataplaneTypeStrict` returns it
   on `dataplaneTypeEBPF`). Pinned by
   `pkg/config/parser_system_test.go:1401-1425`
   (`TestDataplaneTypeExplicitEBPFRejectsRetiredCompile`, asserts
   `errors.Is(err, ErrEBPFDataplaneRetired)`). Runtime:
   `pkg/dataplane/dataplane.go:44-47` (`ErrEBPFBackendRetired`) +
   `:200-206` (`NewRuntimeDataPlane` returns it for `TypeEBPF`). The
   parse path still *accepts* the token so `load merge`/`load override`
   of a pre-retirement config does not syntax-error — that is the only
   place eBPF survives, and it is a rolling-upgrade migration aid, not a
   forwarding backend.
   → README lines 5-10 (deprecation banner "now emits a compile
   warning"), 18-28 (selectable-backends framing), 69-80 (Legacy eBPF
   Dataplane section), 82-103 (comparison table "Legacy eBPF" column),
   126-127 (architecture bullet "remains available"), 262-268
   (Performance "eBPF dataplane … during #1373 retirement").

2. **#1373 family + #1476/#1477 are CLOSED** (verified via
   `gh issue view`). README must reframe them as closed retirement
   evidence and point any *remaining* hardening at OPEN issues (e.g.
   #1614 CoS regression, #1608 cold-path hardening), not closed
   feature-gap trackers.

3. **`bpf/xdp` and `bpf/tc` are gone.** `find bpf -maxdepth 3 -type f`
   shows only `bpf/headers/*.h` + `bpf/headers/README.md`. README
   code-layout rows 328-329 list both deleted dirs as "pending #1476
   source removal".

4. **`make generate` no longer builds bpf2go bindings.**
   `Makefile:18-22`: `generate` runs only `$(GO) generate
   ./pkg/dataplane/...` which post-#1476 emits the retained Rust AF_XDP
   shim object; `:24-31` keeps `generate-userspace-xdp` as the alias.
   README Quick Start line 192 says "Generate Go bindings from BPF C
   (requires clang + bpf headers)".

5. **gaps.md self-contradiction.** `docs/userspace-dataplane-gaps.md:19`
   ("accepted only with a compile warning"), `:117` ("emits an
   operator-visible compile warning while legacy source removal is
   staged") vs `:151-157` (correct hard-reject). Section headers at
   `:56` / inline "before BPF source removal" wording frame closed work
   as pending.

## Concrete design (rewrite, not delete)

### v2 additions from AGY PLAN-NEEDS-MAJOR (all verified against code)

- **README:49-50** "fail closed rather than silently falling back to
  legacy eBPF" → there is no eBPF to fall back to; reframe to "fail
  closed rather than bypassing policy/NAT/conntrack".
- **README:51-53** names `xdp_main_prog`, deleted in #1476. Reframe the
  degraded-mode sentence to describe behavior (keeps the legacy
  in-kernel forwarding program out of the path) without naming the
  deleted program.
- **README:163** "legacy BPF pins remain for explicitly selected eBPF
  compatibility" → eBPF cannot be selected; drop the clause. The real
  remediation is daemon config-only mode
  (`pkg/daemon/daemon_run.go:309-324` catches `ErrEBPFBackendRetired`).
- **README:175** "BPF map occupancy on eBPF" → userspace-only buffer
  view (already in v1 design, restated).
- **README:390** clang/llvm "for legacy BPF compilation" → for the
  retained userspace XDP shim object only (already in v1, restated).
- **gaps.md:15-16** "No BPF source, bpf2go bindings, loader code, test
  targets, or CLI surfaces are removed in this phase." is now
  blatantly false post-#1476. Replace with: the #1476 source-removal
  phase deleted legacy BPF source, bpf2go bindings, and legacy loader
  targets, retaining only the userspace AF_XDP shim + `bpf/headers`
  bootstrap. (This is the in-tree fix AGY HIGH-2 requires.)

### CLAUDE.md disposition (AGY CRITICAL-1)

AGY is correct that `CLAUDE.md:5-9` and `:50` still say "the legacy
eBPF dataplane remains in-tree … remains as the legacy compatibility
and regression path" — stale post-#1476. However, the #1673 task scope
explicitly constrains this PR to `README.md` + `docs/userspace-
dataplane-gaps.md` + this plan doc (disjoint from #1635/#1666/#1661).
Pulling `CLAUDE.md` in would cross that boundary. Disposition: leave
`CLAUDE.md` out of this PR and record the residual `CLAUDE.md:5-9/50`
drift as an explicit follow-up note in the PR body so it is not lost.
The README + gaps.md become internally consistent and code-accurate;
CLAUDE.md remains a separately-tracked follow-up.

### Parser-leniency nuance (confirmed)

`pkg/config/compiler.go:1126-1133` (`validDataplaneType`) returns true
for `ebpf`, so `load merge`/`load override` of a pre-retirement config
parses cleanly; the hard reject fires at compile/commit
(`validateDataplaneTypeStrict`). The README/gaps.md should state this
so operators doing rolling upgrades understand: old configs parse, but
`commit check` hard-fails with `ErrEBPFDataplaneRetired` and the
remediation is `set system dataplane-type userspace`.

README:
- **Banner (5-10):** replace "remains in-tree … emits a compile
  warning … Later phases own source/loader/build/CLI removals" with a
  closed-state notice: userspace AF_XDP is the only runtime dataplane;
  the eBPF retirement (#1373, source removal #1476) is complete; the
  retained eBPF artifacts are the userspace XDP shim + `bpf/headers`
  bootstrap.
- **Dataplane Architecture (16-28):** drop "selectable backends"
  framing. State userspace AF_XDP is the only forwarding path; explicit
  `system dataplane-type ebpf` is hard-rejected at commit
  (`ErrEBPFDataplaneRetired`) and runtime (`ErrEBPFBackendRetired`);
  remediation is `set system dataplane-type userspace` (or omit the
  knob). Note the parser still *accepts* the legacy token only so
  rolling-upgrade `load` of an old config does not syntax-error.
- **Legacy eBPF Dataplane section (69-80):** convert to a short
  **Historical note** subsection — the 14-program tail-call pipeline and
  the 25+ Gbps figure move here as history, with a `git log -- bpf/xdp/
  bpf/tc/` pointer (mirrors CLAUDE.md). Not an "available backend".
- **Comparison table (82-103):** retitle/repurpose so it is not
  "Legacy eBPF vs userspace" as if both are runnable. Either drop the
  Legacy column or relabel it "Legacy eBPF (retired, historical
  parity)". Remove "before BPF source removal" evidence caveats from
  rows 102/108/111 — those closed with #1374/#1375/#1376/#1477; reframe
  remaining caveats as production hardening linked to OPEN issues.
- **Architecture bullets (123-129):** "Legacy eBPF dataplane remains
  available" → retired; the retained eBPF dep is the shim/headers
  bootstrap. Three-phase compilation no longer targets "legacy map
  entries".
- **Quick Start (192):** `make generate` comment → "Generate retained
  Rust AF_XDP userspace XDP shim object (post-#1476; no legacy bpf2go)".
- **Performance (260-273):** move the eBPF perf block under a
  historical heading; keep it as a legacy figure, remove "during #1373
  retirement".
- **Code Layout (327-329):** delete the `bpf/xdp/*.c` and `bpf/tc/*.c`
  rows; keep/clarify the `bpf/headers/*.h` row (shared C structs for the
  retained shim + parity tests). The `userspace-xdp/` row already
  exists (335).
- **`pkg/dataplane/` row (333):** "temporary legacy eBPF compatibility"
  → retirement-error sentinels + retained shim embed.
- **Requirements (390):** "clang/llvm (for legacy BPF compilation and
  XDP shim generation)" → clang/llvm for the retained XDP shim object
  generation.
- **Observability bullet (175) + buffers:** "BPF map occupancy on eBPF"
  is now historical; reframe to the userspace UMEM/TX-ring view (the
  only runtime path).

gaps.md (minimal, surgical — do NOT touch the SNAT row at line 40 or
any doc-guard token):
- **Deprecation Context (12-20):** rewrite the last two sentences so
  "Explicit `system dataplane-type ebpf` is accepted only with a compile
  warning" becomes the hard-reject contract, consistent with the
  already-correct lines 151-157. Reframe "while the source-removal
  blockers close" as "the source-removal phase (#1476) is complete".
- **Line 117:** "explicit `system dataplane-type ebpf` emits an
  operator-visible compile warning while legacy source removal is
  staged" → hard-reject contract; #1474 closed.
- **Section header line 56 / "before BPF source removal" inline
  wording:** reframe the closed #1373/#1476/#1477 work as completed
  retirement rather than pending. Keep the table content (it is
  accurate as a record); only fix the "pending/before removal" tense.
- The "Current Retirement Work After Feature-Gap Closeout" table
  (107-129) lists #1451/#1473/#1493/#1476/#1477 as "tracked removal
  work" — all closed. Reframe as completed-removal record.

## Doc-guard preservation (hard constraint)

Two guards read gaps.md:

1. `userspace-dp/tests/snat_contract_doc_guard.rs` —
   `assert_current_capability_doc_matches_fail_closed_contract` requires
   gaps.md to contain `poll_descriptor.rs`/`mod.rs`, "Source NAT",
   "pool", **"fail-closed"**, "source-NAT call sites", "missing pools",
   "empty pools", "invalid port", "persistent-nat", "exhaustion
   counters" (all in the SNAT row, line 40 — UNTOUCHED), and forbids
   "runtime remains fail-open", "source-NAT call sites can fall
   through", "forward without SNAT", "claim userspace pool-mode SNAT is
   fail-closed". My edits are confined to the eBPF-retirement prose
   (12-20, 56-59 tense, 117, 107-129 tense) and never touch line 40 or
   introduce any forbidden string.
2. `pkg/dataplane/retirement_boundary_canary_test.go`
   `TestActiveDocsDescribeRetainedShimCountersAsDegradedPath` — scans
   gaps.md for fallback wording: forbids `fallback_counters` /
   `userspace_fallback_stats` (without "compatibility" within window),
   "xdp fallback stats", "fallback counters", "fallback reason", "went
   via fallback". My rewrite must NOT introduce any of these phrases.
   The same guard scans the #1373 retirement README
   (`docs/pr/1373-...`) — which I am NOT editing.

Note: `retirement_boundary_canary_test.go` also pins positive tokens in
the `docs/pr/1373-retire-ebpf-dataplane/README.md` (lines 1700, 1751) —
that is a *different* file from the top-level `README.md` I am editing;
no overlap.

Validation: full `cargo test --release` from `userspace-dp/` (guard
manifest is there) — `snat_contract_doc_guard` must stay GREEN; full
`go test ./...` — `retirement_boundary_canary_test` must stay GREEN. 5/5
flake on both touched guards.

## Hidden invariants

- Do not change the meaning of the SNAT pool fail-closed contract row.
- Do not break the `fail-closed` literal token (#1670).
- Do not introduce fallback-wording forbidden by the canary.
- Keep gaps.md table content factually intact; only fix retirement tense
  and the warn→hard-reject statement.
- README must not claim any OPEN-issue hardening links to a CLOSED
  #1373-family issue.

## Risk assessment

| Class | Level | Note |
|-------|-------|------|
| Behavioral regression | NONE | docs only |
| Lifetime/borrow | N/A | no code |
| Performance | NONE | no code |
| Doc-guard regression | MED→mitigated | two guards read gaps.md; edits confined away from their tokens; full cargo+go suites + 5/5 flake gate |
| Accuracy mismatch (the real risk) | MED→mitigated | every claim re-verified against file:line above; reviewers gate on doc-vs-code |

## Test plan

- `rg -n "compile warning|pending #1476|during #1373 retirement|before BPF source removal|legacy eBPF dataplane remains available" README.md docs/userspace-dataplane-gaps.md` → empty.
- README code-layout rows match `find bpf -maxdepth 3 -type f` (only `bpf/headers`).
- Quick Start `make generate` text matches `Makefile:18-22`.
- Closed #1373-family framed as closed; remaining hardening links OPEN issues only.
- `cargo test --release` from `userspace-dp/` green; `snat_contract_doc_guard` 5/5.
- `go test ./...` green; `retirement_boundary_canary_test` 5/5.

## Out of scope

- CLAUDE.md (`:5-9` / `:50` are stale per AGY CRITICAL-1, but the
  #1673 task scope is README.md + gaps.md only; recorded as a PR-body
  follow-up note instead of edited here).
- The `docs/pr/1373-retire-ebpf-dataplane/README.md` retirement doc.
- Any code change. Any cluster smoke (doc-only, no dataplane code).
- #1635 (histogram), #1666 (maps_sync.go), #1661-item8 (audit/scripts).

## Open questions for adversarial review

1. Should the comparison table keep a "Legacy eBPF (retired)" column at
   all, or is keeping it — even relabeled — itself misleading now that
   eBPF cannot run? Drop vs relabel?
2. Is "the parser still accepts the `ebpf` token for rolling-upgrade
   `load`" an accurate and useful nuance to state in the README, or
   does it re-muddy the hard-reject message? (Code: parse accepts,
   compile rejects.)
3. gaps.md's whole "Gated Or Evidence-Only Before BPF Source Removal"
   framing is now retrospective (#1477 closed). Reframe tense only, or
   does the section need a stronger "retirement complete" reframing to
   avoid implying pending work?
4. Does relabeling break either doc-guard via an unanticipated token?
   (Verified no, but hostile re-check requested.)
5. Are #1614/#1608 the right OPEN issues to cite for "remaining
   production hardening", or should the README avoid issue-linking
   hardening entirely and just say "see userspace-dataplane-gaps.md"?
6. Is moving the 25+ Gbps eBPF figure to a historical note the right
   call, or should it be deleted outright since the path can't run?
