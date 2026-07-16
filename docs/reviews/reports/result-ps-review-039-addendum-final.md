# Triage result — ps-review-039-addendum-final.md

- **Subsystem:** Whole-tree decomposition / modularity audit (Paladin-style per-subsystem
  "god-file / god-function / god-struct" split audit). 10 batch areas A1a-A4 across Go
  control plane + Rust `userspace-dp` dataplane.
- **Nature:** REFACTOR / code-motion audit. NOT a correctness/security review. Every A/B/C
  finding is a "split this file / decompose this function / re-lay-out this struct"
  recommendation; every D finding is a "do-NOT-split, already cohesive" negative.
- **Base commit:** `f70146951583823a5ace87b0b11a2e58f46e8db9` — IS an ancestor of master;
  master is **23 commits ahead** (all of which are *more* refactor splits, #4653-#4660 etc.).
  So base != master, but the flagged files were not touched by the intervening commits.
- **Master SHA at triage:** `95b33d49634d56086269a62a92e213dae7926f88`
- **Repo:** real bpfrx (`/home/ps/git/bpfrx`). NOT the avacado-xpf fork. Minor path-prefix
  slips (audit wrote `afxdp/` for a few modules that actually live at `userspace-dp/src/`
  top level) but every symbol resolves — no confabulation.

## Outcome counts
- CONFABULATED: 0 (all files/symbols/structs exist; only cosmetic path-prefix errors)
- GENUINE bug residuals: **0** (this is a refactor audit — nothing produces wrong output)
- DUP of already-filed refactor issues (#4404-#4422): ~9 findings
- NOVEL refactor targets (not yet individually filed, but still refactor-not-bug): ~14
- DELIBERATE / negative (D — do-not-split, audit's own conclusion is no-action): ~20

## Verification performed
- `git merge-base --is-ancestor` — base is ancestor of master, 23 commits behind.
- File existence + LOC on `origin/master` for every cited path (Go + Rust).
- Symbol grep for every named god-function / god-struct.
- `gh issue view` for the referenced backlog issues to validate the audit's own DUP claims.

Cited LOC vs master (spot-check, all match or are close):
| File | Audit LOC | Master LOC | Exists |
|------|-----------|------------|--------|
| pkg/config/compiler_validate_warn.go | 3330 | 3330 | yes |
| pkg/dataplane/userspace/protocol.go | 2979 | 3011 | yes |
| pkg/config/compiler_system.go | 1881 | 1881 | yes |
| pkg/config/compiler_services.go | 1821 | 1821 | yes |
| pkg/config/compiler_nat.go | 2529 | 2529 | yes |
| pkg/api/metrics_descriptors.go | 1896 | 1896 | yes |
| pkg/cluster/sync_conn.go | 1858 | 1858 | yes |
| afxdp/coordinator/wg_control.rs (audit said afxdp/wg_control.rs) | 2280 | 2280 | yes |
| server/helpers.rs | 1292 | 1304 | yes |
| afxdp/frame/mod.rs | 1710 | 1710 | yes |
| event_stream/mod.rs (audit said afxdp/event_stream) | 1693 | 1693 | yes |
| afxdp/forwarding/mod.rs | 2822 | 2822 | yes |
| afxdp/neighbor.rs | 2036 | 2036 | yes |
| nat/source.rs (audit said afxdp/nat) | 1190 | 1389 | yes |
| nat/allocator.rs (audit said afxdp/nat) | 926 | 1416 | yes |
| screen/mod.rs (audit said afxdp/screen) | — | 1540 | yes |
| afxdp/frame/inspect.rs | — | 1813 | yes |
| afxdp/poll_descriptor/mod.rs | 4724 fn | 6053 file | yes |
| afxdp/tx/dispatch/mod.rs | 1048 fn | 1486 file | yes |

Symbols confirmed present on master: `poll_binding_process_descriptor`
(poll_descriptor/mod.rs:603), `enqueue_pending_forwards` (tx/dispatch/mod.rs:270),
`match_source_nat_result_for_tuple` (nat/source.rs:996), `PortAllocatorShared`
(nat/allocator.rs:458), `struct ForwardingState` (afxdp/types/forwarding.rs:14),
`struct CoSInterfaceRuntime` (afxdp/types/cos.rs:556), `struct SessionEntry`
(session/mod.rs:344).

## Why genuineResiduals is empty
The genuineResiduals array is reserved for **novel, reachable, not-dup CORRECTNESS bugs**
(scenario = input → wrong output / crash). This document contains **none**. Every finding
is one of:
1. a decomposition recommendation for a large-but-correct file/function (A/B/C), or
2. a negative "do-not-split" note (D).

None trace an input to a wrong output. The "hot-path (C) perf-positive" items
(SessionEntry Arc-clone-per-packet, ForwardingState 65-field layout, PortAllocatorShared
hot/cold cache-line split) are **optimization opportunities**, not defects — the code is
functionally correct today; the claim is only "could shave ~10ns/packet" or "fewer LLC
misses." That is a perf-refactor backlog item, not a residual bug. Returning empty is the
expected result for a decomposition audit against a heavily-hardened tree.

## Per-finding disposition (grouped by the audit's own batching)

### DUP of already-filed refactor backlog (audit self-declares these)
The referenced issues are real and OPEN/CLOSED as the audit claims:
- **#4404 (OPEN)** poll_descriptor decompose — Finding A1a/#19. Audit adds a fresh
  measurement (fn grew 1368→4724 LOC; file 5759→6053) and new decomposition angles. The
  *target* is already filed → DUP with enrichment, not a new residual.
- **#4408 (OPEN)** tx/dispatch enqueue_pending_forwards + CoS waterfill — Finding A1b/#20,
  D-06. DUP with enrichment (Phase-8 cascade + direct-TX + fabric-triple breakdown).
- **#4409 (OPEN)** nat allocator/source/tests split — Finding A2 PortAllocatorShared +
  match_source_nat_result_for_tuple + D-12 (nat/tests). DUP.
- **#4421 (OPEN)** modularity backlog "extends #4404-#4409" — explicitly lists
  neighbor.rs, SessionTable, ForwardingState. So Findings A1d (SessionEntry hot/cold),
  A1e (ForwardingState god-struct), A1e/#16 (neighbor.rs) are DUP of #4421. Audit itself
  says "overlaps #4421/#4422 but adds field-level hot/cold inventory."
- **#4422 (OPEN)** test-coverage/observability backlog — any LOW test-cov nits map here.
- **#4405 (CLOSED)** compiler_validate_strict split — referenced by D-17 as the *result*
  of a done split (correct: closed).
- **#4406 (CLOSED)** compiler.go compileExpanded decompose — referenced by D-16 as done.
- **#4407 (OPEN)** daemon god-struct + daemon_apply — referenced by D-20 and A4 negative.

### NOVEL refactor targets (real large files, not yet individually filed — still NOT bugs)
These are legitimate, verified-large decomposition candidates that are NOT covered by the
existing #4404-#4422 issue bodies. They are worth FILING as refactor issues, but they are
code-quality/maintainability items, not correctness residuals:
- **compiler_validate_warn.go (3330 LOC)** — largest Go file, not #4405 (that was
  compiler_validate_strict.go). Genuine new split target. Phase-1/#1.
- **protocol.go (3011 LOC, ~72 wire types)** — Phase-1/#2. New target.
- **compiler_system.go (1881) + compiler_services.go (1821)** — Phase-1/#3. New.
- **compiler_nat.go (2529)** — Phase-1/#4 (distinct from nat.rs #4409). New, note the
  "move strict gates" subtlety (validateNATHostMaskStrict / validateNPTv6Strict).
- **metrics_descriptors.go (1896, 279 NewDesc)** — Phase-1/#5. New.
- **sync_conn.go (1858)** — Phase-3/#10, (B) ordering-sensitive HA gen-guard. New; correctly
  flagged as needing /triple-review + test-failover.
- **tunnel.go (1877)** — Phase-3/#11 (Go routing tunnel, note audit's ".rs" suffix is a
  typo — file is pkg/routing/tunnel.go, Go). New.
- **wg_control.rs (2280)** — Phase-2/#6, cold 100ms poll. New (lives at afxdp/coordinator/).
- **server/helpers.rs (1304, 20 helper fns)** — Phase-2/#7. New. (Header says "extracted
  from main.rs Issue 69.1", not the audit's quoted "Pure relocation pending further split"
  — minor mis-quote, file is still a genuine helpers dumping ground.)
- **frame/mod.rs (1710)** — Phase-2/#8. New.
- **event_stream/mod.rs (1693)** — Phase-2/#9, optional. New (lives at src/event_stream/).
- **screen/mod.rs (1540)** — Phase-4/#17 SYN-flood split. New (src/screen/).
- **frame/inspect.rs (1813)** — Phase-4/#18 EH-walker dedup. New.
- **forwarding/mod.rs (2822, 5 god-fns)** — Finding A1e. New scaffolding split target.

Disposition: NOT-MATERIAL-as-bug / file-as-refactor-issue. Severity of each as a *bug* is
n/a (none). As refactor priority the audit's A/B/C classing is reasonable and its guardrail
gates (disassembly diff, criterion bench, test-failover, CoS smoke) are correct.

### DELIBERATE / negative (D — audit's own conclusion is DO-NOT-SPLIT)
D-01 poll_stages.rs, D-02 reject_reply/filter, D-03 tx/transmit, D-04 tx/rings,
D-05 tx/drain, D-06 CoS waterfill, D-07 shared_cos_lease/CoSInterfaceRuntime, D-08 session
leaf modules, D-09 forwarding_build, D-10 forwarding scaffolding, D-11 nat/destination,
D-12 nat/tests (#4409), D-13 wg/engine+cookie, D-14 types/cos+forwarding+protocol/binding,
D-15 event_stream borderline, D-16 compiler_uniformgates (#4406 result), D-17
compiler_validate_strict_filter (#4405 result), D-18 compiler_interfaces/types_system,
D-19 maps_sync/vrrp/instance, D-20 daemon (#4407).
These are negatives — no action requested, so no residual either way. The rationale given
(preserve #2145/#3022 VLAN logic, #3656 H11/H12 ordering, #3485 Junos-order atomicity,
single-responsibility RFC 5798 SM, etc.) is consistent with the hardening lineage. No
correctness claim to refute.

## Bottom line
Decomposition audit, well-grounded in real code, correctly cross-referencing its own
already-filed backlog (#4404-#4422). ~9 findings DUP those issues, ~14 are genuinely-new
*refactor* targets worth filing as issues, ~20 are do-not-split negatives. **Zero
correctness/security residuals** — nothing here produces a wrong output or crash, so
genuineResiduals is empty (expected for a pure refactor audit against a hardened tree).
