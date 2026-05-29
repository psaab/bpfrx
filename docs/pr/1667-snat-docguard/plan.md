# #1667 — Fix red doc-guard `snat_contract_documents_current_fail_closed_runtime`

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)

## Issue framing

`cargo test --release` fails one test on pristine `origin/master`:
`snat_contract_documents_current_fail_closed_runtime`
(`userspace-dp/tests/snat_contract_doc_guard.rs`). The guard requires
`docs/userspace-dataplane-gaps.md` to contain the literal hyphenated
token `fail-closed`; `git show origin/master:docs/userspace-dataplane-gaps.md
| grep -c fail-closed` = 0. The issue asks: decide whether this is
**doc-drift** (runtime is fail-closed, the doc lost the accurate token)
or a **stale guard** (the contract moved / guard points at the wrong
doc), then either restore the doc or retarget/retire the guard. Do NOT
string-stuff `fail-closed` to silence the test — the documented claim
must match reality.

## Decision: doc-drift (single dropped hyphen), not a stale guard

Verified end to end:

### The guard is current and correct
`snat_contract_doc_guard.rs` asserts a coherent, still-true contract
across four artifacts:
1. Runtime (`userspace-dp/src/afxdp/poll_descriptor/mod.rs`): exactly
   four `source_nat_decision_for_flow(` call sites, each of which must
   have `Err(failure)` + `record_source_nat_failure(` within a 32-line
   window (i.e. each must record a fail-closed failure before
   forwarding / session creation). It also forbids the legacy
   `match_source_nat_for_flow(...)` Option helper and any
   `unwrap_or_default()` fail-open handling.
2. Plan doc (`docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md`):
   required tokens incl. `fail-closed` (count = 5, present).
3. `docs/userspace-dataplane-architecture.md`: required tokens incl.
   `fail-closed` (count = 3, present).
4. `docs/userspace-dataplane-gaps.md`: required tokens incl.
   `fail-closed` (**count = 0 — the only failure**). The other eight
   required tokens (`Source NAT`, `pool`, `source-NAT call sites`,
   `missing pools`, `empty pools`, `invalid port`, `persistent-nat`,
   `exhaustion counters`) and the path token `poll_descriptor.rs` are
   all present. All four forbidden stale strings ("runtime remains
   fail-open", "source-NAT call sites can fall through", "forward
   without SNAT", "claim userspace pool-mode SNAT is fail-closed") are
   absent.

So the guard fails on exactly one missing token in one of three docs.
The guard is not stale: it points at live files, the runtime call-site
count is exactly 4 (verified), and each call site does the fail-closed
record (verified at mod.rs:1481/1511/2559/2588 → matching
`Err(failure) => record_source_nat_failure(...)`).

### The runtime genuinely IS fail-closed (claim is TRUE)
`source_nat_decision_for_flow` (mod.rs:43-66) returns
`Err(SourceNatFailure)` for `SourceNatLookup::Unavailable(failure)`
(missing/empty/invalid-port/malformed/no-family/exhausted pools).
Every one of the four call sites matches `Err(failure)` and calls
`record_source_nat_failure` (which bumps exception counters and records
a recent exception) — the packet is NOT forwarded without SNAT. This
exactly matches the gaps.md line-40 prose, which already says the pool
runtime "fail**s** clos**ed** at the `poll_descriptor.rs` source-NAT
call sites before session creation or forwarding".

### Root cause of the drift (single hyphen)
`git log -S fail-closed -- docs/userspace-dataplane-gaps.md` shows the
line previously read "now **fail-closed** at the `poll_descriptor.rs`
source-NAT call sites" (commits `8280e3441` #1417, `c0a047ea2`). The
later reword in `c0a047ea2` ("userspace: add persistent SNAT pool
leases") rewrote that sentence to "fail **closed** at the
`poll_descriptor.rs` ..." — dropping the hyphen — and broadened the
wording for exhaustion/persistent-nat. That commit did not run the
doc-guard, so the hyphen loss went unnoticed. The runtime behavior was
unchanged; only the doc token drifted.

## Concrete change

One-token correction in `docs/userspace-dataplane-gaps.md`, Source NAT
(pool mode) row: change "... or exhausted live translated tuples **fail
closed** at the `poll_descriptor.rs` source-NAT call sites ..." to
"... **fail-closed** at the `poll_descriptor.rs` source-NAT call sites
...". This restores the hyphenated token the guard (and the parallel
architecture.md / plan doc wording) require, and keeps the sentence
grammatical and accurate ("fail-closed" used adjectivally describing
the behavior at the call sites — identical phrasing to the historical
line and to the guard's sibling-doc requirement).

No other doc edits are needed: all other required tokens and the
absence of all stale tokens are already satisfied in gaps.md, and
architecture.md + the plan doc already contain `fail-closed`.

No code change. No guard change (the guard is correct as written).

## Why not retarget/retire the guard
The guard encodes a real, currently-true safety contract (#1377 SNAT
fail-closed) across the runtime + three docs, with explicit
forward-compatibility for the flat→directory `poll_descriptor` layout
(#1327 Step 1). Retiring it would remove regression coverage for a
genuine fail-open hazard the project deliberately closed in #1417.
There is no evidence the contract moved or the guard points at a
retired behavior — the runtime still implements it. Retargeting/
retiring is the wrong call here.

## Test plan
- `cargo test --release --test snat_contract_doc_guard` — must flip
  RED→GREEN (baseline confirmed RED at gaps.md:169 token check).
- 5/5 flake loop on the named guard test.
- Full `cargo test --release` suite green (note: this guard is the only
  known red on master per the issue; confirm 1605/1605).
- Full Go suite `go test ./...` with `TMPDIR=/tmp` (the
  `pkg/dataplane/userspace` socket-bind failures are a >108-char
  $TMPDIR artifact, unrelated).

## Out of scope
- Any rewording of the broader SNAT row beyond restoring the hyphen.
- Any runtime/behavior change to SNAT fail-closed handling.
- Touching #1666 (maps_sync.go), #1661-item8, #1635 (histogram).

## Open questions for adversarial review
1. Is "doc-drift, restore hyphen" the right verdict, or is there a
   reading where the guard itself is stale and should be retargeted?
2. Does restoring only `fail-closed` (hyphen) leave any other guard
   assertion unsatisfied for gaps.md? (All 9 tokens + 4 stale-absence
   checks were enumerated above — is the enumeration complete?)
3. Is the runtime truly fail-closed at all four call sites, or is there
   a path where `SourceNatLookup::NoMatch` (→ `Ok(default)`) silently
   forwards without SNAT in a way the doc overstates? (i.e. is the doc
   claim too strong?)
4. Does the one-word edit keep the sentence accurate and grammatical,
   or does "fail-closed at the ... call sites" misread vs "fail closed
   at the ... call sites"?
5. Should architecture.md / the plan doc also be touched for
   consistency, or is gaps.md the only drifted artifact? (Confirm via
   token counts — they already contain `fail-closed`.)
