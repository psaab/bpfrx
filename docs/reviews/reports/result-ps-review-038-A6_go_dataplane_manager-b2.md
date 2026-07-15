# Triage Result: ps-review-038-A6_go_dataplane_manager-b2

- **Subsystem**: A6 — Go dataplane manager, batch 2/2 (`pkg/dataplane/userspace/*`: nat_*, filter_*, policy_*, zone_*, pbr_*, mss_*, host_inbound, format/*)
- **Base**: d4506d4450e23f9a3fc572206b3c82f6b6c99029 (declared "base ~current master")
- **Current origin/master SHA**: cc451b6b58112328143c8afa654bdb8e48074a99
- **Repo**: real bpfrx (verified — all cited NAT/filter/policy/zone files exist under `pkg/dataplane/userspace/`)
- **Outcome counts**: 1 finding total — 0 GENUINE-RESIDUAL, 1 DUP, 0 ALREADY-FIXED, 0 NOT-MATERIAL, 0 DELIBERATE, 0 CONFABULATED, 0 NEGATIVE

## Notes on the review file itself
This batch file is almost entirely a module-by-module walk plus an integer-truncation
audit that the author self-cleared (NAT pool count / translate port / zone ID / ifindex
all marked safe/bounded). Only ONE actual Finding block is emitted, and it is
self-declared as a known-issue dedup. No novel exploit, no unguarded file:line.

## Per-finding disposition

### F1 — "deterministic NAT (CGNAT port block-size) unenforced + display truncation"
- **Severity (claimed)**: Low (info — known issue), High confidence
- **Claim**: CGNAT/deterministic NAT `block-size` is validated at schema + committed by
  the compiler, but the Rust userspace dataplane ignores it and uses sequential port
  allocation regardless — a carrier CGNAT compliance gap.
- **Disposition**: **DUP of #4559 (OPEN)**.
- **Why**: The review author explicitly writes "Already filed as #4559 OPEN. Not a new
  finding." Verified independently: `gh issue view 4559` returns state=OPEN, title =
  "nat: deterministic NAT (CGNAT port block-size) validated+committed but silently
  unenforced on userspace dataplane (ps-034 M-01, med→low-med)" — a one-to-one match
  with this finding's mechanism (validated + committed in Go, silently unenforced by the
  Rust allocator). #4559 also appears in the session's known-open backlog list. This is
  the same defect, already tracked; the fix lane (implement port-block allocation in the
  Rust allocator) is already recorded on #4559.
- The parenthetical "+ display truncation" in the title is not substantiated anywhere in
  the Finding body (no file:line, no truncated field named). The integer-truncation audit
  section above it explicitly clears every int→smaller-width conversion in this batch as
  bounded/validated. Nothing to escalate — no reachable truncation scenario is provided.
- Not GENUINE-RESIDUAL: no novel unreached path, no crafted input, and the mechanism is
  a known, already-filed feature gap (unimplemented CGNAT enforcement), not a latent bug
  in a hardened path.

## Verification performed
- `git fetch origin master` → master cc451b6b.
- `git ls-tree origin/master pkg/dataplane/userspace/` confirms nat_source.go,
  nat_destination.go, nat_static.go, policycounters.go, zones*.go, host_inbound*.go,
  routes_pbr_priority_*_test.go all present — subsystem is real, not confabulated.
- `gh issue view 4559` confirms the dedup target exists and is OPEN with a matching title.

## Conclusion
No genuine residual. The single finding is a self-declared, independently-confirmed dup of
open issue #4559. No further action beyond leaving #4559 open.
