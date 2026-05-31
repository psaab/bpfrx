# Claude-SMR hostile PLAN review — #1701 r1

Reviewer: Claude (domain SMR + SW design patterns), HOSTILE.
Plan @ 8ae2ff4261 on refactor/1701-config-types-split.

## Independent verification performed

- `grep -n "iota|^var |^const "` on types.go → 4 const blocks (3 iota:
  LoginClassPermission@837, PolicyAction@1350, NATType@1451; 1 non-iota
  RPM-defaults@884) + 1 var (LoginClassPermissions@846). The plan's
  ordinal-sensitive inventory (§6.3) is COMPLETE and correct.
- Verified Perm* consts (838-842) + LoginClassPermissions var (846) +
  Default*RPM* consts (885-890) + RPMTest.Effective* methods (908-945) all
  belong to the System bucket — the plan co-locates them correctly (§6.4,
  §6.5).
- Symbol baseline: 175 `type`, 16 `func`, 4 `const`, 1 `var`. This is the
  reconciliation target for §9.
- `go build ./...` on the worktree base is clean (verified pre-plan).

## Findings

### F1 (over-caution, not a defect) — iota ordinal risk is structurally impossible here
The plan repeatedly worries about an `iota` ordinal shift from splitting a
const block across files (§6.3, §11.Q2). For correctness this is moot:
the proposal NEVER internally splits a const block — it moves each intact
block with its type. And even the value-dependency pairs
(LoginClassPermissions↔Perm*, Default*RPM*↔Effective*) are same-package,
so Go resolves them regardless of which FILE they sit in — file boundaries
have zero visibility semantics in Go. The only real hazard is an
*internally split* const block, which the mechanical method (§4, cut whole
block) prevents by construction. **Recommend the audit explicitly assert
"no const block internally split" — already promised in §11.Q2 answer.**
Not blocking.

### F2 (sound) — sub-package rejection is correct on the issue's own kill criteria
The issue says PLAN-KILL if the split "breaks the consumer API or creates
cycles." A `config/types` (or `config/model`) sub-package would force one
of: (a) 194 consumer files churn `config.Foo`→`types.Foo`, or (b) a wall
of `type Foo = types.Foo` aliases in package config (which negates the
split AND re-exposes the 2055-LOC alias list). Cycle risk is also real:
`config`'s schema_validate/compiler layers both construct and read these
types, so a `config`→`config/types` edge plus any `types`→`config` need
(even a single helper) closes a cycle. Same-package motion has NONE of
this. The plan picks the only decomposition that satisfies the kill
criteria. CORRECT.

### F3 (cohesion — AGY r1 found three REAL re-buckets; I concur) — fixed in plan v2
AGY r1 (PLAN-NEEDS-MAJOR) flagged three domain mis-assignments in plan v1
that I independently verified against types.go and the Junos hierarchy:
- IPsec/IKE types nest under `SecurityConfig.IPsec` (types.go:1205) →
  belong in `types_security.go`, NOT `types_routing.go`. CONFIRMED.
- DynamicAddress/Feed types nest under `SecurityConfig.DynamicAddress`
  (types.go:1206) → `types_security.go`, NOT `types_system.go`. CONFIRMED.
- `SchedulerConfig` (types.go:428, StartTime/StopTime time-range, used by
  `Policy.SchedulerName`) is the `[edit schedulers]` scheduler, NOT the CoS
  queue scheduler `CoSScheduler` (types.go:496) → `types_security.go`, NOT
  `types_cos.go`. A pure name-collision trap. CONFIRMED.
These are correctness-of-cohesion, not just taste: they align the file
boundaries with the actual struct nesting, which is the whole point of a
domain split. Plan v2 incorporates all three. My earlier F3 (FirewallConfig
bucket) remains a non-blocking author's-call cohesion question; leaving
`FirewallConfig` in System is acceptable.

### F4 (sound) — test gate is adequate for pure Go motion
gofmt -l + go build ./... (all 194 consumers) + go vet + go test ./... +
symbol-count reconciliation is the right gate for a no-logic refactor.
go build catches duplicate (redeclared) and missing (undefined) symbols;
go vet catches unused-import/shadow; gofmt catches formatting. The
symbol-count reconciliation (175/16/4/1) is a good belt-and-suspenders
check the #1699 split didn't document. No cluster smoke is correct — the
change cannot reach the dataplane. Reproduce-pre-existing-userspace-
sandbox-failures-first is the right discipline.

### F5 (value judgment) — churn is justified
A 2055-LOC type-only file is navigable by IDE symbol index, so the win is
modest. But the repo's standing modularity discipline
(docs/engineering-style.md: files > ~2000 LOC trigger refactor) is an
explicit project policy, #1699 just executed the identical pattern on the
sibling ast.go, and the parallel-refactor-backlog merge-conflict reduction
is a concrete operational benefit. The git-blame disruption (§11.Q6) is
the real cost and it's acceptable (it was for #1699). Not a KILL.

## Verdict

**PLAN-READY.**

Pure same-package byte-identical motion. No import cycle (no new edge), no
consumer churn (file split invisible to importers), no ordinal hazard (whole
blocks moved). The central #1701 kill criterion is satisfied by the
sub-package rejection. F1/F3 are non-blocking; F3 (FirewallConfig bucket) is
a cohesion question to settle at implementation, not a blocker.

One implementation requirement carried forward: the per-file import set must
be pruned by gofmt/goimports and proven by `go vet` — do not leave an unused
`fmt`/`strconv`/`strings` in any domain file.
