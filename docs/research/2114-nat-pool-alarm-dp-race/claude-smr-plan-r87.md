# Claude SMR hostile plan-review — round 87 (plan v88 @ `4183be25c5ef`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r86 pass
walked the pure-class cells but not MIXED-outcome methods — Codex r86
found the class-1 absent cell could not encode master's
required/optional split (SetNAT64Config errors on absent nat64_configs
but silently skips absent nat64_prefix_map). Recorded: a cell walk that
samples one method per class misses intra-method heterogeneity. This
pass independently re-derives the mixed-site inventory, then the rest.

## A. Fold verification (r86 findings → v88)

### 1. Codex M1 (per-access required/optional semantics) — FOLDED

I independently re-derived the inventory: all 135 production registry
reads (non-test `pkg/dataplane`), minus the 3 publisher writes
(loader_userspace_shim.go:185/:187/:190) and the 3 getter nil-checks
(loader.go:1152/:1157/:1162), leaves 129 reads. Every one is either
comma-ok with an error/continue branch (required or class-2 neutral)
or in the named 11-site optional list — my sweep found ZERO
non-comma-ok reads outside the named inventory. Completeness CONFIRMED
by construction, not trust. Spot-checks:

- `SetNAT64Config` (maps_nat.go:289-304): REQUIRED nat64_configs
  errors on absent (:291), OPTIONAL nat64_prefix_map skips on absent
  (:300's `if ok`) — the v88 rule (row governs required, optional
  keeps per-site outcome) reproduces master exactly.
- `SetNATPoolIPs` (maps_nat.go:191-198): BOTH accesses comma-ok with
  error branches — pure-required, no optional site; correctly absent
  from the inventory.
- The `compiler_nat.go:605/:611` exclusion is CORRECT — those `ok`s
  are `netip.AddrFromSlice` conversions, not registry reads (verified
  at :604-613).
- The partial-registry oracle leg (nat64_configs present +
  nat64_prefix_map absent → SetNAT64Config succeeds on armed and
  retained) closes the r86 gap without touching the whole-batch
  publication invariant (the fixture is a test-side seed of the
  retained state, not a publisher change).

### 2. Codex m2 (fifth singular site) — FOLDED

The canary-allowlist sentence now reads "the two registry helpers
(`lookupMapLocked`/`lookupProgramLocked`...) and
`publishShimRegistryLocked`". A sixth-site hunt: zero remaining
"the registry helper and" singular phrasing.

### 3. Codex m3 (overclaims) — FOLDED

Both "only intentional behavior change" sites now say exactly TWO
changes (the class-1 typed error + class-4 NewEventSource's fresh
typed error, with loader.go:1163's "events map not loaded" as the
master baseline). The §7 tail now names the Close-entry loaded=false
admission-timing narrowing as the one admitted non-post-arm
divergence, and the §8 risk-table cell says "no lifecycle REDESIGN"
with the same qualification. Verified NewEventSource's master error
text at loader.go:1162-1163.

## B. Fresh attacks on the v88 delta

**Attack 1 (FAILED) — an all-optional method misclassifies.**
DeleteStaleNAT64 (maps_stale.go:284-300) has ONLY optional-if-ok
accesses — master succeeds on a fresh registry (all bodies skip), a
neutral outcome. Under the escape-first precedence (§4: class-2 = a
method whose missing-map outcome is NEUTRAL, nil/zero/empty — never an
error) it classifies class-2, NOT class-1 — the fresh cell returns
neutral, matching master. The v88 optional rule is consistent: its
accesses keep master's skip outcome in every state. FAILED.

**Attack 2 (FAILED) — a conditionally-required access exists.** I
walked the comma-ok error-branch sites: every error branch is
UNCONDITIONAL on `!ok` (e.g. maps_nat.go:193/:197, :291, :308 —
`if !ok { return fmt.Errorf(...) }`). No site errors on absent only
under a runtime condition. The required/optional binary encodes every
production site. FAILED.

**Attack 3 (FAILED) — the per-access rule breaks the helper's
atomicity.** The helper returns (handle, present, st) for required
AND optional accesses identically; the required/optional distinction
lives entirely in the caller's existing consumption (error branch vs
skip). Classification+selection remain one scoped operation under
m.mu; no second lookup or re-classification is introduced. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v88 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — the mixed-site inventory is complete (independently
re-derived: zero non-comma-ok reads outside the named 11 sites + 3
writes + 3 getters), the per-access rule reproduces master for pure-
required, pure-optional, and mixed methods, and the two-change/
lifecycle qualifications match the code (NewEventSource at
loader.go:1162-1163, the Close-entry Store(false) at :1206). My r86
miss (sampling one method per class) is recorded; this pass re-derived
the inventory from the grep instead.
