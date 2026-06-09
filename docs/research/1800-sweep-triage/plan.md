# #1800 — Adversarial sweep #1784–#1799: triage + remediation plan

**Status:** DRAFT v1 — pending 3-way hostile plan review (Codex + AGY + Claude SMR)

## 1. Issue framing

The 2026-06-09 four-agent adversarial review filed 16 verified issues
(#1784–#1799) spanning docs, the Go control plane, the config compiler, and the
Rust dataplane. This research pass does NOT design every fix in depth — it
produces the **triage**: grouping into PR-sized work units, sequencing by
operator risk, per-unit disposition (mechanical `/engineer` vs design-decision
needed), the design options where judgment is required, and the validation
gates each unit must pass. The deliverable is a converged plan the operator can
approve once, after which the units proceed through normal `/engineer` cycles
without 16 separate research rounds.

## 2. Honest scope/value framing

These are real, evidence-verified defects, but none is an active outage:
#1792/#1790 are HA correctness under fault conditions (clock step, poisoned
lock), #1796/#1797 silently corrupt specific config shapes, #1799 is a
restart-time loss window, the rest are observability/hygiene/doc debt. The
value of THIS plan is sequencing and not over-engineering: most units are
1-commit fixes. If reviewers conclude a unit is mis-grouped, mis-prioritized,
or actually needs its own research round, that is exactly the feedback wanted.
**PLAN-KILL of individual units (e.g. "defer #1787, it's not worth touching the
hot path now") is an acceptable verdict per-unit without killing the plan.**

## 3. Triage table (the core deliverable)

| Unit | Issues | Kind | Size | Disposition | Gate |
|------|--------|------|------|------------|------|
| **U1 docs** | #1784, #1785, #1788 | doc drift | S | mechanical `/engineer`, one PR, 3 logical commits | build-only (docs/comments) |
| **U2 smalls** | #1786, #1791, #1795 | scoped fixes | S | mechanical `/engineer`, one PR, 3 logical commits | Go tests; cluster smoke (touches sync logging + apply); #1786 shell-check |
| **U3 exec timeouts** | #1794 | scoped fix | S | mechanical `/engineer` (15s `CommandContext` per FRR precedent + un-swallow errors) | Go tests + cluster smoke |
| **U4 session-publish counters** | #1789 | observability | S-M | mechanical `/engineer`, mirrors the #1782 counter pattern | cargo tests + cluster smoke (perf-neutral check) |
| **U5 dual-AST** | #1796, #1797 (+class) | config correctness | M | `/engineer` in two stages: U5a differential harness, U5b fixes (see §5.1) | Go tests + the new harness green; smoke for vrrp-group (HA-adjacent → failover test) |
| **U6 commit persistence** | #1799 | semantics decision | S-M | `/engineer` after panel picks Option A/B (§5.2) | Go tests + restart test |
| **U7 networkd injection** | #1798 | validation | S-M | `/engineer` (reject-at-commit-check + render-side defense + free-text audit, §5.3) | Go tests |
| **U8 DHCP lifecycle** | #1793 | feature-bug | M | `/engineer` with the §5.4 reconcile design | Go tests + standalone-VM DHCP test |
| **U9 HA demote poison** | #1790 | HA correctness | S | mechanical `/engineer`: adopt the in-file `poisoned.into_inner()` recovery (§5.5) | cargo tests + **make test-failover** |
| **U10 monotonic liveness** | #1792 | HA design | M | `/engineer` after panel ratifies §5.6 design | cargo/Go tests + **make test-failover** + clock-step repro |
| **U11 learn-path perf** | #1787 | hot-path perf | M | `/engineer` after panel ratifies §5.7 design; **defer-eligible** | cargo tests + cluster smoke + perf comparison |

Sequencing: U1+U2 immediately (U2 contains #1786, which must land **before the
next #1782 overnight capture** — the harness is broken against fw1). Then
U3/U4/U9 (mechanical), then U5 (the class fix), then U6/U7/U8, then U10, U11
last (perf-sensitive, defer-eligible). Units are file-zone disjoint enough to
parallelize 2-3 at a time if desired.

## 4. What's already shipped / composes with this

- #1781 (`fbd159e55`) fixed 2 of the 3 shared-config append sites; U2/#1791 is
  the third, same shape.
- #1782 PR-1 (`f25b1bca`) established the per-binding-counter → coordinator-sum
  → ProcessStatus → Prometheus pattern U4 copies, and the capture harness U2
  (#1786) repairs.
- `monotonicSeconds()` (`pkg/cluster/sync_protocol.go:14-18`) is the existing
  primitive U10 builds on; `poisoned.into_inner()` (`ha.rs:109-118`) is the
  existing pattern U9 copies.
- #1319 (typed-leaf schema umbrella) owns pure completion/validation gaps; U5
  deliberately handles only gaps that **silently corrupt committed config**
  (compiler-level), and adds schema entries only where required for correct
  SetPath structure (dhcp-relay).

## 5. Design sections (the units needing judgment)

### 5.1 U5 — dual-AST class fix (#1796, #1797)

The two filed bugs are instances of a CLASS: compilers that read only
`node.Children` while flat-set encodes properties in `Keys[2:]`. Fixing only
the two instances leaves unknown siblings. Plan:

- **U5a (test-only PR): differential dual-AST harness.** For every supported
  config stanza family (drawn from setSchema + the compiler test corpus),
  round-trip the same logical config through BOTH parser shapes and diff the
  resulting typed `config.Config`. Any mismatch = a latent dual-AST bug.
  Implementation sketch: table of (flat-set lines, equivalent hierarchical
  text) pairs covering interfaces (incl. vrrp-group, units, VLANs), security
  (zones/policies/NAT/screen), CoS, forwarding-options, routing-options,
  system, chassis. Mark known-broken pairs with expected-fail until U5b lands.
  This is the leverage: it catches the instances we did NOT find by hand and
  pins the class shut against regression.
- **U5b (fix PR): #1796 + #1797 + whatever U5a flags.** vrrp-group: make
  `compileVRRPGroup` read props from `Keys` tail siblings as well as Children
  (same dual-shape handling the rest of compiler_interfaces uses). dhcp-relay:
  add the subtree to setSchema (so SetPath structures it) AND make
  `compileDHCPRelay` dual-shape. Each additional U5a finding gets its own
  logical commit.

Open question for reviewers: is the harness table-driven approach right, or
should it auto-generate flat-set from hierarchical via the existing
`display set` rendering (if one exists) to avoid hand-maintaining pairs?

### 5.2 U6 — commit persistence failure semantics (#1799)

Two options; the panel picks:

- **Option A (fail the commit):** `WriteActive` error → return error from
  `Commit()` BEFORE the in-memory promote (reorder: persist first, promote
  after), so a failed persist leaves candidate intact and the operator sees a
  hard commit error. Cleanest semantics; risk: a transiently full/slow disk
  blocks all config changes (including emergency ones) — but Junos behaves
  this way (commit fails if it can't persist), and a firewall whose config
  can't persist SHOULD be loud.
- **Option B (succeed + loud degradation):** keep the commit, but (1) retry
  persistence with backoff, (2) flip a `configPersistDegraded` health flag
  surfaced via /health 503 + Prometheus + commit-reply warning so the operator
  knows the running config is not crash-safe.

Recommendation: **A**, with the persist moved before the promote (atomicity:
write-temp + rename already exists in the DB layer — verify) and B's health
flag as a cheap addition for the rollback-file write path. HA config-sync
implications must be checked (does a failed persist on the secondary currently
break sync? — reviewer question).

### 5.3 U7 — networkd injection (#1798)

Defense in depth, both layers:
1. **Commit-check validation (primary):** reject control characters
   (specifically `\n`, `\r`) in free-text config fields at SchemaValidate /
   compile time, with a clear commit error. Junos descriptions cannot contain
   newlines; no legitimate config loses expressiveness.
2. **Render-side belt (secondary):** networkd + FRR + any other file-template
   renderers strip/escape newlines in interpolated strings so a future field
   addition can't reopen the hole.
3. **Audit:** grep all template renderers (networkd .network/.link, frr.conf
   managed section, strongSwan configs, Kea config, systemd units) for other
   free-text interpolations (zone descriptions, policy descriptions, user
   full-names) and cover them in the same PR.

### 5.4 U8 — DHCP client lifecycle (#1793)

Reconcile-on-apply design: `applyConfigLocked` computes desired DHCP client
set from the new config and diffs against running clients — start new, stop
removed. Requires: (1) lazily create the manager on first need (drop the
startup-only `needsDHCP` gate), (2) per-client cancellable context (replace
the deliberate `context.Background()` with a per-client `WithCancel` retained
in the registry; manager Stop cancels all), (3) registry hygiene: deregister
on ALL terminal exits (defer in the run goroutine), not just in `Renew`.
Address-release semantics on stop (send RELEASE vs just stop renewing) is an
open reviewer question — lean: just stop + remove the address, matching
interface-deconfiguration behavior elsewhere.

### 5.5 U9 — update_ha_state poison path (#1790)

Minimal fix: replace the `?` early-return on the poisoned worker command lock
with the `poisoned.into_inner()` recovery already used by
`handle_activated_rgs` (ha.rs:109-118). With no remaining `Err` path inside
the demotion block, the store-before-propagate ordering becomes harmless and
does NOT need to move (moving the store would change what concurrent readers
observe mid-propagation — bigger blast radius for no gain). Add a regression
test: poison a worker command mutex, drive a demotion, assert demote commands
+ epoch bumps still land.

### 5.6 U10 — monotonic HA liveness (#1792)

Design options:

- **Option A (monotonic timestamps):** store `monotonicSeconds()` (or a
  monotonic-ns variant) at heartbeat receive; compare monotonic-now in
  timeoutLoop. Fixes NTP/`date -s` steps completely. VM pause/resume: KVM
  guests' CLOCK_MONOTONIC does not advance while paused, so on resume neither
  side sees a false local timeout, and real peer silence during OUR pause is
  re-evaluated against heartbeats that resume immediately — correct behavior.
- **Option B (clock-free counting):** timeoutLoop ticks at `interval` and
  checks a receive sequence counter — "no heartbeat since N ticks ago" with no
  clock arithmetic at all. Most robust, slightly more invasive.
- **Companion fixes either way:** make `LastPeerReceiveAge` /
  `PeerHealthy()` (sync.go) monotonic so the suppress guard survives the same
  step; clamp the VRRP GARP dampening (`instance.go:1081`) so a backward step
  cannot suppress failover GARPs (age < 0 → send).

Recommendation: **A + companions** (smallest diff on a liveness-critical
path; B only if reviewers find a hole in A). Validation: a live clock-step
repro on the loss cluster (`date -s +5sec` on one node under heartbeat
monitoring) + `make test-failover`.

### 5.7 U11 — learn_dynamic_neighbor hot path (#1787)

The bulk 64-shard lock exists for one reason: atomic visibility of the
(physical, logical-VLAN) key pair ("a reader sees either both or neither",
neighbor_dispatch.rs:340-343). Options:

- **Option A (steady-state bypass):** before any insert, read the 1-2 keys via
  per-key single-shard locks; if all already map to `src_mac`, return. Only on
  actual change (new host / MAC move — rare) take the existing bulk path.
  Replaces the `vec!` with a fixed `[i32; 2]` + len. Steady state: 1-2 shard
  read locks, zero allocs, no bulk acquisition. Preserves the pair-atomicity
  guarantee on change.
- **Option B (drop pair-atomicity):** per-key `insert_if_changed` (single-shard)
  for each key independently; accept a sub-microsecond window where one key
  has the new MAC and the other the old. Readers look up exactly one key per
  packet and a momentary stale MAC self-heals next packet; the #949 comment's
  guarantee may be stronger than any consumer needs (reviewer question: does
  ANY reader correlate both keys in one decision?).
- **Option C (widen dedup only):** per-binding N-entry (e.g. 8) LRU of learned
  keys instead of the single-element cache. Cheapest, but keeps the bulk lock
  on every dedup miss — only dilutes the problem.

Recommendation: **A** (keeps every documented invariant, kills the steady-state
cost), C as a complementary micro-fix. Defer-eligible: if reviewers judge the
interleaving workload too rare on current deployments, parking this with a
`perf` label is acceptable.

## 6. Public API preservation

No public Go API or wire-protocol changes in any unit except U4 (adds
ProcessStatus counter fields — additive, omitempty, same as #1782) and U6
Option A (Commit() can newly return a persist error — callers already handle
Commit errors; verify all call sites). U5b changes only compiler-internal
behavior (committed config becomes MORE correct).

## 7. Hidden invariants

- U5b: lenient-compile philosophy — fixes must not turn previously-accepted
  (if broken) configs into commit errors except where validation is the point
  (U7).
- U9/U10: anything touching cluster/VRRP/sync/failover MUST pass
  `make test-failover` before commit (CLAUDE.md).
- U11: hot-path allocation rules; preserve or consciously relax the #949
  pair-atomicity with a documented decision.
- U4: counters must be always-on (not debug-gated) per the #1789 finding
  itself, and perf-neutral (Relaxed atomics on existing branches).
- U2/#1786: per-node FPC naming (`ge-7-0-x` on node1) — the fix must derive,
  not hardcode the other name.

## 8. Risk assessment

| Unit | Behavioral risk | Notes |
|------|-----------------|-------|
| U1/U2/U3/U4 | LOW | doc/comment/log/timeout/counter changes |
| U5 | MED | compiler behavior change for affected stanzas — harness + smoke gate |
| U6 | MED | commit semantics change (Option A) — restart test gate |
| U7 | LOW-MED | new validation can reject previously-committable (broken) configs — release-note it |
| U8 | MED | new reconcile paths on apply — DHCP env test gate |
| U9 | LOW | error-path only; failover gate |
| U10 | MED-HIGH | liveness-critical path — failover + clock-step repro gate |
| U11 | MED | hot path — perf comparison gate; defer-eligible |

## 9. Test plan

Per-unit gates in §3. Global: each PR gets the standard 4-way code review
(Codex + AGY + Claude SMR + Copilot); cluster smoke for anything touching
forwarding/sync/HA; `make test-failover` for U5b(vrrp)/U9/U10; the U5a
harness becomes a permanent CI-class test.

## 10. Out of scope (explicitly)

- #1319-class pure completion/validation gaps (codel-target etc.) — belong on
  #1319.
- Anything in the open review backlogs #1669/#1663/#1661/#1653 not re-filed by
  the sweep.
- #1782 PR-2 itself (separately tracked; U2/#1786 unblocks its capture).
- The `1635-wip` local working-tree state.

## 11. Open questions for adversarial review (each invitable to per-unit KILL)

1. Is the U5a differential harness the right class-closure mechanism, or is a
   targeted audit of `.Children`-only compiler loops cheaper and sufficient?
2. U6: Option A (fail commit) vs B (succeed loud) — and does persist-before-
   promote interact badly with HA config sync or commit-confirmed?
3. U10: does Option A's monotonic comparison have a hole during VM
   pause/resume that Option B avoids? Is the 500 ms default timeout itself too
   tight independent of clock source?
4. U11: does any reader actually depend on the (physical, logical) pair
   atomicity, or can Option B's single-key inserts be justified outright?
   And is U11 worth doing at all now (defer-eligible)?
5. U8: should stopping a DHCP client send a protocol RELEASE or silently stop?
6. Are any groupings wrong — units that should split (U2?) or merge, or a
   priority inversion (should U10 jump ahead of U5)?
7. Is anything in #1784–#1799 mis-triaged as mechanical when it actually needs
   its own research round?
