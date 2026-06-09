# #1800 — Adversarial sweep #1784–#1799: triage + remediation plan

**Status:** DRAFT v2.1 — folds r2 (Codex PLAN-NEEDS-MINOR: all §11 questions answered + PrivateRGElection window correction; AGY r2 re-raised already-folded r1 items — see reviewer-ids.md; SMR r2 PLAN-READY). Pending r3 confirmation.

## 1. Issue framing

The 2026-06-09 four-agent adversarial review filed 16 verified issues
(#1784–#1799). This research pass produces the **triage**: PR-sized work
units, sequencing by operator risk, per-unit disposition, the design decisions
where judgment is required, and validation gates. After convergence the units
proceed through normal `/engineer` cycles without 16 separate research rounds.
**Per-unit PLAN-KILL/defer is an acceptable outcome recorded in the table; it
does not kill the plan.**

## 2. Honest scope/value framing

None of the 16 is an active outage: #1792/#1790 are HA correctness under fault
conditions, #1796/#1797 silently corrupt specific config shapes, #1799 is a
restart-time loss window, the rest are observability/hygiene/doc debt. The
value of this plan is sequencing and not over-engineering. r1 additionally
surfaced two NEW defects adjacent to filed ones, folded into unit scopes below:
the auto-rollback persist hole (§5.2, AGY) and the `RestartHeartbeat`
no-peer-grace false failover (§5.6, AGY).

## 3. Triage table (v2 — resequenced per r1)

| # | Unit | Issues | Size | Disposition | Gate |
|---|------|--------|------|------------|------|
| 1 | **U1 docs** | #1784, #1785, #1788 | S | mechanical `/engineer`, one PR, 3 logical commits | build-only |
| 2 | **U2 smalls** | #1786, #1791, #1795 | S | mechanical `/engineer`, one PR, 3 logical commits | Go tests; cluster smoke; **`make test-failover`** (#1795 touches `pkg/cluster` — the CLAUDE.md rule has no triviality exemption) |
| 3 | **U3 exec timeouts** | #1794 | S | mechanical `/engineer` (15 s `CommandContext` per FRR precedent + un-swallow errors) | Go tests + cluster smoke |
| 4 | **U4 session-publish counters** | #1789 | S-M | mechanical `/engineer`, mirrors #1782 counter pattern | cargo tests + cluster smoke (perf-neutral) |
| 5 | **U9 HA demote poison** | #1790 | S | mechanical `/engineer`: in-file `into_inner` recovery (§5.5) | cargo tests incl. multi-worker partial-propagation regression + **`make test-failover`** |
| 6 | **U10 monotonic liveness** | #1792 (+RestartHeartbeat grace) | M | `/engineer` per §5.6 (monotonic-ns + companion sites + window) | cargo/Go tests + **`make test-failover`** + live clock-step repro + heartbeat-restart repro |
| 7 | **U5 dual-AST** | #1796, #1797 (+class) | M | `/engineer` two stages: U5a `FormatSet()` differential harness, U5b schema+compiler fixes (§5.1) | Go tests + harness green; **`make test-failover`** for the vrrp-group fix |
| 8 | **U7 free-text injection** | #1798 (+renderer audit) | M | `/engineer` per §5.3 (commit-time-only validation + render-side belt + migration) | Go tests incl. Load()-with-bad-persisted-config boot test |
| 9 | **U6 commit persistence** | #1799 (+auto-rollback hole) | M | `/engineer` per §5.2 split semantics | Go tests + restart test + HA sync divergence test |
| 10 | **U8 DHCP lifecycle** | #1793 | M | `/engineer` per §5.4 (reconcile; KEEP the Background root invariant) | Go tests + standalone-VM DHCP test |
| 11 | **U11 learn-path perf** | #1787 | M | **DEFERRED until U1–U10 done** (Codex r2); settled sketch in §5.7 | cargo tests + cluster smoke + perf comparison |

**Sequencing rationale (r1):** mechanical units (1-4) first — U2 contains
#1786 which must land before the next #1782 overnight capture. U9→U10
immediately after: both reviewers judged U10 the highest operational risk and
v1 sequenced it too late. Then the config-surface chain U5→U7→U6 (they share
`pkg/config`/commit-apply test territory — see parallelism below), then U8,
U11 last (defer-eligible).

**Parallelism (replaces v1's loose claim, per Codex F8):** at most two lanes.
Lane A (config surface, serialized): U5 → U7 → U6 — they overlap on
`pkg/config/schema.go`, validation, and commit/apply tests. Lane B (runtime):
U9 → U10 → U8 — U9/U10 are cluster/HA (failover-gated, serialize on the smoke
cluster), U8 is daemon lifecycle. U1-U4 land before the lanes open. U11 joins
lane B at the end if not deferred. Smoke-cluster access is the global
serializer: failover-gated units never run concurrently.

## 4. What's already shipped / composes

- #1781 (`fbd159e55`) fixed 2 of 3 shared-config append sites; U2/#1791 is the
  third, same shape.
- #1782 PR-1 (`f25b1bca`) established the counter pattern U4 copies and the
  harness U2 (#1786) repairs.
- `pkg/cluster/sync_protocol.go:14-18` has `monotonicSeconds()`; U10 needs a
  **nanosecond** monotonic variant (Codex: seconds granularity is too coarse
  for a 500 ms window — comparisons must be monotonic-ns).
- `poisoned.into_inner()` (`ha.rs:109-118`) is the U9 pattern.
- `tree.FormatSet()` (`pkg/config/ast_format.go:154`) is the U5a generator.
- `pkg/dhcp/dhcp.go:191` already creates per-client `WithCancel`; the
  Background **root** is a documented invariant (`pkg/dhcp/README.md:31`:
  graceful daemon restart leaves leases in place) that U8 must preserve.
- #1319 owns pure completion/validation gaps; U5 handles only gaps that
  silently corrupt committed config, plus the schema entries required for
  correct SetPath structure (both `vrrp-group` — missing at `schema.go:419` —
  and `dhcp-relay` — missing at `schema.go:1201`).

## 5. Design sections

### 5.1 U5 — dual-AST class fix (#1796, #1797) — v2 per r1

**U5a (test-only PR): `FormatSet()`-driven differential harness** (both
reviewers rejected v1's hand-maintained table as a boil-the-ocean trap).
Mechanism: take the existing hierarchical test corpus (compiler test
fixtures), for each: parse hierarchical → render via `tree.FormatSet()` →
re-parse the flat-set lines via `ParseSetCommand`+`SetPath` → compile BOTH
trees → diff the typed `config.Config`. Any mismatch = latent dual-AST bug.
Add targeted vrrp-group + dhcp-relay fixtures; mark known-broken cases with an
`ExpectedFail bool` until U5b lands (workable in Go per AGY). **FormatSet
fidelity DECIDED (Codex r2):** no separate preliminary PR needed, but the
embedded sanity check must be tree-level: hierarchical parse → `FormatSet()`
→ `ParseSetCommand`/`SetPath` → compare canonical `FormatSet()` of both
trees BEFORE running the compiler diff — so a FormatSet bug surfaces as a
tree mismatch, not a phantom compiler finding.

**U5b (fix PR):** add `vrrp-group` (schema.go:419 region) and `dhcp-relay`
(schema.go:1201) to setSchema so SetPath structures them; make
`compileVRRPGroup` (compiler_interfaces.go:320) and `compileDHCPRelay`
(compiler_services.go:586) dual-shape; fix whatever else U5a flags, one
logical commit each.

### 5.2 U6 — commit persistence semantics (#1799 + auto-rollback hole) — v2 per r1

r1 split the v1 Option-A/B binary into **per-path semantics** (Codex) and
surfaced a second defect (AGY):

- **Operator-initiated `Commit`/`CommitWithDescription`: Option A** —
  persist-before-promote; `WriteActive` failure → commit returns an error,
  candidate intact, nothing applied anywhere. `WriteActive` already does
  temp+rename (`db.go:116`), so the disk state is never torn. AGY's
  divergence argument does not apply to a refused local commit (the config is
  applied nowhere). Codex concurs A is sane here.
- **`CommitConfirmed`: Option A + do not arm** — on persist failure the
  confirm timer must NOT be armed and confirm state NOT set (Codex r1).
  **Ordering invariant (Codex r2):** do not cancel/overwrite an existing
  pending confirm timer/state until the NEW confirmed commit has durably
  persisted — today the code cancels (`store.go:872`) and saves confirm
  state (`:878`) BEFORE WriteActive (`:894`). Implementation order: write
  candidate to active storage first → mutate history/active/confirm state →
  journal + saveRollbackFiles. Codex verified this order breaks neither the
  journal nor rollback-file bookkeeping.
- **HA `SyncApply` (store.go:238): Option B** — failing the secondary's apply
  on its local disk trouble would silently diverge the cluster (primary
  already running the new config, never notified — sync is one-way
  fire-and-forget, `sync_conn.go:572`). Keep the in-memory apply, flip a
  `configPersistDegraded` health flag (/health 503 + Prometheus + journal
  ERROR) and retry persistence with backoff.
- **`performAutoRollback` (store.go:964): NEW defect, same family** — its
  `WriteActive` is also warn-only; a persist failure during auto-rollback
  reverts memory but leaves the unconfirmed candidate on disk → reboot loads
  the config the operator never confirmed, breaking the rollback contract.
  Rollback must never be blocked (always proceed in-memory) → Option B
  treatment: degraded flag + persist retry.

The "Junos parity" claim from v1 is withdrawn for the cluster case (Junos
commit-synchronize is two-phase; ours is async one-way — AGY).

### 5.3 U7 — free-text injection (#1798 + renderer audit) — v2 per r1

1. **Commit-time-ONLY validation (critical r1 correction, AGY):** reject
   `\n`/`\r` in free-text fields in the STRICT compile path
   (`CompileConfig` via Commit/CommitCheck) — **not** in the shared
   `SchemaValidate` that `Load()`'s lenient path also executes, or a box with
   bad persisted config fails to boot. Gate: a regression test that `Load()`
   of a persisted config containing a newline description still boots (and
   logs a sanitization warning).
2. **Render-side belt:** strip/escape newlines at every file-template
   interpolation regardless of validation.
3. **Migration:** already-persisted bad values must not make the next
   unrelated commit fail mysteriously (Codex). **DECIDED (Codex r2 Q4):
   sanitize-with-warning** — refuse/quarantine risks boot failure or
   mysterious unrelated-commit failure. On Load, sanitize-with-warning
   so the in-memory candidate is clean; document in the release note.
4. **Audit scope (Codex):** beyond networkd descriptions — FRR
   `policy_render.go:260` (BGP/policy strings), FRR passwords/auth keys,
   IPsec IDs/secrets, Kea config, systemd unit fields, zone/policy
   descriptions. Each free-text → file-template flow gets the same two-layer
   treatment.

### 5.4 U8 — DHCP client lifecycle (#1793) — v2 per r1

v1's "replace `context.Background()`" language was WRONG (Codex): the
Background root is a deliberate, documented invariant (graceful daemon
restart must not kill leases, `pkg/dhcp/README.md:31`), and per-client
`WithCancel` already exists (`dhcp.go:191`). The actual fix:
1. Reconcile-on-apply: `applyConfigLocked` diffs desired-vs-running clients —
   start new (lazily creating the manager; drop the startup-only `needsDHCP`
   gate at `daemon_dhcp.go:17`), explicitly cancel removed ones via the
   existing per-client cancel. **The diff key must include option identity,
   not just `(iface, family)`** (Codex r2): `Start()` no-ops on an existing
   key while e.g. DHCPv6 `stateless` is captured at goroutine start
   (`dhcp.go:196`, `:675`) — a same-interface option change must
   restart that client.
2. Registry hygiene: deregister on ALL terminal run-goroutine exits (defer),
   not just in `Renew`; fix `StopAll` to clear entries.
3. Stop semantics (open question resolved → lean): stop renewing + remove the
   address; do NOT send protocol RELEASE (matches interface-deconfiguration
   behavior elsewhere; r2 may override).

### 5.5 U9 — update_ha_state poison path (#1790) — v2 per r1

Recovery-only is sufficient, and the premise is now stated explicitly (SMR
F2): the poisoned-lock `?` at ha.rs:42-47 is the ONLY fallible early-exit in
the demotion block (verified by AGY across ha.rs:40-76); with inline
`into_inner` recovery the SAME call completes all propagation — worker
commands to every worker, `demote_shared_owner_rgs`, epoch bumps — so no
partial state can form and the store-before-propagate ordering need not move.
Implementer must re-verify no other `?`/`return Err` exists in that span at
implementation time. **Regression test strengthened (Codex):** poison one of
N(≥3) worker command mutexes, drive a demotion, assert ALL workers received
DemoteOwnerRGS + shared-session demotion ran + epochs bumped — i.e. model the
partial-propagation scenario, not just the single-mutex case.

### 5.6 U10 — monotonic HA liveness (#1792 + RestartHeartbeat) — v2 per r1

**Resequenced to position 6 (right after U9)** — both reviewers: highest
operational risk, v1 had it too late.

Design (Option A refined):
- Store a **monotonic-nanosecond** reading at heartbeat receive and compare
  monotonic-now in timeoutLoop (NOT `monotonicSeconds()` — seconds granularity
  is unusable against a 500 ms window; add a `monotonicNanos()` sibling).
- The v1 KVM-pause-behavior claim is **withdrawn** (Codex): do not bank
  split-brain prevention on guest clock semantics. Validation must include a
  pause/stall simulation, not an argument.
- **Companion wall-clock sites (AGY enumerated):** `hbSuppressStart`
  (`daemon_ha_sync.go:149-157` — backward step blocks failover indefinitely,
  forward step cuts suppression short); `LastPeerReceiveAge`/`PeerHealthy()`
  (sync.go:489-526); VRRP GARP dampening (`instance.go:1080-1082` — clamp so
  a backward step cannot suppress failover GARPs). All move to monotonic or
  clamp.
- **NEW in-scope defect (AGY r1): `RestartHeartbeat` no-peer-grace** — when
  the local node restarts its heartbeat sockets (bind retries at 1 s
  intervals, up to ~5 s), the peer has no grace period; a restart taking
  >500 ms fires a false peer-failover. **DECIDED (Codex r2): coordinated
  restart suppression is REQUIRED** (reuse the hbSuppress machinery around
  restarts) — widening alone cannot close it, since a 1 s retry cadence
  races any plausible window.
- **Default-window DECIDED (Codex r2):** the v2 framing "VRRP owns fast
  failover" was WRONG for the default path — `PrivateRGElection` is compiled
  on by default (`compiler_system.go:937`) and suppresses RETH VRRP
  (`daemon_ha_vip.go:92`), so **heartbeat detection itself owns promotion**
  and the 5×100 ms window IS the failover-detection budget. Default stays
  5×100 ms; widening (e.g. 5×200 ms) is offered only as an explicit,
  operator-opted, documented failover-latency trade — never silently.
- Validation: `make test-failover` + live clock-step repro (`date -s +5sec`
  on one node, then both) + heartbeat-restart repro + pause/resume.

### 5.7 U11 — learn_dynamic_neighbor (#1787) — v2.1: DEFERRED, design settled

**Disposition (Codex r2): DEFER until U1–U10 are done** unless current perf
pressure demands otherwise. Both reviewers independently hunted for a
pair-consuming reader of the (physical, logical-VLAN) dynamic-neighbor keys —
including tests and debug dumps — and found NONE: forwarding resolves exactly
one key per packet (`forwarding/mod.rs:1529`), fabric link resolution tries
overlay then parent sequentially (`forwarding/mod.rs:300`), so the #949
pair-atomicity guarantee is stronger than any consumer needs.

Settled implementation sketch for when it runs (common ground of both r2
reviews): replace `vec!` with fixed `[i32; 2]`+len (zero allocs), and add a
**steady-state equality bypass** — read the ≤2 keys via per-key single-shard
locks; if all already map to `src_mac`, return without writing. On actual
change (rare): Codex prefers per-key `insert_if_changed` (Option B, drops the
unneeded invariant with the justification inlined in the comment); AGY notes
keeping the existing bulk write on the change path (Option A shape) preserves
the invariant at zero extra cost since change is rare. Either is acceptable —
the steady-state cost is identical (zero writes, zero allocs, no bulk lock);
the implementer picks one and documents it. Pair-consuming-reader absence
must be re-verified at implementation time.

## 6. Public API preservation

No public Go API or wire changes except: U4 adds ProcessStatus counter fields
(additive, omitempty); U6 makes operator `Commit`/`CommitWithDescription`/
`CommitConfirmed` able to return persist errors (callers already handle Commit
errors — U6 implementer enumerates and verifies every call site, including
grpcapi/api commit handlers and the HA forward path, as an explicit task);
U10 may add a heartbeat-window config knob (additive).

## 7. Hidden invariants

- U5b: lenient-compile philosophy — no new commit errors except where
  validation is the point (U7, strict path only).
- U7: `Load()` must NEVER fail on persisted free-text (boot safety) — AGY's
  lenient-path finding is the load-bearing constraint.
- U8: the Background root invariant (leases survive graceful restart) is
  preserved; only explicit reconcile-stop cancels a client.
- U9/U10/U5b(vrrp)/U2: `make test-failover` mandatory (cluster/VRRP/sync
  rule, no triviality exemption).
- U11: hot-path allocation rules; the pair-atomicity relaxation must carry
  the verified no-pair-reader justification in the code comment.
- U4: counters always-on, Relaxed atomics on existing branches only.
- U2/#1786: derive per-node names (`ge-7-0-x` on node1), never hardcode.

## 8. Risk assessment

| Unit | Risk | Notes |
|------|------|-------|
| U1-U4 | LOW | doc/log/timeout/counter |
| U9 | LOW | error-path only; failover-gated |
| U10 | MED-HIGH | liveness-critical; clock-step + restart + failover gates |
| U5 | MED | compiler behavior change; harness + smoke gates |
| U7 | MED | new strict-path validation + Load sanitization; boot-test gated |
| U6 | MED | commit semantics split; restart + sync-divergence tests |
| U8 | MED | new reconcile paths; DHCP env test |
| U11 | MED | hot path; perf-comparison gate; defer-eligible |

## 9. Test plan

Per-unit gates in §3/§5. Global: every PR gets the 4-way code review (Codex +
AGY + Claude SMR + Copilot); failover-gated units serialize on the smoke
cluster; the U5a harness becomes a permanent regression suite.

## 10. Out of scope (explicitly)

- #1319-class pure completion/validation gaps.
- Items already tracked in #1669/#1663/#1661/#1653 and not re-filed.
- #1782 PR-2 (separate; U2/#1786 unblocks its capture).
- The `1635-wip` local working-tree state.

## 11. Open questions for adversarial review (r2)

1. U6 split semantics: does anyone see a hole in A-for-operator /
   B-for-SyncApply / B-for-auto-rollback / not-arm-for-CommitConfirmed?
2. U10: widen-the-window vs coordinated-restart-suppression for the
   RestartHeartbeat grace gap — which, or both? And is 5×200 ms an acceptable
   detection-window default given VRRP owns fast failover?
3. U5a: is the FormatSet-fidelity sanity check sufficient to trust the
   generated corpus, or does FormatSet need its own differential test first?
4. U7: is sanitize-with-warning on Load the right migration (vs refuse-and-
   quarantine the offending field)?
5. U11: confirm no pair-consuming reader exists anywhere (incl. tests/tools),
   then Option B stands; otherwise fall back to A. Defer or do now?
6. Any remaining grouping/sequencing error or unit needing its own research
   round?
