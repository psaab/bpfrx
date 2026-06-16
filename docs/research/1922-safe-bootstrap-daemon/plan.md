# #1922 M1b — SAFE-BOOTSTRAP daemon work (plan of action)

**Revision:** v3 — 2026-06-16 (folds round-1 Claude SMR + AGY + Codex; converged)
**Branch:** `research/1922-safe-bootstrap-daemon`
**Status:** research only — STOP at PLAN-READY; no production code touched.

> This plan is the daemon-side subset of the SAFE-BOOTSTRAP design already
> converged in the #1879 research plan (`research/1879-install-simplify`,
> `docs/research/1879-install-simplify/plan.md` §5 SAFE-BOOTSTRAP, 3-of-3
> PLAN-READY at `ad37d95a8`). #1879/PR #1906 shipped Path C (appliance images
> + day-0 drive) and explicitly deferred the four M1b items to this issue.
> This plan re-grounds §5 against the *current* code, fixes the open questions
> §5 left to /engineer-time, and is itself subject to a fresh hostile review
> (§5's reviewers approved a packaging plan; M1b is the daemon-state subset and
> deserves its own adversarial pass).

---

## 1. Status

v3 — CONVERGED. Re-uses the converged #1879 §5 SAFE-BOOTSTRAP design. Scopes to
the four daemon-side deferred items (M1b). No code written. Round-1 verdicts (all
three NEEDS-CHANGES, none could PLAN-KILL — all code grounding verified correct):
**Claude SMR PLAN-NEEDS-CHANGES** (5 findings); **AGY PLAN-NEEDS-CHANGES**
(`adversarial-review-mqh0nudo-ov2222`, 2 CRITICAL + 2 HIGH); **Codex
PLAN-NEEDS-CHANGES** (1 High + 2 Med + 2 Low; all 4 required code checks PASS).
The three reviewers converged on the SAME architecture and the SAME required
changes. v2 folded SMR+AGY (changelog below); **v3 folds the two Codex
refinements (C7, C8)** — both are tightenings of existing changes, not new
architecture, so this is the convergence revision.

### Round-1 changelog (v1 → v2 → v3)

### Round-1 changelog (v1 → v2)

- **C1 (AGY F2 CRITICAL + SMR F3): gate takeover ACTIONS, not manager
  construction.** v1 said "gate the `!d.opts.NoDataplane` block behind
  `if !bootstrapMode`." That would leave `d.routing`/`d.frr`/`d.networkd`/`d.dp`
  nil; the apply path nil-guards every one of them, so the first confirmed
  commit (bootstrap exit) would silently skip all of them → permanently
  unconfigured. **v2:** managers are instantiated unconditionally at startup;
  only the *takeover actions* are gated (interface rename, host tunables,
  boot-time `applyConfig`, dataplane attach, FRR managed-section write, VRRP
  instance creation). See revised Item 2.
- **C2 (AGY F3 HIGH + SMR F4): bootstrap exit on SyncApply + explicit cluster
  short-circuit.** v1 exited bootstrap only on a local confirmed commit, which
  would strand a cluster secondary that first-boots empty and receives config
  via `SyncApply`. **v2:** (i) exit bootstrap on ANY successful apply of a
  non-empty config to the store (local confirmed commit OR `SyncApply`); (ii)
  the predicate short-circuits to NOT-bootstrap when `clusterMode==true` AND a
  node-id is present.
- **C3 (AGY F4 HIGH + SMR F2): marker migration rule fixed.** **v2:** the
  step-0 marker is **envelope option (a)** (a committed-generation field in the
  #1917 envelope, integrates with the #1799 retry loop), and a missing field on
  a DB written by an older build defaults to **committed=true** — an upgraded
  box with an existing active config can never misclassify into bootstrap.
- **C4 (SMR F1 + AGY OQ-A: corrupt-DB lifeline ordering decided).** **v2:**
  on a corrupt/too-new DB (case 4) the daemon does NOT write a new lifeline —
  fail-closed means touch nothing. Mgmt reachability for repair relies on the
  networkd files + lifeline record persisted by a PRIOR successful boot (which
  survive `networkctl reload` and restarts, invariant 2). A never-booted box
  with a corrupt day-0-seeded DB has no prior mgmt identity to preserve and
  falls back to the hypervisor/physical console — honest, bounded residual.
- **C5 (SMR F5: two-PR split adopted as the recommended sequencing).** PR-1 =
  Item 1 (commit-confirmed service-mode fixes + serialization test),
  independently valuable and low-churn; PR-2 = Items 2-4 (bootstrap mode +
  lifeline + protected-set). See §5 sequencing note + OQ-G.
- **C6 (SMR F3: startup subsystem gate matrix).** Added as a named
  /engineer-time deliverable (revised Item 2) — the highest-churn part of the
  diff.
- **OQ-D resolution (both reviewers): auto-exempt the protected interface from
  dataplane claim while still allowing mgmt-zone policy** (not strict
  refuse-zone-assignment). Recorded under Item 4 / OQ-D.
- **C7 (Codex Low — tighten Item 1 scope).** Codex verified the gRPC/REST
  `commit confirmed` FORWARD path is ALREADY correct: `commitConfirmedAndApply`
  (`daemon_apply.go:136-148`) acquires `applySem` then runs
  `store.CommitConfirmed` + `applyConfigLocked` together. The bug is ONLY the
  **timeout rollback executor** (the timer→`centralRollbackFn` path, mis-wired +
  non-atomic) and the **first-commit rollback target** (`prevCfg==nil`). **v3:**
  Item 1 scope is narrowed explicitly to those two — do NOT touch the
  already-serialized forward commit path. This shrinks PR-1's diff and removes a
  false target.
- **C8 (Codex Med — sharpen the C2 cluster short-circuit; node-id ≠
  clusterMode).** Codex found a real nuance: `clusterMode=true` is derived ONLY
  from a compiled active config carrying `Chassis.Cluster`
  (`daemon_run.go:256-259`), while node-id comes from `/etc/xpf/node-id`
  independently (`daemon.go:398-405`). So a node-id-only boot with no DB/xpf.conf
  is NOT structurally a cluster boot — C2's "clusterMode && node-id" can't fire
  because clusterMode is false until a cluster config loads. **v3 decision:** the
  cluster short-circuit keys on **node-id-file presence** (the
  install-time-stable signal), NOT on `clusterMode`: *a node with
  `/etc/xpf/node-id` present is HA-managed and resolves NOT-bootstrap* (case 2/3
  via its own DB/xpf.conf; if neither exists it is fail-safe-with-loud-error, and
  **HA availability is explicitly NOT promised for a node-id-only-no-config
  boot** — that is an operator misconfiguration, documented). This matches how
  `cluster-setup.sh:886-909` always pushes config + node-id + clears `.configdb`
  before enabling xpfd. Belt-and-suspenders bootstrap-exit-on-`SyncApply` (C2)
  remains.

## 2. Issue framing

#1879/PR #1906 ("M1b adjudication") shipped the appliance-image safe-bootstrap
*structurally* — vNIC#1→fxp0 is an image property, day-0 config is validated
*before* install, and a no-config first boot uses the existing fxp0-DHCP
bootstrap. It explicitly named four daemon-side gaps that the image path does
not need but a **foreign-host / non-appliance install** (M1a `.deb`, manual
install) does:

1. **commit-confirmed service-mode fixes** — a bad/non-applying `commit` must
   not strand mgmt; in service mode (no TTY) the auto-rollback must restore the
   last-good config. PR #1906 named the two concrete holes:
   `pkg/cli/cli.go:289` (rollback callback registration) and the
   `prevCfg == nil` first-commit case in `pkg/configstore/store.go`.
2. **Explicit bootstrap mode + five-case boot predicate** — a deterministic
   predicate that classifies the boot into fresh / day-0-present / valid-active
   / corrupt-or-too-new / degraded, selecting bootstrap vs normal vs fail-safe.
3. **PCI-keyed lifeline interface** — make "mgmt is reachable" a *daemon*
   property (not just an image property) so a foreign host with no/blank/broken
   config always keeps one reachable mgmt NIC.
4. **Protected-set enforcement** — the daemon must NEVER bring down the
   lifeline/mgmt NIC during interface reconciliation.

This hardens #1917 D1 (MERGED, `3569af7d6`): `Store.Load` returns
`ErrConfigDBUnreadable` on a present-but-unparseable / too-new config DB and
`daemon_run.go:208-220` makes that **fatal** (fail closed, refuse to start and
overwrite). The D1 comment block at `daemon_run.go:204-207` literally names
#1922 as the foreign-host hardening that makes fail-closed safe — without a
guaranteed mgmt lifeline, fail-closed on a corrupt DB could strand a remote
box that the operator can no longer reach to repair the DB.

## 3. Honest scope / value framing

**What this buys:** the daemon stops being able to lock an operator out of a
remote box it manages, in four ways: (a) a bad first interactive `commit`
auto-reverts and restores mgmt (today the service-mode rollback callback is
mis-wired and the first-commit rollback target is wrong); (b) a fresh/foreign
host enters a defined *bootstrap mode* that does NOT rename NICs / cycle links /
take over networkd / load the dataplane until the operator has committed a
config it confirmed; (c) the management NIC is identified and preserved across
the rename by PCI address, not by the convention "mgmt happens to be idx 0";
(d) the reconcile path can never down the protected mgmt NIC.

**What this is NOT:** packaging (M1a `.deb` is a separate issue — debian/ already
exists in-tree), the install.sh path (M3), the appliance image (shipped). No
hot-path / dataplane-loop code. No change to the day-0 image flow (it resolves
NOT-bootstrap before any interactive session, by design).

**Honest cost:** this touches three load-bearing daemon subsystems — startup
ordering (`daemon_run.go`), configstore commit-confirmed/rollback
(`pkg/configstore/store.go`), and the unmanaged-interface strip
(`pkg/dataplane/compiler_iface.go:compileZones`). Every existing deployment
(all test VMs, the loss cluster, every box with a committed or cleanly-preseeded
config) MUST resolve NOT-bootstrap and see zero behavior change except the
protected-set exemption (a strict safety widening). The five-case predicate's
single job is to be provably no-op for those.

## 4. What's already shipped / partially batched (current code, grounded)

- **#1917 D1 (MERGED `3569af7d6`):** `Store.Load` →
  `fmt.Errorf("read config: %w: %w", ErrConfigDBUnreadable, err)` on a
  present-but-unreadable DB (`store.go` Load, ReadActive failure path);
  `daemon_run.go:208-220` makes it fatal with operator guidance pointing at
  `.configdb/active.json`. `envelope.go` defines `ErrConfigDBUnreadable`;
  `envelope_test.go` proves too-new / garbage → tagged. **This is the corrupt /
  too-new case of the five-case predicate — already wired, M1b consumes it.**
- **Commit-confirmed core (#1799/#1817):** `Store.CommitConfirmed`
  (`store.go:1065`), `ConfirmCommit` (:1134), `performAutoRollback` (:1166)
  with the `confirmGen` staleness guard and the #1799 persist-before-promote
  ordering. **The mechanism exists; the two M1b holes are (a) the rollback
  *executor* and (b) the first-commit rollback *target*.**
- **fxp0 bootstrap:** `enumerateAndRenameInterfaces` (`linksetup.go:48`) +
  `writeBootstrapFxp0Network` (:291, DHCP-only). PCI enumeration
  (`enumeratePCINICs`, :136) already extracts the PCI bus address per NIC —
  **the lifeline-keying input already exists, it is just discarded after sort.**
- **Day-0 loader (PR #1906):** `scripts/image/xpf-day0-config` +
  `configstore.CheckText` / `xpfd check-config`. Validates day-0 config BEFORE
  install. The image path therefore never enters the M1b interactive-commit gate.
- **Unmanaged strip:** `compileZones()` in
  `pkg/dataplane/compiler_iface.go:1060-1150` enumerates all kernel NICs, marks
  any not in the config `Unmanaged=true` → `networkd.go:406` emits
  `ActivationPolicy=always-down` + immediate `LinkSetDown` + address strip
  (:1134-1149). **No fxp0 / mgmt exemption today** — this is the protected-set
  enforcement site.

## 5. Concrete design — the four M1b items

> Reuses #1879 §5 mechanisms. Diff surface is bounded to: `pkg/configstore/`
> (predicate marker + rollback executor hook), `pkg/daemon/` (startup gating,
> lifeline record, rollback-transaction ownership, `enterBootstrapMode`),
> `pkg/dataplane/compiler_iface.go` (protected-set exemption), `pkg/config/`
> (one schema leaf), and the relevant docs/tests. Zero dataplane-loop code.

**Recommended sequencing — two PRs (C5).** **PR-1 = Item 1** (commit-confirmed
service-mode fixes + the rollback-vs-concurrent-commit serialization test):
independently valuable, hardens an existing shipped feature, no startup-gating
churn, low risk. **PR-2 = Items 2-4** (bootstrap mode + five-case predicate +
PCI-keyed lifeline + protected-set): the cohesive larger change with the
high-churn startup gate. Bisectable; lets the risky gate land separately; gives
an early operator win. Each PR carries its own named must-pass tests (§9).

### Item 1 — commit-confirmed service-mode fixes

**1a. Daemon-owned rollback transaction (Codex #1879 r2-1, GROUNDED).**
Today the rollback executor is a CLI-registered callback
(`cli.go:289` → `c.applyConfigFn` = `d.applyConfig`). Two confirmed problems:

- **Service-mode mis-wiring:** the callback is registered in `CLI.Run`
  (`cli.go:284`), i.e. the *interactive* shell. A `commit confirmed` issued
  over gRPC/REST (service mode, the foreign-host SSH-then-`cli`-then-gRPC path,
  or an automation client) arms the timer in the store, but if no interactive
  `CLI.Run` ran in *this daemon process* the central rollback fn may be nil →
  `performAutoRollback` reverts the in-memory config and persists it but
  **`fn == nil` so the kernel/dataplane is never re-applied** (`store.go:1215`).
  Mgmt stays broken on the unconfirmed config's kernel state. (Note: the
  in-process `cli` command path does register it; the remote `cli` binary over
  gRPC and any non-CLI committer do not.)
- **Atomicity violation:** `performAutoRollback` mutates `s.active`/`s.compiled`
  (`store.go:1178-1179`) and persists (:1197) BEFORE invoking `fn`
  (:1216), and `fn`=`d.applyConfig` only holds `applySem` *around its own apply*.
  A concurrent `commit` can interleave between store-promotion and rollback-apply
  → store says new-commit while kernel says rollback (violates the
  commit→apply atomicity contract; cf. `pkg/daemon/apply_serialize_test.go`,
  `pkg/configstore/README.md`).

**Fix (plan-level requirement; exact hook shape is /engineer's call):** the
daemon owns the whole rollback transaction. The confirm timer fires into a
daemon-registered executor that **acquires `d.applySem` FIRST, then performs
store promotion + reconcile apply inside the same critical section**, so
promotion and apply are atomic under `applySem`. Registration moves from
`CLI.Run` to daemon init (so it is wired in service mode regardless of whether
an interactive shell ran). The interactive shell's existing handler reduces to a
TTY notification. A dedicated serialization test (rollback-vs-concurrent-commit)
lands alongside `apply_serialize_test.go`.

**Scope (C7, Codex-verified):** the fix touches ONLY the timeout-rollback
executor and the first-commit rollback target (1b). The gRPC/REST/CLI FORWARD
`commit confirmed` path is ALREADY correct — `commitConfirmedAndApply`
(`daemon_apply.go:136-148`) acquires `applySem` then runs `store.CommitConfirmed`
+ `applyConfigLocked` together. Do NOT refactor the forward path.

*Path option A (executor callback):* store exposes a registration like
`SetRollbackExecutor(func(target) error)`; `performAutoRollback` defers ALL
mutation into the executor (executor acquires `applySem`, promotes store state
via a store method, applies). *Path option B (promotion-deferral):*
`performAutoRollback` computes the target and hands it to the daemon, which
acquires `applySem` then calls a store `PromoteRollback(target)` + apply in one
section. **Recommended: B** — keeps the store the single owner of the
promotion primitive (no second mutation path), matches how
`commitAndApply`/`syncAndApply` already pair store-mutation with apply under
`applySem` (`daemon_apply.go:86,116`). A must NOT bypass the #1817 `confirmGen`
guard or the #1799 persist-failure semantics either way.

**1b. First-commit (`prevCfg == nil`) rolls back to bootstrap, persists
never-committed (AGY #1879 r2-2, GROUNDED).** On a fresh box the FIRST
`commit confirmed` sets `confirmPrevTree = s.active.Clone()` (empty tree) and
`confirmPrevCfg = s.compiled` (`store.go:1096-1097`). On timeout:
`performAutoRollback` sets `s.active = empty`, **persists the empty tree to disk
via `writeActive`** (:1197), and at :1215 `prevCfg == nil` (no compiled
empty) means **`fn` is never even called** — the dataplane keeps running the
unconfirmed first-commit's state. Two bugs: (i) mgmt-affecting takeover is not
reverted; (ii) the on-disk empty *committed* tree makes a subsequent restart
classify committed-empty → NOT bootstrap (Item 2) → full takeover on an empty
config. Worse than today.

**Fix:** the `prevCfg == nil` (genuinely first-commit) case rolls back via
`enterBootstrapMode` (Item 2's cleanup sequence), NOT via a normal apply of an
empty tree, AND it must NOT write an empty *committed* tree — it persists the
**never-successfully-committed** marker (Item 2 step-0 below). This requires the
store to distinguish "never committed" from "operator committed empty".

### Item 2 — explicit bootstrap mode + five-case boot predicate

**Step-0 marker (prerequisite) — DECIDED in v2 (C3).** The store distinguishes
*never-successfully-committed* from *operator-committed-empty* via **envelope
option (a): a committed-generation field in the #1917 config-DB envelope**
(0 / absent = never committed; ≥1 = committed). This integrates cleanly with the
#1799 persist-degraded retry loop (the field rides the same envelope write) and
does not disturb `ErrConfigDBUnreadable` detection (it is a header field, not a
new file). **Migration rule (C3, mandatory):** a DB written by an older build
lacks the field; the new reader MUST default a missing field on an otherwise
valid envelope to **committed=true** — an upgraded box with an existing active
config can NEVER misclassify into bootstrap. (Belt-and-suspenders: any persisted
active tree, empty or not, also reads as committed; the never-committed marker is
forward-only, applied only to DBs this build itself created without a successful
commit.) Today `ActiveConfig()` returns `s.compiled` (nil when nothing loaded)
and an absent DB (`ReadActive` → `tree == nil`) returns nil from `Load`
(start-fresh); there is no marker yet.

**The five-case predicate** (computed once at startup and on
rollback-to-bootstrap; stable across restarts). Each case maps to exactly one of
{bootstrap, normal, fail-safe}:

| # | Boot condition (grounded in current code) | Predicate result | Today's behavior | M1b behavior |
|---|---|---|---|---|
| 1 | **Fresh / no config**: absent `.configdb` (`ReadActive` → nil) AND no readable `xpf.conf` (or `bootstrapFromFile` import fails) | **bootstrap** | renames all NICs, DHCP fxp0, takes over interfaces on empty config | bootstrap mode: no rename (except lifeline path), no takeover, fxp0 DHCP, control plane up |
| 2 | **Day-0 / preseeded valid**: absent DB but `xpf.conf` imports cleanly (every existing test/cluster deploy; the day-0 image path) | **normal** | bootstrap from file → full takeover | **unchanged** (zero regression — this is the no-op case) |
| 3 | **Valid active.json**: DB present, `Load` succeeds, `ActiveConfig() != nil` | **normal** | loads from DB, full takeover | **unchanged** |
| 4 | **Corrupt / too-new active.json**: `Load` → `ErrConfigDBUnreadable` (#1917 D1, MERGED) | **fail-safe** (fatal-on-parse) | **already** fatal: refuse to start (`daemon_run.go:209`) | **unchanged fatal — touch nothing** (C4). No NEW lifeline is written (fail-closed). Mgmt reachability for repair relies on the networkd files + lifeline record persisted by a PRIOR successful boot (invariant 2). A never-booted box with a corrupt day-0 DB has no prior mgmt identity → hypervisor/physical console (bounded residual). |
| 5 | **Degraded / never-confirmed**: never-successfully-committed (incl. the post-rollback-from-first-commit state from Item 1b), OR operator-committed-empty | never-committed → **bootstrap**; committed-empty → **normal** (operator meant it; protected set still shields mgmt) | committed-empty and never-committed are indistinguishable today | the step-0 marker (C3) disambiguates |

**Cluster / HA-node guard (C2 + C8, mandatory):** keyed on **`/etc/xpf/node-id`
presence** (the install-time-stable HA signal), NOT on `clusterMode` — Codex
verified `clusterMode=true` is derived only from a compiled active config with
`Chassis.Cluster` (`daemon_run.go:256-259`), so it is false until a cluster
config loads and cannot be used to pre-empt the predicate. Rule: a node with
`/etc/xpf/node-id` present is HA-managed; it resolves NOT-bootstrap via its own
persisted DB or preseeded `xpf.conf` + node-id (case 2/3, the
`cluster-setup.sh:886-909` deploy path). **If an HA node has node-id but NEITHER
a DB nor an importable `xpf.conf`, it is fail-safe-with-loud-error and HA
availability is explicitly NOT promised** (operator misconfiguration —
documented, tested). Belt-and-suspenders: bootstrap-exit also fires on a
successful non-empty `SyncApply` from the primary (so even a hypothetical
empty-boot secondary recovers on first config sync).

**Bootstrap mode, defined** (new — does not exist today). Active iff the
predicate yields bootstrap. In bootstrap mode the daemon: runs gRPC/REST/CLI as
normal; performs **NO** PCI rename beyond the lifeline-gated path (Item 3),
**NO** link down/up cycles, **NO** networkd takeover writes except the lifeline
`.network`, **NO** AF_XDP attach / dataplane load, **NO** FRR managed-section
writes, **NO** boot-time `applyConfig`, **NO** VRRP instance creation.

**Gate ACTIONS, not construction (C1, CRITICAL).** v1's "gate the
`!d.opts.NoDataplane` block at `daemon_run.go:231-307` behind `if !bootstrapMode`"
was WRONG: the apply path nil-guards every manager (`d.routing`/`d.frr`/
`d.networkd`/`d.dp`), so leaving them nil would make the first confirmed commit
(bootstrap exit) silently skip all of them → permanently unconfigured. **v2: all
managers are constructed unconditionally at startup; only the takeover ACTIONS
are suppressed in bootstrap mode.** The /engineer deliverable (C6) is a **startup
subsystem gate matrix** classifying each subsystem as construct-always /
arm-only-when-not-bootstrap:

| Subsystem | Construct at boot? | Armed/actuated in bootstrap? |
|---|---|---|
| gRPC / REST / CLI control surfaces | yes | **yes** (management must work) |
| routing / FRR / networkd / dataplane managers | yes | **no** (no managed-section / takeover writes / AF_XDP attach) |
| `enumerateAndRenameInterfaces` rename loop | n/a | **no** (except the lifeline-gated path, Item 3) |
| host tunables / RSS indirection | n/a | **no** |
| boot-time `applyConfig` | n/a | **no** |
| VRRP / cluster takeover | constructed if clusterMode (but clusterMode ⇒ NOT bootstrap per C2) | n/a in bootstrap |

**Exit from bootstrap mode (C2):** happens on the FIRST successful apply of a
non-empty config to the store — a local confirmed commit (Item 1 / 4-gate) OR a
cluster `SyncApply` from the primary — which then runs the full normal startup
reconcile (rename, networkd, dataplane, FRR). Exit is one-way for the daemon's
lifetime.

*Path option for predicate placement:* (A) compute in `daemon_run.go` right
after `Load()` + `bootstrapFromFile()` resolve, using `ActiveConfig() != nil`
plus the step-0 marker; (B) a store method `BootMode()` that encapsulates the
five cases. **Recommended A for the gate decision, B for the marker query** —
the gate is a daemon-startup concern (it controls daemon subsystems), the
never-vs-empty distinction is store state.

**First-takeover gate (Junos commit-confirmed model).** When current mode is
bootstrap, a plain `commit` of an interface-owning config is **refused** with
guidance: `first commit on this system must be 'commit confirmed <minutes>'
(interface takeover can cut off management; the system rolls back automatically
unless confirmed)`. On confirm-timeout, the daemon-owned rollback (Item 1a)
executes `enterBootstrapMode`. Escape hatch `commit no-confirm` for console
installs. Day-0 configs bypass by design (predicate already resolved
NOT-bootstrap before any interactive session). **OQ-B:** gate scope — any first
commit (blunt, simple) vs only interface-claiming first commits (precise, more
logic). #1879 §5 recommended blunt-with-`no-confirm`-escape; this plan inherits
that pending review.

**`enterBootstrapMode` — explicit cleanup, NOT apply(empty).** A failed first
takeover leaves real state: xpf networkd files, FRR managed section, VRRP
instances, a running helper with AF_XDP sockets, renamed NICs. A normal
`applyConfig(empty)` is wrong — the userspace apply path *ensures the helper
exists* (`pkg/dataplane/userspace/manager.go`) i.e. it would resurrect the
dataplane bootstrap promises not to run. The sequence, in order: (1) remove
xpf-written `.network`/`.link` takeover files EXCEPT the lifeline `.network` and
the `.link` files, `networkctl reload`; (2) clear the FRR managed section + remove
VRRP instances; (3) stop the dataplane helper / detach AF_XDP (inverse of
startup load; exact teardown call audited at /engineer time); (4) re-assert
bootstrap-mode suppressions for the daemon's lifetime. **Renames persist
deliberately** — reverting would link-cycle a degraded box for cosmetic benefit.
Post-rollback bootstrap state = renamed NICs + lifeline `.network` (matching the
post-rename name via the PCI-keyed record) + zero config-driven claims. Tests are
reachability/claims-based, never name-restoration-based.

### Item 3 — PCI-keyed lifeline interface

**Lifeline preservation at first start.** When the predicate yields bootstrap,
before any rename: xpfd identifies the interface carrying the current IPv4/IPv6
default route and records its **PCI bus address + MAC** (the PCI address is
already extracted by `enumeratePCINICs` at `linksetup.go:136-166` and currently
discarded after sort) to a persistent record (e.g. `/etc/xpf/lifeline-interface`).
**Keyed by PCI address (+ MAC tiebreaker for non-PCI NICs), NOT by name** (AGY
#1879 r2 Critical): a name-keyed record goes stale the instant the rename turns
recorded `enp5s0` into `fxp0`, dropping it from the protected set exactly when
rollback needs it. Protected-set evaluation (Item 4) resolves the recorded PCI
address to the device's *current* name at reconcile time.

- If the default-route interface is the one that would become fxp0 (idx 0):
  snapshot its *current* addressing into the bootstrap `.network` —
  `Address=`/`Gateway=`/`DNS=` when static, plain DHCP when DHCP — so the
  rename's link cycle restores the same reachability. This replaces today's
  DHCP-only `writeBootstrapFxp0Network` (`linksetup.go:291`).
- If the default-route interface would NOT become fxp0: **no rename, no link
  cycle, no takeover** — log loudly, stay in bootstrap mode, require the operator
  to re-wire or set `system management-interface` + commit.

Diff surface: one guard before the rename loop in `enumerateAndRenameInterfaces`
(`linksetup.go:64-88`) + the lifeline-aware bootstrap writer (replacing
`writeBootstrapFxp0Network`) + a small persistent-record reader/writer.

*Path options for lifeline IDENTIFICATION* (the design's main branch point):
- **(A) Default-route interface** (recommended primary signal). Detect the
  interface of the active IPv4 default route; fall back to IPv6 default route;
  else refuse takeover and stay in bootstrap. Simple, matches "the NIC the
  operator reaches the box on" in the common single-homed case.
- **(B) Explicit `system management-interface <name>` config leaf** (TNSR
  model). New schema leaf (default `fxp0`). Authoritative when present. Does NOT
  help the genuinely-fresh no-config box (no leaf yet) — so it composes WITH
  (A), it does not replace it.
- **(C) MAC-only / first-NIC heuristic** — rejected as primary: re-introduces
  the "mgmt happens to be idx 0" fragility this item is meant to kill.
- **Recommended: (A) for the no-config first boot + (B) as the operator override
  once a config exists.** The persistent record is keyed by PCI+MAC regardless of
  which signal selected it. **OQ-C:** multi-homed / split v4-v6 default route /
  policy-routed mgmt ambiguity (#1879 OQ-5) — the proposed resolution is "v4
  default, else v6 default, else refuse-and-instruct".

### Item 4 — protected-set enforcement

**The enforced protected set** = union of: (a) the `system management-interface`
leaf value when present (Item 3 option B), (b) the default `fxp0`, (c) the
lifeline-recorded interface resolved from its PCI address to the current name
(Item 3). (b) and (c) are effective **even when the active config is empty,
absent, corrupt, or rolled back** — that is the whole point.

**Enforcement site:** `compileZones()` in
`pkg/dataplane/compiler_iface.go:1060-1150` and the `.network` writer
(`networkd.go:406`). A protected interface is **never** marked
`Unmanaged=true`, never `ActivationPolicy=always-down`, never address-stripped
(:1134-1149), never bound into the dataplane. The protected-set membership lives
**outside the config tree** (in the reconcile path), so the designation cannot
be removed by the very rollback it protects (#1879 r1-S2/AGY-3).

Today `compileZones` has a `daemonOwned` exemption map (vrf-mgmt, tunnels,
fabric, bridges) but **no fxp0/mgmt exemption** — fxp0 is protected only by being
in the config. M1b adds the protected-set resolution into that exemption check.

*Path option for the protected-set plumbing:* (A) resolve the protected set in
the daemon and pass it into the compiler call that builds `ManagedInterfaces`;
(B) the compiler reads the lifeline record + leaf directly. **Recommended A** —
keeps the compiler a pure function of (config, protected-set input) and keeps
file/sysfs I/O (PCI→name resolution) in the daemon, matching the existing
pattern where the daemon assembles inputs and the compiler is deterministic.

**OQ-D — RESOLVED in v2 (both reviewers):** **auto-exempt** the protected
interface from dataplane claim while still allowing normal mgmt-zone policy to
apply. (Not strict Junos refuse-zone-assignment — that is more rigid than xpf
needs and breaks an operator who wants mgmt-zone firewall policy on fxp0.)
Residual question for review: is the protected-set union too wide for a box that
legitimately repurposes fxp0 as a revenue port? Proposed mitigation: the
`system management-interface` leaf, when explicitly set to a non-fxp0 NIC,
*narrows* (b) so fxp0 is no longer auto-protected — i.e. the operator can move
the protection off fxp0. Confirm this is the right escape valve.

## 6. Operator-facing surface preservation

- All `make` targets, `test/incus/setup.sh`, `cluster-setup.sh` flows unchanged.
  Every existing deployment resolves NOT-bootstrap (case 2 or 3) → zero behavior
  change except the protected-set exemption (strict safety widening).
- CLI grammar: additive only — `system management-interface` (Item 3B) and
  possibly `commit no-confirm` (Item 2 escape hatch; verify whether a
  no-confirm form already exists or must be added).
- The day-0 image path (PR #1906) is untouched — it resolves NOT-bootstrap
  before any interactive session.
- gRPC/REST/CLI control surfaces run in bootstrap mode exactly as in normal mode
  (the gate only suppresses takeover, not management).

## 7. Hidden invariants the change must preserve

1. **#1917 D1 fail-closed:** corrupt/too-new DB stays fatal (case 4). M1b only
   adds lifeline reachability around it; it must not downgrade fatal-on-parse.
2. **Interface lifeline:** between "fresh boot" and "first confirmed commit" the
   mgmt path must not depend on an un-renamed kernel NIC name or an address the
   daemon is about to remove. The lifeline `.network` survives `networkctl
   reload`, daemon restarts, and rollback-to-bootstrap.
3. **Protected-set enforcement is config-independent:** the designation
   (leaf ∪ fxp0 ∪ lifeline-record) lives in the reconcile path, not (only) the
   config tree, so it holds under empty/absent/rolled-back configs. On a
   **corrupt/too-new DB the daemon is fatal (case 4) and never runs reconcile** —
   there protected-set "enforcement" is only the *persisted* prior lifeline/
   networkd state (no new reconcile or write occurs on a corrupt DB); a
   never-booted corrupt box has no prior state (console-only, bounded residual).
4. **RETH `.link` semantics** (`MACAddress=` vs `OriginalName=`,
   `ensureRethLinkOriginalName`), `KeepConfiguration=static` VIP preservation,
   and FPC-7 node-1 naming untouched — the SAFE-BOOTSTRAP diff is confined to the
   bootstrap-predicate path and the fxp0 bootstrap writer.
5. **#1799 persist semantics:** the step-0 marker and the rollback executor must
   not alter `persistDegraded`/retry or the #1817 `confirmGen` guard or HA
   `SyncApply`.
6. **Commit→apply atomicity:** rollback promotion + apply atomic under
   `applySem` (the Item-1a fix); a dedicated serialization test enforces it.
7. **No new hot-path code:** entirely control-plane/startup work; zero
   dataplane-loop changes.
8. **Cluster behavior:** `/etc/xpf/node-id` present ⇒ HA-managed ⇒ NOT-bootstrap
   via the node's own DB/xpf.conf (C2+C8 — keyed on node-id FILE, not the
   config-derived `clusterMode`), so a cluster member can never enter bootstrap
   mode on a normal deploy. node-id-without-config = fail-safe-with-loud-error
   (HA availability not promised). Bootstrap exit also fires on `SyncApply` as a
   second guard. `make test-failover` enforces no failover regression.
9. **Manager construction is unconditional (C1):** bootstrap mode suppresses
   takeover ACTIONS only; `d.routing`/`d.frr`/`d.networkd`/`d.dp` are never nil,
   so the bootstrap-exit reconcile wires every subsystem.
10. **Marker is forward-only (C3):** a pre-M1b DB (no committed field) reads as
    committed=true; only DBs this build creates without a successful commit ever
    read never-committed — no upgrade can misclassify into bootstrap.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (existing deployments) | MED | Touches daemon startup, configstore rollback, unmanaged-strip. Mitigations: the predicate is provably NOT-bootstrap for cases 2/3 (every existing deploy) with an explicit case-matrix test; protected-set is a strict safety widening; `make test-failover` gates daemon-startup changes; the Item-1a serialization hazard is fixed by design + a dedicated test |
| Lockout / safety regression | LOW (net improvement) | The plan's purpose. Riskiest sub-items: the lifeline static-snapshot writer and the synthesized-bootstrap rollback target — both carry named must-pass tests |
| Cluster misclassification | MED | A secondary entering bootstrap mode would refuse takeover and break HA. OQ-E + a cluster-boot predicate test + `make test-failover` |
| Predicate edge cases | MED | committed-empty vs never-committed disambiguation depends on the step-0 marker being correct across the #1799 persist-degraded path; explicit five-case unit tests |
| Architectural mismatch | LOW | All mechanisms reuse existing primitives (commit-confirmed + #1799/#1817, linksetup PCI enumeration, compileZones exemption map, applySem). No new daemons/state stores |
| Scope creep | MED | Must NOT pull in M1a packaging, M3 install.sh, or image work; reviewers police re-entry |

## 9. Test plan

- **Unit/Go** (`make test`): (a) five-case predicate table test (absent DB±
  xpf.conf, failed import, valid DB, `ErrConfigDBUnreadable`, committed-empty vs
  never-committed); (b) step-0 marker survives the #1799 persist-degraded path;
  (c) Item-1a rollback-vs-concurrent-commit serialization test alongside
  `apply_serialize_test.go` (promotion + apply atomic under `applySem`);
  (d) Item-1b `prevCfg == nil` → `enterBootstrapMode` in service mode (no TTY),
  and restart-after-timed-out-first-commit stays bootstrap (predicate stability);
  (e) PCI-keyed lifeline resolution across a simulated rename
  (recorded PCI → new name); (f) protected-set never marks fxp0/lifeline
  `Unmanaged` even with empty/absent/rolled-back config (compileZones test);
  (g) `system management-interface` schema test (if Item 3B lands);
  (h) **marker migration (C3):** a pre-M1b DB (populated or empty active tree,
  no committed-generation field) → reads committed=true → NOT bootstrap;
  (i) **HA-node guard (C2+C8):** `/etc/xpf/node-id` present ⇒ NOT bootstrap when
  a DB/xpf.conf exists; node-id-without-config ⇒ fail-safe-with-loud-error (HA
  not promised); and bootstrap-exit-on-`SyncApply`;
  (j) **manager-nonnil (C1):** bootstrap-then-exit reconcile actually actuates
  routing/FRR/networkd/dataplane (managers constructed at boot, never nil).
- **Named must-pass integration (standalone incus VM):**
  - **T1 rollback-restores-lifeline:** first `commit confirmed 1` with a
    deliberately broken/lockout config in SERVICE mode (no interactive shell), do
    not confirm → after timeout, mgmt reachable on the lifeline address, bootstrap
    `.network` intact, daemon in bootstrap mode. Run twice: DHCP mgmt and static mgmt.
  - **T2 fresh-foreign-host bootstrap:** wipe `.configdb` + `xpf.conf`, boot →
    bootstrap mode, fxp0 DHCP reachable, NICs NOT renamed beyond lifeline path,
    dataplane NOT armed; `commit confirmed` + confirm → full takeover.
  - **T3 corrupt-DB fail-closed (C4):** write a too-new envelope DB (case 4) on a
    PREVIOUSLY-BOOTED node → daemon fatal per #1917 D1, NO new lifeline written,
    mgmt still reachable for repair via the prior-boot lifeline/networkd files.
    Negative case: a never-booted box with a corrupt day-0 DB has no prior mgmt
    identity → console-only (bounded residual, asserted not silently masked).
  - **T4 mgmt-not-idx-0 refusal:** default route on a non-idx-0 NIC → daemon
    refuses takeover, stays bootstrap, logs loudly, mgmt stays reachable.
- **HA:** `make test-failover` for any commit touching daemon startup /
  configstore / linksetup (standing rule); plus a cluster-boot test proving a
  secondary never misclassifies into bootstrap (OQ-E). Local legacy cluster
  (`CLUSTER_ENV=`), never the shared loss cluster.
- **No-regression:** `make test-vm && make test-deploy` end-to-end (this exercises
  case 2 — preseeded `xpf.conf` → NOT bootstrap → unchanged takeover).

## 10. Out of scope (explicitly)

- M1a policy-correct `.deb` packaging + `xpf-upgrade` wrapper (separate; debian/
  exists in-tree already — do not refactor it here).
- M3 Tailscale-style `install.sh` + signed apt repo.
- The appliance image / day-0 flow (shipped in PR #1906; untouched).
- Migrating hosts from ifupdown/NetworkManager to networkd automatically (#1879
  OQ-3 records refuse-and-instruct).
- Any change to the shared loss-cluster deploy flow.
- CLI-orchestrated ISSU; A/B image rollback; cloud-init modules.
- Any dataplane-loop / hot-path code.

## 11. Open questions for adversarial review

- **OQ-A — RESOLVED (C4):** corrupt-DB boot writes no new lifeline (fail-closed);
  reachability relies on the prior-boot networkd files + lifeline record; a
  never-booted corrupt box = console. Residual accepted as bounded.
- **OQ-B (first-commit gate scope):** any first commit vs only interface-claiming
  first commits. Is the `commit no-confirm` escape hatch itself a foot-gun on a
  foreign host (operator types it reflexively, locks themselves out)? *Still open.*
- **OQ-C (lifeline detection heuristic):** default-route interface as primary
  signal — sufficient for multi-homed / split v4-v6-default / policy-routed mgmt?
  Is "v4 default, else v6 default, else refuse" the right fallback ladder?
  *Still open.*
- **OQ-D — RESOLVED (v2):** auto-exempt-from-claim (not refuse-zone-assignment);
  explicit non-fxp0 `system management-interface` narrows the auto-protection off
  fxp0. Confirm the escape valve.
- **OQ-E — RESOLVED (C2 + C8):** the HA-node guard keys on `/etc/xpf/node-id`
  presence (NOT `clusterMode`, which is config-derived per Codex), resolving
  NOT-bootstrap via the node's own DB/xpf.conf; node-id-without-config is
  fail-safe-with-loud-error and does NOT promise HA availability;
  bootstrap-exit-on-`SyncApply` is the belt-and-suspenders guard. Cluster-boot
  test in §9.
- **OQ-F — RESOLVED (C3):** envelope option (a) (committed-generation field),
  missing-field-defaults-committed=true migration rule.
- **OQ-G — RESOLVED (C5):** ship as two PRs (Item 1; then Items 2-4). Reviewers
  may still PLAN-KILL a sub-item, but the split is the recommended sequencing.
