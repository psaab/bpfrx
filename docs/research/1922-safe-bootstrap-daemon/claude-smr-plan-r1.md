# Claude SMR — hostile plan review r1 (#1922 SAFE-BOOTSTRAP daemon)

Reviewing `docs/research/1922-safe-bootstrap-daemon/plan.md` v1 as domain SMR +
CPU-arch/concurrency + SW-design. Posture: hostile. I verified the load-bearing
code claims against the worktree rather than trusting the plan's citations.

## Verified-true claims (the plan is grounded, not hand-wavy)

- **Item-1a atomicity hazard is REAL.** `performAutoRollback` mutates
  `s.active`/`s.compiled` (`store.go:1178-1179`) and persists
  (`writeActive`, :1197) BEFORE invoking the central rollback fn (:1216). That
  fn (`d.applyConfig` via `cli.go:289`) only holds `applySem` around its own
  apply. `apply_serialize_test.go`'s own header states the contract is "the
  commit→apply pair is atomic **per caller**" — and `performAutoRollback` is NOT
  one of the serialized callers (it is not `commitAndApply` /
  `commitConfirmedAndApply` / `applyConfig`; it pre-mutates store state then
  calls a callback). So a concurrent commit CAN interleave between store
  promotion and rollback apply. The plan's Item-1a is correctly motivated and
  the recommended Path B (store owns a `PromoteRollback` primitive, daemon wraps
  promotion+apply under applySem) is the right shape.
- **Item-1a service-mode mis-wiring is REAL.** `SetCentralRollbackHandler` is
  called inside `CLI.Run` (`cli.go:284`), i.e. only when an interactive shell
  runs in this process. A `commit confirmed` over gRPC/REST with no interactive
  `CLI.Run` leaves `centralRollbackFn` nil → at `store.go:1215` `fn != nil` is
  false → kernel/dataplane never re-applied on timeout. Confirmed.
- **Item-1b prevCfg==nil hole is REAL.** First `commit confirmed` sets
  `confirmPrevTree=s.active.Clone()` (empty) / `confirmPrevCfg=s.compiled`
  (`store.go:1096-1097`). On timeout it persists the empty tree (:1197) and
  `prevCfg==nil` short-circuits the apply (:1215). Both sub-bugs the plan names
  are present. The "persists committed-empty → restart misclassifies" knock-on
  is correct and is exactly why Item 2's step-0 marker is a prerequisite, not a
  nice-to-have. Good chaining.
- **#1917 D1 is MERGED and is case 4.** `daemon_run.go:208-220` makes
  `ErrConfigDBUnreadable` fatal; `envelope_test.go` proves too-new/garbage gets
  tagged. The plan correctly *consumes* D1 rather than re-implementing it.
- **Item 3 input already exists.** `enumeratePCINICs` extracts `busAddr`
  (`linksetup.go:166`) and discards it after sort — keying the lifeline record
  by PCI is a small, real addition, not a new subsystem.
- **Item 4 site is correct and has NO mgmt exemption today.** `compileZones`
  has a `daemonOwned` map (vrf-mgmt/tunnel/fabric/bridge) but fxp0 is protected
  only by being in the config; an absent/empty config WILL mark fxp0
  `Unmanaged=true` → `networkd.go:406` always-down + `LinkSetDown` +
  address-strip (`compiler_iface.go:1134-1149`). The lockout the plan describes
  is genuinely reachable today.

## Findings (severity-ranked)

### F1 — Med — OQ-A is the load-bearing gap, and v1 under-commits.
The corrupt-DB case (4) exits fatal at `daemon_run.go:209`, which is BEFORE the
enumerate/lifeline block at :231. So on a box whose DB went corrupt/too-new, the
lifeline-write path never runs *on that boot*. The plan lists this as OQ-A with
three options but does not pick one. For the issue's own thesis — "fail-closed on
a corrupt DB must not strand a foreign host" — the answer matters: if the only
lifeline is one written on a PRIOR successful boot (option A2), then a
*first-ever* boot with a corrupt day-0-seeded DB has NO lifeline and the operator
is stranded exactly in the scenario #1917 D1 was worried about. The plan should
state the chosen resolution as a requirement, not leave it fully open.
**Action:** pick option A2 (rely on the previously-persisted lifeline record) as
the primary, AND state that a never-booted box with a corrupt DB falls back to
the hypervisor/physical console (it has never had a reachable mgmt identity to
preserve) — that is honest and bounded. Move from OQ to a stated decision with
the residual called out.

### F2 — Med — committed-empty vs never-committed marker: migration hazard for
existing DBs is not addressed. OQ-F asks the representation question but the plan
does not say what happens to a DB written by a *current* (pre-M1b) build that has
no marker. If the marker is "absence of an active record," every existing
populated DB reads correctly (case 3). But the *committed-empty* state — an
operator who committed an empty tree on a current build — is today persisted as a
real (empty) active tree, which the new code must classify NOT-bootstrap.
**Action:** state the migration rule explicitly: a pre-M1b DB with ANY persisted
active tree (empty or not) = committed = NOT bootstrap; the never-committed marker
only ever applies to DBs this build itself created without a successful commit.
This makes the marker forward-only and removes the migration hazard. Add this to
§7 invariants and the test plan (load a pre-M1b empty-committed DB → NOT bootstrap).

### F3 — Low/Med — the bootstrap-mode gate placement is asserted but not
traced through the FULL startup. §5 says "gate the `!d.opts.NoDataplane` block at
daemon_run.go:231-307 behind `if !bootstrapMode`," but the daemon does a lot more
after :307 (routing/FRR/IPsec managers at :309+, DHCP clients, cluster init,
gRPC). The plan must enumerate which of those run in bootstrap mode (gRPC/REST/CLI
yes; FRR managed-section/dataplane/VRRP no) and confirm the gate does not leave a
half-initialized manager that a later `commit confirmed` (bootstrap exit) cannot
finish wiring. This is exactly the `enterBootstrapMode` "any subsystem that cannot
shrink to zero gets its residue enumerated" discipline — but applied to STARTUP
(never-grew) not teardown. **Action:** add a "startup subsystem gate matrix" to
§5 (each manager: init-in-bootstrap? / armed-in-bootstrap?) at /engineer time;
flag as the highest-churn part of the diff.

### F4 — Low — OQ-E (cluster secondary) is correctly flagged but I'll
strengthen the belief so reviewers can close it. Config sync is unidirectional
primary→secondary (`daemon_ha_sync.go:344-346`) and a secondary boots from its
OWN persisted DB / preseeded `xpf.conf` (case 3/2), never empty. The risk is only
a *first-ever* cluster bring-up where node-1 boots before any config exists on it
at all — but `cluster-setup.sh` / deploy always pushes a config + node-id first
(case 2). So the real requirement is: **bootstrap mode must be unreachable when
`clusterMode=true` AND node-id is present** — make that an explicit predicate
short-circuit (cluster node with node-id ⇒ never bootstrap), not an emergent
property. **Action:** add "cluster node-id present ⇒ NOT bootstrap" as an explicit
predicate rule (belt-and-suspenders), plus the cluster-boot test already listed.

### F5 — Nit — OQ-G (split) is the right question and I'd push harder. Item 1
(commit-confirmed service-mode fixes) is independently correct, lower-risk, has
no startup-gating churn, and directly hardens an existing shipped feature. Items
2-4 (bootstrap mode + lifeline + protected-set) are a cohesive larger change.
**Recommendation:** ship as TWO PRs — PR-1 = Item 1 (+ its serialization test),
PR-2 = Items 2-4. This is bisectable, lets the risky startup-gate land separately,
and gives the operator an early win. Not a blocker; a sequencing recommendation.

## Verdict

**PLAN-NEEDS-CHANGES (r1).** The plan is well-grounded — every load-bearing code
claim I checked is true, the design reuses existing primitives correctly, and the
risk framing is honest. But it is not yet PLAN-READY because two open questions
that the issue's own thesis turns on (F1 OQ-A corrupt-DB lifeline ordering, F2
marker migration) are left fully open rather than decided, and the startup gate
(F3) needs a subsystem matrix before /engineer can scope it. F4 wants an explicit
cluster short-circuit. Fold F1/F2/F4 into stated requirements (not OQs), add the
F3 matrix as a /engineer-time deliverable, adopt the F5 two-PR split, and this is
PLAN-READY.

---

# Claude SMR — plan review r2 (v3, convergence)

v3 folds all five r1 SMR findings, both AGY CRITICALs, and both Codex
refinements:

- F1/OQ-A (corrupt-DB lifeline) → **C4**: decided — no new lifeline on a
  corrupt boot (fail-closed); rely on prior-boot networkd files; never-booted
  corrupt box = console (bounded residual stated). No longer an open question.
- F2 (marker migration) → **C3**: envelope committed-gen field; missing field on
  an old DB defaults committed=true; marker forward-only. Migration hazard closed.
- F3 (gate actions not construction + startup matrix) → **C1 + C6**: managers
  constructed unconditionally; only takeover ACTIONS gated; subsystem gate matrix
  added.
- F4 (cluster) → **C2 + C8**: HA-node guard keyed on `/etc/xpf/node-id` presence
  (Codex correctly noted `clusterMode` is config-derived and cannot pre-empt the
  predicate); bootstrap-exit-on-SyncApply belt-and-suspenders.
- F5 (split) → **C5**: two-PR sequencing adopted.
- Codex C7: Item 1 scope narrowed to the timeout-rollback executor + first-commit
  target (the forward `commitConfirmedAndApply` path is already correct) — a real
  diff-shrinking refinement.

I re-verified the two newly-load-bearing facts: `clusterMode` IS derived only
from `cfg.Chassis.Cluster` (`daemon_run.go:256-259`) and node-id is read
independently from `/etc/xpf/node-id` (`daemon.go:398-405`), so keying the guard
on the node-id file (C8) is correct; and `commitConfirmedAndApply` DOES hold
applySem across commit+apply (`daemon_apply.go:136-148`), so C7's scope narrowing
is right. No residual architectural concern. OQ-B (first-commit gate scope /
no-confirm escape hatch) and OQ-C (lifeline detection heuristic for multi-homed
hosts) are genuine /engineer-time design choices, not plan blockers.

**Verdict: PLAN-READY (r2).**
