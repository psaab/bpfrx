# #1828 — WAN smart queueing as an operator-facing config surface

## 1. Status

**DRAFT v1 — pending adversarial plan review.**

Research-only. No production code on this branch. Base: master `2ab3220f0`.

Builds on the settled #1829 boundary verdict (posted on #1828, hostile-verified
3-way, "airtight"): kernel fq_codel/CAKE on uplinks is a **NO-OP for forwarded
traffic** — both AF_XDP TX modes bypass the qdisc layer; every forwarded-traffic
TX terminates at the XSK ring. That verdict is ground truth here and is not
re-litigated. #1828 is therefore the **config-surface/UX question on top of the
existing userspace CoS engine**: what does "smart queueing on a WAN uplink"
mean as an operator-facing surface, given the engine is the MQFQ CoS path plus
(evidence-gated) #1829 CoDel?

## 2. Issue framing

#1828 (residue from #1389) asks for fq_codel/CAKE-class "smart queueing" on WAN
uplinks. With the kernel-qdisc route closed, the honest decomposition of the
CAKE value proposition against this codebase is:

- **(a) bandwidth shaping** to keep the queue out of the upstream CPE/modem
  buffer — the core SQM move;
- **(b) per-flow fairness** so mice are not stuck behind elephants;
- **(c) AQM** (CoDel) to bound standing delay inside our own shaped queue;
- **(d) one-knob simplicity** — CAKE's real product is that
  `tc qdisc add ... cake bandwidth 450mbit` buys (a)+(b)+(c) plus sane
  defaults (diffserv tiers, triple-isolate, ack-filter) in one line.

This plan inventories exactly which of those already exist as xpf knobs
(§3, each cited), lays out the full option space (§4), and recommends a
layered answer: **a docs cookbook now (Option C), plus a precisely-spec'd
one-knob profile leaf gated on #1829 Phase 2 (Option B)** — with Option A
(macro now) explicitly rejected and Option D (CAKE-specific engine work)
explicitly out of scope.

## 3. Honest scope/value framing — the CAKE→xpf inventory

The decisive, verified fact: **the one-knob already exists.** A bare

```
set class-of-service interfaces reth0 unit 80 shaping-rate 450m
```

admits the interface into CoS (`contributes_usable_cos_state` gate requires
only `cos_shaping_rate_bytes_per_sec > 0`,
`userspace-dp/src/afxdp/forwarding_build/cos.rs:380-385`) and materializes the
**synthetic default best-effort queue** (queue_id 0, non-exact,
`guarantee_enabled: true`, `transmit_rate = shaping rate`,
`forwarding_build/cos.rs:392-411`; doc contract at
`docs/cos-traffic-shaping.md:804-807`). That single line therefore buys:

| CAKE property | xpf today | Evidence |
|---|---|---|
| (a) Bandwidth shaping | **EXISTS** — root token-bucket shaper per interface unit: `class-of-service interfaces <if> unit <u> shaping-rate <bw> [burst-size <b>]` | `pkg/config/schema.go:896-898`, `compiler_class_of_service.go:305-315`, root-node responsibilities `docs/cos-traffic-shaping.md:99-107` |
| (b) Per-flow fairness (the "fq" half) | **EXISTS, zero-config** — MQFQ per-flow buckets on ALL shaped queues post-#1735 (PR #1740): eager promotion on exact, lazy promotion on non-exact (incl. the synthetic default queue) via the hash-free front-key probe | `queue_ops/push.rs:43`; flow key = 5-tuple `SessionKey` hashed into 4096 buckets, `cos/flow_hash.rs:111-151` |
| (c) AQM | **PARTIAL** — admission-path AQM is shipped: BDP-aware per-flow share caps (`admission.rs:124`), 5 ms flow-fair aggregate delay clamp (`admission.rs:218`, `:44`), depth-threshold ECN CE marking (`admission.rs:276`). Dequeue-time sojourn CoDel = **#1829 Phase 2, evidence-gated** (Phase 1 sojourn telemetry = PR #1846, in review). `codel-target` exists as a per-scheduler knob in the compiler (`compiler_class_of_service.go:254-261`) but is **write-only** in the engine and **absent from `setSchema`** (verified: zero `codel` matches in `pkg/config/schema.go`) — a completion/validation gap owned by #1829 Phase 2 | as cited; #1829 plan §3, §6 |
| (d) DiffServ tiers | **EXISTS, multi-line** — forwarding-classes + DSCP/802.1p classifiers + per-class schedulers (`transmit-rate`, `priority`, `surplus-sharing`) + scheduler-maps | `schema.go:812-905`; worked example `docs/cos-traffic-shaping.md:759-764` |
| (d) Per-host isolation (triple-isolate) | **ABSENT** — flow keying is the 5-tuple only; no src-host/dst-host keying mode | `cos/flow_hash.rs:111-134` |
| (d) Ack-filter | **ABSENT** — no ACK thinning anywhere in the TX path | (no engine surface) |
| (d) Overhead compensation (`overhead`/`atm`) | **ABSENT** — shaping/scheduling account **payload bytes**, not wire bytes + framing | `docs/cos-traffic-shaping.md:521-526` |
| Download (ingress) shaping | **EXISTS, structurally better than tc** — SQM's ifb redirect hack is unnecessary: forwarded "download" traffic egresses the LAN-side AF_XDP interface, so `shaping-rate` on the LAN unit shapes the download direction natively | architecture: egress-only shaper, `docs/cos-traffic-shaping.md:5-15`; same synthetic-queue mechanics |

Two deliberate non-mappings:

- **`equal-flow-enforcement` is NOT the CAKE fairness analogue** and must not
  appear in a smart-queueing default. It is a non-work-conserving strict
  per-flow-equality clip with throughput loss, valid only on a positive
  **exact**-rate scheduler without surplus-sharing
  (`docs/fairness-regimes.md:583-585, 814-816`). CAKE's flow isolation is
  work-conserving DRR — that is MQFQ, row (b), already automatic.
- **`transmit-rate exact` per-class** is the SLA/measurement regime, not the
  WAN-SQM regime; the cookbook uses plain shaping + surplus where classes
  appear.

**So the residual value of #1828, at absolute scale, is:** (1) operators do
not know the one-liner exists or what it buys — there is no WAN-SQM-shaped
documentation anywhere in `docs/` (the CoS doc is an engine design doc, not an
operator recipe); (2) once #1829 Phase 2 ships, enabling CoDel on a bare
shaped WAN unit is **impossible without rewriting the config into an explicit
scheduler-map** (the synthetic queue hardcodes `codel_target_ns: 0`,
`forwarding_build/cos.rs:406-410`) — a genuine surface gap; (3) the
`codel-interval` knob has no home, and WAN RTTs approaching 100 ms are
precisely where it matters (#1829 §6.2e assigned it here). There is **no
performance win in this issue at all** — it is documentation plus, at most, a
thin config-plumbing rider on #1829.

*If reviewers conclude the residual value is too small to justify even the
gated config rider — i.e., the cookbook alone is the whole deliverable —
narrowing to docs-only (Option C pure) is an acceptable verdict, as is
PLAN-KILL of any individual deliverable.*

## 4. Multiple Path Options (explicit)

### Option A — `smart-queueing` macro/profile leaf NOW — REJECTED

A unit-level leaf that expands today to a canned CoS config. **Verified to be
vocabulary-only:** everything functional it could expand to is already what
bare `shaping-rate` produces — MQFQ is automatic (row b), admission AQM is
automatic (row c), `equal-flow-enforcement` is the wrong default (exact-only,
non-work-conserving, §3), and `codel-target` is inert until #1829 Phase 2
(write-only field). An expansion-to-named-objects implementation (synthesized
schedulers/maps in the AST) additionally drags in name-collision, `show`/
`display inheritance`, rollback-diff and FormatSet-differential semantics
(#1791/#1796-class config-surface risk) for zero behavior. A new keyword whose
expansion equals an existing one-liner is negative value. **Rejected.**

### Option B — profile leaf bundled with #1829 Phase 2 — RECOMMENDED AS GATED RIDER

When (if) #1829 Phase 2 survives its sojourn-evidence gate, the profile leaf
stops being vocabulary: it becomes the only way to put CoDel on the synthetic
default queue without rewriting into scheduler-maps, and the natural home for
`codel-interval`. Spec'd precisely in §6 Deliverable 2: **typed-config
plumbing, not AST macro expansion** — compile-time only, zero engine deltas
beyond what #1829 Phase 2 itself ships. Gated: if Phase 2 is PLAN-KILLED by
the Phase 1 telemetry, Deliverable 2 dies with it and #1828 closes on the
cookbook.

### Option C — docs cookbook NOW — RECOMMENDED AS PRIMARY

A WAN-SQM operator recipe is shippable today and is honestly ~80% of the
value: the one-liner per direction, the diffserv variant, an `apply-groups`
template (the existing xpf macro mechanism — `pkg/config/ast_groups.go`
`ExpandGroups`, already shipping), rate-selection guidance (shape at 85-95%
of contracted uplink — standard SQM headroom), what telemetry to watch
(PR #1846's `sojourn_*` gauges are exactly the operator's bufferbloat
instrument once merged), and an explicit "not yet" list (CoDel pending #1829
evidence, overhead compensation, per-host isolation). Validated once on the
loss userspace cluster so the recipe is load-bearing, not aspirational.

### Option D — CAKE-specific engine work (ack-filter, per-host keying, overhead compensation) — OUT OF SCOPE

Each is real engine work with its own evidence bar:

- **Per-host isolation**: a flow-key mode knob (src-host/dst-host keying in
  `cos_item_flow_key`/`exact_cos_flow_bucket`) — plausible future, no demand
  evidence; #1829 §4 already parked it the same way.
- **Ack-filter**: TX-path packet inspection + queue surgery; high
  invariant-risk (snapshot stack, MQFQ accounting) for a benefit that mostly
  matters on highly asymmetric links. Own issue if ever.
- **Overhead compensation**: the shaper counts payload bytes
  (`docs/cos-traffic-shaping.md:524`); on low-rate PPPoE/DSL/DOCSIS uplinks
  CAKE's per-packet overhead accounting is a correctness feature for (a).
  This is the most defensible Option D item; recommend filing it as its own
  small issue at close-out, not blocking #1828.

None of these belong in this issue. Filing them separately keeps #1828's
deliverable honest.

## 5. What's already shipped / composition constraints

- **#1735 / PR #1740** — flow-fair MQFQ on all shaped queues (the "fq" half);
  applies to the synthetic default queue via lazy promotion. The cookbook's
  fairness claims cite this, not new work.
- **#1829 plan (CONVERGED v3, `ebb716101` on `research/1829-fqcodel-aqm`)** —
  Phase 1 telemetry = PR #1846 (in review); Phase 2 CoDel evidence-gated on
  §6.1d attribution. Its §6.2e + Phase 3 explicitly assign the
  `codel-interval` knob and the "#1828 config-surface" follow-up here. Its
  Phase 2 PR adds `codel-target` range validation to `setSchema` — Deliverable
  2 must coordinate, not double-add.
- **#1614 A3** — `codel-target` per-scheduler knob: compiler + typed config +
  wire, end-to-end write-only (`compiler_class_of_service.go:254`,
  `types_cos.go:90-96`, `protocol.go:236-242`, `protocol/cos.rs:118-119`).
  The synthetic queue hardcodes 0 (`forwarding_build/cos.rs:406-410`).
- **`apply-groups`** (`pkg/config/ast_groups.go`) — the existing, shipped
  config-template mechanism; the cookbook leans on it instead of inventing a
  macro layer.
- **Two-SSOT config grammar (#1319)** — any new leaf lands in
  `config.setSchema` (`pkg/config/schema.go`) with typed-leaf validation in
  `schema_walk.go`; operational commands in cmdtree are untouched.
- **Dual AST shape** — the compiler must handle hierarchical AND flat-set
  shapes for any new unit child; the #1796/#1797 sweep found exactly this
  class of gap (flat-set compiling EMPTY). Deliverable 2's tests must use
  `ParseSetCommand()` + `SetPath()` per the project testing rule.
- **Deploy wipes CoS** — smoke validation must re-apply CoS config after
  deploy (`test/incus/apply-cos-config.sh`), per standing gotcha.

## 6. Concrete design

### Deliverable 1 (now): `docs/cos-wan-sqm.md` cookbook + one validation run

New operator-facing doc (the existing `docs/cos-traffic-shaping.md` is an
1172-line engine design doc; a recipe buried in it is unfindable — Open
Question Q3). Contents, fully specified:

1. **What "smart queueing" means here** — 4-row mapping table from §3, with
   the kernel-qdisc NO-OP verdict stated up front (one paragraph, linking
   #1828's boundary comment) so nobody reaches for `tc`.
2. **Upload (WAN egress) one-liner:**
   ```
   set class-of-service interfaces reth0 unit 80 shaping-rate 450m
   ```
   What it buys: root shaping at 450 Mbit (keeps the CPE buffer empty),
   automatic per-flow MQFQ fairness, admission ECN + 5 ms delay clamp.
3. **Download (LAN egress) one-liner:** `shaping-rate` on the LAN-side unit
   (e.g. `reth1 unit 0`), with the caveat that multiple LAN egress interfaces
   each get an independent shaper (same per-interface semantics as CAKE).
4. **Rate selection guidance:** 85-95% of contracted rate; remind that the
   shaper is average-rate with bounded burst (`burst-size` default
   `max(rate/100, 64*MTU)`, `docs/cos-traffic-shaping.md:772-773`).
5. **DiffServ variant:** the existing multi-class recipe (classifier +
   schedulers + scheduler-map) for operators who want EF/BE tiers, citing the
   `docs/cos-traffic-shaping.md:759-764` example.
6. **Reusable template:** a `groups wan-sqm { class-of-service ... }` +
   `apply-groups wan-sqm` example using the shipped groups mechanism.
7. **What to watch:** `show class-of-service interface`;
   `xpf_userspace_cos_*` admission/ECN counters; once PR #1846 merges, the
   per-queue `sojourn_{ewma,peak,windowed_min}_ns` gauges as the bufferbloat
   instrument (windowed-min sustained above ~5 ms under load = standing
   queue).
8. **Explicit not-yet list:** CoDel (#1829 Phase 2, evidence-gated; knob
   exists but is inert), overhead compensation, per-host isolation,
   ack-filter — with the §3 honesty about `equal-flow-enforcement` being a
   strict-SLA mode, not an SQM default.

**Validation (engineer time, one smoke slot):** apply the §6.2 one-liner on
the loss userspace cluster WAN unit (reth0.80), `iperf3 -P 12` to
172.16.80.200: shape held at the configured rate, per-flow fairness CoV in
the known band, admission ECN counters moving; then remove the stanza and
verify clean no-CoS line-rate restore. This pins every cookbook claim to a
run artifact.

### Deliverable 2 (gated on #1829 Phase 2 shipping): the one-knob profile leaf

**Spelling (Q2):** `smart-queueing` under the CoS interface unit:

```
set class-of-service interfaces reth0 unit 80 shaping-rate 450m
set class-of-service interfaces reth0 unit 80 smart-queueing
set class-of-service interfaces reth0 unit 80 smart-queueing codel-target 5
set class-of-service interfaces reth0 unit 80 smart-queueing codel-interval 200
```

Junos has no native analogue (its AQM surface is RED `drop-profiles`; CoDel
is foreign vocabulary regardless of spelling), and the tree already carries
xpf-only CoS keywords (`surplus-sharing`, `equal-flow-enforcement`,
`codel-target`), so the issue-title vocabulary `smart-queueing` is the most
operator-discoverable choice. Presence-enables with defaults
(target 5 ms, interval 100 ms); children override.

**Semantics — typed-config plumbing, NOT AST macro expansion:**

- `pkg/config`: `setSchema` gains the `smart-queueing` node under
  `interfaces.unit` with typed `codel-target` (1..=1000 ms) and
  `codel-interval` (10..=10000 ms, must exceed target) leaves; compiler fills
  new `CoSInterfaceUnit` fields `SmartQueueing bool`, `CodelTargetNS`,
  `CodelIntervalNS` (both AST shapes + FormatSet round-trip).
- Wire: `CoSInterfaceSnapshot` unit entry gains the two u64s
  (`protocol.go` + `protocol/cos.rs`, additive, omitempty/serde-default,
  both-sides grep per standing rule).
- `forwarding_build/cos.rs`: the synthetic default queue takes
  `codel_target_ns` (and interval) from the unit instead of the hardcoded 0
  at `cos.rs:406-410`. **That is the entire engine-side delta** — everything
  downstream is #1829 Phase 2's machinery, untouched.
- No named objects are synthesized; `show configuration` shows exactly what
  the operator typed; rollback/diff/inheritance semantics are untouched.

**Commit-check rules (all in `SchemaValidate`/compile checks):**

1. `smart-queueing` without `shaping-rate > 0` on the same unit → commit
   error ("smart-queueing requires shaping-rate on the unit"). Without
   shaping there is no CoS queue to act on (admission gate, §3) — and
   unshaped AF_XDP TX never stands a queue we control.
2. `smart-queueing` + `scheduler-map` on the same unit → commit error
   directing to `schedulers <s> codel-target`. With a scheduler-map the
   synthetic queue does not exist; silently spraying profile params across
   explicit schedulers is merge ambiguity by construction. **Reject, don't
   merge** (Q1).
3. `codel-interval` ≤ `codel-target` → commit error.

**Sibling deliverable, same PR:** per-scheduler `codel-interval` knob
(compiler + typed + wire + build), closing #1829 §6.2e's Phase-3 assignment —
this is the WAN-RTT case (#1829: "real WAN RTTs can approach the 100 ms
interval"). Coordinate with #1829's Phase 2 PR on `setSchema` ownership of
`codel-target` so it lands exactly once.

**Gate discipline:** Deliverable 2 starts only after #1829 Phase 2 has
merged (not merely PLAN-READY — Phase 2 is itself evidence-gated and can
still die on Phase 1 telemetry). If Phase 2 is killed, #1828 closes with
Deliverable 1 plus a cookbook note recording what the sojourn telemetry
showed.

## 7. Public API preservation

- Deliverable 1: none touched (docs only).
- Deliverable 2: all existing config grammar, wire fields, and engine
  signatures preserved; changes are strictly additive (new optional unit
  leaf, new optional wire fields with serde-default/omitempty, one
  hardcoded-0 replaced by a config-sourced value defaulting to 0). Old
  daemon + new helper and vice versa remain wire-compatible (absent field =
  0 = disabled, the today behavior).
- No gRPC/REST/cmdtree operational-command changes in either deliverable.

## 8. Hidden invariants the change must preserve

1. **Dual AST shape** — the new unit child must compile from BOTH
   hierarchical and flat-set forms; tests via `ParseSetCommand()`+`SetPath()`
   (the #1796/#1797 flat-set-compiles-EMPTY class is the precise hazard).
2. **FormatSet round-trip** — `show configuration | display set` must emit
   the new leaves such that re-applying them reproduces the tree (the #1786
   FormatSet differential surface).
3. **Wire both-sides rule** — `protocol.go` AND `protocol/cos.rs` change
   together; fixture regenerated; key-absent pinned both sides
   (`feedback_wire_protocol_both_sides`).
4. **Default-off** — absent `smart-queueing` ⇒ synthetic queue
   `codel_target_ns == 0` ⇒ bit-identical behavior to today (single enable
   gate, same predicate discipline as #1829 §6.2b).
5. **No engine hot-path deltas in this issue** — Deliverable 2 must not touch
   admission, MQFQ, or the fused-pop path; if a diff strays there it belongs
   to #1829 and the PR is mis-scoped.
6. **Smoke environment** — deploy wipes CoS; re-apply before measuring; WAN
   path is reth0.80 → 172.16.80.200 (never 172.16.100.x).
7. **`setSchema` is the config-mode SSOT (#1319)** — completion + validation
   for the new leaves live there, not in cmdtree.

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **LOW** | Deliverable 1: zero (docs). Deliverable 2: additive default-off config plumbing; the only behavior change requires the operator to type the new leaf, and the enforcement semantics are #1829's, already reviewed there. Residual risk = commit-check rules rejecting configs operators expect to merge (mitigated by precise error text + Q1 review). |
| Lifetime / borrow-checker | **NONE/LOW** | Go config structs + one Rust build-time field source change; no hot-path borrows. |
| Performance regression | **NONE** | No hot-path code in this issue. |
| Architectural mismatch | **LOW** | The #961-pattern risk here is the macro temptation: a profile leaf that grows into a config-rewriting kitchen sink. Guarded structurally: typed-config plumbing only, reject-don't-merge on scheduler-map interaction, Option D fenced into separate issues. The cookbook carries no mismatch risk at all. |

## 10. Test plan

- **Deliverable 1:** doc builds/links; the one validation smoke run on the
  loss userspace cluster (§6, one smoke-runner slot, serialized per standing
  rule): shape held, fairness CoV in band, ECN counters, clean restore after
  delete. Run artifacts referenced from the cookbook.
- **Deliverable 2 (at its PR):** Go config tests — hierarchical + flat-set
  compile parity, FormatSet round-trip, all three commit-check errors,
  defaults (presence-only → 5 ms/100 ms); wire fixture regen + key-absent
  pins both sides; cargo test for the build plumb (synthetic queue receives
  unit codel params; absent ⇒ 0); full suites (30 Go packages, 1000+ cargo
  tests, `make audit-check`); smoke = per-class CoS sweep 5201-5211 with the
  leaf UNSET (no-op proof) + the #1829 Phase 2 codel smoke legs re-run with
  the leaf as the enablement path; standard 13-stream failover smoke per
  deploy gate.

## 11. Out of scope (explicitly)

- Any kernel qdisc/tc/networkd integration (closed by the boundary verdict).
- #1829 Phase 2 itself (CoDel control law) — this issue only adds surface to
  reach it; if Phase 2 dies, Deliverable 2 dies.
- Ack-filter, per-host/triple-isolate keying, overhead compensation
  (Option D — separate issues on demand; overhead compensation recommended
  for filing at close-out).
- `equal-flow-enforcement` changes or defaults (strict-SLA mode, not SQM).
- Ingress policing, per-flow XDP_REDIRECT cross-binding fairness (#899
  lineage), anything cross-worker.
- Auto-rate detection (CAKE `autorate-ingress`-style) — no measurement
  substrate; not proposed.

## 12. Open questions for adversarial review

1. **Q1 (interaction rule):** is reject-don't-merge for
   `smart-queueing` + `scheduler-map` right, or should the leaf act as a
   default-filler for explicit queues lacking `codel-target`? (Plan says
   reject: filler semantics create precedence ambiguity and a silent
   behavior change when a scheduler-map is later added.) Challenge it.
2. **Q2 (spelling):** `smart-queueing` vs `sqm` vs hanging children off
   `shaping-rate` (e.g. `shaping-rate 450m smart-queueing`)? Is a non-Junos
   keyword at the unit level acceptable given the existing xpf-only scheduler
   keywords? Note `shaping-rate` already has a child (`burst-size`), so the
   child-of-shaping-rate spelling is grammatically available.
3. **Q3 (doc placement):** new `docs/cos-wan-sqm.md` vs a section in
   `docs/cos-traffic-shaping.md` (1172-line design doc)? Plan says new doc,
   cross-linked both ways.
4. **Q4 (close-out shape):** should #1828 close after Deliverable 1 with
   Deliverable 2 re-homed as #1829 Phase 3 (one tracking surface, as the
   boundary comment offered), or stay open as the gate-keeper for
   Deliverable 2? Either is workable; plan proposes keeping #1828 open as
   the config-surface tracker since #1829's plan scoped it out.
5. **Q5 (cookbook honesty):** does the validation run as spec'd actually pin
   the cookbook's fairness claim (MQFQ lazy promotion on the synthetic
   queue under -P 12), or does it need an explicit
   `active_flow_buckets`/promotion-telemetry check added to the leg?
6. **Q6 (Option D triage):** is overhead compensation worth filing now as
   the one Option D item with a correctness (not luxury) argument for
   low-rate uplinks — or is the loss-cluster operator base all
   high-rate-ethernet, making it dead weight?
7. **Q7 (defaults):** are 5 ms target / 100 ms interval the right
   presence-only defaults for a WAN profile, given #1829 §6.2e ties target
   to the existing 5 ms clamp envelope but WAN RTTs can exceed 100 ms?
   Should the profile default interval higher (e.g. 300 ms) than the
   scheduler-level default?

## 13. Reviewer ledger

Task IDs + verdicts per round in `reviewer-ids.md` (same directory);
per-round docs `codex-plan-r<N>.md` / `agy-plan-r<N>.md` /
`claude-smr-plan-r<N>.md`.
