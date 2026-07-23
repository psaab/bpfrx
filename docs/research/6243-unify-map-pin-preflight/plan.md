# #6243 — Unify the activated + deferred BPF map-pin preflight

Research plan v1 (DRAFT). Class B dedup. No production code in this branch.

---

## 1. Status

**PLAN-DRAFT — awaiting adversarial plan review.** Deliverable is this
document plus the assessment relayed to the parent. No production source is
edited on this branch; the two duplicated functions are surveyed via
`git show`/reads only.

Firsthand read: **unification is genuinely behavior-preserving and drives to
merge — MODERATE complexity, not PLAN-KILL-shaped.** The two implementations
share the whole essential contract (the same 7 pins, the same requiredness,
the same `OwnedFd::open_bpf_map` openability check, the same typed
`ReconcileStage` identities). The only real differences reduce to (a) *keep vs
drop* the opened FDs — handled by RAII with no `mode` param, and (b) the
side-effect stamping (`last_reconcile_stage` + per-binding `last_error`) —
pulled into a thin cold adapter on the activated caller. There is **one
genuine wrinkle worth a reviewer's attention**: the two paths currently
*diverge* on multi-fault ordering (a latent misclassification bug, both still
fail-closed), so unification must pick one canonical order — which fixes the
bug by construction. That is a feature, not a blocker.

---

## 2. Framing

`reconcile/snapshot.rs` carries two independent implementations of the
"validate + open the seven snapshot BPF map pins" contract:

- **`preflight_map_fds`** (`snapshot.rs:48-196`, ~140 LOC) — the **activated**
  reconcile path. Called once, from `Coordinator::reconcile`
  (`reconcile/mod.rs:284`), BEFORE `tear_down`. It validates the 3 mandatory +
  4 optional pins, **opens and RETAINS** the FDs (returns
  `ReconcileSnapshotFds`), and on any fault **mutates** `coord.last_reconcile_stage`
  (typed `ReconcileStage`) plus every registered binding's `last_error`
  (`String`), returning `None`.

- **`validate_map_pins`** (`snapshot.rs:289-333`, ~44 LOC) — the **deferred**
  validation path. Called once, from `Coordinator::validate_snapshot_buildable`
  (`reconcile/mod.rs:197`), which the deferred-activation control handler
  (`server/handlers/snapshot.rs:308`) runs to prove a RETH-MAC-pending snapshot
  is fully buildable BEFORE it acks + persists it as the boot baseline. It lists
  the **same seven pins**, opens each with the **same** `OwnedFd::open_bpf_map`,
  **drops** each FD immediately, mutates nothing, and returns
  `Result<(), ReconcileError>` — wrapping the typed `ReconcileStage` in
  `ReconcileError::MapSetup`.

`validate_snapshot_buildable`'s entire contract (doc-comment `reconcile/mod.rs:150-160`,
locked by `validate_snapshot_buildable_matches_reconcile_5171`,
`tests.rs:4058`) is: *reject exactly the snapshots `reconcile` rejects, with
the same `ReconcileError` variant and the same stage descriptor.* Today that
parity is a **convention maintained by two hand-kept lists**, not an invariant.
Any future map addition, requiredness flip, pin-name change, or
error-classification change must be edited in **both** functions plus their
tests — and a silent drift is a fail-open / misclassification risk on a
security appliance's fail-closed boundary.

---

## 3. Honest scope + value (and when PLAN-KILL is acceptable)

**Value (real):** collapse the 7-pin contract to a single source of truth so
the deferred-validation path and the activated forwarding path can never drift
on *which snapshots pass the map-pin gate* or *what they report*. The dedup
also **closes a currently-latent divergence** (§5.1) that the existing parity
test does not catch. This is squarely the Class-B "two implementations of one
contract" risk the issue names.

**Honest scope caveat:** the net LOC delta is modest — this is a *drift-risk*
refactor, not a size refactor. The win is the invariant (one list, one opener,
one fault→stage/label mapping), plus the bug fix, not line count.

**PLAN-KILL is acceptable if** the activated-vs-deferred contracts turn out to
differ so fundamentally that a unified function needs enough `mode`/branch
machinery that it is *not simpler* than the two current functions. This plan's
firsthand finding is the **opposite**: the difference collapses to *keep vs
drop the FD bundle* (pure RAII, no `mode` param) plus a *cold side-effect
adapter* on one caller — so the unified opener is a pure
`fn(&MapPins) -> Result<OpenedSnapshotMaps, MapPinFault>` with no branching on
caller identity. If a reviewer disagrees and shows the mode-branching is
irreducible, PLAN-KILL is the honest call. A reviewer may also PLAN-KILL if
they judge normalizing the deferred path's multi-fault stage (§5.1) an
unacceptable wire/operator-visible behavior change rather than a bug fix.

---

## 4. What is already shipped (the ground this builds on)

- **#6244 — typed `ReconcileStage`** (`reconcile/stage.rs`). The stage strings
  that both functions used to build as raw `String`s are now **typed enum
  variants**: `MissingPin(MandatoryPin)` and
  `OpenMapFailed { map: &'static str, err: String }`. The legacy operator
  string is produced BYTE-FOR-BYTE in exactly one place — `ReconcileStage`'s
  `Display` (`stage.rs:134`) — and a fail-on-revert
  (`reconcile_stage_renders_byte_identical_legacy_strings`, `stage.rs:279`)
  locks every rendering. **The unified preflight must build the typed variant,
  not a raw string** — it inherits #6244's Display guarantee for free.
- **#6244 also** made `ReconcileError::MapSetup(ReconcileStage)` carry the typed
  stage (was a cloned `String`), and the activated caller wraps the fault as
  `ReconcileError::MapSetup(self.last_reconcile_stage.clone())` (`mod.rs:291`).
- **#5171** factored `validate_snapshot_buildable` out and added the parity test
  — but implemented the contract twice (the exact thing this issue consolidates).
- **#2440 / #2444** established the fail-closed discipline (mandatory-pin
  failure aborts BEFORE teardown/publish; a *present* optional pin that fails to
  open is fatal, an *empty* optional pin is silent-absent). The test seam
  `TEST_MAP_PIN_OK` / `TEST_MAP_PIN_FAIL` (`bpf_map/pin.rs:31`) lets preflight
  ordering be exercised without bpffs.
- **Adjacent, NOT in scope: #6246** (folded into #6243 per the issue's
  design-review amendment) wants to also remove the
  `forwarding: ForwardingState::default()` placeholder and make `apply_snapshot`
  non-optional. This plan keeps that placeholder handling byte-identical and
  treats #6246 as a follow-up (see §10 + open question Q5).

---

## 5. The seven-pin contract, side by side

| # | `MapPins` field | Required | Missing → stage (`Display`) | Open-fail → stage (`Display`) | Per-binding `last_error` (missing) | Per-binding `last_error` (open-fail) |
|---|-----------------|----------|------------------------------|-------------------------------|-------------------------------------|--------------------------------------|
| 1 | `xsk`           | **mandatory** | `MissingPin(Xsk)` → `missing_xsk_pin` | `OpenMapFailed{map:"xsk"}` → `open_xsk_map_failed:{err}` | `missing XSK map pin path` | `open XSK map: {err}` |
| 2 | `heartbeat`     | **mandatory** | `MissingPin(Heartbeat)` → `missing_heartbeat_pin` | `OpenMapFailed{map:"heartbeat"}` → `open_heartbeat_map_failed:{err}` | `missing heartbeat map pin path` | `open heartbeat map: {err}` |
| 3 | `sessions`      | **mandatory** | `MissingPin(Session)` → `missing_session_pin` | `OpenMapFailed{map:"session"}` → `open_session_map_failed:{err}` | `missing session map pin path` | `open session map: {err}` |
| 4 | `conntrack_v4`  | optional | — (empty ⇒ absent; silent) | `OpenMapFailed{map:"conntrack_v4"}` → `open_conntrack_v4_map_failed:{err}` | — | `open conntrack_v4 map: {err}` |
| 5 | `conntrack_v6`  | optional | — | `OpenMapFailed{map:"conntrack_v6"}` | — | `open conntrack_v6 map: {err}` |
| 6 | `dnat_table`    | optional | — | `OpenMapFailed{map:"dnat_table"}` | — | `open dnat_table map: {err}` |
| 7 | `dnat_table_v6` | optional | — | `OpenMapFailed{map:"dnat_table_v6"}` | — | `open dnat_table_v6 map: {err}` |

**Both functions produce the identical `map` tokens** for `OpenMapFailed`
(mandatory: `xsk`/`heartbeat`/`session`; optional names match). So the *stage
identity* already agrees between the two implementations — with one exception
(§5.1).

**Byte-parity trap (mandatory pins only):** the stage `map` token is lowercase
`"xsk"`, but the **per-binding** `last_error` label is uppercase — `"open XSK
map: {err}"` / `"missing XSK map pin path"`. `heartbeat`/`session` are lowercase
in both. Optional pins reuse one token for both (`conntrack_v4`, …). A naive
"reuse the stage token for the binding string" would silently rewrite
`open XSK map` → `open xsk map`. The per-binding strings are **test-locked**
(`tests.rs:3641` `"missing session map pin path"`; `tests.rs:3590`
`"open session map:"`; `tests.rs:4574` `"open conntrack_v4 map:"`; `tests.rs:4638`
`"open dnat_table map:"`). The unified descriptor MUST carry a **separate
per-binding label** distinct from the stage token.

Only the **activated** path also derives `DnatTableFds { v4, v6 }` (raw `fd`
ints copied from the opened dnat `OwnedFd`s, `snapshot.rs:177`) and stashes the
`forwarding: ForwardingState::default()` placeholder (`snapshot.rs:194`).

### 5.1 The one current divergence (a latent bug the unification fixes)

The two functions walk the mandatory pins in **different order structures**:

- `preflight_map_fds` (activated) — **two-pass**: check *all three* mandatory
  pins for emptiness first (`snapshot.rs:53-79`, xsk→heartbeat→session), *then*
  open all three (`snapshot.rs:80-124`), *then* the optional pins.
- `validate_map_pins` (deferred) — **one-pass sequential**: for each mandatory
  pin, check-empty *then* open, before touching the next pin
  (`snapshot.rs:290-312`).

For a **multi-fault** snapshot where an *earlier* mandatory pin is
**present-but-unopenable** AND a *later* mandatory pin is **empty**, the two
paths report **different** stages:

| Snapshot | `preflight_map_fds` (activated) | `validate_map_pins` (deferred) |
|----------|----------------------------------|--------------------------------|
| xsk present+unopenable, heartbeat **empty** | pass-1 catches empty heartbeat → **`MissingPin(Heartbeat)`** (`missing_heartbeat_pin`) | opens xsk first → **`OpenMapFailed{xsk}`** (`open_xsk_map_failed:…`) |
| xsk ok, heartbeat present+unopenable, sessions **empty** | pass-1 catches empty sessions → **`MissingPin(Session)`** | opens heartbeat (fails) → **`OpenMapFailed{heartbeat}`** |

Both still **reject** (fail-closed is preserved on *both* paths — this is a
*misclassification*, not a fail-open), but they name a different fault. The
existing parity test only covers "sessions empty, xsk+heartbeat present &
openable" (`fail_open_snapshot` sets xsk/heartbeat to `TEST_MAP_PIN_OK`,
`tests.rs:3496`) — a case where the two paths **agree** — so it misses the
divergence entirely.

**Consequence for the deferred path:** the reported stage flows into
`response.error = format!("snapshot integrity error: {}", err)`
(`server/handlers/snapshot.rs:321`) and into `coord.last_reconcile_stage` on
the activated path (operator-visible `show`/wire `debug_reconcile_stage`). A
snapshot with two faults gets a *different* human-facing reason depending on
which path evaluated it.

**Design decision:** unification **normalizes to ONE canonical order** —
recommended: the **activated two-pass precedence** (all mandatory emptiness in
xsk→heartbeat→session order; then mandatory opens in that order; then present
optionals in fixed order). Rationale: the activated path is the real forwarding
path and the source of truth the deferred gate exists to mirror, and it is the
order the existing parity test already asserts. Normalizing **changes the
deferred path's** reported stage on multi-fault inputs (bug fix). That behavior
change must be called out and covered by a fail-on-revert (§9).

---

## 6. Concrete design

### 6.1 One 7-pin descriptor (single source of truth)

Replace the two hand-kept lists with one authoritative table. Because the
opened FDs land in *named* struct fields (not a homogeneous array) and mandatory
vs optional carry different typed identities, keep the descriptor small and
concrete — no trait objects, no heap table:

```rust
/// The requiredness + typed identity of one snapshot map pin.
enum MapReq {
    /// mandatory: typed stage pin + the per-binding label (note the CASE
    /// divergence — Xsk's label is "XSK", not the "xsk" stage token).
    Mandatory { pin: MandatoryPin, binding_label: &'static str },
    /// optional: one `&'static str` doubles as the OpenMapFailed `map`
    /// token AND the per-binding label root ("open {name} map").
    Optional { name: &'static str },
}
```

The canonical walk order is expressed directly in code (two passes for
mandatory), so a literal `[MapPinDesc; 7]` array is optional — its value is
documentation + a single place to add pin #8. Either form is acceptable; the
invariant is *one* list.

### 6.2 One typed fault carrying the #6244 stage + the per-binding label

```rust
enum MapPinFault {
    /// a mandatory pin was empty
    MissingRequired { pin: MandatoryPin, binding_label: &'static str },
    /// a pin (mandatory OR present-optional) failed to open
    Open { map: &'static str, binding_label: &'static str, err: io::Error },
}

impl MapPinFault {
    /// Build the #6244 typed stage — the ONLY place both callers get it.
    fn stage(&self) -> ReconcileStage { /* MissingPin | OpenMapFailed{map,err} */ }
    /// The verbatim per-binding last_error string (case-correct labels).
    fn binding_error(&self) -> String { /* "missing XSK map pin path" | "open XSK map: {err}" */ }
}
```

`stage()` inherits #6244's byte-identical `Display`; `binding_error()` owns the
uppercase-`XSK` byte-parity trap in exactly one place.

### 6.3 One shared, PURE opener (no `mode` param)

```rust
/// Opens all seven pins in the canonical order (two-pass mandatory
/// precedence). PURE: no coord/binding mutation, no last_reconcile_stage
/// write. Both callers route through this.
fn open_snapshot_maps(pins: &MapPins) -> Result<OpenedSnapshotMaps, MapPinFault> {
    // pass 1: mandatory emptiness (xsk -> heartbeat -> session)
    // pass 2: mandatory opens (same order) into owned FDs
    // then:   present-optional opens (conntrack_v4/v6, dnat_table[/v6])
    // Ok -> OpenedSnapshotMaps { xsk, heartbeat, sessions, conntrack_v4, ... }
}

struct OpenedSnapshotMaps {
    xsk: OwnedFd, heartbeat: OwnedFd, sessions: OwnedFd,
    conntrack_v4: Option<OwnedFd>, conntrack_v6: Option<OwnedFd>,
    dnat_table: Option<OwnedFd>, dnat_table_v6: Option<OwnedFd>,
}
```

**Why no `mode: Open | ValidateOnly` param is needed:** the activated path
*keeps* the bundle; the deferred path *drops* it. That is exactly what Rust
ownership already models — the deferred caller writes `.map(|_| ())` and the
bundle's `OwnedFd`s close on drop. The opener is identical for both. (This is a
key simplification finding vs the issue's "mode param" framing — the
open-vs-validate distinction is not a runtime branch.)

### 6.4 The two callers become thin

- **Activated** `preflight_map_fds(coord, snapshot, bindings)`:
  ```rust
  let maps = match open_snapshot_maps(&snapshot.map_pins) {
      Ok(m) => m,
      Err(fault) => {
          coord.last_reconcile_stage = fault.stage();           // typed #6244
          for b in bindings.iter_mut() {
              if b.registered { b.last_error = fault.binding_error(); }
          }
          return None;
      }
  };
  let dnat_fds = DnatTableFds { v4: maps.dnat_table.as_ref().map(|f| f.fd),
                                v6: maps.dnat_table_v6.as_ref().map(|f| f.fd) };
  Some(ReconcileSnapshotFds { map_fd: maps.xsk, heartbeat_map_fd: maps.heartbeat,
      session_map_fd: maps.sessions, conntrack_v4_fd: maps.conntrack_v4, ...,
      dnat_fds, forwarding: ForwardingState::default() })
  ```
  The stamping (`last_reconcile_stage` + per-binding `last_error`) is the **cold
  adapter** — the only activated-specific behavior — and it lives here, not in
  the shared opener.

- **Deferred** `validate_map_pins(snapshot)`:
  ```rust
  open_snapshot_maps(&snapshot.map_pins)
      .map(|_| ())
      .map_err(|fault| ReconcileError::MapSetup(fault.stage()))
  ```

Both now derive requiredness, names, ordering, stage identity, and per-binding
labels from `open_snapshot_maps` + `MapPinFault`. A pin #8 (or a requiredness
flip) is a **one-place** edit.

### 6.5 Call sites

- `preflight_map_fds` — **1** caller (`reconcile/mod.rs:284`).
- `validate_map_pins` — **1** caller (`validate_snapshot_buildable`,
  `reconcile/mod.rs:197`).
- `validate_snapshot_buildable` — **1** caller
  (`server/handlers/snapshot.rs:308`, deferred-apply handler).
- `open_optional_map` — a private helper folded into `open_snapshot_maps`
  (the optional-pin arm); no external callers.

Small, closed blast radius: two public `pub(super)` functions rewritten in
terms of one new shared opener, no signature change visible outside
`reconcile/`.

---

## 7. Public API preservation

- `preflight_map_fds` and `validate_map_pins` keep their **exact signatures**
  (`pub(super)`), returns, and side-effect contracts. `reconcile` and
  `validate_snapshot_buildable` are untouched.
- `ReconcileSnapshotFds`, `ReconcileError`, `ReconcileStage`, `MandatoryPin`,
  `DnatTableFds` — unchanged. The unified opener produces the *same* typed
  `ReconcileStage` values #6244 defined.
- The operator/wire strings (`reconcile_debug` / `debug_reconcile_stage`,
  `ReconcileError::Display`, the deferred handler's `response.error`) render
  through #6244's single `Display`; the per-binding `last_error` strings render
  through `MapPinFault::binding_error()` — both **byte-for-byte** unchanged
  (except the deliberate §5.1 multi-fault normalization on the *deferred* path).
- New types (`OpenedSnapshotMaps`, `MapPinFault`, `MapReq`) are `pub(super)`
  internal to `reconcile/` — no crate-public surface.

---

## 8. Hidden invariants a reviewer MUST guard

1. **Requiredness matrix exact:** 3 mandatory (xsk/heartbeat/sessions), 4
   optional (conntrack_v4/v6, dnat_table[/v6]). An empty MANDATORY pin ⇒ reject;
   an empty OPTIONAL pin ⇒ silent absence (no gating); a PRESENT optional pin
   that fails to open ⇒ **fatal** (#2444). Flipping any cell is a fail-open /
   over-gate.
2. **#3296/#2440 fail-closed:** a missing/unopenable mandatory pin aborts
   BEFORE teardown/publish on the activated path; the deferred path rejects
   before ack/persist. `open_snapshot_maps` must return `Err` — never a partial
   `Ok` — on any mandatory fault.
3. **The activated path still OPENS and RETAINS the FDs** (returns real
   `OwnedFd`s in `ReconcileSnapshotFds`), and still builds `DnatTableFds` from
   the *raw fd ints* only AFTER a successful open. The deferred path opens then
   drops (RAII).
4. **RAII single-close on partial failure:** in the two-pass walk, if a *later*
   open fails, every *earlier*-opened `OwnedFd` must close **exactly once** via
   drop of the local/partial bundle — never leak, never double-close. `OwnedFd`
   is the sole owner (`bpf_map/pin.rs:63` `Drop` → `close`).
5. **Byte-identical stage strings** (via #6244 `Display`) AND **byte-identical
   per-binding labels** (via `binding_error()`), including the uppercase-`XSK`
   vs lowercase-`xsk`-token divergence (§5). Test-locked at `tests.rs:3590/3641/4574/4638`
   and `stage.rs:279`.
6. **Canonical multi-fault order** (§5.1): one order for both paths. The
   deferred path's multi-fault stage changes to match the activated path — a
   deliberate, tested normalization.
7. **Purity of the shared opener:** no `coord`/`bindings`/`last_reconcile_stage`
   mutation inside `open_snapshot_maps` — the deferred path depends on validation
   being side-effect-free (`validate_snapshot_buildable` doc `mod.rs:175`).
8. **`OwnedFd::open_bpf_map` does NOT validate map type/key/value ABI** — it is
   only `bpf_obj_get` (`bpf_map/pin.rs:55`). "Openability" is the sole signal; a
   "wrong-object" fault does not exist at this layer (see §9 note + Q3).

---

## 9. Risk table

| Risk | Likelihood | Impact | Severity | Mitigation |
|------|-----------|--------|----------|------------|
| A pin's requiredness or fatal/silent classification silently flips during the merge to one list | Low | Fail-open (mandatory→optional) or over-gate (optional→mandatory) on a security boundary | **MED-HIGH** | One descriptor + a table-driven fail-on-revert asserting every cell of §5's matrix, on BOTH paths |
| The §5.1 order normalization is judged an unacceptable operator/wire behavior change (deferred multi-fault stage now differs from pre-#6243) | Med | Different `response.error` / `last_reconcile_stage` text on multi-fault snapshots | **MED** (crux) | Both paths already fail-closed; normalizing makes deferred MATCH the forwarding SSOT. Call it out; cover with a paired fail-on-revert. PLAN-KILL-invitable (Q1) |
| Per-binding label rewritten to the lowercase stage token (`open XSK map`→`open xsk map`) | Med | Operator-visible per-binding `last_error` drift | **MED** | `binding_error()` owns the labels; `tests.rs:3641/4574/4638` lock them |
| RAII leak/double-close of an earlier-opened FD on a later open failure | Low | fd leak or `EBADF` double-close | **MED** | `OwnedFd` sole-owner + drop; a test that fails an optional open after mandatory opens succeed and asserts no leak (or reasons via the sole-owner invariant) |
| Activated path stops retaining an FD or mis-derives `DnatTableFds` | Low | Worker brought up with wrong/closed map fd → forwarding outage | **MED-HIGH** | Assemble `ReconcileSnapshotFds` explicitly from the bundle; existing bring-up tests + a loss-cluster deploy |
| `mode`-param over-engineering re-introduces branching the design removed | Low | Complexity regression (defeats the refactor) | LOW | Design mandates the pure no-mode opener; reviewer rejects any caller-identity branch inside the opener |

---

## 10. Test plan

- **`make test-rust`** (the `userspace-dp` cargo suite) — the primary gate;
  run with `TMPDIR=/tmp` (socket-path `sun_path` 108-byte limit under a long
  TMPDIR is a known false red).
- **Preserve + extend the existing suite:** `validate_snapshot_buildable_matches_reconcile_5171`
  (`tests.rs:4058`), the `missing session` / `open session` / optional
  `conntrack_v4` / `dnat_table` per-binding assertions (`tests.rs:3553/3590/3641/4545/4574/4615/4638`),
  and `reconcile_stage_renders_byte_identical_legacy_strings` (`stage.rs:279`)
  must all stay green unchanged (except the deliberate §5.1 addition).
- **New table-driven parity fail-on-revert (the merge gate):** for all seven
  pins, across `{empty, present+unopenable, present+openable}`, assert the
  **activated** path (`reconcile`) and the **deferred** path
  (`validate_snapshot_buildable`) yield the **identical** `ReconcileError`
  variant + `ReconcileStage`, AND the activated path stamps the exact
  per-binding `last_error`. Reverting either caller to its own hand-rolled list
  (or flipping a requiredness cell) turns it RED. Both paths route through
  `open_snapshot_maps` — deleting that routing on one caller diverges a pair.
- **New multi-fault precedence case (§5.1):** xsk present+unopenable +
  heartbeat empty (and xsk ok + heartbeat unopenable + sessions empty) — assert
  BOTH paths now report the **same** canonical stage. This is the case the
  current parity test misses; it locks the normalization.
- **RAII / no-leak:** a snapshot whose optional `dnat_table` is unopenable while
  all mandatory pins open — assert the abort is clean (the earlier mandatory
  FDs drop; no leak). Uses the `TEST_MAP_PIN_OK`/`TEST_MAP_PIN_FAIL` seam.
- **Drop the "wrong-object" unit matrix** (issue AMEND): `open_bpf_map` only
  does `bpf_obj_get`, so a "pin resolves to the wrong map type" fault is not
  observable at this layer. Keep that claim only for a real pinned-map
  integration gate.
- **Loss-cluster smoke** (`make cluster-deploy` + `make test-failover`, v4+v6,
  loss userspace cluster ONLY): this IS the reconcile map-pin path — a real
  pinned-map startup/rebind exercises `preflight_map_fds` end-to-end. Serialize
  through one agent; re-apply CoS after deploy; reassert node0 before failover.

---

## 11. Out of scope

- **#6246** (`OpenedSnapshotMaps`-only return, non-optional `apply_snapshot`,
  removing the `ForwardingState::default()` placeholder / `PreparedReconcile`
  split). The issue's amendment folds #6246's acceptance criteria into #6243,
  but this plan keeps the placeholder-forwarding handling **byte-identical** and
  treats #6246 as a **follow-up** so the map-pin dedup lands as a tight,
  independently-reviewable change. See Q5.
- Any generalization of BPF map access beyond this snapshot-owned fixed 7-pin
  set (the AMEND's "do not generalize" guardrail).
- Deeper typing of the `OpenMapFailed` `err: String` payload into a structured
  error (that is #6244's explicitly-deferred #6243/#6245 boundary; here the
  `io::Error` is rendered to `String` at the stage boundary exactly as today).
- The policy-preflight (`preflight_policy_state`) and forwarding-build
  (`validate_forwarding_buildable`) legs — already shared verbatim by #5171;
  untouched.

---

## 12. Open questions (each PLAN-KILL-invitable)

1. **Canonical order (the crux).** Is normalizing the deferred path's
   multi-fault stage to the activated two-pass precedence (§5.1) an acceptable
   bug-fix, or a wire/operator behavior change that must be gated/flagged
   separately — or does a reviewer prefer the *deferred* one-pass order as
   canonical (which would instead change the *activated* path, touching the real
   forwarding SSOT)? If neither normalization is acceptable, is a unified opener
   even possible without a `mode`-ordering branch? **→ PLAN-KILL if the order
   cannot be normalized without branching.**
2. **`MapPinFault` vs bare `ReconcileStage`.** Is the richer typed
   `MapPinFault` enum (§6.2) worth it, or should the opener return
   `Result<OpenedSnapshotMaps, ReconcileStage>` and derive the per-binding label
   by matching on the stage? The bare-stage form is a smaller diff but folds the
   uppercase-`XSK` label mapping into the caller. **→ PLAN-KILL if the extra
   type adds surface without reducing drift risk.**
3. **Wrong-object / ABI validation.** `open_bpf_map` is only `bpf_obj_get` — no
   map type/key/value check. Should the unification *add* `bpf_obj_get_info` ABI
   validation (a real hardening win, but a behavior change + scope creep), or
   stay strictly openability-only? **→ PLAN-KILL the ABI-validation ask; keep it
   a separate issue.**
4. **Descriptor form.** Literal `[MapPinDesc; 7]` array walked by a loop, vs
   explicit two-pass code with the descriptor as documentation only? The array
   is a cleaner "one place to add pin #8" but complicates the named-field bundle
   assembly and RAII precedence. Which does the reviewer want? **→ PLAN-KILL if
   the array form is judged to obscure the fail-closed ordering.**
5. **#6246 fold — now or follow-up?** The issue amendment folds #6246 into
   #6243. Do we land the map-pin dedup alone (tight, this plan) and file #6246
   as the immediate follow-up, or must the placeholder-forwarding removal +
   non-optional `apply_snapshot` ship together to avoid a churny intermediate
   `OpenedSnapshotMaps`→`ReconcileSnapshotFds` shape? **→ PLAN-KILL this plan's
   narrow scope if the reviewer requires the combined #6243+#6246 landing.**
6. **Deferred multi-fault: is it reachable in production?** A RETH-MAC-pending
   deferred apply with two simultaneous map-pin faults — does any real
   Go-control-plane path emit such a snapshot, or is the divergence purely
   theoretical? If unreachable, does the normalization still earn its keep as
   drift insurance, or is it gold-plating? **→ PLAN-KILL the §5.1 test if the
   multi-fault input cannot occur.**
