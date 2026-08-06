# Claude SMR — hostile plan review r7 of `plan.md` v6-r7 (#2387)

Reviewed at `e80db2eae`. v6-r7 fixes Codex r5's three findings in the design. I attacked
those three fixes. **All three hold in direction, but two carry defects and one of them
re-introduces a hazard a prior reviewer already caught on this exact constant.**

## SMR-14 — MAJOR. Pinning `SessionSyncWireVersion` re-creates the hazard Copilot caught.

§4.3b's fix is to decouple and pin `SessionSyncWireVersion` so a `CurrentHAProtocolVersion`
bump does not trip the exact-match session-sync gate. The direction is right — the payload
change genuinely is additive, so the sync schema does not change incompatibly.

**But read the constant's own doc comment** (`pkg/cluster/sync.go:21-36`). It explains why
it tracks `CurrentHAProtocolVersion` and then says, verbatim:

> *"Deriving from the fixed Legacy constant would silently pin the gate to the stale
> schema version after an HA bump (Copilot)."*

**That is precisely what my fix does.** A prior review already identified this failure mode
on this exact line, and v6-r7 walks back into it. The coupling is not accidental — it is an
*automatic safety property*: it guarantees that whenever the HA protocol moves, the
session-sync gate moves with it, so an author who changes the sync format cannot forget to
bump. Pinning deletes that automatic property and replaces it with author discipline.

The risk is not to #2387 — it is to the **next** change. After pinning, someone who alters
`syncMsg*`/`syncHeader` incompatibly gets **no** signal, and `GateMixedBaseSwap` cheerfully
declares a mixed-base swap safe while the frames do not decode. That is a session-loss or
mis-decode bug in the upgrade path, which is the highest-consequence path in the product.

**Required:** pinning is still the right call, but it must ship with the safety property
replaced, not merely removed:

1. give `SessionSyncWireVersion` its **own explicit literal** with a comment stating the
   bump rule (exactly as the doc comment prescribes: *"replace this with its own counter"*);
2. add a **guard test that fails when the sync wire layout changes without a bump** — the
   golden fixture `userspace-dp/tests/fixtures/protocol_wire_v1.json` already exists and is
   the natural anchor. Without this, the constant silently rots;
3. state in the plan that the four existing `sync_protocol.go` comments asserting a change
   "does NOT bump SessionSyncWireVersion" (`:688`, `:733`, `:846`, `:931`) become the
   *only* remaining documentation of the rule, and that the guard is what makes them
   enforceable rather than aspirational.

Note also that the constant has **real consumers** I under-stated: `cmd/xpfd/main.go:199`
exports it as `session-sync-protocol-version`, which is what the Python deploy gate reads.
Pinning changes a value that crosses into `scripts/deploy/`.

## SMR-15 — MODERATE. §7a's "byte-identical on non-trunk topologies" is WRONG, and the defect is WIDER than the plan says.

§7a says: *"An untagged port has no `(parent, vlan)` entry, so `logical == physical` … which
is precisely why the error is invisible on every non-trunk topology."*

**The gate is not tagged-vs-untagged. It is parented-vs-unparented.**
`forwarding_build/interfaces.rs:291-295` inserts `(bind_ifindex, vlan_id) -> iface.ifindex`
whenever **`iface.parent_ifindex > 0`** — regardless of VLAN id. The existing test
`forwarding_build/tests.rs:1250` asserts exactly this for VLAN **0**:
`ingress_logical_ifindex.get(&(10, 0)) == Some(&11)`.

So a **unit-0 subinterface on a parent diverges too**. That includes `reth1.0` — which is
the LAN interface on the actual loss smoke cluster (`docs/ha-cluster-userspace.conf`).

**Two consequences, both in the plan's favour and both currently unstated:**

- the naive derivation is wrong on **more** topologies than claimed, so the fix is more
  load-bearing than §7a argues;
- the **test matrix widens**: the fixture must cover a parented **VLAN-0** unit as well as
  two tagged units on one parent. A reviewer who reads only the current §7a would build the
  tagged-only fixture and leave the vlan-0 parented case unbound.

**Required:** restate the divergence condition as `parent_ifindex > 0`, cite
`interfaces.rs:291-295` and the vlan-0 test at `tests.rs:1250`, and add the parented-unit-0
case to the test axis.

## SMR-16 — MODERATE. "Bounded" is conditional, and the plan should say on what.

§4.3c states the fail-open posture is *"bounded"* by the flush at the first authoritative
`BulkEnd`. That bound only exists **if a first authoritative bulk ever completes.** If the
peer never upgrades — or the bulk repeatedly fails — non-authoritative rows are never
flushed and the exposure persists indefinitely.

This is **not** a defect in the design, and I want to be precise rather than alarmist: in a
never-upgraded cluster the behaviour is *identical to today's status quo*, so it is not a
regression — it is simply the absence of the improvement. But calling it "bounded" without
that qualifier overstates the guarantee, and a reviewer or implementer could reasonably read
it as a hard bound and skip the observability.

**Required:** restate as *"bounded once the peer upgrades; in a never-upgraded cluster the
posture is exactly today's, which is the status quo and not a regression"*, and require a
**counter/log for non-authoritative rows still resident**, so an operator can see the
exposure rather than infer it. Also specify the flush's atomicity with respect to the fast
path — a packet must not observe a half-flushed table.

## What I attacked and could not break

- **The logical-ifindex direction (§0a/§7a)** is correct — `resolve_ingress_logical_ifindex`
  (`forwarding/mod.rs:114`) is keyed `(ifindex, vlan)` and is the same resolution
  `prerouting_ingress_scope` uses, so mirroring it is right.
- **The test-axis argument** holds: a physical-port-axis fixture passes against the broken
  design *and* survives RED-on-revert. That reasoning is sound and is the most valuable
  paragraph in the document.
- **Per-entry provenance (§4.3c)** genuinely eliminates all four races. Each row carrying its
  own truth means no row's behaviour depends on a mutable global — I could not construct a
  race against it beyond the never-completes case in SMR-16.
- **§4.3b(i) and (ii)** are correct: `MinCompat` is enforced as a floor at
  `imageversions.go:156`, and the exact-match session-sync comparison at `:170` is the real
  blocker. Only the *remedy* in (iii) is incomplete.

## Verdict

The three fixes are directionally right and the provenance redesign is a genuine
improvement. But SMR-14 has v6-r7 re-introducing a hazard a prior reviewer flagged on this
exact constant, and SMR-15 shows §7a understates its own defect in a way that would produce
an incomplete test fixture. Both are contained edits; neither is a redesign.

**VERDICT: PLAN-NEEDS-REVISION**

Required for r8:
1. Pin `SessionSyncWireVersion` **with** a replacement safety property — own literal, stated
   bump rule, and a golden-fixture guard test that fails on an unbumped layout change.
   Acknowledge the Copilot note at `sync.go:21-36` explicitly rather than silently
   contradicting it.
2. Restate the ifindex divergence condition as `parent_ifindex > 0` (not tagged-vs-untagged),
   and extend the test axis to the parented VLAN-0 case (`reth1.0` is a live example).
3. Qualify "bounded" in §4.3c, add an observability counter for resident non-authoritative
   rows, and specify flush atomicity against the fast path.
