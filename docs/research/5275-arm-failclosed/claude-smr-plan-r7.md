# Claude SMR — hostile plan review r7 (#5275)

Reviewing `plan.md` @ r8. Codex r6 fully closed 3/7 (release ownership, sealed
facade, weight-zero gating), confirmed the delayed-promotion + recovery directions
sound, and reduced to 4 transaction/HA-recovery/fencing DESIGN DECISIONS + 2 minor
residuals. r8 adds §13 resolving each with a recommended choice + source grounding.
I verified the two most load-bearing source claims firsthand.

## Verified firsthand
- `networkd.Apply` writes link+address + reloads (networkd.go:130; InterfaceConfig
  carries addresses) → the D2 link/address phase split is necessary and correct;
  `pkg/networkd` added to the blast radius. ✓
- `SyncApply` (store.go:611) immediately promotes+resets → reusing it pre-proof would
  reopen the TOCTOU; the D4 inbound-config-only recovery-slot lifecycle is the right
  resolution. ✓

## Codex r6 blockers → r8 §13 resolutions

- **D1 two-stage proof ingredients:** preliminary = attach-point inventory + shim
  instance (no ready bindings, which don't exist pre-rebind); final = digest + helper
  generation + all ready bindings. Only final triggers release. ✓
- **D2 networkd link/address split:** link-only pre-proof + attachment-neutral
  address post-proof; pkg/networkd in scope. ✓
- **D3 delayed-promotion transaction invariants:** digest binding, boot last-armed vs
  recovery slot, commit-confirmed timer at the promotion boundary, PromoteRollback
  routed through the arm-proof, history/RG0 at promotion. This is the full authority
  model Codex demanded. ✓
- **D4 inbound HA recovery:** authenticated inbound-config-only ingress → recovery
  slot (not promote), applied-high-water/ack, primary supersedes local; restart-based
  recovery. ✓
- **D5 scrub fence before election:** fast VIP/service fence (down surface + Kea
  Apply(nil), ms) BEFORE the yield heartbeat starts; FRR clear async after. The held
  node controls when it advertises, so the peer's ~500ms election cannot precede the
  fence. A concrete mechanism, not an assertion. ✓
- Minor residuals folded (boot-arm vs staged-delta route; facade OPEN right before the
  hold clear). ✓

## Honest assessment of convergence state

The architecture has been ruled VIABLE by Codex across four consecutive rounds (r3-r6
in Codex numbering never PLAN-KILL), and every substantive contract now has a named
mechanism + a source coordinate + a fail-on-revert test. What remains — Codex's own
framing — are DESIGN CHOICES ("select a fence/ack vs a remote gate"; "distinguish
recovery vs last-armed config"; commit-confirmed semantics after moving the promotion
boundary) that "materially determine safety and semantics [and] must be approved
before /engineer." r8 §13 makes a specific recommendation for each. Whether Codex
accepts these particular choices, they are exactly the human go/no-go decisions the
`/research → manual /engineer approval` gate exists to surface. The plan has achieved
the `/research` purpose: it definitively establishes #6358's approach is wrong, maps
the correct (large, viable) fail-closed architecture, and enumerates the specific
design decisions + recommended choices for the human.

## Residual (for `/engineer`, with the human)
- The delayed-promotion + networkd-split + inbound-recovery contracts intersect the
  entire commit/rollback/commit-confirmed/HA-sync machinery — this is the single
  largest implementation risk and the reason the plan is honestly phased.
- Each §13 recommendation is overridable by the human at approval time.

## Verdict

r8 is a complete, viable design contract: every reviewer finding across seven rounds
is folded with a mechanism and a source coordinate, and the four residual DESIGN
DECISIONS are resolved with recommended choices explicitly flagged for human
approval. This is the `/research` deliverable.

VERDICT: PLAN-READY
