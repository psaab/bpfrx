# #1712 — FRR OSPFv2 per-interface `ip ospf area` (drop `network 0.0.0.0/0 area`)

**Status:** PLAN-READY v2 — Codex PLAN-NEEDS-MINOR (task-mpta3w3q-yvxr2c,
minors folded in below), AGY PLAN-READY (adversarial-review-mpta426w-nrlywl),
Claude-SMR PLAN-READY. No PLAN-KILL.

### v2 deltas from adversarial review (Codex minors)

- **FRR forbids mixing `network` and `ip ospf` activation** on the same
  instance — this makes deleting the global `network` line not just an
  improvement but *required* for a well-formed config.
- **Test invariant strengthened:** assert the rendered OSPFv2 config contains
  NO `network ... area ...` line at all (not merely no `network 0.0.0.0/0`).
- **"Exactly one interface block" claim corrected:** `generateInterfaceSettings`
  (config_render.go:65, called before `generateProtocols` per manager.go:261)
  can already emit an earlier `interface <name>` block for bandwidth /
  point-to-point. Multiple FRR `interface` stanzas for the same name are legal
  (FRR merges them). The real invariant is **one OSPFv2 `ip ospf area`
  activation line per configured OSPF interface**, not one interface block.
- **VRF claim qualified:** bare `interface <name>` + `ip ospf area` is correct
  for this repo's Linux-VRF model (interface enslaved to VRF independently;
  OSPFv3 already relies on it). Not asserted as universal across all FRR zebra
  backends.
- **Mandatory implementation constraint (Claude-SMR):** the interface block
  MUST be emitted UNCONDITIONALLY for every OSPF interface — today it is gated
  on `cost/network-type/auth/BFD`. A plain interface (none of those) currently
  relies solely on the `network` line for activation; if the block stays
  conditional, plain interfaces silently lose OSPF entirely.

## Issue framing

`pkg/frr/policy_render.go` renders OSPFv2 area membership with a global
`network 0.0.0.0/0 area <id>` statement, one per configured interface
(`generateProtocols`, lines 116-119), using the placeholder helper
`ifaceNetwork()` which hardcodes `"0.0.0.0/0"`.

In FRR OSPFv2 (zebra/ospfd), `network 0.0.0.0/0 area X` under
`router ospf` does **not** mean "the interface named in the AST." The
`network <prefix> area` form matches **every interface in the VRF whose
primary address falls inside `<prefix>`**, and `0.0.0.0/0` contains every
IPv4 address. Consequences:

1. **Over-activation.** Configuring OSPF on one interface activates OSPF on
   *every* IPv4 L3 interface in the VRF — including interfaces the operator
   never placed in any area (mgmt, untrust, etc.). That forms unintended
   adjacencies and leaks LSAs.
2. **Wrong-area placement with multiple areas.** With two areas, the renderer
   emits two overlapping `network 0.0.0.0/0 area A` / `... area B` lines.
   ospfd assigns an interface to the **first** matching `network` statement;
   since both match everything, render order (AST area/interface order)
   silently decides the area. The operator's per-interface area intent is
   discarded.

The helper name `ifaceNetwork(name)` implies interface specificity; the value
it returns is global. This is a HIGH correctness defect in routing-plane
config generation. `frr_test.go:142` currently **pins** the buggy output
(`network 0.0.0.0/0 area 0.0.0.0`), so the test suite actively protects the
bug.

## Fix

Render OSPFv2 area membership per-interface using the standard FRR
**interface-level** idiom — exactly mirroring how OSPFv3 (`router ospf6`)
already does it in this same function (lines 189-193: per-interface
`interface <name> area <id>`):

Under `interface <name>`:
```
interface trust0
 ip ospf area 0.0.0.0
exit
!
```

`ip ospf area <area>` under an `interface` stanza is the canonical FRR
OSPFv2 form for activating OSPF on exactly that interface in exactly that
area, and requires **no** interface CIDR (FRR derives the network from the
interface's own addresses). It is the per-interface analogue of the global
`network ... area` form and does not over-match. Validity confirmed against
FRR ospfd documentation and the existing in-tree usage: the function
**already emits** `ip ospf area %s` at line 177 inside the conditional
per-interface settings block — so the form is already trusted by this code;
the bug is solely that the *primary activation* still goes through the global
`network` line and the per-interface `ip ospf area` is emitted only when an
interface ALSO has cost/network-type/auth/BFD set.

### Concrete change in `generateProtocols` (OSPF branch)

1. **Delete** the global `network %s area %s` emission (lines 117-119), but
   keep the `passive-interface` / `no passive-interface` handling that is
   interleaved in that loop (lines 120-126). `passive-interface <name>` and
   `no passive-interface <name>` under `router ospf` remain valid FRR and are
   independent of activation; leaving them in the `router ospf` block is the
   minimal, behavior-preserving choice.
   - Net effect of the inner loop after edit: it emits only the passive
     directives. The `network` line is gone.

2. **Always emit a per-interface `interface <name>` block** for every OSPF
   interface in every area, containing at least `ip ospf area <area>`. Today
   the second loop (lines 147-181) only emits a block when
   `iface.Cost>0 || NetworkType!="" || AuthType!="" || BFD`. After the fix,
   the block is emitted **unconditionally** for every interface (because the
   `ip ospf area` activation now lives there), and the optional
   cost/network/auth/BFD lines are emitted inside it as before. `ip ospf area`
   stays as the activation line (line 177 today) and remains the last
   per-interface directive before `exit`.

3. **Remove `ifaceNetwork()`** entirely — it has no other callers
   (`grep` confirms the only call site is the line being deleted). Update the
   `policy_render.go` file-header symbol comment (line 17) and
   `pkg/frr/README.md:21` which both list `ifaceNetwork` as a symbol.

### Resulting OSPFv2 output shape (two areas, one unrelated iface)

For OSPF with area 0.0.0.0 = {trust0}, area 0.0.0.1 = {dmz0}, and an
unrelated L3 interface `untrust0` **not** in any OSPF area:
```
router ospf
 ospf router-id 1.1.1.1
 passive-interface dmz0           # if configured passive
exit
!
interface trust0
 ip ospf area 0.0.0.0
exit
!
interface dmz0
 ip ospf area 0.0.0.1
exit
!
```
`untrust0` gets **no** `ip ospf area` and **no** `network` line that could
match it → OSPF is never activated on it. With per-interface `ip ospf area`,
area placement is explicit and render-order-independent.

## OSPFv3 parity note

OSPFv3 already uses the per-interface idiom (`interface <name> area <id>`
under `router ospf6`, line 191) and is **not** affected by this bug. This
change brings OSPFv2 rendering into line with the OSPFv3 approach. OSPFv3 is
out of scope except as the reference idiom.

## Optional refactor (`pkg/frr/ospf/`)

The issue suggests extracting `pkg/frr/ospf/`. `generateProtocols` is a single
~390-line function rendering 5 protocols; the OSPF branch is ~75 lines.
Extracting a clean `pkg/frr/ospf/` package would require either moving the
whole multi-protocol function or threading `bfdProfiles`/`bfdProfileName`
(shared with ISIS/BGP) and `resolveRedistribute` (a `*Manager` method) across
a package boundary — i.e. it is **not** a clean seam at the OSPF granularity.
**Decision: do NOT extract** in this PR. The bug fix is the priority; the
optional extract would balloon the diff and entangle shared BFD/redistribute
helpers. Recorded as out-of-scope; can be revisited under the `pkg/frr`
file-layout mandate separately.

## Hidden invariants the change must preserve

- **Deterministic output.** Areas and interfaces are iterated in AST order
  (slices, not maps) — order is already deterministic and unchanged.
- **passive-interface semantics.** `PassiveDefault` + per-iface
  `Passive`/`NoPassive` directives must still be emitted exactly as before
  (count and text). They move nowhere; only the `network` line is removed
  from the same loop.
- **Area type / virtual-link / maximum-paths / export.** All emitted from the
  area loop / after it under `router ospf`; untouched.
- **VRF suffix.** `router ospf vrf X` header is unchanged. `interface <name>`
  blocks need no vrf suffix — in FRR an interface is bound to its VRF
  independently, and `ip ospf area` under `interface` activates it in that
  VRF's ospf instance. (Confirmed: OSPFv3 already emits bare
  `interface <name>` blocks for VRF instances in this same function.)
- **No double-emission.** Each interface gets exactly one `interface` block.
  Previously an interface with cost/auth/bfd got one block AND a `network`
  line; now it gets one block only.

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression (config semantics) | **This IS a behavior change — intended.** OSPFv2 stops over-activating; this is the fix. No *unintended* behavior change for correctly-single-area configs that previously happened to work by luck. |
| Borrow/lifetime | N/A (Go, string builder) |
| Performance | None (config render, runs on commit) |
| Architectural mismatch | LOW — mirrors the existing in-tree OSPFv3 idiom and the existing `ip ospf area` emission; no new architecture. |

## Test plan

- `go test ./pkg/frr/...` — update `TestGenerateProtocols_OSPF` to REJECT
  `network 0.0.0.0/0` and ASSERT per-interface `ip ospf area` blocks.
- New test `TestGenerateProtocols_OSPFTwoAreasUnrelatedIface`: two areas with
  distinct interfaces + the renderer must NOT emit any `network 0.0.0.0/0`,
  must emit `interface trust0 / ip ospf area 0.0.0.0` and
  `interface dmz0 / ip ospf area 0.0.0.1`, and must place each interface in
  its own area (no overlap). (An "unrelated L3 interface" is one simply not
  present in `ospf.Areas` — the renderer never references it, so the
  assertion is "no `network 0.0.0.0/0` that would catch it" + "only the two
  configured ifaces get `ip ospf area`".)
- Existing `TestGenerateProtocols_OSPFExportAndCost` /
  `TestGenerateProtocols_VRF` must still pass (cost/auth/vrf paths).
- Full Go suite: `go test ./...`.
- No cluster smoke (FRR config-render, not dataplane). Optional light
  FRR-reload sanity check on loss:xpf-userspace-fw0 stated but not required.

## Out of scope

- `pkg/frr/ospf/` extraction (see above — not a clean seam).
- OSPFv3 changes (already correct).
- Any AST / parser / schema changes (the typed `OSPFInterface`/`OSPFArea`
  already carry per-interface area membership — the renderer just wasn't
  using it correctly).

## Open questions for adversarial review

1. Is `ip ospf area <area>` under `interface <name>` valid and sufficient to
   activate OSPFv2 on exactly that interface in FRR (no `network` line
   needed)? (Claim: yes — standard ospfd interface-level form.)
2. Does removing the global `network` line break any *currently-correct*
   deployment — e.g. one relying on `0.0.0.0/0` matching an interface whose
   name wasn't in the AST but whose address the operator wanted in OSPF?
   (Claim: no such path exists; the AST only carries explicitly-configured
   interfaces, and over-matching others is the bug.)
3. For a VRF OSPF instance, does a bare `interface <name>` block with
   `ip ospf area` correctly target the VRF's ospfd instance, or is a
   `vrf`-qualified form required? (Claim: bare is correct — interface is
   VRF-bound independently; OSPFv3 already relies on this.)
4. Does moving activation out of the `router ospf` block while leaving
   `passive-interface`/`no passive-interface` there create any FRR ordering
   or dependency problem (e.g. passive referencing an interface not yet
   activated)? (Claim: no — passive directives are independent of activation
   order in ospfd.)
5. Should `passive-interface <name>` instead move to `ip ospf passive` under
   the per-interface block for consistency? (Claim: not required for the fix;
   keeping it minimizes the diff and both forms are valid. Open to reviewer
   preference, but a behavior-equivalent relocation is out of scope risk.)
