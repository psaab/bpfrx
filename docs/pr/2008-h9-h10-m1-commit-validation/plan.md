# #2008 H9 / H10 / M1 — commit-validation quick-wins

Status: PLAN-READY v2 — Codex PLAN-NEEDS-MINOR (task-mqmx7m0r-4nmff6),
all three minor points folded (citation reproducibility, dual-AST H9
tests added + passing, M1-vs-H9/H10 strictness rationale). Gemini Code
Assist companion is deprecated (client unsupported) — second independent
review to be dispatched by the parent.
Base: origin/master c7b5800a4
Branch: refactor/2008-h9-h10-m1-commit-validation

## Issue framing

#2008 is the vSRX-parity umbrella tracking 27 gaps (H1..H18 + M1..M9).
The triage comment classified **H9, H10, M1** as "reject-at-commit /
commit-warning quick-wins (control-plane)". This increment closes the
remaining silent-drop gaps among them.

The three audit rows:

| Gap | Stanza | Today (master) | Audit's full-fix |
|---|---|---|---|
| **H9** | `interface unit family inet policer arp <name>` | parse=accepted / compile=**none** / implement=none. Interface Policer is "Missing" in `feature-gaps.md:348`. | schema child + `ARPPolicer` field + ref-resolution to firewall policer + per-unit dataplane encode |
| **H10** | `interface mac <addr>` (static MAC override) | parse=accepted / compile=**none** / implement=none. RETH MAC is deterministically computed per node. | `ValueMAC`/`ValidateMAC` + `MAC` field + compiler extract + dataplane respect-if-present (diverges from Junos read-only MAC) |
| **M1** | `system commit persist-groups-inheritance` | full / full / **no-op + commit WARNING** (`compiler.go:1533`, `types_system.go:47`) | Daemon group-membership persistence + schema formalization |

## Source-verified state (master c7b5800a4)

- **H9.** `pkg/config/schema_interfaces.go` `family inet`/`inet6` have
  NO `policer` child. `pkg/config/compiler_interfaces.go` never reads a
  `policer`/`arp` token under a family. `SchemaValidate`
  (`schema_walk.go:241-244`) returns nil for an unknown keyword. So
  `set interfaces ge-0/0/0 unit 0 family inet policer arp x` commits
  cleanly and is silently dropped. The userspace dataplane has NO
  per-interface ARP policer enforcement (`feature-gaps.md:348`
  "Interface Policer ... Missing"); the only policer enforcement is the
  admitted firewall-filter path + color-blind three-color discard
  (`pkg/dataplane/userspace/filters.go`). A per-unit ARP rate-limiter
  is a net-new dataplane subsystem — **not** a quick-win.
- **H10.** `interfaces <if>` wildcard node has NO `mac` child;
  `unit <n>` has none either. `compiler_interfaces.go` never reads a
  `mac` token at interface or unit scope. The RETH virtual MAC is
  computed deterministically per node (`02:bf:72:CC:RR:NN`,
  `programRethMAC`), and `set chassis device-map interface ... mac` is a
  *match-identity key*, not an override. A static per-interface MAC
  override silently drops today and, if implemented, would diverge from
  Junos (where interface MAC is read-only) and collide with the
  deterministic cluster MAC. **Reject-at-commit is the correct
  disposition** (triage: "recommend reject-at-commit").
- **M1.** `persist-groups-inheritance` is ALREADY parsed
  (`compiler_system.go:126`), stored (`PersistGroupsInheritance`,
  `types_system.go:47`), and **commit-warned**
  (`compiler.go:1533-1534`). The silent-drop is already closed; the only
  remaining work is real daemon-side group-membership persistence — a
  large feature the #2008 "Tier-2 parity research" comment graded
  "large-needs-design / likely reject ... prove apply-groups
  equivalence first ... lowest value. NOT Increment-2." (The full Tier-2
  plan doc lives on the `research/2008-tier2` branch, not master; the
  disposition is reproduced verbatim in the #2008 issue comment thread.)

### Why H9/H10 are stricter (reject) than M1 (warn)

M1 is a daemon *behaviour* knob that is harmless as a no-op: a config
that sets `persist-groups-inheritance` still produces a correct firewall
posture (xpf's eager group expansion already yields the persisted
result), so a warning is honest. H9 and H10 are *false promises about
dataplane enforcement / interface identity*: a committed `policer arp`
claims ARP is rate-limited and a committed `mac` claims a specific
hardware address — neither of which the running firewall delivers.
Silently accepting (or only warning at commit on) such a stanza lets an
operator deploy a config they believe is enforcing security/identity
when it is not. The split: strict on commit/commit-check (block a new
operator edit that would deploy a fake guarantee), lenient on
load/peer-sync (an already-imported or peer-synced config that an older
binary silently accepted must still boot — import-compatibility, the
PR #659 precedent — and the stanza is a harmless no-op once booted).

## Disposition

- **H9 — SHIP (reject-at-commit).** The dataplane cannot enforce a
  per-unit ARP policer, so admitting the stanza is a silent functional
  drop. Hard-reject at commit with a diagnostic pointing the operator
  at the limitation; lenient-downgrade-to-warning on load/peer-sync per
  the #1960 fail-closed-on-load doctrine so an older-binary-persisted or
  peer-synced config still boots.
- **H10 — SHIP (reject-at-commit).** Same silent-drop class; static MAC
  override is unsupported (diverges from Junos read-only MAC, conflicts
  with deterministic cluster MAC). Hard-reject at commit, lenient on
  load/peer-sync.
- **M1 — SPLIT to /research (exclude from this PR).** Not a silent-drop
  (already commit-warned) and not a clean reject candidate (legitimate
  no-op-tolerated knob; rejecting would break configs that set it
  expecting Junos behaviour). The real fix is the large daemon
  persistence feature the Tier-2 research already flagged needs a design
  + apply-groups-equivalence experiment. Per the task's STOP rule, M1 is
  excluded and recommended for /research. No code change for M1.

So this PR ships **H9 + H10** as paired reject-at-commit validators and
leaves M1's existing warning untouched.

## Concrete design

One new file `pkg/config/compiler_interfaces_unsupported.go` carrying an
AST pre-walk over the group-expanded, inactive-pruned `interfaces`
subtree, mirroring `validateVRRPTrackInterfaceAST`
(`compiler_interfaces.go:789`) exactly:

```go
// returns (warnings, error); strict=hard-reject, lenient=warn
func validateUnsupportedInterfaceStanzasAST(nodes []*Node, lenient bool) ([]string, error)
```

Wired into `compileExpanded` (`compiler.go`) alongside the existing AST
pre-walks (control-char, VRRP-track, tcp-mss), AFTER group expansion so
apply-groups-inherited statements are covered and AFTER the inactive
prune so an `inactive:` H9/H10 stanza is ignored (H1 doctrine —
free by construction since `compileConfigWithOpts` prunes+expands before
`compileExpanded`).

Detection (scoped to the `interfaces` stanza ONLY, so the firewall
`policer` stanza and chassis device-map `mac` are never touched):

- Walk top-level nodes; descend ONLY into the `interfaces` node.
- For each interface (wildcard) node:
  - **H10 interface-level MAC**: any direct child with `Keys[0]=="mac"`.
  - For each `unit` child:
    - **H10 unit-level MAC**: any direct child with `Keys[0]=="mac"`.
    - For each `family` child whose family is `inet`/`inet6`:
      - **H9 ARP policer**, two AST shapes:
        - flat-set: a child with `Keys[0]=="policer" && Keys[1]=="arp"`
        - hierarchical: a `policer` child containing an `arp` child.

Both detections produce a deterministic, path-qualified error on the
strict path and a `cfg.Warnings` entry on the lenient path.

A paired `compileOpts.lenientUnsupportedInterfaceStanzas` flag, set ONLY
in `CompileConfigLenient` + `CompileConfigForNodeLenient`, mirrors every
sibling lenient gate. The warning text names the exact stanza +
interface/unit path so the operator can find and remove it.

### Why an AST pre-walk and not SchemaValidate

`SchemaValidate` is opt-in per typed leaf and returns nil for unknown
keywords by design (`schema_walk.go:241`); it cannot REJECT an unknown
stanza. The existing reject-at-commit-for-unsupported gates
(control-char, VRRP-track, tcp-mss, tunnel-id) all live as AST pre-walks
in `compileExpanded` for exactly this reason. H9/H10 follow that
established pattern.

### Why not add the schema child + drop silently

Adding a schema child without a compiler consumer would make completion
advertise a stanza that still silently drops — worse than today. The
honest control-plane contract for an unenforceable stanza is a commit
rejection that tells the operator the firewall will not honour it.

## Public API preservation

No exported signatures change. `CompileConfig` / `CompileConfigLenient`
/ `CompileConfigForNode` / `CompileConfigForNodeLenient` keep their
signatures; only their internal `compileOpts` gains one bool field and
`compileExpanded` gains one validator call. No typed-config field is
added (the stanzas are rejected, not stored). No dataplane wire change.

## Hidden invariants preserved

- **#1960 fail-closed-on-load.** Strict on commit / commit-check;
  lenient (warn) on load / peer-sync — an older-binary-persisted config
  that silently accepted these stanzas, or a peer-synced section, still
  boots.
- **#2008 H1 inactive.** An `inactive:` H9/H10 stanza is ignored (the
  prune runs before `compileExpanded`). Covered by a test.
- **apply-groups.** Runs on the expanded tree, so an
  apply-groups-inherited H9/H10 stanza is caught. Covered by a test.
- **Scope isolation.** Detection descends only the `interfaces` stanza;
  `firewall policer <name>` and `chassis device-map interface ... mac`
  are untouched. Covered by a non-regression test.
- **No side-effect reordering.** Read-only AST walk on the lenient path
  too (warn-only; unlike VRRP-track it does NOT prune — the stanza is
  already a no-op, so leaving it in the tree is harmless and the warning
  is the operator signal).

## Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure additive commit-time validator; no compiled output changes for any valid config. The only behaviour change is: a config carrying H9/H10 now FAILS commit (was a silent no-op). That is the intended parity fix. |
| Load/peer-sync regression | LOW | Lenient downgrade is the established #1960 pattern; an upgraded node loading a legacy config warns rather than fails. |
| Performance | NONE | One extra O(interfaces×units×families) AST walk at commit only. |
| Architectural mismatch | LOW | Mirrors four existing AST-pre-walk gates verbatim. No new abstraction. |

## Test plan (control-plane — NO dataplane smoke)

`pkg/config/compiler_interfaces_unsupported_test.go`, dual-AST via
`ParseSetCommand`+`SetPath` (flat) AND `NewParser` (hierarchical):

1. H9 flat-set inet rejected on strict commit (`CompileConfig` err).
2. H9 flat-set inet6 rejected.
3. H9 hierarchical rejected.
4. H9 lenient (`CompileConfigLenient`) accepts + warns (non-fatal).
5. H10 interface-level MAC rejected (flat + hier).
6. H10 unit-level MAC rejected.
7. H10 lenient accepts + warns.
8. `inactive:` H9/H10 stanza COMPILES clean (no error, no warning).
9. apply-groups-inherited H9/H10 rejected on strict.
10. Non-regression: `firewall policer <name>` definition + a unit
    `family inet filter` + chassis `device-map interface ... mac`
    all compile clean (no false positive).
11. Non-tautological: each reject test ALSO asserts the SAME tree minus
    the offending stanza compiles clean (proves the validator, not an
    unrelated error, fails the bad case — fails pre-fix).

Plus: `go build ./...`, `go test ./pkg/config/...`, full `go test ./...`.

## Docs

- `docs/feature-gaps.md` Interface Policer row (line 348): note H9 ARP
  policer is reject-at-commit (unsupported, not silently dropped).
- Add an H9/H10 entry to the parity tracking where the other #2008
  rows are recorded (config-schema or feature-gaps), marking them
  reject-at-commit-shipped. M1 stays as-is (already warned).

## Out of scope (explicit)

- M1 daemon group-membership persistence — split to /research.
- Any real ARP policer dataplane enforcement (H9 full fix).
- Any static MAC override dataplane support (H10 full fix).
- Schema-completion entries for `policer arp` / interface `mac` — we
  deliberately do NOT advertise a stanza we reject.

## Open questions for adversarial review

1. Is reject-at-commit the right disposition for H9/H10, or should one
   be a warn-only (like M1) instead of a hard reject? (Argument for
   reject: silent functional drop today; for warn: less likely to break
   an imported vSRX config on first commit.)
2. Does scoping detection to the `interfaces` stanza miss any legitimate
   place `mac`/`policer arp` can appear under an interface that we'd
   false-reject — e.g. `aggregated-ether-options`, `gigether-options`,
   a `mac` inside something else?
3. Is the M1 split-to-research correct, or is there a cheap upgrade
   (e.g. strengthen the warning) worth doing in this PR?
4. Is the lenient warn-only (no prune) safe, given the stanza is a
   no-op? Could leaving it in the expanded tree confuse any later
   compiler pass?
5. Should H10 also catch `mac` under `interface-set` / logical-systems
   or other interface containers, or is physical+unit sufficient for
   parity?
6. Could a future real implementation of H9/H10 want these as typed
   leaves instead of rejects, making this PR throwaway churn? (If so,
   PLAN-KILL one or both.)
