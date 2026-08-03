# Plan of Action - #6744: Revalidate and split `kimi-review-003`

## 1. Status

**DRAFT v8 - round-seven major findings addressed; pending round-eight review**

- Issue: [#6744](https://github.com/psaab/xpf/issues/6744)
- Source report: `/tmp/kimi-review-003.md`
- Base: `origin/master` at `ad959117748181dabe46b8ddc2827de670380cea`
- Branch: `research/6744-kimi-review-003`
- Revision: 8
- Round-one plan SHA: `78891c3242a80b719bebdddc702087c07543e05b`
- Round-two plan SHA: `01b67530e53016cf127d43c4a28c0582513718f8`
- Round-one verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-NEEDS-MAJOR`; independent SMR-method fallback `PLAN-NEEDS-MAJOR`.
  The Claude Code CLI was infrastructure-blocked before analysis, so no
  Anthropic-model verdict is claimed.
- Round-two verdicts: Codex `PLAN-READY`; AGY `PLAN-READY`; independent
  SMR-method fallback `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed
  before analysis at the account spend limit, so no Anthropic-model verdict is
  claimed. Round two did not converge; revision 3 incorporates every valid
  finding from the dissenting review.
- Round-three plan SHA:
  `d746944992d3d91763e79498ba5bf5b139eff943`.
- Round-three verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-READY`; independent SMR-method fallback
  `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed before
  analysis at the account spend limit, so no Anthropic-model verdict is
  claimed. Round three did not converge; revision 4 incorporates every valid
  source-grounded finding.
- Round-four plan SHA:
  `26843cb0f4870b89c4849bcb1f24ff7dc0ec658d`.
- Round-four verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-READY`; independent SMR-method fallback
  `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed before
  analysis at the account spend limit, so no Anthropic-model verdict is
  claimed. Round four did not converge; revision 5 closes the DDNS authority
  lifetime, compiler-equivalent RG view, confirm-recovery state-machine, and
  canonical SNMP-shape gaps found by the dissenting reviews.
- Round-five plan SHA:
  `fdd7bbf06157ef18b295026d4b245c08c23e1090`.
- Round-five verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-READY`; independent SMR-method fallback
  `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed before analysis at the
  account spend limit, so no Anthropic-model verdict is claimed. Round five
  did not converge; revision 6 closes confirm target classification and raw
  hash ordering, endpoint-aware DDNS co-ownership, fixed-updater provenance,
  existing SNMP compatibility and rejected-only diagnostics, RG product-domain
  and mixed-version behavior, and public override-input parity.
- Round-six plan SHA:
  `cab8851171889b6e97d518d6fe9540341fc942f7`.
- Round-six verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-NEEDS-MAJOR`; independent SMR-method fallback
  `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed before analysis at the
  account spend limit, so no Anthropic-model verdict is claimed. Round six
  converged on rejection but not `PLAN-KILL`: revision 7 removes the
  speculative generalized DDNS teardown and commit-confirm protocol redesigns,
  defines an actual normalized-SNMP carrier and deep fold, separates RG control
  definitions from dataplane owner slots, and closes the rejected-config
  session-install race with an exact epoch gate and resync request.
- Round-seven plan SHA:
  `c952d74ef6ea8bea994b44f1697b412353577d6d`.
- Round-seven verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-READY`; independent SMR-method fallback
  `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed before analysis at the
  account spend limit, so no Anthropic-model verdict is claimed. Round seven
  did not converge; revision 8 makes both indistinguishable SNMP input forms
  reloadable, preserves structured SNMP client-deny semantics, gives each DDNS
  store an exact surface contract, orders co-owner claim release before delete
  authority, removes the impossible RG artifact-freshness oracle, fences reused
  RG slots, linearizes session install against config apply and bulk repair,
  validates the nested confirm rollback tree, and restores the exact #6548
  ownership boundary.
- Mode: `/research`. Stop at `PLAN-READY` or `PLAN-KILL`. Do not write
  production code and do not open a pull request.

## 2. Issue framing

The source report says it found 15 individually fileable defects and a
128-item low-materiality cohort. Before treating that report as an engineering
backlog, this research must answer four separate questions for every claim:

1. Does the alleged path still exist on the exact current `master` revision?
2. Does the execution trace and impact survive hostile source inspection?
3. Is the root cause already owned by an open issue or fully fixed by a closed
   issue and merged pull request?
4. If a residual is real, what is the smallest production-safe change and
   validation boundary?

The report is not internally self-verifying. Its body contains two route-map
entries for one root cause, its final split adds a `vipWarnedIfaces` race that
has no body finding, and it does not preserve or enumerate the 128 proposed
cohort items. The research therefore treats the report as an input, not as
ground truth.

### 2.1 Disposition vocabulary

- **LIVE**: mechanically proved on current `master`, with no existing owner.
- **PARTIAL**: a narrower residual is live, but the report's scope, standards
  claim, or impact is overstated.
- **DUPLICATE**: an open issue already owns the same root cause and path.
- **FIXED**: the claimed defect was removed, with the fixing history identified.
- **REFUTED**: the claimed execution path or invariant is false.
- **UNACTIONABLE**: provenance is insufficient to reproduce or deduplicate the
  claim; it must not become an engineering workstream without source evidence.

### 2.2 Current disposition matrix

All source anchors below were checked at the base SHA. Targeted current tests
for `pkg/config`, `pkg/configstore`, `pkg/ddns`, `pkg/logging`, `pkg/snmp`,
`pkg/routing`, and `pkg/daemon` pass; those passing suites do not cover the
adversarial traces in this matrix.

| ID | Report claim | Disposition | Confidence | Corrected severity | Ownership / evidence |
|---|---|---|---|---|---|
| K003-01 | Flowless LocalDelivery passes ICMP type 0 into host-inbound, disabling the global ICMP-error admission | **LIVE** | High | Medium | `userspace-dp/src/afxdp/poll_descriptor/flowless_verdict.rs`; closed #3171 and #3292 implemented the two halves but did not test their composition |
| K003-02 | Local in-process CLI commits a partial terminal paste after Ctrl-C or read failure | **DUPLICATE** | High | Medium | Open [#6548](https://github.com/psaab/xpf/issues/6548) owns this exact `pkg/cli/cli_config.go` residual |
| K003-03 | Disabling one DDNS family can withdraw through the other family's backend | **LIVE** | High | Medium | `pkg/ddns/manager.go:907-921` uses the cross-family `m.updater` despite per-family anchors added by #5814. The trigger is narrower than reported: it requires the family to become backend-less, both blocks to disappear, or backend construction to fail while withdrawal is needed |
| K003-04 | `compileInterfaces` indexes `afNode.Keys[0]` on persisted malformed AST input | **LIVE** | High | Low | `pkg/config/compiler_interfaces.go:365`; closed #4827 fixed sibling firewall walks only. The report's HA-sync path is false because peer sync reparses text; reachability is malformed persisted JSON or a handcrafted tree |
| K003-05 | Nested `from-zone X { to-zone Y { ... } }` is accepted and silently omitted | **LIVE (honesty, not parity)** | High | Medium | The omission is real, but the report's vSRX parity premise is false: Junos documents one combined `from-zone X to-zone Y` hierarchy. Open [#4313](https://github.com/psaab/xpf/issues/4313) supplies the closed-world doctrine but explicitly delegates concrete domain gaps; Workstream M owns exact rejection of this unsupported shape |
| K003-06 | Repeated top-level/global address-book blocks replace or ignore earlier entries | **LIVE** | High | Low | `pkg/config/compiler_security_addressbook.go:221-235`; #4706/#4818 fixed inner/sibling merge classes, not these containers |
| K003-07 | Empty zone, zone-pair, global-scope, and policy identities commit and then reject or widen at runtime | **LIVE** | High | Medium | Empty string is a special token in `compiler_validate_strict_zones.go`; `sortDedupZones` strips it while Rust preflight rejects concrete empty references. #6455 and #6464 do not own the Go acceptance residual |
| K003-08 | Route-map bounds count one referenced prefix-list name while rendering one row per IP family | **LIVE** | High | Medium | `pkg/config/routemap_seq_bound.go` disagrees with `pkg/frr/prefix_list_render.go`; the second report heading is the same root cause, not another finding |
| K003-09 | `LoadOverride` advertises flat set input but parses it as hierarchical junk and atomically replaces the candidate | **LIVE** | High | Medium | `pkg/configstore/store_command.go:304-335`; `LoadMergeAs` and `LoadSetAs` already contain the missing flat-line validation/replay pattern |
| K003-10 | RG IDs beyond the 16-entry dataplane domain can commit but never become active | **PARTIAL** | High | Medium | The owner-binding cap mismatch is live, but control definitions 0..255 are intentionally supported by heartbeat/session-sync and Rust. Only explicit userspace dataplane bindings are constrained to 1..15; zero is unbound and every binding must name a definition. The blanket definition clamp in the report is false |
| K003-11 | Bond delete and tunnel clear treat every `LinkByName` failure as absence and forget ownership | **LIVE** | High | Medium | `pkg/routing/bond.go:576-589` and `pkg/routing/tunnel.go:1237-1262`; sibling XFRM code already has correct `isLinkNotFound` handling |
| K003-12 | Syslog TLS handshake has no deadline | **REFUTED** | High | None | `tls.Dialer.DialContext` derives a deadline from `NetDialer.Timeout` and applies it to `HandshakeContext`; the configured five-second timeout already bounds DNS, TCP, and TLS handshake |
| K003-13 | SNMPv3 configured protocol without required key material silently lowers the served security level | **LIVE** | High | Medium | Schema/compiler permit partial credentials; `pkg/snmp/v3.go` derives and enforces the floor from key presence rather than configured intent. This is a residual of #4897 |
| K003-14 | SESSION_OPEN/CLOSE trace and REST/SSE surfaces render an intentionally meaningless wire action 0 as `deny` | **LIVE** | High | Low | Rust lifecycle producers intentionally write zero; `pkg/logging/trace.go` and `pkg/api/sse.go` expose it as a forwarding decision |
| K003-15 | Binary SESSION_OPEN stores action 0 (`deny`) while only SESSION_CLOSE maps to `0xff` | **LIVE** | High | Low | `pkg/logging/ringbuf.go:1370-1379`; same semantic root as K003-14 and should be fixed in one workstream |
| K003-16 | `vipWarnedIfaces` reset and mutation use unrelated synchronization | **LIVE** | High | Medium | `pkg/daemon/daemon_apply.go` resets the map under `applySem`; `daemon_ha_vip.go` accesses it under other call-path locks. A reset between lazy-init/check and assignment can panic with `assignment to entry in nil map`; no external exploit or persistent corruption is proved |
| K003-C | 128 low-materiality cohort survivors | **UNACTIONABLE** | High | None | The report neither lists them nor preserves the batch artifacts. A number and category summary cannot be reproduced, deduplicated, or reviewed |

Net result: 13 live claims, one partial claim, one current duplicate, one
refuted claim, and one unactionable cohort. K003-14 and K003-15 are one semantic
root, leaving **13 independent retained root causes**.

## 3. Honest scope and value framing

This is a correctness and security-hardening batch, not a throughput project.
Most fixes are cold-path configuration, control-plane, or observability work.
The only packet-path change proposed is one already-computed ICMP type byte on a
flowless local-delivery branch; it adds no allocation, lookup, or common-path
work.

The material value is absolute rather than statistical:

- prevent one concurrent HA warning-state interleaving from crashing `xpfd`;
- prevent commit/apply divergence that can leave stale permissive policy state
  armed or silently widen an empty global scope;
- prevent cross-family wrong-endpoint DNS deletion and retain ownership whenever
  same-family authority cannot be proved;
- prevent unauthenticated SNMPv3 reads when the operator configured an auth or
  privacy protocol but omitted required material;
- restore PMTUD and ICMP error delivery on the specific AF_XDP flowless
  local-delivery path;
- prevent one oversized dual-stack route policy from poisoning a whole FRR
  reload;
- reject or correctly replay a flat override before it can replace the entire
  candidate with a junk tree;
- preserve routing ownership on transient netlink lookup failures;
- stop accepted RG configurations from advertising master state while the
  dataplane remains permanently inactive.

There is no defensible aggregate cycle or memory saving to claim. Expected
steady-state performance change is zero for 12 workstreams and below measurement
noise for the flowless ICMP workstream. If reviewers conclude the perf gain is
too small to justify the churn, PLAN-KILL is an acceptable verdict. For this
batch, reviewers should instead kill any workstream whose reproduced correctness
impact does not justify its independent code and test surface.

## 4. What is already shipped or already owned

### 4.1 Work that composes with retained residuals

- #3171 / PR #3218 added globally admitted host-inbound ICMP error classes;
  #3292 / PR #3601 added flowless LocalDelivery gates. K003-01 is their missing
  composition.
- #5814 / PR #5981 added per-family DDNS previous-backend anchors and
  fingerprint checks for endpoint transitions. K003-03 must reuse those anchors,
  not create a third ownership mechanism.
- #4827 / PR #4853 established length-safe malformed-family-node handling in
  firewall compilers. K003-04 should use the same idiom.
- #4706 and #4818 established merge-not-replace semantics for related address
  book and security-zone containers. K003-06 extends that invariant one level up.
- #6464 added Rust fail-closed policy-scope preflight. K003-07 closes the Go
  commit-accept/runtime-reject split; it must not weaken the Rust backstop.
- #5701 / #5732 and their merged PRs added route-map and composed-chain sequence
  ceilings. K003-08 fixes their estimator rather than adding another ceiling.
- #5187 made load-set/load-merge replay atomic, and #3442 hardened flat command
  validation. K003-09 must reuse the same clone-then-swap and line-validation
  helpers.
- #4826 constrains RETH-derived VRIDs above RG 155. K003-10 is the independent
  userspace-shim capacity ceiling at RG 15.
- #4901 / PR #5003 retained routing ownership on `LinkDel` failure; #5495 / PR
  #5499 correctly distinguishes not-found from transient lookup failures for
  XFRM. K003-11 applies that established contract to bond and tunnel paths.
- #4897 / PR #4938 added SNMPv3 minimum-level enforcement for users that actually
  have keys. K003-13 closes the missing-key intent downgrade.
- #2513, #2593, and #4914 fixed lifecycle action semantics on other output
  surfaces. K003-14/K003-15 need one central semantic rule for all remaining
  formatters.

### 4.2 Existing owner, related doctrine, and rejected inputs

- K003-02 stays on open issue #6548. This research must not open a second issue
  or implementation PR for it. Before engineering, correct that issue's wording:
  `io.EOF` is the successful terminal-load terminator; `readline.ErrInterrupt`
  and every other read error abort and discard the partial body.
- K003-05 is related to, but not owned by, open umbrella #4313. That issue
  defines the per-subtree closed-world doctrine and explicitly delegates
  concrete domain gaps. K003-05 therefore gets its own child issue for
  fail-loud rejection of the unsupported shape. It does not get a vSRX-parity
  implementation because the official hierarchy does not define that syntax.
- K003-12 is closed as refuted in this plan. A synthetic TLS stall test may be
  useful generally, but it cannot be justified as a fix for an unbounded
  handshake that does not exist.
- K003-C is not an issue backlog. Recovering the original 128 entries with
  file/line evidence is a prerequisite to any future triage.

## 5. Concrete design

### 5.1 Multiple path options

#### Path A - evidence-led split into bounded workstreams (recommended)

Create one child issue and one implementation PR per retained root cause, except
that K003-14 and K003-15 remain one lifecycle-action workstream. Land independent
packages in parallel, but sequence changes that share compiler gates. Each child
issue carries the trace, invariants, exact tests, and its own rollback boundary.

Advantages:

- a logging semantic correction cannot hide a policy compiler regression;
- reviewers can reject a controversial compatibility choice without blocking
  the HA race or SNMP security fix;
- each fix can be reverted independently;
- smoke requirements match actual dataplane impact.

Cost: 13 issues and PRs, plus explicit merge ordering for the compiler slices.

#### Path B - one audit-batch PR

Implement all live findings in one branch. This minimizes issue bookkeeping but
mixes Rust packet-path behavior, Go parser/compiler rules, DDNS ownership,
netlink reconciliation, HA concurrency, SNMP security, FRR generation, and wire
format semantics. Review and rollback become unreliable. **Rejected.**

#### Path C - issue-only triage with no proposed implementation shape

Publish dispositions and ask later engineers to redesign each fix. This is safer
than Path B but fails the research contract: known cross-layer invariants would
be rediscovered repeatedly, and superficially local fixes can be wrong (notably
DDNS ownership, RG capacity, and lifecycle action semantics). **Rejected.**

### 5.2 Workstream A - isolate `vipWarnedIfaces` synchronization (K003-16)

Add a dedicated lock owned by the warning state, not by the direct-VIP lifecycle:

```go
type Daemon struct {
    // Existing directVIPMu remains responsible for direct VIP operations.
    vipWarningMu     sync.Mutex
    vipWarnedIfaces  map[string]struct{}
}

func (d *Daemon) resetVIPWarnings()
func (d *Daemon) markVIPWarning(iface string) (first bool)
func (d *Daemon) clearVIPWarning(iface string)
```

Every read, lazy initialization, write, delete, and reset must go through these
helpers. Do not reuse `directVIPMu`: existing callers already hold it and an
internal re-lock would deadlock. The helper's lock scope must not include
netlink, helper RPC, logging, or retry sleeps.

### 5.3 Workstream B - reject empty security identities before normalization (K003-07)

Add one AST-level validator on the apply-groups-expanded tree that runs before
typed normalization can erase empty list elements. It must detect:

- an empty `security-zone` definition;
- empty concrete `from-zone` and `to-zone` keys;
- an empty policy name;
- empty elements in global policy `match from-zone` / `to-zone` lists.

Remove `""` from `policyZoneSpecialTokens`; retain only meaningful tokens such
as `any` and `junos-host`. This class is an explicit exception to the normal
warning-only lenient doctrine: neither dropping a deny nor preserving a permit
after scope normalization is action-agnostic safe. The same validator therefore
returns an error on strict and tolerant compile paths.

- Strict commit/check rejects the candidate with a scope-qualified diagnostic.
- `Store.Load` retains the parsed tree for recovery but returns the existing
  compile-failed class, so daemon bring-up enters bootstrap/lifeline mode with
  no interface takeover and a fresh userspace helper remains default-deny.
- `Store.SyncApply` rejects atomically and retains the previous active/compiled
  snapshot; cluster state does not advance `lastAppliedConfigGen`, so the
  existing manual-transfer freshness gate remains false.

Do not rely on `sortDedupZones`, `Policy.LenientContentDropped`, or Rust
preflight for this root. The first removes the evidence, the second does not
cover every host-inbound actuator, and the third sees only the already-normalized
snapshot. A zone definition with an empty quoted name is semantic invalidity,
not malformed JSON structure; Workstream G must continue to accept the string
at the persistence boundary so this validator can report it precisely.

```go
func validateNonEmptySecurityIdentities(root *ConfigTree) error
```

Both compile paths call the same hard gate on the compiler's canonical
node-effective tree, so their accepted identity grammar cannot drift. Extract
only the existing pre-`compileExpanded` preparation shared by generic/local/peer
compiles: clone, strip inactive subtrees, and expand groups with `${node}`
substitution. Do **not** move interface-range expansion earlier: its current
position inside `runPreWalkGates` is observable through validator ordering,
first errors, and warning order.

Place B, C, and M plus I's explicit-binding syntax gate immediately after the
existing `expandInterfaceRanges(tree)` call in `runPreWalkGates`. Normal and
peer hard-gate compilation therefore see the same expanded members at the same
phase without duplicating the range algorithm or reordering any existing gate.

A strict operator-driven commit on a cluster must also prove the peer-effective
view. Add a focused peer compilation mode that runs the normal section
dispatcher and final typed lowering (therefore preserving repeated-root
replacement semantics), keeps unrelated historical tolerant validators at
their existing warning posture, but forces the B, C, I, and M gates to their
hard setting:

```go
type EffectiveHardGateResult struct {
    SNMPv3 SNMPv3IntentResult
}

func runEffectiveHardGates(
    view preparedCompileView,
    lenientSNMP bool,
) (EffectiveHardGateResult, error)
func compilePeerEffectiveHardGateView(
    tree *ConfigTree,
    peerNodeID int,
) (*Config, error)
```

`runEffectiveHardGates` owns the B, C, and M AST gates plus I's explicit-binding
syntax check. `compileConfigWithOpts` invokes it after `prepareCompileView` and
carries both the prepared view and its SNMP result into section lowering. B and M always return errors; C
returns a rejection result in lenient mode and an error in strict mode. I's
definition membership and repeated-root truth are checked on the final typed
`Config`, not by unioning raw chassis roots.

The config-store strict promotion path first compiles the local view normally,
then invokes `compilePeerEffectiveHardGateView` for the other node when
`localNodeID` is 0 or 1. The peer mode uses the same preparation, full
`runPreWalkGates`, section dispatch, derivations, and typed RG validation as
ordinary compilation.
Only these four action-agnostic gates are forced hard; unrelated tolerant
validators retain their current compatibility posture. A peer-only failure
names the effective node and rejects before promotion. Standalone node IDs are
a no-op. Fundamental parse/expansion/lowering errors still reject because no
meaningful effective peer config exists.

### 5.4 Workstream C - enforce SNMPv3 configured security intent (K003-13)

Configured intent must be validated on the canonical, node-effective AST
**before** `compileSNMPv3` lowers it. The typed `SNMPv3User` is too late: today
a password is copied only when nested under a recognized protocol node, so
legitimate noAuthNoPriv and malformed password-only syntax can collapse to the
same typed object.

Top-level `snmp v3 usm local-engine user` remains the canonical documented
form. Existing hierarchy is not dead: `compileSystem` accepts
`system { snmp { ... } }`, the shipped Incus config uses it, and the ordinary
`FormatSet` renderer emits `set system snmp ...` for that stored tree. Add
`snmp: schemaSNMP` under `schemaSystem` as a deprecated, fully typed alias so
the product can reload its own display-set artifact.

The parser AST contains no source-form provenance: a genuine hierarchical
`system { snmp { ... } }` container, a persisted copy, and flat
`set system snmp ...` replay all become the same `system/snmp` nodes. The
compiler therefore **accepts all three identically** and emits one nonsecret
deprecation warning. It must not claim that flat `set system snmp` can be
rejected while its own `FormatSet` output reloads. New documentation and
fixtures use top-level `snmp`, but compatibility input remains typed and live.

Normalization is a first-class compiler-preparation result, not a warning-side
effect or a synthetic node that section dispatch later forgets:

```go
type preparedCompileView struct {
    Root               *ConfigTree
    NormalizedSNMPRoot *Node
    SNMPSources         map[string][]SNMPSourceObservation
}

type SNMPSourceObservation struct {
    Identity string // community/trap/user semantic key
    Field    string // keyword only; never a secret value
    Path     string
    Present  bool
    Empty    bool
    Conflict bool // distinct values/selectors observed; values are not retained
}

func prepareCompileView(root *ConfigTree, opts compileOptions) (
    preparedCompileView,
    error,
)
```

`prepareCompileView` runs after inactive removal and apply-groups expansion.
It collects every top-level `snmp` root and every typed `system snmp` alias in
expanded source order, then performs a schema-aware **deep fold**. A plain
concatenation is forbidden because `compileSNMP` constructs a fresh
`SNMPConfig` and a later trap-group occurrence overwrites the prior map row.
The fold retains every source observation needed to reject malformed or
conflicting duplicates; a one-path/last-writer carrier is forbidden. Secret
values are compared in memory only long enough to set `Empty` or `Conflict`
and are never copied into observations, warnings, config projections, hashes,
or logs. The fold has these exact semantics:

- scalar `location`, `contact`, and `description` use the last explicit writer;
- `community <name>`, `trap-group <name>`, and
  `v3 ... user <name>` are keyed by their complete semantic identity and merge
  recursively;
- trap `targets` and `categories` form a stable de-duplicated union in
  first-appearance order;
- `clients <prefix> [restrict]` is a structured row, not a leaf-list. Parse and
  canonicalize the prefix, key by that canonical prefix, preserve first
  appearance, and resolve equal-prefix duplicates with `restrict=true`
  (deny) winning over unrestricted allow. An invalid prefix or extra child is
  retained as a rejecting observation rather than folded away;
- scalar properties inside a keyed object, including trap `version` and one
  selected auth/privacy protocol, use the last explicit writer only when that
  writer is structurally valid; and
- unknown or conflicting children are retained with their first source path so
  validation cannot erase a bad earlier occurrence.

Implement the generic portion by reusing the schema identity/leaf-list rules
behind `mergeNodes`, with later occurrences as the precedence side. Register
the schema-specific `clients` reducer above instead of routing it through the
generic leaf-list path; do not create a second complete SNMP keyword table.
Validate a complete trap group only after all occurrences are folded, so
targets in one occurrence and version or categories in another form one
object. The source observations supply stable, path-qualified diagnostics
without retaining secret values.

`runEffectiveHardGates`, SNMP intent validation, and section lowering all
receive the same `preparedCompileView`. Raw top-level `snmp` roots and
`system snmp` aliases are skipped by ordinary dispatch; `compileSNMP` is invoked
exactly once with `NormalizedSNMPRoot`. A canary rejects any second call or any
gate that re-walks a raw occurrence. This gives the validator and compiler one
authoritative object and makes `configured = installed + omitted` describe the
configuration that actually survives lowering.

The intent pass aggregates every normalized occurrence by identity without
copying secret values into diagnostics:

- a nonempty username with no authentication or privacy declaration is valid
  noAuthNoPriv;
- exactly one authentication protocol requires exactly one authentication
  password whose value is nonempty;
- exactly one privacy protocol requires an authentication protocol/password
  and exactly one nonempty privacy password;
- any password without its corresponding protocol is rejected;
- every child under a user, selected authentication protocol, or selected
  privacy protocol is closed-world; an unknown protocol or password keyword is
  rejected rather than ignored;
- an empty username is rejected because the empty wire username is reserved for
  engine discovery;
- distinct protocol selections or conflicting password declarations observed
  across repeated roots/aliases reject the identity even if a later writer
  would otherwise replace the lowered scalar. Flat reassignments already
  coalesced inside one `SetPath` node retain ordinary last-set semantics; this
  pass does not claim access to provenance already erased before preparation.

If any occurrence for a username is invalid or conflicts with another
occurrence, that username is rejected as a whole. Strict mode reports the first
stable path error. Lenient mode omits **all** occurrences of that username so a
valid duplicate cannot hide a malformed one.

```go
type SNMPv3UserRejection struct {
    Identity string // nonempty name, otherwise a stable path token
    Path     string
    Reason   string // field names only; never a secret value
}

type SNMPv3IntentResult struct {
    Rejected      []SNMPv3UserRejection
    rejectedNames map[string]struct{} // internal, non-serialized lookup
}

func validateSNMPv3Intent(
    view preparedCompileView,
    lenient bool,
) (SNMPv3IntentResult, error)
```

The dataflow is explicit, rather than hidden in a warning slice:

1. `prepareCompileView` returns the normalized root and source observations;
   `runEffectiveHardGates` consumes that exact view and returns the local
   `SNMPv3IntentResult` to `compileConfigWithOpts`.
2. The section dispatcher invokes `compileSNMP` once with
   `view.NormalizedSNMPRoot`; `compileSystem` does not lower its alias
   independently.
3. `compileSNMPv3` takes the rejected-name set and skips every
   rejected username without mutating the source AST.
4. After lowering, explicitly delete from `V3Users` every identity present in
   the compiler rejection set. Compiler rejection dominates every valid
   duplicate globally; an invalid occurrence can never be resurrected by a
   later valid occurrence.
5. The compiler attaches the
   stable, sorted, nonsecret slice to
   `SNMPConfig.RejectedV3Users` and appends the same reasons to
   `Config.Warnings`.
6. Both custom `SNMPConfig.MarshalJSON` and
   `MarshalYAML` projections include
   `RejectedV3Users`. The SNMP reconcile hash includes the sorted
   rejection metadata so a metadata-only transition cannot disappear behind
   the unchanged-hash shortcut.

Strict compile returns a path-qualified error and never lowers a rejected
username. Lenient persisted loading keeps the source tree for diagnosis and
lowers only valid users.

Runtime remains an independent belt, but there is one evaluator rather than a
boolean predicate and a second agent-only validator:

```go
type V3RuntimeRejection struct {
    Identity string
    Path     string
    Reason   string
}

type V3Evaluation struct {
    Installable map[string]*config.SNMPv3User
    Rejected    []V3RuntimeRejection
    Configured  int
    Installed   int
    Omitted     int
}

func EvaluateV3Users(cfg *config.SNMPConfig) V3Evaluation
func (a *Agent) deriveV3Users(eval V3Evaluation) map[string]*usmUser
```

`EvaluateV3Users` iterates sorted map keys and never dereferences a nil value.
The map key is the canonical identity; an embedded `user.Name` must be nonempty
and equal or the row is rejected. It implements the compiler's complete
credential matrix exactly:

- noAuthNoPriv is valid only when auth protocol/password and privacy
  protocol/password are all absent;
- authNoPriv is valid only with exactly one supported auth protocol and one
  nonempty auth password, with both privacy fields absent;
- an auth password without a protocol is rejected;
- authPriv is valid only with a valid authentication pair, exactly one
  supported privacy protocol, and one nonempty privacy password;
- a privacy password without a protocol is rejected;
- every partial auth/privacy combination is rejected as a whole and never
  downgraded to a lower security level; unsupported protocols, nil users,
  empty map keys, and key/name mismatch are rejected.

Compiler rejection has absolute precedence. Before evaluating typed users,
seed the rejection map from `SNMPConfig.RejectedV3Users`; an identity present
there is never installable even if a hand-built typed duplicate is valid.
Installed and rejected sets are disjoint by construction. Identity-less
structural errors key on a stable path token. Counts are computed from the
union, not by adding occurrence counts, so `Configured == Installed + Omitted`
always holds.

Runtime rejection metadata is unioned with
`SNMPConfig.RejectedV3Users` by stable identity (`Identity`, or `Path` when no
name exists), with deterministic sorted field-only reasons. One logical user is
counted once even if both belts reject it. `NewAgent` and `UpdateConfig` consume
the already-computed evaluation, localize only `Installable`, and swap the
config pointer, localized table, and rejection snapshot together under
`cfgMu`. Password-to-key localization is deterministic for a structurally valid
descriptor and cannot downgrade security intent.

Listener behavior and diagnostics are evaluated before lifecycle selection.
Boot and day-2 reconcile both call `EvaluateV3Users`, publish one structured
diagnostic containing exact configured/installed/omitted counts plus sorted
nonsecret identities, then choose start/update/stop from
`!isProcessDisabled(cfg, "snmpd") && (validCommunityCount > 0 ||
evaluation.Installed > 0)`. The existing administrative disable always wins;
normalization must not restart a disabled listener. Rejected-only input
therefore publishes its result even when no Agent exists and then stops or
declines UDP/161. The boot path and day-2 reconcile consume this same decision;
the daemon and Agent may not maintain another acceptance predicate. The
reconcile hash covers the normalized SNMP object, compiler rejection metadata,
the disabled-process decision, and every runtime-significant field.

Operational surfaces have explicit authority. Configuration displays remain a
configured-intent view; they iterate sorted map keys, use that key as the
display identity, skip nil values safely, and render compiler/runtime omissions
from the pure evaluation in a separate nonsecret section. Agent/runtime status
reports only installed identities plus the same rejection snapshot. Local CLI,
REST, and gRPC use `EvaluateV3Users`, so rejected-only state is visible without
a live Agent and no surface dereferences a malformed value. Do not infer
configured intent from derived key presence.

### 5.5 Workstream D - restore flowless ICMP global admission (K003-01)

Pass the already-parsed first ICMP byte to `host_inbound_gated_lo0_action` only
when L4 is present:

```rust
let host_inbound_icmp_type = if extra.l4_present {
    extra.icmp_type
} else {
    0
};
```

No parser or packet read is added. Non-first fragments retain zero and remain
fail-closed. The global accept is still limited by
`is_icmp_host_inbound_global_accept`; arbitrary ICMP types do not become
permitted.

### 5.6 Workstream E - bind DDNS withdrawal to record ownership (K003-03)

Fix the reproduced cross-family bug at its existing ownership boundary. Do not
add a credential-generation catalog in this workstream. The exported
`DNSUpdater` methods return one aggregate error even though RFC2136
can mutate the forward RR and then independently skip or fail the PTR
operation. Retrying a compound operation under another credential could erase
the only authority for one component. Credential-rotation fallback therefore
requires separate operation-result research and is not necessary to stop a v6
record from being deleted through v4.

Remove the production use of the single representative `m.updater` at the
family turn-off block and stop advancing it from whichever family happened to
resolve last. Preserve it only as the fixed updater used by the exported
constructor compatibility seam. `reconcileEnv` carries an explicit
`fixedUpdaterMode` bit (`m.newUpdater == nil`) so compatibility authority can
never leak into production factory mode.

Production factory mode is exactly `m.newUpdater != nil`; fixed-updater mode is
the existing constructor/test seam. Resolve the current updater and existing
`dhcpBackendFingerprint` independently for family 4 and family 6. Do not change
Surface-A wire behavior, `WireRRClaim`, HTTP-provider identity, or the exported
`DNSUpdater` contract in this workstream. Preserve the deliberate #6015
cross-surface ownership policy: Surface B may release a duplicate claim without
wire I/O, while Surface A retains and reasserts until B disappears.

Keep the existing `fpb1` fingerprint and its current semantics. This plan does
not claim that `fpb1` proves a global DNS namespace, credential generation, or
compound forward/PTR/DHCID authority. It is only the already-shipped guard that
binds one Surface-B durable row to one in-process family updater. Empty legacy
fingerprints remain governed by existing compatibility behavior; no durable
row or wire-claim schema changes.

The source defect is the representative-updater fallback at
`manager.go:907-921` and the pre-reconcile anchor rotation at `:933-938`.
Remove both. A backend-less family may use only its own retained pair from
`lastLiveUpdater[famIdx(family)]` and `lastLiveFP[famIdx(family)]`; the updater
must be non-nop and the stored nonempty `BackendFingerprint` must match. A
current live same-family updater is used only when its current fingerprint
matches the row. Otherwise the row stays owned and no DNS operation occurs.

Choose the delete updater for each owned row, not once for the family:

```go
func (e *reconcileEnv) updaterForOwnedWithdrawal(
    owned ownedRecord,
) (DNSUpdater, bool)
```

The two stores use the same JSON struct but have distinct authoritative paths.
Make that existing path boundary explicit without adding a disk field:

```go
type ownedRecordSurface uint8

const (
    ownedRecordSurfaceLease ownedRecordSurface = iota + 1
    ownedRecordSurfaceInterface
)

func loadDDNSState(path string, want ownedRecordSurface) (*ddnsState, error)
func loadStateOrDegrade(
    path string,
    want ownedRecordSurface,
    now func() time.Time,
) (*ddnsState, bool, string)
func validateOwnedRecordForSurface(r ownedRecord, want ownedRecordSurface) error
```

`NewProductionManager`/`NewManager` pass `ownedRecordSurfaceLease` for
`dhcp-ddns-state.json`; `NewSurfaceAManager` passes
`ownedRecordSurfaceInterface` for `interface-ddns-state.json`. Test constructors
do the same explicitly. A file is never auto-classified from an ambiguous row,
and no `surface` tag or durable version migration is introduced.

The exact legacy-compatible lease/Surface-B matrix is: family exactly 4 or 6;
nonempty parseable `Address` of that family; matching `A`/`AAAA`; nonempty
identity; `AddrText`, `PriorAddrText` empty and `PublishPending=false`; FQDN in
the stored form produced by `finalizeFQDN`/`buildLeaseRecord` (valid lowercase
DNS name with no trailing dot, **not** the trailing-dot form returned by
`dnsCanonicalFQDN`); exact PTR derived from `Address`; and an absent/zero scope
or a scope whose family is zero/the row family and whose `FQDN` axis is empty.
`PTRPending`, legacy empty `ClientID`/`BackendFingerprint`, and existing scope
transport axes remain valid.

The interface/Surface-A matrix is: `Identity == surfaceAIdentity`;
`Address`, `SubnetID`, `OwnerID`, `ClientID`, and `PTRName` empty;
`PTRPending=false`; nonempty parseable `AddrText` with matching family and
`A`/`AAAA`; a canonical lowercase/no-trailing-dot row FQDN; nonnil nonzero
scope whose family matches and whose raw operator FQDN satisfies
`surfaceAName(scope.FQDN) == row.FQDN`; and valid pending-state shape. Raw scope
FQDN equality is deliberately **not** required because existing valid scopes
preserve accepted uppercase and single-trailing-dot input while `buildHostRecord`
stores the canonical wire name in the row. `PriorAddrText` is empty when
`PublishPending=false`; when pending it is either empty or a parseable address
of the same family. Existing optional backend fingerprint and settled/pending
rows remain valid.

Any row outside its expected matrix makes the complete store corrupt and
engages the existing quarantine/degraded fail-closed path. Delete selection
repeats the Surface-B check before `famIdx` or DNS I/O so family 0/5 cannot
alias the IPv4 slot. This validation addition covers both stores only to avoid
misclassification; K003-03 otherwise changes no Surface-A reconcile behavior.

For each stale Surface-B row, order teardown exactly:

1. Validate the row against the lease matrix above.
2. Run the existing same-surface and lock-free cross-surface wire-RR co-owner
   check. If another claim exists, durably release only this Surface-B row and
   perform **zero** provider I/O. This claim-only release is safe with a nop or
   unavailable updater and is deliberately exempt from no-authority retention.
3. Only for the last claimant, select wire-delete authority using the rules
   below. No authority then retains the row and alarms.

The deterministic last-claimant authority selection is:

1. In production factory mode, if the current updater for `owned.Family` is
   live and its nonempty current `fpb1` equals
   `owned.BackendFingerprint`, use it.
2. Otherwise, if that family's previous-cycle updater is live and
   `prevFP` equals the nonempty owned fingerprint, use it. This is the
   normal disable, temporary factory-failure, and endpoint-transition cleanup
   path.
3. In fixed-updater mode, preserve the existing whole-store caller-attestation
   contract for valid empty-fingerprint test/embedding rows. A nonempty
   fingerprint is never authorized by fixed mode. The daemon uses
   `NewProductionManager`, so this cannot become a production fallback.
4. Otherwise return no authority. Keep the durable ownership row, increment the
   existing orphan/backend-mismatch alarm, and block republish of that identity
   for the pass.

Every production comparison is same-family and exact. An empty production
fingerprint is uncertainty, not permission. The code never substitutes another
family, a representative updater, or a merely non-nil backend.

The claim-release order is load-bearing: selecting authority first can retain a
co-owned Surface-B row forever after restart, while Surface A sees the B claim
and keeps reasserting it. The lock-free Surface-A claim snapshot remains the
existing #6015 mechanism; this workstream does not infer DNS-view identity from
configured server strings and does not attempt a new teardown election. The
research found real adjacent questions around endpoint aliases/anycast,
forward-versus-PTR/DHCID compound ownership, publication-versus-deletion races,
and stale lock-free snapshots. They need a separate protocol design with an
authoritative namespace identifier and crash-linearizable state machine; they
are not prerequisites for removing the reproduced cross-family fallback.

Anchor lifetime is post-reconcile, not pass-start rotation. Capture the old
updater/fingerprint pair before resolving the current endpoint and do not mutate
`lastLiveUpdater`/`lastLiveFP` until the complete pass ends. After reconcile,
scan the retained ownership rows for that family:

- if any row still carries the old nonempty fingerprint and it differs from
  the current fingerprint, keep the old pair unchanged for the next retry;
- otherwise, install the live current updater and nonempty fingerprint in
  lockstep;
- if no current endpoint exists and no retained row depends on the old pair,
  clear both slots in lockstep.

Therefore A -> B followed by a successful forward delete and failed PTR delete
retains A across later cycles. The next pass again selects A; only after the
owned A row is fully deleted may B become the retained anchor. A third endpoint
rotation while an older row still depends on A is alarmed and retained rather
than guessed: the bounded one-old-anchor design does not claim automatic
cleanup across multiple unresolved credential generations.

There is deliberately no automatic second-credential retry. Any error surfaced
by the selected updater, including a simulated partial forward/PTR failure,
retains the owned row and returns through the existing retry/alarm path. The
workstream does not redefine the RFC2136 backend's established policy for PTR
NOTAUTH/REFUSED skips; it makes no new per-component authority claim. A later
reconcile may use a newly current same-family updater if its delete-authority
fingerprint still matches. This bounded behavior fixes K003-03 without
inventing component authority that the current backend API cannot report.

For a **last-claimant** row, the no-authority branch never writes DNS, changes a
fingerprint, drops ownership, or increments success. It preserves the existing
`errDDNSNoBackendToWithdraw`/backend-mismatch observability classes and lets
unrelated rows reconcile. Restart after the operator removed the only
production backend cannot reconstruct historical credentials; it retains and
alarms. Claim-only co-owner release remains the sole exception. No secret,
credential-generation catalog, durable format, claim format, or public
constructor change is introduced.

### 5.7 Workstream F - make `LoadOverride` format handling explicit and atomic (K003-09)

Use constrained F1 and remove F2 as an implementation choice. `LoadOverride`
already promises a complete flat `set` artifact, so honor that contract without
pretending an edit transaction against an empty tree is a full configuration.

The classifier lexes comments and quoted strings before classifying, then scans
every significant line before mutation. Inline `#` or `//` comments and one
optional trailing semicolon use the existing `ParseSetVerb` contract. A
terminated block comment is valid hierarchical/comment-only syntax; an
unterminated block comment is always an error. Flat replay remains one command
per physical line and rejects any block comment mixed with flat commands.

1. Empty, whitespace-only, or lexically valid comment-only input keeps each
   current caller's behavior. Store, REST, and gRPC may continue to represent
   an empty replacement tree. The local terminal CLI is unchanged by this
   workstream; its partial-body handling on `readline.ErrInterrupt` and other
   non-EOF errors remains owned exclusively by #6548. K003-09 neither claims
   nor tests terminal interrupt safety.
2. If any line begins with a recognized flat verb, every significant line must
   begin with a recognized flat verb. A typo such as `sett` is an unrecognized
   flat verb at that line, not an implicit bare `set` path and not hierarchical
   fallback.
3. Otherwise parse as hierarchy on a detached tree and validate every top-level
   node against a helper derived from the existing `setSchema` SSOT. Do not
   maintain a second root-name list. An unknown `systm { ... }` root fails even
   though it has braces. A schema container root must have actual structural
   container shape; packed brace-less input such as `system host-name fw;`
   cannot masquerade as a hierarchy. Schema leaf roots that are legitimately
   top-level remain accepted without invented braces.
4. Flat override accepts only `set` and `deactivate`. Reject `delete` and
   `activate` with a line-numbered diagnostic directing the caller to
   `load set` or `load merge`; those are edit verbs with no unambiguous meaning
   against a fresh replacement tree.
5. Apply all `set` lines to a detached empty `ConfigTree`, then apply
   `deactivate` lines so a canonical `show | display set` artifact is
   order-independent. A missing deactivate target rejects the complete load.
   Comments-only/empty input produces a valid empty tree only after the caller's
   existing entrypoint contract admits it.
6. A flat/hierarchical mixture is an error at the first conflicting line.

```go
func classifyOverride(content string) (overrideFormat, []flatOverrideLine, error)
func parseFlatOverride(lines []flatOverrideLine) (*config.ConfigTree, error)
func parseHierarchicalOverride(content string) (*config.ConfigTree, error)
func ValidateOverrideTopLevelShape(tree *ConfigTree) error // package config
```

Only after complete parse/replay succeeds does `LoadOverrideAs` swap the
candidate and update generation/dirty/lease state. Every error leaves candidate
bytes, generation, dirty state, lock owner, and lease deadline unchanged. The
Store parser returns one stable class for nonempty unknown-root, typoed-verb,
and mixed-format input. Entry-point tests pin Store, REST, gRPC, and successful
non-interrupted local loads only. No file in `pkg/cli` is in the implementation
write scope, and terminal read-error parity remains deferred to #6548.

### 5.8 Workstream G - validate persisted AST shape and retain compiler belts (K003-04)

Apply the established #4827 compiler idiom:

```go
afName := afNode.Name() // safe for empty Keys
if len(afNode.Keys) >= 2 {
    afName = afNode.Keys[1]
}
```

The compiler guard is defense in depth, not the primary persisted-data contract.
Immediately after JSON unmarshal, recursively validate the actual persistence
shape:

- the `*ConfigTree` is non-nil (an empty object with no children remains valid);
- every descendant pointer in `Children` is non-nil;
- every descendant `Node` has `len(Keys) > 0`;
- every child recursively satisfies the same rules.

Do **not** require `Keys[0] != ""`: a quoted empty key is structurally valid AST
data whose semantic rejection belongs to Workstream B and other strict schema
gates. A single validator is called from `DB.readTreeMeta`, so active,
candidate, and JSON rollback-slot readers cannot drift. `DB.ReadConfirm` calls
the same validator immediately after it proves `PrevTree != nil` and before it
returns the record; that nested rollback tree is also authoritative persisted
AST and is compiled by `recoverPendingConfirmLocked`.

An active-tree structural violation is surfaced through the existing
`ErrConfigDBUnreadable` load classification. Daemon bring-up refuses startup
and refuses overwrite of `active.json`; it does not enter compile-failed
bootstrap/lifeline mode. Candidate/rollback readers return a path-qualified
validation error.

This bounded workstream changes no `confirm.json` field, guarded hash, rollback
target classification, timer ordering, or confirmed-commit API. It only rejects
a structurally malformed nonnil `PrevTree` at the existing read boundary. The
round-six review proved the wider concerns require a separate crash-consistent
multi-file transaction design: current active hashing is based on
`tree.Format()`, not canonical JSON, and an active/confirm ordering change must
specify old-reader compatibility and every power-loss point. That research is
recorded in Section 10 rather than hidden inside this malformed-AST fix.

```go
func ValidatePersistedTreeShape(tree *ConfigTree) error
```

Peer HA sync is out of this trace because it reparses text and cannot create an
empty-key node. Add the same safe-`Name()` belt at both known reachable
indices: interface family lowering and sampling/service family lowering. Audit
the remainder of persisted-JSON compiler entry points for unguarded
`Keys[n]` reads, but do not turn this workstream into a parser rewrite.

### 5.9 Workstream H - share exact route-map expansion cardinality (K003-08)

The guard and renderer must use one family expansion owned by `pkg/config`.
Move the current `prefixListFamilies` classification there and make `pkg/frr`
consume it. For each `from prefix-list` name,
the count contributes one reference for v4-only, v6-only, nil/undefined, or
empty lists and two for a mixed-family list. Sum those expanded references
before multiplying the other OR dimensions and route-filter family split.

```go
type PrefixListFamily uint8

const (
    PrefixListIPv4 PrefixListFamily = iota + 1
    PrefixListIPv6
)

const MaxRouteMapTermSequences = 65535/10 - 1

func PrefixListFamilies(pl *PrefixList) []PrefixListFamily
func RouteMapTermSequenceCount(
    po *PolicyOptionsConfig,
    ps *PolicyStatement,
) uint64
func ComposedRouteMapTermSequenceCount(
    po *PolicyOptionsConfig,
    chain []string,
) uint64
func RouteMapHighestSequence(termCount uint64) uint64
func RouteMapSequenceFits(termCount uint64) bool
```

The two count functions return only emitted term sequences. The composed count
stops after the first member with an explicit policy default, exactly where the
renderer stops. Every rendered single or composed map then emits exactly one
terminating/default sequence. `RouteMapHighestSequence` is the saturated value
`10 * (termCount + 1)` and `RouteMapSequenceFits` compares that value with
65535. This separates cardinality from the reserved terminal row instead of
pretending the default is a term.

Replace the existing exported helpers rather than retaining an estimate under
an exact-sounding name. Repository search shows every caller is internal: the
single-policy strict gate, composed-chain strict gate, single-policy FRR belt,
composed-chain FRR belt, and tests. Migrate all of them in the same PR. No safety
caller may use a context-free wrapper or compare a raw count directly with a
separately derived maximum. Saturating arithmetic, undefined/empty-list
single-family fallback, prefix-list family expansion, chain termination, and
the one terminal reservation must be shared by gate and renderer.

### 5.10 Workstream I - align accepted RG IDs with dataplane capacity (K003-10)

Do not contract the control-plane RG domain. Chassis definitions remain
canonical decimal IDs 0..255, with at most 255 groups, matching heartbeat
fields, current strict validation, boundary tests, session-sync enumeration,
and Rust's `BTreeMap` HA state. The 16-entry BPF `rg_active`/`ha_watchdog` maps
are a **dataplane owner-binding** limit, not a definition limit. A definition
above 15 remains legal for control/election/session-sync uses that do not bind a
userspace forwarding interface.

Binding semantics are narrower: value zero is the Go/BPF/Rust unbound or
standalone sentinel, so an explicit interface/RETH dataplane owner binding is
valid only in 1..15 and must reference a definition in the same node-effective
tree. This closes the live defect without rejecting legal unbound RG16..255 or
rewriting the documented session-sync behavior.

Validate raw identities on both local and peer effective trees after group and
interface-range expansion. Use one strict canonical-decimal parser rather than
`Atoi` fallback: definition names must parse and round-trip in 0..255, and
per-RG `node` identities must be exactly 0 or 1. Nonnumeric, signed,
overflowing, and aliasing forms cannot lower to RG0/node0. This gate is hard in
strict and tolerant modes because aliasing election identities is never a safe
compatibility warning.

At the same phase, validate every explicit dataplane binding before typed
lowering can collapse zero into "not configured." Reject malformed, zero, and
above-15 bindings. Then validate final binding range and membership on the
fully lowered typed `Config`; this honors repeated-`chassis` replacement
semantics rather than unioning definitions from discarded roots. Definition
zero remains legal for control election/monitoring and is never emitted as a
dataplane owner.

```go
const MaxHeartbeatRedundancyGroupID = 255 // existing control definition limit
const MaxDataplaneRedundancyGroups = 16  // owner slots 0..15

func ValidateDataplaneRGBindingID(id int) error    // 1..15
func validateCanonicalRGIdentities(root *ConfigTree) error // defs 0..255, nodes 0/1
func validateDataplaneRGBindingSyntax(root *ConfigTree) error
func ValidateDataplaneRGTyped(cfg *Config) error
```

`pkg/dataplane.MaxRedundancyGroups` remains the owner-slot alias. Source/ABI
canaries prove its equality with BPF `MAX_REDUNDANCY_GROUPS`, shim map specs,
and Rust `MAX_RG_EPOCHS`; they do **not** equate it with the 255 control-ID
limit. Supporting independent dataplane ownership for RG16..255 remains a
separately researched pinned-map/protocol migration.

This is an action-agnostic semantic safety error, not a class-II capability.
The identity and binding syntax halves participate in `runEffectiveHardGates`;
the typed membership half runs after section dispatch/derivation on local and
peer hard-gate compiles. A peer-only malformed definition, overflowing node,
RG16 **binding**, explicit binding zero, orphan binding,
interface-range-inherited binding, or binding resolved against replaced
chassis roots receives the same verdict as the published config. A legal
unbound RG16..255 remains accepted. Do **not** set
`ForwardingSupported=false`: that value actively disarms a running helper and
cannot mean "reject this generation and retain previous-good."

- `Store.Load` keeps the parsed source for diagnosis but returns the existing
  compile-failed classification only when an invalid dataplane binding or
  malformed identity exists; a fresh boot stays lifeline/default-deny.
- `Store.SyncApply` rejects atomically, leaves `lastAppliedConfigGen` unchanged,
  and retains byte-identical active/compiled state and helper maps.
- A later valid generation compiles and applies normally; there is no sticky
  quarantine bit.

Runtime belts use one **bound owner inventory**, not the full control-plane
definition list. Build the set from final typed forwarding interfaces (including
RETH-derived bindings) whose `RedundancyGroup` is 1..15, and require each value
to name a definition. `seedHAGroupInventoryLocked`, map read/merge, watchdog
updates, `UpdateRGActive`, helper `update_ha_state` requests, readiness checks,
shutdown fencing, and any fixed-array/map key all consume that same set. Legal
unbound definitions above 15 remain visible to control/election/session-sync
status but never reach a 16-slot actuator. Every write-side belt validates range
and inventory membership before BPF, in-memory, or helper mutation.

Pinned owner slots are state, not empty storage. Diff the previous bound-owner
inventory against the new one before any map replay:

- every removed slot is cleared before it leaves the inventory;
- every newly introduced slot is cleared before it becomes readable or
  publishable; on process start the previous inventory is empty, so every bound
  slot is introduced and stale pins from an earlier configuration are fenced;
- unchanged bound slots may retain reconciled state.

`clearHAOwnerSlotFailClosed` writes `rg_active[id]=0` first, then
`ha_watchdog[id]=0`, then publishes the same inactive/unarmed state to a running
helper. The new snapshot/inventory is not published until all required clears
succeed. If any enforcement authority cannot be proved inactive, stop/disarm
the helper and retain retry debt rather than replaying the pin; the apply
returns degraded/fail-closed. A valid transition that encounters I/O failure
may therefore leave an affected previous-good RG deliberately fenced, never
stale-active. Typed-validation rejection still occurs before this transition
and remains mutation-free.

`userspace.Manager.Compile` calls `config.ValidateDataplaneRGTyped(cfg)`
immediately after nil/input checks and before pin deletion, shim
selection/compile, generation changes, attachment sync, inventory mutation,
maps, or helper RPC. Lower compilers do likewise. Diagnostics distinguish
control definition range, dataplane binding range/membership, heartbeat uint8,
and RETH-derived VRID limits.

Mixed-version behavior follows existing failover doctrine rather than inventing
a config-sync ACK. An upgraded standby rejects an old-primary RG16+ **binding**,
keeps previous-good, marks config stale/degraded, and blocks manual transfer.
Automatic peer-loss takeover remains available with previous-good forwarding
and a prominent stale-config alarm; this plan does not turn a control-plane
version mismatch into a total failover outage. Fresh boot with only the invalid
config remains lifeline/default-deny.

Before either node in a rolling upgrade is changed, freeze configuration and
select the operator/deployment system's authoritative unredacted source
artifact. A redacted `show configuration` export is forbidden because
`check-config` correctly rejects its secret placeholders. If the source of
truth or its freshness cannot be established operationally, the rolling
upgrade blocks rather than pretending a stale `/etc/xpf/xpf.conf` is current.
Record one SHA-256 of the selected bytes and run both effective views against
those exact same bytes:

```text
xpfd check-config -node-id 0 <temp-file>
xpfd check-config -node-id 1 <temp-file>
```

Exit 0 on both views permits rollout; exit 2 on either blocks it with the exact
offending binding. Other exit codes are operational failures and also block.
`xpfd check-config` validates file content only: it does not read daemon/DB
state and **does not prove freshness**. Release notes state that limitation and
assign source-of-truth selection/config freeze to the operator; no test claims
that a stale but valid substitute can be detected. Manual `/engineer 6744`
approval signs off this fail-safe operational restriction; it does not approve
reducing legal unbound definitions.

Session install and config apply share one linearization gate rather than
independent atomics:

```go
type configInstallGate struct {
    mu              sync.Mutex
    cond            *sync.Cond
    protected       bool
    baselinePending bool
    applying        bool
    acceptedEpoch   uint64
    inFlight        uint64
    debtGeneration  uint64
    completedDebt   uint64
    requestedDebt   uint64
    requestInFlight bool
    awaitingBulk    bool
}
```

The daemon sets `protected` from the actual config-authority direction before
session sync starts and before role transitions expose traffic; it is not
inferred from a racy `lastRecvConfigGen != 0` observation. The active/active
inverse direction is explicitly unprotected and retains its documented frozen
nonzero-epoch admission.

`beginSessionInstall(epoch)` runs before bulk membership and before the per-key
generation guard. Under the gate mutex it rejects and increments recovery debt
when `applying`, when a protected reconnect is awaiting a baseline, or when a
protected nonzero epoch differs from `acceptedEpoch`; otherwise it increments
`inFlight`. `endSessionInstall` decrements and signals the condition after the
dataplane operation and generation bookkeeping finish. Legacy epoch zero is
admitted only after a protected baseline exists and while no apply is active.
Rejected frames consume neither per-key generation nor authoritative-bulk
membership.

`beginConfigApply(gen)` closes the gate, sets `applying`, and waits for
`inFlight==0` before `OnConfigReceived` may sweep or publish policy. No existing
session, bulk, config-queue, or dataplane lock is held while waiting. The gate
mutex is released during callback/helper I/O but remains logically closed. A
successful callback publishes `acceptedEpoch=gen`, clears `baselinePending`,
then reopens; failure retains the previous epoch and reopens only for matching
previous-good traffic. Thus an install linearizes wholly before the sweep or is
refused after gate closure; it cannot pass a check and land after the sweep.

Split `resetRecvGen`: BulkStart resets only per-key session generations and
full-set sequence state. It never clears config authority, accepted epoch,
apply state, or recovery debt. A full both-fabric disconnect in the protected
direction sets `baselinePending` and closes new installs. The first successful
post-reconnect config may establish a lower rebooted-peer generation as a new
baseline; bulk frames that race ahead are refused and create repair debt. The
unprotected active/active inverse does not wait for a config it never receives.

An authoritative outbound bulk has an exact session-data barrier. Under
`bulkSendMu`, set a producer gate so new session install/delete frames append to
a bounded deferred journal, enqueue an in-band barrier token to `sendCh`, and
wait until the send loop has written every pre-barrier session frame. Then take
the session snapshot and directly write BulkStart, snapshot rows, and BulkEnd.
Control/config/heartbeat frames may interleave because the receiver never adds
them to the session set. After BulkEnd, release deferred session deltas to
`sendCh` in original order and reopen producers. Overflow or write failure
retains/journals deletes, arms `forceResync`, and never reports the bulk
complete. This prevents a delayed ordinary incremental from entering the
authoritative window while preserving post-snapshot churn after BulkEnd.

On receive, add a key to `bulkRecvV4/V6` only after its install passes the
config gate and succeeds. A malformed or refused session marks that bulk
invalid. Matching BulkEnd for an invalid bulk performs no stale-session
reconcile, sends no success ACK, does not release readiness, and cannot clear
recovery debt; it schedules another repair after an acceptable config
baseline. A valid matching BulkEnd is the only recovery completion event.

Refused protected installs increment `debtGeneration`. Add
`syncMsgBulkRequest = 29`, an additive length-zero request. After a successful
protected config apply (and again after reconnect), atomically claim the latest
uncompleted debt generation, mark `requestInFlight`, and write outside the gate
mutex. Nil connection, short/failed write, or disconnect clears in-flight state
but leaves debt armed. A successful write moves the token to `awaitingBulk`;
only a valid matching BulkEnd advances `completedDebt` through that token. If a
new refusal increments debt during request or bulk, completion leaves the newer
generation pending and emits another request. A new sender coalesces requests
through the existing pre-bulk `forceResync` CAS; a request arriving during a
bulk survives for the next bulk. An older peer ignores type 29, so debt and
manual-transfer unready state remain visible rather than being falsely cleared.

### 5.11 Workstream J - merge repeated global address-book containers (K003-06)

Initialize `sec.AddressBook` once, iterate every top-level `address-book` child
and every nested `global` child, and merge through one deterministic helper:

```go
func ensureGlobalAddressBook(sec *SecurityConfig) *AddressBook
func compileGlobalAddressBooks(nodes []*Node, sec *SecurityConfig) error
```

Mandate the existing `parseAddressBookEntries` contract: repeated blocks form a
union by object name; same-name address fields merge through `mergeAddressNode`;
and address-set members are de-duplicated while preserving first-seen source
order. The outer-container fix must not replace the accumulated book or invent a
new duplicate-resolution rule.

### 5.12 Workstream K - retain routing ownership on transient lookup errors (K003-11)

Use the package's established error classifier:

```go
link, err := ops.LinkByName(name)
switch {
case err == nil:
    // delete and forget only after success
case isLinkNotFound(err):
    // already absent: forget ownership
default:
    // transient/unknown: retain ownership and return/aggregate err
}
```

For tunnel `Clear`, only names proved absent or successfully deleted leave
`ownedNames`; failed names remain retryable. For bond removal, do not delete the
tracking row before successful deletion or genuine absence.

### 5.13 Workstream L - centralize lifecycle action applicability (K003-14/K003-15)

Define one semantic predicate at the decoded-event boundary:

```go
func eventHasForwardingAction(eventType uint8) bool
func normalizedEventAction(eventType, wireAction uint8) (
    name string,
    binary uint8,
    applicable bool,
)
```

`eventHasForwardingAction` is a positive exhaustive allowlist of current event
protocol constants: `POLICY_DENY`, `SCREEN_DROP`, and `FILTER_LOG`. Unknown
future event types default to not-applicable until their producer and every
surface are reviewed. Do not implement a negative SESSION_OPEN/CLOSE list that
silently treats a future lifecycle/alarm event's zero byte as deny.

SESSION_OPEN and SESSION_CLOSE have no forwarding action. Normalize both to
`name="n/a"`, `binary=0xff`, and `applicable=false` at both EventRecord decode
entry points **before** either path derives `actionStr` or emits
`slog`. Every formatter receives normalized applicability; no caller
may reconstruct an action from the raw wire byte. The surface contract is
explicit:

| Surface | Lifecycle action contract |
|---|---|
| Daemon generic `slog` | omit the action attribute |
| Standard and structured syslog | omit the action attribute |
| Flow trace text | omit `action=` |
| SSE text (`formatLogMessage`) | omit `action=` |
| Local CLI human text | omit the action column/token as it does today |
| Remote CLI / monitor human text | omit the action column/token |
| REST JSON | retain required scalar field as `"n/a"` |
| SSE structured JSON | retain required scalar field as `"n/a"` |
| gRPC/protobuf | retain existing scalar field as `"n/a"` |
| Binary log | encode `0xff` for OPEN and CLOSE |

Event filtering uses normalized applicability: `action=deny` excludes
lifecycle records and `action=n/a` selects them. POLICY_DENY,
FILTER_LOG, and SCREEN_DROP retain their existing decoded action and severity;
each formatter also retains its existing intentional omissions, such as
SCREEN_DROP flow trace not printing action. The invariant is "never fabricate a
decision and never regress an existing real-decision surface," not "every
formatter must print every applicable action." Cover the live ring path and
decode-only path so daemon slog, trace, event buffer, both SSE renderers, APIs,
CLIs, filters, and binary cannot diverge. Do not change the Rust event-stream
wire layout or the intentional producer byte zero.

### 5.14 Workstream M - reject unsupported nested zone-policy containers (K003-05)

Add an AST-shape gate after inactive stripping and apply-groups expansion but
before `compilePolicies` can silently skip an unrecognized container. For every
direct `security policies from-zone` child, the gate accepts only the
current canonical representation with exact keys
`["from-zone", <src>, "to-zone", <dst>]`, emitted by both the
hierarchy parser and current schema-aware `SetPath`.

Repository history and checked persistence fixtures contain no authentic
pre-schema nested chain. The permissive `compilePolicies` fallback is
dead compatibility code, not evidence of a supported persisted format. Remove
that branch in the same workstream; an implementation-created fixture cannot
retroactively establish compatibility.

A hierarchical `from-zone <src> { to-zone <dst> { ... } }`, a partial combined
key tuple, or a malformed flat chain is rejected with a path-qualified message
that shows the supported combined syntax. Do not reinterpret or lower the
unsupported hierarchy: Junos/vSRX does not document it, and accepting an
approximation would turn an honesty fix into invented compatibility.

```go
func validateSecurityPolicyContainerShapes(root *ConfigTree) error
```

This is another action-agnostic fail-closed exception to tolerant warnings. A
silently omitted nested deny under `default-policy permit-all` is a concrete
scope widening, while silently omitted permit rules cause an unexplained
outage. Strict and tolerant compile therefore return an error. `Store.Load`
keeps the source tree for recovery but returns the existing compile-failed
classification so boot stays in lifeline/default-deny without interface
takeover. `Store.SyncApply` rejects the peer generation and retains the exact
previous active and compiled snapshots. Workstream M links to #4313 for the
closed-world doctrine but has its own child issue and rollback boundary. It is
also included in the both-node-effective strict preflight from Workstream B, so
a peer-only unsupported container cannot pass the primary commit.

### 5.15 Recommended issue and merge waves

After manual `/engineer 6744` approval, create child issues first so each PR has
one owner and close condition.

| Wave | Parallel workstreams | Reason |
|---|---|---|
| 1 | A (VIP race), C (SNMP intent), D (flowless ICMP), E (DDNS ownership) | Highest security/availability value; disjoint packages and files |
| 2a | B (empty identities), G (persisted AST bounds), J (address book), M (nested policy shape) | Shared `pkg/config` surface; implement in separate worktrees but merge/rebase serially and rerun all config tests after each |
| 2b | F (LoadOverride), H (route-map count), I (RG capacity) | Mostly independent, but H/I consume config APIs and must rebase after 2a |
| 3 | K (routing ownership), L (lifecycle action) | Independent correctness/observability work with lower immediate blast radius |

K003-02 remains with #6548. K003-05 gets a child issue linked to #4313 but does
not claim vSRX parity. K003-12 and K003-C create no child issue.

## 6. Public API preservation

The implementation plan preserves these signatures and wire contracts:

- `(*configstore.Store).LoadOverride(string) error`
- `(*configstore.Store).LoadOverrideAs(string, string) error`
- existing CLI, REST, and gRPC load request/response shapes;
- DDNS `Updater`, manager constructor, and reconcile entry points;
- daemon direct-VIP and apply entry points;
- SNMP configuration field names and SNMPv3 wire protocol;
- route manager public methods and netlink operation interfaces;
- Rust event-stream record layout and event action byte;
- binary event record length and field offsets;
- BPF pinned map specifications and helper protocol in the recommended RG path;
- the HA wire protocol gains only the additive, ignorable
  `syncMsgBulkRequest`; no existing message changes shape or meaning;
- route-map helpers intentionally become the context-aware term-count and
  highest-sequence/fit APIs in Workstream H; all repository callers migrate
  atomically because a context-free exact count is impossible.

Workstream G adds no recovery API and changes no `confirm.json` field. Its
validator also checks the existing nested `PrevTree` at `ReadConfirm`; all
belts are internal. Workstream E changes only internal surface validation,
per-family updater selection, claim-release order, and anchor lifetime;
`ownedRecord`, `WireRRClaim`, the exported updater contract, and exported
constructor signatures remain unchanged.
Workstream C adds an internal `preparedCompileView` so validation and lowering
consume one normalized SNMP root; it is not an API or wire type.

Intentional behavior changes are fail-loud validation, not API removal:

- malformed empty security identities stop committing;
- unsupported nested policy containers stop committing under a child issue
  linked to #4313;
- RG definitions remain 0..255; malformed identities, explicit dataplane
  bindings outside 1..15, and bindings to undefined groups stop committing;
- mixed-format override input is rejected atomically;
- invalid SNMPv3 credential combinations stop installing a downgraded user and
  add nonsecret rejection metadata to existing config projections;
- hierarchical, persisted, and flat-set `system snmp` forms normalize
  identically with a deprecation warning because the AST cannot distinguish
  their source provenance; canonical documentation remains top-level `snmp`;
- lifecycle APIs stop calling a non-applicable action `deny` and return the
  existing string field as `"n/a"`.

## 7. Hidden invariants the changes must preserve

1. **Commit/apply equivalence:** anything accepted by strict Go compilation must
   be representable by Rust snapshot hydration. Lenient persisted/HA input may
   warn and quarantine, but it must not panic, widen scope, or install stale
   permissive state as if apply succeeded.
2. **Fail-closed without false deny:** unreadable ICMP fragments remain denied;
   readable ICMP errors in the established global class remain admitted.
3. **DDNS cleanup authority:** a Surface-B production delete uses only a live
   current or retained previous updater for the exact family whose nonempty
   current `fpb1` equals the owned row's fingerprint. The old family anchor
   remains live while a retained row depends on it. Fixed-constructor mode may
   act only on complete valid empty-fingerprint rows under its existing
   whole-store caller-attestation contract. Expected-surface validation runs at
   each store load. Existing #6015 claim-only release runs before delete
   authority and is permitted without an updater; only the last claimant needs
   authority. There is no cross-family, representative-updater, or
   second-credential fallback. On last-claimant uncertainty or any delete
   error, retain ownership, count failure, return error, and alarm.
4. **Atomic config load:** parsing/replay happens on a detached tree. On any
   error, candidate bytes, generation, dirty bit, lock lease, and active config
   remain unchanged.
5. **Persisted AST integrity:** an invalid JSON node tree is rejected by
   `readTreeMeta` for active, candidate, and JSON rollback slots and cannot
   reach an unsafe compiler walk. `ReadConfirm` applies the same shape check to
   its nonnil `PrevTree` before recovery can compile it. Local interface and
   sampling indexing belts remain safe. Confirm transaction/hash semantics are
   otherwise unchanged pending their own crash-consistency research.
6. **Route-map guard equals renderer:** term count includes every family
   expansion, OR-product dimension, and reachable composed-chain member, while
   the shared highest-sequence/fit helper reserves exactly one terminal row.
   Both layers preserve saturating arithmetic.
7. **HA capacity consistency:** control definitions fit canonical IDs 0..255;
   explicit dataplane bindings fit 1..15 and reference a definition in both
   node-effective views. Only groups present in the final typed bound-owner
   inventory reach fixed-slot BPF/helper paths. The 16-slot limit is never
   presented as the heartbeat/session-sync definition limit. A binding error
   occurs before any snapshot or actuator mutation and never reuses
   `ForwardingSupported=false`. Removed and newly introduced bound slots are
   inactive/unarmed in BPF and helper state before the new inventory publishes;
   an uncertain clear disarms the helper rather than replaying stale pins.
8. **HA ordering:** an invalid live sync leaves active config, compiled config,
   helper maps, forwarding arm state, and applied-generation high-water
   unchanged. Fresh boot remains lifeline/default-deny. A mixed-version RG16+
   binding loudly blocks manual transfer while automatic peer-loss takeover may
   use previous-good with a stale alarm. Legal unbound RG16..255 remains
   accepted. In the explicitly protected config-authority-to-receiver
   direction, the shared install/apply gate admits sessions only outside apply,
   after reconnect baseline, and at the accepted epoch before per-key ordering.
   Apply waits for admitted installs to finish before its policy sweep. The
   explicitly unprotected active/active inverse retains its documented
   admission. BulkStart cannot reset config authority; invalid bulks cannot
   reconcile stale sessions or discharge generation-tracked repair debt.
9. **No lock-order expansion:** VIP warning-state helpers take only their own
   short-lived mutex and are never called while attempting to acquire
   `directVIPMu` internally.
10. **Routing ownership truth:** a tracked object is forgotten only after
    successful deletion or positive not-found classification. Transient errors
    remain retryable.
11. **Lifecycle action semantics:** absence of a forwarding action is not deny.
    Real deny/reject/drop records retain their decoded action and every
    formatter preserves its established real-action behavior; intentional
    per-surface omissions are not broadened.
12. **Wire and pinned-state portability:** no event ABI, helper protocol, BPF
    map size, or pinned-map migration is introduced. The sole HA wire addition
    is an ignorable zero-length resync request; older peers keep parsing all
    existing traffic and may omit only the requested continuity repair.
13. **Allocation and hot-path shape:** K003-01 uses existing parsed metadata;
    none of the other workstreams add packet-path allocation or shared-state
    contention.
14. **Determinism:** strict validation and duplicate diagnostics remain stable
   across map iteration order, repeated blocks, and HA replay.
15. **Both-node commit safety:** action-agnostic security identity, SNMP, RG,
    and policy-shape hard gates run on both canonically prepared node-effective
    trees before an operator commit is promoted. RG membership is checked on
    each final typed config, including interface-range and repeated-root
    semantics.
16. **Tolerant-path safety classes:** legacy semantic violations normally warn,
    but empty security identities, unsupported policy containers, malformed RG
    identities, out-of-range dataplane bindings, or bindings to undefined
    groups return the existing compile-failed class and enter
    lifeline/retain-previous behavior. Genuine hierarchical legacy SNMP is
    normalized and warned, not rejected. Structurally malformed persisted JSON
    read through `readTreeMeta` returns `ErrConfigDBUnreadable`.
17. **Unsupported policy shape is never omission:** only the canonical combined
    four-key zone-pair shape compiles; every other `from-zone`
    container fails before typed policy construction on strict and tolerant
    paths.
18. **SNMP intent is exact:** strict input uses canonical top-level `snmp`;
    tolerant legacy hierarchy normalizes into the same merged root. Every
    invalid compiler or hand-built runtime identity is omitted from the USM
    table, compiler rejection dominates duplicates, one pure evaluation drives
    diagnostics and lifecycle, and rejected-only config leaves no stale
    listener running.

## 8. Risk assessment

| Risk class | Rating | Why | Required mitigation |
|---|---|---|---|
| Behavioral regression | HIGH | Thirteen independent roots include security policy acceptance, SNMP auth, DDNS deletion, HA activation, and config loading | Separate PRs; fail-on-revert traces; strict/lenient paired tests; package-wide reruns after each config merge |
| Lifetime / borrow-checker | LOW | Only K003-01 changes Rust and it passes a copied byte already present in metadata; no ownership or shared-lifetime change | Rust unit tests, clippy/build, and packet-path smoke |
| Concurrency / lock ordering | MEDIUM | K003-16 repairs a race but a careless lock reuse can deadlock direct VIP reconciliation | Dedicated mutex; helper-only access; race tests and lock-scope review |
| Performance regression | LOW | One copied byte on a rare flowless path; all other work is cold path | No new packet reads/allocations; userspace throughput baseline and perf smoke for K003-01 only |
| State/ownership corruption | HIGH | DDNS wrong-family delete, malformed cross-surface state, routing ownership loss, stale RG pins, and interleaved session bulk/apply are explicitly stateful | Expected-surface validation with canonical-equivalent Surface-A identity; exact same-family `fpb1` selection; no representative/credential fallback; post-pass anchor lifetime; RG slot clear/fence debt; linearized config/install gate; authoritative bulk barrier; generation-tracked repair; injected failure/retry tests |
| HA compatibility | HIGH | RG bindings above the 16-slot dataplane domain were previously accepted; upgraded peers must reject without partial apply while definitions through 255 remain legal; older peers ignore the additive repair request | Honest operator-bound preflight/release note; fresh-boot, reconnect, previous-good, stale-pin, invalid-bulk, and repair-debt state-machine tests; definition/binding/membership validation; userspace HA reject/recovery smoke |
| Public API regression | MEDIUM | Route-map Go helpers gain required context and lifecycle strings change from false `deny` to `n/a` | Migrate every repository caller atomically; release notes; REST/gRPC/CLI/filter/action golden tests |
| Architectural mismatch | MEDIUM | Mega-batching repeats the #961/#946 Phase-2 dead-end pattern; RG owner widening would create a pinned-map migration project | Path A split; preserve 0..255 definitions but gate owner bindings to 1..15; no broad parser or ABI redesign |

## 9. Test and validation plan

### 9.1 Test-first requirement per workstream

Every implementation PR begins with a red test or deterministic reproducer that
passes on the fix and fails when the fix hunk is reverted.

- **A / VIP race:** helper-level atomicity under concurrent reset/mark/clear, a
  source canary that permits no direct `vipWarnedIfaces` access outside the
  helpers, concurrent apply/HA event coverage, and `go test -race ./pkg/daemon`.
- **B / empty identities:** flat-set and hierarchical strict failures for empty
  zone, pair side, policy name, and global list element; persisted `Store.Load`
  compile-failed boot classification; `SyncApply` rejection with byte-identical
  previous active/compiled snapshot; peer-only group expansion fails the
  originating strict commit; no userspace or host-inbound publication.
- **C / SNMP:** canonical top-level cases for nonempty valid noAuthNoPriv,
  empty username, empty password, password-only,
  protocol-without-password, privacy-without-auth, privacy-without-password,
  conflicting protocols, repeated expanded-tree occurrences, and flat scalar
  replacement semantics. Repeated canonical roots prove source-order merge
  rather than replacement. Production `SetPath`, persisted JSON, and genuine
  hierarchy tests prove every `system snmp` source shape normalizes to identical
  effective SNMP with one migration warning in strict and lenient modes. A
  `FormatSet` artifact reloads identically. The shipped Incus fixture is
  migrated, while an old persisted copy still boots with identical effective
  SNMP. Equal client prefixes prove `restrict` wins independent of source order;
  malformed clients never become unrestricted. Repeated user declarations
  prove unknown/empty/conflicting auth or privacy observations survive folding
  without any secret value in diagnostics. Strict/lenient tests prove
  intent is observed before lowering and a rejected identity dominates every
  valid duplicate; peer-only invalid users fail the originating strict commit;
  JSON/YAML projections and reconcile hash carry sorted nonsecret metadata.
  Runtime tables cover nil values, empty keys, embedded-name/key mismatch,
  unknown protocols, every protocol/password iff combination,
  compiler-rejected plus runtime-valid duplicate, stable disjoint union/counts,
  and valid-to-invalid atomic removal. Config CLI/REST/gRPC remain nil-safe and
  show canonical configured/installable/omitted identities. A rejected-only
  day-2 config publishes exact diagnostics before stopping; rejected-only boot
  publishes the same counts and never binds UDP/161. Packet tests prove
  noAuthNoPriv and authNoPriv cannot satisfy stronger configured intent.
- **D / flowless ICMP:** IPv4 type 3/11/12 and IPv6 type 1/2/3/4 global admits;
  ND 133..137 where relevant; non-first fragment remains denied; unrelated ICMP
  remains denied; native-GRE and interface-NAT flowless entry coverage.
- **E / DDNS:** distinct v4/v6 fake updaters with a backend-less v6 disable
  reproduce the wrong-family call before the fix and prove no v4 updater ever
  receives a v6 delete afterward. Cover both family blocks removed, transient
  per-family factory failure, a current same-family exact `fpb1`, a retained
  previous same-family exact `fpb1`, mismatching and empty production
  fingerprints, mixed-family rows in one pass, and restart without historical
  authority. Expected-Surface-B load and selection reject family 0/5,
  family/address/type mismatch, trailing-dot/uppercase/noncanonical FQDN,
  forged PTR, Surface-A-only fields, and scope-family/FQDN mismatch before
  indexing or DNS I/O. Expected-Surface-A load accepts settled and pending
  router-self rows, including uppercase and single-trailing-dot scope names whose
  `surfaceAName` equals the stored canonical row name, and rejects lease fields,
  address-family mismatch, malformed prior address, noncanonical row FQDN, and
  true canonical scope/FQDN mismatch. A valid row cannot be reclassified by
  heuristics because each constructor supplies the expected store surface.
  Fixed-updater tests preserve valid empty-fingerprint compatibility and refuse
  nonempty fingerprints.
  Stateful A -> B tests make forward deletion succeed and PTR deletion fail,
  retain A for the next pass, and advance the anchor only after the row is
  fully removed; A -> B -> C while A is unresolved retains and alarms. Any
  updater error causes no second-credential retry and retains ownership.
  Last-claimant no-authority asserts zero wire writes, retained row, non-nil
  error, failure counter, and alarm. Co-owned no-authority asserts claim-only
  durable release, zero provider calls, then Surface-A convergence after the B
  claim disappears. Existing #6015 cross-surface ordering tests remain green;
  this workstream adds no namespace/election claim. A source canary forbids
  production reads or writes of representative `m.updater` outside the fixed
  compatibility seam and forbids new generation/catalog state.
- **F / LoadOverride:** flat valid input, braced hierarchical valid input,
  one-line hierarchy, schema-valid top-level leaf, singleton `sett` typo,
  unknown brace-less and braced roots, packed schema-container misuse, blank,
  full-line and inline hash/slash comments, single-line and multiline block
  comment rejection in flat mode, terminated block-comment-only empty success,
  unterminated block-comment failure, block-comment support in hierarchy, optional
  trailing semicolon, set-before-deactivate normalization, missing deactivate
  target, delete/activate rejection, mixed format rejection, typoed/malformed
  mid-file command, and empty override. One Store-level table covers all
  classifier inputs. Store, REST, and gRPC tests pin current empty/comment-only
  behavior; a local CLI test covers only successful non-interrupted load. No
  Ctrl-C/non-EOF assertion or `pkg/cli` code change is claimed under this issue.
  Nonempty unknown-root, typo, and mixed input have matching error classes.
  Every failure asserts candidate bytes, generation, dirty state, lock owner,
  and lease deadline are unchanged.
- **G / AST bounds:** malformed active, candidate, and JSON rollback-slot data
  is rejected immediately after unmarshal; null child and empty-Keys descendant
  active trees are `ErrConfigDBUnreadable`; quoted empty `Keys[0]` remains
  structurally accepted for semantic validation. Handcrafted empty-Keys
  interface and sampling family nodes cannot panic their compilers; valid
  empty/populated JSON still loads; peer text sync is a negative reachability
  control; malformed trees become fuzz seeds. `ReadConfirm` rejects a nonnil
  `PrevTree` containing a nil child or empty `Keys`, while valid first-commit,
  encrypted/plaintext, and legacy records round-trip. Revert canaries prove the
  same validator serves `readTreeMeta` and `ReadConfirm`; no hash, timer,
  persistence field, recovery class, or public operation changes.
- **H / route-map:** term count equals actual rendered term rows for v4-only,
  v6-only, dual-stack, empty/undefined lists, mixed route-filter x mixed
  referenced-list products, multiple referenced names, community and AS-path
  products, and terminating/nonterminating composed chains; highest-sequence
  separately equals the renderer's final row at 65535 boundaries; no
  context-free safety caller or raw-count ceiling comparison remains.
- **I / RG:** canonical definition IDs 0, 15, 16, 155, 156, and 255 remain
  accepted when unbound; -1, signed/leading-alias/nonnumeric/overflow, and 256
  fail without RG0 alias. Node identities accept exactly 0/1 and reject peer-only
  malformed/overflow aliases. Explicit binding IDs 0, 1, 15, 16, malformed,
  and undefined prove only 1..15 plus membership is accepted; normal RETH,
  private-election, no-RETH, and unused definitions; node0-valid/node1-invalid
  apply-group cases for out-of-range and orphan bindings; interface-range
  inherited/overridden bindings; and repeated `chassis` roots where only the
  final typed definition set is authoritative. Tolerant fresh boot returns
  compile-failed only for bad identity/binding and remains default-deny.
  Previous-good -> invalid sync preserves active, compiled, maps, arm state,
  and applied-generation high-water; a later valid generation applies. A
  userspace compile seam snapshots link pins, shim selector calls, generation,
  attachment calls, inventory, maps, and helper requests and proves every value
  unchanged on typed RG rejection.

  Inventory tests define RG1 and unbound RG20 but bind only RG1, then exercise
  seeding, map merge, watchdog, helper publication, readiness, shutdown/fence,
  `UpdateRGActive`, and every fixed-slot call site: RG1 acts, RG20 never indexes
  or publishes, and a direct RG20 update fails before mutation. Constant drift
  canaries distinguish definition capacity 255 from BPF/shim/Rust owner-slot
  capacity 16 and preserve RG0 as definition-only. Rolling upgrade feeds an
  old-primary RG20 binding to a new standby and proves previous-good plus stale
  alarm, manual-transfer refusal, and automatic peer-loss takeover behavior;
  unbound RG20 syncs normally. Active RG1 -> unbound -> process restart/rebind
  on a secondary proves stale pinned active/watchdog values are cleared before
  replay. New-slot, removed-slot, unchanged-slot, each map/helper clear failure,
  retry debt, and helper-disarm behavior are executable. Preflight invokes the
  staged binary against the same operator-designated unredacted artifact/hash
  for node 0 and node 1 and covers exit 0, exit 2, redacted input, and tool
  failure; a stale valid file is explicitly outside the command's detectable
  contract and is not asserted rejected.

  Protected-direction gate tests cover fresh boot, legacy zero after baseline,
  exact match, future, older, apply-in-progress, and post-reconnect baseline for
  v4 and v6. A barrier-controlled install that passed admission before apply
  must finish before the sweep; one arriving after closure is refused before
  per-key generation or bulk membership. Apply success/failure, lower rebooted
  generation baseline, role transition, and the explicitly unprotected
  active/active inverse are deterministic.

  Bulk tests enqueue a pre-barrier incremental, churn installs/deletes while the
  snapshot iterates, and prove only snapshot rows lie between markers while
  deferred deltas retain order after BulkEnd. Queue overflow/write failure
  re-arms authoritative repair. A refused/malformed bulk member invalidates the
  bulk: no stale reconcile, success ACK, readiness release, or debt discharge.
  `BulkStart` resets per-key/full-set ordering but preserves config authority.

  Recovery-debt tests cover atomic claim, duplicate refusals, nil connection,
  partial/failed write rearm, disconnect/reconnect retry, a refusal concurrent
  with request, a refusal concurrent with bulk, valid BulkEnd token completion,
  and another request when newer debt remains. Type-29 uniqueness, old-peer
  unknown-message behavior, sender `forceResync` coalescing, and failed-G ->
  successful-baseline -> valid-full-bulk recovery are pinned.
- **J / address book:** repeated outer blocks, repeated global blocks, duplicate
  legal entries, duplicate illegal names, references to first and later blocks,
  deterministic diagnostics.
- **K / routing:** genuine not-found, transient `LinkByName`, `LinkDel` failure,
  subsequent retry recovery, and ownership-map assertions for bond and tunnel.
- **L / lifecycle action:** golden events originating from actual Rust wire
  bytes for OPEN/CLOSE across both decode paths and every row of the surface
  matrix: daemon slog, both SSE renderers, both CLIs, monitor text, trace,
  standard and structured syslog, REST, gRPC, and binary. Exact filters prove
  deny excludes lifecycle and n/a selects it. Unknown future event types default
  to not-applicable. Positive POLICY_DENY/FILTER_LOG/SCREEN_DROP goldens prove
  decoded action and each formatter's existing include/omit behavior are
  unchanged.
- **M / nested policy shape:** the canonical combined form remains accepted;
  every legacy-chain, nested, partial, or malformed container fails in strict
  and tolerant compilers with canonical syntax in the message; no test-created
  legacy fixture is accepted. A peer-only nested shape fails the originating
  strict commit. Persisted boot enters compile-failed lifeline/default-deny and
  `SyncApply` retains a byte-identical previous active/compiled snapshot.

### 9.2 Required local gates

At minimum, each PR runs its package tests plus the affected dependency fanout.
The integration wave runs:

```bash
go test ./pkg/config ./pkg/configstore ./pkg/ddns ./pkg/logging ./pkg/snmp \
  ./pkg/routing ./pkg/daemon ./pkg/api ./pkg/frr ./pkg/dataplane/...
go test -race ./pkg/daemon ./pkg/ddns ./pkg/routing ./pkg/snmp
cargo build --manifest-path userspace-dp/Cargo.toml
cargo test --manifest-path userspace-dp/Cargo.toml
cargo clippy --manifest-path userspace-dp/Cargo.toml --all-targets -- -D warnings
```

Run the full repository Go suite (at least the project's 30-package gate) and
the full current Rust suite (not an obsolete fixed count; record the observed
count, which must be no lower than the current 952+ baseline). Every named
adversarial test runs 5/5 without a flake.

### 9.3 Runtime smoke requirements

- K003-01 and K003-10 require the isolated userspace HA cluster: IPv4 and IPv6
  forward/reverse traffic, per-class CoS ports 5201-5206, ICMP error/PMTUD
  injection, RG active/standby transition, and failover acceptance. K003-10
  additionally exercises previous-good -> rejected invalid sync -> valid
  recovery and malformed fresh boot, proving no helper-map mutation or
  demotion occurs for the rejected generation, manual transfer is blocked,
  previous-good automatic peer-loss takeover remains available, and refused
  sessions are repaired by the post-success bulk request. Restart/rebind smoke
  also seeds stale active/watchdog values in removed and newly introduced slots
  and proves they are fenced before publication; reconnect smoke races config
  baseline with a bulk and proves an invalid bulk cannot reconcile, ACK,
  release readiness, or clear repair debt.
- K003-07 requires apply/rollback validation proving a rejected commit cannot
  replace the previous helper policy snapshot.
- K003-03 requires authoritative fake/isolated DNS endpoints with operation
  logs proving every Surface-B delete used the exact same-family updater whose
  `fpb1` matched the row, no cross-family fallback occurred, partial failure
  retained the old anchor, and no-authority rows caused zero DNS writes.
- K003-11 requires a netns or fake-netlink retry sequence proving the kernel and
  ownership view converge after a transient lookup failure.
- Control-plane-only display and parser PRs do not require throughput smoke, but
  they still require their full package and API golden tests.

Optional perf capture is required only if K003-01 introduces work beyond copying
the already-parsed byte. Any additional packet parse or map lookup is a plan
deviation and returns to review.

## 10. Out of scope

- Engineering, production code, child issues, or pull requests during this
  `/research` run.
- Reimplementing #6548's local CLI fix or broadening #4313 beyond K003-05's
  concrete security-policy-container gate.
- A syslog handshake-deadline change based on K003-12.
- Filing or engineering the undocumented 128-item cohort.
- Broad AST/parser normalization across all configuration packages.
- Supporting nested policy syntax as a vSRX feature; official Junos hierarchy
  uses the combined `from-zone X to-zone Y` container.
- Widening dataplane owner capacity above slots 1..15 or migrating pinned BPF
  maps. Control definitions remain supported through 255.
- Generalized DDNS namespace and teardown protocol: endpoint aliases/anycast,
  cross-Surface-A/B linearization, publication-versus-deletion races, durable
  claimant election, legacy `fp1` migration, HTTP-provider identity, and
  duplicate-key semantics. Retrying across credential generations or reporting
  separate forward/PTR/DHCID outcomes also belongs there. The bounded K003-03
  fix deliberately retains and alarms instead of guessing.
- Commit-confirm transaction redesign: crash-safe ordering between
  `active.json` and `confirm.json`, current `tree.Format()` hash semantics,
  stale-before-target interpretation, old-reader compatibility, rollback
  target classes, downgrade behavior, quarantine/remediation, and RBAC. K003-04
  does not change that protocol beyond validating the already-embedded
  `PrevTree` node shape. After manual approval, create a dedicated
  research owner for this subject before any production change.
- Documenting `system snmp` as canonical. It remains a deprecated typed alias;
  hierarchy, persistence, and flat-set reload are necessarily accepted because
  their AST representation is identical.
- Changing Rust event wire layout or retroactively assigning permit/deny to
  lifecycle events.
- Refactoring all logging formatters beyond central action applicability.
- Unrelated DDNS ownership, SNMP feature expansion, FRR rendering, or routing
  reconciliation improvements discovered while implementing a child issue.

## 11. Resolved adversarial decisions

Rounds one through seven closed the design choices rather than delegating them
to implementors:

1. Path A remains the recommendation. The config-heavy workstreams are separate
   PRs but merge serially in waves; no root needs an atomic cross-package batch.
2. The current issue snapshot found exact ownership only for K003-02 (#6548).
   K003-05 is a live honesty/security gap with its own child issue; #4313 is the
   related doctrine umbrella, not an exact owner. The fix rejects rather than
   implements the noncanonical nested hierarchy.
3. Flat override accepts complete `set` plus `deactivate` artifacts and rejects
   destructive `delete`/`activate` verbs. This honors the documented API without
   inventing replacement-tree edit semantics. Hierarchical mode validates
   top-level roots and container shape from schema SSOT rather than treating
   braces as proof. Empty/comment-only behavior remains entrypoint-specific
   until #6548. K003-09 does not touch or test the local terminal
   interrupt/read-error contract.
4. Control definitions remain canonical IDs 0..255. Sixteen is only the
   dataplane owner-slot count: explicit bindings are 1..15 and must reference a
   definition; zero remains unbound/control. One bound-owner inventory feeds all
   fixed-slot paths. Newly introduced and removed slots are cleared/fenced
   before inventory publication, including process-start replay of persistent
   pins. Mixed-version high bindings reject fail-safe, block manual transfer,
   preserve previous-good automatic peer-loss takeover with an alarm, and
   require the two-node-view `xpfd check-config` content preflight. The command
   cannot prove artifact freshness; source-of-truth selection and config freeze
   are explicit operator prerequisites. A 256-entry owner ABI/pinned-map
   migration remains separate research.
5. Production Surface-B DDNS uses only the exact same-family current or retained
   previous updater whose nonempty existing `fpb1` matches the owned row. Anchor
   rotation happens after reconciliation and is deferred while a retained row
   depends on the old endpoint. The expected store surface is validated without
   a new disk tag, and #6015 claim-only co-owner release occurs before
   last-claimant authority selection. Fixed-constructor mode preserves its
   whole-store caller authority for valid empty-fingerprint rows; daemon
   production does not use that seam.
   There is no representative-updater or credential-generation fallback.
   Namespace/election and component-outcome redesign require separate research.
6. SNMPv3 intent is validated on one merged canonical root before lowering.
   Strict and tolerant input normalize every AST-equivalent `system snmp` form
   with a deprecation warning. Structured client rows preserve equal-prefix
   deny-wins, and multi-source observations prevent an invalid/conflicting
   occurrence from disappearing in a last-writer fold. Compiler rejection
   dominates duplicates. One pure
   runtime evaluation supplies installable users, disjoint rejection union,
   exact counts, operational diagnostics, and listener decisions before Agent
   lifecycle, so rejected-only config remains visible and stops the listener.
7. Lifecycle action applicability is a positive event-type allowlist applied
   before daemon slog or record construction. Structured APIs preserve their
   scalar field shape with `"n/a"`; lifecycle human text omits the key
   and binary uses 0xff. Existing formatter-specific behavior for real action
   events is preserved.
8. VIP warning state has one dedicated mutex and helper-only access. It adds no
   lock-order edge to `directVIPMu` or `applySem`.
9. Persisted JSON gets one minimum structural validator in `readTreeMeta` for
   active, candidate, and JSON rollback slots and in `ReadConfirm` for its
   nonnil `PrevTree`. K003-04 also owns the two known indexing belts.
   `confirm.json` hash, transaction ordering, target classes, and recovery
   semantics remain dedicated crash-consistency research.
10. Route-map term counters require `PolicyOptionsConfig`, while one shared
    highest-sequence/fit helper owns the terminal-row reservation. No
    conservative wrapper or raw-count comparison remains in a safety decision.
11. The two Low-severity roots remain worth bounded child issues: repeated
    address-book blocks silently lose configured objects, and false lifecycle
    deny values corrupt SIEM/forensic classification. Their independent PRs may
    still receive `PLAN-KILL` if a new reproduction disproves those impacts.
12. Malformed definition/node identities and out-of-slot/orphan dataplane
    bindings are compile failures on strict and tolerant paths; legal unbound
    definitions through 255 remain accepted. Raw syntax is checked after
    canonical group/interface-range expansion; binding membership is checked
    on final typed config. The exported runtime belt executes before pin, shim, generation,
    attachment, inventory, map, or helper side effects. The failure never sets
    `ForwardingSupported=false`; invalid live sync retains the exact previous
    generation and fresh boot remains lifeline/default-deny. Fixed-slot runtime
    paths consume only the typed bound-owner inventory.
13. The B/C/I/M action-agnostic hard gates run against both canonically prepared
    node-effective trees before strict promotion. Peer validation uses the same
    section lowering and typed semantics as local compilation while unrelated
    compatibility warnings remain lenient. This is a focused extension of the
    existing peer-effective SNAT precedent, not a global conversion of every
    lenient warning into a peer commit failure.
14. Only the canonical four-key zone-pair AST is accepted. Repository history
    has no authentic legacy nested persistence fixture, so the permissive
    compiler fallback is removed instead of being enshrined by a new fixture.
15. In the explicitly protected authority-to-receiver direction, one gate
    linearizes session installs against config apply, blocks reconnect traffic
    until a successful baseline, and accepts exact applied epochs before
    per-key bookkeeping. The explicit active/active inverse remains
    unprotected. A send-side barrier prevents ordinary session deltas from
    contaminating authoritative bulks. Generation-tracked refusal debt is
    retried across write failure/reconnect and clears only at a fully valid
    BulkEnd requested through additive type 29; old peers ignore the request
    but cannot make readiness falsely green.

Manual approval of this plan accepts those product choices. A material change to
any one returns that child workstream to plan review rather than being improvised
inside implementation.
