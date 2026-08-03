# Plan of Action - #6744: Revalidate and split `kimi-review-003`

## 1. Status

**DRAFT v5 - round-four major findings addressed; pending round-five review**

- Issue: [#6744](https://github.com/psaab/xpf/issues/6744)
- Source report: `/tmp/kimi-review-003.md`
- Base: `origin/master` at `ad959117748181dabe46b8ddc2827de670380cea`
- Branch: `research/6744-kimi-review-003`
- Revision: 5
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
| K003-10 | RG IDs beyond the 16-entry dataplane domain can commit but never become active | **PARTIAL** | High | Medium | The dataplane cap mismatch is live. Definitions are limited to 0..15; explicit dataplane bindings are 1..15 because zero is the unbound/standalone sentinel, and each binding must name a definition. The blanket `16..255` wording is too broad because RETH/VRRP and control-group reachability differ |
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
  snapshot; it never acknowledges the invalid peer generation.

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
    effective *ConfigTree,
    lenientSNMP bool,
) (EffectiveHardGateResult, error)
func compilePeerEffectiveHardGateView(
    tree *ConfigTree,
    peerNodeID int,
) (*Config, error)
```

`runEffectiveHardGates` owns the B, C, and M AST gates plus I's explicit-binding
syntax check. `compileConfigWithOpts` invokes it after canonical preparation and
carries its SNMP result into section lowering. B and M always return errors; C
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

The only supported configuration root is the schema-linked Junos form,
top-level `snmp v3 usm local-engine user`. The dead `compileSystem` fallback is
removed. A direct `system snmp` child is an action-agnostic hard error on strict
and tolerant paths with a diagnostic that points to canonical `set snmp ...`
syntax. This is preferable to blessing an undocumented alias whose flat
`SetPath` shape is a packed leaf rather than the child hierarchy
`compileSNMP` expects. The intent pass aggregates every canonical occurrence by
identity without copying secret values into diagnostics:

- a nonempty username with no authentication or privacy declaration is valid
  noAuthNoPriv;
- exactly one authentication protocol requires exactly one authentication
  password whose value is nonempty;
- exactly one privacy protocol requires an authentication protocol/password
  and exactly one nonempty privacy password;
- any password without its corresponding protocol is rejected;
- an empty username is rejected because the empty wire username is reserved for
  engine discovery;
- distinct protocol selections or conflicting password declarations that
  survive in the expanded AST are rejected. Flat scalar reassignments already
  coalesced by `SetPath` have ordinary last-set semantics; this pass
  does not claim access to erased input provenance.

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
    root *ConfigTree,
    lenient bool,
) (SNMPv3IntentResult, error)
```

The dataflow is explicit, rather than hidden in a warning slice:

1. `runEffectiveHardGates` returns the local
   `SNMPv3IntentResult` to `compileConfigWithOpts`.
2. The section dispatcher passes that result only through the canonical
   top-level `compileSNMP` path. `compileSystem` has no SNMP branch.
3. `compileSNMPv3` takes the rejected-name set and skips every
   rejected username without mutating the source AST.
4. After all SNMP stanza locations are lowered, the compiler attaches the
   stable, sorted, nonsecret slice to
   `SNMPConfig.RejectedV3Users` and appends the same reasons to
   `Config.Warnings`.
5. Both custom `SNMPConfig.MarshalJSON` and
   `MarshalYAML` projections include
   `RejectedV3Users`. The SNMP reconcile hash includes the sorted
   rejection metadata so a metadata-only transition cannot disappear behind
   the unchanged-hash shortcut.

Strict compile returns a path-qualified error and never lowers a rejected
username. Lenient persisted loading keeps the source tree for diagnosis and
lowers only valid users.

Runtime remains an independent belt:

```go
type V3RuntimeRejection struct {
    Identity string
    Path     string
    Reason   string
}

func HasInstallableV3Users(cfg *config.SNMPConfig) bool

func (a *Agent) deriveV3Users(
    cfg *config.SNMPConfig,
) (map[string]*usmUser, []V3RuntimeRejection)
```

`deriveV3Users` iterates sorted map keys and never dereferences a nil value. It
rejects an empty map key, nil user, empty declared key, privacy without valid
authentication, unknown protocol, and a `user.Name` that is empty or differs
from its map key. The map key is the canonical installed identity; a malformed
embedded name can never redirect or overwrite another user.

Runtime rejection metadata is unioned with
`SNMPConfig.RejectedV3Users` by stable identity (`Identity`, or `Path` when no
name exists), with deterministic sorted field-only reasons. One logical user is
counted once even if both compiler and runtime belts reject it. The resulting
counts are exact: `configured = installed + omitted`; `omitted` is the size of
that unique rejection union. `NewAgent` and `UpdateConfig` derive the complete
valid table and union before taking `cfgMu`, then swap the config pointer,
valid-user table, and rejection snapshot together. A valid user changed to
invalid therefore disappears in one atomic swap. One structured warning reports
configured, installed, and omitted counts plus sorted nonsecret identities.

Listener behavior is not delegated to the implementor. `snmpEnabled` continues
to require at least one valid community or installable v3 user. It calls
`snmp.HasInstallableV3Users`, a zero-localization view over the exact same pure
structural validator `deriveV3Users` uses before password-to-key work; the
daemon and agent may not maintain separate acceptance predicates. A config
whose only identities are rejected stops an existing agent (or declines
startup) after publishing the compiler/runtime rejection diagnostic; it does
not leave UDP/161 open with an empty USM table. The reconcile hash includes
sorted compiler rejection metadata and all runtime-significant input, so a
transition cannot hide behind the unchanged-hash shortcut. Do not infer
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

Production factory mode resolves current and retained anchors independently per
family. `dhcpBackendFingerprint` identifies an executable RFC2136 endpoint from
backend/server/key-name/algorithm/bind identity even when publication policy is
disabled. `enabled` controls whether leases are desired; it is not part of
endpoint identity. A removed stanza or unusable factory still produces no
current endpoint.

Choose the delete updater for each owned row, not once for the family:

```go
func (e *reconcileEnv) updaterForOwnedWithdrawal(
    owned ownedRecord,
) (DNSUpdater, bool)
```

Reject an owned row before any family-array lookup or DNS operation unless its
family is exactly 4 or 6 and its address family agrees with `Address`/`AddrText`
and `ForwardType` (`A` for v4, `AAAA` for v6). The ownership loader applies the
same semantic check and quarantines an invalid store. The selector repeats it
as a belt so a handcrafted in-memory row cannot alias family 0 or 5 to the IPv4
slot.

The deterministic authority selection is:

1. In production factory mode, if the current updater for `owned.Family` is live and its nonempty
   fingerprint equals `owned.BackendFingerprint`, use it.
2. Otherwise, if that family's previous-cycle updater is live and
   `prevFP` equals the nonempty owned fingerprint, use it. This is the
   normal disable, temporary factory-failure, and endpoint-transition cleanup
   path.
3. In fixed-updater mode only, a non-nop caller-supplied updater is trusted to
   withdraw a valid-family row whose `BackendFingerprint` is empty. This
   preserves the public constructor's historical contract: its caller attests
   that the one updater is authoritative for records that constructor created.
   A nonempty fingerprint is never authorized by fixed mode.
4. Otherwise return no authority. Keep the durable ownership row, increment the
   existing orphan/backend-mismatch alarm, and block republish of that identity
   for the pass.

Every production comparison is same-family and exact-fingerprint. An empty
legacy production fingerprint is uncertainty, not permission. The code never
substitutes another family, a representative updater, or a merely non-nil
backend.

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
reconcile may use a newly current same-family updater if its endpoint
fingerprint still matches. This bounded behavior fixes K003-03 without
inventing component authority that the current backend API cannot report.

The no-authority branch never writes DNS, changes a fingerprint, drops
ownership, or reports success. Restart after the operator removed the only
backend cannot reconstruct an executable updater; it retains and alarms. The
fixed-mode trust bit is in-memory constructor state, not persisted authority.
No new secret, generation ID, map, catalog, memory cap, disk schema, or public
API is introduced.

### 5.7 Workstream F - make `LoadOverride` format handling explicit and atomic (K003-09)

Use constrained F1 and remove F2 as an implementation choice. `LoadOverride`
already promises a complete flat `set` artifact, so honor that contract without
pretending an edit transaction against an empty tree is a full configuration.

The classifier lexes comments and quoted strings before classifying, then scans
every significant line before mutation. A significant flat line is neither
blank nor a full-line `#`/`//` comment. Inline `#`
or `//` comments and one optional trailing semicolon are accepted
through the existing `ParseSetVerb` lexer contract. Every
`/* ... */` block comment is rejected in flat mode, including a
single-line block: replay is one command per physical line and must not acquire
a second comment grammar. Block comments remain valid in hierarchical mode.

1. If no line begins with a recognized flat verb, select hierarchical mode
   only when the comment/string-aware lexer finds structural braces. A one-line
   hierarchy such as `system { host-name fw; }` is valid. A nonempty brace-less
   body has no positive hierarchy evidence and is rejected as ambiguous; in
   particular `sett system host-name fw` cannot become an implicit
   hierarchy leaf at EOF. Empty input or input containing only blank,
   full-line `#`, and full-line `//` comments is a valid
   empty override; block-comment-only input is rejected.
2. If any line begins with a recognized flat verb, every significant line must
   begin with a recognized flat verb. A typo such as `sett` is an unrecognized
   flat verb at that line, not an implicit bare `set` path and not hierarchical
   fallback.
3. Flat override accepts only `set` and `deactivate`. Reject `delete` and
   `activate` with a line-numbered diagnostic directing the caller to
   `load set` or `load merge`; those are edit verbs with no unambiguous meaning
   against a fresh replacement tree.
4. Apply all `set` lines to a detached empty `ConfigTree`, then apply
   `deactivate` lines so a canonical `show | display set` artifact is
   order-independent. A missing deactivate target rejects the complete load.
   Comments-only/empty input produces a valid empty tree.
5. A flat/hierarchical mixture is an error at the first conflicting line.

```go
func classifyOverride(content string) (overrideFormat, []flatOverrideLine, error)
func parseFlatOverride(lines []flatOverrideLine) (*config.ConfigTree, error)
func parseHierarchicalOverride(content string) (*config.ConfigTree, error)
```

Only after complete parse/replay succeeds does `LoadOverrideAs` swap the
candidate and update generation/dirty/lease state. Every error leaves candidate
bytes and metadata unchanged.

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
the same validator for `confirmRecord.PrevTree` after its existing
object/deadline/non-nil checks. A malformed rollback target must never reach
`recoverPendingConfirmLocked`, which can compile or durably promote that tree.

An active-tree structural violation is surfaced through the existing
`ErrConfigDBUnreadable` load classification. Daemon bring-up refuses startup
and refuses overwrite of `active.json`; it does not enter compile-failed
bootstrap/lifeline mode. Candidate/rollback readers return a path-qualified
validation error. A malformed confirm rollback target makes `ReadConfirm`
return an error; boot keeps the already loaded active config, does not re-arm a
timer, does not roll back, and does not delete or rewrite the corrupt recovery
record. This is an inert quarantine, not silent cleanup of forensic state.

Semantic recovery is also checked before state mutation. After the existing
`GuardedHash` stale-record check (a stale record is durably removed and never
interpreted), enforce the `FirstCommit` state invariant: `FirstCommit=true`
requires a canonical empty `PrevTree` (`len(Children)==0`). A populated target
under that flag is quarantined rather than promoted as a nil-compiled bootstrap
config. `FirstCommit=false` may legitimately target an empty operator-committed
config and still goes through tolerant compilation.

Extract one compatibility preparation helper:

```go
func (s *Store) preparePersistedTreeForLenientCompile(
    raw *config.ConfigTree,
    caller persistedTreeCaller,
) (prepared *config.ConfigTree, compiled *config.Config, err error)
```

It clones the raw tree, applies the retired-dataplane rewrite, sanitizes control
characters, and invokes the same node-local tolerant compiler. `Store.Load`,
`Store.SyncApply`, and confirm recovery use this helper with caller-specific
diagnostics. The raw `confirm.json` tree remains byte-for-byte forensic input;
the prepared clone is the tree that is both compiled and, after successful
validation, installed/persisted as the rollback target. This prevents recovery
from compiling one representation and later promoting another.

For every non-`FirstCommit` record,
`recoverPendingConfirmLocked` prepares and compiles `PrevTree` through that
helper **before** assigning `s.active`, populating `confirmPrevTree`, or arming a
timer. For a valid first-commit record it prepares a canonical empty clone and
keeps the compiled target nil. A structural, first-commit-consistency, or
semantic failure preserves the already-loaded active and compiled config,
retains the exact confirm file, and arms no timer. Expired and future records
obey the same preflight-before-mutation order.

Add `confirmRecoveryDegraded bool` under `Store.mu` and include it in
`ConfigPersistDegraded()` so the existing `/health` 503 and
`xpf_daemon_config_persist_degraded` metric surface the quarantine. Expose a
focused accessor for diagnostics. Set the latch on malformed `confirm.json`, an
inconsistent first-commit record, or a non-first-commit target that cannot be
prepared and compiled. While latched, a new `CommitConfirmed` is rejected so it
cannot overwrite the forensic record and silently launder the fault.

The named remediation is `Store.DiscardQuarantinedConfirm()`, exposed as
`request system configuration discard-quarantined-confirm` through the local
CLI and the existing remote `SystemAction` channel. Because it does not mutate
the shared candidate, it does not borrow the configuration lock; it is instead
classified as a privileged maintenance action and requires the same explicit
interactive confirmation discipline as other destructive `request system`
operations. The store method refuses unless the recovery latch is set and no
confirm timer is armed, then calls the existing durable `DB.DeleteConfirm`. It
changes neither active nor candidate config. Only a successful
unlink-plus-directory-fsync clears the latch; failure leaves health degraded
and returns the error. The successful path writes a nonsecret
`confirm_quarantine_discarded` journal entry. A process restart after an
operator repairs the file naturally re-runs validation; there is no in-process
"later read" claim and no background retry that can reinterpret changing
forensic bytes.

A path-qualified journal/log diagnostic contains no config values or secrets.

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

Select a global product limit of 16 definition slots, IDs 0..15. Userspace
inventory seeds every configured RG, including an otherwise unused definition,
so a narrower "dataplane-bound definition" predicate is not real. Binding
semantics are different: value zero is the Go/BPF/Rust unbound or standalone
sentinel, so an explicit interface/RETH dataplane binding is valid only in
1..15 and must reference a definition present in the same node-effective tree.

Validate explicit binding syntax on the canonical node-effective AST after
interface-range expansion, before typed lowering can collapse an explicit zero
into the ordinary zero-value "not configured." Reject malformed, zero, and
above-15 bindings there. Then validate definition range, final binding range,
and membership on the fully lowered typed `Config`; this honors the compiler's
current repeated-`chassis` replacement semantics rather than incorrectly
unioning definitions from roots that do not survive lowering. Definition zero
remains legal for control-group election and monitoring; it is never emitted as
a dataplane owner.

```go
// pkg/config: lowest-layer product contract.
const MaxDataplaneRedundancyGroups = 16

func ValidateDataplaneRGDefinitionID(id int) error // 0..15
func ValidateDataplaneRGBindingID(id int) error    // 1..15
func validateDataplaneRGBindingSyntax(root *ConfigTree) error
func ValidateDataplaneRGTyped(cfg *Config) error
```

`pkg/dataplane.MaxRedundancyGroups` becomes an alias of the config constant.
Source/ABI canaries prove equality with BPF `MAX_REDUNDANCY_GROUPS`, shim map
specs, and Rust `MAX_RG_EPOCHS`; widening remains a separately researched pinned
map/protocol migration.

This is an action-agnostic semantic safety error, not a class-II capability.
The syntax half participates in `runEffectiveHardGates`; the typed half runs
after section dispatch and derivation on local and peer hard-gate compiles. A
node1-only RG16, explicit binding zero, orphan binding, interface-range-inherited
binding, or binding resolved against repeated chassis roots therefore receives
the same verdict as the config that would actually be published. Strict and
tolerant compilers return the same error before config-store promotion or peer
acknowledgment. Do **not** set `ForwardingSupported=false`: that value actively
disarms a running helper and cannot represent "reject this generation and
retain previous-good."

- `Store.Load` keeps the parsed source for diagnosis but returns the existing
  compile-failed classification; a fresh boot stays in lifeline/default-deny
  with no interface takeover.
- `Store.SyncApply` rejects atomically, does not acknowledge the invalid peer
  generation, and retains byte-identical active/compiled state and helper maps.
- A later valid generation compiles and applies normally; there is no sticky
  quarantine bit.

Runtime `UpdateRGActive`, inventory build, map sync, and helper publication
remain belts. Most importantly, `userspace.Manager.Compile` calls exported
`config.ValidateDataplaneRGTyped(cfg)` immediately after its nil/input check and
**before the first side effect**: before deleting XDP link pins, selecting or
compiling the userspace shim, deriving/bumping a snapshot generation,
synchronizing XDP/TC attachments, seeding inventory, mutating maps, or issuing a
helper request. Lower dataplane compilers call the same preflight before their
own mutation. `UpdateRGActive` rejects an invalid ID before map or in-memory
state changes. Definitions reject IDs outside 0..15; owner bindings treat zero
as absent and reject positive IDs above 15 or absent from inventory. Diagnostics
distinguish definition range, binding range/membership, heartbeat uint8, and
RETH-derived VRID limits. No path selectively drops an RG or one of its
interface bindings.

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
- route-map helpers intentionally become the context-aware term-count and
  highest-sequence/fit APIs in Workstream H; all repository callers migrate
  atomically because a context-free exact count is impossible.

Workstream G intentionally adds one bounded recovery API:

- `(*configstore.Store).DiscardQuarantinedConfirm() error` and the corresponding
  existing-channel `SystemAction` / operational CLI command. It can only
  durably remove a quarantined, unarmed `confirm.json`; it cannot change active
  or candidate configuration.

Intentional behavior changes are fail-loud validation, not API removal:

- malformed empty security identities stop committing;
- unsupported nested policy containers stop committing under a child issue
  linked to #4313;
- RG definitions outside 0..15, explicit bindings outside 1..15, and bindings
  to undefined groups stop committing under the selected global limit;
- mixed-format override input is rejected atomically;
- invalid SNMPv3 credential combinations stop installing a downgraded user and
  add nonsecret rejection metadata to existing config projections;
- the undocumented, schema-unlinked `system snmp` path is rejected with the
  canonical top-level `snmp` syntax rather than silently compiling empty;
- lifecycle APIs stop calling a non-applicable action `deny` and return the
  existing string field as `"n/a"`.

## 7. Hidden invariants the changes must preserve

1. **Commit/apply equivalence:** anything accepted by strict Go compilation must
   be representable by Rust snapshot hydration. Lenient persisted/HA input may
   warn and quarantine, but it must not panic, widen scope, or install stale
   permissive state as if apply succeeded.
2. **Fail-closed without false deny:** unreadable ICMP fragments remain denied;
   readable ICMP errors in the established global class remain admitted.
3. **DDNS cleanup authority:** production deletes require the current or
   retained previous updater for the exact same family and nonempty endpoint
   fingerprint. The old anchor remains live while any retained row depends on
   it. Fixed-constructor mode may act only on valid-family rows with empty
   fingerprints under its explicit caller-trust contract. There is no
   cross-family, representative-updater, or second-credential fallback. On
   uncertainty or any delete error, retain ownership and alarm.
4. **Atomic config load:** parsing/replay happens on a detached tree. On any
   error, candidate bytes, generation, dirty bit, lock lease, and active config
   remain unchanged.
5. **Persisted AST integrity:** an invalid JSON node tree is rejected at every
   deserialization boundary (`active`, `candidate`, JSON rollback, and confirm
   rollback target) and cannot reach an unsafe compiler walk. A structurally
   valid confirm rollback target receives the same compatibility preparation as
   active load and compiles before mutation or timer arming; the prepared tree
   is the tree later promoted. `FirstCommit` implies an empty target.
   Quarantine is visible through persistent degraded health, cannot be
   overwritten by a new confirmed commit, and clears only after the explicit
   durable discard succeeds. Local interface and sampling indexing belts remain
   length-safe.
6. **Route-map guard equals renderer:** term count includes every family
   expansion, OR-product dimension, and reachable composed-chain member, while
   the shared highest-sequence/fit helper reserves exactly one terminal row.
   Both layers preserve saturating arithmetic.
7. **HA capacity consistency:** accepted definitions fit IDs 0..15; explicit
   dataplane bindings fit 1..15 and reference a definition in both node-effective
   views. BPF arrays, Go inventories, Rust epoch state, helper messages,
   heartbeat fields, and derived VRIDs agree. A compile error occurs before any
   snapshot or actuator mutation and never reuses
   `ForwardingSupported=false`.
8. **HA ordering:** an invalid live sync leaves active config, compiled config,
   helper maps, forwarding arm state, and acknowledgment generation unchanged.
   Fresh boot remains lifeline/default-deny. `UpdateRGActive` and lower belts
   still reject out-of-domain IDs before mutation.
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
12. **Wire and pinned-state portability:** no event ABI, helper protocol, BPF map
    size, or pinned-map migration is introduced by the recommended paths.
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
    but empty security identities, unsupported policy containers, and
    out-of-range RG definitions/bindings or bindings to undefined groups return
    the existing compile-failed class and enter lifeline/retain-previous
    behavior. Structurally malformed persisted JSON returns
    `ErrConfigDBUnreadable`; a malformed confirm target quarantines only that
    rollback record while preserving loaded active state.
17. **Unsupported policy shape is never omission:** only the canonical combined
    four-key zone-pair shape compiles; every other `from-zone`
    container fails before typed policy construction on strict and tolerant
    paths.
18. **SNMP intent is exact:** only canonical top-level `snmp` is accepted; every
    invalid compiler or hand-built runtime identity is omitted from the USM
    table, rejection metadata is a deterministic identity union, and a
    rejected-only config leaves no stale listener running.

## 8. Risk assessment

| Risk class | Rating | Why | Required mitigation |
|---|---|---|---|
| Behavioral regression | HIGH | Thirteen independent roots include security policy acceptance, SNMP auth, DDNS deletion, HA activation, and config loading | Separate PRs; fail-on-revert traces; strict/lenient paired tests; package-wide reruns after each config merge |
| Lifetime / borrow-checker | LOW | Only K003-01 changes Rust and it passes a copied byte already present in metadata; no ownership or shared-lifetime change | Rust unit tests, clippy/build, and packet-path smoke |
| Concurrency / lock ordering | MEDIUM | K003-16 repairs a race but a careless lock reuse can deadlock direct VIP reconciliation | Dedicated mutex; helper-only access; race tests and lock-scope review |
| Performance regression | LOW | One copied byte on a rare flowless path; all other work is cold path | No new packet reads/allocations; userspace throughput baseline and perf smoke for K003-01 only |
| State/ownership corruption | HIGH | DDNS wrong-backend delete and routing ownership loss are explicitly stateful | Same-family fingerprint proof, no credential fallback, retain-on-uncertainty, injected failure/retry tests |
| HA compatibility | HIGH | RG and hard security gates must reject both node-effective views before Store promotion, helper/map mutation, election effects, or peer acknowledgment; `ForwardingSupported=false` would disarm live forwarding | Fresh-boot and previous-good sync state-machine tests, definition/binding/membership validation, peer-only group fixtures, userspace HA reject/recovery smoke |
| Public API regression | MEDIUM | Route-map Go helpers gain required context, lifecycle strings change from false `deny` to `n/a`, and confirm quarantine gains one bounded SystemAction | Migrate every repository caller atomically; release notes; REST/gRPC/CLI/filter/action golden tests |
| Architectural mismatch | MEDIUM | Mega-batching repeats the #961/#946 Phase-2 dead-end pattern; RG widening would create a pinned-map migration project | Path A split; global RG clamp; no broad parser or ABI redesign |

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
  replacement semantics. Production `SetPath`/flat-command tests, not a
  hand-shaped AST alone, prove `set system snmp ...` fails on strict and
  tolerant paths with canonical syntax. Strict and lenient compiler tests prove
  intent is observed before lowering and a rejected identity is omitted
  everywhere; peer-only invalid users fail the originating strict commit;
  JSON/YAML projections and reconcile hash carry sorted nonsecret metadata.
  Runtime tables cover nil map values, empty keys, embedded-name/key mismatch,
  unknown protocols, compiler+runtime duplicate rejection, stable union/counts,
  and valid-to-invalid atomic removal. A rejected-only day-2 config stops the
  prior listener; a rejected-only boot never binds UDP/161. Packet tests prove
  noAuthNoPriv and authNoPriv requests are rejected when configured intent is
  stronger.
- **D / flowless ICMP:** IPv4 type 3/11/12 and IPv6 type 1/2/3/4 global admits;
  ND 133..137 where relevant; non-first fragment remains denied; unrelated ICMP
  remains denied; native-GRE and interface-NAT flowless entry coverage.
- **E / DDNS:** distinct v4/v6 fake servers; explicit backend-less v6 disable;
  both blocks removed; transient per-family factory failure; matching current
  fingerprint; matching previous-family fingerprint; mismatching and empty
  production fingerprints; disabled-but-configured endpoint identity; fixed
  updater empty-fingerprint compatibility and nonempty-fingerprint refusal;
  invalid family 0/5 plus family/address/type mismatch at load and selector;
  mixed-family owned rows in one pass; and restart with no executable historical
  updater. A multi-cycle A -> B trace injects a partial delete error, proves the
  A anchor survives, retries A on the next pass, and advances to B only after
  the A row is gone. An A -> B -> C rotation while A remains unresolved retains
  and alarms rather than guessing. Packet/operation
  logs prove no v4 updater receives a v6 delete or vice versa. Any surfaced
  updater error, including simulated partial forward/PTR deletion, retains
  ownership and performs no second-credential retry; established PTR
  NOTAUTH/REFUSED skip behavior is a pinned negative control. Source canaries
  forbid production reads or writes of representative `m.updater`
  outside the fixed-updater seam and forbid catalog/generation state.
- **F / LoadOverride:** flat valid input, braced hierarchical valid input,
  one-line hierarchy, singleton `sett` typo, unknown brace-less root, blank,
  full-line and inline hash/slash comments, single-line and multiline block
  comment rejection in flat mode, block-comment support in hierarchy, optional
  trailing semicolon, set-before-deactivate normalization, missing deactivate
  target, delete/activate rejection, mixed format rejection, typoed/malformed
  mid-file command, empty override, candidate byte equality and
  generation/dirty/lease invariance on failure.
- **G / AST bounds:** malformed active, candidate, rollback, and
  `confirmRecord.PrevTree` JSON is rejected before compile; null child and
  empty-Keys descendant active trees are `ErrConfigDBUnreadable`; quoted empty
  `Keys[0]` remains structurally accepted for semantic validation; malformed
  confirm keeps active unchanged, sets degraded health/metric, and neither arms
  nor deletes the record; structurally valid but semantically uncompilable
  future and expired `PrevTree` targets behave identically. A populated
  `FirstCommit=true` target quarantines; a `FirstCommit=false` empty target
  compiles normally. Retired-dataplane and control-character targets prove
  active load and confirm recovery use the same prepared clone, and expiry
  promotes exactly that clone. Legacy empty `GuardedHash` behavior remains;
  a stale guarded record is resolved before target semantics are interpreted.
  `CommitConfirmed` refuses while quarantined. The local and remote
  `discard-quarantined-confirm` command requires privileged interactive
  confirmation, refuses an armed or
  nonquarantined record, leaves active/candidate byte-identical, and clears the
  latch only after successful unlink plus directory fsync; injected unlink and
  fsync failures retain the record/latch. Handcrafted empty-Keys interface and sampling family nodes cannot
  panic their compilers; valid empty/populated JSON still loads; peer text sync
  is a negative reachability control; add malformed trees as fuzz seeds.
- **H / route-map:** term count equals actual rendered term rows for v4-only,
  v6-only, dual-stack, empty/undefined lists, mixed route-filter x mixed
  referenced-list products, multiple referenced names, community and AS-path
  products, and terminating/nonterminating composed chains; highest-sequence
  separately equals the renderer's final row at 65535 boundaries; no
  context-free safety caller or raw-count ceiling comparison remains.
- **I / RG:** definition IDs -1, 0, 15, 16, 155, 156, 255, and 256; explicit
  binding IDs 0, 1, 15, 16, malformed, and undefined; normal RETH,
  private-election, no-RETH, and unused definitions; node0-valid/node1-invalid
  apply-group cases for out-of-range and orphan bindings; interface-range
  inherited/overridden bindings; and repeated `chassis` roots where only the
  final typed definition set is authoritative. Tolerant fresh boot
  returns compile-failed and remains default-deny; previous-good -> invalid sync
  preserves active, compiled, maps, arm state, and acknowledgment -> valid
  recovery applies. A userspace compile seam snapshots link pins, shim selector
  calls, generation, attachment calls, inventory, maps, and helper requests and
  proves every value unchanged on typed RG rejection; lower compilers and
  `UpdateRGActive` receive equivalent pre-mutation tests. Constant drift
  canaries cover config/dataplane/BPF/shim/Rust capacity and preserve RG0 as a
  definition-only control group.
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
  recovery and malformed fresh boot, proving no helper-map mutation, demotion,
  or peer acknowledgment occurs for the rejected generation.
- K003-07 requires apply/rollback validation proving a rejected commit cannot
  replace the previous helper policy snapshot.
- K003-03 requires authoritative fake/isolated DNS endpoints with packet or
  operation logs proving every performed delete reached the owner fingerprint's
  endpoint and every no-authority row caused zero DNS writes.
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
- Widening RG capacity or migrating pinned BPF maps under the K003-10 bug fix.
- Retrying DDNS withdrawal across credential generations or redesigning the
  updater API to report separate forward/PTR component outcomes. The retained
  single-old-anchor contract deliberately alarms rather than guesses across a
  second unresolved endpoint rotation.
- Adding `system snmp` as a schema alias; canonical top-level `snmp` remains the
  only supported hierarchy.
- Changing Rust event wire layout or retroactively assigning permit/deny to
  lifecycle events.
- Refactoring all logging formatters beyond central action applicability.
- Unrelated DDNS ownership, SNMP feature expansion, FRR rendering, or routing
  reconciliation improvements discovered while implementing a child issue.

## 11. Resolved adversarial decisions

Rounds one through four closed the design choices rather than delegating them
to implementors:

1. Path A remains the recommendation. The config-heavy workstreams are separate
   PRs but merge serially in waves; no root needs an atomic cross-package batch.
2. The current issue snapshot found exact ownership only for K003-02 (#6548).
   K003-05 is a live honesty/security gap with its own child issue; #4313 is the
   related doctrine umbrella, not an exact owner. The fix rejects rather than
   implements the noncanonical nested hierarchy.
3. Flat override accepts complete `set` plus `deactivate` artifacts and rejects
   destructive `delete`/`activate` verbs. This honors the documented API without
   inventing replacement-tree edit semantics. Hierarchical mode requires
   comment/string-aware structural braces; nonempty brace-less input without a
   recognized flat verb is rejected as ambiguous.
4. Sixteen definition slots, IDs 0..15, is the current global product limit.
   Explicit dataplane bindings are 1..15 and must reference a definition; zero
   remains the unbound/control-group sentinel. A 256-entry ABI/pinned-map
   migration is out of scope and requires separate research if product demand
   appears.
5. Production DDNS uses only the exact same-family current or retained previous
   updater whose nonempty endpoint fingerprint matches the owned row. Anchor
   rotation happens after reconciliation and is deferred while a retained row
   depends on the old endpoint. Fixed-constructor mode is an explicit
   compatibility authority only for its own empty-fingerprint rows. There is no
   representative-updater or credential-generation fallback. Partial
   forward/PTR credential fallback requires a different operation-result API
   and is deliberately out of scope; uncertainty retains ownership and alarms.
6. SNMPv3 intent is validated only at canonical top-level `snmp` before compiler
   lowering can erase malformed presence; `system snmp` fails loudly. The
   result flows through section lowering, nonsecret JSON/YAML metadata,
   reconcile hashing, deterministic compiler/runtime rejection union, and an
   independently validated atomic runtime swap. A rejected-only config stops
   the listener instead of retaining an empty agent.
7. Lifecycle action applicability is a positive event-type allowlist applied
   before daemon slog or record construction. Structured APIs preserve their
   scalar field shape with `"n/a"`; lifecycle human text omits the key
   and binary uses 0xff. Existing formatter-specific behavior for real action
   events is preserved.
8. VIP warning state has one dedicated mutex and helper-only access. It adds no
   lock-order edge to `directVIPMu` or `applySem`.
9. Persisted JSON gets one minimum structural validator in `readTreeMeta` plus
   the same check for `confirmRecord.PrevTree`. Confirm recovery shares active
   load's retired-dataplane/control-character compatibility preparation, and
   promotes the exact prepared clone it compiled. `FirstCommit` requires an
   empty target. Failure latches degraded health while preserving active state
   and forensic bytes; only the named durable discard operation clears it.
   K003-04 owns the interface and sampling indexing belts.
10. Route-map term counters require `PolicyOptionsConfig`, while one shared
    highest-sequence/fit helper owns the terminal-row reservation. No
    conservative wrapper or raw-count comparison remains in a safety decision.
11. The two Low-severity roots remain worth bounded child issues: repeated
    address-book blocks silently lose configured objects, and false lifecycle
    deny values corrupt SIEM/forensic classification. Their independent PRs may
    still receive `PLAN-KILL` if a new reproduction disproves those impacts.
12. Out-of-range/orphan RG definitions and bindings are compile failures on
    strict and tolerant paths. Raw syntax is checked after canonical group and
    interface-range expansion; range/membership is checked on the final typed
    config. The exported runtime belt executes before pin, shim, generation,
    attachment, inventory, map, or helper side effects. The failure never sets
    `ForwardingSupported=false`; invalid live sync retains the exact previous
    generation and fresh boot remains lifeline/default-deny.
13. The B/C/I/M action-agnostic hard gates run against both canonically prepared
    node-effective trees before strict promotion. Peer validation uses the same
    section lowering and typed semantics as local compilation while unrelated
    compatibility warnings remain lenient. This is a focused extension of the
    existing peer-effective SNAT precedent, not a global conversion of every
    lenient warning into a peer commit failure.
14. Only the canonical four-key zone-pair AST is accepted. Repository history
    has no authentic legacy nested persistence fixture, so the permissive
    compiler fallback is removed instead of being enshrined by a new fixture.
15. A quarantined confirm record is never silently overwritten. The explicit
    `discard-quarantined-confirm` operation is a confirmed privileged
    maintenance action, has no
    active/candidate mutation, and clears degraded health only after durable
    removal succeeds.

Manual approval of this plan accepts those product choices. A material change to
any one returns that child workstream to plan review rather than being improvised
inside implementation.
