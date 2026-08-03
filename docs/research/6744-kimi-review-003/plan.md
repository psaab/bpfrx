# Plan of Action - #6744: Revalidate and split `kimi-review-003`

## 1. Status

**DRAFT v3 - round-two major findings addressed; pending round-three review**

- Issue: [#6744](https://github.com/psaab/xpf/issues/6744)
- Source report: `/tmp/kimi-review-003.md`
- Base: `origin/master` at `ad959117748181dabe46b8ddc2827de670380cea`
- Branch: `research/6744-kimi-review-003`
- Revision: 3
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
| K003-10 | RG IDs beyond the 16-entry dataplane domain can commit but never become active | **PARTIAL** | High | Medium | The dataplane cap mismatch is live. The blanket `16..255` wording is too broad: RETH/VRRP rejects 156..255 in normal RETH mode, while private/no-RETH and unused definitions have different reachability. Every RG that drives userspace-shim HA state must be in 0..15 |
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
- prevent wrong-endpoint DNS deletion and permanent loss of cleanup authority;
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

Both compile paths call the same function after inactive stripping and group
expansion, so their accepted identity grammar cannot drift.

### 5.4 Workstream C - enforce SNMPv3 configured security intent (K003-13)

Configured intent must be validated on the apply-groups-expanded AST **before**
`compileSNMPv3` lowers it. The typed `SNMPv3User` is too late: today a password
is copied only when nested under a recognized protocol node, so legitimate
noAuthNoPriv and malformed password-only syntax can collapse to the same typed
object.

The AST pass walks every `system snmp v3 usm local-engine user` instance and
records presence without copying secret values into diagnostics:

- no protocol and no password is valid noAuthNoPriv;
- exactly one authentication protocol requires exactly one authentication
  password;
- exactly one privacy protocol requires an authentication protocol/password
  and exactly one privacy password;
- any password without its corresponding protocol is rejected;
- distinct/repeated protocol selections or repeated password declarations for
  one single-valued slot are rejected rather than resolved by source order.
  Exact duplicate set commands that the AST has already coalesced remain one
  logical declaration.

```go
type SNMPv3UserRejection struct {
    Name   string
    Reason string // path/field only; never a secret value
}

type SNMPv3IntentResult struct {
    Rejected []SNMPv3UserRejection
}

func validateSNMPv3Intent(root *ConfigTree) SNMPv3IntentResult
```

Strict compile returns a path-qualified error when `Rejected` is nonempty.
Lenient persisted loading keeps the source tree for diagnosis, compiles only
valid users, appends stable warnings, and carries the sorted non-secret
rejections in `SNMPConfig.RejectedV3Users`. This metadata is the durable
handoff between the pre-lowering validator and runtime reconcile; runtime must
not try to reconstruct erased intent from a typed user.

Runtime remains a second belt. `deriveV3Users` builds a complete replacement
table and rejects any internally inconsistent typed user before taking
`cfgMu`; `UpdateConfig` swaps config plus users together. A valid user changed
to an invalid definition therefore disappears in the same atomic swap, with no
request observing the new config and old keys. Startup/day-2 reconcile emits a
single structured warning containing configured, installed, and omitted counts
and sorted user names, never passwords. A config containing only rejected v3
users may leave UDP/161 listening, but its empty USM table answers no request.
Do not infer operator intent from `authKey != nil`, `privKey != nil`, or empty
typed protocol fields.

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

Delete the cross-family `m.updater` fallback from family turn-off. Replace the
single previous-cycle slot with a per-family, fingerprint-keyed in-memory
catalog of **credential generations**. A backend fingerprint proves endpoint
identity but intentionally excludes TSIG/API secrets; one map value per
fingerprint would let a bad rotated credential overwrite the only working
historical authority.

```go
type authorityGenerationID uint64

type withdrawalAuthority struct {
    id          authorityGenerationID
    fingerprint string
    credentialKey [32]byte // process-keyed HMAC; never persisted or logged
    updater     DNSUpdater
}

// [0] is IPv4 and [1] is IPv6; guarded by Manager.mu.
withdrawalByFingerprint [2]map[string][]withdrawalAuthority
authorityByOwnedRecord  map[ownedRecordKey]authorityGenerationID
authorityCatalogKey     [32]byte

func (m *Manager) updaterForOwnedWithdrawalLocked(
    family int,
    owned ownedRecord,
    env reconcileEnv,
) ([]withdrawalAuthority, bool)
```

Selection order:

1. the exact in-process authority generation bound when this process published
   or adopted the owned record;
2. other same-family generations under the exact endpoint fingerprint,
   preferring the current generation and then newest to oldest;
3. after restart, when generation bindings are intentionally absent, the
   current same-family updater only if its fingerprint exactly matches the
   persisted ownership fingerprint;
4. no authority: retain ownership, increment the orphan/backend-mismatch alarm,
   and skip republish of the same identity this cycle.

Bind `authorityByOwnedRecord` only after a successful upsert/adoption by that
generation. On withdrawal, try the bound generation first. An explicit
retryable authentication failure may advance to another generation for the
same endpoint fingerprint; ownership conflicts, malformed requests, and a
different fingerprint never do. A failed bad-new/good-old rotation therefore
falls back to the still-working old credential without ever targeting another
server, while a good-new credential can retire an RR after the authoritative
server stops accepting the old secret.

Retry classification is typed, not string-based:

```go
func isAuthorityCredentialRetryable(err error) bool
```

It accepts wrapped `dns.ErrAuth`, `dns.ErrSig`, and typed RFC2136
`NOTAUTH`/`REFUSED` `rcodeErr` values only. It rejects timeouts, cancellation,
malformed records, DHCID ownership conflicts, and arbitrary backend errors.
Every retry remains within the exact same family and endpoint fingerprint.

At manager construction, generate `authorityCatalogKey` with `crypto/rand`; a
failure puts DDNS into its existing fail-closed degraded state. For each
resolved backend, derive `credentialKey` as HMAC-SHA256 over a canonical,
length-delimited encoding of every endpoint and credential field (including
revealed secret material) using that process key. Compare keys in constant time.
The key is only an in-memory deduplication token: never serialize, expose, or
log it. This is required because the updater factory reconstructs an object on
every reconcile, so pointer/interface identity would create an unbounded new
generation each cycle.

Resolution alone does not promote a new credential into history: a syntactically
valid but rejected secret must not accumulate forever. Treat the current updater
as a transient candidate, and add/reuse its generation only after an
authenticated DNS operation succeeds. A successful upsert/reassert binds every
affected owned record to that generation, proving the new credential can act at
the endpoint; a failed rotation leaves the older binding intact. Keep a catalog
generation while an in-memory record binding references it. Garbage-collect an
unbound generation only after a successful ownership-state save; the transient
current updater remains directly available without requiring catalog retention.
A persisted record with no post-restart binding may try only the transient
current updater when its fingerprint matches, and gains a binding only after a
successful authenticated reassert.
A failed delete therefore retains both the ownership key and every potentially
usable same-endpoint authority. This handles uninterrupted A -> B -> C endpoint
transitions and S1 -> S2 credential rotations.

The catalog is deliberately not persisted: serializing credentials into the
DDNS ownership file would create a new secret store. After restart, a historical
fingerprint that the current config cannot reconstruct has no executable
authority; retain it and alarm exactly as #5814 already specifies. This
workstream guarantees **never delete at an unproved endpoint**, not magical
post-restart cleanup after the operator removes the only credential source.
Unknown pre-fingerprint records likewise retain and alarm rather than using a
representative updater. Generation IDs and credentials are process-local: do
not serialize or log either. Catalog size is bounded by current backends plus
the credential generations referenced by in-process ownership and the distinct
fingerprints still present in durable ownership.

The no-authority branch is side-effect free with respect to publication and
catalog history: it never registers a fallback updater, advances an owned
record's fingerprint, erases an older catalog entry, or saves ownership as if
cleanup succeeded.

### 5.7 Workstream F - make `LoadOverride` format handling explicit and atomic (K003-09)

Use constrained F1 and remove F2 as an implementation choice. `LoadOverride`
already promises a complete flat `set` artifact, so honor that contract without
pretending an edit transaction against an empty tree is a full configuration.

The classifier lexes comments and quoted strings before classifying, then scans
every significant line before mutation. A significant flat line is neither
blank nor a full-line `#`/`//` comment. Inline `#` or `//` comments and one
optional trailing semicolon are accepted through the existing `ParseSetVerb`
lexer contract. Multiline `/* ... */` comments are rejected in flat mode
because replay is deliberately one command per physical line; they remain
valid in hierarchical mode.

1. If no line begins with a recognized flat verb, select hierarchical mode
   only when the comment/string-aware lexer finds structural braces. A one-line
   hierarchy such as `system { host-name fw; }` is valid. A nonempty brace-less
   body has no positive hierarchy evidence and is rejected as ambiguous; in
   particular `sett system host-name fw` cannot become an implicit hierarchy
   leaf at EOF. Comments-only input remains a valid empty override.
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
record. This is an inert quarantine with a persistent health/log diagnostic,
not silent cleanup of forensic state.

```go
func ValidatePersistedTreeShape(tree *ConfigTree) error
```

Peer HA sync is out of this trace because it reparses text and cannot create an
empty-key node. Audit the remainder of persisted-JSON compiler entry points for
unguarded `Keys[n]` reads, but do not turn this workstream into a parser rewrite.

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

Select a global product limit of 16 groups, IDs 0..15. Userspace inventory seeds
every configured RG, including an otherwise unused definition, so a narrower
"dataplane-bound" reachability predicate is not real. Strict validation rejects
every out-of-range `chassis cluster redundancy-group` definition **and every
interface RG binding** before typed snapshot construction. Checking definitions
alone is insufficient because malformed/legacy persisted trees can carry a
binding whose definition is absent or differently shaped.

```go
// pkg/config: lowest-layer product contract.
const MaxDataplaneRedundancyGroups = 16

func ValidateDataplaneRGID(id int) error
```

`pkg/dataplane.MaxRedundancyGroups` becomes an alias of the config constant.
Source/ABI canaries prove equality with BPF `MAX_REDUNDANCY_GROUPS`, shim map
specs, and Rust `MAX_RG_EPOCHS`; widening remains a separately researched pinned
map/protocol migration.

This is an action-agnostic semantic safety error, not a class-II capability.
Strict and tolerant compilers return the same range error before inventory,
map, helper, HA-election, or acknowledgment side effects. Do **not** set
`ForwardingSupported=false`: that value actively disarms a running helper and
cannot represent “reject this generation and retain previous-good.”

- `Store.Load` keeps the parsed source for diagnosis but returns the existing
  compile-failed classification; a fresh boot stays in lifeline/default-deny
  with no interface takeover.
- `Store.SyncApply` rejects atomically, does not acknowledge the invalid peer
  generation, and retains byte-identical active/compiled state and helper maps.
- A later valid generation compiles and applies normally; there is no sticky
  quarantine bit.

Runtime `UpdateRGActive`, inventory build, map sync, and helper publication
remain belts and reject IDs >=16 before any partial mutation. The diagnostic
distinguishes this product limit from the heartbeat uint8 and RETH-derived VRID
limits. No path selectively drops an RG or one of its interface bindings.

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
entry points. The surface contract is explicit:

| Surface | Lifecycle action contract |
|---|---|
| Standard and structured syslog | omit the action attribute |
| Flow trace text | omit `action=` |
| SSE text (`formatLogMessage`) | omit `action=` |
| Local CLI human text | omit the action column/token as it does today |
| Remote CLI / monitor human text | omit the action column/token |
| REST JSON | retain required scalar field as `"n/a"` |
| SSE structured JSON | retain required scalar field as `"n/a"` |
| gRPC/protobuf | retain existing scalar field as `"n/a"` |
| Binary log | encode `0xff` for OPEN and CLOSE |

Event filtering uses normalized applicability: `action=deny` excludes lifecycle
records and `action=n/a` selects them. POLICY_DENY, FILTER_LOG, and SCREEN_DROP
retain their existing action and severity. Cover the live ring path and
decode-only path so trace, event buffer, both SSE renderers, APIs, CLIs,
filters, and binary cannot diverge. Do not change the Rust event-stream wire
layout or the intentional producer byte zero.

### 5.14 Workstream M - reject unsupported nested zone-policy containers (K003-05)

Add an AST-shape gate after inactive stripping and apply-groups expansion but
before `compilePolicies` can silently skip an unrecognized container. For every
direct `security policies from-zone` child, the gate accepts:

- the current canonical representation with exact keys
  `from-zone <src> to-zone <dst>`, emitted by both the hierarchy parser and the
  current schema-aware `SetPath`; and
- only where backward-compatibility fixtures prove it was emitted by an older
  persistence format, the legacy pre-schema SetPath chain whose `from-zone`
  node contains source instances, each containing `to-zone` and destination
  instances. This is a persisted-AST compatibility shape, not the current flat
  syntax contract.

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
closed-world doctrine but has its own child issue and rollback boundary.

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

Intentional behavior changes are fail-loud validation, not API removal:

- malformed empty security identities stop committing;
- unsupported nested policy containers stop committing under a child issue
  linked to #4313;
- every RG definition or interface binding above 15 stops committing under the
  selected global limit;
- mixed-format override input is rejected atomically;
- invalid SNMPv3 credential combinations stop installing a downgraded user;
- lifecycle APIs stop calling a non-applicable action `deny` and return the
  existing string field as `"n/a"`.

## 7. Hidden invariants the changes must preserve

1. **Commit/apply equivalence:** anything accepted by strict Go compilation must
   be representable by Rust snapshot hydration. Lenient persisted/HA input may
   warn and quarantine, but it must not panic, widen scope, or install stale
   permissive state as if apply succeeded.
2. **Fail-closed without false deny:** unreadable ICMP fragments remain denied;
   readable ICMP errors in the established global class remain admitted.
3. **DDNS cleanup authority:** only an executable credential generation for
   the exact same-family endpoint fingerprint may delete an owned RR. A secret
   rotation never overwrites older authority. On uncertainty, retain ownership
   and alarm; never delete at another endpoint or erase the only usable key.
4. **Atomic config load:** parsing/replay happens on a detached tree. On any
   error, candidate bytes, generation, dirty bit, lock lease, and active config
   remain unchanged.
5. **Persisted AST integrity:** an invalid JSON node tree is rejected at every
   deserialization boundary (`active`, `candidate`, JSON rollback, and confirm
   rollback target) and cannot reach an unsafe compiler walk; local indexing
   belts still remain length-safe.
6. **Route-map guard equals renderer:** term count includes every family
   expansion, OR-product dimension, and reachable composed-chain member, while
   the shared highest-sequence/fit helper reserves exactly one terminal row.
   Both layers preserve saturating arithmetic.
7. **HA capacity consistency:** accepted definitions and bindings fit BPF
   arrays, Go inventories, Rust epoch state, helper messages, heartbeat fields,
   and derived VRIDs. A compile range error occurs before any snapshot or
   actuator mutation and never reuses `ForwardingSupported=false`.
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
11. **Lifecycle action semantics:** absence of a forwarding action is not deny,
    but real deny/reject/drop records retain their action on every surface.
12. **Wire and pinned-state portability:** no event ABI, helper protocol, BPF map
    size, or pinned-map migration is introduced by the recommended paths.
13. **Allocation and hot-path shape:** K003-01 uses existing parsed metadata;
    none of the other workstreams add packet-path allocation or shared-state
    contention.
14. **Determinism:** strict validation and duplicate diagnostics remain stable
    across map iteration order, repeated blocks, and HA replay.
15. **Tolerant-path safety classes:** legacy semantic violations normally warn,
    but empty security identities, unsupported policy containers, and
    out-of-range RG definitions/bindings return the existing compile-failed
    class and enter lifeline/retain-previous behavior. Structurally malformed
    persisted JSON returns `ErrConfigDBUnreadable`; a malformed confirm target
    quarantines only that rollback record while preserving loaded active state.
16. **Unsupported policy shape is never omission:** the canonical combined and
    explicitly fixture-proven legacy persisted zone-pair shapes compile
    identically; every other `from-zone` container fails before typed policy
    construction on strict and tolerant paths.

## 8. Risk assessment

| Risk class | Rating | Why | Required mitigation |
|---|---|---|---|
| Behavioral regression | HIGH | Thirteen independent roots include security policy acceptance, SNMP auth, DDNS deletion, HA activation, and config loading | Separate PRs; fail-on-revert traces; strict/lenient paired tests; package-wide reruns after each config merge |
| Lifetime / borrow-checker | LOW | Only K003-01 changes Rust and it passes a copied byte already present in metadata; no ownership or shared-lifetime change | Rust unit tests, clippy/build, and packet-path smoke |
| Concurrency / lock ordering | MEDIUM | K003-16 repairs a race but a careless lock reuse can deadlock direct VIP reconciliation | Dedicated mutex; helper-only access; race tests and lock-scope review |
| Performance regression | LOW | One copied byte on a rare flowless path; all other work is cold path | No new packet reads/allocations; userspace throughput baseline and perf smoke for K003-01 only |
| State/ownership corruption | HIGH | DDNS wrong-backend delete and routing ownership loss are explicitly stateful | Fingerprint proof, retain-on-uncertainty, injected failure/retry tests |
| HA compatibility | HIGH | RG rejection must happen before Store promotion, helper/map mutation, election effects, or peer acknowledgment; `ForwardingSupported=false` would disarm live forwarding | Fresh-boot and previous-good sync state-machine tests, definition+binding validation, userspace HA reject/recovery smoke |
| Public API regression | MEDIUM | Route-map Go helpers gain required context and lifecycle strings change from false `deny` to `n/a` | Migrate every repository caller atomically; release notes; REST/gRPC/CLI/filter golden tests |
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
  previous active/compiled snapshot; no userspace or host-inbound publication.
- **C / SNMP:** AST-level cases for valid noAuthNoPriv, password-only,
  protocol-without-password, privacy-without-auth, privacy-without-password,
  duplicate/conflicting protocols, and repeated password leaves; strict and
  lenient compiler tests prove intent is observed before lowering and only
  non-secret rejection metadata survives; valid-to-invalid hot reconfigure
  proves the old user disappears atomically; packet tests prove noAuthNoPriv
  and authNoPriv requests are rejected when configured intent is stronger.
- **D / flowless ICMP:** IPv4 type 3/11/12 and IPv6 type 1/2/3/4 global admits;
  ND 133..137 where relevant; non-first fragment remains denied; unrelated ICMP
  remains denied; native-GRE and interface-NAT flowless entry coverage.
- **E / DDNS:** distinct v4/v6 fake servers; explicit backend-less v6 disable;
  both blocks removed; retained-server disable (negative control that must still
  choose the correct updater); updater-construction failure; matching/mismatching
  fingerprints; A -> B -> C with A deletion failure; same-fingerprint
  bad-S2/good-S1 and good-S2/bad-S1 credential rotations; exact generation is
  tried first and retry occurs only on classified retryable failures; authority
  survives repeated transitions and delete retry; unchanged credentials across
  repeated updater reconstruction do not grow the catalog; catalog-key entropy
  failure degrades fail-closed; generation GC only after
  ownership save and zero in-memory references; restart with no historical
  binding; unknown fingerprint; ownership retained on every ambiguity; no
  generation ID or secret serialized/logged; fallback resolution never changes
  a fingerprint or erases older authority.
- **F / LoadOverride:** flat valid input, braced hierarchical valid input,
  one-line hierarchy, singleton `sett` typo, unknown brace-less root, blank,
  full-line and inline comments, optional trailing semicolon, multiline block
  comment rejection in flat mode, set-before-deactivate normalization, missing
  deactivate target, delete/activate rejection, mixed format rejection,
  typoed/malformed mid-file command, empty override, candidate byte equality and
  generation/dirty/lease invariance on failure.
- **G / AST bounds:** malformed active, candidate, rollback, and
  `confirmRecord.PrevTree` JSON is rejected before compile; null child and
  empty-Keys descendant active trees are `ErrConfigDBUnreadable`; quoted empty
  `Keys[0]` remains structurally accepted for semantic validation; malformed
  confirm keeps active unchanged and neither arms nor deletes the record;
  future/expired deadlines, `FirstCommit`, legacy empty `GuardedHash`, and stale
  guarded records retain existing behavior; handcrafted empty-Keys family node
  cannot panic the compiler; valid empty/populated JSON still loads; peer text
  sync is a negative reachability control; add malformed trees as fuzz seeds.
- **H / route-map:** term count equals actual rendered term rows for v4-only,
  v6-only, dual-stack, empty/undefined lists, mixed route-filter x mixed
  referenced-list products, multiple referenced names, community and AS-path
  products, and terminating/nonterminating composed chains; highest-sequence
  separately equals the renderer's final row at 65535 boundaries; no
  context-free safety caller or raw-count ceiling comparison remains.
- **I / RG:** strict IDs -1, 0, 15, 16, 155, 156, 255, and 256 across normal
  RETH, private-election, no-RETH, unused definition, and bindings with absent
  or malformed definitions; tolerant fresh boot returns compile-failed and
  remains default-deny; previous-good -> invalid sync preserves active,
  compiled, maps, arm state, and acknowledgment -> valid recovery applies;
  runtime belts reject before mutation; constant drift canaries cover
  config/dataplane/BPF/shim/Rust capacity.
- **J / address book:** repeated outer blocks, repeated global blocks, duplicate
  legal entries, duplicate illegal names, references to first and later blocks,
  deterministic diagnostics.
- **K / routing:** genuine not-found, transient `LinkByName`, `LinkDel` failure,
  subsequent retry recovery, and ownership-map assertions for bond and tunnel.
- **L / lifecycle action:** golden events originating from actual Rust wire
  bytes for OPEN/CLOSE across both decode paths and every row of the surface
  matrix: both SSE renderers, both CLIs, monitor text, trace, standard and
  structured syslog, REST, gRPC, and binary. Exact filters prove deny excludes
  lifecycle and n/a selects it. Unknown future event types default to
  not-applicable; real policy deny/filter/screen events retain action/severity.
- **M / nested policy shape:** the canonical combined form remains accepted;
  legacy nested-chain acceptance requires a checked-in pre-schema persistence
  fixture, not a newly handcrafted tree. Nested/partial/malformed containers
  fail in both strict and tolerant compilers with the canonical syntax in the
  message; persisted boot enters compile-failed lifeline/default-deny and
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
  operation logs proving every delete reached the owner fingerprint's endpoint.
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
- Changing Rust event wire layout or retroactively assigning permit/deny to
  lifecycle events.
- Refactoring all logging formatters beyond central action applicability.
- Unrelated DDNS ownership, SNMP feature expansion, FRR rendering, or routing
  reconciliation improvements discovered while implementing a child issue.

## 11. Resolved adversarial decisions

Rounds one and two closed the design choices rather than delegating them to
implementors:

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
4. Sixteen RGs is the current global product limit. A 256-entry ABI/pinned-map
   migration is out of scope and requires separate research if product demand
   appears.
5. DDNS uses a same-family, fingerprint-keyed catalog with multiple process-local
   credential generations and exact per-record bindings. Historical authority
   and generation IDs are not persisted with secrets; restart uncertainty
   retains ownership and alarms.
6. SNMPv3 intent is validated before compiler lowering can erase malformed
   presence. An invalid user is omitted from runtime registration on tolerant
   load and named through non-secret rejection metadata; there is no disabled
   protocol object that could accidentally answer requests.
7. Lifecycle action applicability is a positive event-type allowlist. Structured
   APIs preserve their scalar field shape with `"n/a"`; every human text path
   omits the key and binary uses 0xff.
8. VIP warning state has one dedicated mutex and helper-only access. It adds no
   lock-order edge to `directVIPMu` or `applySem`.
9. Persisted JSON gets one minimum structural validator in `readTreeMeta`, plus
   the same check for `confirmRecord.PrevTree`; K003-04 still owns the local
   compiler indexing belt and bounded persistence hardening.
10. Route-map term counters require `PolicyOptionsConfig`, while one shared
    highest-sequence/fit helper owns the terminal-row reservation. No
    conservative wrapper or raw-count comparison remains in a safety decision.
11. The two Low-severity roots remain worth bounded child issues: repeated
    address-book blocks silently lose configured objects, and false lifecycle
    deny values corrupt SIEM/forensic classification. Their independent PRs may
    still receive `PLAN-KILL` if a new reproduction disproves those impacts.
12. Out-of-range RG definitions or bindings are compile failures on strict and
    tolerant paths. They never set `ForwardingSupported=false`; invalid live
    sync retains the exact previous generation and fresh boot remains
    lifeline/default-deny.

Manual approval of this plan accepts those product choices. A material change to
any one returns that child workstream to plan review rather than being improvised
inside implementation.
