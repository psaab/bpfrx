# Plan of Action - #6744: Revalidate and split `kimi-review-003`

## 1. Status

**DRAFT v1 - pending adversarial plan review**

- Issue: [#6744](https://github.com/psaab/xpf/issues/6744)
- Source report: `/tmp/kimi-review-003.md`
- Base: `origin/master` at `ad959117748181dabe46b8ddc2827de670380cea`
- Branch: `research/6744-kimi-review-003`
- Revision: 1
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
| K003-05 | Nested `from-zone X { to-zone Y { ... } }` is accepted and silently omitted | **DUPLICATE** | High | Medium | The omission is real, but the report's vSRX parity premise is false: Junos documents one combined `from-zone X to-zone Y` hierarchy. Open [#4313](https://github.com/psaab/xpf/issues/4313) owns fail-loud rejection of unsupported shapes under schema subtrees |
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
| K003-16 | `vipWarnedIfaces` reset and mutation use unrelated synchronization | **LIVE** | High | High | `pkg/daemon/daemon_apply.go` resets the map under `applySem`; `daemon_ha_vip.go` accesses it under other call-path locks. A reset between lazy-init/check and assignment can panic with `assignment to entry in nil map` |
| K003-C | 128 low-materiality cohort survivors | **UNACTIONABLE** | High | None | The report neither lists them nor preserves the batch artifacts. A number and category summary cannot be reproduced, deduplicated, or reviewed |

Net result: 12 live claims, one partial claim, two current duplicates, one
refuted claim, and one unactionable cohort. K003-14 and K003-15 are one semantic
root, leaving **12 independent retained root causes**.

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

### 4.2 Existing owner and rejected inputs

- K003-02 stays on open issue #6548. This research must not open a second issue
  or implementation PR for it. Before engineering, correct that issue's wording:
  `io.EOF` is the successful terminal-load terminator; `readline.ErrInterrupt`
  and every other read error abort and discard the partial body.
- K003-05 stays on open umbrella #4313. This research must not create a
  vSRX-parity implementation for a syntax shape the official hierarchy does not
  define. The required behavior is fail-loud unsupported-shape handling under
  #4313's per-subtree closed-world design.
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

Cost: 12 issues and PRs, plus explicit merge ordering for the compiler slices.

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

Add an AST-level strict validator that runs before typed normalization can erase
empty list elements. It must reject:

- an empty `security-zone` definition;
- empty concrete `from-zone` and `to-zone` keys;
- an empty policy name;
- empty elements in global policy `match from-zone` / `to-zone` lists.

Remove `""` from `policyZoneSpecialTokens`; retain only meaningful tokens such
as `any` and `junos-host`. The lenient load/HA-sync path emits deterministic
warnings and relies on the existing Rust fail-closed preflight. It must never
turn an authored empty scope into `nil`/wildcard.

```go
func validateNonEmptySecurityIdentitiesStrict(root *Node) error
func warnEmptySecurityIdentitiesLenient(root *Node) []string
```

The strict and lenient walkers should share one collector so their accepted
identity grammar cannot drift.

### 5.4 Workstream C - enforce SNMPv3 configured security intent (K003-13)

Validation rules:

- an authentication protocol requires an authentication password;
- a privacy protocol requires both authentication protocol/password and a
  privacy password;
- a password without its protocol is rejected rather than silently ignored.

Strict commit rejects. Lenient persisted/peer loading warns and quarantines the
invalid user instead of installing a lower-security user. Runtime remains a
belt: calculate the required level from configured protocol intent before key
derivation, and never register a user if the required key set is incomplete.

```go
type v3RequiredLevel uint8

func requiredV3Level(cfg config.SNMPV3User) (v3RequiredLevel, error)
func deriveV3User(cfg config.SNMPV3User, engineID []byte) (*usmUser, error)
```

Do not infer operator intent from `authKey != nil` or `privKey != nil`.

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

Delete the cross-family `m.updater` fallback from family turn-off. For each owned
record, select a withdrawal updater only when an updater fingerprint proves it
is the backend that published that record:

```go
func (m *Manager) updaterForOwnedWithdrawal(
    family int,
    owned OwnedRecord,
    env reconcileEnv,
) (Updater, bool)
```

Selection order:

1. current family updater when its fingerprint equals
   `owned.BackendFingerprint`;
2. previous updater for that same family when `prevFP` equals the owned
   fingerprint;
3. no updater: retain ownership, increment the orphan/backend-mismatch alarm,
   and skip republish of the same identity this cycle.

Never infer cleanup authority from a representative updater or from family
alone. Advance `lastLiveUpdater[idx]` and `lastLiveFP[idx]` in lockstep only
after updater resolution. This composes with #5814's transition behavior.

### 5.7 Workstream F - make `LoadOverride` format handling explicit and atomic (K003-09)

Two viable local designs exist:

- **F1, recommended:** honor the existing API documentation. Detect flat input,
  replay every validated line into a new empty tree using the same helpers as
  `LoadMergeAs`/`LoadSetAs`, and swap `s.candidate` only after all lines succeed.
- **F2:** reject flat input with a line-numbered message directing callers to
  `load set`, and correct the public documentation.

F1 avoids a breaking behavior change and matches the current doc contract:

```go
func parseOverride(content string) (*config.Node, error) {
    if detectFlatConfig(content) {
        working := config.NewRoot()
        if err := applyFlatLinesAtomically(working, content); err != nil {
            return nil, err
        }
        return working, nil
    }
    return parseHierarchicalStrict(content)
}
```

Format selection must reject mixed flat/hierarchical non-comment lines. Failed
loads leave candidate bytes, generation, dirty state, and lease timestamp
unchanged.

### 5.8 Workstream G - validate persisted AST shape and retain compiler belts (K003-04)

Apply the established #4827 compiler idiom:

```go
afName := afNode.Name() // safe for empty Keys
if len(afNode.Keys) >= 2 {
    afName = afNode.Keys[1]
}
```

The compiler guard is defense in depth, not the primary persisted-data contract.
After JSON unmarshal and before a persisted candidate/active tree reaches any
compiler, recursively validate the structural minimum that every `Node` has a
non-empty `Keys` slice and non-empty first key. A malformed persisted tree
returns a typed load error so daemon bring-up takes the existing safe bootstrap /
lifeline path; it must not boot a partially omitted interface configuration.

```go
func ValidatePersistedNodeShape(root *Node) error
```

Peer HA sync is out of this trace because it reparses text and cannot create an
empty-key node. Audit the remainder of persisted-JSON compiler entry points for
unguarded `Keys[n]` reads, but do not turn this workstream into a parser rewrite.

### 5.9 Workstream H - share exact route-map expansion cardinality (K003-08)

The guard must use the same family expansion as the renderer. Move the family
reference count into `pkg/config` or a dependency-neutral callback so `pkg/frr`
and validation cannot implement separate formulas.

```go
func RouteMapSequenceCountExact(
    po *PolicyOptionsConfig,
    ps *PolicyStatement,
) uint64

func ComposedChainSequenceCountExact(
    po *PolicyOptionsConfig,
    chain []*PolicyStatement,
) uint64
```

Retain existing exported signatures for source compatibility, but remove them
from safety decisions. They may return a documented conservative upper bound
(two references per non-empty prefix-list name) when no policy-options context
is available. Strict gates and both FRR render belts must call the exact helpers.
Saturating arithmetic and the trailing default sequence remain included.

### 5.10 Workstream I - align accepted RG IDs with dataplane capacity (K003-10)

Two options exist:

- **I1, recommended:** reject any RG definition or interface binding that can
  reach userspace-shim HA state with ID outside 0..15. Add a shared Go capacity
  constant and cross-language drift canaries for the BPF map and Rust epoch
  domain. Lenient load warns and quarantines the invalid RG/interface binding;
  runtime methods return an explicit capacity error before touching maps.
- **I2:** widen BPF maps, pinned-map ABI, Go inventories, Rust arrays, epoch
  encoding, helper protocol, and migration behavior to 256 entries.

I2 is not a bug-fix-sized change and risks incompatible pinned maps. It should be
a separate capacity enhancement only if product requirements need more than 16
active groups. I1 closes the green-commit/permanent-blackhole behavior without a
state migration.

```go
const MaxDataplaneRedundancyGroups = 16

func ValidateDataplaneRGID(id int) error
```

The validation message must distinguish the 16-entry dataplane limit from the
unrelated heartbeat uint8 limit and the RETH-derived VRID limit.

### 5.11 Workstream J - merge repeated global address-book containers (K003-06)

Initialize `sec.AddressBook` once, iterate every top-level `address-book` child
and every nested `global` child, and merge through one deterministic helper:

```go
func ensureGlobalAddressBook(sec *SecurityConfig) *AddressBook
func compileGlobalAddressBooks(nodes []*Node, sec *SecurityConfig) error
```

Preserve existing duplicate-name semantics. If duplicate definitions are
illegal, the strict duplicate validator must reject them before merge; if
repeated blocks are legal, entries merge in source order without replacing the
container. Do not silently introduce last-wins behavior.

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
func normalizedEventAction(evt Event) (name string, binary uint8, applicable bool)
```

SESSION_OPEN and SESSION_CLOSE have no forwarding action. Trace and text output
omit `action`; REST/SSE represent it as absent rather than `deny`; binary uses
the existing `actionNotApplicable` value `0xff` for both. POLICY_DENY,
FILTER_LOG, SCREEN_DROP, and any event carrying a real forwarding verdict retain
their current action. Do not change the Rust event-stream wire layout or the
intentional producer byte zero.

### 5.15 Recommended issue and merge waves

After manual `/engineer 6744` approval, create child issues first so each PR has
one owner and close condition.

| Wave | Parallel workstreams | Reason |
|---|---|---|
| 1 | A (VIP race), C (SNMP intent), D (flowless ICMP), E (DDNS ownership) | Highest security/availability value; disjoint packages and files |
| 2a | B (empty identities), G (persisted AST bounds), J (address book) | Shared `pkg/config` surface; implement in separate worktrees but merge/rebase serially and rerun all config tests after each |
| 2b | F (LoadOverride), H (route-map count), I (RG capacity) | Mostly independent, but H/I consume config APIs and must rebase after 2a |
| 3 | K (routing ownership), L (lifecycle action) | Independent correctness/observability work with lower immediate blast radius |

K003-02 remains with #6548, and K003-05 remains with #4313. K003-12 and
K003-C create no child issue.

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
- existing `RouteMapSequenceCount` and `ComposedChainSequenceCount` exported
  signatures, retained as compatibility wrappers while safety call sites move to
  context-aware exact helpers.

Intentional behavior changes are fail-loud validation, not API removal:

- malformed empty security identities stop committing;
- unsupported nested policy containers are handled by #4313, not this plan;
- dataplane-bound RG IDs above 15 stop committing under I1;
- mixed-format override input is rejected atomically;
- invalid SNMPv3 credential combinations stop installing a downgraded user;
- lifecycle APIs stop calling a non-applicable action `deny`.

## 7. Hidden invariants the changes must preserve

1. **Commit/apply equivalence:** anything accepted by strict Go compilation must
   be representable by Rust snapshot hydration. Lenient persisted/HA input may
   warn and quarantine, but it must not panic, widen scope, or install stale
   permissive state as if apply succeeded.
2. **Fail-closed without false deny:** unreadable ICMP fragments remain denied;
   readable ICMP errors in the established global class remain admitted.
3. **DDNS cleanup authority:** only the backend fingerprint that published an
   owned RR may delete it. On uncertainty, retain ownership and alarm; never
   delete at another endpoint or overwrite the only cleanup key.
4. **Atomic config load:** parsing/replay happens on a detached tree. On any
   error, candidate bytes, generation, dirty bit, lock lease, and active config
   remain unchanged.
5. **Persisted AST integrity:** an invalid JSON node tree is rejected at the
   deserialization boundary and cannot reach an unsafe compiler walk; local
   indexing belts still remain length-safe.
6. **Route-map guard equals renderer:** exact count includes every family
   expansion, OR-product dimension, composed chain, and trailing default while
   preserving saturating arithmetic.
7. **HA capacity consistency:** accepted IDs fit BPF arrays, Go inventories,
   Rust epoch state, helper messages, heartbeat fields, and derived VRIDs. A
   range error occurs before any partial state publication.
8. **HA ordering:** `UpdateRGActive` cannot advertise control-plane master while
   helper/shim state remains inactive. The recommended plan prevents the invalid
   configuration; runtime belts still reject out-of-domain IDs.
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
15. **Tolerant-path no-brick rule:** malformed persisted state produces bounded,
    attributable warnings and safe omission; it does not crash startup.

## 8. Risk assessment

| Risk class | Rating | Why | Required mitigation |
|---|---|---|---|
| Behavioral regression | HIGH | Thirteen independent roots include security policy acceptance, SNMP auth, DDNS deletion, HA activation, and config loading | Separate PRs; fail-on-revert traces; strict/lenient paired tests; package-wide reruns after each config merge |
| Lifetime / borrow-checker | LOW | Only K003-01 changes Rust and it passes a copied byte already present in metadata; no ownership or shared-lifetime change | Rust unit tests, clippy/build, and packet-path smoke |
| Concurrency / lock ordering | MEDIUM | K003-16 repairs a race but a careless lock reuse can deadlock direct VIP reconciliation | Dedicated mutex; helper-only access; race tests and lock-scope review |
| Performance regression | LOW | One copied byte on a rare flowless path; all other work is cold path | No new packet reads/allocations; userspace throughput baseline and perf smoke for K003-01 only |
| State/ownership corruption | HIGH | DDNS wrong-backend delete and routing ownership loss are explicitly stateful | Fingerprint proof, retain-on-uncertainty, injected failure/retry tests |
| HA compatibility | MEDIUM | RG acceptance changes and config leniency must be identical on both peers | Mixed strict/lenient tests, peer-snapshot tests, userspace HA smoke |
| Public API regression | LOW-MEDIUM | Signatures remain, but invalid configs and lifecycle JSON semantics intentionally change | Compatibility wrappers, release notes, schema/golden tests |
| Architectural mismatch | MEDIUM | Mega-batching repeats the #961/#946 Phase-2 dead-end pattern; RG widening would create a pinned-map migration project | Path A split; choose RG clamp I1; no broad parser or ABI redesign |

## 9. Test and validation plan

### 9.1 Test-first requirement per workstream

Every implementation PR begins with a red test or deterministic reproducer that
passes on the fix and fails when the fix hunk is reverted.

- **A / VIP race:** deterministic reset-between-check-and-write seam, concurrent
  apply/HA event test, and `go test -race ./pkg/daemon`.
- **B / empty identities:** flat-set and hierarchical strict failures for empty
  zone, pair side, policy name, and global list element; lenient warnings;
  previous-good snapshot retention without scope widening.
- **C / SNMP:** table of noAuth/auth/privacy protocol-password combinations;
  strict and lenient compiler tests; packet tests proving noAuthNoPriv and
  authNoPriv requests are rejected when configured intent is stronger.
- **D / flowless ICMP:** IPv4 type 3/11/12 and IPv6 type 1/2/3/4 global admits;
  ND 133..137 where relevant; non-first fragment remains denied; unrelated ICMP
  remains denied; native-GRE and interface-NAT flowless entry coverage.
- **E / DDNS:** distinct v4/v6 fake servers; explicit backend-less v6 disable;
  both blocks removed; retained-server disable (negative control that must still
  choose the correct updater); updater-construction failure; matching/mismatching
  fingerprints; delete failure; no-op delete; restart with no prior updater;
  ownership retained on ambiguity.
- **F / LoadOverride:** flat valid input, hierarchical valid input, comments and
  blanks, mixed format rejection, malformed mid-file command, candidate byte
  equality and generation/dirty/lease invariance on failure.
- **G / AST bounds:** malformed persisted JSON is rejected before compile;
  handcrafted empty-Keys family node cannot panic the compiler; valid persisted
  JSON still loads; peer text sync remains a negative reachability control; add
  the malformed tree as a no-panic fuzz seed.
- **H / route-map:** count equals actual rendered rows for v4-only, v6-only,
  dual-stack, empty/undefined lists, route-filter family split, community and
  AS-path products, composed chains, and 65535 boundary cases.
- **I / RG:** strict IDs 0, 15, 16, 155, 156, and 255 across normal RETH,
  private-election, no-RETH, unused definition, and interface binding; lenient
  quarantine; runtime manager rejection before map/helper mutation; constant
  drift canaries for Go/BPF/Rust capacity.
- **J / address book:** repeated outer blocks, repeated global blocks, duplicate
  legal entries, duplicate illegal names, references to first and later blocks,
  deterministic diagnostics.
- **K / routing:** genuine not-found, transient `LinkByName`, `LinkDel` failure,
  subsequent retry recovery, and ownership-map assertions for bond and tunnel.
- **L / lifecycle action:** golden events originating from actual Rust wire bytes
  for OPEN/CLOSE across trace, binary, REST, SSE, and standard text; real policy
  deny/filter/screen events remain deny/reject/drop.

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
  injection, RG active/standby transition, and failover acceptance.
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
- Reimplementing #6548's local CLI fix or #4313's unsupported-shape gate under
  another issue.
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

## 11. Open questions for adversarial review

Each question may justify `PLAN-KILL` for the affected workstream or the whole
batch split.

1. Is Path A sufficiently independent, or do any retained roots share an
   invariant that requires one atomic implementation PR?
2. Does any current open issue beyond #6548 already own one of the retained
   source paths closely enough that this plan would duplicate work?
3. Does #4313's per-subtree closed-world scope unambiguously own K003-05, or is a
   narrowly linked child issue needed there without claiming feature parity?
4. For K003-09, does honoring the existing flat-override API contract via F1
   create dangerous `delete` semantics on a new empty tree, making F2 rejection
   the safer choice?
5. For K003-10, is 16 active RGs an intentional product limit that should be
   documented and rejected globally, or is there a committed near-term need for
   the I2 256-entry ABI migration?
6. Can DDNS ever have more than one historical backend fingerprint represented
   in owned records for a family? If yes, are the current one-cycle
   `lastLiveUpdater` anchors sufficient, or must cleanup authority be persisted
   per backend identity before K003-03 can be safely engineered?
7. Should invalid SNMPv3 users be omitted entirely on lenient load, or retained
   as disabled status objects so operators can diagnose them through show/API
   surfaces without exposing a request handler?
8. Is `null`/absent action acceptable for existing REST/SSE clients, or must the
   API preserve a string field with an explicit `n/a` value while binary uses
   `0xff`?
9. Does a dedicated VIP warning mutex cover every access, including test seams
   and reset paths, without establishing a lock-order edge to `directVIPMu` or
   `applySem`?
10. Are strict/lenient gates enough for malformed `Keys`, or should persisted
    Node deserialization gain a global structural validator before any compiler
    walk? If the latter is required, should K003-04 be killed as too narrow and
    replaced by a separately researched parser-boundary project?
11. Is a conservative compatibility wrapper for exported route-map counts safe,
    or should the public signatures change in one release so every caller must
    supply `PolicyOptionsConfig`?
12. Does any retained Low-severity workstream (address-book merge or lifecycle
    display) fail the value-to-churn bar and deserve `PLAN-KILL` rather than an
    implementation issue?
