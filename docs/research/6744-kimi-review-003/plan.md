# Plan of Action - #6744: Revalidate and split `kimi-review-003`

## 1. Status

**DRAFT v16 - round-fifteen major findings addressed; pending round-sixteen review**

- Issue: [#6744](https://github.com/psaab/xpf/issues/6744)
- Source report: `/tmp/kimi-review-003.md`
- Base: `origin/master` at `ad959117748181dabe46b8ddc2827de670380cea`
- Branch: `research/6744-kimi-review-003`
- Revision: 16
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
- Round-eight plan SHA:
  `bebffd32c7a0c2956a7eabbf584a92c6604ec5b2`.
- Round-eight verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-READY`; independent SMR-method fallback
  `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed before analysis at the
  account spend limit, so no Anthropic-model verdict is claimed. Round eight
  did not converge; revision 9 adds transport/role incarnation, fail-closed legacy-zero
  admission, capability-gated causally fenced bulks, echoed repair request IDs,
  reconcile-error failure, explicit readiness, full-replacement RG staging,
  classified DDNS claim durability and pre-#2903 compatibility, and redacted
  SNMP observation identities.
- Round-nine plan SHA:
  `ff17e6351f0e0da4fc2ac0b45d0ecdd4c4b99be5`.
- Round-nine verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-READY`; independent SMR-method fallback
  `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed before analysis at the
  account spend limit, so no Anthropic-model verdict is claimed. Round nine did
  not converge; revision 10 defines config callback completion across
  single-fabric replacement, separates continuity from timeout availability,
  prohibits legacy ACK proof, gates both RG0 actuator paths, initializes receive
  authority before network exposure, gives clustered helper debt a sole owner,
  resolves capability setup before registration, pins repair to its requesting
  connection, joins cancellable reconciliation, fences every used outbound
  connection, makes capable cold sync receiver-requested, and splits activation
  into an inactive-first implementation stack.
- Round-ten plan SHA:
  `103acbfd28115993f8f6393ed6b55d632bcfb4ee`.
- Round-ten verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-READY`; independent SMR-method fallback
  `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed before analysis at the
  account spend limit, so no Anthropic-model verdict is claimed. Round ten did
  not converge; revision 11 moves transport restart and retirement outside
  joined workers, makes config callbacks cancellable and authority-transactional,
  separates raw RG0 election state from committed authority, serializes every
  direct HA actuator with inventory debt, orders ACK/config writes, owns queued
  peer requests, repairs both session directions after config, and closes
  readiness, setup, request-send, and resync-pressure races found in the hostile
  composition pass.
- Round-eleven plan SHA:
  `e316e5b0c193f844289a6a6aeb505929108a550a`.
- Round-eleven verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-READY`; independent SMR-method fallback
  `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed before analysis at the
  account spend limit, so no Anthropic-model verdict is claimed. Round eleven
  did not converge; revision 12 defines sender-owned config epochs with one
  canonical cross-peer digest and an immutable replay API, commits one full
  all-RG ownership snapshot, leases every
  status-bearing helper response and protocol callback, makes barrier and bulk
  tokens exact, and closes setup, cluster-comms, notifier, ACK-write, and
  callback self-transition lifetime gaps.
- Round-twelve plan SHA:
  `1f1325f3348c5904e451e1e3b4dcd8cc8ec71bc6`.
- Round-twelve verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-READY`; independent SMR-method fallback
  `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed before analysis at the
  account spend limit, so no Anthropic-model verdict is claimed. Round twelve
  did not converge; revision 13 defines complete heartbeat authority, stable
  config identity and boot/restart semantics, exact local and peer config
  preparation transactions, state-mutating helper RPC ownership, final-fabric
  setup veto, finite replay/worker budgets, metadata-free canonical identity,
  controlled counter-exhaustion restart, synchronous bulk membership, explicit
  coordinator ownership, process-namespaced failover-transfer leases,
  receipt-bound failover ACKs, a closable helper-side-effect registry, checked
  store mutation generations, and concrete helper/export/bulk deadline and
  failure contracts.
- Round-thirteen plan SHA:
  `34619216673f66b1180274b50877f40628556999`.
- Round-thirteen verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY
  `PLAN-READY`; independent non-Anthropic SMR-method fallback
  `PLAN-NEEDS-MAJOR`. The Claude Code CLI again failed before analysis at the
  account spend limit, so no Anthropic-model verdict is claimed. Round thirteen
  did not converge; revision 14 adds urgent preemption of authority-mutating
  helper work, splits remote failover mutation from its post-publication ACK
  waiter, separates sparse replay windows from nonterminal and completed
  ledgers, binds helper results and event frames to their source generation
  through final enqueue, invalidates continuity on every helper process
  replacement, and defines a request-private owner-session export plus terminal
  event watermark for capable authoritative bulk. Revision 14 further replaces
  that first full-vector design with a credential-bound bounded binary stream,
  makes the coordinator store the exact inventory authority, retains ambiguous
  partial-batch keys, closes the early-tail ACK race, and derives capability
  capacity from the actual fully replicated worker/store, single-map alias,
  DNAT, ledger, and transient-tail surfaces with a fail-closed versioned shim-map
  migration.
- Round-fourteen plan SHA:
  `df53c23111385e84178d4025788468e82b58d31a`.
- Round-fourteen verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY `PLAN-READY`;
  independent non-Anthropic SMR-method fallback `PLAN-NEEDS-MAJOR`. The Claude
  Code CLI again failed before analysis at the account spend limit, so no
  Anthropic-model verdict is claimed. Round fourteen did not converge;
  revision 15 terminates legacy-map dual publication at a durably journaled
  local cutover, preserves only the legacy map's proved starting domain, escrows NAT ownership
  across ambiguous mutation prefixes, adds origin-qualified ambiguity cleanup,
  makes worker delta loss monotonic and export-fatal, includes static DNAT and
  kernel session maps in capacity, distinguishes capable-process and ephemeral
  legacy-transport authority while inventorying stale peer incarnations,
  applies coalesced tail tuple transfers with dependency-preserving
  release/acquire phases, proves that the TailAck write fence and mandatory
  all-fabric barrier order every successor maintenance BulkStart after final
  ACK postcommit, and reconciles every stale migration-scope statement.
- Round-fifteen plan SHA:
  `47b32a033e756316e5c24ba1e74442e58047968a`.
- Round-fifteen verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY `PLAN-READY`;
  independent non-Anthropic SMR-method fallback `PLAN-NEEDS-MAJOR`. The Claude
  Code CLI again failed before analysis at the account spend limit, so no
  Anthropic-model verdict is claimed. Round fifteen did not converge;
  revision 16 adds receiver-visible tail phase commits, target-bound handoff
  provenance and canonical promoted export ownership, removes the redundant
  compiler static-DNAT BPF projection so config promotion is snapshot-atomic, and
  per-key ordinary-mutation ownership through final Go ledger/journal commit.
  Its pre-commit hostile passes further make EventStream correctness frames
  non-evictable in one bounded intrusive replay arena, publish allocator
  predecessor fencing before physical reuse/expiry, separate persistent lease-
  group identity from per-flow reverse reservations, bound 128 wire frames plus
  at most two releases per frame as 384 explicit physical mutations, fence
  persistent expiry during tail escrow, make tombstone compaction barrier-
  qualified, and add receiver-verifiable cross-fabric tuple dependencies plus
  bounded chunked persistent-group eviction. Later hostile passes require every
  peer-wire waiter/dependency/owner to retain a barrier-visible admission token
  through final commit, and replace unsafe in-place legacy DNAT cleanup with one
  journaled forward-only v2 program/session/dynamic-DNAT cutover. Old map bytes
  are never migration authority or userspace mutation targets; a boot-scoped
  legacy execution capsule keeps every transitive program/map edge alive
  and confines late historical packet-side writes outside v2 authority.
  The integrated migration now binds every target map by held FD against a
  complete generated reference manifest, proves the complete v2 contents by
  exact membership plus cardinality, and identifies programs by their full
  kernel-reported identity rather than a tag or pathname. Read loops now only
  admit bounded lane records; one fixed 64-worker scheduler executes ready
  owners while a fixed coordinator handles deadlines and barriers, and every
  lifecycle transition joins that scheduler before replacing authority. A
  kernel-authoritative XDP/TC/TCX inventory and generation-owned link pins make
  both hook coverage and post-crash attachment lifetime explicit. Because Linux
  exposes no XDP BPF-link netns identity, online cutover additionally requires a
  durable link-ID-to-netns provenance record; pre-existing links without one
  fail closed and use the documented clean-reboot path. A new daemon process
  never resumes authority from old pins: it first moves every exactly owned
  XDP/TC/TCX hook to a map-free typed drop quarantine, then constructs a fresh
  XDP-only successor and detaches legacy TC/TCX. Kernel-boot identity,
  non-renewable `CLOCK_BOOTTIME` deadlines, an explicit root-only forward-resume
  command, and identity-checked `unlinkat` make every crash boundary
  forward-only and fail closed.
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
The warning carries a stable code and canonical path. Commit preflight
deduplicates identical warning keys across local and peer-effective prepared
views while retaining genuinely node-specific diagnostics; one source alias in
one commit never produces two indistinguishable operator warnings.
The key for this global alias warning is exactly `{warningCode, canonicalPath}`
and deliberately excludes the chassis/evaluation node; node identity remains a
separate diagnostic field and participates in keys only for warnings whose
cause is genuinely node-specific.

Normalization is a first-class compiler-preparation result, not a warning-side
effect or a synthetic node that section dispatch later forgets:

```go
type preparedCompileView struct {
    Root               *ConfigTree
    NormalizedSNMPRoot *Node
    SNMPSources         map[SNMPObservationID][]SNMPSourceObservation
}

type SNMPObservationID struct {
    Kind    SNMPObjectKind
    Ordinal uint32 // stable first-appearance ordinal, never a secret-derived hash
}

type SNMPSourceObservation struct {
    Identity string // username/trap name, or "community[N]"; never the community
    Field    string // keyword only; never a secret value
    Path     string // every secret token replaced with "<redacted>"
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
values are compared in memory only inside the preparation call. A private,
function-local table may key the fold by the actual community so repeated
occurrences correlate, but the returned carrier uses a first-appearance
ordinal such as `community[2]`; its path replaces the community token with
`<redacted>`. Every returned path uses the same secret-leaf classification as
`ConfigTree.RedactedClone`, including authentication/privacy passwords; a
source canary keeps those classifiers in lockstep rather than maintaining an
SNMP-only keyword list. It never uses a secret-derived hash. Secret values and raw paths
are never copied into observations, warnings, exported config projections, or
logs. The normalized AST and typed `SNMPConfig` remain the required
secret-bearing authorities. The fold has these exact semantics:

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

The existing private `snmpConfigHash` remains deliberately credential-aware:
it consumes raw community strings and v3 passwords in process so credential
rotation restarts or updates the listener. That nonexported value is never
persisted, logged, returned by an API, or reused as an observation identity.
This internal change detector is the sole exception to the no-secret-derived
diagnostic rule; replacing it with the redacted projection would make password
and community rotation invisible.

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
scope whose family matches; and valid pending-state shape. A current-shape
scope has a nonempty raw operator FQDN satisfying
`surfaceAName(scope.FQDN) == row.FQDN`. Raw scope FQDN equality is deliberately
**not** required because valid scopes preserve accepted uppercase and a single
trailing dot while `buildHostRecord` stores the canonical wire name in the row.

There is one bounded legacy exception: a Surface-A row satisfying every other
condition above may have `scope.FQDN == ""`. That is the shipped pre-#2903 disk
shape exercised by `TestSurfaceAFQDNMigrationAdoptsExistingRecord` and
`TestSurfaceAFQDNMigrationStillAdoptsWithFingerprint`; quarantining it would
turn a supported in-place migration into startup degradation. The exception
does not apply to a zero scope, a Surface-B identity, an empty/noncanonical row
FQDN, or any family/record-shape mismatch. Loading preserves the row and the
existing Surface-A reconcile adopts it into the FQDN-bearing key without a wire
delete. New writes always use the current shape. `PriorAddrText` is empty when
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
   It uses a dedicated remove-and-save helper, not the end-of-pass durability
   backstop:

   - copy the owned row, remove it from the candidate state, and call
     `ddnsState.save()` before publishing a reduced `WireRRClaims` snapshot or
     incrementing the release-success counter;
   - on a pre-rename save error, restore the copied row in memory, republish the
     snapshot with the claimant still present, return the error, and perform no
     provider I/O;
   - on `*fsatomic.PostRenameSyncError`, converge memory and the claim snapshot
     to the new visible file (claim removed), report the durability alarm, and
     still perform no provider I/O. A crash may expose old or new state; old
     state safely retries the same co-owner release, while new state has the
     surviving claimant; and
   - only save success or the classified post-rename outcome permits the claim
     to disappear from the lock-free cross-surface snapshot.
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
Immediately after JSON unmarshal, validate the actual persistence shape with an
explicit iterative node stack (not recursive descent over corrupt input):

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

### 5.10 Workstream I - align RG capacity and preserve HA generation authority (K003-10)

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

Helper `update_ha_state` is a **full replacement**, not a per-slot patch. The
transition therefore has two explicit representations: per-slot pinned-map
fences and one staged full helper inventory. First,
`clearHAOwnerSlotFailClosed` writes `rg_active[id]=0` and then
`ha_watchdog[id]=0` for every removed or introduced slot. It does not issue a
one-row helper request. Next build a complete transitional helper payload from
the final new inventory: preserve the reconciled state of every unchanged slot,
include every introduced slot as inactive/unarmed, and omit every removed slot.
On process start this one replacement also removes any helper-only stale slot
not present in the new inventory.

Send the staged payload through a helper method that accepts the explicit
snapshot; it must not read the not-yet-published `m.haGroups`. Clustered retry
state is concrete manager-owned state, distinct from the existing standalone
debt:

```go
type haInventoryDebt struct {
    generation              uint64
    desiredConfigGeneration uint64
    desiredOwners           map[int]HAGroupState
    stagedHelperGroups      []HAGroupState
    requiredFenceSlots      bitset16
    confirmedFenceSlots     bitset16
    nextAttempt             time.Time
    backoff                 time.Duration
}

type helperStatusLease struct {
    processGeneration          uint64
    snapshotGeneration         uint64
    desiredInventoryGeneration uint64
    publishedInventoryGeneration uint64
    debtGeneration             uint64
    helperMutationSerial       uint64
    positivePublicationAllowed bool
}

type helperSideEffectLease struct {
    processGeneration uint64
    snapshotGeneration uint64
    registryGeneration uint64
    operationID uint64
    phase helperSideEffectPhase // queued, inFlight, or consuming
    cancel context.CancelFunc
    done <-chan struct{} // closes after helper I/O and final consumer exit
}

type helperSessionSourceLease struct {
    processGeneration       uint64
    snapshotGeneration      uint64
    helperMutationSerial    uint64
    registryGeneration      uint64
    operationID             uint64
    localHelperGeneration   uint64
    managerAuthoritySerial  uint64
    ownershipGeneration     uint64
    authorityGeneration     uint64
    debtGeneration          uint64
    committedConfigEpoch    senderConfigEpoch
}

type HelperSessionBatch struct {
    Source   helperSessionSourceLease
    Complete bool
    Deltas   []SessionDeltaInfo
}

type helperSessionTransition struct {
    oldGeneration       uint64
    newGeneration       uint64
    authorityGeneration uint64
    debtGeneration      uint64
    reason              helperReplacementReason
}

type authorityMutationLease struct {
    serial            uint64
    class             helperRequestClass
    processGeneration uint64
    preempted         bool
    phase             authorityMutationPhase // admitted, externalStep, or publishing
    stepKind          authorityExternalStepKind
    cancel            context.CancelFunc
    closeConn         func() error
    stepDone          <-chan struct{} // closes when the admitted external step exits
    done              <-chan struct{} // closes when the whole mutator clears active
}

type authorityMutationLane struct {
    mu              sync.Mutex
    cond            *sync.Cond
    admissionClosed bool
    urgentSerial    uint64
    recoverySerial  uint64
    terminal        bool
    active          *authorityMutationLease // one: haInventoryTxnMu serializes admission
}

const helperSideEffectCapacity = 64
```

The manager atomically installs or supersedes this whole debt under its HA
state mutex; a newer desired config generation replaces the older snapshot,
but its required fence set is recomputed from the last **published** inventory
to the newest desired inventory and unions every older unconfirmed fence. It
never drops an uncertain clear merely because an intermediate desired
generation was superseded. The helper payload is always rebuilt from only the
newest desired generation, and an older retry can never publish over it. The userspace status/reconcile
loop is the sole retry consumer. While clustered debt exists, ordinary status
refresh must not source helper state from `m.haGroups`, rearm active/watchdog
state, publish forwarding ready, or advertise the staged inventory. It first
retries every `requiredFenceSlots - confirmedFenceSlots` clear (both inactive
and watchdog writes are idempotent), sets a confirmed bit only after both writes
succeed for that slot, and sends the helper
replacement only after all required bits are confirmed. Success
publishes `desiredOwners` and clears only the matching generation. Failure
retains the full snapshot, advances bounded backoff, disarms the helper, and
keeps forwarding degraded/fail-closed. Shutdown drains or persists no new disk
format; it leaves all debt-owned slots fenced.

A dedicated `haInventoryTxnMu` serializes initial transition, retry helper I/O,
config-generation supersession, **and every** direct HA actuator/helper writer,
including `UpdateRGActive`, `UpdateHAWatchdog`, status reconciliation, shutdown
fencing, and readiness publication. The existing broad `Manager.mu` is the
manager HA state mutex for this workstream; no fictional second state lock is
introduced. Its only nested state-lock order is
`haInventoryTxnMu -> Manager.mu`: code snapshots/updates debt, releases
`Manager.mu`, performs a debt-mutating fence/helper RPC while retaining only the
transaction mutex, then reacquires `Manager.mu` only to publish the exact
generation. A new config waits for an older debt-mutating helper RPC to finish
before installing/superseding debt, so a late full-replacement RPC cannot
overwrite a newer desired generation in the helper even if its Go completion is
rejected. Ordinary positive or replacement map writes may not occur before
acquiring this mutex. The sole exception is the typed urgent-negative
preemption lane below; it can only make forwarding less permissive and cannot
publish manager authority.

Every helper response carrying `ProcessStatus` is also in this graph, not only
`update_ha_state`. Refactor control-socket I/O so no caller holds `Manager.mu`
across a request. One exhaustive `helperRequestClass` registry classifies every
Rust `ControlRequest` match arm and Go constructor into exactly one row:

| Class | Exact request types | Transaction rule |
|---|---|---|
| Read-only | `ping`, `status` | capture/revalidate status lease; release transaction during I/O |
| Authority/forwarding-mutating | `apply_snapshot`, `set_forwarding_state`, `update_ha_state`, `update_fabrics`, `update_neighbors`, `bump_fib_generation`, `set_queue_state`, `set_binding_state`, `rebind`, `stop_workers`, `shutdown` | retain `haInventoryTxnMu` through request, helper mutation, response, and publication |
| Authority-neutral side effect | `clear_policy_counters`, `clear_nat_counters`, `clear_zone_counters`, `inject_packet`, `sync_session`, `drain_session_deltas`, `export_owner_rg_sessions`, `export_all_sessions` | use the operation's own bounded serializer/token; capture/revalidate any returned status but never publish authority from it; session-bearing results remain source-qualified through final consumption |

Read-only and authority-neutral requests
acquire
`haInventoryTxnMu -> Manager.mu`, capture `helperStatusLease` plus immutable
request input, and release both locks before bounded socket I/O. Read-only
requests then proceed directly. An authority-neutral side effect must first
register a `helperSideEffectLease` in the current process/snapshot registry while
those locks are held; the fixed registry admits at most 64 operations and returns
typed retryable `ErrHelperSideEffectBusy` without I/O at capacity. It remains
registered through the actual helper mutation, response decode, and every
downstream effect of that response. The control-
socket serializer is a context-aware capacity-one token, not an uncancelable
mutex wait. After obtaining it, the operation revalidates and changes its exact
registry entry from `queued` to `inFlight` under `Manager.mu` alone; a closed or
superseded entry exits without helper I/O. At most one control-socket side effect
is therefore across the mutation boundary. Session-socket operations use their
own existing capacity-one path but the same queued/in-flight registry contract.
After releasing `controlSocketToken`, an operation with no downstream mutation
marks the exact registry entry done under `Manager.mu` alone before attempting
HA/status lease consumption. A session-bearing operation instead revalidates and
moves `inFlight -> consuming`, materializes an immutable
  `helperSessionSourceLease`, and invokes one internal callback-form consumer while
  the entry remains registered. A finite delta operation uses
  `func(context.Context, HelperSessionBatch) error`; the authoritative owner-RG
  export instead uses a non-escapable
  `func(context.Context, AuthoritativeSessionStream) error` that owns the exact
  authenticated stream lease through private Final, peer BulkEnd/ACK, and tail
  flush. Both receive the remaining operation deadline and own no helper control-
  socket token. The admitted handle stays
in the registry until the callback returns and closes `done`; every loop,
capacity reservation, and SessionSync enqueue must observe that context. A
source canary rejects a callback without context propagation or one that starts
unregistered child work. `DrainSessionDeltas` and
  `ExportOwnerRGSessions` therefore do not expose a bare `[]SessionDeltaInfo` to
  daemon code: they accept the corresponding batch or stream callback and
  unregister only after that
callback has either committed the whole exact batch or rejected it and armed
repair debt. Returning a batch for later untracked consumption is forbidden by
the interface and a source canary.

Every authority/forwarding-mutating request in the classification table,
including snapshot/config, HA/fabric/neighbor/FIB, queue/binding/forwarding arm,
helper replacement, rebind/stop/shutdown, and process-generation change, closes
side-effect admission under
`haInventoryTxnMu -> Manager.mu`, snapshots the finite handles, releases
`Manager.mu`, cancels every `queued` handle, and joins them while retaining
`haInventoryTxnMu`. A queued operation that races token acquisition must perform
the phase revalidation above and cannot start after close. The at-most-one
`inFlight` operation per socket is not canceled during an ordinary transition;
it receives its operation-specific bounded response, after which the transition
also joins its finite `consuming` callback. Thus transition latency is bounded by
one active round trip and one bounded consumer per physical helper socket, not
`64 * deadline`. A canceled queued operation returns
typed retryable `ErrHelperSideEffectSuperseded` and is mutation-free; its caller
may recapture against the reopened generation without arming ambiguity debt.
Completion does
not need that transaction mutex, so the join cannot invert. Only after all exact
handles finish may the newer helper mutation begin. A successful exact mutation
and its lease-aware reconciliation opens a fresh nonzero registry generation;
failed/uncertain apply
leaves it closed. Thus counter clears, packet injection, session installs,
destructive delta drains, and exports cannot mutate a replacement helper or a
new config after their capture even though they do not globally serialize every
flow behind the HA transaction.

The daemon bridge captures a SessionSync enqueue lease at operation admission,
not after the helper response. Final consumption compares the complete helper
source tuple and enqueue lease against current helper process/snapshot/mutation,
local-helper, manager/ownership/authority/debt, and committed-config identities.
It stamps the outgoing session record with the source lease's config epoch; it
never reads and stamps the then-current epoch. A mismatch queues **none** of the
batch, retains or advances repair debt, and completes the registry entry as a
stale rejection. Consequently a C1 response paused before consumption cannot
resume after C2 and masquerade as C2. Config and lifecycle coordinators close
Manager and SessionSync admissions first, release both state-lock domains, and
then join consumers. If the consumer wins, it commits under C1 before C2 can
publish; if SessionSync transition wins, the old enqueue lease rejects without
waiting for `haInventoryTxnMu`. No consumer calls Manager while holding a
SessionSync lock, and no transition waits while holding `Manager.mu`, `s.mu`, or
`gate.mu`.

For finite delta batches, "queues none" is implemented as a bounded reservation/
staging operation, not a loop that can expose a prefix and then discover
capacity exhaustion. The consumer validates the complete source, reserves the
complete finite batch, validates again at one commit point, and only then
publishes it. For the authoritative stream, installing the exact stream token is
the admission commit; no peer state changes before authenticated Header and
BulkStart. Cancellation before BulkStart publishes no member. Cancellation
after BulkStart cannot roll back a peer incrementally, so it retires the
transport, leaves receiver table taint and repair debt set, and forbids takeover
until a fresh complete bulk. Neither form may continue under C2 with a C1 source.

The same source rule applies to asynchronous session events. Extend the private
Rust-helper event envelope with the nonzero helper `snapshotGeneration` supplied
by the corresponding canonical `apply_snapshot`; the EventStream instance adds
its immutable process/local-helper generation at frame admission. Pending and
replay records retain that complete source tuple, and callback consumption uses
the same exact enqueue lease and all-or-nothing stale rejection above. The Rust
event schema/version generator and Go decoder are changed together, and a layout
canary rejects an event producer that omits the generation. Reading a frame from
the socket after C2 therefore cannot relabel a C1 worker event as C2, even when
the frame was still in a kernel buffer during the transition.

This is an exact private helper-protocol version bump, not tolerant additive
JSON. One generated `HelperPrivateProtocolVersion`, distinct from the config-
snapshot `ProtocolVersion`, is reported by the boot/status probe and owns the
control-response metadata plus EventStream schema. The startup probe verifies
that exact version, the generation-bearing session
frame schema, and `MSG_EXPORT_BOUNDARY` type before any EventStream frame can be
admitted to SessionSync authority. The listener may already be bound so the
helper can connect during boot, but its generation-capturing callback stays in
the not-ready/withhold-ACK state until that probe succeeds. A Go/helper mismatch
fails helper start with forwarding disarmed; no old helper may silently emit
generation-zero frames or treat the boundary as an unknown telemetry record.

The Rust runtime view publishes config and that generation in one `ArcSwap`;
each worker copies the generation from the exact view that produced the session
mutation into the event. A rejected or preflight-failed apply never advances it,
and Go retains a sealed generation-to-committed-epoch record until every old
callback/consumer is joined or rejected. Merely reading the coordinator's latest
generation at serialization time is forbidden because an old worker event could
then be mislabeled.

Every authority/forwarding mutator also admits one
`authorityMutationLease` into the independent `authorityMutationLane` before its
first external effect. It retains `haInventoryTxnMu`, but each helper RPC, map
write, status application, compensation, and final publication enters and exits
one typed `externalStep` in that lane. The exact control connection is published
to the lease before write. Between steps and before publication the holder must
revalidate `preempted=false`; after preemption it may only unwind, classify any
already-crossed mutation boundary as ambiguous, and close `done`. It cannot
compensate by rearming old state or consume a late positive status. The lane
mutex is never held during I/O. Ordinary admission/revalidation has the single
brief edge `haInventoryTxnMu -> authorityMutationLane.mu`; urgent code acquires
the lane alone, and no lane holder acquires `haInventoryTxnMu` or `Manager.mu`.
The mutator is the sole closer of its `stepDone` and `done` channels. Exact-
serial cleanup clears `active` and broadcasts the condition even after
preemption; a stale cleanup cannot clear a successor lease.
Outside a declared `externalStep`, mutator code is bounded local bookkeeping:
it may acquire only the stated short state locks and may not perform I/O, wait on
a callback/channel, sleep, or enter an untracked syscall. A source canary owns
that finite step table.

Urgent demotion, whole-forwarding disarm, stop/rebind/shutdown, and helper-health
failure do not queue behind `haInventoryTxnMu`. One daemon-owned urgent
coordinator closes positive admission and marks the active lane lease preempted
under `authorityMutationLane.mu`, captures its cancel/connection/process handles,
and releases the lane. It closes the exact client connection immediately. If the
current helper step has not returned within
`helperSideEffectUrgentDrainGrace`, it terminates and joins that exact helper
generation, making a mutation-with-lost-response explicitly ambiguous. It then
waits for the at-most-one current external step to leave the lane; preemption
prevents any successor step. Existing fail-closed BPF/RG fences are applied
through a negative-only actuator after that ordering point and therefore land
after every old positive map step. The final negative demotion/stop receipt and
peer-visible secondary/held authority publication wait for the fences and exact
old-helper termination, but do not wait for positive recovery; this permits the
peer to take over. Any later local positive authority, readiness, or forwarding
waits for canonical replacement plus mandatory session repair. The old mutator
may still own `haInventoryTxnMu` while unwinding, but it has no remaining
external or publication capability; once it releases, ordinary reconciliation
records or supersedes the exact ambiguity debt. A stuck non-helper kernel map
syscall is a host-fatal dataplane condition and triggers the existing supervised
fail-closed daemon exit; the coordinator never races a second write to the same
map and calls that a fence.

Urgent admission is level-triggered and generation checked. The first urgent
transition sets `admissionClosed`, advances `urgentSerial`, and copies that value
to `recoverySerial`; another urgent request coalesces its negative work but
advances the serial so an older recovery cannot reopen the lane. After the
current `stepDone` and whole-mutator `done` close, the urgent coordinator applies
the exact negative fences and publishes only secondary/held state. Ordinary
mutators remain rejected while `admissionClosed` is true. Only canonical helper
replacement, ambiguity-debt reconciliation, and mandatory session repair may
call `CompleteAuthorityRecovery(exactUrgentSerial)` to reopen admission; Stop or
terminal helper failure sets `terminal` and never reopens it. No timeout, stale
completion, or merely empty `active` pointer is a recovery signal.
After preemption, closing `stepDone` must fall through in the same mutator call
stack to exact cleanup and `done` without another scheduling or blocking point.
Violation is the same host-fatal invariant class as a cancellation-blind
consumer: authority stays fenced and the supervised daemon exits. It is never
converted into an unbounded urgent wait.

Closed admission does not deadlock the recovery that must reopen it. The urgent
coordinator owns one unforgeable recovery capability carrying the exact latest
urgent serial. It may admit only typed replacement/fail-closed reconciliation
steps through `haInventoryTxnMu -> authorityMutationLane.mu` while ordinary
callers remain rejected. Ordinary callers perform an advisory admission check
before queueing for `haInventoryTxnMu` and the authoritative recheck after they
acquire it, so already-queued callers drain by rejecting before any effect and
cannot starve recovery. Each recovery step revalidates that serial; a newer urgent transition cancels
the older recovery. Those steps may apply the canonical snapshot and repair
state, but no positive readiness/authority publication is legal until the final
exact `CompleteAuthorityRecovery` compare-and-swap.

Urgent negative authority/lifecycle work never waits an export's full 125-second
client bound. Demotion, forwarding/binding disarm, stop/rebind/shutdown, and
helper replacement first preempt any authority mutator as above, then close the
side-effect registry and apply every available out-of-helper fail-closed fence.
They wait at most
`helperSideEffectUrgentDrainGrace` for the one in-flight operation on each
socket or one consuming callback. If it remains active, the owner closes its client connection,
terminates/joins the helper process, classifies that operation as ambiguous under
the rules below, and continues only with a full replacement; no positive
authority opens during the replacement. Ordinary prepared config transitions
may wait the operation-specific bound because the old committed config remains
authoritative until promotion. This separates availability-safe config
serialization from the safety-critical demotion latency contract.

Killing the helper is not claimed to cancel a Go consumer. Urgent close also
cancels every `consuming` callback context and waits its exact `done` within the
same grace. All production consumers are repository-owned, nonblocking except
for context-aware SessionSync admission, and must exit. Failure to join one is a
host-fatal invariant breach: keep out-of-helper authority fenced and take the
supervised fail-closed daemon exit rather than publishing a replacement while a
stale Go callback can still run. Production durations remain constants; tests
inject a per-instance clock/grace seam, never an environment variable.

Registry close does not pretend that canceling a Go socket cancels a Rust
handler. It waits for each bounded response. If any side-effect round trip is
ambiguous, the registry records its exact operation class, the process owner
terminates/joins that helper, and config may proceed only against a replacement
process with a full canonical snapshot. Every process replacement arms the
helper-session transition and mandatory bilateral repair/full-bulk debt below.
Ambiguous `sync_session` or `drain_session_deltas` additionally records its
operation-specific uncertainty in that debt because the install or destructive
drain may have happened; neither is blindly retried. Ambiguous counter clear marks its telemetry baseline unknown until the
replacement status, ambiguous injection reports unknown and is never duplicated,
and an export discards partial output and may be retried only as a new operation
after replacement. This is the failure contract for mutation after response
loss, not response-lease validation masquerading as rollback.

Read-only and completed side-effect callers reacquire
the same order to consume the response **only after releasing** the control-
socket serializer. This prevents a read response from holding the socket while
waiting for a mutating request that owns `haInventoryTxnMu` and itself waits for
the socket. Consumption requires exact process, snapshot,
desired inventory, published inventory, debt, and helper-mutation serials.
`sync_session` is deliberately authority-neutral but registry-bound: globally
serializing every replicated flow behind the HA transaction would create
control-plane starvation, while letting it escape the process/snapshot registry
would mutate stale authority. Its response may publish session telemetry but no
control, binding, forwarding, watchdog, or HA authority.

Authority/forwarding-mutating requests
retain `haInventoryTxnMu` from request construction through the actual bounded
RPC and response consumption. Rejecting a stale response is not a rollback:
the Rust helper mutates before it replies. Consequently no newer config,
inventory, process, or debt generation may become visible while an older
mutating request is in flight. The request releases `Manager.mu` during I/O,
then reacquires it while still owning `haInventoryTxnMu` to publish the exact
result. Immediately before each such write, it advances
`helperMutationSerial` under the transaction; status leases captured before the
write therefore fail revalidation even when that request does not change the
snapshot or inventory generation. A timeout/ambiguous write installs matching
uncertainty debt and keeps helper control, bindings, and positive readiness
false. Snapshot/control/HA/fabric/neighbor/FIB/queue/binding ambiguity requires
helper-process replacement followed by the exact full canonical snapshot,
fences, and status reconciliation. Ambiguous `rebind` or `stop_workers` is
process-lifecycle debt and likewise forces replacement rather than trusting an
in-process status. `shutdown` marks that helper instance terminal, waits for or
kills it through the existing process owner, and permits only a new process;
there is no impossible same-process status recovery after shutdown.

Helper-process replacement is also a **session-authority transition**, not
merely config/helper recovery. `Coordinator::new` constructs a new
`SessionManager` whose synced, NAT, and forward-wire maps and owner-RG indexes
are empty. Replaying the canonical config snapshot cannot reconstruct those
runtime tables. Consequently every creation of a Rust helper receives one
nonzero checked `processGeneration`; replacing it must invalidate session
continuity even when no `sync_session` or `drain_session_deltas` RPC was
ambiguous. A source canary permits process stop, signal, kill, `cmd.Wait`, and
new helper publication only inside one `replaceHelperProcess` lifecycle. Health
failure, binding-plan restart, rebind, shutdown/restart, urgent side-effect
termination, and future process-supervision paths all use that lifecycle.

The daemon installs a process-lifetime helper-session observer before the first
helper can start. Because boot may start the helper before constructing
`SessionSync`, that observer is a daemon-owned activation multiplexer rather
than a closure over one SessionSync pointer. In clustered mode its session
callback returns not-ready and withholds ACK while the authority object is
absent; the bounded event-stream pending/replay path retains those frames. The
initialization transaction binds the exact SessionSync plus helper generation
and flushes them only after all authority fields are installed. In standalone
mode it classifies session replication as a permanent no-op while retaining
dataplane telemetry callbacks. A dedicated `helperLifecycleMu` is the outer coordinator; it
is never acquired from SessionSync, `haInventoryTxnMu`, `Manager.mu`, a helper
socket token, or an event-stream callback. Before acquiring the HA/helper lock
domain for teardown, `replaceHelperProcess` calls
`BeginHelperSessionTransition(oldGeneration, reason)`. That method enters the
SessionSync write fence and serialized continuity publisher, closes inbound
session-install and outbound producer admission, invalidates bulk/request/
barrier/ACK tokens, increments `outboundAuthorityGeneration`, clears current
continuity, arms a new mandatory bidirectional repair debt generation, and
publishes the ordered false edge. It then cancels and joins the exact admitted
install, reconciliation, bulk, export, and helper-event callback handles outside
all state locks. Only after this call returns may the manager acquire
`haInventoryTxnMu`, close/join its side-effect registry, fence forwarding, and
terminate the old helper. An admitted session install can therefore finish
before `Begin` returns, but no new one can enter and no manager lock is held
while SessionSync waits for it.

Event-stream callbacks belong to the helper generation, not to a replaceable
`*EventStream` pointer. The manager stores one daemon-registered callback set
independently of the stream object and installs generation-capturing wrappers on
each new stream **before** `EventStream.Start` exposes its listener. Replace
`Close`-without-join with a closable registry/`CloseAndWait(context.Context)`
that closes admission and joins the accept, read, ACK, pending-callback flush,
and already-entered callback handles. Every session/full-resync callback
revalidates its captured helper generation before queueing a peer delta,
requesting a bulk, or acknowledging a local frame; a stale callback returns the
closed/superseded result and cannot mutate SessionSync or telemetry for the new
process. The fallback monitor observes the registered generation rather than
assuming callbacks wired to the first stream also apply to its replacement.

After the new helper starts, the manager applies the exact canonical snapshot,
HA fences, and status reconciliation while positive control remains closed,
then calls `CompleteHelperSessionTransition` with the exact transition token and
new process generation. Completion binds that generation into the initialized
gate and every ordinary install, receive window, ACK, request, barrier, and
outbound-bulk token, but deliberately leaves continuity false and repair debt
armed. It also retires and replaces the whole SessionSync transport while
reusing the daemon `peerProcessID`, committed config record, checked request
counters, and replay floors. That transport replacement is the wire fence: old
helper-derived frames and ACKs are joined before a new connection incarnation,
so `localHelperGeneration` remains local control state and is not improvised as
an unnegotiated wire field.

The replacement transport performs the existing capable bilateral requested-
bulk protocol under the new helper generation. Inbound owner snapshots
repopulate every RG for which this node is standby. For RGs this node owns, the
new helper's table is the authoritative post-reset snapshot, even when empty;
its exact outbound BulkEnd/reconcile plus TailAck removes stale pre-restart
replicas on the peer and proves the captured tail.
Helper-replacement debt completes only after every required inbound bulk and
every required locally owned outbound reset bulk/two-stage ACK succeeds for the
new generation. No prior `bulkEverCompleted`, previous helper status, timeout,
listener-bound bit, or same-daemon process identity can discharge it or permit
manual transfer.

A planned replacement while the node owns an RG first attempts the normal
committed-authority demotion/transfer, allowing the peer's existing replica to
carry live sessions. If that transfer cannot complete, the old healthy helper
and committed config remain in service and the planned replacement is retried;
it does not silently reset flows. An unplanned dead/unhealthy helper or an
urgent safety kill cannot preserve in-memory sessions: out-of-helper fences and
the ordered false continuity edge run first, the replacement proceeds, and the
node reports a typed `helper_session_state_reset` degraded reason plus a
monotonic reset counter. In HA, local positive/manual-takeover authority remains
closed until ownership and bilateral repair converge. In standalone operation,
full config/HA-independent forwarding may reopen after helper bring-up, but
existing flows are explicitly lost and alarmed; this workstream does not claim
lossless recovery from memory that died with the process. On later peer
reconnect, the new authoritative reset bulk reconciles stale peer replicas
before continuity can become ready.

Top-level public wrappers such as `Status` and `Compile` acquire the transaction
once and call `...TxnHeld` internal variants. Config/recovery paths that already
own `haInventoryTxnMu` call only those internal variants; they may not reacquire
the non-reentrant mutex. A source canary maps every `ControlRequest` kind and
every helper wrapper plus the Rust match arms to one class/entrypoint and fails
if a new kind, direct socket write, or nested public-wrapper call is
unclassified. Reclassifying a request is an invariant change requiring plan
review, not an implementation convenience. The allowed socket edge is
`haInventoryTxnMu -> controlSocketToken` for mutating requests only; no path may
hold `controlSocketToken` while acquiring `haInventoryTxnMu`. Side-effect queue-to-
in-flight promotion may acquire `Manager.mu` alone while holding the socket token
only to revalidate the registry entry, and completion may acquire it alone after
dropping the socket only to unregister; neither step may publish state or acquire
`haInventoryTxnMu`.

Split status application into a pure telemetry decoder and
`applyHelperControlStatusWithLeaseLocked`. `recordHelperStatusLocked` records the
manager's current published/debt view rather than blindly copying a stale
helper view. A response may publish positive `userspace_ctrl`, bindings,
forwarding-ready, watchdog, or helper HA state only if
`positivePublicationAllowed` was true at capture, remains true at completion,
no debt exists, and every lease field still matches. A stale or debt-crossing
read-only response may update explicitly read-only counters after process
identity validation, but it retains fail-closed control, stamps status as
inventory-transition degraded, and schedules a fresh pass. Returned raw status
may be exposed for diagnostics; only the lease-aware consumer mutates manager
or BPF control state.

Peer config uses an explicit store transaction rather than trying to install
debt around the current indivisible `SyncApply` call:

```go
type PreparedSyncApply struct {
    id                      uint64 // all fields package-private
    storeMutationGeneration uint64
    tree                    *config.ConfigTree
    compiled                *config.Config
    canonical               canonicalCommittedConfigIdentity
    view                    PreparedConfigView
    sealedDigest            [32]byte
}

type PreparedConfigView struct {
    StoreMutationGeneration uint64
    Canonical               canonicalCommittedConfigIdentity
    BoundOwnerIDs           []uint8              // sorted copy
    ConfigSyncEnabled       bool
    ZoneRedundancyGroups    map[uint16]uint8      // deep copy
    Runtime                 clusterCommsRuntimeSnapshot
}

type PromotedConfigView struct {
    Prepared PreparedConfigView
    Compiled *config.Config // fresh sole-owner clone, returned only after promotion
}

func (s *Store) PrepareSyncApply(text string, preserve bool) (*PreparedSyncApply, error)
func (s *Store) ViewPreparedSync(p *PreparedSyncApply) (PreparedConfigView, error)
func (s *Store) PromotePreparedSync(p *PreparedSyncApply) (*PromotedConfigView, error)
func (s *Store) AbortPreparedSync(p *PreparedSyncApply)
```

`PrepareSyncApply` executes the exact parse, chassis preservation,
retired-dataplane rewrite, sanitation, hard gates, and lenient compile pipeline
once against a detached tree; no second compile is authoritative. The object is
opaque outside `configstore`: no tree, compiled pointer, canonical identity, or
generation field is exported. `ViewPreparedSync` validates the one-shot token
and returns only a deep-copied immutable value summary containing the canonical
wire identity, bound-owner inventory, config-sync/zone-RG authority inputs, and
cluster-runtime inputs needed to stage the daemon transaction. It exposes no AST
or compiled pointer. `PromotePreparedSync` revalidates the token/sealed digest
and returns a `PromotedConfigView` whose compiled config is a fresh clone of the
same store-owned sealed object only after atomic promotion. Thus daemon debt and
the promoted/apply payload cannot be assembled from independently mutable
arguments.

`Store` owns one checked `storeMutationGeneration` under its mutex. A newly
constructed process-local Store starts at zero; the sole successful bootstrap
`Load` publication advances it to one. A later authoritative reload is an
ordinary mutation and advances from the current value rather than resetting it;
only constructing a new Store in a new daemon process creates another zero-to-
one namespace. The value is not restored from disk. Every
successful publication that changes active, candidate, compiled, rollback, or
commit-confirm state increments it exactly once through one helper; parse,
validation, conflict, and other mutation-free errors do not. This includes
flat/hierarchical edits, loads, local commit/confirmed commit, peer promotion,
candidate rollback, automatic prepared rollback, confirm/cancel, and bootstrap
state replacement. Prepare captures it while snapshotting all inputs; promotion
requires exact equality and consumes the token while incrementing the generation
for its own publication. At `MaxUint64-1`, an attempted mutation returns typed
`ErrStoreGenerationExhausted` before changing any pointer/file/state; the daemon
converts it to the controlled process-exhaustion path. A source canary requires
all writes of the listed store fields to pass through this helper. Retire the
unchecked backing field `candidateGen`: the source-compatible
`CandidateGeneration`, `CompileCandidateGen`,
`CommitWithDescriptionGen`, and `CommitConfirmedGen` APIs use this same checked
store mutation generation. That conservatively conflicts on any intervening
store publication, not only a candidate edit, and leaves no second ABA-sensitive
counter that can wrap independently.

Under `applySem`, the daemon derives the desired owner inventory from the opaque
prepared view and, when the canonical identity differs from the
current local record, reserves the next checked local sender record **before**
any gate, helper, or store mutation. Exhaustion therefore exits fail-closed
without exposing an epoch-less active tree. A later promotion conflict burns
that reserved generation; gaps are legal and an identity is never reused.
The daemon then acquires `haInventoryTxnMu`, waits for older mutating helper
RPCs and registered side effects, captures the prior inventory/authority record,
installs/supersedes exact debt, and stages the helper/dataplane apply from that
same opaque prepared view before `PromotePreparedSync`. Workstream I-d first
activates removal of the redundant compiler-owned static-DNAT projection from
`dnat_table{,_v6}`; therefore config promotion has no static-map side effect or
map rollback arm. Promotion validates the one-shot object and unchanged store
mutation generation and atomically installs that same sealed prepared
tree/compiled pair. Only that exact promoted token authorizes helper/dataplane
staging and the one allocation-free committed-runtime publication. A returned
promotion error is mutation-free at the store and at both dynamic-only DNAT
maps, but the daemon must abort the staged transition: it re-drives the captured
prior inventory, helper snapshot, and gate authority through the same debt engine and
does not retry preparation or reopen admission until that compensation succeeds.
Failure to compensate remains explicit fail-closed recovery debt. Success makes
the candidate observable only while its matching debt and fences already exist.
The daemon releases the transaction mutex before unrelated apply tails or retry
waits. A post-promotion tail failure retains that exact candidate/debt pair and
its pre-reserved local record fail-closed until exact reapply or a newer full
replacement succeeds. No status/actuator path takes `applySem`, and source tests
reject the reverse edge or any direct peer call to legacy `SyncApply`.

While debt exists, a direct positive active/watchdog request is rejected with a
typed retryable `ErrHAInventoryTransition` **before** either pinned-map write or
helper publication. The daemon retains its level-triggered desired RG state and
re-drives it after the exact debt generation clears; the periodic watchdog path
also naturally retries. A negative request may clear/fence a still-required
slot, but it folds that result into the matching debt and never constructs a
helper payload from the old published `m.haGroups`. A request for a slot absent
from the newest desired inventory is rejected even if the slot remains present
in the previous published inventory. Debt success wakes one level-triggered
actuator reconciliation before forwarding-ready publication. Tests pause each
direct writer both before and after its mutex acquisition while a removal debt
is installed and prove no old active/watchdog/helper state can reappear.

Normal status publication and helper backstops take the transaction mutex too;
they either observe no debt and one published inventory or observe debt and emit
only degraded/fenced state. A source canary enumerates every production writer
of `rg_active`, `ha_watchdog`, `m.haGroups`, `userspace_ctrl`, forwarding/
binding readiness, and `update_ha_state`; every call to
`applyHelperStatusLocked`/its replacements; and every `ProcessStatus` response
consumer. It requires the transaction boundary and rejects the inverse
`Manager.mu -> haInventoryTxnMu` edge. Tests exercise every enumerated call
site, not a hand-maintained subset of status-loop paths.

Only after every pinned fence and the full replacement succeed may the manager
publish the new bound inventory and normal helper state. Retry never replays an
older full map, a sequence of patches, or the unpublished `m.haGroups`. A valid
transition that encounters I/O failure may leave an affected previous-good RG
deliberately fenced, never stale-active or an unchanged RG spuriously omitted.
Typed-validation rejection still occurs before this transition and remains
mutation-free.

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

Session install, config apply, reconnect, ownership transition, and repair use one
authority state machine. The implementation must not infer authority from a
nonzero counter or from whichever callback happened to run first.

Before `SessionSync.Start` exposes a listener or dialer, the daemon calls one
initialization method with all reconciliation authority:

```go
type SessionSyncAuthority struct {
    Runtime                clusterRuntime
    Identity               *daemonSyncIdentity
    CommittedConfig        committedConfigRecord
    LocalHelperGeneration  uint64
    ManagerAuthoritySerial uint64
    CommittedRGAuthority   map[int]RGAuthorityEntry
    ZoneOwners             map[uint16]bool
    ConfigSyncEnabled      bool
}

type daemonSyncIdentity struct {
    peerProcessID [16]byte
    configGeneration checkedCounter
    bulkEpoch checkedCounter
    remote *daemonRemoteProtocolState // nil or exactly one current peer process
}

type daemonRemoteProtocolState struct {
    peerProcessID [16]byte
    failoverTransactionID checkedCounter
    requestIDs map[syncMessageType]*checkedCounter // non-failover request protocols
    prepareActivationIDs [256]checkedCounter // one fire-and-forget namespace per RG
    replay *protocolReplayLedger
}
```

The method also installs config, peer, bulk, and ownership callbacks. It
deep-copies the immutable local config record and committed maps and records a
separate `initialized` bit, so a legitimately empty map is not confused with an
unwired runtime. `Start` fails before binding if the runtime, nonzero local
sender epoch/canonical digest, nonzero current local helper generation,
generation-bound callbacks, exact manager ownership serial, or zone-owner
snapshot has not been initialized.

Full daemon boot is the only construction exception to record replay. Before
network exposure, the daemon loads and structurally validates `store.active`,
runs the complete boot compile/apply, computes
`CanonicalCommittedConfigIdentity` from that exact active tree, and allocates
generation 1 in the newly generated daemon `peerProcessID` namespace. This
single boot transaction publishes the first `committedConfigRecord` and
`committedRuntimeConfig`; before any concurrent reader exists, the constructor
uses the same validation/publication primitive with a distinguished no-static-
transition token and initializes the registry and ledger together. After boot,
that primitive is reachable only through the live lock contract below. Failure
leaves cluster comms unstarted. A later
`SessionSync` or cluster-comms restart in the same daemon receives that exact
record and the same daemon-owned `daemonSyncIdentity`; config, request, and bulk
wire counters therefore cannot reset under the unchanged process ID. It
also retains completed replay windows/reject-below floors for the still-current
remote process after all old in-flight callbacks are joined, so an in-process
restart cannot make an old request executable again. It allocates nothing merely
because the transport restarts. A full process restart
creates a new process ID and repeats boot construction at generation 1; no
in-memory counter or old process-owned record is restored from disk.

Capable causal request counters are scoped to the ordered pair
`{local peerProcessID, remote peerProcessID}`. Capability setup resolves the
remote process before any such request can be allocated. Single/batch failover
request and its matching commit share one `failoverTransactionID`; commit never
allocates a second ID. Other request protocols use their declared message-kind
counter, and prepare activation uses its per-RG namespace below. A new remote
process receives fresh counters beginning at one; reconnect or cluster-comms
restart to the same remote process reuses its exact counters and receiver replay
ledger. This gives a freshly restarted receiver a well-defined first ID without
permitting a same-process reconnect to reset replay state.
The daemon retains exactly one `daemonRemoteProtocolState`: peer replacement
first closes admission and joins all old callbacks/waiters, then destroys the
old state and installs the new one. Repeated peer identities therefore cannot
grow a process-ID map for the daemon lifetime.

Initial config apply obtains the current `d.applyResult()` zone map and passes
it into this method before `Start`. Subsequent changes are transactional, not a
reentrant setter: local commit/rollback obtains a local transition lease before
store promotion and completes it after the exact full apply; a peer callback
returns the typed authority delta in `ConfigApplyOutcome` for the config loop to
commit with the exact callback lease. `BulkStart` is refused without ACK,
callback, reconciliation, or readiness if initialization is absent. Sweep and
event-stream producers also start only after initialization and successful
`Start`.

Protection is exactly `ConfigSyncEnabled && CommittedRGAuthority[0].State` is secondary:
this is
the authority-to-receiver direction. RG0 primary and config-sync-disabled mode
are unprotected. Config-sync enable/disable and every RG ownership change are
first-class gate transitions. Enabling on a secondary establishes a fresh baseline,
clears current continuity, and does so before any peer session can install.
Disabling removes only that
baseline obligation after admitted config/session/reconcile work drains; it
does not erase generic session-repair debt. Boot computes this mode from the
already-applied config before `Start`.
On a capable connection, completing a transition to unprotected immediately
issues a fresh nonzero bulk request; completing a transition to protected waits
for the next successful baseline before issuing it.
An unknown/unresolved RG0 role initializes `transitioning` and fail-closed; it
is never treated as unprotected merely because it is not yet secondary.

`transportEpoch` is a local nonzero monotonically increasing identity for one
continuously connected peer interval shared by both fabrics. Each accepted TCP
connection also receives a unique nonzero `connectionIncarnation`. A secure
random nonzero `peerProcessID` identifies one daemon process, not one
restartable `SessionSync` object. It is generated before the daemon boot apply,
remains stable across every cluster-comms/SessionSync restart in that daemon,
and changes only after a full daemon process restart. Transport epoch and
connection incarnation, not process identity, distinguish those in-process
restarts. The gate owns authority and receive-window state:

```go
type senderConfigEpoch struct {
    generation uint64
    digest     [32]byte
}

type canonicalCommittedConfigIdentity struct {
    wireText string
    digest   [32]byte
}

type configApplyLease struct {
    transportEpoch uint64
    peerProcessID  [16]byte
    ownershipGeneration uint64
    authoritySerial uint64
    peerConfigEpoch senderConfigEpoch
}

type committedConfigRecord struct {
    epoch   senderConfigEpoch
    identity canonicalCommittedConfigIdentity
    runtime clusterCommsRuntimeSnapshot
}

type failedConfigMutation struct {
    source           ConfigMutationSource
    storeMutationGeneration uint64
    peerProcessID    [16]byte
    peerConfigEpoch  senderConfigEpoch
    localRecord      *committedConfigRecord
    ownershipReceipt *RGMutationReceipt
    text             string // in-memory only; never logged or exposed
    stage            ConfigMutationStage
}

type repairAttempt struct {
    requestID             uint64
    localHelperGeneration uint64
    transportEpoch        uint64
    connectionIncarnation uint64
    peerProcessID         [16]byte
    ownershipGeneration        uint64
    authoritySerial       uint64
    authorityGeneration   uint64
    requesterConfigEpoch  senderConfigEpoch
    debtGeneration        uint64
    deadline              time.Time
    phase                 requestAttemptPhase // writing, awaiting, or bound
}

type pendingPeerBulkRequest struct {
    requestID                    uint64
    localHelperGeneration        uint64
    transportEpoch               uint64
    connectionIncarnation        uint64
    peerProcessID                [16]byte
    ownershipGeneration               uint64
    authoritySerial              uint64
    authorityGeneration          uint64
    requesterConfigEpoch         senderConfigEpoch
    debtGeneration               uint64
    deadline                     time.Time
    phase                        peerRequestPhase // queued or claimed
}

type pendingBarrierSet struct {
    localHelperGeneration uint64
    transportEpoch       uint64
    peerProcessID        [16]byte
    ownershipGeneration uint64
    authoritySerial      uint64
    authorityGeneration uint64
    senderConfigEpoch    senderConfigEpoch
    barrierSetID         uint64
    coveredWireGeneration uint64
    memberCount          uint8
    members              [maxSyncFabrics]barrierMember
}

type barrierMember struct {
    fabric                syncFabric
    connectionIncarnation uint64
    sequence              uint64
    acked                 bool
}

// allFabricGenerationBarrierReceipt is valid only in the exact transport and
// peer-process namespace whose frozen capable membership produced it. It is a
// fixed two-fabric value, not a map or an independently reconstructible claim.
type allFabricGenerationBarrierReceipt struct {
    localHelperGeneration uint64
    transportEpoch uint64
    peerProcessID [16]byte
    ownershipGeneration uint64
    authoritySerial uint64
    authorityGeneration uint64
    senderConfigEpoch senderConfigEpoch
    barrierSetID uint64
    coveredWireGeneration uint64
    memberCount uint8
    members [maxSyncFabrics]barrierMember
    membershipDigest [32]byte
}

type helperSnapshotStreamLease struct {
    processGeneration     uint64
    localHelperGeneration uint64
    exportID              uint64
    nonce                 [16]byte
    expectedPeerPID       int
    expectedPeerUID       uint32
    conn                  *net.UnixConn
    done                  <-chan struct{}
}

type authoritativeSessionSnapshot struct {
    source                 helperSessionSourceLease
    exportID               uint64
    workerSetGeneration    uint64
    expectedWorkerCount    uint32
    expectedBoundaryDigest [32]byte
    terminalEventSequence  uint64
    sourceMemberCount      uint64
    sourceMemberDigest     [32]byte
    complete               bool
    stream                  helperSnapshotStreamLease
}

type pendingOutboundBulk struct {
    bulkEpoch             uint64
    requestID             uint64
    localHelperGeneration uint64
    transportEpoch        uint64
    connectionIncarnation uint64
    peerProcessID         [16]byte
    ownershipGeneration        uint64
    authoritySerial       uint64
    authorityGeneration   uint64
    senderConfigEpoch     senderConfigEpoch
    debtGeneration        uint64
    snapshot               authoritativeSessionSnapshot
    writtenMemberCount     uint64
    writtenMemberDigest    [32]byte
    writtenTailCount       uint64
    writtenTailDigest      [32]byte
    phase                  outboundBulkPhase // exporting, snapshot, endingBulk, awaitingBulkACK, flushingTail, endingTail, awaitingTailACK, complete
    deadline               time.Time // 180s bulk, 20s bulk ACK, 180s tail, 20s tail ACK
}

type SessionSyncAuthorityDelta struct {
    ConfigSyncEnabled bool
    ZoneOwners        map[uint16]bool
}

type RGMutationReceipt struct {
    serial           uint64
    desiredMapDigest [32]byte
}

type ConfigApplyOutcome struct {
    Authority           SessionSyncAuthorityDelta
    OwnershipMutation   *RGMutationReceipt
    CommittedConfig     committedConfigRecord // local sender epoch
    Runtime             clusterCommsRuntimeSnapshot
    RestartClusterComms bool
}

type LocalConfigCommitOutcome struct {
    Authority           SessionSyncAuthorityDelta
    OwnershipMutation   *RGMutationReceipt
    CommittedConfig     committedConfigRecord
    PushGeneration      bool
    RestartClusterComms bool
}

type ConfigApplyFailure struct {
    Stage             ConfigMutationStage // pre-promotion, promoted, or armed
    OwnershipMutation *RGMutationReceipt
    Err               error
}

type transportRetireRequest struct {
    transportEpoch uint64
    fabric          syncFabric
    connIncarnation uint64
    wholeTransport bool
    reason          transportRetireReason
}

type configInstallGate struct {
    mu                    sync.Mutex
    cond                  *sync.Cond
    initialized           bool
    configSyncEnabled     bool
    protected             bool
    transitioning         bool
    drainingTransport     bool
    baselinePending       bool
    continuityReady       bool
    previousGoodContinuity bool
    bulkMutationTainted   bool
    ledgerInventoryDirty  bool
    continuityEventSeq    uint64
    applying              *configApplyLease
    receiveWindow         *bulkReceiveWindow
    transportEpoch        uint64
    peerProcessID         [16]byte
    ownershipGeneration        uint64
    transitionSerial      uint64
    managerAuthoritySerial uint64
    localHelperGeneration uint64
    outboundAuthorityGeneration uint64
    committedConfigEpoch  senderConfigEpoch
    acceptedPeerConfigEpoch senderConfigEpoch
    inFlightInstalls      uint64
    debtGeneration        uint64
    completedDebt         uint64
    requestAttempt        *repairAttempt
    pendingPeerRequest    *pendingPeerBulkRequest
    pendingBarriers       *pendingBarrierSet
    pendingOutboundBulk   *pendingOutboundBulk
    pendingReceiveAck     *receiveAckCommit
    tailReceiveWindow     *tailReceiveWindow
    mutationJournals      *ambiguousMutationJournalRegistry
    failedConfigMutation  *failedConfigMutation
    authorityApplyFailed  bool
    inboundBulkAuthorized bool
    outboundBulkAuthorized bool
}

type bulkReceiveWindow struct {
    serial                uint64
    localHelperGeneration uint64
    phase                 bulkReceivePhase // receiving or reconciling
    connIncarnation       uint64
    transportEpoch        uint64
    peerProcessID         [16]byte
    ownershipGeneration        uint64
    authoritySerial       uint64
    authorityGeneration   uint64
    senderConfigEpoch     senderConfigEpoch
    bulkEpoch             uint64
    requestID             uint64
    claimedDebtGeneration uint64
    deadline              time.Time
    generationLedger      *capableGenerationLedger
    generationFloor       uint64
    lastWireGeneration    uint64
    receivedMemberCount   uint64
    receivedMemberDigest  [32]byte
    zoneOwners            map[uint16]bool
    cancelReconcile       context.CancelFunc
}

type receiveAckCommit struct {
    serial                uint64
    localHelperGeneration uint64
    connIncarnation       uint64
    transportEpoch        uint64
    peerProcessID         [16]byte
    ownershipGeneration        uint64
    authoritySerial       uint64
    authorityGeneration   uint64
    senderConfigEpoch     senderConfigEpoch
    bulkEpoch             uint64
    requestID             uint64
    claimedDebtGeneration uint64
    memberCount           uint64
    memberDigest          [32]byte
    generationLedger      *capableGenerationLedger
    lastWireGeneration    uint64
}

type tailReceiveWindow struct {
    serial                uint64
    localHelperGeneration uint64
    connIncarnation       uint64
    transportEpoch        uint64
    peerProcessID         [16]byte
    ownershipGeneration   uint64
    authoritySerial       uint64
    authorityGeneration   uint64
    senderConfigEpoch     senderConfigEpoch
    bulkEpoch             uint64
    requestID             uint64
    claimedDebtGeneration uint64
    phase                 tailReceivePhase // bulkAckWriting, receiving, or tailAckWriting
    bulkAckWriteConfirmed bool
    deadline              time.Time
    maxUniqueTailRows     uint64
    maxTailSessionFrames  uint64
    maxTailPhaseMarkers   uint64
    maxTailWireBytes      uint64
    chargedUniqueTailRows uint64
    receivedSessionCount  uint64
    receivedMarkerCount   uint64
    receivedTailWireBytes uint64
    receivedTailDigest    [32]byte
    expectedBankSerial    uint64
    expectedBankPhase     uint8 // 1 release, 2 acquire
    receivedPhaseCount    uint64
    receivedPhaseDigest   [32]byte
    transferEscrow        *tailTransferEscrow
    generationLedger      *capableGenerationLedger
    lastWireGeneration    uint64
}

// tailTransferEscrow is a startup-reserved, fixed-capacity typed-reservation
// index owned by one tailReceiveWindow. It contains allocator reservation/lease
// tokens and exact refcount deltas, not a second session inventory. A release
// can transfer an exclusive token or a compatible shared-lease reference to a
// later acquire; no exclusive token returns to ordinary allocation until the
// complete bank resolves.
type tailTransferEscrow struct {
    capacity uint64
    byteCapacity uint64
    // generated fixed member/group slots plus bounded indexes; records,
    // indexes, typed token unions, and alignment are all preallocated
}

type sharedLeaseGroupIdentity struct {
    allocatorConfigID [32]byte // canonical pool/prefix/rule identity
    family uint8
    mode uint8
    reserved [6]byte
    persistentSourceKey generatedPersistentSourceKey
    leaseTarget generatedSharedLeaseTarget // address or address+port owned by the lease
}

type memberReservationIdentity struct {
    allocatorConfigID [32]byte
    family uint8
    mode uint8
    sharing uint8 // exclusive or persistent-shared
    groupPresent uint8
    sharedGroup sharedLeaseGroupIdentity // canonical zero when groupPresent == 0
    memberKey generatedMemberReservationKey
    // memberKey is the exact per-flow translated/reverse occupancy identity.
    // It includes the remote endpoint where address-only reverse ownership does.
}

// tuplePredecessorDescriptor is the exact 88-byte capable session-mutation
// trailer carried by every Open/Update while predecessor debt is attached. The
// sender writes canonical zero when the attempted reservation has no unresolved
// cross-key predecessor. canonicalKey is the 40-byte v6-sized key encoding; v4
// uses its 16-byte key followed by canonical zero padding.
type tuplePredecessorDescriptor struct {
    present uint8
    family uint8
    pad [6]byte
    predecessorGeneration uint64
    canonicalKey [40]byte
    memberIdentityDigest [32]byte
}

type ordinaryTupleDependencyEntry struct {
    peerProcessID [16]byte
    predecessor tuplePredecessorDescriptor
    successorKey canonicalSessionKey
    successorGeneration uint64
    target memberReservationIdentity
    laneHandle uint32 // checked non-owning sessionMutationLaneArena waiter
    deadline time.Time
    phase tupleDependencyPhase
}

type tailTransferEscrowGroupEntry struct {
    identity sharedLeaseGroupIdentity
    token typedSharedLeaseToken
    expiryFence persistentLeaseExpiryFenceHandle // acquired before first release
    startingRefs uint32
    releasedRefs uint32
    acquiredRefs uint32
    untouchedRefs uint32
    phase tailEscrowEntryPhase
}

type tailTransferEscrowMemberEntry struct {
    identity memberReservationIdentity
    token typedAllocatorMemberReservationToken
    groupSlot uint32 // generated invalid sentinel for exclusive members
    phase tailEscrowEntryPhase
}

type capableGenerationLedger struct {
    peerProcessID [16]byte
    repairSerial uint64
    maxObservedGeneration uint64
    retiredGenerationFloor uint64
    retiredFloorBarrier allFabricGenerationBarrierReceipt
    v4       *generationLedgerTable[dataplane.SessionKey]
    v6       *generationLedgerTable[dataplane.SessionKeyV6]
    rows     uint64
    capacity uint64
}

type generationLedgerTable[K comparable] struct {
    index      map[K]uint32
    pages      [][]generationLedgerSlot[K] // fixed-size, lazily allocated pages
    free       []uint32
    liveExtent uint32
}

type generationLedgerSlot[K comparable] struct {
    key      K
    state    bulkMemberState
    occupied bool
}

type sessionMutationOwnerClass uint8
const (
    sessionMutationPeerWire sessionMutationOwnerClass = iota + 1
    sessionMutationBulkEviction
)

type receiveBarrierAdmissionToken struct {
    peerProcessID [16]byte
    transportEpoch uint64
    connectionIncarnation uint64
    wireGeneration uint64
    fabric uint8
    state receiveBarrierAdmissionState // admitted or finalCommitted
}

type sessionMutationLaneRecord struct {
    slotGeneration uint32
    ownerClass sessionMutationOwnerClass
    laneState sessionMutationLaneState // waiter, dependency, owner, ambiguous
    barrierToken receiveBarrierAdmissionToken // zero only for internal eviction
    // exact operation, owner/waiter links, intrusive ready-queue link,
    // journal handle, completion state
}

// sessionMutationScheduler is allocated once for a capable transport
// generation. Read loops admit records but never execute or wait for them.
// Only ready owner handles enter the intrusive FIFO; dependency and same-key
// waiters consume arena credit without consuming an executor.
type sessionMutationScheduler struct {
    generation uint64
    readyHead uint32
    readyTail uint32
    readyCount uint32
    running uint16
    state sessionMutationSchedulerState // accepting, draining, stopped
    // one fixed wake primitive, one fixed cancellation source, and exactly
    // sessionMutationExecutorCount startup-owned workers
}

type ambiguousMutationJournal struct {
    helperGeneration uint64
    peerProcessID     [16]byte
    batchID           uint64
    records           [clusterSyncPhysicalMutationCapacity]ambiguousMutationRecord
    incomingStaging   [clusterSyncBatchCapacity]bulkIncomingStagingRecord
    ledgerTransitions [clusterSyncBatchCapacity]bulkLedgerTransitionRecord
    replacementEscrow bulkReplacementEscrow
    count             uint16
}

type bulkIncomingStagingRecord struct {
    family uint8
    key canonicalSessionKey
    generation uint64
    value canonicalSessionValue
    sourceDigest [32]byte
    transitionHandle uint32
    phase bulkIncomingStagingPhase
}

// bulkLedgerTransitionRecord overlays one incoming attempt on either a free
// ledger slot or the exact stale incumbent slot it will replace. The attempted
// key is indexed only by the journal's fixed staging index until complete
// commit; one ledger slot never represents two committed keys.
type bulkLedgerTransitionRecord struct {
    incumbentSlot uint32
    incumbentKey canonicalSessionKey
    incumbentGeneration uint64
    attemptedStagingSlot uint16
    phase bulkLedgerTransitionPhase
}

type ambiguousMutationJournalRegistry struct {
    slots [clusterSyncBatchInFlightCapacity]ambiguousMutationJournal
    used  [clusterSyncBatchInFlightCapacity]bool
    // fixed reusable arena; no allocation after startup
}

type ambiguousMutationRecord struct {
    family          uint8
    key             canonicalSessionKey
    ownerClass      sessionMutationOwnerClass // peerWire or bulkEviction
    wireGeneration  uint64 // nonzero only for peerWire
    evictionRepairSerial uint64 // nonzero only for bulkEviction
    evictionBatchID uint64
    expectedRetainedGeneration uint64
    beforeValid     bool
    before          derivedSurfaceCleanupDescriptor
    attemptedValid  bool
    attempted       derivedSurfaceCleanupDescriptor
    incumbentReservationValid bool
    incumbentReservation originQualifiedNATReservation
    attemptedReservationValid bool
    attemptedReservation originQualifiedNATReservation
}

type bulkReplacementEscrow struct { // one fixed instance per journal slot
    members [clusterSyncReleaseMutationCapacity]bulkReplacementMemberEntry
    groups  [clusterSyncReleaseMutationCapacity]bulkReplacementGroupEntry
    parkedGroups [bulkParkedGroupCapacity]parkedBulkGroupRelease
    // generated fixed member/group/translated-target indexes and free stacks
}

type parkedBulkGroupRelease struct {
    slotGeneration uint32
    identity sharedLeaseGroupIdentity
    token typedSharedLeaseToken
    expiryFence persistentLeaseExpiryFenceHandle
    finalGroupSlot uint16
    releasedMemberCount uint32
    phase parkedBulkGroupReleasePhase
}

type bulkGroupEvictionPlan struct { // one receive-window-owned prerequisite
    slotGeneration uint32
    identity sharedLeaseGroupIdentity
    target memberReservationIdentity
    token typedSharedLeaseToken
    expiryFence persistentLeaseExpiryFenceHandle
    expectedMemberCount uint64
    removedMemberCount uint64
    cursor checkedGenerationLedgerCursor
    incomingBatchID uint64
    incomingWireOrdinal uint16
    phase bulkGroupEvictionPhase
    // One fixed chunk uses the ordinary journal/lane/escrow arenas. The group
    // token and fence survive between chunks; member tokens do not accumulate.
}

type bulkReplacementMemberEntry struct {
    incumbentKey, acquiringKey canonicalSessionKey
    identity memberReservationIdentity
    token typedAllocatorMemberReservationToken
    releaseRecord, acquireRecord uint16
    groupSlot uint16
    phase tupleTransferEscrowPhase
}

type bulkReplacementGroupEntry struct {
    identity sharedLeaseGroupIdentity
    owner bulkGroupTokenOwner
    startingRefs, releasedRefs, acquiredRefs, untouchedRefs uint32
    phase tupleTransferEscrowPhase
}

// Exactly one tagged arm owns the group token plus expiry fence. Handles carry
// slot generations; canonical-zero inactive arms are rejected by validation.
type bulkGroupTokenOwner struct {
    kind bulkGroupTokenOwnerKind // inlineToken, activePlanHandle, parkedHandle
    generation uint32
    inlineToken typedSharedLeaseToken
    inlineExpiryFence persistentLeaseExpiryFenceHandle
    activePlanHandle uint32
    parkedHandle uint32
}

type bulkMemberState struct {
    generation uint64
    valueValid bool
    value      canonicalSessionValue // exact last accepted peer value for cleanup/replay
    present    bool
    installed  bool
    ambiguous  bool // exact attempted key retained across a partial helper batch
    seenRepairSerial uint64
    seenTailSerial uint64
}

const (
    maxSyncFabrics                = 2
    syncCapabilitySetupTimeout = 3 * time.Second
    protocolControlTimeout     = 5 * time.Second
    repairStartTimeout         = 5 * time.Second
    outboundBulkACKTimeout     = 20 * time.Second
    outboundTailACKTimeout     = 20 * time.Second
    authoritativeBulkTransferTimeout = 180 * time.Second
    authoritativeTailFlushTimeout = 180 * time.Second
    failoverCallbackTimeout    = 20 * time.Second
    minimumRequestedResync     = 30 * time.Second
    maximumRequestBackoff      = 30 * time.Second
    configRecoveryInitialBackoff = 1 * time.Second
    configRecoveryMaximumBackoff = 30 * time.Second
    continuityOutboxCapacity   = 64
    protocolInFlightCapacity   = 64
    failoverSparseWindowCapacity = 1024
    failoverNonterminalTransferCapacity = 64
    failoverCompletedResultCapacity = 1024
    protocolDuplicateWaitersPerEntry = 8
    helperSnapshotWorkerQueueCapacity = 1024
    clusterSyncBatchCapacity        = 128 // maximum admitted peer wire frames
    clusterSyncReleaseMutationCapacity = 2 * clusterSyncBatchCapacity
    clusterSyncPhysicalMutationCapacity = 3 * clusterSyncBatchCapacity
    ambiguousMutationJournalRecordCapacity = clusterSyncPhysicalMutationCapacity
    ambiguousMutationJournalSlotCapacity = clusterSyncBatchInFlightCapacity
    ambiguousMutationJournalByteCapacity = 256 << 20
    clusterSyncBatchDeadline        = 5 * time.Second
    clusterSyncBatchInFlightCapacity = 64
    sessionMutationWaitersPerKey = 8
    sessionMutationLaneRecordCapacity = clusterSyncPhysicalMutationCapacity * clusterSyncBatchInFlightCapacity
    sessionMutationLaneByteCapacity = 64 << 20
    sessionMutationExecutorCount = clusterSyncBatchInFlightCapacity
    sessionMutationReadyCapacity = sessionMutationLaneRecordCapacity
    ordinaryTupleDependencyCapacity = sessionMutationLaneRecordCapacity
    ordinaryTupleDependenciesPerTarget = 8
    bulkGroupEvictionPlanCapacity = 1
    bulkParkedGroupCapacity = clusterSyncBatchCapacity
    authorityProvenanceTransitionDeadline = 180 * time.Second
    eventCriticalReplayGeneralFrameCapacity = 8192
    eventCriticalRefQueueCapacity = 8192
    eventTelemetryRefQueueCapacity = 8192
    eventCriticalReplayByteCapacity = 256 << 20
    allocatorPredecessorByteCapacity = 64 << 20
    allocatorPredecessorShardCount = 256
    predecessorOrderUpdateBatchCapacity = 128
    allocatorGenerationRetireDeadline = 20 * time.Second
    captureTailBankCount       = 2
    captureTailTotalByteCapacity = 256 << 20 // shared generated coalescer-row credit
    captureTailMaxRows         = 262144
    tailTransferEscrowByteCapacity = 64 << 20
    ownerRGExportStartDeadline = 5 * time.Second
    allSessionsExportServerBudget  = 120 * time.Second
    allSessionsExportRoundtripDeadline = 125 * time.Second
    helperSideEffectUrgentDrainGrace = 1 * time.Second
    tupleReleaseFenceSlotsPerWorker = 1024
)
```

The existing `syncWriteDeadline` remains two seconds and applies to each wire
write. Failover request/commit callbacks use `failoverCallbackTimeout` because
they share the existing ACK lease; prepare-activation, fence, and full-set
callbacks use `protocolControlTimeout`. Ordinary helper control uses the existing
size-scaled `controlRoundtripDeadline(serializedLen)`: three seconds below one
MiB, plus one second per complete MiB, capped at 120 seconds.
`export_owner_rg_sessions` has a five-second control-admission deadline; its
credential-bound private stream, worker cursors, EventStream boundaries, peer
writes, and Final proof all share the 180-second authoritative-bulk deadline.
The control response contains no member data. `export_all_sessions` remains the
response-work exception with a 125-second Go round-trip deadline
around a new 120-second **aggregate** Rust export budget. The latter is not
`5s * session_count`: `AllSessionsExport::push` captures one absolute deadline
and passes `min(LOSSLESS_QUEUE_TIMEOUT, remaining)` into each
`push_delta_lossless_within`; expiry returns an explicit application error and
stops iterating. A drift test owns both Go/Rust constants and requires the
five-second response margin. The client timeout remains an ambiguous side-effect
outcome and therefore takes the replacement/full-repair path above; a Rust
budget error is an unambiguous failed export and records full-bulk debt without
killing a responsive helper; neither its response nor its event frames delimit a
capable authoritative bulk. Session-socket requests retain their two-second
dial and three-second round-trip bounds except the new bulk-mutation batch,
which uses the explicit five-second cap further bounded by the receive window.
Config apply does not invent an
aggregate wall-clock
timeout over local compilation and dataplane work: every blocking production
suboperation must accept the admitted context or one of the explicit bounded
RPC/write deadlines above. Cancellation-unaware operations are prohibited from
that callback path. Recovery retries use the stated exponential backoff and
each attempt receives a fresh admitted context. Timeout always records debt,
retires the affected transport when wire outcome is ambiguous, and leaves
positive authority/readiness closed.

`transitionSerial` is the gate's local mutation sequence;
`managerAuthoritySerial` is the exact full-RG ownership snapshot serial staged
in the gate.
Every token's `authoritySerial` copies the latter and every
`authorityGeneration` copies `outboundAuthorityGeneration`. Admission requires
the local transition to be complete **and** the manager snapshot to be committed
at the same serial/full ownership map. A `senderConfigEpoch` always belongs to
the process that created its generation: `committedConfigEpoch` is local,
`acceptedPeerConfigEpoch` is remote, outbound bulk/barrier/request records carry
the local epoch, and receive-window/ACK/peer-request records carry the remote
epoch. Generations from different processes are never compared for equality or
ordering. An epoch is compared as one exact generation/digest value only within
its owning daemon-process identity; canonical digests, not generations, prove
that two peers run the same forwarding/config hierarchy after explicitly
excluded display metadata is removed. The local config/debt counters are
monotonic only before their immutable records are committed.

Every session install, export, barrier, bulk, request, reconciliation, and ACK
token also copies `localHelperGeneration`. This generation is meaningful only
inside the local daemon and is never compared with a peer value. A mismatch is
an unconditional stale-token failure that retains repair debt; it cannot be
waived by matching config, ownership, process, or transport identity. Replacing
the helper forces whole-transport retirement before the new generation becomes
admissible, which supplies the remote ordering boundary without changing a
legacy wire layout.

No counter rotates process identity in place. Before incrementing any
ABA-sensitive identity (`senderConfigEpoch.generation`, request/bulk IDs,
connection/transport incarnations, local helper-process generations, transition and manager-authority serials,
ownership/authority/debt generations, receive/ACK serials, continuity sequence,
worker IDs, replay high-waters, and `Store.storeMutationGeneration`), the checked allocator reserves
`MaxUint64` for terminal sequencing and rejects an ordinary allocation that
would exceed `MaxUint64-1` with `ErrIdentityCounterExhausted`. Therefore no
counter is already wrapped when shutdown begins. The daemon closes all
admissions, increments `continuityEventSeq` once through its reserved terminal
slot (the next value, at most `MaxUint64`) to publish/acknowledge the terminal
false edge, fail-closes helper/dataplane
authority, drains cluster comms, and returns that typed fatal error to the
top-level process, which exits. Terminal shutdown allocates no request, bulk,
transport, worker, or authority identity. The service supervisor starts a new
daemon with a new random `peerProcessID`; boot rebuilds the canonical active
record at generation 1, performs the full boot apply and establishes a fresh
baseline. No in-process wrap, rekey, or record reuse crosses process identity.
A persisted record from an older binary at `MaxUint64` is likewise
re-canonicalized into generation 1 under the new boot identity rather than fed
to `max(old)+1`.

`helperLifecycleMu` is outside both the Manager and SessionSync lock graphs. It
may invoke the SessionSync Begin/Complete lifecycle methods or enter
`haInventoryTxnMu`, but it never nests the two domains and neither domain calls
back while holding one of its locks. This order is enforced together with the
process-lifecycle source canary.

The connection registry and exact setup state remain under `s.mu`. The only
permitted nested lock orders are `s.mu -> gate.mu`,
`bulkSendMu -> producerMu`, `continuityPublishMu -> s.mu -> gate.mu`, and the
narrowly bounded write-fence/revalidation edge
`writeMu -> s.mu -> gate.mu`. An invalidation that also emits a readiness edge
uses the combined prefix `continuityPublishMu -> writeMu -> s.mu -> gate.mu`,
reserving its outbox slot before taking `writeMu`; no inverse edge exists. No
other mutex is nested. No path waits for
`writeMu` while holding `s.mu` or `gate.mu`. Every config-send, config-receive,
ownership, disconnect, and shutdown invalidation first acquires `writeMu`, then
advances/invalidates the exact gate tokens under `s.mu -> gate.mu`, releases
the state locks and `writeMu`, and only then cancels or joins workers. Thus an
ACK/config/request writer already past its token check completes before the
invalidation linearization point; an invalidator that wins makes every later
writer check fail. The fence never spans callback, cancellation wait, worker
join, or helper/dataplane I/O. In particular, the gate
is the sole owner of `receiveWindow`, membership, and reconciliation phase;
`bulkMu` is removed as an independent authority. Writer, pending-ACK,
delete-journal, and helper locks are otherwise acquired only after any
gate/registry lock is released. The narrow revalidation releases both state
locks before retaining `writeMu` for network output. No network/dataplane/helper
I/O, callback, cancellation wait, or condition wait occurs while a state mutex
is held.

Frame admission takes `s.mu -> gate.mu`, verifies the exact registered
connection, and returns an immutable lease. Session-install completion takes
the same lock order before adding bulk membership or publishing completion.
Config callback completion is deliberately transport/process/ownership scoped, not
connection scoped: once a callback was admitted, replacing only its source
fabric cannot undo the store mutation it may already have performed. If the
transport, peer process, ownership generation, and config epoch still match, a
successful callback may publish `acceptedPeerConfigEpoch` even when that one
connection incarnation was replaced. Queued but not admitted frames remain
connection scoped and are dropped with their connection.

Last-fabric loss is different. Under `s.mu`, each retire producer sets the exact
fabric's `retirementPending` bit before it returns or wakes the coordinator.
When pending requests cover every active pre-reconnect fabric incarnation, the
same critical section sets `wholeTransportPending`, closes connection/setup
promotion admission, and marks the old transport draining. A setup attempt that
was admitted earlier may finish authentication, but its final promotion checks
both bits; it closes the new socket rather than installing a replacement. Thus
a replacement cannot make the transport nonempty between final EOF and the
coordinator's empty/drain decision.

For `wholeTransportPending`, the coordinator then closes all admissions and
closes/joins the exact setup lanes and data registry, including config callback, protocol callbacks, admitted
installs, receive/writer, ACK, reconcile, barrier, request, and bulk handles. No
replacement transport may register or promote during this drain. Only after
quiescence does it advance `transportEpoch`, clear current-transport
observability mirrors, invalidate outbound bulk authorization, set validated
continuity false, and establish a protected baseline obligation. The sticky
`bulkEverCompleted` history remains only as previous-good evidence for the
separate automatic peer-loss doctrine; it cannot satisfy current continuity or
manual readiness. Thus an old callback may finish as
previous-good, but cannot overlap or clear the new transport's baseline.

That drain is owned by one dedicated lifecycle-coordinator handle which is not
a member of `lifetimeWorkers`, `setupWorkers`, or `dataWorkers`. Do not reuse
one `sync.WaitGroup` across setup, transport, coordinator, and process
lifetimes. Ownership is explicit:

- `lifetimeWorkers` owns accept loops, permanent outbound connect loops, the
  config loop, and notifier. Only the coordinator can close their setup/data
  descendants during ordinary retirement; external `Stop` closes this lifetime
  registry after coordinator quiescence. The coordinator itself has one
  separate `{cancel, done}` handle.
- `setupWorkers[transportEpoch][fabric]` is two independently closable setup
  lanes, each with a nonzero `setupGeneration`. It owns each bounded inbound or
  outbound handshake/capability attempt for that fabric. `beginSetup` captures
  epoch/fabric/setup-generation and registers a handle under `s.mu` **before**
  launching or entering setup; the outbound connect loop runs the attempt as a
  registered child rather than as untracked inline work. A drained single-
  fabric lane can be replaced by a fresh higher generation without reopening
  the other lane or the transport data registry.
- `dataWorkers[transportEpoch]` owns receive, the normal send loop,
  heartbeat/write, protocol,
  config-callback, ACK, reconcile, and bulk handles admitted after setup. Both
  per-epoch registries are closable maps of `{id, cancel, done}`, not reusable
  WaitGroups: close prevents insertion, snapshot is finite, and completion
  deletes only the exact ID.

Each data handle is typed as connection-incarnation scoped or transport scoped.
A surviving-fabric retirement closes/joins only the lost incarnation's receive,
writer, ACK, and connection-pinned bulk/request handles; an already admitted
config callback is transport scoped and may complete. Last-fabric/whole-
transport retirement closes and joins both classes. Scope is fixed at
registration and cannot be inferred later from whichever connection is active.

On EOF, protocol violation, or ambiguous write, a worker atomically records a
bounded `transportRetireRequest`, wakes the coordinator through a coalescing
channel, and returns to its completion handle. The coordinator has two distinct
transitions:

- **Single-fabric drain:** under `s.mu -> gate.mu`, close only that fabric's
  setup lane and snapshot its setup handles plus data handles scoped to the lost
  connection incarnation. The transport-wide data registry and surviving lane
  remain open. Outside locks, cancel/join those finite snapshots. Reacquire the
  locks and revalidate the exact epoch, pending slot, surviving connection, and
  absence of `wholeTransportPending`; then remove the lost connection, install a
  fresh higher `setupGeneration` lane, clear only that fabric's pending slot,
  and wake its permanent connector. If the other fabric retired while the join
  ran, do not reopen: the whole-transport path owns both lanes.
- **Whole-transport drain:** close both setup lanes and the complete data
  registry for the exact epoch, snapshot all handles, cancel/join setup first and
  data second outside locks, and advance the transport only after both are empty.
  No lane or data registration is reopened in that epoch.

A setup completion may install only if its captured epoch, fabric, and setup-
generation lease is still open and exact; both `retirementPending[fabric]` and
`wholeTransportPending` must also be false. Otherwise it closes its socket and
returns. Successful setup atomically moves its handle from its exact setup lane
into the data registry and installs the connection in one `s.mu` critical
section. Single- and whole-drain snapshot/move use that same lock, so the handle
is present in exactly one finite snapshot and cannot fall between them. No
replacement epoch is published until both lanes and the data registry are empty.
Pending retirement is a fixed two-fabric slot
array plus one whole-transport bit, not a lossy single mailbox or unbounded
queue. Each slot stores the exact epoch/fabric/incarnation; requests for both
fabrics cannot overwrite each other, duplicate requests monotonically coalesce,
and an older epoch cannot retire a replacement. Producers record the slot/bit
before a nonblocking wake. The coordinator atomically drains a snapshot and
rechecks the level-triggered slots before sleeping, so a request racing wake
consumption cannot be lost. `beginSetup` rejects while its fabric pending bit,
closed setup lane, whole-transport bit, or `stopping` is set; only the
coordinator's fresh single-fabric lane reopens it.

External `Stop` follows one non-self-joining terminal sequence: under the state
locks it sets `stopping`, closes new setup/data/lifetime admission, and submits
one terminal request carrying a one-shot completion channel. The coordinator
drains setup/data, delivers and receives acknowledgement for the final false
continuity edge, then closes that completion channel. `Stop` waits on it without
holding any lock, then cancels and joins `lifetimeWorkers` (which do not include
the coordinator); finally it closes retire intake, cancels and joins the
dedicated coordinator handle. The terminal completion is fulfilled exactly once
even when ordinary retirement was already pending. `beginSetup`, permanent connect loops, and
callback admission all reject after `stopping`. The daemon post-config restart
worker is outside SessionSync ownership.
A receive/setup worker can cause its own retirement but can never join itself,
and a config callback can request a future restart but cannot stop its own
`SessionSync`. Registration, drain, and shutdown tests use exact handle
completion rather than a timing-based five-second escape.

The word `protocol` in `dataWorkers` is concrete, not a catch-all promise. Every
callback reached from `handleMessage` receives and is registered with an
immutable lease before the receive loop launches or invokes it:

```go
type protocolCallbackLease struct {
    kind                  syncMessageType
    transportEpoch        uint64
    connectionIncarnation uint64
    peerProcessID         [16]byte
    ownershipGeneration   uint64
    authoritySerial       uint64
    requestID             uint64 // zero only for protocols with no wire ID
}
```

Remote failover request/commit, batch failover request/commit, and their ACK
writers are connection scoped. Their callbacks accept a bounded `context` and
the exact lease; completion revalidates before every ownership mutation and writes
the result only to the original registered connection under the write fence.
`sendFailoverResult`/batch variants may not call `getActiveConn`. If the source
fabric disappears, the operation is canceled or allowed to finish only where
its mutation was already irreversibly admitted, but its ACK is suppressed; it
never migrates to a surviving or replacement connection.

Remote failover dispatch is explicitly two-stage; the current monolithic
callback/wait/result worker is removed. A connection-scoped
`failoverMutationHandle` invokes `ManualFailoverWithAuthorityReceipt`, records
the normalized transaction's exact returned `RGMutationReceipt` and
`mutationAppliedAwaitingPublish` phase in the replay ledger, and then completes
without waiting for publication or writing an ACK. Only these mutation handles
belong to `CompleteOwnershipTransition`'s pre-publish join set. After that handle
has surrendered the immutable receipt, a separately registered
`postPublishFailoverWaiter` binds the source connection/process/request, receipt
serial/full-map digest, replay phase, and result writer. It cannot mutate
ownership. It waits for the daemon authority coordinator's receipt completion
and writes the cached applied/failed result only after exact final publication.

Replay-result finalization does not belong to that waiter. Immediately after
`PublishRGAuthority` succeeds or the exact prepared publication fails, the
daemon authority coordinator invokes one idempotent
`RecordFailoverPublicationResult(receipt, result)` that compare-and-swaps the
matching replay phase and wakes all waiters. This call occurs after `Publish`,
outside `CompleteOwnershipTransition`, and performs no ownership mutation. The
result therefore reaches the process-scoped ledger even if every source
connection and waiter disappeared before publication; an exact later retry can
observe it without repeating the mutation.

The post-publish waiter for the serial currently being committed is deliberately
not in that serial's pre-publish join set; otherwise it would wait for
`PublishRGAuthority` while `CompleteOwnershipTransition` waited for it. It remains
connection scoped and is canceled/joined on source loss, peer-process or whole-
transport replacement, transaction supersession/failure, and Stop. Canceling it
suppresses only its ACK: an already admitted safe demotion may still publish and
its replay/transfer lease remains transaction-bound. An exact retry attaches a
new source waiter to the retained phase/result. Waiter completion never calls an
ownership mutator and does not allocate another authority serial.
Each waiter has its own `failoverCallbackTimeout`; expiry suppresses only that
connection's ACK and removes the waiter. It neither restores ownership nor
marks the transaction failed. The independent transfer lease and publication
finalizer decide the transaction result.

On connections where both peers negotiated `bounded-replay-v1`, the result-
cache replay algorithm applies exactly to single/batch failover request and
single/batch failover commit callbacks; Type 29 repair, bulk,
barrier, full-set, fence, and prepare activation retain their separately defined
tokens/high-waters below. It is finite and process scoped. One failover
transaction key is `{peerProcessID, requestID}`. Its entry stores the normalized
RG-set digest and independent request-phase and commit-phase state/results;
single and batch are wire encodings of that normalized transaction, not separate
ID namespaces. Commit must reuse the request ID and exact RG set, may run only
after an applied request result, and is itself idempotent. Reuse of an ID with a
different RG set, or commit before a successful request, is a protocol
violation. The request entry is nonterminal while an applied demotion awaits its
matching commit, or while a post-mutation failure awaits the transaction-key-bound owner-
side auto-restore lease. It becomes terminal only after a cached mutation-free
reject/failure, successful commit, or observed lease-expiry restoration. Commit
after restoration is rejected from that terminal result; another transfer must
allocate another ID. Per peer process there are at most 64 in-flight callback
phases total and three distinct bounded stores: a 1,024-slot sparse request
window above the contiguous reject floor, a 64-entry nonterminal owner-transfer
ledger, and a 1,024-entry completed-result cache at or below the floor. An
applied request that still awaits commit or lease restoration moves from the
advancing request window into the nonterminal ledger; admission returns busy
before mutation when that ledger is full. No in-flight or nonterminal transfer
is evicted. A sparse-window slot is never evicted while its ID remains above the
floor, even when its result is terminal, because an older gap still makes exact
replay admissible. Once the contiguous floor covers a terminal result it may
move to the completed cache; oldest entries are evictable there because an exact
retry after eviction is safely rejected stale by the floor rather than
re-executed. If no exact window slot, nonterminal slot, or safely floor-covered
completed-cache victim is available, new unique work receives busy without
mutation. Each
phase admits at most eight duplicate waiters; further exact duplicates receive the capable
`failoverAckBusy` response (wire status value 4, valid only with
`bounded-replay-v1`) without a worker or mutation. A new unique request
at the in-flight limit likewise receives busy and may retry after the advertised
five-second control backoff. `busy` is flow control, not an operation result: it
is neither inserted into completed replay nor allowed to advance the reject
floor. A unique request rejected busy remains unseen/retryable with the exact
same ID/body, and waiter-overflow busy does not change the original entry.
Legacy/non-fully-capable requests consume the same in-flight worker budget but
receive existing `failoverAckFailed` on saturation; no status 4 is emitted and
the operator may retry the failed command. They do not gain a claim of capable
replay/continuity proof.

The owner-side transfer lease uses the same tagged namespace, not the legacy bare
`reqID`. Introduce an opaque `RemoteTransferKey{peerNamespace, requestID,
normalizedRGSetDigest}` where `peerNamespace` is the capable `peerProcessID` or,
for an old peer with no capability identity, the exact legacy transport epoch.
Pass it through request demotion, commit, clear, and
expiry restoration. The capable `OnRemoteFailover*` callbacks receive that key
from their immutable protocol lease; no daemon callback reconstructs it from a
current connection. Lease expiry reports the exact restored key back to the
replay ledger and makes that transaction terminal before a later commit can be
classified. Peer-process replacement closes admission and joins callbacks, then
synchronously restores every nonterminal transfer owned by the old process and
records the terminal outcomes before destroying its sole remote-protocol state.
Failure to restore keeps ownership/positive readiness closed and blocks the new
peer process/legacy transport; a new namespace whose request counter restarts at
one can therefore never clear, commit, or inherit an old namespace's transfer
lease. Legacy callbacks receive only the fixed 64-worker admission budget and
existing ACK statuses, not the capable completed-result ring or cross-reconnect
replay claim; losing their transport first restores every pending transfer in
that tagged legacy namespace before another legacy transport is admitted.

Senders allocate capable failover transaction IDs strictly increasing from the
pair-scoped `failoverTransactionID`, but
the receiver does **not** require cross-fabric arrival order: two ordered TCP
streams can deliver IDs 12 and 11 in that order. It accepts an unseen ID above
the request reject floor and no more than 1,024 positions ahead of it, subject to
the separate finite in-flight budget. It tracks sparse request phases explicitly
and uses the highest observed ID only for diagnostics. IDs start at one for each
newly resolved local/remote process pair, so this receive window has an exact
base; reconnect to the same pair retains it. The request reject floor advances
only across a contiguous prefix of completed request phases. A retained exact
request or commit is looked up in the sparse window, nonterminal ledger, and
completed cache before that floor check and receives its cached phase result.
Once a floor-covered terminal result ages out of the completed cache, a request
or commit at/below the floor is stale and rejected, never re-executed. A new request
ID beyond the right edge is a protocol-window violation and retires the
transport rather than allocating memory. Gaps inside the window remain
admissible and cannot be skipped merely because a larger ID arrived first. The
fixed modulo slot for a gap is reserved by the window geometry rather than being
consumed by old nonterminal transfers or higher terminal results.

The sender retains each allocated-but-unacknowledged request or commit phase and
retries that exact ID/body/phase after ambiguity or `busy`; it may issue later
transactions concurrently within the window, but it may not declare a missing
request ID abandoned and advance forever. Same ID with changed RG set is
forbidden. A successful request awaiting commit cannot be evicted; commit or the
existing transaction-key-bound transfer-out lease must first produce a terminal transaction
result. Thus ordinary reconnect/write failure eventually closes each legitimate gap,
while a peer that deliberately withholds a gap reaches a bounded fail-closed
window instead of growing memory. A callback records phase completion before
any result write. Its original waiter writes only to the original source; an
independently admitted exact retry on another current connection attaches its
own source waiter or receives the cache and writes there. The old callback never
migrates its ACK. The ledger is destroyed only after peer-process replacement
has closed admission, joined every callback/waiter for the old identity, and
completed the exact old-process transfer restoration above.

`dataWorkers` charges the same 64-entry protocol in-flight budget before
launching callback work. Captured session deltas use the finite per-key tail
coalescer defined with the authoritative bulk below; its checked capacity is
derived from aggregate helper session capacity rather than a 4,096-event FIFO.
Overflow closes producers, records mandatory full-bulk debt, and retires the
transport if the current snapshot cannot absorb the tail. No callback, waiter,
or deferred item allocates an unbounded goroutine/channel.

`OnFenceReceived` and `OnPrepareActivation` are transport/process scoped,
cancellable, idempotent callbacks. A same-process surviving fabric may let an
already admitted callback complete, but last-fabric/process replacement closes
and joins it before new authority. Capability mode extends prepare activation
with an exact payload of nine bytes: `{rgID uint8, requestID uint64 LE}` with a
nonzero request ID. Legacy mode accepts exactly one byte containing only `rgID`
and remains idempotent without an acknowledged causal guarantee. Capability
mode rejects the one-byte form; legacy mode rejects the nine-byte form; every
other length is malformed and retires the source transport.

Prepare activation remains a one-way best-effort prewarm and therefore does not
pretend to use the result-bearing replay cache. The sender allocates its capable
ID from the fixed per-remote-process/per-RG counter. The receiver has a fixed
256-entry high-water array scoped to that sender process: for the exact RG it
atomically records a larger ID before launching the idempotent callback and
drops equal/lower IDs. Cross-fabric reordering for one RG is latest-wins; another
RG has an independent namespace, so RG2 cannot suppress RG1. No ACK, waiter,
cached result, receive-window gap, or unbounded map is created. If stronger
causal activation proof is later required, it needs a separately versioned ACK
rather than being inferred here.

IPsec and DHCP full-set callbacks are
connection/process/sequence scoped and run in registered handles rather than
blocking the receive worker; stale completion cannot publish after the exact
full-set guard, transport, or process moves. Peer-connected, config, bulk,
barrier, continuity, and metrics callbacks are likewise listed in one source
registry with their scope and lease. Metrics-only callbacks may outlive no data
handle and cannot mutate authority.

No callback receives `context.Background`, no bare `go On...` remains in a
production protocol dispatch, and no callback or ACK chooses authority from the
then-current active connection. A source canary enumerates every callback field,
handler launch, result writer, and waiter map; adding a new callback without a
declared scope, registry owner, context, and invalidation test fails CI.

Raw election state cannot be the authorization state for **any** redundancy
group. Add one immutable, atomically published full ownership snapshot owned by
`cluster.Manager`:

```go
type RGAuthorityEntry struct {
    Present   bool
    State     NodeState
    Priority  int
    Weight    int
    Heartbeat HeartbeatGroup // exact saturated wire row, including GroupID
}

type RGAuthoritySnapshot struct {
    Serial        uint64
    Desired       map[int]RGAuthorityEntry
    Committed     map[int]RGAuthorityEntry
    ChangedGroups bitset256
    Transitioning bool
}

// Additive internal field; zero only for non-authority observability events.
type ClusterEvent struct {
    // existing fields...
    AuthoritySerial uint64
}
```

Every production mutation of a **local** redundancy-group state, priority,
effective weight, or definition
routes through one manager-owned mutation boundary. Single-election actions use
`mutateLocalRGLocked(groupID, stateMutation)`; config reconciliation uses one
`replaceLocalRGDefinitionsLocked(fullDefinitions)` batch, never a loop of
independently publishable inserts/removals. The batch derives the complete
desired election state and returns one `RGMutationReceipt` under the same
serial. RG0 removal desires `StateSecondaryHold` and drains/fences before final
publish rather than deleting authority out from under the gate.
A source canary permits direct writes of `rg.State`, `rg.LocalPriority`, or
`rg.Weight` and `m.groups` insert/delete only inside those two mutation
boundaries (peer-state storage is a separate typed field). Monitor recalculation
computes the candidate weight first and enters this boundary before storing it;
it cannot publish raw zero as an early peer-election signal. A real local
state/priority/weight/definition change builds a complete desired ownership map
and exact saturated heartbeat rows, publishes a
new nonzero manager-wide serial with `Transitioning=true` **under the manager
mutex before** it writes any raw field, changes the local group map, or emits an
event. This covers monitor success/failure and priority/config changes, normal
election, manual and batch failover,
secondary-hold preparation, kernel self-recovery, upgrade drain, and config
reconciliation rather than only `election.go`. An idempotent write of the same
desired full map allocates no serial and emits no event; if that map is already
pending, callers join/re-drive the existing serial rather than creating an
unbounded transition storm. Concurrent changes coalesce by replacing the one
pending full desired map with a newer serial; they never independently publish
two partial ownership sets.

Every local-RG authority event carries the exact serial; a handler never pairs
an old event's `NewState` with a newly loaded snapshot. The safety net consumes
the current level-triggered full snapshot directly. While transitioning, the
snapshot retains the full previous committed map and exact heartbeat rows for
wire serialization and
returns unknown/fail-closed for each changed group's committed-authority query.
`buildHeartbeat` reads only `RGAuthoritySnapshot.Committed`, sorts those rows by
GroupID, and never reads raw `m.groups` priority, weight, presence, or state.
Thus a remote election sees the complete old row until negative traffic fencing
and final authority publication commit the complete new row; it never sees old
primary state paired with new zero weight or priority.
SessionSync closes its global producer/receive authority for the whole ownership
transition, even when one group changed, because one authoritative bulk spans
all locally owned zones. It atomically replaces the deep-copied `ZoneOwners`
map only at commit. This deliberate coarse barrier makes stale RG1+ owners
unable to produce a zone while a new owner starts and prevents an old-owner
bulk from deleting the new owner's valid sessions.

Every authority-sensitive consumer (config push/write and store ownership for
RG0; session ownership for every RG; heartbeat/readiness, forwarding/VIP/VRRP/
helper positive acts, and ancillary advertisements for their owning RG) uses
`CommittedRGAuthority(groupID)` or the immutable full committed snapshot, never
raw `IsLocalPrimary`, `GroupState`, or event `NewState`. Raw election state
remains available only to election mechanics and explicitly labelled
observability. The AST/source canary covers all production `IsLocalPrimary*`,
`GroupState`/`GroupStates`, local `ClusterEvent.NewState`, direct local
`rg.State` writes, group-map insert/delete, direct `sendEvent`, and zone-owner
construction; intentional election and labelled observability sites are a
finite AST-resolved allowlist, not a substring search.

The existing `sendEvent` path's synchronous primary-side `triggerGARP` is also
an authority actuator. The raw-state helper records history and emits only the
serialled transition event; it does **not** trigger GARP or any other positive
side effect for any RG. After `PublishRGAuthority` succeeds, the daemon invokes
one idempotent post-publish activation wrapper for each changed group, which
re-reads the exact committed serial before GARP/NA, VIP, VRRP, helper,
forwarding, store, config, session ownership, or readiness publication. A
dual-active `Primary -> Primary` reaffirm allocates no transition, but may
announce only after revalidating that the same group is primary in the current
committed snapshot.

Remote manual-transfer ACK gating is receipt-bound to this same publication.
`armFailoverActuation` first reserves a one-shot token; the remote-transfer-only
`ManualFailoverWithAuthorityReceipt(token, ...)` mutation boundary atomically
binds it to the newly allocated manager authority serial/full-map digest before
emitting its event and returns that receipt. Batch transfer binds one token to
the batch's single full-map receipt. The daemon
coordinator completes that token only after all required negative actuators and
`PublishRGAuthority` have succeeded and the exact committed entries are
secondary/held. `WaitFailoverApplied*` waits that token, not a per-RG boolean or
the earlier BPF-fence completion. Supersession, timeout, or publication failure
returns failed, retains/restores the transaction-key-bound owner transfer lease,
and sends no applied ACK. Therefore a requester cannot promote from a failover
ACK while the demoting node's committed heartbeat/authority row is still the old
primary, even if the packet fence finished first.

Every local RG heartbeat row is derived from the snapshot's full committed
`NodeState`, not `rg.State`. During a transition each changed row continues
advertising its **previous committed** role until local drain/fencing, gate
staging, and final manager publish complete; this prevents the peer from
promoting on a demotion that has not yet removed local forwarding. Boot with no
prior committed role advertises `StateSecondaryHold`. After commit, all changed
rows atomically switch to their new roles. Operational status shows desired/raw,
changed-group set, transitioning serial, and committed/advertised state so the
deliberate lag is diagnosable.

The manager starts with an unknown, transitioning full snapshot. Authority
initialization reconciles all already-computed raw roles and the exact config
zone-to-RG map into SessionSync before publishing the first committed snapshot,
so boot cannot expose positive authority during wiring. A dropped event cannot
restore authority: the level-triggered safety net sees the pending serial and
full desired map directly from the manager.

Every local-RG actuator path then uses one daemon coordinator shared by
`watchClusterEvents` and that safety net:

```go
token := ss.BeginOwnershipTransition(snapshot.Serial, snapshot.Desired,
    zoneOwnersForCommittedConfig(snapshot.Desired, committedConfigRecord),
    configSyncEnabled)
// Demotion may apply idempotent fail-closed traffic fences here.
publish, err := cluster.PrepareRGAuthorityCommit(snapshot.Serial,
    snapshot.Desired)
gatePermit, err := ss.CompleteOwnershipTransition(ctx, token)
err = cluster.PublishRGAuthority(publish, gatePermit)
// Only the exact final publish may expose group ownership or positive acts.
```

`Begin` first passes through the write fence above, then claims the
manager-published serial and marks the SessionSync gate transitioning, closes
all admission and outbound producers, cancels old-ownership bulk/reconcile
contexts, invalidates repair bindings, sets current continuity false, increments
`outboundAuthorityGeneration`, and returns without waiting under a lock.
Config-sync-mode change and every local/received config authority transaction
increment that same generation before canceling work. It does **not** advance
`ownershipGeneration` while an admitted config callback can still mutate the
store. The callback may finish under the unchanged predecessor gate ownership,
but raw election movement grants no authority because the manager snapshot is
transitioning. `PrepareRGAuthorityCommit` verifies the exact manager serial and
complete desired map and returns an opaque one-shot publish token, but
deliberately leaves `Transitioning=true`. `Complete` then joins every
old-ownership producer, failover **mutation** handle and other callback that can
change the ownership map, receive
window, repair, and bulk operation; atomically verifies the SessionSync token;
deep-copies the complete new `ZoneOwners`; advances `ownershipGeneration`; and
stages the new gate ownership. It excludes only the exact serial's non-mutating
`postPublishFailoverWaiter`; stale/superseded waiters are canceled outside locks,
and lifecycle/Stop still joins every waiter.

It returns an opaque one-shot gate permit only when the exact full ownership
serial is staged, config authority is fully applied when RG0/config-sync inputs
changed, and no config-mutation/apply failure is present. A protected RG0
secondary may still have `baselinePending`: committing a non-owner role is
required so it can receive that baseline, while the separate session gate
continues to block continuity/manual transfer. A failed or partially armed
callback returns no permit and leaves the manager transitioning until exact or
newer reapply. Admission and positive acts remain blocked because every gate
check also requires the same serial and ownership map to be globally committed.
The manager's `PublishRGAuthority` requires both one-shot tokens, verifies their
common serial and full-map digest, and is the final exact compare-and-swap that
clears `Transitioning` last. It is the sole visibility point for the new
ownership set.
If any token is superseded between prepare, stage, and publish, the manager
remains transitioning, a stale staged gate cannot admit because its serial does
not match committed global authority, and the level-triggered coordinator
retries the newest desired snapshot.

On any group demotion/removal, only negative traffic removal (inactive RG, blackhole, VIP
withdrawal, VRRP resign) may run before completion. Store ownership, config
acceptance/readiness, helper rearm, config push, and every positive act wait for
the final publish. Promotion likewise performs no forwarding, VIP, VRRP, store,
session production, config-write, or config-push act before the final publish.
Timeout leaves affected forwarding fenced and the global session-ownership gate
closed. One full desired-ownership slot coalesces newer serials and retries with
bounded backoff; event and safety-net paths cannot bypass each other or consume
a failed transition.

The config handler resolves the exact source registration before changing any
high-water. Admission closes the session gate and waits for admitted installs.
Configuration identity has two deliberately different scopes. A nonzero
generation is allocated and owned by one daemon process and is meaningful only
together with that `peerProcessID` and digest. Different processes need not
allocate the same generation. The sender process plus `senderConfigEpoch` is
the equivocation/replay identity; digest equality is the prerequisite for
reciprocal active/active session exchange.

`CanonicalCommittedConfigIdentity(tree)` is a separately owned pure function,
not an alias for arbitrary `tree.Format()`. It deep-clones the complete prepared
tree, recursively strips source positions and display-only metadata
(`Node.Annotation` and `Node.InheritedFrom`), applies the existing deterministic
hierarchy normalization, renders that clone, and returns the exact `wireText`
plus `SHA-256(wireText)`. Annotations remain local operator metadata and are not
config-synchronized. The function must be idempotent: parsing `wireText` and
running it again returns byte-identical text/digest. This identity proves only
equality of the canonical forwarding/config hierarchy after those explicit
metadata exclusions; it does not claim that all semantically equivalent input
programs have equal digests.

The upgraded sender transmits only this metadata-free `wireText`. The receiver
parses it, recomputes the identity, and requires byte/digest equality before
preparation or promotion. Local commit, peer apply, daemon boot, persistence
reload, and cluster-comms restart all call or replay this same function/result;
none hashes an annotated `Format()` result. A source canary rejects direct
config-sync digest construction and direct `Node.Format()` hashing.

Boot owns generation 1. Before each later local or peer promotion of a new
canonical identity, the owning daemon reserves the next checked local generation
once and carries that immutable prospective `committedConfigRecord` in the
transition lease. A failed/conflicting pre-promotion attempt burns the reserved
generation, while promotion success commits it and a post-promotion failure
retains it in `failedConfigMutation` for exact recovery. No generation is ever
reused. A fully successful peer apply records the received **peer** epoch
separately in `acceptedPeerConfigEpoch` and never copies it into the local
record. An exact replay of the already accepted remote process/epoch plus
canonical identity reuses both records and allocates nothing. Reconnect, retry, RG0 promotion, and reciprocal
session production replay those immutable records. Replace allocating
`QueueConfig(string)` with `QueueCommittedConfig(committedConfigRecord) error`;
only boot/local/peer transaction completion may call the checked allocator, and
a source canary rejects generation allocation in send/reconnect/reconcile paths.
The compact session `ConfigEpoch` and every locally sent bulk token use
`committedConfigRecord.epoch.generation`, never the accepted peer generation or
a live counter read.

Peer epoch movement is separated from local config mutation. If an incoming
capable payload has byte-identical canonical text/digest to the current local
record and no failed apply exists, a newer valid epoch in that remote process
advances only `acceptedPeerConfigEpoch` under the gate transaction; it performs
no store promotion/full dataplane apply, allocates no local epoch, and preserves
local-only annotations. An exact duplicate remote epoch is idempotent. The same
remote generation with another digest is corruption, and a different digest
requires the full prepared apply. A record matching a `failedConfigMutation`
never takes this equality fast path: it must complete the exact recovery apply.

The upgraded config payload is exactly
`[config text][configEpochMagic (8)][generation LE (8)][digest (32)]`; the
decoder hashes only the text prefix and requires equality with the trailer.
`configEpochMagic` is a new fixed eight-byte sentinel distinct from the legacy
generation sentinel. A fully capable connection requires this form; malformed,
zero, or digest-mismatched input retires the transport before callback
admission. Legacy/partial-capability connections send and decode only the
existing config payload and can never establish authoritative continuity.
Type 29 also carries `{requestID, generation, digest}` and declares the
requester's local outbound epoch. A capable responder never compares that
generation with its own. It responds only when the requester's digest equals
its own canonical committed digest and the request is admissible under the
requester's process-scoped epoch ledger. Its BulkStart/BulkEnd then declare the
responder's own sender epoch, BulkAck accepts the baseline, and TailAck commits
the captured tail. The
receiver binds the responder generation before admitting ordinary responder
session frames. The committed RG0 authority pushes config text when the peer's
digest is stale; a protected receiver waits for that full config and then
issues a new request. Thus an RG0 secondary that owns RG1 sessions proves
equivalent config to the RG0 primary without sending a reverse full config,
even though the two processes legitimately use different generations. The
per-session wire remains one `uint64`: the corresponding digest is bound by the
preceding request/bulk marker exchange and producer authorization cannot open
before the matching epoch-bearing TailAck.

Reaching the operational `MaxUint64-1` allocation boundary executes the
controlled full-process exit described above; it never wraps or rotates
identity in place. Within one process, generations
increase strictly and one generation may never name two digests;
same-process/same-generation/different-digest input is a protocol violation that
retires the transport. A higher generation with a different digest requires a
fully validated config apply before it can become accepted; a Type-29 or bulk
marker alone cannot change effective config. The first protected baseline from
a new peer process may establish a lower rebooted generation only after full
text/digest validation or, when config sync is disabled, after exact canonical
digest equality with the independently committed local config. Both session
directions remain closed until paired epoch-bearing requests/bulks succeed.
Generation zero or a digest not bound to that sender/process is never
authoritative.
A successful callback has the internal signature
`func(context.Context, string) (ConfigApplyOutcome, error)`, returns a
`ConfigApplyOutcome`, and publishes the deep-copied
authority delta through its exact `configApplyLease`; no callback invokes a
SessionSync authority setter while it is itself admitted. The callback returns
the newly committed local record in `ConfigApplyOutcome.CommittedConfig`; it is
never reconstructed from the peer generation. The gate atomically commits the
remote `acceptedPeerConfigEpoch`, local `committedConfigEpoch`,
`ConfigSyncEnabled`, and `ZoneOwners` after the callback returns nil and its
transport, process, ownership, peer generation, and digest lease still match.
Manager-authority movement is a separate publication decision, not grounds for
discarding a mutation that has
already changed the store/dataplane. In particular, the callback's existing
`cluster.UpdateConfig` tail may run election and publish transitioning serial
`S+1` while the callback was admitted under committed serial `S`.
`cluster.UpdateConfig` returns the exact `RGMutationReceipt` in
`ConfigApplyOutcome` rather than hiding the child transition behind an event.
Completion verifies the receipt digest against the manager's pending full map,
records the successful config/delta against the predecessor gate lease, and
keeps admission and every positive act closed; `BeginOwnershipTransition` must
join that callback before replacing the gate serial and then stages `S+1` with
the callback's newly committed zone map.
An unrelated manager transition uses the same rule. A globally committed serial
past the lease is an invariant violation because ownership completion must join
the callback; it still cannot erase the successful mutation record, so the gate
stays failed/closed, the transport retires, and the level-triggered authority
coordinator adopts the applied generation under the current serial before any
reopen. `acceptedPeerConfigEpoch` is the authoritative inbound high-water and
`committedConfigRecord.epoch` is the local effective/outbound epoch; existing
atomic last-applied/counter fields become observability or allocation mirrors
updated inside that same closed-admission commit. There is no interval in which
session admission sees new ownership with an old config epoch (or the inverse).
Failure keeps baseline and previous-good state, sets
`authorityApplyFailed`, records the exact `failedConfigMutation`, and leaves
**all** config/session/bulk admission fail-closed until a full apply succeeds. It
does not restore old authority, because prepared peer/local promotion may already have promoted or
partially armed the incoming config. After recording diagnostics, a failed peer
callback retires the transport; it does not wait indefinitely for a future
unrelated commit.

A daemon-owned, level-triggered config-recovery worker handles the case where a
promoted/armed failure also left global RG ownership transitioning, so waiting
for a new peer frame would deadlock behind closed authority. It belongs to the daemon
lifetime registry and retries the exact in-memory failed text/generation/digest
through the normal context-aware full apply under `applySem`; the recovery lease
permits only this local mutation while global authority is transitioning and
does not admit network config/session/bulk frames. It uses bounded exponential
backoff, coalesces to the newest failed/full-replacement record, never logs or
persists config text. Full success clears the matching failure and wakes the
desired-ownership coordinator, which re-enters fresh exact Begin/Prepare/Complete
tokens for the still-pending serial; only that pass returns a gate publish
permit.
Pre-promotion failures under still-committed authority may also recover by the
immutable sender replay. Process restart discards the in-memory failure record
and performs the normal full boot apply before authority initialization.

On reconnect, a replay matching the failed process/config epoch bypasses
the ordinary equal-generation duplicate fast path and runs the complete apply
and arm pipeline again. A higher immutable sender record may instead replace a
failed generation; it runs as a full replacement from the current promoted
state and clears the older failure only after complete success. A same
generation with another digest never clears it. An already accepted exact
duplicate performs no store mutation but may establish the new transport's
config baseline and paired repair. This gives the sender concrete state to
re-emit and the receiver concrete state to distinguish idempotent duplicate,
mandatory reapply, valid supersession, and protocol corruption.

The context belongs to the admitted apply lease. Last-fabric loss, a newer
config mutation, and Stop cancel it. An ownership transition does **not** cancel
an admitted callback: the callback may itself have caused that transition via
`cluster.UpdateConfig`, so cancellation would create a self-induced failed
apply. Global authority is already transitioning/fail-closed; `Begin` fences
negative traffic as needed and joins the bounded callback before staging the new
ownership map. `syncAndApply` passes that context to
`applySem.Acquire`, `applyConfigLocked`, and every potentially blocking tail;
it never substitutes `context.Background`. Local operations that cannot accept
a context use an explicit bounded deadline. The callback returns a typed
`ConfigApplyFailure` identifying whether cancellation/error happened before
promotion, after prepared-store promotion, or after dataplane arm. Pre-promotion
failure is mutation-free. If manager mutation already produced a receipt, the
typed failure carries it and the failed-mutation/recovery record adopts that
exact pending serial rather than relying on event delivery. A promoted/armed
failure is never abandoned: all
suboperations cease before callback return, the active digest remains unmarked,
authority remains failed/closed, and either the exact record or a strictly newer
full replacement must apply completely before establishing a baseline. No replacement authority may overlap a
still-mutating callback, but bounded cancellation guarantees the join itself is
not an unbounded dependency on an opaque operation.

Local active-config mutation uses a concrete symmetric API:

```go
type PreparedActiveMutation struct { // configstore-owned; all fields private
    id                      uint64
    storeMutationGeneration uint64
    mode                    activeMutationMode
    view                    PreparedConfigView
    sealedDigest            [32]byte
    // private tree/compiled/persistence transaction state
}

type localConfigTransitionLease struct {
    source            ConfigMutationSource
    prepared          *configstore.PreparedActiveMutation
    view              configstore.PreparedConfigView
    previousRecord    committedConfigRecord
    reservedRecord    *committedConfigRecord // nil only for unchanged canonical identity
    authorityToken    ownershipTransitionToken
    preparedInventory boundOwnerInventory
}

func (s *Store) PrepareLocalCommitGen(gen uint64,
    description string) (*PreparedActiveMutation, error)
func (s *Store) PrepareLocalCommitConfirmedGen(gen uint64,
    timeout time.Duration) (*PreparedActiveMutation, error)
func (s *Store) PreviewPendingRollback(gen uint64) (*PreparedActiveMutation, error)
func (s *Store) ViewPreparedActive(*PreparedActiveMutation) (PreparedConfigView, error)
func (s *Store) PromotePreparedActive(*PreparedActiveMutation) (*PromotedConfigView, error)
func (s *Store) AbortPreparedActive(*PreparedActiveMutation)

func (d *Daemon) BeginLocalConfigTransition(ctx context.Context,
    source ConfigMutationSource,
    prepared *configstore.PreparedActiveMutation) (*localConfigTransitionLease, error)
func (d *Daemon) AbortLocalConfigTransition(
    *localConfigTransitionLease, error) error
func (d *Daemon) CompleteLocalConfigTransition(*localConfigTransitionLease,
    *configstore.PromotedConfigView, LocalConfigCommitOutcome) error
```

Under `applySem`, plain/operator commit, autonomous event-engine commit, and
commit-confirmed ask `configstore` to compile, preflight, canonicalize, and seal
the generation-bound candidate in one opaque `PreparedActiveMutation`, then call
`BeginLocalConfigTransition` immediately before `PromotePreparedActive`. The
daemon can inspect only `ViewPreparedActive`; no independently supplied compiled
pointer, canonical identity, or generation can disagree. Begin derives
authority and owner-inventory deltas from that exact immutable view. If its
identity differs from the current identity, Begin first reserves the next
checked local record; exhaustion occurs before any gate or store mutation. It
then captures the complete previous authority/inventory record, closes/drains
the gate, installs required fences/debt, and returns a one-shot lease. By the
configstore contract, any returned commit error means no active mutation (all
post-rename outcomes converge and return success), but Begin may already have
applied negative fences. `AbortLocalConfigTransition` therefore does not merely
drop a token: under the same serializers it restores the captured previous
inventory/helper snapshot and gate authority through the
debt engine, returning
only after success. Compensation uses a fresh daemon-lifetime bounded recovery
context rather than the possibly canceled management request context. If
restoration fails, it returns the joined error, retains
explicit fail-closed compensation debt, and the caller may not retry a candidate
until recovery completes. The unused reserved generation is burned. Promotion
success consumes the reserved local record and proceeds through the full
context-aware apply using only the fresh sole-owner compiled clone returned by
`PromotePreparedActive`. It stages all helper/dataplane work into one immutable
`PreparedRuntimePublicationToken`; the ordinary config transaction consumes
that exact token at the sole committed-runtime linearization. No caller publishes
`committedRuntimeConfig` independently. The complete outcome authorizes parent
`Complete` to publish `OwnershipMutation`, the canonical record,
zone/config-sync delta, push decision, and restart outcome. A partial or
ambiguous helper/dataplane apply remains exact parent recovery debt and cannot
report full apply success or release positive admission.

Automatic commit-confirmed rollback gets an exact pre-promotion target through
`PreviewPendingRollback(gen)`, returning the same opaque prepared type with an
immutable view and private target tree/compiled/persistence state. It begins a
local transition from that view before `PromotePreparedActive(token)`.
Supersession/no pending state is mutation-free and aborts the lease. Promotion
success applies the exact promoted clone; a first
commit rollback transitions explicitly to bootstrap/default-deny and runs the
teardown under the same closed gate. Candidate-only `Rollback`,
`ConfirmCommit`, and pending-confirm cancellation/demotion do not replace active
config and therefore do not open a local authority transaction. Initial file
bootstrap and persisted boot apply occur before SessionSync exposure and use
the boot transaction, not a live transition. Peer `PrepareSyncApply` remains the
separate remote-source path above.

A post-promotion/arm/tail failure records one source-typed
`failedConfigMutation` containing the store mutation generation, canonical text/digest,
stage, and exact ownership receipt; the recovery worker retries that active
record rather than the candidate or current store by inference. Authority and
positive readiness remain closed. A source canary enumerates every production
active-store promotion call (`PromotePreparedActive` and
`PromotePreparedSync`) and requires its corresponding Begin/Abort/Complete path;
direct production calls to legacy `CommitWithDescriptionGen`,
`CommitConfirmedGen`, `SyncApply`, or rollback promotion fail the canary. gRPC,
REST, shell, event-engine, timer rollback, and
first-commit bootstrap fixtures execute their real daemon entrypoints. No path
publishes new zone ownership or config-sync mode midway through
`applyConfigLocked`.

The local push decision is bound to that transaction, not re-derived only from
the new active config. An RG0 authority sends the immutable committed record when
`old.ConfigSyncEnabled || new.ConfigSyncEnabled`: false -> true propagates the
enabling generation, and true -> false propagates one final disabling
generation before later pushes stop. The outcome records this exact decision so
the post-apply path cannot skip the disable by observing only the new false
value. A config that remains false does not push, but it still commits its new
local sender epoch into the gate, invalidates both old epoch authorizations, and
requests capable bidirectional repair. Repair remains closed with an operational
digest-mismatch alarm until the independently managed peer commits the same
canonical digest; it never treats generation equality as a substitute. The
final disabling generation still uses the capable config-plus-request
transaction and both peers complete post-config session repair before remaining
in unprotected/manual-unready legacy semantics as applicable.

Transport restart is an outcome, never an action performed from
`OnConfigReceived`. The daemon adds `configRuntimePublishMu`, a narrow mutex
whose only mutable state is the immutable pointer-valued
`committedRuntimeConfig` ledger. The sole publication helper is
called with `applySem` and `haInventoryTxnMu` already held; it takes
`configRuntimePublishMu`, verifies the exact prepared publication token and
store/helper/worker generations, swaps the ledger pointer, and releases the
mutex without allocation, I/O, RPC, or wait. Every ledger reader uses a bounded
accessor under that same mutex. The lock graph adds
`applySem -> haInventoryTxnMu -> configRuntimePublishMu`; the existing sibling
edge `haInventoryTxnMu -> Manager.mu` remains, and `configRuntimePublishMu` and
`Manager.mu` are never nested. No reverse edge is legal.

After lease publication and high-water advancement, that helper publishes the
exact **local sender** generation/digest plus a deep-copied
`clusterCommsRuntimeSnapshot` in `committedRuntimeConfig`. This publication
happens only after the whole runtime has been prepared while packet workers and
positive admission remain closed; `store.active` is not the runtime-selection
oracle because a prepared store transaction may promote a candidate before its
tail succeeds. The config loop then sends a nonblocking level-triggered wake
to a daemon-owned restart coordinator outside `SessionSync` ownership. On every
wake the coordinator reads only `committedRuntimeConfig`, never the current
active store. Thus a waiting generation `G1` cannot restart from promoted but
failed `G2`; a later fully committed `G3` simply supersedes the desired ledger.
The wake may coalesce but desired state cannot be dropped: before sleeping the
coordinator re-reads the ledger and requires the running epoch identity to equal
its generation/digest/runtime snapshot.

One `clusterCommsEpoch` owns the constructor, SessionSync, watchdog, heartbeat,
gRPC, userspace event stream, reconcile, IPsec, and both fabric workers through
an explicit context and closable handle registry. Start builds and registers a
new epoch from the committed runtime snapshot before publishing it. Restart
atomically detaches the old epoch, closes registration, cancels it, joins every
handle without the current timeout-abandon path, closes resources, and only
then publishes the replacement. A source canary enumerates every goroutine
launched from `startClusterComms` and requires an epoch handle. The restart
coordinator itself belongs to the daemon lifetime registry; shutdown closes its
event admission, cancels and joins it, and then drains the current comms epoch,
so no delayed event can start workers after shutdown. Consequently `Stop` can
cancel and join the config loop without that loop synchronously waiting for
itself, old/new epoch workers cannot overlap, and a stale event cannot restart
an older transport over a newer committed generation.

Config receive hashes the decoded text, validates the complete peer-process/
config-epoch identity, and records a pending frame high-water identity
only after exact source admission; a scalar generation alone is never enough.
If the ordered apply queue cannot accept that frame, the closed authority gate
does not linger waiting for an unrelated commit: it records repair/error debt
and asks the lifecycle coordinator to retire the transport, forcing the same
unaccepted generation to be re-pushed on reconnect.

A config send on the authority side first takes the write fence and increments
`outboundAuthorityGeneration` under `gate.mu`, clears
both bulk-authorized directions, closes the producer gate, and snapshots the
cancellation handles for any outbound bulk, barrier set, inbound window,
pending peer request, pending receive ACK, and request attempt. It also clears
current continuity, retains previous-good,
and arms repair. For a real continuity edge it enters through the combined
continuity-publisher and write-fence order and commits the reserved false event
after releasing state locks. After releasing the gate and the write fence it joins those
workers, then calls `QueueCommittedConfig(record)` and follows it on the **same
exact connection** with a fresh nonzero type-29 request carrying that record's
epoch for the peer's post-config owned-session snapshot;
that request attempt is recorded before either write.
It holds the SessionSync `writeMu` once across both bounded writes so no other
frame can separate their TCP order. Under the narrow pre-write lock edge, it
revalidates the exact connection/transport/process/ownership/authority token before
the config write **and again after that write before the request write**. An
incoming config or ownership transition that lands during the first syscall may
therefore leave a delivered config without its request, but can never emit a
stale request afterward; the transport retires and reconnect re-primes both
directions. The config writer is itself in every authority-transition join set,
so an old-ownership write cannot outlive ownership commit. The pair is one
authority-write transaction: failure of either write retires the transport. BulkSync captures this generation in
its immutable token and revalidates it before every barrier set and BulkStart;
a config writer that wins any race therefore prevents the old bulk marker.

Config-frame admission on the receiver first takes the same write fence, then
increments `outboundAuthorityGeneration`, clears both authorization
directions/current continuity, and invalidates pending ACK/request state before
invoking the callback. Because the
following request is received in TCP order, its sender tuple captures the
pending received config epoch as its minimum accepted identity and cannot
trigger an outbound bulk until that exact epoch applies.
After the exact config callback succeeds,
the receiver (a) may service that pending peer request with its own post-config
snapshot and (b) issues a reciprocal fresh request for the authority's snapshot.
Thus active/active ownership converges both directions; failure leaves both
producer/continuity gates closed. The sender cannot use `OnPeerConnected`
cold-prime as a substitute.
The paired request/producer closure applies only to a fully capable transport.
Legacy mixed transport retains current config plus ordinary incremental
behavior, emits no type 29/bulk, and remains continuity/manual-transfer unready.

Session install admission precedes per-key ordering and membership. It rejects
and increments repair debt when initialization/connection/transport/ownership
or local helper generation is stale, transition/apply/drain/reconciliation is active, a protected baseline
is pending, the peer's bound config epoch is zero, or the frame's nonzero
generation differs from `acceptedPeerConfigEpoch.generation`. Ordinary
production is still closed unless the Type-29 digest binding and exact final
TailAck proved the complete baseline plus captured tail, so a colliding bare generation cannot pass this
compact per-session check. Dataplane install runs outside locks. Completion adds
membership only if the exact connection, receive-window serial, and destination
helper generation are still current. A successful install whose window later aborts remains an ordinary
valid nontransactional install; the protocol does not promise rollback. The
failed window performs no final ACK, readiness release, previous-good takeover,
or debt discharge, and the next authoritative repair converges any retained row.

Per-key and full-set ordering remain qualified by
`(transportEpoch, peerProcessID, generation)` (plus existing wire incarnation/
sequence where applicable). A frame must first match the current registration;
process IDs are identities, not sortable values. No BulkStart resets any
high-water. IPsec/DHCP full sets are never bulk members.

Connection setup resolves capability before active registration. Existing
authentication HELLO/PROOF frames are setup traffic and are exempt from the
"first post-auth frame" rule. After `performSyncHandshake` and wrapping the raw
connection, every upgraded build, keyed or unkeyed, emits one capability frame
as its first post-auth frame while concurrently reading the peer's first post-auth frame
under `syncCapabilitySetupTimeout`. A frame already consumed by authentication is
staged into this same step. The frame is never dispatched before registration.
The exchange is full duplex: the setup handle starts one tracked bounded
capability write while the same handle reads (or consumes the staged frame),
then joins the write result before classification. The write is not an
unregistered goroutine, uses the same absolute setup deadline, and is canceled/
joined by setup retirement. Thus symmetric upgraded peers and `net.Pipe` cannot
deadlock in write-then-read, and no setup write survives its epoch.
If an unkeyed local no-op handshake encounters an old keyed peer's HELLO/PROOF
in this step, the setup parser consumes it under the existing dual-accept rules
and continues reading; auth frames neither classify the peer legacy nor enter
`handleMessage`. Repeated/unexpected auth setup still shares the same deadline.
The existing `beginSetup` admission slot remains held through capability
resolution and `finishSetup` runs exactly once afterward; the new deadline
therefore cannot create an unbounded post-auth setup/socket-buffer population.

`syncMsgCapabilities = 30` has exactly 50 payload bytes: little-endian
`version uint16`, little-endian `flags uint64`, nonzero
`peerProcessID [16]byte`, `maxLocallyCreatedLogicalSessions uint64`,
`maxAcceptedLogicalSessions uint64`, and `maxCapturedTailRows uint64`. All
three capacities are nonzero and checked against local integer/memory bounds
whenever any complete-bulk bit is advertised. An upgraded endpoint whose
capacity plan cannot support complete bulk emits all three as zero with all
five complete-protocol bits clear; that is a valid partial capability for
legacy ordinary traffic, but zero with any required bit is a protocol
violation. `maxLocallyCreatedLogicalSessions` is the node's checked ceiling for
new locally sourced forward authority before peer promotion.
`maxAcceptedLogicalSessions` is the receiver's
reserved maximum peer-owned **forward logical sessions**, not a worker-table or
shared-map entry count. `maxCapturedTailRows` is additional temporary mutation
headroom during the two-stage baseline/tail transaction; it is not reusable
baseline credit. Before capability setup the applied helper builds one immutable
`SessionCapacityPlan` with:

- `workerLocalCreationForwardCeiling`, the checked sum of every worker's local SessionTable
  entry ceiling. This deliberately over-reserves: a forward plus a locally
  materialized reverse may consume two of those entries, so the number of local
  forward logical sessions can never exceed the sum.
- `localAuxiliaryForwardCeiling = DEFAULT_MAX_SESSIONS`, a new hard cap for
  coordinator-created local-tunnel forward sessions. Their current
  `UpsertLocal -> upsert_synced_with_origin` path bypasses every worker local cap
  and its 4,096-row refresh/prune threshold is not an admission bound. Admission
  above this cap fails with a dedicated drop/pressure metric before publishing
  shared/BPF/worker state.
- `localCreationForwardCeiling = workerLocalCreationForwardCeiling +
  localAuxiliaryForwardCeiling`; all newly created non-peer forward origins must
  be classified into one of those bounded classes before they can enter the
  shared store. This is the advertised
  `maxLocallyCreatedLogicalSessions`.
- `peerForwardReserve = maxAcceptedLogicalSessions` and
  `peerTailReserve = maxCapturedTailRows`.
- `authorityForwardReserve = peerForwardReserve`, one shared physical reserve
  for the complete local-plus-peer authority set. Local and peer provenance are
  disjoint classifications of rows in that set, not additive independent
  maxima. Promotion changes provenance without adding a row.
- `physicalLogicalReserve = authorityForwardReserve + peerTailReserve`, using
  checked arithmetic throughout.

After bilateral capability exchange, checked addition derives
`clusterAuthorityForwardCeiling = localCreationForwardCeiling +
peer.maxLocallyCreatedLogicalSessions`. Both nodes require that same sum to fit
**both** advertised `maxAcceptedLogicalSessions` values before enabling the
complete protocol. All current forward authority represented by local plus
peer provenance must remain at or below that cluster ceiling. New local
admission checks its class ceiling and the cluster total; promotion consumes no
new row but carries the peer namespace in `LocalAuthoritySource::Promoted`, so
takeover cannot erase the accounting class. This permits a node that has taken
over both nodes' sessions to export the complete cluster authority back to a
restarted peer. Merely proving one node's creation ceiling fits the peer reserve
is explicitly insufficient. Independently, every local runtime enforces total
local-plus-peer authority at or below its `authorityForwardReserve`; a peer bulk
that temporarily owns the whole cluster and ordinary local admission therefore
cannot consume the same physical credit twice.

The planner validates the **actual receiving topology**, not the legacy map
names or status approximation. Every worker receives replicas of all local and
peer rows, so every worker's distinct total-entry ceiling must be at least
`2 * physicalLogicalReserve`. The coordinator store must have the same
two-entry-per-logical bound. There is one AF-agnostic userspace-XDP
`USERSPACE_SESSIONS` hash, not separate v4/v6 maps; one forward publish can
install at most four distinct redirect keys (canonical forward, translated
forward, reverse wire, and reverse canonical), while its synthesized reverse is
already one of that set. Its entry ceiling must therefore be at least
`4 * physicalLogicalReserve`.

The persistent kernel `sessions` and `sessions_v6` maps are separate production
surfaces even though userspace forwarding does not consult them. The Go receive
and status paths publish forward plus reverse rows there, so **each family**
must independently reserve `2 * physicalLogicalReserve`; an all-v4 or all-v6
population is valid. Failure on either map is a typed partial batch result and
keeps continuity closed rather than silently degrading operator-visible session
truth.

Each `dnat_table` family becomes an explicitly **dynamic-only** reverse-SNAT
surface. The active userspace compile path already wraps `Manager` in
`userspaceShimCompileDataplane`: its `SetDNATEntry{,V6}`, static-NAT setters,
and stale-static cleanup methods are no-ops, while the Rust builder independently
lowers destination NAT and static NAT into the immutable forwarding snapshot.
Workstream I-d therefore removes that dead compiler/interface projection and
makes the existing userspace ownership rule structural instead of trying to
transact a dormant `flags=1` path with config promotion. This is not a semantic
shortcut. In the retained shim, the only possible consumer of a legacy
`flags=1` row is the native-GRE inner classifier: a DNAT lookup hit returns
`USERSPACE_SESSION_ACTION_REDIRECT`, while a miss returns zero; its caller
falls through to the same AF_XDP redirect for both values and exits only for
`PASS_TO_KERNEL`. The returned `DnatValue` is ignored. Non-GRE misses already
reach the helper through the binding/session-miss path. The Rust helper owns the
complete source-/zone-/application-scoped `DnatTable` and `StaticNatTable` in
its immutable forwarding snapshot and remains the sole authority that decides
whether and how static translation applies.

The implementation boundary is explicit:

- `compileNAT` stops allocating `writtenDNAT{,v6}`, stops issuing the configured
  destination-NAT calls that the active userspace adapter currently discards,
  and stops calling `DeleteStaleDNATStatic{,V6}`. The static rule continues to
  be lowered independently into the same Rust forwarding snapshot before the
  config can publish. Tests prove this is behavior-preserving for userspace mode
  before the dead methods are removed.
- Replace the broad `SetDNATEntry{,V6}` surface with
  `SetDynamicDNATEntry{,V6}`. Its value type has no caller-settable flag or pad;
  the adapter constructs canonical `flags=0`/zero-pad wire values and rejects a
  noncanonical raw value at the new map boundary. `DeleteDNATEntry{,V6}` remains
  available only to the session/reverse-NAT owner. Generated/source canaries
  reject a compiler or config-apply caller. Retire `DNATFlagStatic`,
  `ClearDNATStatic{,V6}`, and `DeleteStaleDNATStatic{,V6}`. No production path
  mutates a legacy `flags=1` row.
- I-c adds pinned `userspace_dnat_dynamic_v2` and
  `userspace_dnat_dynamic_v2_v6` maps with generated key/value ABI and
  `BPF_F_NO_PREALLOC`. Values have no static discriminator. The v2 shim and all
  Go/helper session writers use only those maps after the one-way cutover.
  `dnat_table{,_v6}` are retirement inputs, never resized, scrubbed, or reused.
- A generated target-program reference manifest enumerates **every** map ID and
  ABI the v2 XDP program may reference. It classifies exactly the session and
  two DNAT maps as generation-owned authority and explicitly classifies each
  unchanged ctrl/binding/XSK/cpumap/local-address/counter infrastructure map.
  The loader clones the collection spec, disables implicit `PinByName` for every
  generation-owned symbol, precreates and explicitly pins the three authority
  maps in the target directory, and supplies them through `MapReplacements`.
  Every retained symbol is likewise replaced from its already-open exact
  infrastructure FD rather than reopened by name. The loader
  rejects a legacy authority-map ID, a missing/extra reference, or an
  unclassified writable map. A kernel that cannot report complete
  `ProgramInfo.MapIDs` is unsupported for this migration and fails preflight;
  program tag or source ELF alone is not substitute proof. Structural infrastructure writers obey the same
  migration freeze; telemetry-only per-CPU counter increments may continue.
- Static-DNAT config cardinality no longer consumes BPF-map capacity. Each
  family independently requires only its checked worst-case dynamic
  `physicalLogicalReserve <= mapMaxEntries`; an all-v4 or all-v6 population is
  valid.

Historical maps become isolated retirement state, not immutable state. They
cannot be deleted or reused merely because a displaced program ID disappears:
a native, generic, TC, or TCX invocation may still execute under kernel RCU.
Legacy `xdp_zone` consumed `DnatValue` to rewrite packets, and an earlier
userspace shim sent a DNAT hit to XSK while a local/VIP miss went to the kernel.
Moreover, historical XDP/TC conntrack and policy programs can update/delete old
session and dynamic-DNAT rows after their hook has changed. The plan therefore
makes **no execution-grace or byte-immutability claim and performs no userspace
lookup/update/delete on an old authority map**. Such late packet-side writes are
permitted only inside an isolated old object that no current accessor, target
program, capacity proof, status path, or recovery path can consult.

Before `forwardOnly`, the manager materializes one boot-scoped
`retiredLegacyExecutionCapsule` under a generation directory. From held FDs it
duplicate-pins the fixed point of a generated historical kernel-object graph.
Every program edge follows the program's complete `ProgramInfo.MapIDs`. Every
occupied `PROG_ARRAY`, `CPUMAP`, `DEVMAP`, and `DEVMAP_HASH` value follows its
nonzero child-program ID; every occupied `ARRAY_OF_MAPS`/`HASH_OF_MAPS` value
follows its child-map ID; each child program/map is opened, fully identified,
and traversed recursively. This covers the historical root -> `cpu_map` ->
`xdp_cpumap_prog` -> `cpumap_xdp_progs` chain as well as XDP/TC tail calls and
optional device-map programs. The manifest classifies every reachable map type,
slot/value shape, permitted cycle, program, and ABI. An unknown program-bearing
or map-bearing type, noncanonical value, missing child, edge/cycle outside the
manifest, unsupported info/query operation, or capacity above the generated
closure bound fails before any hook changes. The capsule receipt records every
program/map ID, ABI, graph edge/slot, and pin identity and proves a second pin
opens the same object. On the same kernel boot, cleanup never removes these
capsule pins or closes the final userspace reference to any program-bearing map:
in particular, the kernel clears PROG_ARRAY entries when its user reference
count reaches zero even while an old root or queued CPUMAP invocation still
references the map. The one-time legacy
capsule is retired only after a different boot ID and proof that no xpf
attachment, process FD, socket/AF_XDP owner, or live BPF object from that capsule
survived. This preserves a paused invocation's later tail call without treating
anything it mutates as v2 authority.

The existing side-by-side shim migration below is expanded to one program and
three maps: `userspace_sessions_v2` plus both dynamic-DNAT v2 families. Under
closed local/peer admission and joined helper/session/reverse-NAT writers, the
new DNAT maps are rebuilt only from authoritative coordinator session rows and
their typed reverse-NAT companions, never by filtering/copying the old maps.
Configured destination/static NAT remains solely in the sealed Rust snapshot.
A restarted daemon with empty coordinator authority builds empty v2 maps and
keeps continuity false until repair; it never promotes old pinned rows as truth.
Unknown old flags/padding are irrelevant to v2. An already-running old
invocation may read or mutate its isolated legacy objects, but it cannot affect
the separately populated v2 generation.

Before that migration starts, one process-wide `helperLifecycleLease` uses an
exclusive nonblocking `flock`. If the lock is free, the daemon acquires it and
retains the same open-file description across helper exec. If it is busy, the
daemon does not wait indefinitely or infer identity from the lock owner: it
discovers the control peer/AF_XDP owner, identifies a recognized prior helper by
socket `SO_PEERCRED`, UID, executable device/inode/build digest, PID start time,
lock-file device/inode, and (when available) nonce, requests shutdown, then
pidfd-kills on timeout and pidfd-joins. Only after lock release does it retry
and acquire the lease. Future children use `Pdeathsig=SIGKILL`, verify parent
PID plus `/proc` start time after exec, and return a random parent/lease-bound
nonce in status. A pre-lease helper is discovered by its control peer and
`/proc/*/fdinfo` references to the old map IDs. An unknown process is never
killed; because old maps are never used as new authority, any mutation through
its FD remains isolated from v2, but an unresolved lease, AF_XDP, or socket owner keeps
migration readiness closed.

Eligible-hook discovery is a kernel-authoritative, fail-closed algorithm rather
than `Manager`'s in-memory link maps. The daemon records and holds its startup
network-namespace FD plus device/inode; the current product supports dataplane
hooks only in that one namespace, and any manager/config object attributed to a
different or unprovable namespace blocks migration. Under a new
`networkHookMutationLease`, config apply, interface hotplug/rebind, and every
Manager attach/update/detach path stop before discovery.

Every BPF-link attachment created by the new loader first captures
`{kernelBootID, netnsDevice, netnsInode, ifindex, direction, attachMode}` from
the held namespace, then after attach duplicate-pins and readbacks the link and
atomically publishes a root-owned `durableHookProvenanceRecord` containing that
tuple, link ID, full program identity, pin identity, creation process identity,
and monotonic hook generation. The Manager does not publish the handle or
readiness before the record and parent directory are durable. A crash between
attach and provenance publication leaves an unowned hook that the next startup
will not adopt. A link loaded from a prior-process fixed pin without this record
is likewise unproven: root pin, program ID, program bytes, ifindex, and current
RTM attachment together still cannot reveal which namespace owns an XDP BPF
link. It remains fail-closed debt and requires the documented clean reboot; no
online command synthesizes provenance after the fact. On a different boot,
absence of every xpf BPF/helper/AF_XDP object permits archival of the stale
record and a fresh proved attachment.

Within one absolute deadline the inventory takes two identical consecutive
eligible snapshots from:

- a recursive `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` walk of the
  root-owned xpf bpffs tree, opening and classifying every pinned link, program,
  and map by FD;
- one bounded one-shot inventory subprocess that enters the held namespace
  before starting the query runtime, proves its `/proc/<pid>/ns/net` identity,
  and returns over an inherited credential-bound pipe: `BPF_PROG_QUERY` for
  `AttachTCXIngress` and `AttachTCXEgress` on every compiled managed ifindex,
  including program IDs, link IDs, attach flags, and revision; `RTM_GETLINK`
  for native, generic, and hardware XDP attachment IDs; and
  `RTM_GETTFILTER` for clsact ingress/egress at every chain/priority/handle.
  Hardware offload is unsupported and blocks rather than being skipped; and
- `BPF_LINK_GET_NEXT_ID`/`BPF_LINK_GET_FD_BY_ID` only to open and fully identify
  the exact link IDs returned by the namespace-scoped query or referenced by a
  root pin/current Manager handle. Global `bpf_link_info.ifindex` is never used
  to infer a namespace.

The union key is `{netnsDevice, netnsInode, ifindex, direction, attachKind,
attachMode, linkID-or-{parent,chain,priority,handle}}`. It includes compiled
expected hooks, all root-pinned xpf links, all current Manager handles, and any
extra attachment whose complete program/map closure proves a generated xpf
artifact. A TCX attachment must return a nonzero link ID and query revision from
inside the held namespace, and that ID must open to the same program/attach
tuple globally. XDP's namespace-scoped RTM result is correlated to a BPF link
only through an exact valid `durableHookProvenanceRecord`; a matching
global `{ifindex,programID}` alone is ambiguous because `bpf_link_info` carries
no namespace. A surviving prior-process XDP BPF link without provenance
therefore blocks whether pinned or unpinned. A link created by the current
process becomes eligible only after its generation pin and provenance record
are durable, and a legacy netlink XDP attachment has no link receipt. A root-pinned or
Manager TCX link absent from the namespace query is ambiguous debt, even when
another namespace has the same ifindex. Missing query fields, unsupported TCX
`BPF_PROG_QUERY`, helper/pipe failure,
dump interruption, duplicate occupants,
interface-generation drift, a disappearing eligible object, or two unequal
snapshots fails preflight. An unpinned legacy netlink XDP or classic-TC
attachment is xpf-owned only when
its complete program identity matches a generated historical artifact, every
transitive program/map graph edge matches that artifact, and the exact map
objects are rooted in the xpf pin tree or the newly proved legacy capsule; a
tag, program ID, name, ifindex, or instruction digest alone is insufficient.
An unknown program on an expected hook is external ownership debt and is never
replaced. Unsolicited eligible netlink/BPF-link change notifications invalidate
the frozen inventory. Updates use the held link FD where a BPF link exists and
`IFLA_XDP_EXPECTED_FD` for a legacy netlink XDP attachment; classic TC removal
uses its exact namespace/parent/chain/priority/handle and mandatory before/after
readback. The threat model excludes a concurrent hostile root process, which
could alter any router state regardless of this migration; any observed root-
level churn still aborts.

The one-way link cutover uses explicit full source/v2 program identities, all
three old/v2 map identities, and exact typed eligible-hook receipts in the same fsynced
migration journal. The final disposition is v2 only for native/generic XDP;
every xpf-owned legacy TC/TCX reader ends detached because the retained
userspace dataplane intentionally has no TC program. After the first hook changes
there is no rollback and no old-map repair: failure/crash keeps admission closed
and resumes forward. Once every XDP hook selects the v2 program, every owned
legacy TC/TCX hook is absent, the v2/coordinator barrier succeeds, and the
committed record is durable, all daemon/helper writers target v2 only. Old link
aliases may then be removed after the exact durable successor receipt, but the
boot-scoped legacy execution capsule remains pinned and isolated for the rest of
the boot.

Every BPF-link-backed eligible hook is durably rehomed before its first update.
It must already have a valid same-boot namespace/link provenance record; a
legacy fixed pin without one is not eligible for online cutover. Using the
already-open link FD, the manager adds a generation-owned pin, reopens
that pin, and proves the same link ID/source program/hook tuple while retaining
the legacy alias and FD. The capsule/link receipt is durable before
`Link.Update`. After update, exact attached-program readback and a second durable
receipt bind that same link ID to v2 or quarantine. Only then may the fixed
legacy link alias be removed; the generation pin remains the active manifest's
ownership root and the new hook receipt supersedes the old provenance record.
A crash before generation pinning leaves the legacy alias;
after pinning it leaves at least one exact pin; after alias removal the
generation pin preserves the attachment when every process FD closes. Legacy
netlink XDP and classic TC have no BPF-link object and are recorded as typed
kernel-persistent attachment receipts rather than fictional pins.

An in-flight old invocation may finish, perform packet-side writes to its old
objects, and tail-call through the retained program arrays; none of those
objects is reachable from v2. This closes native/generic XDP and TC/TCX
retirement without requiring an unavailable userspace RCU-execution barrier or
pretending that old packet code is read-only.

The executable current-shim proof still compares final XDP action, selected XSK,
and metadata bytes for v2 native-GRE dynamic hit and miss. A source/ELF canary
proves the current shim's session/DNAT authority references resolve only to the
three v2 maps, every other reference is classified infrastructure, and no
translated value is used as configured static authority. Historical reader
fixtures instead prove that late old-map writes and tail calls remain confined
to the retained legacy capsule and cannot change v2 map contents, selected XSK,
helper authority, status, or recovery decisions.

Config atomicity is consequently the existing opaque prepared-object contract:
promotion publishes one sealed Rust forwarding snapshot and one matching
`committedRuntimeConfig`; no static BPF side effect exists before, during, or
after that linearization point. A promotion conflict leaves both the old helper
snapshot and both dynamic maps unchanged. A post-promotion helper/dataplane
failure remains ordinary exact failed-apply debt and cannot publish readiness.
Fresh process boot and same-process helper replacement select the committed
runtime through their existing generation-qualified lifecycle; neither path
scrubs or reconstructs configured static rows in a kernel map. Dynamic rows from
a dead helper generation remain governed by the helper-replacement/session-loss
rules later in I-d, not by configuration rollback.

The shared NAT, forward-wire, and typed member/group reservation indexes use
slot handles into the coordinator store and reserve their checked two-alias,
one-alias, one-per-logical-member, and at-most-one-group-per-member maxima rather
than cloning complete entries. The member index keeps every exact reverse-token
owner; the group index keeps checked local/peer refcounts and exact shareable-
lease identity. Tail preflight can therefore distinguish untouched compatible
refs from an incompatible raw-tuple or per-flow reverse-key collision without
scanning the store. The
generation ledger separately reserves
`peerForwardReserve + peerTailReserve` rows.

`SessionCapacityPlan` also freezes the exact worker count and generated private-
event/allocator/operation record sizes used by the protected replay,
predecessor, and mutation-lane arenas, including the fixed executor set,
intrusive ready handles, wake state, deadline state, and barrier coordinator.
Checked multiplication derives every
partition and byte span described below; a count overflow, size-manifest
mismatch, requirement above 256 MiB for critical replay, above 64 MiB for
predecessor state, or above 64 MiB for the 24,576 mutation-lane records rejects
helper startup before any worker, event listener, allocator, or peer capability
is exposed. A worker-count/config change replaces the helper generation and
rebuilds these arenas under the normal continuity-false repair contract; a live
arena is never resized.

This replaces the current unsound `worker_count * DEFAULT_MAX_SESSIONS` import
cap: `upsert_synced_with_origin` currently bypasses the per-worker local cap,
every import is fanned to every worker, and `publish_live_session_entry` can
consume four entries in the single 262,144-entry shim map. I-d cannot activate
the capable protocol against that pin. I-c introduces a generated, versioned
`userspace_sessions_v2` hash plus `userspace_dnat_dynamic_v2` and
`userspace_dnat_dynamic_v2_v6`, all with `BPF_F_NO_PREALLOC`, generated
cross-language ABI, checked per-family capacities no greater than 10,000,000,
and inactive capacity planning.
I-d performs one fail-closed, forward-only side-by-side migration of the program
and all three maps. Each target is an immutable generation directory containing
the generated v2 program and three map pins; the loader binds the program to
those exact map IDs and a generation-qualified active manifest supplies every
daemon/helper/status accessor. No caller opens a fixed pin path. I-d first
acquires the helper lifecycle lease, loads one inactive v2 target generation,
closes local/peer session admission ahead of both read loops, stops and joins the
fixed session-mutation scheduler and inbound-barrier coordinator, cancels and
joins bulk/wire producers and session/reverse-NAT installers, and takes the
coordinator mutation barrier. Migration proceeds only when the scheduler ready
FIFO is empty, all 64 executors are joined, every lane/barrier token is final
and recycled, and no ambiguity debt remains. Every worker ACKs a read-only-existing-session phase: no Open, Close,
GC, expiry, allocator ownership transition, or map publication may occur while
links span generations. A historical packet hit may still change only its
isolated legacy-capsule maps; those bytes are outside current structural
session/NAT authority. The bound 180-second migration deadline
includes this freeze; timeout stays fail closed.

Under one stable coordinator serial, fixed-credit iterators populate
`userspace_sessions_v2` with the complete authoritative alias set and populate
both dynamic-DNAT v2 maps from those same sessions' typed reverse-NAT companions.
The migration neither enumerates old maps as authority nor performs a map
operation on them. Today's old session
map may contain a sequential-publish subset, old DNAT may contain configured
`flags=1` rows, and a historical eBPF invocation may still dereference its old object;
that invocation may mutate the isolated object, but none of those bytes enter
v2. Exact readback proves each v2 map against
coordinator-derived truth before the first hook changes. It records the expected
cardinality and canonical stable-slot-order SHA-256 for diagnostics, but does
not hash BPF iteration order. A fixed-credit walk validates every actual
key/value against the coordinator's alias or typed reverse-companion index and
requires actual count equal expected count. BPF hash keys are unique, so
all-actual-membership plus equal cardinality proves exact set equality without a
global sort or probabilistic commutative digest. Iterator error, duplicate
coordinator key, noncanonical value, missing expected lookup, or count mismatch
fails closed. A daemon restart never
pretends an old pin reconstructs lost Rust SessionTables: an empty restarted
coordinator produces empty v2 maps and continuity stays false until capable
repair.

The manager records every eligible hook's exact source program identity, typed final
disposition (`v2XDP` or `detachedLegacyTC`), and the source/target IDs and ABI
digests for all three map pairs, the complete generated target-program map-
reference manifest and exact retained-infrastructure IDs, the held network-
namespace identity, frozen eligible-hook inventory generation/digest, complete
legacy execution-capsule closure/second-pin receipts, and generation-owned
link-pin receipts plus prior/successor durable hook-provenance records, kernel
boot ID, migration ID, daemon process ID, target
generation, v2 XDP program identity, and
one non-renewable `CLOCK_BOOTTIME` start/deadline pair. Before the first link update it
atomically temp-writes, fsyncs, renames, and directory-fsyncs a root-owned fixed
journal in phase `prepared`, including the stable coordinator serial, exact
session/v4-DNAT/v6-DNAT expected counts/canonical diagnostic digests and
row-membership proof receipts. Every capsule object and BPF-link-backed hook is
already rooted by its proved generation pin before this `prepared` record can
become durable. It
then durably advances the same record to `forwardOnly` **before** changing the
first hook. Record failure before `forwardOnly` mutates no link; failure at or
after it can only resume forward. Every hook receipt is appended and fsynced
after exact readback; a crash between update and receipt is recovered by exact
current full program identity plus link identity, never an error string.

An exact program identity is
`{programID, type, expectedAttachType, tag, btfID, xlatedInstructionSHA256,
completeSortedMapIDs}` read from an open FD. Pinning is separate typed ownership
evidence, because a valid legacy netlink attachment may have no program pin.
`programOwnershipProof` is exactly one of a root-owned pin opened beneath the
held directory FD, a current-manager held FD created under the lifecycle lease,
or an unpinned historical-artifact proof with the complete root-owned
transitive program/map graph described above. The tag alone
is never identity or authority. The instruction digest covers the complete kernel-reported
translated instruction stream; inability to retrieve any field fails migration
preflight. Identity is re-read from the attached program after each link update,
so program-ID reuse or a matching short tag cannot satisfy a receipt. Discovery,
validation, and attach retain the same opened program/map/link FDs under a
root-owned directory FD; no post-validation pathname reopen participates in an
update.

Each link update has exact old/new program identities, ifindex, direction,
attach mode, typed BPF-link ID or legacy attachment tuple, generation-pin
identity when applicable, and final disposition in its receipt; an
`already attached` string is not proof. While hooks span generations, all three
v2 maps are frozen snapshots and every current structural writer remains
joined. An already-running old invocation may still mutate only its isolated
legacy-capsule objects; new invocations use the frozen v2 maps. No dual-publish
adapter exists. Interface add/remove/rebind is frozen by the same
lifecycle token. A link-update failure, timeout, cancellation, or Stop retains
`forwardOnly`, keeps admission/readiness closed, and retries remaining hooks;
it never selects the old program again or performs userspace repair/mutation on
an old map.

Startup resolves the journal before helper/session/network admission. A
same-process valid `prepared` record with no changed hook may discard an
unreferenced target generation and build a new one before durably entering
`forwardOnly`. With no journal and no pre-existing xpf-owned hook or object, the
daemon may start a fresh inactive target normally. A different daemon process
never claims any pinned cache as coordinator truth: no-journal or `prepared`
startup with an exactly owned pre-existing hook enters the quarantine path below
before map population or traffic admission. A same-process `forwardOnly` retry
may continue with the recorded immutable target only while its helper lifecycle
lease, coordinator serial, all three target IDs/ABIs, and every writer-join
receipt remain valid; it repeats the exact row-membership/count proof rather
than trusting a stored content digest.

The journal's kernel boot ID is authoritative only as a discriminator, not as
state proof. On a different boot ID, startup may archive/reset the old journal
and begin fresh only after proving there are no surviving xpf-owned BPF links,
program/map pins, helper/control sockets, AF_XDP owners, or exact eligible-hook
attachments. Any surviving or unknown object under a mismatched boot ID is
operator-visible fail-closed debt. On the same boot ID, every prior-process
object follows exact quarantine/successor recovery.

A same-boot XDP BPF link with no valid namespace provenance is not an
`exactlyOwnedHook` for quarantine. Startup reports its pin/link/program identities and
the clean-reboot requirement but never updates, detaches, adopts, or fabricates a
record for it. `recover-userspace-shim --resume-forward` rejects it for the same
reason. The operational escape is a controlled reboot into the new loader: the
kernel destroys the ambiguous link/object graph, clean-boot proof observes no
survivor, and fresh XDP links receive durable provenance before readiness.

A new daemon process finding any exactly owned prior-process hook, including
no-journal legacy hooks or a prior-process `prepared`, `forwardOnly`,
`recoveryQuarantine`, or `committed` generation, cannot trust or rewrite its
maps while any hook is live. It validates the exact
eligible-hook/source/target identities and loads a generated map-free
quarantine set: an XDP program returning `XDP_DROP` and a sched-cls program
returning `TC_ACT_SHOT` for TC/TCX. It pins both under the migration generation,
durably records their exact full program identities, advances the
journal to `recoveryQuarantine`, and then replaces every
eligible native/generic-XDP and TC/TCX hook with its exact typed quarantine
program. Each quarantine update has the same fsynced exact receipt
and crash recovery rule. Already-running historical or prior-target invocations
retain their map references and may finish; a historical packet-side write is
confined to its retained legacy capsule, while every newly admitted packet is
dropped. Only after every eligible hook readbacks quarantine may startup create
a fresh successor v2 generation, populate its three inactive maps from the new
coordinator (empty after helper loss), durably bind the successor IDs/digests in
the journal, replace every XDP hook forward from quarantine to that successor,
and detach every owned legacy TC/TCX quarantine hook with an exact absence
receipt.
A crash in either quarantine or successor replacement resumes the same forward
phase. Neither quarantine program has a packet-pass mode or session/NAT map
reference.

The 180-second deadline is evaluated against the journal's same-boot
`CLOCK_BOOTTIME` value, so process restart, progress, or phase change never
renews it. Once expired, recovery may perform only the bounded idempotent work
needed to place every exactly owned hook in the typed drop quarantine; it may
not build/publish a successor or admit traffic. It then exposes terminal
migration debt and requires an explicit operator recovery command to validate
current identities and install one new deadline. The additive root-only command
is `xpfd recover-userspace-shim --migration-id <hex> --resume-forward`; it
acquires the same lifecycle `flock`, requires the daemon control socket absent,
requires the journal/boot ID and every currently attached hook to match an exact
recorded source, target, or quarantine identity, and writes the renewed
same-boot deadline with the ordinary atomic journal protocol. It never accepts a
pin path, program ID, or rollback option from the operator. The next normal
startup performs the work. That command remains forward-only and cannot select
a historical program or map. A separate
generated 20-second emergency-quarantine deadline is stored before its first
hook update; expiry with any non-quarantined owned hook leaves the daemon failed
closed and names every unresolved hook.

`pkg/dataplane/README.md` and
`docs/operations/userspace-shim-pin-recovery.md` document the four journal
phases, expected packet loss during quarantine, clean-cold-boot classification,
the exact root-only resume command and preconditions, object identities exposed
by status, the memory retained by the legacy execution capsule until reboot,
generation-owned active-link pins, the eligible-hook inventory, and the
mandatory clean-reboot procedure for a pre-provenance XDP BPF link. They also
state that neither the resume command nor manual pin surgery can adopt such a
link, and prohibit manual `bpftool map delete`, pin removal, or rollback. Startup errors include the migration ID, phase, boot-ID relation,
deadline, unresolved typed hooks, and that runbook path without printing secret
material.

A valid same-process `committed` record requires every eligible XDP hook to
select the exact final v2 generation, every owned legacy TC/TCX reader to be
absent, its complete live `ProgramInfo.MapIDs` set to equal the classified
target manifest, and all current logical accessors to resolve to its manifest.
On a later process boot it is a proved source identity for the
mandatory quarantine/successor transition, not reusable session authority.
Missing/corrupt/unknown records, an unowned hook, or map/program identity drift
fails closed with operator-visible debt; no recovery path flushes, repairs,
rebuilds in place, or rolls back an old/previous-target map. A recognized xpf
hook may be quarantined only after exact ownership proof; an unknown external
hook is never overwritten by guesswork.

After every XDP hook selects the final v2 generation and every owned legacy
TC/TCX reader is absent, a final frozen v2/coordinator readback succeeds and the
helper atomically switches its generation-qualified
map handles to that generation. The daemon then temp-writes, fsyncs, renames,
and directory-fsyncs the generation-qualified active manifest and only afterward
durably writes phase `committed` with that manifest digest. Structural writers
may then resume against v2 only. A failure at either durable boundary remains
forward-only and closed. Old link and map pins are unpinned and
closed only when they are duplicate fixed aliases whose exact object is already
rooted by the active link manifest or boot-scoped legacy capsule. The legacy
capsule itself remains pinned through the current boot without a map operation
or final PROG_ARRAY user-reference drop. A kernel invocation already executing
the old program may read or mutate its isolated maps and tail-call safely; no
userspace RCU grace is claimed. Superseded v2 target/quarantine cleanup and
next-boot legacy-capsule cleanup are local
lifecycle operations independent of peer repair, so standalone and mixed-version
nodes terminate migration. Capable repair may establish HA continuity afterward
but is not a map-migration prerequisite. The logical helper/status accessor
resolves to the selected generation; no caller hard-codes a pin name.

Each removable duplicate old/superseded pin unlink uses the held root directory FD, opens the current
pinned object without following a replacement path, and compares its full
journaled identity before `unlinkat`. A mismatched recreated pin is debt and is
never removed. Absence after a crash is idempotent only when the journal already
proved the corresponding hook's final disposition; no recovery recreates an old
pin. Link/program/map FDs stay held through the comparison and receipt.

For this version the planner requests checked `peerForwardReserve =
2 * localCreationForwardCeiling` so a symmetric pair can return the combined
authority of both nodes after takeover, and requests `peerTailReserve =
min(captureTailMaxRows,
captureTailTotalByteCapacity / max(v4CapturedMutationFootprint,
v6CapturedMutationFootprint),
tailTransferEscrowByteCapacity / max(v4TailTransferEscrowFootprint,
v6TailTransferEscrowFootprint),
maxTailRowsAllowedByEveryPhysicalSurface(peerForwardReserve))`, with every generated
capture footprint including the first-before descriptor and final state, and
every generated escrow footprint including the complete typed allocator token,
old key, canonical reservation identity, exclusive/shared refcount fields,
tuple/provenance, bank serial, result phase, index load factor, and alignment.
The final term
uses checked inverse 1x/2x/4x capacity arithmetic and may reduce transient tail
credit, but never the cluster baseline reserve. It activates
the complete capability only if both nonzero requests fit every inequality
above; it does not quietly lower baseline reserve and then claim full symmetric
HA. Failure leaves the transport partial-capability/continuity-unready rather
than publishing a deceptive ceiling: all complete bits and all three capacity
fields are zero. Before negotiation, source creation capacity is the checked
`localCreationForwardCeiling`. After negotiation, each side computes the exact
combined cluster-authority ceiling from both advertised creation capacities and
requires it to fit both baseline reserves before enabling the complete
protocol. During a
bulk, physical surfaces retain the additional tail reserve because cross-worker
event sequencing may expose an Open before the compensating Delete. Before
TailAck, the receiver requires the ledger's final `present=true` count to be at
most `peerForwardReserve`; only then may transient physical tail credit be
released. Later ordinary Opens reserve one baseline credit before mutation and
Deletes release it after all derived surfaces complete. Generated cross-language
tests own every factor and reject truncation, overflow, alias-factor drift,
worker-replication disagreement, or mismatch with applied helper/map status.

The advertised tuple is immutable for one installed transport epoch, not for
the whole daemon process. Any applied worker-count/local-entry/replica-entry
limit, BPF/DNAT map, shared-store/index, ledger, or capture-budget change first closes session admission, cancels/joins
bulk work, retires the whole transport, and only then publishes the new helper
capacity and reconnects; the daemon process ID may remain unchanged. A
capacity-decreasing prepared apply fails before helper/config mutation and
retains the old applied snapshot when current local/peer forward rows, derived
worker/BPF/index rows, or generation-ledger rows do not fit the new ceilings. A successful change always
requires fresh bilateral capability resolution and authoritative repair; an old
connection may never mutate its capability in place. Version 1 defines
`barriered-authoritative-bulk-v1`, `repair-token-v1`, and
`config-epoch-digest-v1`, plus `bounded-replay-v1` and
`tuple-predecessor-v1`; unknown bits are ignored.
Because this capability has not shipped, `barriered-authoritative-bulk-v1`
normatively includes the 56/96-byte baseline markers and the counted TailEnd/
TailAck second commit; there is no deployed one-ACK meaning to preserve.
`bounded-replay-v1` makes failover ACK status value 4 mean retryable busy; it is
never emitted or interpreted without that negotiated bit.
`tuple-predecessor-v1` requires the exact 88-byte capable Open/Update predecessor
trailer and bounded receiver dependency state for cross-key translated-tuple
reuse across fabrics. Valid capability resolves
the connection `capable`. Any other first
post-auth frame resolves it `legacy` and is staged until after registration.
The complete new authority/replay protocol requires all five defined bits and
bilateral capacity compatibility: the checked sum of both nodes' advertised
local-creation maxima must fit each node's advertised accepted maximum, and each sender limits
unique capture-tail rows to `min(localCaptureRows, peerMaxCapturedTailRows)`. A
valid advertisement
missing any bit may carry ordinary traffic but cannot request, send, accept,
ACK, or satisfy continuity with a bulk. Fabrics in one transport must agree on
the defined-bit set, process ID, and all three capacity fields; unknown bits do
not participate.
`syncMsgBulkTailEnd = 31`, `syncMsgBulkTailAck = 32`,
`syncMsgBulkTailPhaseEnd = 33`, `syncMsgGenerationBarrier = 34`, and
`syncMsgGenerationBarrierAck = 35` are emitted or accepted only when that
complete capable bit set is negotiated. TailEnd/TailAck use the exact 96-byte
payload and TailPhaseEnd the exact 112-byte payload defined below. The capable
barrier and ACK each use an exact 128-byte little-endian payload, matching the
existing session-sync codec:
`{barrierSetID u64, peerProcessID [16]byte, transportEpoch u64, fabric u8,
zeroPad [7]byte, connectionIncarnation u64, sequence u64,
coveredWireGeneration u64, ownershipGeneration u64, authoritySerial u64,
authorityGeneration u64, senderConfigGeneration u64,
senderConfigDigest [32]byte}`. The ACK echoes all 128 bytes exactly. Existing
legacy type-13/14 eight-byte barriers remain byte-for-byte unchanged and can
never satisfy a capable floor or predecessor proof. Any capable-only type on a
legacy or partial-capability connection, any nonzero pad, or any wrong length is
a protocol violation, not an ignorable ordinary frame.
On an unkeyed transport the process ID is only an incarnation/correlation
namespace, never an authenticated identity claim; existing sync-network trust
and connection-admission limits remain unchanged.
Wrong version/length, zero ID, duplicate/late capability, or capability mutation
closes the connection. Generate the process ID once during daemon-boot authority
initialization and reuse it across cluster-comms/SessionSync restarts.
If `crypto/rand` fails, `Start` fails before bind and emits no type-30 frame; no
zero/weak ID or asymmetric half-capable setup is permitted. An unexported
per-instance entropy seam supports tests, never a package global.

Both fabrics in one transport must resolve to the same setup class. Capable
fabrics must also advertise the same process ID and all capacity fields. A
capable/legacy mix or process/capacity mismatch rejects the newcomer, marks continuity unready, and retires the
transport before retry; frames from two process lifetimes never mix. The bounded
setup timeout classifies a silent/old peer as legacy; any later capability on
that connection is a protocol violation. Whole-transport retirement uses the
same draining/join path as last-fabric loss before advancing the epoch. Only
after setup resolution and the
authority initialization check may `installConn`, receive loops, staged-frame
dispatch, `OnPeerConnected`, clock sync, or producers become visible.

Capable cold synchronization is receiver-request driven. A config-sync-disabled
or unprotected initialized receiver sends a unique nonzero type-29 request after
capable registration. A protected receiver sends it only after a successful
current-transport config baseline. The capable sender keeps all session
producers closed from connection registration (and after every config send or
ownership transition) until it receives that request, sends the exact requested
authoritative bulk, receives its exact intermediate BulkAck, safely flushes the
deferred tail, and receives the exact final TailAck. This removes the current
`handleNewConnection` bulk-before-config race.
This producer-authorization gate applies only to a fully capable transport.
Legacy mixed transports keep existing ordinary incremental production but never
send or accept an authoritative bulk and never become continuity-ready.
The two directions are independent: both capable peers may request and send
their owned-session snapshots concurrently. Outbound and receive tokens remain
separate, each captures the same initialized ownership view, and existing
cluster-originated installs/deletes must not feed back into outbound producers.
No receive-window lock is held while waiting for the opposite-direction ACK.

Before a receiver sends its first capable type-29 request for a helper/process/
ownership generation, it closes capable session admission and runs one
context-aware `ForEachClusterSynced` iterator over the currently installed
forward peer-synced domain using the captured zone-ownership snapshot. Origin
classification is backend authoritative, not inferred from zone alone. The
userspace implementation serializes a private `inventory_peer_synced_sessions`
operation with other helper snapshot streams and scans the coordinator-owned
shared `sessions.synced` authority, never one worker replica. Refactor that map
behind a modular `afxdp/ha/session_store.rs` `SyncedSessionStore`: a
`FastMap<SessionKey, slotID>` indexes paged stable slots containing the existing
`SyncedSessionEntry`, a bounded free-slot stack permits reuse, `liveExtent`
bounds scans, and a checked nonzero `peerInventorySerial` advances whenever a
forward row enters, leaves, or changes the explicit peer-authority inventory
domain. This replaces the current `FastMap<SessionKey,
SyncedSessionEntry>` representation rather than adding a second full key or
entry copy. The current `nat` and `forward_wire` maps also clone complete
`SyncedSessionEntry` values, so leaving them unchanged would defeat both the
memory bound and the capacity proof. `SyncedSessionStore` therefore owns the
primary, NAT-alias, forward-wire, and owner-RG indexes as key/slot-handle or
RG/slot-handle indexes into the one stable entry store. It reserves the exact
checked alias maxima from `SessionCapacityPlan`, validates every handle before
lookup, and updates all indexes transactionally under its recovered mutex. The
existing coordinator, worker-launch, reconcile, and shared-lookup call sites
receive narrow wrapper methods; no caller can mutate one index independently or
retain a slot reference after releasing the store guard.

`SessionOrigin` remains packet/install lineage; it is not authority provenance.
That distinction is required because the local-origin tunnel path deliberately
uses `SessionOrigin::SyncImport` to select the coordinator install family even
though no peer supplied the row. Add an explicit non-optional field to each
forward authority record:

```rust
enum PeerAuthorityNamespace {
    Capable { peer_process_id: [u8; 16] },
    Legacy {
        transport_epoch: u64,
        connection_incarnation: u64,
    },
}

enum LocalAuthoritySource {
    Worker { owner_worker: u16 },
    Promoted {
        from: PeerAuthorityNamespace,
        handoff_serial: u64,
        canonical_owner_worker: u16,
    },
}

enum LocalAuthorityDisposition {
    Active,
    HandoffExportable {
        target_peer_process_id: [u8; 16],
        ownership_transition_serial: u64,
    },
    Quarantined { ownership_transition_serial: u64 },
}

enum SessionAuthorityProvenance {
    LocalAuthoritative {
        source: LocalAuthoritySource,
        disposition: LocalAuthorityDisposition,
    },
    LocalAuxiliary { class: LocalAuxiliaryClass },
    PeerSynced { namespace: PeerAuthorityNamespace },
}

struct SessionAuthorityRecord {
    provenance: SessionAuthorityProvenance,
    provenance_generation: u64,
    worker_set_generation: u64,
}

struct AuthorityProvenanceTxn {
    serial: u64,
    ownership_transition_serial: u64,
    worker_set_generation: u64,
    source_generation: u64,
    target_generation: u64,
    stable_slot_cursor: u32,
    staged_workers: FixedWorkerBitmap,
    committed_workers: FixedWorkerBitmap,
    absolute_deadline_ns: u64,
    phase: AuthorityProvenanceTxnPhase,
}
```

Reverse/alias rows inherit the forward record's provenance and cannot choose it
independently. Local tunnel admission uses `LocalAuxiliary`, may continue to use
the sync-family installation mechanics, consumes auxiliary capacity, is never
exported as locally worker-owned, and is never inventoried as peer authority.
Wire import alone creates `PeerSynced`: a capable frame uses the authenticated
or correlated daemon `peerProcessID`, while a legacy frame uses the exact
ephemeral `{transportEpoch, connectionIncarnation}` that admitted it. Legacy
transport identity is never promoted into a process identity and is invalid as
soon as that transport retires **for new wire mutation authority**; retained
rows keep the old namespace as source evidence and remain eligible for gated
local takeover or later stale cleanup.

The coordinator's stable-slot store is the canonical provenance authority; a
worker replica is never a commit oracle. Every promotion, canonical-owner
reassignment, demotion staging, and post-TailAck relabel uses one
`AuthorityProvenanceTxn` under the closed producer/receive/export gate. Each
affected coordinator slot retains committed plus optional staged provenance
tagged with the transaction serial, so chunked staging adds no second session
inventory. The coordinator stages every row in bounded stable-slot chunks, then
sends one generation/transaction-qualified stage command to every exact worker.
The transaction records one monotonic absolute deadline at creation, capped by
`authorityProvenanceTransitionDeadline` (180 seconds) and by any enclosing
handoff/bulk deadline; chunk progress and worker-set restage never renew it.
`stable_slot_cursor` is the only resume cursor, and every worker command uses a
fixed-capacity inbox and bounded slot batch rather than allocating a full
inventory copy.
After all stage ACKs, it sends an idempotent commit command and records each
worker commit ACK. Only when all surviving workers acknowledge the exact target
does one coordinator CAS advance `authorityProvenanceGeneration`, make staged
records committed, and permit the matching forwarding/export gate to open.
Readers and export predicates require that committed generation plus the
captured worker-set generation; staged or split replicas are invisible.

Any timeout, partial ACK vector, stale completion, worker loss, or helper loss
publishes explicit `authorityProvenanceDebt` containing the transaction, target
generation, stable-slot cursor, absolute deadline, and both ACK bitmaps. It
leaves all positive and handoff export
closed and retries from coordinator staged truth; it never infers success from a
worker row. Worker-set change invalidates the old command set, cancels/joins its
commands, selects a new checked worker-set generation under the same transaction
serial and deadline, resets the cursor, and restages every surviving replica
before reopening. A stale command cannot commit against the new worker-set
generation. Deadline exhaustion keeps export and forwarding admission closed
and takes the controlled helper/process recovery path rather than renewing or
discarding split debt. Stop/config/helper replacement cancel and join the
transaction or retain its debt until all packet workers are torn down. Thus fanout may be
incremental internally, but externally export cardinality is always zero during
transition and exactly one only after the canonical commit.

Legacy compatibility keeps its current single-configured-peer trust without
claiming stronger identity. An accepted legacy Open/Delete is bound to the
currently registered connection incarnation before helper mutation. A same-key
Open may transactionally replace an older legacy namespace and a current legacy
delete may remove it under that existing trust, but both record the current
ephemeral namespace and can never create capable generation or continuity
proof. A legacy BulkStart snapshots the current transport namespace; present
members rebind to it and exact legacy BulkEnd reconciliation removes absent old
legacy namespaces through the existing stale-session path. Disconnect cancels
that window. A delayed frame from a retired incarnation cannot mutate or relabel
the retained row. When a later capable process appears, every surviving legacy
namespace enters its generation-zero inventory as described below.

Promotion to local ownership is one gated provenance transition to
`LocalAuthoritative::Promoted`, retaining the source namespace and a checked
nonzero handoff serial before positive authority publication. It also chooses
the lowest live worker ID as `canonical_owner_worker` under the captured worker-
set generation and stages that same source/disposition through the provenance
transaction above. A
worker-local row exports only from its `owner_worker`; a promoted row exports
only from its `canonical_owner_worker`. Worker loss/rebind first closes the
producer gate, invalidates any export through worker-set generation, and
transactionally reassigns the deterministic lowest surviving worker across the
coordinator and all replicas before reopening. No surviving worker leaves the
row quarantined with debt; if no worker survives, the row becomes
`Quarantined` and forwarding/export remain closed. Thus provenance-based authority does not duplicate a
promoted canonical member merely because every worker stores a replica.

Demotion does **not** relabel a row merely because raw RG state changed. Under
the ownership-transition token, the producer gate first closes, positive
forwarding is removed, and every affected row changes from `Active` to
`HandoffExportable` bound to the one capable target process and exact nonzero
ownership-transition serial. This state is ineligible for ordinary export,
ordinary admission, and positive forwarding, but the target-bound owner-RG
export must include it exactly once from its canonical owner. Header/Final and
TailAck bind the target process, transition serial, exact member count/digest,
and source config epoch. Only after that exact handoff reaches TailAck and the
matching ownership transition commits may the source start a new provenance
transaction that relabels those rows `PeerSynced::Capable` for that target. The
rows remain `HandoffExportable` with export closed until that relabel commits.

A legacy peer, no peer, failed/ambiguous TailAck, target replacement, or
ownership invalidation changes `HandoffExportable` to `Quarantined` with the
same serial and retains local provenance plus repair debt; it is not exportable
to an unbound process. A retry first creates a fresh target-bound transition
serial. The row may be restored to `Active` only if the local ownership
transaction proves it never committed away; otherwise it remains quarantined
until cleanup or a new exact handoff. This prevents both a demotion/reconnect
from inventing peer provenance and a TailAck over a bulk that omitted the rows
being handed off.

A generated exhaustive transition table covers all eight current
`SessionOrigin` variants, both peer namespace variants, both local-authority
sources, all three local dispositions, and every forward/reverse/materialized
replica. Illegal combinations
fail before shared/BPF/worker mutation. Authority-sensitive code may call only
`is_peer_authority()`/`is_exportable_local_authority()` on provenance plus the
current authority gate; a source canary rejects `origin.is_peer_synced()` in
inventory, export, ownership, capacity, reconcile, promotion/demotion, and
delete-authority decisions. `is_peer_synced()` remains permitted only for
explicitly enumerated replication/install mechanics.

Inventory captures `(peerInventorySerial, liveExtent)` under the recovered shared-
store lock, then repeatedly locks only long enough to revalidate the serial and
copy at most 256 fixed records from stable slots into the private stream queue.
It filters to every forward entry with `PeerSynced` provenance, regardless of
which capable-process or legacy-transport namespace created it; synthesized
reverse and every local-authoritative/local-auxiliary record are excluded even
when their install lineage is `SyncImport`. Rows matching the current capable
`peerProcessID` preserve their generation. Rows from a prior capable process or
any legacy transport remain in the inventory as generation-zero stale
candidates in the new capable namespace, so an empty replacement authority
deletes them rather than hiding them. A legacy connection never runs this
capable inventory protocol and therefore cannot preserve or reassign a capable
generation. Any peer-domain mutation,
slot corruption, serial exhaustion, cancellation, or capacity violation aborts
the stream instead of returning a fuzzy inventory. A final lock/revalidation
precedes Final. The same credential-bound fixed-record Header/member/Final
stream is used with no JSON or snapshot-sized vector; Header binds inventory
mode, helper generation, starting mutation serial, and live extent, and Final
repeats the serial plus count/digest. Stable slots make cursor resumption exact
without holding the shared mutex across socket backpressure. Legacy/BPF adapters
cannot advertise the capable protocol and need no new inventory behavior.
Local-only slot insert/remove/reuse does not advance `peerInventorySerial` and
cannot change the filtered peer set; every slice still reads slots while locked.
Any provenance transition into or out of peer-synced forward authority,
including replacement at the same key or peer-namespace replacement, advances the
serial and invalidates the scan.
The iterator seeds the
stable generation ledger in place with keys, current values/generations when
they belong to the same capable-process namespace, and generation-zero
membership when transitioning from any legacy transport or a different capable
process. The iterator checks
cancellation and row capacity every 256 entries and allocates no second key
vector. Only successful complete initialization permits the request and starts
its five-second start timer; failure retains baseline debt and sends nothing.
Every later successful Open replaces the ledger's exact canonical value and
every successful Delete retains the last value until all derived cleanup is
complete, so a Delete ambiguity never loses its before descriptor. Ledger
capacity includes those fixed values; they are the sole Go-side authoritative
copy and are not duplicated into a second cleanup map.
The same inventory is mandatory again whenever a partial batch or reconcile
marks `ledgerInventoryDirty`. Rebuild mutates the one ledger in place while
retaining the peer process's scalar `maxObservedGeneration` and every
`ambiguous` row from an attempted non-complete batch. It may add authoritative
shared-store rows, but may not discard an ambiguous attempted key until a fresh
complete baseline plus tail proves whether that key is present and idempotently
reapplies the corresponding Open or Delete to shared/BPF/all-worker surfaces.
Because every batch key reserves its ledger slot before helper mutation, this
conservative set remains within the negotiated ledger capacity and needs no
second repair-key vector. Request-ID-zero maintenance
bulk is refused unless inventory is clean and a prior requested two-stage bulk
completed. The process-level session
authority owns the ledger across an in-process cluster-comms transport restart;
helper replacement or a new peer process invalidates its generation namespace
but not the need to inventory any surviving installed rows.

A transport becomes `outboundBulkAuthorized` only after one exact requested
bulk reaches final TailAck postcommit. Later maintenance/overflow bulks may use
request ID zero only while that authorization remains current; config send,
ownership change, last-fabric loss, or capability/process change clears it. A
repair request is pinned to the exact capable source connection. If that
connection disappears, its request expires and the transport is retired; the
sender never silently moves it to preferred fabric 0. `requestAttempt` has a
bounded deadline; expiry re-arms the same debt generation and emits a new unique
request on a current capable connection.

The outbound queue is typed. One `producerMu` linearizes every session producer's
check-and-enqueue/defer operation with gate closure. The complete producer set is
normal v4/v6 installs/deletes, helper EventStream callbacks, delete-journal
replay, and sweep replay; a canary forbids direct production session writes
around the helper. Under `bulkSendMu -> producerMu`, the sender closes the gate,
switches the exact-generation EventStream callback to capture mode, and enqueues
an in-process drain token. Every captured helper frame retains its source lease
and event sequence. The send loop returns both success/failure and the set of exact
`(transportEpoch, connectionIncarnation)` values on which any pre-drain frame was
attempted or written.
The sender releases `producerMu` immediately after the mode switch/token enqueue;
it never holds that mutex while waiting for drain, network barriers, helper
export/boundaries, bulk writes, or ACK. EventStream callbacks need only
`producerMu` to update the current capture token/coalescer and wake waiters after
releasing it, so the bulk worker cannot deadlock the evidence it awaits.

After drain, take `s.mu -> gate.mu`, freeze
`G=maxAssignedWireGeneration`, freeze connection membership, and form the
union of that used set and every currently live capable fabric. If a used
connection is no longer exactly registered, or membership/process/ownership
changes, retire the whole transport and retry after the new baseline/request.
Otherwise install one fixed-array `pendingBarrierSet` before the first barrier
write, send a unique sequence plus G and the exact config/authority identity on
every union member, and mark each member ACKed only on exact fabric/incarnation/
sequence/generation/identity equality. Each receiver ACK is withheld until all
earlier <=G barrier-admission tokens, including owner and non-owning waiter
states, reach unambiguous final commit. Revalidate the token and frozen registry
after all ACKs before clearing it and writing BulkStart. A joining fabric cannot
carry session traffic until the producer gate reopens. Disconnect, config,
ownership, process, epoch, or membership movement invalidates the whole set;
neither a later ACK nor a `>=` sequence comparison can satisfy it. This fences
late receive-loop ordering on both fabrics and prevents a frame written to a
now-disconnected connection from appearing after the bulk. The same
revalidation includes `outboundAuthorityGeneration`; config send can never land
between the final fence proof and an old-generation BulkStart.

The selected bulk connection is the request connection for a requested/repair
bulk; an authorized request-ID-zero bulk may choose a still-frozen member.
Before writing `BulkStart`, the sender installs one absolute
`authoritativeBulkTransferTimeout` deadline in `pendingOutboundBulk`; every
snapshot/export/capture step and ordered frame write observes its remaining
context. The token starts in `exporting` before any helper request and carries
the exact helper source and SessionSync authority identities, so config,
ownership, helper replacement, or transport retirement can cancel and join it.

The capable authoritative source is a redesigned
`export_owner_rg_sessions`, not `export_all_sessions` and not
`drain_session_deltas`. It is an incremental binary export, not a JSON response
or an in-memory Rust/Go member vector. At the configured maximum of 131,072
forward sessions per worker, a multi-worker vector of the current string-heavy
`SessionDeltaInfo` would consume gigabytes and require multiple copies. The
control response therefore acknowledges only that the exact export was admitted;
it is not completion and contains no members.

The daemon owns one process-lifetime Linux `SOCK_SEQPACKET` listener in its
root-owned runtime directory. The socket has mode `0600`, is unlinked only after
the old listener has been closed and joined, and accepts at most the one
inventory/export operation admitted by a dedicated
`helperSnapshotStreamMu` (`bulkSendMu` remains the outbound-bulk owner). Before
sending the helper request, Go creates a
`helperSnapshotStreamLease` containing a cryptographically random 128-bit nonce,
the exact daemon/helper generations and export ID, and the expected helper PID
and UID. The helper request carries that nonce and export ID. An accepted
connection must match `SO_PEERCRED`, the current registered lease, and the exact
private helper-protocol version and registered operation mode before Go reads any member. A second connection,
wrong credential/nonce/generation, malformed record, or stream that survives its
lease closes the stream, cancels and joins the helper operation, replaces an
ambiguous helper generation, and retains full-repair debt. Filesystem mode is
defense in depth; peer credentials plus the nonce bind the stream.

Every private stream record has an exact 24-byte little-endian header
`{privateVersion uint16, type uint8, flags uint8, payloadLen uint32,
exportID uint64, streamSequence uint64}`. `streamSequence` begins at one and is
strictly contiguous. The only record types are `Header`, `MemberV4`, `MemberV6`,
`WorkerDone`, `Final`, and `Abort`; every type has one generated exact payload
length except the bounded Header worker-ID vector. Header binds the nonce,
process/local-helper/snapshot/worker-set generations, operation mode, sorted
worker IDs, owner-RG set, and source config epoch. Member records are generated fixed-width canonical
binary projections of the fields needed to build `SessionKey{,V6}` and
`SessionValue{,V6}`; they contain numeric IDs and address/MAC bytes, never JSON,
unbounded strings, pointers, or host layout. Rust and Go consume the same
field-order/version manifest, exact-size constants, and cross-language golden
fixtures. A new source field without an explicit wire disposition fails CI.
Payload length, checked count, and cumulative bytes are bounded before each read
by the captured checked source-session capacity and generated record sizes.

The Rust worker command receives the export ID and one bounded request-private
SPSC channel per exact worker ID. Rebind/worker-set mutation is an authority
mutator and cannot pass the registered export, so the captured nonzero
`workerSetGeneration`, sorted worker IDs, and expected worker count stay fixed.
The helper registers one shared cancellation token and accepts the command on
every captured worker before returning the small admitted control response. If
any command inbox refuses it, the coordinator cancels the token, joins or
observes cancellation from every worker that accepted it, emits Abort on an
already-authenticated private stream if necessary, and returns an unambiguous
admission failure; Go has not written BulkStart at that point. A partially
dispatched export can therefore neither run unowned nor later attach to another
export lease.
At the command's point in that worker's single-threaded packet/session loop, it
installs one export cursor with the session slab's captured slot high-water. It
scans at most 256 slots or 50 microseconds per subsequent poll iteration,
whichever comes first, then resumes packet work; production constants are
benchmark-owned and tests use a per-instance budget seam. A qualifying locally
owned forward session becomes one stack/fixed-record channel item. The generated
eligibility predicate is parity-locked to the current authoritative export:
forward only, `is_exportable_local_authority()` under the captured authority
gate, not fabric-ingress, owner RG zero or currently active, and
`ForwardCandidate`/`FabricRedirect` disposition. A worker-local record is
eligible only on its exact `owner_worker`; a promoted record is eligible only
on its exact `canonical_owner_worker`, so replicas never duplicate a canonical
member. Local auxiliary and `Quarantined` demotion rows are excluded regardless
of install origin. `HandoffExportable` is excluded from every ordinary or
diagnostic export, but a separate generated handoff arm includes it only when
the request's target process and ownership-transition serial match exactly; the
same canonical-owner rule still emits it once. Header and Final bind that mode,
target, serial, count, and digest. The legacy diagnostic export has no handoff
arm. Drift tests enumerate every exclusion and both target-bound inclusions. If the
request-private channel is full, the worker abandons that export slice and
returns to packet polling; it neither blocks nor allocates on the packet loop and
retries the same cursor position later. The coordinator drains all worker
channels fairly and writes records directly to the private socket. New sessions
allocated beyond the captured high-water are represented by captured ordinary
Opens. Slot deletion/reuse before or after its scan position is corrected by the
captured final per-key event. Ordinary opens/deletes continue through their
normal EventStream producer and never enter a request-private worker channel.

Every worker owns a process-lifetime checked `sessionDeltaLossEpoch`. Every
failure to enqueue a session delta increments it **before** returning failure,
including a ring-full path that cannot allocate an EventStream sequence. The
counter is never reset or consumed by resync; exhaustion is process-fatal under
the same controlled fail-closed rule as wire-generation exhaustion. A Boolean
loss latch may still schedule repair, but it is not proof of a lossless export.
The export command captures each worker's starting epoch and registers one
fixed-size shared `ExportLossState`. Any epoch movement while that token is live
atomically marks the token failed directly, without requiring another ring
event. WorkerDone, private Final, the Go pending-bulk token, and the final
capture-seal proof all carry the exact epoch vector/digest. Any mismatch emits
Abort when possible and suppresses BulkEnd/TailEnd; resync cannot clear it.

Each worker then emits one private `MSG_EXPORT_BOUNDARY` through the **same
lossless sequenced EventStream producer** used by its preceding ordinary session
events. Its exact 32-byte payload is `{exportID uint64 LE, workerID uint32 LE,
phase uint8, reserved [3]byte, workerSetGeneration uint64 LE,
lossEpoch uint64 LE}` and the ordinary frame header supplies the boundary
sequence. Reserved bytes must be zero; phase 1 is scan completion and phase 2
is final tail sealing. At final cursor completion, before the phase-1 marker and before that
worker resumes its next packet batch, it drains and losslessly submits every
pending session delta; inability to drain one fails the export. The worker
reports completion only after that marker is
successfully assigned and enqueued. Because the snapshot, all prior event
flushes, and marker are ordered by that single worker loop, and marker allocation
participates in `producer_seq_lock`, every event through that worker's completed
scan has a lower sequence. Mutations after the marker remain ordinary captured tail events. A
marker enqueue timeout or loss is an export failure, never a synthetic
watermark.

After a worker's final snapshot item is accepted by its SPSC channel, it performs
the delta drain and EventStream-boundary enqueue above, then enqueues a
`WorkerDone` item carrying that assigned boundary sequence and unchanged
start/current loss epoch on the same SPSC channel. A full channel delays WorkerDone to a later packet-loop iteration; it
does not block the worker. The coordinator writes all preceding member records
before the corresponding private `WorkerDone`; it computes a
rolling source-member count and SHA-256 digest over the exact generated canonical
member payloads in actual stream order. It does not sort or retain a global key
set. The helper writes `Final` only after every expected WorkerDone and its
EventStream boundary have been successfully enqueued. Final carries
`complete=true`, the exact worker-set generation/count, sorted
`{workerID,boundarySequence,lossEpoch}` digest and terminal sequence, and source-member
count/digest. An Abort, EOF, timeout, changed loss epoch, missing/duplicate worker, count/capacity
violation, nonzero legacy caller `max`, or incomplete Final is failure. Reading
`next_seq` after worker ACKs is expressly forbidden because it proves no causal
relationship to worker-local events.

Capture mode and shared byte accounting begin before the helper request. After
the control admission response and an authenticated Header, Go writes BulkStart
on the already fenced peer connection and then consumes each private Member
incrementally. It validates and hashes the source payload, converts it to one
capable session Open, assigns a fresh checked nonzero process-global sender
generation, stamps the source lease's committed config epoch, and writes it
directly to that exact peer connection. No member enters the ordinary send queue
or a full-snapshot heap. Go separately computes the count/digest over the exact
canonical capable Open payloads it writes; this is the peer-wire digest and may
differ from the helper source digest. A generated manifest and golden fixtures
prove that every helper source field has the intended capable-wire projection.
Failure after any BulkStart retires the transport, because the peer may have a
partial table; failure before BulkStart can cleanly abort the unchanged
transport.

After private Final, Go requires its source count/digest and loss-epoch digest
to match the incrementally observed source records. It then waits until
EventStream has decoded the exact boundary set/digest and a contiguous sequence
through Final's terminal sequence.
Only after both proofs and an exact peer-wire count/digest recomputation may the
sender enter `endingBulk` and write BulkEnd. A gap, changed loss epoch, asserted
loss state, missing/duplicate
boundary, stale source or worker-set generation, timeout, capture overflow, or
digest mismatch suppresses BulkEnd and retires a post-start transport. The
boundary frame is control evidence, never a session member. Events duplicated by
the scan remain in the capture tail deliberately: their coalesced final state
after the multi-iteration scan is idempotent, while any mutation before, during,
or after a slot observation supplies the correction. Events assigned after the
terminal sequence remain in the same capture structure. A control response or a
private Final alone is never completion.

`MSG_EXPORT_BOUNDARY` is correctness-critical like a session delta, not droppable
telemetry. The Go read loop validates its exact private-version payload, records
it under `producerMu` in the current capture token, and only then advances the
applied/ACK watermark; it wakes the waiting bulk worker after releasing that
mutex. Decode failure, a sequence gap, an unexpected export/worker/generation,
or a boundary that matches neither the active capture nor its bounded retained
completed/aborted token latches full-repair debt and retires the helper event
connection. Retain that exact token until its terminal sequence is cumulatively
ACKed or the helper generation is joined; an exact replayed marker is idempotent
and may advance ACK without resurrecting the bulk. A marker cannot be silently
discarded by the unknown-event path or cumulatively ACKed past before capture
records it. Because `bulkSendMu` admits one export at a time, new export
admission also requires that retained token to be ACK-covered; there is never an
unbounded map of abandoned export IDs.

The authenticated stream lease and incremental count/digest state are copied
into the pending token before BulkStart. BulkStart, every converted member, and
BulkEnd are direct ordered writes on one connection. Failure to finish BulkEnd
before the absolute deadline retires the transport and retains debt even when
each individual write stayed below two seconds. Captured tail events are stamped
only after snapshot members and therefore outrank duplicate snapshot Opens or
close them with a strictly newer per-key generation. `export_all_sessions`
remains an asynchronous legacy/diagnostic EventStream operation and is expressly
forbidden as a capable authoritative source; its control response proves only
enqueue, never callback consumption.
The baseline BulkAck authorizes only the ordered capture-tail phase; it does not
open ordinary producers, publish repair completion, or prove current
continuity. The producer gate remains closed until the exact capable TailAck.
Config/failover authority writers cancel and join
the bulk first. A closed allowlist permits only heartbeat/ACK, clock,
barrier/ACK, BulkAck/TailEnd/TailAck, IPsec-SA, and DHCP-lease full-set frames to
interleave; a canary classifies every production writer.

The co-versioned private Rust-to-Go EventStream session-mutation payload gains a
generated fixed `before` projection; the public cluster session wire does not.
Before any local SessionTable/allocator mutation, the producer copies
`{present, canonical key/value, authority provenance, translated tuple and
reservation identity}` from the incumbent entry. Open/rebind carries that
projection plus its normal after-state; Close carries the removed entry rather
than only its key/RG/zones. Absent is explicit. The fixed record is enqueued
without allocation, and enqueue failure advances the worker loss epoch. Go's
ordinary path may discard `before`, but capture mode requires it and rejects an
old/malformed payload. This deliberately adds control-stream bytes and one
fixed copy on session mutation, not a packet lookup or per-packet allocation;
generated size/ring-capacity canaries and event-rate benchmarks gate it.

EventStream acceptance becomes a durable in-process ordering contract rather
than an mpsc-send observation. At helper-generation startup, checked arithmetic
computes and preallocates one fixed `criticalEventReplayArena`: a dedicated
tuple-Close partition of
`workerCount * tupleReleaseFenceSlotsPerWorker`, a boundary/seal partition of
`2 * workerCount + 1`, and
`eventCriticalReplayGeneralFrameCapacity` (8,192) general correctness-critical
session-mutation slots. A generated manifest supplies the exact maximum bytes
for every admitted frame; the complete count plus byte spans must fit
`eventCriticalReplayByteCapacity` (256 MiB) before workers start. Telemetry uses
the existing evictable replay class and cannot consume these reservations.

The current shared 8,192-entry mpsc channel becomes one preallocated ordered
`eventRefRing` with separately accounted 8,192-entry critical and 8,192-entry
telemetry quotas. Telemetry cannot consume critical reference credit. A
correctness-critical producer first reserves its declared arena partition slot
and byte span and materializes the complete fixed frame outside
`producer_seq_lock`. Under that lock it then reserves critical ring-reference
credit, commits the next global sequence and ACK-owner link into the stable
slot, and publishes the reference. Failure releases every reservation and
commits no sequence. Telemetry uses its own quota in the same ring, so append
order remains global sequence order without a merge queue or copying frame
bytes while holding the global producer lock.

Every protected arena slot contains generated intrusive replay links and exact
stream/sequence identity. The I/O thread moves references, not frame ownership,
from the ring into one fixed sequence-ordered protected replay list, returns
ring-reference credit when it pops the ring, and unlinks only after cumulative
ACK or terminal-generation join. Socket backlog is a cursor over that list, not
another allocation or independently sized queue. On disconnect, draining the
remaining FIFO ring references appends them after the existing replay tail, so
reconnect has one contiguous ordered source. The generated 256-MiB calculation
includes all links, partition heads/tails, and alignment; no protected-frame
reference exists outside the arena or ring quotas.
An `EventEnqueueReceipt` is returned
only after this atomic admission and contains
`{helperGeneration, eventStreamGeneration, sequence, protectedSlot}`. Such a
slot is non-evictable until cumulative ACK covers its sequence or the whole
stream generation reaches terminal retirement. Reconnect replays every
protected unacknowledged slot in sequence before admitting continuation.
Capacity/byte exhaustion allocates no sequence and returns no receipt; an
ordinary critical mutation advances the worker loss epoch, while a tuple Close
retains its allocator token. Replay wrap may still evict telemetry, but can
never evict a protected session mutation, boundary, seal, or receipt-backed
Close. If an evicted telemetry sequence creates a gap between protected frames,
reconnect does not skip it: the event-stream generation becomes terminal,
continuity remains false, and authoritative repair precedes any later ordinary
or capture output.

Terminal stream retirement closes ordinary/capture output, publishes continuity
false, and joins the protected arena with its helper generation. It may discard
protected frames only after every receipt owner has either cumulative-ACK
coverage or the exact terminal local-replay receipt: packet workers, allocator
ownership, producer/I/O, and the protected arena for that generation are joined,
and authoritative repair has transferred or torn down each record's complete
debt. Merely establishing a new baseline is insufficient; no later output
inherits the retired sequence namespace. Stop,
config-driven helper replacement, socket failure, and repair tests use this
same rule rather than treating a previously returned receipt as permanently
valid across generation retirement.

Allocator reuse is ordered before capture, not repaired afterward. Every worker
owns `tupleReleaseFenceSlotsPerWorker` (1,024) fixed
`pendingTupleRelease` slots. Before removing a session that can return a pool
SNAT, address-only/persistent/shared-lease, deterministic-CGNAT, NAT64, or
NAPT64 translated tuple, the worker atomically reserves a pending slot, one
generation-stamped allocator-predecessor record containing the full Close
descriptor and typed allocator token, and credits/hidden slots in both fixed
indexes. The predecessor record begins in `awaitingReceipt`; its tuple-index
entry is hidden from claim/reuse and is not yet a free-tuple predecessor.
Timeout/GC
may defer removal if either reservation is unavailable; an urgent negative path
that cannot reserve both fences forwarding and forces helper-repair/replacement
rather than freeing the tuple. Session removal does **not** call allocator
release. The worker's normal time-sliced delta flush offers the fixed Close
record plus predecessor-record handle to the dedicated protected-Close
partition. Before making the ring reference visible, EventStream writes the
exact helper/event generations, sequence, and protected-slot handle into that
already-reserved record and makes the protected slot's ACK owner the same
generation-stamped record. Only then does an exact `EventEnqueueReceipt` change
the pending slot to sequenced and permit the allocator release transaction.
Backpressure retries the same pair; enqueue failure increments the worker loss
epoch and retains the token and reservations.
An arena record cannot be reused while any protected slot names it. Cancellation
may return an unexposed pair directly, but after ring visibility it must either
complete the allocator publication or terminally join the event generation;
there is no unregister-and-reuse race with ACK.

Each helper generation also preallocates a fixed allocator-owned predecessor
arena with exactly
`workerCount * tupleReleaseFenceSlotsPerWorker` records and generated byte size
no greater than `allocatorPredecessorByteCapacity` (64 MiB). A record is keyed by
the full allocator generation, pool/prefix identity, address family, mode, and
translated/reverse reservation identity and stores the Close stream generation,
sequence, protected-slot reference, state, checked live-handle count, a typed
`localReplayState`, the assigned nonzero Delete wire generation, exact peer
process/transport/fabric identity, and a typed `remoteOrderState`.
`localReplayState` is one of `awaitingCumulativeACK`, `cumulativeACKCovered`, or
`terminalGenerationJoined`; the last value carries the exact terminal-repair
receipt described below and is not inferred from socket loss. `remoteOrderState` is
one of `notRequired`, `awaitingWireGeneration`, `descriptorRequired`,
`barrierCovered`, `legacyConnectionOrdered`, or `terminalRepairOwned`; it is not
an ACK bit inferred from local EventStream progress. It has a fixed tuple hash
index plus sequence-to-slot index and exactly
`allocatorPredecessorShardCount` (256) fixed shard locks/counters; neither index
grows. The arena also has at most one fixed `persistentPredecessorShell` per
record in an independent shell free pool; a live lease does **not** permanently
consume one. Each persistent lease entry has one discriminated ownership union:
either it directly owns the typed physical tuple token, or it owns a checked
handle to a shell that owns that token plus the lease group's intrusive record
head/tail, ordering high-water, and deferred-free state. The first unresolved
Close for a group reserves a shell and, under `allocator live -> predecessor
shard`, atomically transfers token ownership from the exact generation-stamped
lease entry before session mutation. If no shell is available, Close/GC defers
without changing the session, refcount, lease, or occupancy.
The checked 64-MiB startup calculation includes records, shells, both indexes,
shard metadata, alignment/padding, and every allocator family/mode. There is no
per-address/per-port predecessor bitmap outside that bound.

Every predecessor has two independent completion dimensions. The single
`localReplayComplete(record)` predicate is true only when its typed state is
`cumulativeACKCovered` or `terminalGenerationJoined`; every unlink, pressure,
shell-transfer, teardown, and arena-recycle path calls that predicate rather
than testing for ACK directly. Remote-order completion means one and only one of:

1. session sync was administratively absent/disabled, no peer process had any
   session authority in the current daemon namespace, and the record was created
   as `notRequired`; enabling a producer is a config transaction that first
   closes admission and completes authoritative initialization, so it cannot
   inherit ordinary ordering debt;
2. the sender received the complete exact all-current-fabric generation-barrier
   ACK set covering the Delete's assigned wire generation, yielding
   `barrierCovered`;
3. on a legacy transport, the dependent Open was written after the Delete to
   the same still-current single connection and its ordered writer, yielding
   `legacyConnectionOrdered`; or
4. the exact transport/helper generation entered terminal repair while ordinary
   admission stayed closed and the replacement baseline took ownership of the
   remote-order debt, yielding `terminalRepairOwned`.

Local cumulative ACK alone never proves that a peer applied a Delete. A zero
Delete wire generation cannot become remotely complete through ACK or a
generation barrier. Producer setup/retirement freezes the classification under
the transport epoch: an active or disconnected previously authorized legacy or
capable peer creates remote debt. Mere absence of a live connection never means
`notRequired`; only the administratively no-sync state above does.

ACK cannot outrun publication: the protected slot points to the stable
`awaitingReceipt` record before the I/O thread can observe it. Cumulative ACK
atomically changes that exact record to `cumulativeACKCovered` and cannot
reclaim/reuse the protected slot until the mark is complete. The allocator release transaction then takes the
declared `allocator live -> predecessor shard` order, inserts the same record in
the tuple index, performs an Acquire catch-up read of its local replay and remote
order state, and only afterward removes/clears the incumbent ownership. If the
local ACK already covered the Close, that dimension is complete, but the record
may retire before making the tuple free only when remote order is independently
complete; otherwise the indexed record remains unresolved. There is no
copy-from-recycled-slot handoff. Enqueue failure or index/capacity failure leaves
the incumbent ownership visible; all index capacity is reserved before session
removal, so the post-receipt transition itself cannot discover a full index.

Terminal repair has an explicit local-replay completion arm; it does not wait
for an ACK that the retired stream can never emit. Under closed ordinary and
tuple admission it first joins the old worker set, EventStream producer/I/O
thread, protected replay arena, and allocator generation. Authoritative repair
then either transfers the complete predecessor/token/debt into the replacement
generation or proves the old session and every derived reservation surface
absent and performs the exact teardown. Only that exact generation-qualified
receipt changes `awaitingCumulativeACK` to `terminalGenerationJoined`; the same
transaction may independently set `terminalRepairOwned` for remote ordering.
A process crash, stream disconnect, new baseline start, or protected-slot drop
without this join-and-repair receipt satisfies neither dimension. The old arena
may be recycled only after every record has cumulative-ACK coverage or this
terminal local receipt, plus its independent remote-order proof and zero checked
handles.

Port-backed release publishes the indexed record, increments its shard's fixed
`unresolvedCount` with Release ordering, and only then clears occupancy. A
successful claim/reserve uses Acquire ordering, checks that shard counter, and
when nonzero performs one bounded hash lookup under the shard lock before
returning the live allocation token. A zero counter is the no-predecessor fast
path; an unrelated nonzero record costs one bounded lookup but cannot alias.
Address-only owners and persistent/shared leases perform the same publish-before-
remove and lookup-on-reuse under their existing allocator-live serializer. ACK
handling only marks a stable fixed record atomically; bounded maintenance
retires it and decrements the counter under `allocator live -> predecessor
shard` only after both completion dimensions hold, so it never introduces the
reverse edge.

A persistent/shared lease links every protected Close record into its fixed
arena shell's intrusive sequence-ordered list and points
`unresolvedCloseHighWater` at the greatest unresolved sequence before
decrementing the flow/refcount, even when other flows keep the translated lease
active or its inactivity timer retains it. The links and shell live in the
already bounded predecessor arena; there is no per-lease allocation and lease-
map removal cannot destroy the ordering anchor. Every same-lease reuse acquires
a checked handle to the exact high-water slot before incrementing the refcount;
concurrent reuses share handles, never copy or unlink the record. Handle
discharge records either a strictly later protected Open or a rollback with no
successor. Handle-count exhaustion rejects reuse before refcount or session
mutation.

Cumulative ACK or the exact terminal-generation receipt marks local replay
independently of lease activity, and remote ordering resolution is separate from
local replay and physical slot lifetime. Under `allocator live -> predecessor
shard`, only the conjunction of `localReplayComplete(record)` and one proved
remote-order state immediately unlinks the record from
the lease's ordering list, removes its tuple-index/counter obligation, and atomically
repoints high-water to the greatest still-ordering-unresolved record (or zero).
Existing checked handles pin the now-detached slot only until they discharge;
new reuses never acquire a handle to an already resolved record. The slot is
reclaimed once its handle count reaches zero. When a live lease shell has zero
ordering records, zero reuse handles, no tail-transfer expiry fence, and is not
in `deferredPhysicalFree`, the same lock order transfers its typed physical
token back into the exact still-live lease entry, clears the lease's shell
handle, and immediately recycles the shell even if untouched flows still hold
the lease. A generation mismatch keeps the shell owned and fail closed. A rollback that published no
successor leaves the record linked unless a barrier/legacy/terminal proof
resolved remote order. A descriptor-bearing capable successor changes the
record to `descriptorRequired` but does not resolve it. One active untouched flow is never itself a reason to retain a record
whose two completion dimensions are proved. Predecessor pressure closes new
tuple admission and drives the bounded all-current-fabric generation barrier;
after its complete exact receipt, rows whose local replay is cumulatively ACKed
or terminally joined and whose remote order is covered recycle with their shells
even when untouched flows remain active. A partial, timed-out, wrong-
process, or wrong-fabric barrier cannot recycle anything and forces terminal
repair with admission closed. Persistent reuse therefore cannot overtake a
Close merely because no bitmap bit became free, and ACK-only peer lag cannot be
mistaken for ordering completion.

The moved record supplies `predecessorReleaseSequence`; the eventual protected
Open frame must receive a strictly larger global EventStream sequence. Rollback
restores the same record and predecessor marker before making the tuple free;
exact-reserve, HA reserve, persistent reuse, and allocation all use the same
mode adapter. On a capable transport, a claimant moves the checked predecessor
handle into the successor session/lease token. Every ordinary Open **and Update**
for that key, on either fabric, carries the same exact predecessor descriptor
while the handle is `descriptorRequired`; constructing or successfully writing
one frame does not clear it. If that successor closes before a covering barrier,
its new Close record is appended to the fixed per-target intrusive predecessor
chain and the physical tuple remains withheld from another owner until the
older record resolves; no capable frame carries a truncated descriptor chain.
The tuple index points to the fixed chain head/tail, all links are included in
the 64-MiB arena calculation, and one Close consumes one already-counted record.
Updates and compatible persistent-group joins may continue with the inherited
descriptor, but a different physical owner cannot create a second reuse edge.
A free or moved-live/shared record becomes ordering-resolved only after local
replay completion and one remote-order proof, then retires physically after its
checked handles reach zero.
Thus zero means **no predecessor with unresolved local replay or remote-order
debt**, not "never previously owned." Fresh tuples and tuples covered by both
proofs are intentionally equivalent.
The central producer and Go capture reject a nonzero predecessor not already
ordered before the Open.

Persistent inactivity expiry is one allocator/predecessor transaction, not a
direct lease-map removal. Allocation-triggered expiry, pressure GC, per-address
GC, and chunked background GC all take `allocator live -> predecessor shard`,
revalidate the exact idle lease/expiry generation, require both checked reuse
handles and checked tail-transfer expiry fences to be zero, reserve a shell if
the lease still directly owns its physical token, and transition that shell
from `liveLease` to `deferredPhysicalFree` before removing the lease and expiry
indexes. If any handle/fence remains or no shell is available, expiry is
deferred with all indexes and ownership unchanged. For
PAT/NAT64/NAPT64, the shell publishes its greatest still-unresolved record in
the tuple index and increments the shard obligation before the occupancy bit can
clear. Chunked GC may then drop `allocator live` and perform the lock-free bit
clear only while holding that generation-stamped deferred-free token; a claimant
must observe either the indexed predecessor or prior two-dimensional resolution.
Completion CASes the same shell without retiring a record moved by a racing
claim. Address-only persistent expiry clears no port bit, but transfers every
member reverse predecessor to the same arena-owned shell before removing the
lease. With no ordering record, the fixed shell still owns the deferred free
until the physical clear completes. Only a completed clear plus zero checked
handles and no retained record can recycle the shell. No expiry path may call a
raw `free_translated_port` or remove `persistent_by_source` outside this adapter.

An in-process config that changes a pool, prefix, allocator mode, worker set, or
allocator generation cannot drop this state. It closes local session admission
and the matching producer, then either drains every pending/moved predecessor to
its local-replay plus remote-order terminal state or retains the complete old allocator plus arena in
one fixed `retiringAllocatorGeneration` slot while the new snapshot remains
unpublished. A second replacement is retryable-busy until that slot clears; no
chain of retired allocators is allowed. Its monotonic absolute deadline is
`allocatorGenerationRetireDeadline` (20 seconds), and progress never renews it.
Deadline or ambiguous teardown replaces
the helper generation with continuity false and requires authoritative repair
before publication. Pool identity in each record prevents a new allocator from
claiming old metadata by tuple coincidence.

Therefore another worker cannot publish `Open(A,T)` before `Delete(B,T)`: before
the Delete has protected admission, T is still reserved; once it is reusable,
the protected arena contains the Delete and the allocator carries its sequence.
A bank detach can place the two events in one bank or consecutive banks, but
never reverse them. This fence is off the packet-forwarding hot path and reuses
the existing time-sliced delta-drain path; protected-replay occupancy, predecessor
occupancy, high-water, oldest-age, and retained-tuple pressure are exported.
Crossing the generated 75-percent predecessor high-water or deferring one Close
for lack of a record atomically closes Rust tuple creation and admits one
generation-coalesced, correctness-critical `PredecessorPressure` frame to the
protected general EventStream arena. Go closes ordinary production and drives
the barrier/repair procedure below. The latch clears only after Rust validates a
complete remote-order update batch and occupancy falls below 50 percent; polling
telemetry is diagnostic, not the correctness trigger. Failure to admit the
pressure frame leaves local tuple creation closed and makes helper health
fail-closed, so a saturated event arena cannot silently postpone recovery.

Sender-local sequence order alone is not receiver order across two TCP fabrics.
When capable ordinary serialization assigns the predecessor Delete its nonzero
wire generation, it stores that generation back into the checked allocator
predecessor record before serializing a dependent mutation. Every Open/Update
whose session/lease token retains the checked handle carries the
exact 88-byte `tuplePredecessorDescriptor`: predecessor family/canonical key,
wire generation, and SHA-256 of the predecessor's canonical
`memberReservationIdentity`. This trailer is emitted only after both fabrics
negotiate `tuple-predecessor-v1`; legacy traffic remains on one active fabric
and keeps its byte shape and TCP order.

The Go/Rust boundary uses generated, credential-bound, generation-qualified
fixed batches of at most `predecessorOrderUpdateBatchCapacity` (128) records.
`BindPredecessorWireGeneration` CAS-binds
`{helperGeneration, predecessorHandle, eventStreamGeneration, closeSequence}`
to the exact peer process, transport/fabric, and assigned nonzero Delete wire
generation before any dependent mutation can be admitted. A second bind, a zero
generation, a stale handle, or an epoch mismatch leaves the record unresolved,
closes tuple admission, and requests repair.
`MarkPredecessorDescriptorRequired` verifies the successor session/lease owns
the checked handle and makes the descriptor mandatory on every capable
Open/Update without completing remote order. `CompletePredecessorRemoteOrder`
accepts only one typed proof: the complete barrier receipt below, the same-
current-legacy-connection ordered-writer receipt, or the terminal repair
receipt. All operations use `protocolControlTimeout`; timeout or an
ambiguous helper response retains the predecessor and enters replacement rather
than guessing completion. The private helper-protocol generator, version probe,
Go/Rust layouts, and byte/capacity canaries own all fixed messages.

The all-fabric generation barrier is the same bounded primitive used for
pre-bulk fencing and ledger compaction, with explicit generation semantics. The
sender first closes ordinary production at G, drains every already-assigned
frame through G into its exact current capable connection writer, freezes the
one- or two-fabric membership, installs a fixed `pendingBarrierSet`, and writes
`{barrierSetID, peerProcessID, transportEpoch, fabric,
connectionIncarnation, sequence, coveredWireGeneration=G,
ownershipGeneration, authoritySerial, authorityGeneration,
senderConfigEpoch}` on every member.
The receiver maintains one fixed inbound barrier set for that exact ID and
freezes the same one- or two-member capable transport membership on the first
marker. It emits **no** member ACK until every expected marker has arrived on
its named current connection after that read loop admitted every earlier frame,
and every live `receiveBarrierAdmissionToken` in the frozen process/transport/
fabric set with wire generation at or below G has reached `finalCommitted`.
This includes mutation owners, higher-generation waiters, and non-owning
dependency waiters. Marker handling takes the lane-arena barrier lock and scans
its stable records with a checked cursor; final commit clears a token under the
same lock only after ledger/journal commit. Both markers seal their read loops,
so no new token at or below G may appear afterward; waiter promotion preserves
the existing token with no zero-count interval. It then atomically commits its local
`allFabricGenerationBarrierReceipt` and scalar floor before either ACK writer is
released. Any missing member, membership change, or admitted token left waiting,
ambiguous, partial, or timed out
suppresses every ACK, taints continuity, and forces repair; a barrier never
converts ambiguity into applied order. Each ACK echoes every field. The sender
forms a separate mirrored receipt only from the complete exact echo set and
revalidates its frozen membership after the final receipt. Partial sets, `>=`
sequence matches, wrong process/epoch, or timeout prove nothing. The receiver's
receipt may advance only its scalar floor. The predecessor arena retains the
sender's mirrored receipt as one namespace-qualified monotonic covering
high-water. It may remotely resolve only sender predecessor records with a
nonzero bound Delete generation at or below G in the same
peer/transport/config/authority namespace, regardless of whether the local
cumulative ACK arrived first or later. Barrier completion walks a checked stable
cursor in generated batches of 128 and marks every matching record
`barrierCovered`; tuple admission remains closed until the cursor completes.
The local cumulative-ACK callback performs the inverse catch-up check against
that retained receipt before testing the two completion dimensions. Thus either
callback ordering converges, including an arena larger than one update batch,
without treating descriptor emission as proof. Pressure uses this barrier under
the existing five-second `protocolControlTimeout`; failure retires the
transport and moves the exact records into terminal-repair ownership while
ordinary and tuple admission remain closed. No extra predecessor, ledger, or
barrier record is allocated on pressure.

The receiver does not treat the descriptor as delete authority. It recomputes
both member identities from the authenticated config and requires their target
relationship to match. If the predecessor key has the exact peer-owned
tombstone/generation, or its generation is covered by a proved all-fabric
`retiredGenerationFloor` and allocator truth shows no foreign owner, the Open/Update
may enter ordinary reservation. Otherwise it occupies one checked
`ordinaryTupleDependencyEntry` backed by the existing mutation-lane arena and
per-target index and performs no helper/BPF/allocator/worker mutation. This
dependency variant is a **non-owning**, generation-ordered waiter on the
successor key: it cannot install that key's owner handle until the predecessor
proof succeeds. A later-arriving lower-generation Delete for the same canonical
key therefore inserts ahead of the waiter and may own/commit normally. This is
required for two-key swaps where `Open(A,T2)` depends on `Delete(B,T2)` while
`Open(B,T1)` depends on `Delete(A,T1)`; neither Open may hold A or B while
waiting for the Deletes. The
matching Delete commits first and wakes dependent mutations in successor-generation
order even if it arrived on the other fabric. A predecessor Delete with local,
static, wrong-peer, wrong-generation, or wrong-identity ownership fails the
dependency and requests repair; it can never release that tuple for the mutation.
There are at most eight dependencies per translated target and 24,576 globally;
the next entry returns busy before mutation. Each entry has the ordinary
operation's absolute deadline. Timeout, connection retirement, ambiguous Delete,
or missing protected replay taints continuity and forces a requested capable
bulk instead of applying the successor out of order. ACK/floor compaction may
reclaim the predecessor tombstone only after every dependency handle has
discharged.

Captured deltas, including every capture-mode event through and after the export
watermark, form a bounded per-canonical-key coalescer rather than a 4,096-event
FIFO. Each `capturedSessionMutation` is a generated fixed-size value containing
the first observed before-state/tuple-release descriptor, final
Open/Update/Delete, and first/last EventStream sequence for the canonical key;
every final present state retains the checked predecessor handle/descriptor from
its allocator token until a covering barrier. No sender generation is allocated until flush. Because the streamed snapshot
deliberately retains no baseline key set, a final Delete is never discarded
merely because Go did not observe that key in a materialized set. Repeated churn
for one key still consumes one row, but coalescing may not erase a tuple-release
dependency needed by another key.

Each detached bank is planned as one bounded `TailFinalStateBatch` with a
release phase and an acquire phase. The release phase emits at most one
later-generation Delete for every touched key whose starting peer-owned tuple
must be released or whose final state is absent. Only after every release frame
is written, the sender writes an exact release `TailPhaseEnd` marker; only then
does the acquire phase emit at most one final Open for each present key, in
stable last-sequence/key order, followed by an exact acquire `TailPhaseEnd`
marker. Thus `Delete(B,T), Open(A,T), Open(B,U)`
cannot collapse into the invalid `Open(A,T), Open(B,U)` order: B is released
before either acquisition. Swaps and cycles use the same all-releases-first
rule. Every capable tail frame carries a generated canonical
`memberReservationIdentity` derived from its authenticated config snapshot and
typed allocator descriptor. Exclusive members carry a canonical-zero shared
group. Persistent members additionally carry their
`sharedLeaseGroupIdentity`, which names the lease's complete source/permit scope
and lease-owned translated target but deliberately excludes the per-flow remote
reverse token. Their member identity separately retains that exact reverse
occupancy key, including the remote endpoint for address-only persistent NAT.

The sender bank planner groups equal translated targets. Duplicates are valid
only when every member is persistent-shared, every shared-group identity is
byte-identical, every member reservation is individually valid and unique, and
lease parameters are compatible. An exclusive identity, different persistent
source/permit scope, different allocator config ID, duplicate member reverse
token, or group/member disagreement collides and rejects. The receiver's full
allocator/coordinator preflight applies the same two-level predicate. It rejects
a target held by an untouched incompatible peer key or any local/static owner,
but permits an acquire to join an untouched compatible persistent lease while
validating and transferring each distinct per-flow reverse token; it never
synthesizes a delete for that lease's untouched sessions. A key can therefore
produce at most two session frames and each nonempty bank exactly two phase markers.
Session-frame, marker-count, and byte capacity reserve those worst cases while
row credit remains per unique key. Partial release/acquire application is explicitly
ambiguous and enters the cleanup/repair path; it is never rolled back as though
the old tuple were still owned. Across banks, wire order remains causal and a
later bank may release or reacquire a key with newer generations.

`syncMsgBulkTailPhaseEnd = 33` is capability-gated and has an exact 112-byte
little-endian payload: the 56-byte capable bulk identity/config prefix followed
by `{bankSerial uint64, phase uint8, pad [7]byte, phaseCount uint64,
phaseDigest [32]byte}`. Bank serials start at one and are contiguous; phase is
one for release and two for acquire. Both markers are required even when one
phase has zero session frames, and their zero-count SHA-256 digest is canonical.
The phase digest covers only that phase's session frames in wire order. The
overall TailEnd count/digest still covers every session frame and excludes
markers. Wrong order, serial, phase, count, digest, length, or nonzero padding
is a protocol failure before the next phase can mutate.

Every capable baseline, tail, and ordinary Open/Delete draws a fresh checked
nonzero value from the daemon-lifetime global sender counter, so global ordering
implies per-key ordering and an unknown-key Delete still receives a tombstone
generation. The current bounded `genSentV4/V6` maps and their generation-zero
overflow fallback remain only for legacy peers; capable emission never consults
them. Counter exhaustion follows the existing controlled fail-closed process
restart rule and cannot wrap.

Exactly two lazily allocated banks share one checked fixed byte-credit pool,
`captureTailTotalByteCapacity`; they do not each reserve aggregate session
capacity and no snapshot-sized vector is counted or allocated. Credit is charged
at the generated maximum fixed captured-mutation footprint to active and detached rows
until a detached row is successfully written and released. A separate tail-row credit is capped by the peer's advertised
`maxCapturedTailRows`. It charges the first insertion into each active bank and
is not released until the bulk terminates; coalescing another mutation into that
same bank row is free, while a key reappearing after its earlier bank detached
conservatively consumes another row credit. This needs no unbounded cross-bank
key set and guarantees receiver-unique growth cannot exceed the advertised
credit even though repeated keys may overcount. The checked emitted session-
frame ceiling is `2 * chargedTailRows`, and the phase-marker ceiling is also
`2 * chargedTailRows` because every emitted bank consumes at least one charged
row and has two markers. Wire-byte credit includes both products using generated
maximum session-frame bytes and the exact 112-byte marker; markers cannot hide
outside the advertised tail budget.
The implementation validates fixed record sizes and arithmetic at
startup, publishes current/high-water/overflow telemetry, and refuses a new
bulk if the credit pool cannot be reserved. Pre-snapshot unique churn or a
producer that outpaces a detached drain fails closed when the shared credit is
exhausted; it never allocates a third bank or spills silently. The production
credit limit and high-cardinality RSS/throughput measurements are deployment
owned, not a test-only unbounded override.

The ordinary send queue is not required to absorb the captured tail. After the
exact intermediate BulkAck, install a fresh absolute
`authoritativeTailFlushTimeout`. Under
`producerMu`, detach the active coalescer bank, install the empty second bank,
and release the mutex. Directly write the detached bank on the exact bulk
connection in complete release-marker-acquire-marker order with fresh per-key
generations and normal bounded write/token revalidation while computing a
count/digest over every tail frame in wire order; duplicate keys across banks
are valid later state, not a protocol duplicate. Events arriving meanwhile
coalesce into the active bank. Repeat the bank swap/drain until the active bank
is empty under `producerMu`, mark the local token `finalizing`, release that
mutex, and then issue one generation-bound
`finalize_owner_rg_session_capture` helper command. Every captured worker drains
pending deltas, emits its phase-2 boundary with the unchanged loss epoch, and
the helper enqueues one lossless in-band `MSG_EXPORT_CAPTURE_SEAL` under
`producer_seq_lock` after all those boundaries. Its exact 48-byte payload is
`{exportID uint64, workerSetGeneration uint64, lossEpochDigest [32]byte}`; the
ordinary EventStream header supplies terminal sequence S. The helper response
echoes S/digest but is not the partition point.

The single Go EventStream read loop processes the seal frame in sequence. Its
callback validates every phase-2 boundary and loss epoch, acquires `producerMu`,
detaches the active bank as the final `<=S` bank, switches capture routing to the
closed ordinary queue, records S/digest, releases the mutex, and wakes the bulk
worker **before** the read loop can decode S+1. Thus an S+1 mutation of the same
key cannot overwrite/coalesce an S mutation. The bulk worker joins the helper
response, waits for the seal callback, drains the detached final bank, and only
then records one TailEnd token containing the bulk
identity and tail count/digest. A phase-2 loss, epoch movement, sequence gap,
seal mismatch/replay from another token, final-bank overflow, or finalize
failure suppresses TailEnd. Loss after the
terminal cut follows ordinary-stream loss handling and invalidates the pending
continuity token; it cannot be hidden by clearing a Boolean latch. Release
`producerMu`, write the
exact 96-byte TailEnd on the bulk connection, and wait up to 20 seconds for its
exact TailAck. Only TailAck opens the ordinary writer and publishes outbound
repair completion, so no frame on another fabric can overtake TailEnd. No
network write occurs while holding `producerMu`; at most one detached and one
active bank exist. Ordinary-queue overflow while awaiting TailAck or sustained
churn that cannot reach the sealed point before the absolute tail deadline is an
explicit repair failure, not an unbounded flush.

On overflow or flush failure, preserve required deletes in the existing delete
journal, drop only installs covered by a mandatory follow-up bulk, and retain
repair debt. Failure before BulkStart may reopen the unchanged transport after
complete local cleanup; failure/timeout after any BulkStart suppresses whichever
end/ACK phase has not crossed, retires the transport before producer reopening,
and leaves the peer tainted. The replacement transport starts with producers
closed and fresh repair debt. `producerMu` is never nested with the delete-
journal mutex.

The gate is the sole receive-window state machine. BulkStart is authoritative
only on an initialized, current, capable connection and only when admission is
open. A requested bulk must echo the exact nonzero request ID; an ordinary
request-ID-zero bulk is accepted only after independent
`inboundBulkAuthorized` is true. Receiver authorization becomes provisional
only at the record-before-send TailAck precommit and durable only after its
postcommit; baseline BulkAck sets neither. Config
send and config-frame admission clear both authorization directions before
write/apply. Ownership/config-sync change, last-fabric loss, or capability/process
change also clears both before new traffic. Sender ACK success never directly sets the
receiver bit, and receiver reconcile success never directly sets the sender bit.
The receive window stages the marker's **peer-owned** epoch. If config sync has
already applied that peer generation, it must match `acceptedPeerConfigEpoch`
exactly. Otherwise, a new peer process or config-sync-disabled independently
committed peer may stage it only when its digest exactly equals the local
canonical committed digest and it does not conflict with a prior generation/
digest declaration for that same process. The staged epoch is not published as
accepted until baseline reconciliation, intermediate BulkAck, tail
reconciliation, and exact TailAck postcommit all succeed. During the
post-reconcile ACK precommit, causally released tail frames compare against that
provisional staged peer epoch; failure clears it and retires the transport.
Capable BulkStart is the exact 56-byte little-endian form
`{bulkEpoch uint64, requestID uint64, configGeneration uint64,
configDigest [32]byte}`. Capable BulkEnd is exactly 96 bytes: the same 56-byte
prefix followed by `{memberCount uint64, memberDigest [32]byte}`. The first eight
bytes preserve the legacy bulk epoch; the capability-gated fields bind the
request, sender-owned config epoch, and exact streamed member set. Other capable
marker lengths are malformed. A receiver compares the config digest with its
canonical committed digest, but never compares the sender generation with its
own local generation.

Acceptance of `BulkStart` installs the same 180-second absolute deadline in the
receive window, sets `bulkMutationTainted=true`, closes current continuity, and
blocks previous-good automatic-election availability before the first member
can mutate the dataplane. It covers member installation, arrival of `BulkEnd`,
and context-aware reconciliation; member progress does not extend it. Expiry
cancels/joins reconciliation if started, publishes no ACK/continuity/debt
success, leaves taint set, and retires the transport. The five-second request-start timer ends
only when the exact start binds this receive window; it is not reused as the
bulk-completion budget.

The same admission binds one working `capableGenerationLedger`. Its checked
capacity is the receiver's advertised accepted logical-session ceiling plus the maximum
unique tail rows it advertised in the bilateral capability frame
(`peerTailReserve`, already bounded by `captureTailMaxRows`, the generated
coalescer footprint, and every physical-surface residual, in this version). The byte
budget and row ceiling are both enforced; neither can be inferred from the
other because v4/v6 fixed record sizes differ. The baseline
membership map, generations, and later tail tombstones share this one
allocation: `present=true` rows drive stale reconciliation, and wire Deletes
newer than the last proved all-fabric floor retain `present=false` tombstones.
Decoded baseline Opens do **not** consume a committed ledger slot before stale
selection. Each of the at most 128 wire rows first occupies its fixed
`incomingStaging` journal record and staging index. Existing-key attempts bind
their existing slot; a disjoint attempt binds either a charged free slot or one
exact selected stale slot through `bulkLedgerTransitionRecord`. That incumbent
slot retains the old key/high-water until the all-surface Delete and attempted
Open reach an unambiguous final result. Complete success atomically removes the
old index and rekeys the same slot to the attempted row; old-survives, new-
survives, and neither-survives repair outcomes resolve the union explicitly.
During the bound bulk ordinary admission is closed, and the fixed staging index
is the only lookup authority for attempted keys, so the main key index never
contains two committed keys for one slot. Partial results retain both identities
in the already-reserved journal without charging another ledger row.
The ledger separately stores a scalar `retiredGenerationFloor` plus the exact
all-fabric barrier receipt that authorized it. A key row may be removed only
when its high-water is at or below that floor; every later frame at or below the
floor is rejected before per-key lookup. This does not reject legitimate
cross-fabric reorder: the floor advances only after every member of the frozen
current capable set contributes one generation-bearing barrier and every earlier
admitted receive barrier token, including a dependency waiter, has joined with an
unambiguous final ledger/journal commit. If tail/tombstone reserve fills, ordinary admission closes and runs that
barrier; failure leaves repair debt rather than erasing a tombstone.

For the same peer process, BulkStart increments a
checked repair serial in place and preserves every per-key high-water; each
successfully applied baseline/tail operation stamps that serial. A new peer
process resets the inventoried rows' generation namespace to zero before its
first request and resets `retiredGenerationFloor` plus its barrier receipt to
zero/invalid; BulkStart may bind it only after table taint is set and the old
process token is invalidated. Keys remain available for stale selection and
capacity replacement. The pre-bulk all-fabric barrier advances
`retiredGenerationFloor` to the frozen `generationFloor`. A complete internal
stale eviction therefore removes its slot instead of manufacturing a tombstone:
its retained high-water is already covered by the scalar floor. A full disjoint
N-to-N baseline pairs each new staged row with one old slot and commits that
slot's exact old-to-new transition only after the physical result is known, so
it needs N committed rows plus the advertised tail reserve, not 2N and not 128
extra committed rows while decoding. A real
wire Delete above the floor remains a tombstone through TailAck or a later
proved generation barrier. No second maximum-size ledger is allocated.

The ledger is not a bare Go map. `pkg/cluster/generationledger/` owns two typed
paged stable-slot tables with a key-to-slot index, fixed-size lazily allocated
pages, a bounded free-slot stack, checked `uint32` handles, and a monotonic live
extent. Lookup remains expected O(1); successful insertion charges one shared
row credit before allocating a page. The stable slot extent gives compaction a
real resumable stale-candidate/reconciliation cursor without Go-map iteration
state, a second key vector, or a per-row heap object. Removal clears the index
before returning the slot to the free stack, and invariant tests reject stale
index handles or duplicate free slots. This is an internal modular package, not
another `sync_feature.go` file.

Baseline frames require a nonzero generation, a unique key, and a value greater
than the retained same-process high-water. BulkStart freezes
`generationFloor=maxObservedGeneration`; because the capable sender allocates
fresh values in exact stream order, every baseline and tail frame must be
strictly greater than the prior wire frame starting at that floor. Each admitted
operation advances `lastWireGeneration` and the ledger's scalar maximum even if
a later dataplane prefix fails, so retry cannot reuse it. Capable ordinary frames
on redundant fabrics retain per-key ordering and update the scalar only with
`max(old, incoming)`; they are not globally rejected merely for cross-fabric
arrival order. Every Open must resolve through the
captured compiled zone/RG view to a currently peer-owned ingress domain; an
unknown zone, local-owned zone, owner mismatch, or existing local-origin backend
entry is a hard conflict before Go BPF/helper mutation. Tail and later capable
ordinary frames require a strictly increasing nonzero generation per key. A
Delete mutates the dataplane only when the ledger says the key is a present
peer-synced row and the backend confirms that origin; an unknown/absent-key
Delete is idempotent tombstone-only and can never remove a same-key local-origin
session. The all-fabric pre-bulk barrier makes it safe for baseline capacity
admission to reclaim an unseen old tombstone or delete an unseen old peer-synced
live row before inserting a new key. One wire batch admits at most 128 incoming
Opens. Batch preflight marks every existing incoming key tentatively seen and
emits an explicit release sub-operation for each incoming row whose current
full session/reservation differs from the desired Open. It then resolves every
translated-target incumbent before choosing ordinary capacity evictions.

An exclusive incumbent or a one-member incompatible shared group contributes
one selected stale release to the final batch. An incompatible persistent-
shared group may contain arbitrarily many peer flows, so it is never forced into
the 384-operation final request. If all members are peer-owned, unseen or
released by this same incoming batch, and no member is local/static or already
committed seen, preflight installs the receive-window's one fixed
`bulkGroupEvictionPlan`. It acquires the group token and generation-stamped
expiry fence before the first decrement, then synchronously walks stable member
slots in deterministic chunks. Each prerequisite helper request contains at
most 128 explicit internal Deletes, uses an ordinary journal/lane slot, reports
`AppliedWire=0`, and must complete on every surface before the cursor advances.
Its escrow group entry carries the tagged `activePlanHandle` owner arm with the
exact plan slot generation rather than a copy of the group token. Member tokens are discharged after their exact surfaces
are absent; only the plan-owned group token/fence and checked cursor survive
between chunks, so a 262,144-member
group does not allocate 262,144 escrow records. Current-batch members are left
for a final **park** step rather than the later acquire request. That step uses
their already-reserved peer-wire owners/journal records to delete the current-
batch members from every surface, moves their exact member tokens into final
batch escrow, reserves a generation-stamped `parkedBulkGroupRelease`, and under
the escrow lock atomically CASes the group entry's ownership union from
`activePlanHandle` to `parkedHandle` while moving the sole token/fence out of the
plan. Stale generation, duplicate transfer, or any noncanonical union fails
closed before plan reuse. Only after the old group's refcount reaches
zero and that transfer commits may the serial plan slot/cursor recycle for the
next incompatible group. This is plan-terminal, not transaction-terminal: no
token becomes free and no incoming Open has run. At most 128 parked groups and
128 current-batch member records exist because one wire batch has at most 128
Opens; they are included in the journal's generated byte bound.

The incoming Opens remain staged and contribute no receive count or digest
until every required group is parked and the final acquire succeeds. A second
or later group is processed serially after the preceding plan-to-park transfer,
so a two-group swap cannot wait on its own final phase. Timeout, partial result,
disconnect, or helper loss retains all completed parked records plus the one
active plan as ambiguity debt, taints the table, and suppresses the wire batch
rather than returning any target to local allocation. The receive window's
180-second absolute deadline bounds total prerequisite work; progress and group
size do not renew it.

After all prerequisite groups are parked, deterministic capacity pressure chooses
at most one additional ordinary stale row per incoming frame. The final request
therefore still contains at most 128 not-already-parked same-key releases, 128
single-row stale or capacity releases, and 128 Opens. It prepends all remaining release sub-operations to the
same at-most-384 physical-mutation request and reserves a distinct mutation-lane
record plus ambiguity-journal record for every Delete and Open before the first
effect. The helper and each worker receive those exact all-release-before-
acquire operations and return per-operation outcomes; no stale Delete is
implicit in an Open result. Internal Deletes and reclaimed rows do not count in
the peer-wire digest. Complete internal eviction removes the stable slot because
the pre-bulk scalar floor already covers its high-water. If the evicted key
appears in a later baseline batch, its fresh generation installs it normally
and may displace a different still-unseen row. Final baseline reconciliation
deletes every remaining unseen live row in bounded chunks before BulkAck but
preserves wire tombstones newer than the scalar floor through TailAck. Thus a
full disjoint replacement never exceeds helper/BPF/ledger capacity, while a
desired set that truly exceeds receiver capacity fails before the affected Open. An unfinished
bulk preserves every observed high-water and remains non-authoritative under
table taint. Capable mode never falls back to generation zero or clears a
same-process ledger. The existing 200,000-row/gen-zero behavior remains
legacy-only.

Generation admission is not permission for concurrent same-key mutation. One
startup-preallocated `sessionMutationLaneArena` contains exactly
`sessionMutationLaneRecordCapacity` (24,576) fixed operation records, matching
the complete 64-batch-by-384-physical-mutation admitted domain. Its generated records, fixed
completion primitives, free stack, and alignment must fit
`sessionMutationLaneByteCapacity` (64 MiB) at startup. A ledger slot stores only checked
owner/head/tail handles and an eight-bit waiter count, not eight full operation
records per possible session. Arena records contain exact batch ID, generation,
source connection, helper/config/authority lease, phase, and intrusive
generation-ordered links. The arena's generated byte footprint is included in
the accepted-session capacity plan; no queue node or completion channel is
allocated after startup.

Every admitted `sessionMutationPeerWire` frame initializes the lane record's
generation-qualified `receiveBarrierAdmissionToken` synchronously in the read
loop before it can enqueue. The read loop performs bounded parse, namespace,
generation, and capacity validation, links the record under the arena lock,
and returns to decoding; it never waits on a lane completion, predecessor,
helper, BPF operation, barrier, or worker. A dependency or higher-generation
waiter is linked only in the corresponding fixed per-key/per-target index. An
immediately executable owner is also appended by handle to the arena's
intrusive ready FIFO. No operation allocates a goroutine, queue node, channel,
timer, or closure.

Exactly `sessionMutationExecutorCount` (64) scheduler workers are created and
owned by one capable transport generation. A worker takes only a ready owner,
revalidates its source/config/authority/helper lease and actual incumbent, and
runs its bounded mutation outside state locks. A waiting predecessor or busy-
key record never consumes a worker. Final owner commit under
`s.mu -> gate.mu` either appends the next still-current same-key owner and each
newly proved cross-key dependency to the ready FIFO or records exact ambiguity;
workers never sleep waiting for another lane record. The FIFO contains at most
`sessionMutationReadyCapacity` handles stored in the lane records themselves,
and each handle has one queued/running generation state, so duplicate enqueue,
ABA reuse, or queue overflow is an invariant failure that closes capable
admission before another mutation. Cross-key result order is intentionally
unspecified; per-key generation order, dependency proof, and final ledger/
journal commit are the only semantic ordering constraints.

The scheduler also owns one fixed inbound-barrier coordinator. Read loops seal
and publish member markers into the fixed barrier set and continue decoding;
they never wait for token completion. Once every member marker is present, the
coordinator advances its checked arena cursor only when final commits signal
the fixed wake primitive. It releases ACK writers only after the complete scan
finds no admitted token through G. Thus a marker, dependency waiter, or slow
owner cannot occupy either TCP read loop and prevent a later predecessor Delete
or peer marker from being admitted.

The token is independent of mutation
ownership: a higher-generation waiter and a descriptor-blocked dependency have
the same `admitted` barrier state as an owner. Waiter-to-owner promotion changes
only `laneState` under `s.mu -> gate.mu`; it neither transfers nor temporarily
clears the token. Only unambiguous final ledger/journal commit changes the token
to `finalCommitted` and permits record recycling. Partial/timeout/ambiguous
completion retains it. Internal stale evictions have canonical-zero tokens and
cannot affect a peer generation barrier.

Under `s.mu -> gate.mu`, an idle slot atomically
installs its owner handle
before incrementing `inFlightInstalls`. A busy slot may reserve a journal/batch
slot and operation record and link a strictly higher generation, but it performs
no helper, BPF, allocator, worker, or Go-ledger mutation. The waiter consumes no
executor and remains parked in the arena until owner completion, predecessor
proof, cancellation, or its receive-window/ordinary-operation absolute
deadline. The scheduler's fixed deadline coordinator, not the read loop or an
executor, moves an expired waiter to typed repair debt. Per-key waiter or global
arena/batch-slot exhaustion fails before mutation, closes admission, and retires
the transport into repair debt; it never launches an untracked goroutine, grows
per-session memory, or drops a capable operation as though it applied.
Descriptor-blocked dependency records use this same waiter representation but
are never promoted merely because the successor key is idle. They become
promotion-eligible only after exact predecessor commit/floor proof, at which
point the fixed scheduler appends the record to its ready FIFO and the
executing worker revalidates generation and actual incumbent state.
Lower generations admitted while a dependency is blocked are inserted before
it; no dependency waiter can reserve an owner handle or create a cross-key wait
cycle.

`sessionMutationPeerWire` owners use the nonzero sender generation and the
higher-generation waiter ordering above. When an incoming Open replaces an
existing same-key row, that one peer-wire owner spans two explicit physical
journal/helper sub-operations: release of the exact expected incumbent in the
global release phase and acquisition of the desired row in the later acquire
phase. It retains the lane and `inFlightInstalls` credit across both; the
release sub-operation cannot promote a waiter or commit a tombstone by itself.
Whole success commits the incoming generation/value once, while any partial
prefix retains both sub-records and transfer escrow under the same owner.

An unrelated internal stale Delete instead uses
`sessionMutationBulkEviction` with exact
`{repairSerial, batchID, expectedRetainedGeneration}`. That class is legal only
inside the bound baseline window after ordinary admission is closed and all
earlier owners/waiters are joined; the target must be a present unseen
peer-owned row at exactly the retained generation and cannot be an incoming key
in the same batch. It never enters the higher-generation FIFO and never invents
or advances a wire generation. Complete eviction retains no row: the pre-bulk
all-fabric barrier already advanced `retiredGenerationFloor` through the exact
prior high-water, so final commit removes the index/slot and the scalar floor
rejects every delayed equal/lower replay. Partial eviction retains the same
class, expected generation, and slot in ambiguity debt. A later real Open must
carry a wire generation strictly above the scalar floor. Zero, a borrowed
incoming generation, or reuse of the evicted row's generation as a peer-wire
owner is an invariant failure.

An owner retains the key through Rust completion, every external-surface
result, and final Go ledger/journal commit or ambiguity discharge. Completion
reacquires `s.mu -> gate.mu` and uses an exact owner-token CAS. On complete
success it commits the generation/value and promotes the next still-current
waiter. That successor derives its actual before/allocator incumbent from the
newly committed coordinator and ledger state at promotion time, not from the
snapshot observed when its wire frame arrived; the wire before projection is
retained for source consistency and cleanup evidence but cannot overwrite the
actual predecessor. A generation between the owner and an already queued token
is inserted before that token; a generation at or below the committed/active
owner high-water is stale. Queued state transitions are not coalesced away merely
because a larger generation arrived. This supports legitimate cross-fabric
arrival reorder without reversed completion.

Any partial/ambiguous owner result keeps the owner descriptor and tuple escrow,
marks the key and table tainted, cancels every unstarted waiter into the same
bounded repair record, and admits no successor until origin-aware cleanup and
fresh authoritative repair. Disconnect or one fabric's retirement cannot move
an owner or waiter to another connection. Stop/config/ownership/helper
replacement first closes scheduler admission ahead of the read loops, cancels
the scheduler generation, and joins all 64 workers. It then proves the ready
FIFO empty and every record either free/final or exact ambiguity debt before
replacing authority; a waiter is never joined by waiting inside a receive loop.
Map migration requires the stronger zero-ambiguity form and does not freeze or
repopulate a map until the scheduler is stopped, all workers are joined, and
every lane/barrier token is final and recycled.
Legacy traffic retains its single-active-fabric rule and cannot enter this
capable queue. Thus the current production assumption that guard, helper
mutation, and generation recording cannot overlap on one key is replaced by an
explicit bounded state machine rather than silently invalidated by two fabrics.

Only frames from the bound bulk connection can become membership. Any session
frame on another fabric while the window is receiving or reconciling is a
protocol violation that invalidates the window and retires the transport; a
valid sender's all-fabric fences and producer gate make such traffic impossible.
A config frame invalidates the receiving window and then enters config apply.
If reconciliation has started, config/ownership/disconnect/Stop cancels and joins the
worker before proceeding; no same-loop condition wait is used.

Bulk baseline application is synchronous and bounded in the bound receive loop,
but it is not one helper RPC per session. `BulkStart` first closes ordinary
admission and waits for all earlier admitted installs to decrement
`inFlightInstalls`. The loop decodes at most
`clusterSyncBatchCapacity` (128) wire mutations into one fixed-capacity batch;
after deterministic stale selection the derived physical batch is bounded by
`clusterSyncPhysicalMutationCapacity` (384).
The baseline grammar admits only forward Open frames. For each frame it validates
the exact capable payload/canonical key and inserts one fixed incoming-staging
record, not a committed ledger row; the staging index rejects a duplicate before
any dataplane call. Stale selection then binds each staged record to an existing,
free, or replacement-transition ledger slot before mutation. A full batch or the arrival of
BulkEnd captures one apply token under
`s.mu -> gate.mu`, releases locks, and invokes:

```go
ApplyClusterSyncBatch(context.Context, ClusterSyncBatch) (
    ClusterSyncBatchResult, error,
)
```

The result is successful only when `Complete=true`,
`AppliedPhysical==len(PhysicalOperations)`,
`AppliedWire==len(WireOperations)`, and
the exact source/helper/authority lease remains current. The userspace adapter
builds up to 384 explicit physical-mutation records from one sealed config snapshot, uses one bounded
`sync_session_batch` helper request, and updates its BPF shim in the same bounded
operation. Before incrementing `inFlightInstalls` or issuing that request, Go
reserves one slot in its fixed 64-slot `ambiguousMutationJournalRegistry` and
fills up to 384 records only after each key's mutation-owner token is current.
Across all 64 slots, generated physical records, member/group transfer escrow,
incoming staging/transition records and indexes, parked-group records, completion
state, token unions, and alignment must fit
`ambiguousMutationJournalByteCapacity` (256 MiB) at startup; exact size drift or
overflow refuses capable activation rather than allocating a side structure.
Each record uses the exact coordinator/ledger/allocator before-value observed
when that token becomes owner and the sealed attempted value, including every
Go-owned kernel/shim/DNAT descriptor; a queued same-key waiter never snapshots
a predecessor before it commits;
registry exhaustion returns busy before mutation. Therefore a lost helper
response cannot prevent cleanup. The co-versioned Rust
handler prevalidates the ordered operations
against one tentative map view, computes and reserves the batch's exact net
new-key growth under the shared synced-map lock before mutation, and returns
explicit applied/idempotent/stale/capacity/publish outcomes; it may
not reuse the current void-returning
`upsert_synced_session` behavior that silently ignores stale/capacity failures.
`PhysicalOperations` contains every explicit internal Delete and peer-wire
Open; `WireOperations` is the authenticated Open subsequence used for receive
count/digest. The two checked result counters and per-physical-operation
outcomes cannot let a successful stale eviction masquerade as an applied wire
member.
Prevalidation builds the same synthesized reverse companion for an Open and the
same forward/reverse removal set for a Delete, accounting for replacements and
all earlier release operations plus earlier operations on the same key before any shared-map, BPF, or worker
mutation. It refuses an Open collision with a local-origin entry and a Delete
whose target is not peer-synced; the Go ledger's tombstone-only operation is not
sent to the helper.

Before ordinary translated-Open reservation, the batch builds its fixed
`bulkReplacementEscrow` under the allocator/coordinator serializers. **Every
explicit release**, whether it is the release arm of a same-key peer-wire owner,
a selected one-row stale Delete, or one prerequisite group-eviction member,
contributes its exact `memberReservationIdentity`, optional
`sharedLeaseGroupIdentity`, incumbent key/generation, typed physical or reverse-
member token, and release/acquire record ordinals. The overlay is therefore the
single source of tuple availability for incoming-only swaps and cycles; a
same-key release can feed a different key's acquire and is not trapped in its
per-key owner record. Exclusive tokens
remain unavailable to ordinary allocation but become consumable by exactly one
later compatible Open in this same batch. Persistent-shared groups retain exact
untouched/released/acquired refcounts and distinct member reverse tokens; before
the first decrement they take the same generation-stamped expiry fence used by
tail transfer. A prerequisite/final request for a planned group follows the
checked tagged ownership union from inline token to active-plan handle to parked
handle; it never copies or independently releases the token/fence. Fixed
translated-target, member, and group indexes reject a
duplicate consumer, incompatible group, or local/static/seen incumbent. This
overlay is fully reserved and validated before the first Delete of each bounded
request, so swaps and cycles never require a temporarily free bitmap bit. A
same-key owner still retains its lane across its release/acquire pair, but its
physical token is transferred through this overlay. It is the shared bounded
tuple-transfer module used by baseline and tail state machines, with separate
fixed owners rather than duplicate ad hoc NAT logic.

For a translated Open, preflight also converts
`reserve_synced_source_nat_allocation` and
`reserve_synced_nat64_allocation` from void best-effort loops into typed,
origin-qualified reservations. A matching local pool/prefix with an occupied
translated tuple rejects unless the exact compatible token is already reserved
by an earlier selected Delete in `bulkReplacementEscrow` or the Open legally
joins an untouched compatible persistent group. An exhausted reverse-identity index, foreign pool provenance
under an allegedly equal config digest, or allocator error rejects the logical
operation before any session/BPF/worker mutation. Replacement is a two-token
transaction, not today's destructive `reserve_flow`: preflight captures the
incumbent reservation and reserves the attempted tuple **without** releasing or
mutating the incumbent. If the canonical tuple/provenance is unchanged, it uses
one idempotent incumbent token and creates no second refcount. If the tuple
changes and no exact earlier release token in `bulkReplacementEscrow` supplies
it, occupied/exhausted attempted state fails with the incumbent byte-for-byte
intact; address-only and persistent/shared-lease modes may not silently
return the old translation for a changed decision.

Each successful tentative attempted reservation plus any incumbent token is
held in the batch transaction. Either may be rolled back/released only while
the entire operation is still preflight-only and the incumbent was never
detached. Immediately before the first shared, BPF, kernel-map, or worker
mutation for that operation, both move to non-reusable ambiguity escrow in the
fixed journal described below. Whole-batch success transfers the attempted
token to normal session teardown and releases the incumbent only after every
derived surface commits. A selected stale token consumed by a later Open is
transferred only after its Delete has completed on every required surface. An
unconsumed released token is returned only after every old surface is proved
absent; a shared-group expiry fence is discharged only after exact new/retained
membership or origin-aware cleanup commits. Any partial/unknown prefix keeps
all incumbent, attempted, and cross-key transfer tokens escrowed until
cleanup proves whether the old or new session survives; neither tuple is
returned merely because the logical operation did not commit. Persistent lease
and shared source-key refcounts follow the same two-token rule.
Delete releases only the reservation owned by that exact peer-synced session.
The Rust process owns a matching fixed registry entry keyed by exact
`{helperGeneration,batchID}` before its first mutation; it contains allocator
escrow plus shared/worker before/attempted state. An unambiguous preflight-only
failure removes both journals, whole success transfers ownership and removes
them, and any partial result or lost response retains them. A retry queries or
cleans that exact ID; it cannot create a second reservation. Go's independently
prepared descriptors remain sufficient to quarantine and clean external maps
if the helper process disappears with its private registry.
No capability count claims to predict tuple collisions: the count reserves
memory/map slots, while this per-operation reservation is the fail-closed
semantic gate. Every captured worker applies both entries for each logical operation
in exact batch order, while its acknowledgement reports the physical-operation
count and exact outcome vector; a missing reverse, half-applied pair, reordered mutation, or disagreement
between entry growth and physical count is a partial failure. Baseline wire
membership contains only unique Opens while its physical batch may prepend
explicit stale Deletes; tail batches contain phase-separated Open/Delete
operations and may repeat a key across bank boundaries.
`SessionTable` keeps its current local-admission ceiling but gains a separate
hard total-entry ceiling from `SessionCapacityPlan`; sync-family upserts no
longer grow without bound. The total ceiling reserves two entries for every
local, peer-baseline, and transient-tail logical credit on **every** worker,
because both locally learned and peer-imported sessions are replicated to all
other worker tables. Batch preflight reserves net entry growth across every
worker inbox before the first shared-store or BPF mutation. A reservation token
is consumed by each worker's exact acknowledgement and is released only after
all workers complete or the helper generation is retired; timeout/partial apply
marks every attempted key ambiguous in its exact ledger slot or fixed staging/
transition record and cannot turn a prefix into reusable capacity. Ordinary
local installs continue to use the local ceiling, but their
replica fan-out consumes already-reserved total-entry credit and cannot fail at
a peer worker after the owner worker commits.
The request deadline is `min(clusterSyncBatchDeadline, remaining receive
window)`, so neither worker backpressure nor a stuck completion can turn one
batch into an unbounded receive-loop stall. The validated operations are held
once in an `Arc<[ClusterSyncMutation]>`; the
handler enqueues one `WorkerCommand::ApplyClusterSyncBatch` descriptor, not
one command or one record clone per session, into each worker's bounded import
inbox. Each worker applies at most 64 records or 50 microseconds of that batch
per poll before returning to packet work, then publishes the exact
`{helperGeneration, batchID, workerSetGeneration, appliedCount, outcome}`
completion to the handler. A helper success response is forbidden until every
worker in the captured set has acknowledged all members and the checked shared
table plus BPF-shim publication have completed. Inbox credit exhaustion,
worker-set drift, a missing/duplicate ACK, partial application, helper
replacement, or the request deadline produces an explicit partial/failure
result. The bounded descriptor/inbox and per-poll budgets prevent both the
existing per-member fanout explosion and a control-plane batch from monopolizing
a packet worker; an asynchronous "queued" result is never accepted as installed
session continuity.
This is a two-phase Rust server operation. A process-scoped registry admits at
most `clusterSyncBatchInFlightCapacity` waits; the next request returns busy
before validation or mutation. `prepare_cluster_sync_batch` runs
under the global `ServerState` lock only long enough to validate/reserve, apply
the checked shared/BPF mutation prefix, register one bounded cancellation token,
capture worker generation/ACK handles, and enqueue the ref-counted descriptors.
It returns `ClusterSyncBatchWait`; the server drops `ServerState` before waiting
for worker completions and constructing the response. Rebind, worker removal,
and shutdown cancel and join every registered wait before worker teardown, and
the waiter revalidates the captured worker-set generation before success. No
status, HA update, urgent fence, or unrelated session request is blocked on a
worker ACK while holding global coordinator state.
If a kernel-map or worker publication fails after a prefix crossed its mutation
boundary, the result reports partial failure rather than claiming rollback;
table taint plus `ledgerInventoryDirty` and mandatory origin-aware cleanup and
re-inventory make that fail closed. Existing-key attempts remain ambiguous in
their already-reserved ledger slots. A disjoint replacement leaves the incumbent
key/high-water in the main ledger index and marks its fixed incoming-staging and
old-to-new transition records ambiguous; it does not allocate a second ledger
slot or rekey the incumbent speculatively. The receiver retains the batch's
already-reserved journal slot until cleanup chooses old, new, or neither.
Unlike the key-only generation ledger, each record owns the exact before and
attempted derived-surface descriptors: forward/reverse and alias keys plus
expected encoded values, worker replicas, dynamic-DNAT key/value/flags,
peer-authority namespace, wire generation, and any escrowed SNAT/NAT64 token.
Delete captures its pre-mutation descriptor before removing shared authority;
therefore later inventory cannot erase the information needed to remove an
orphan. The first ambiguous result closes new admission, but every already-
admitted ordinary or bulk batch keeps its distinct slot until it finishes. The
gate then joins all `inFlightInstalls` and discharges retained slots in checked
batch-ID order. At most 64 x 384 physical-mutation records exist in the startup-sized reusable
arena, matching the Rust wait registry; neither fabric can overwrite another
batch or accumulate unbounded cleanup state.

Discharge of all retained slots runs before peer re-inventory. The recovery gate
first closes local create/teardown, peer import, config apply, and helper-derived
surface publication, then joins every already-admitted Go map/worker writer.
The userspace XDP shim is read-only for these maps. Under that exclusive writer
ownership, bounded chunks perform application-level lookup, exact-value
revalidation, and delete; this is the plan's only meaning of compare-delete and
does not assume a kernel BPF compare-and-delete primitive. They remove
both before and attempted peer-owned rows from every shared/BPF/kernel/worker
surface. A shared or worker row must still carry the recorded peer namespace and
generation/value; a dynamic DNAT row is removed only when `flags == 0`, padding
is canonical zero, and its entire value equals the recorded dynamic value.
Because kernel/shim/DNAT rows
do not all encode provenance, cleanup first freezes config and local-session
admission and resolves every descriptor against the coordinator/allocator
authority snapshot. A key/tuple currently owned by a local or newer peer row is
preserved and republished from that authority instead of deleted; only
unowned derived aliases are removed. Any `flags != 0` value is impossible in a
dynamic-DNAT v2 map and is reported as typed corruption debt; legacy old-map
bytes are outside this cleanup path and remain untouched. Local
provenance, a newer generation, and any foreign value are preserved and
reported as typed conflicts. Config apply shares the same closed gate and cannot
create a static map owner. Only after all surfaces prove absent may the
allocator release the escrowed tuple and clear the full descriptor; the scalar
`maxObservedGeneration` and key tombstone remain. Cleanup failure replaces the
ambiguous helper generation and keeps admission closed. Before a replacement
helper can admit local allocation, it rebuilds reservations for every surviving
coordinator session and quarantines every still-journaled tuple; external-map
cleanup then releases quarantine exactly once. A fresh authoritative inventory
and requested bulk may proceed only after journal discharge, and only exact
TailAck clears table taint. Ordinary incrementals retain the existing
single-session API but use the same tentative-to-escrow mutation boundary.

Baseline batch completion reacquires the same locks, decrements its token exactly once,
revalidates the window, and only after exact whole-batch success commits the
bounded tentative stale removals/seen stamps, changes incoming keys from pending
to installed, atomically commits every old-to-new ledger rekey, and advances the
checked receive count/digest over the canonical
capable payloads in wire order. A non-complete result commits no speculative
presence/generation result from the helper; it preserves the locally admitted
wire-generation high-water, marks existing ledger rows or disjoint staging/
transition records `ambiguous` according to their preflight representation, and
marks inventory dirty as described above. No apply goroutine is launched.
Because the TCP loop cannot dispatch the next marker while a batch call is
running, it cannot process BulkEnd before every preceding member batch has
completed. Pending keys or a nonzero install count at BulkEnd are internal
invariant failures that invalidate and retire the transport. Config, ownership,
disconnect, and Stop close admission and wait for these finite tokens before
replacing authority. The 180-second maximum-cardinality benchmark is a release
gate; per-member helper RPC fallback must fail that gate.

BulkEnd must repeat the exact BulkStart prefix and its count/digest must equal
the receive window's checked unique successfully installed member set. A
mismatch, duplicate, overflow, or malformed end is a protocol failure. A valid
BulkEnd changes `receiving -> reconciling` under `gate.mu`, detaches membership
and the initialized zone snapshot, creates a SessionSync-owned child context,
and runs reconciliation outside every lock in one joined worker. Extend the
internal cluster-session adapter to
`ReconcileClusterBulk(context.Context, ClusterBulkReconcileInput)`; every
implementation must observe cancellation during iteration and between bounded
delete chunks. `ClusterBulkReconcileInput` carries read-only `ContainsPresentV4/
V6` callbacks over the stable ledger rather than copied full maps; only rows
stamped with the current repair serial are present. The backend iterator must
identify peer-synced origin and refuses to delete a local-origin collision even
inside a remote-owned zone. The shared adapter checks `ctx.Err()` in each iterator callback,
records cancellation after an early stop, and deletes stale rows in fixed
256-entry v4/v6 chunks with a context check between chunks; each userspace
helper request retains its existing RPC deadline. Cancellation returns a typed
error even if the underlying iterator's early-stop return is nil. This replaces
the current unbounded one-call `DeleteBatchKnownV4/V6(stale)` shape. After
backend deletion succeeds, the same worker advances the ledger's stable-slot
cursor in bounded chunks. It removes unseen live rows whose exact deletion
completed and tombstones at or below `retiredGenerationFloor`; it preserves
every wire tombstone above the floor through TailAck or a later proved barrier.
No maximum-size copy or state-locked scan is introduced.
`Stop` cancels and joins this worker before dataplane teardown and may not use
the current five-second abandon path. Disconnect, config apply, and ownership change
also cancel and join before admitting a replacement authority.

Reconciliation returns a typed result and error. Any malformed/refused member,
nested/mismatched marker, cancellation, iterator error, or delete error fails
the window. Earlier valid installed members may remain, but failure publishes no
BulkAck, `bulkEverCompleted`, bulk callback, continuity readiness, previous-good
availability, or debt completion; `bulkMutationTainted` remains set. Successful
completion reacquires `s.mu -> gate.mu` and publishes
no success directly; it may advance to the ACK precommit below only if the
complete window token and registration still match.

ACK completion is a two-stage commit. After successful baseline reconciliation,
the receiver revalidates the complete token, detaches `receiveWindow` into
`pendingReceiveAck`, and installs the exact `tailReceiveWindow` in
`bulkAckWriting` phase with its 180-second absolute tail deadline **before**
writing BulkAck. Ordinary admission,
continuity, previous-good availability, maintenance authorization, and repair
debt remain closed/pending. The BulkAck writer acquires SessionSync `writeMu`,
reacquires `s.mu -> gate.mu` only to revalidate the exact pending token and
authority generation, releases state locks, and writes outside them. Config
send/receive, ownership change, disconnect, and Stop acquire the same write fence
before invalidating either token. If the ACK writer wins, its old-authority ACK
is ordered first; if the invalidator wins, revalidation emits nothing.

The sender may deliver captured tail frames as soon as it receives BulkAck,
before the receiver's write call returns. The bound receive loop therefore
accepts those frames in both exact `bulkAckWriting` and `receiving` phases and
feeds them through marker-delimited, release-only or acquire-only bounded
128-frame batches within the 384-physical-mutation helper capacity. A release phase accepts only Delete frames; an acquire
phase accepts only Open frames. Tail Open/Delete frames retain wire order and
their per-key generations; repeated keys are valid and advance the session-frame
count/digest once per frame, while a stale/reordered generation is an explicit
failure. Tail batches do not alter the detached baseline membership set used for
stale reconciliation. No other connection or message class is admitted. The
first causal tail frame or `TailPhaseEnd` may advance
`bulkAckWriting -> receiving`, and TailEnd may advance onward to
`tailAckWriting`, before the BulkAck syscall completes. Unambiguous BulkAck
write success therefore only marks `bulkAckWriteConfirmed=true` and changes
`bulkAckWriting -> receiving` when that phase has not already advanced; it never
regresses `receiving` or `tailAckWriting` and never restarts the absolute
deadline. TailEnd/TailAck processing requires either that flag or the stronger
causal fact that a valid bound tail session frame or phase marker arrived, but
publishes no readiness from either fact alone. A failed/partial/ambiguous write
retires the transport and leaves table taint/debt even if causally released tail
frames arrived.

When `tailReceiveWindow` is installed it freezes the receiver's advertised
`maxUniqueTailRows`, checked
`maxTailSessionFrames = 2 * maxUniqueTailRows`, checked
`maxTailPhaseMarkers = 2 * maxUniqueTailRows`, and checked
`maxTailWireBytes = maxTailSessionFrames * maxCapableSessionFrameBytes +
maxTailPhaseMarkers * 112` from the immutable capability tuple. Before decoding
either frame class, the receive loop checked-increments its separate class count
and the exact aggregate wire-byte count. A session frame charges a row only on
the first tail-transfer appearance of that canonical key. A checked nonzero
`tailReceiveWindow.serial` compared with the ledger slot's `seenTailSerial`
provides key charging without an unbounded key set; a serial cannot wrap or be
reused. The transfer escrow preallocates exactly `maxUniqueTailRows` member
slots and at most `maxUniqueTailRows` shared-group slots plus generated fixed
member/group indexes within `tailTransferEscrowByteCapacity` (64 MiB), so
release cannot allocate while processing the wire. A checked generated manifest
includes both indexes, typed token unions, records, and alignment; inability to
represent the advertised row ceiling rejects capability setup rather than
shrinking either index at runtime.
Exceeding a row, session-frame, phase-marker, wire-byte, or escrow limit, or any
arithmetic overflow, fails before the next helper/BPF/worker mutation and
retires with taint. The existing generation-ledger slot is not permission for
unlimited same-key churn.

The receiver starts at bank serial one, release phase. On the exact release
`TailPhaseEnd`, it first verifies the marker's serial/phase, canonical-zero pad,
and phase-local session count/digest, then synchronously flushes the final
release-only batch on the same bound receive loop. No later socket bytes are
processed until its helper result, every derived-surface result, Go generation
ledger, and mutation journal commit. A successful Delete removes the old
session surfaces and applies one exact decrement to the window's member-
reservation entry; it does not release an exclusive translated tuple to
ordinary allocation. For exclusive modes the final decrement moves the exact
SNAT/NAT64 member token. For `persistent-shared`, the member entry retains that
flow's exact reverse token and points to one shared-group escrow entry holding
the receiver's lease token, starting/untouched refcount, and every released
session ref without pretending the physical tuple became free. Before the
first decrement for that group, preflight takes `allocator live`, revalidates
the exact lease generation/refcount/member set, checked-increments the live
lease's `tailTransferExpiryFenceCount`, and stores the resulting generation-
stamped `persistentLeaseExpiryFenceHandle` in the group entry. Every
allocation-triggered, pressure, per-address, and background expiry path tests
that count under the same allocator serializer and must defer without removing
the lease, expiry row, reverse members, or physical token while it is nonzero.
The count increment and group-entry publication precede the first refcount
decrement; inability to reserve the entry/fence fails before mutation. Both entries
bind old canonical key, allocator provenance, bank serial, and mutation result.
Before the first decrement, the coordinator's group index and member index must
agree with the allocator's starting live lease refcount, exact reverse-token set,
and local/peer member classes; mismatch is preexisting ambiguity and fails
before the phase mutates.
Local admission and every competing producer remain closed for the complete
window.

Only that successful release-marker commit advances the same bank to acquire
phase. An acquire preflight must atomically consume/retarget an exact matching
exclusive member token, validate and claim a unique reverse member token while
incrementing its exact compatible shared-group lease entry, join an untouched
compatible shared lease, or obtain an ordinary typed free reservation. Multiple
shared acquires update checked group `acquiredRefs` and distinct member rows;
exclusive tokens remain single-consumer. It rejects the translated target when
held by an untouched incompatible peer row, local authority, static DNAT,
foreign allocator identity, a different persistent source/permit group, a
duplicate/colliding member reverse key, or another exclusive acquire in the
bank. Thus the concrete sequence
`Delete(B,T), Open(A,T), Open(B,U)` completes the release of B/T before the
receiver preflights A/T or B/U even when all three operations fit one nominal
128-frame batch within the 384-physical-mutation helper capacity. The acquire `TailPhaseEnd` performs the same synchronous
marker verification and final-batch commit. Only after every old surface is
proved absent may an unconsumed exclusive token be returned to its allocator.
Shared group entries instead prove
`startingRefs - releasedRefs + acquiredRefs == allocatorLiveRefs`; their member
index proves the exact untouched plus acquired reverse-token set. Consumed
exclusive tokens and acquired shared member/group handles become the new
sessions' normal teardown ownership. Only after the acquired/untouched member
set, checked group refcount, and all derived surfaces are committed, or after
origin-aware ambiguity cleanup has established the exact retained truth, does
the group entry checked-decrement its exact expiry-fence handle. A stale,
duplicate, wrong-generation, or underflowing discharge is fatal allocator debt;
config/helper generation retirement joins every fence before old allocator
teardown. If the final count is zero and the lease has no active members, the
normal expiry adapter is scheduled only after that discharge. Any partial,
unknown, timeout, or digest mismatch retains every affected token in ambiguity
escrow, taints the table, cancels the remainder, and prevents the next phase or
bank. A successful acquire marker increments the expected bank serial, returns
to release phase, and resets only the phase-local count/digest.

The sender terminates tail transfer with an exact 96-byte
`syncMsgBulkTailEnd`: the same bulk identity/config prefix followed by
`{tailCount uint64, tailDigest [32]byte}` over every tail frame in wire order.
It is valid only while the receiver expects the next bank's release phase, with
no pending phase batch, no uncommitted phase marker, and no retained transfer
escrow. Its tail count/digest covers session frames only and must equal the
bounded received session-frame count/digest; marker count and aggregate wire
bytes have already been checked independently. Baseline reconciliation already
removed every row absent from the repair serial before BulkAck, so no maximum-
cardinality scan remains.
The receiver changes the tail token to `tailAckWriting`, installs a
record-before-send final ACK token, and provisionally opens ordinary
same-transport admission only; maintenance authorization, current continuity,
and taint remain closed/unchanged. This precommit is safe because a sender can
release ordinary frames only after receiving the TailAck. A request-ID-zero
BulkStart additionally requires a fresh all-current-fabric producer barrier
completed after that TailAck, so it is not admitted by this provisional edge.

The TailAck writer first enters `continuityPublishMu` and reserves one fixed
continuity-outbox slot, waiting/canceling outside every state and write lock. It
then acquires `writeMu` before final-token revalidation and keeps that fence
continuously through the exact 96-byte TailEnd echo, unambiguous write
classification, `s.mu -> gate.mu` postcommit, reserved-outbox commit, and
durable inbound-authorization publication. It holds no state mutex during
socket I/O, but does not release `writeMu` between the write and postcommit. A
stale token or pre-write failure releases the reservation without an edge. Once
bytes are written unambiguously, postcommit performs no allocation or fallible
external operation. Only if the complete final token remains current does it mark the
fully reconciled working capable receiver-generation ledger authoritative,
clear `bulkMutationTainted`, set `bulkEverCompleted`, current/previous-good
continuity, callback, and matching debt completion and commit the already
reserved ordered true edge.

This fence provides the successor-bulk ordering without another receive state.
After the peer consumes TailAck it may start the mandatory barriers, but every
barrier-ACK writer on every currently registered capable fabric also requires
this same `writeMu`. A barrier handler validates and copies its request under
state locks, releases every state lock before waiting for `writeMu`, and then
uses the established write-fence/revalidation order; it never waits for the
fence while holding `s.mu` or `gate.mu`. Those ACKs cannot be written until TailAck postcommit and
outbox commit finish. A maintenance BulkStart is valid only after the
sender has received that complete exact barrier set, so it cannot validly reach
the receiver before postcommit. A BulkStart lacking that completed barrier is a
protocol violation rather than a deferred marker. Config/ownership
invalidation that wins `writeMu` first suppresses TailAck; if TailAck wins, the
invalidation and all barrier ACKs order after its postcommit.

Subsequent
capable ordinary operations validate and update that ledger around their exact
dataplane result; a new-key capacity failure closes admission and requests a
fresh authoritative bulk rather than degrading its generation guard. Failure,
ambiguous write,
disconnect, config apply, or ownership transition clears provisional admission/
authorization, publishes none of those effects, and retires the transport; any
installed baseline/tail prefix remains tainted until repair. All authority-
transition and shutdown join sets include both ACK writers and the tail batch.

Type 29 is exactly 48 bytes:
`{requestID uint64, configGeneration uint64, configDigest [32]byte}` in
little-endian field order. The epoch must exactly equal the requester's current
local committed record and becomes part of the claimed peer-request token. The
responder requires canonical digest equality with its local record and rejects
a generation that conflicts with the known ledger for that same peer process;
it does not require generation equality with its own record. Generation zero or
an all-zero/mismatched digest is malformed on a capable transport. IDs
come from the checked counter for this exact local/remote process pair and
message kind; exhaustion triggers the controlled full-process fail-closed exit
and fresh boot described above, never an in-place identity rotation. A request
attempt captures local helper generation, connection, transport, process, ownership,
authority/config epoch, debt generation, and a `repairStartTimeout` deadline;
record it under the gate in `writing` phase **before** the network write. A
matching BulkStart may atomically bind either writing or awaiting phase, because
the peer can respond before local `Write` returns. “Matching” means exact
request ID, source connection, transport, peer process, ownership, authority,
and debt plus canonical digest equality; the responder generation is validated
in the remote process namespace and is intentionally **not** compared with the
requester's generation. The resulting `bulkReceiveWindow` stores that responder
epoch. Write success changes only an unbound exact token to awaiting; a token
already bound remains bound. Nil
connection, short/ambiguous write, timeout, disconnect, or supersession retires
the transport and leaves debt armed rather than erasing a causally triggered
bulk. The receiver binds only matching start/end markers on the same connection
whose request ID is exact and whose declared epoch is the responder's current
local committed epoch.
Newer debt creates a later unique request. The sender stores the exact source
tuple; a newer unclaimed request supersedes an older one, while a request arriving
after claim waits for the next bulk. Only the matching final TailAck clears the
claim.
Sender state is bounded to one claimed and one newest pending tuple per
transport. The `minimumRequestedResync` monotonic interval and exponential
backoff capped at `maximumRequestBackoff` limit requested full snapshots;
requests inside the interval only replace the single
pending tuple and increment a coalesced counter. They never spawn a goroutine,
allocate an unbounded queue, or reset backoff. Authentication remains the trust
boundary when configured; unkeyed mode gains no claim that an on-link peer is
trusted, so the same bound applies in both modes.

Capable BulkAck is the exact 96-byte BulkEnd tuple and echoes
`{bulkEpoch, requestID, configGeneration, configDigest, memberCount,
memberDigest}` from the accepted BulkEnd. Install one full
`pendingOutboundBulk` before BulkStart, move it to `endingBulk` before the
BulkEnd write, and permit an exact ACK to bind `endingBulk` or
`awaitingBulkACK` because the peer can respond before local `Write` returns.
BulkEnd success changes only an unacked exact token to `awaitingBulkACK`; an
already-acked token moves directly to `flushingTail`.
Require equality, never `>=`, across bulk epoch, request ID, local helper
generation, source connection, transport, process, ownership, authority, the
sender-owned config epoch, member count/digest, and debt. An ACK on the surviving
fabric cannot satisfy a bulk sent on a replaced fabric. Spurious/future/old
ACKs have no effect. Only one outbound token exists. Legacy 8-byte ACK is never
proof for an upgraded sender and cannot clear readiness or repair debt. The
`outboundBulkACKTimeout` starts after BulkEnd and retires the transport/re-arms
the claimed request on expiry; writing `BulkEnd` atomically replaces the
180-second transfer deadline with this 20-second ACK deadline. Exact BulkAck
replaces it with the 180-second absolute capture-tail flush deadline but clears
no claim or completion.

Before writing `syncMsgBulkTailEnd`, move the outbound token to `endingTail` and
record its exact tail count/digest. An exact 96-byte TailAck may bind
`endingTail` or `awaitingTailACK`; TailEnd write success installs a fresh
`outboundTailACKTimeout` (20-second) deadline unless the early exact ACK already
bound. TailAck equality
includes every BulkAck identity plus tail count/digest and source connection.
Only that final ACK moves the token to complete, clears the claimed request and
outbound debt, opens the ordinary writer, and permits callbacks. Wrong, stale,
legacy-length, other-fabric, or post-reconnect TailAck has no effect.

Split the current overloaded readiness signal. `SetSyncReady`/`IsSyncReady`
remain source-compatible but mean **validated session continuity only** and are
set true solely by a successful current capable inbound bulk. Add a separate
`electionTimeoutExpired` availability signal for the existing cold-start timer.

```go
func (m *Manager) SetSyncElectionTimeoutExpired(expired bool)
func (m *Manager) SyncAutomaticElectionSessionAvailable() bool
```

These methods read/write manager state under `m.mu`; the availability method combines the
three explicitly allowed session inputs below and is the only session-readiness
input consumed by the election pipeline. Manager state adds
`syncPreviousGood` and `bulkMutationTainted`, both initially false. The exact
successful capable two-stage bulk/TailAck path sets both `syncReady` and
`syncPreviousGood` true;
clearing current continuity leaves previous-good true until process restart.
No timeout or legacy ACK sets previous-good. Accepting any BulkStart sets taint
before member installation; only exact baseline reconcile, tail reconcile, and
TailAck postcommit clear it. Status reports current continuity, previous-good,
bulk taint, and timeout separately.
SessionSync updates its gate-owned continuity/previous-good fields and increments
a nonzero `continuityEventSeq`, then sends the event to one ordered notifier
worker; bare `go OnBulkSyncReceived()` readiness callbacks are removed. The
notifier payload is
`ContinuityEvent{Seq, Ready, PreviousGood, TransportEpoch, OwnershipGeneration,
Reason}` and one `OnContinuityChanged` callback handles both true and false
edges. Existing bulk callbacks may retain metrics-only work but cannot mutate
readiness or release VRRP holds.
The worker delivers every edge in sequence from a fixed 64-entry outbox and
calls the daemon/Manager synchronously. It does **not** coalesce true/false
edges. All producers enter one `continuityPublishMu` outside state locks, reserve
an outbox slot (waiting on the outbox condition if necessary), then take
`s.mu -> gate.mu`, revalidate their exact transition token, mutate continuity,
and allocate the next sequence. After releasing state locks they commit the
reserved FIFO slot before releasing `continuityPublishMu`; a stale/no-edge
attempt releases its reservation. The notifier alone removes committed slots.
This reservation-before-sequence protocol means producer `N+1` cannot enqueue
before a blocked producer `N`, while queue backpressure still occurs only
outside state locks. Each event has an exact delivery acknowledgement. The
internal Manager callback is bounded and performs no I/O. Last-fabric loss,
config/ownership transition, and Stop
wait for their false event's delivery acknowledgement before proceeding, so a
previous bulk-success callback cannot arrive afterward and reopen readiness.
Delivery and acknowledgement waits hold no SessionSync or Manager mutex; daemon
callbacks may query snapshots without inversion. Stop joins the notifier.
`SetSyncReady` remains source-compatible but is deprecated internally; a source
canary permits production calls only from the ordered continuity adapter.
`SetSyncReady(true)` sets both Manager current and previous-good; false clears
only current continuity.
Manual transfer reads the immediate SessionSync snapshot, and automatic election
reads the ordered Manager mirror; neither synthesizes readiness from the other's
timeout.
The timer never calls `SetSyncReady(true)`, never fires the bulk callback, never
clears repair/baseline state, and never releases manual-transfer or session
continuity holds. Automatic peer-loss takeover may consult the timeout plus
previous-good state under the existing availability doctrine only while
`bulkMutationTainted=false`; it must alarm that current continuity is unproved.
A partial or failed bulk disables that fallback until a fresh complete bulk
repairs the table. Manual failover always requires continuity,
baseline clear, and all repair generations complete.

The timeout bit is scoped to the current cold-start/ownership generation. Last-fabric
loss stops the timer but preserves an already-expired bit long enough for the
same generation's confirmed peer-loss decision; it never converts an unexpired
timer into availability after disconnect. Registration of a new transport,
config-authority transition, or config-sync-mode change clears the bit before
arming any new timer. The
automatic election input is true only when all existing non-session gates pass,
peer loss is confirmed, `bulkMutationTainted=false`, and one of current
continuity, retained previous-good continuity, or this generation's timeout is
true. Fresh boot with neither a successful requested capable two-stage bulk nor
an expired timer remains held. A successful capable two-stage bulk
stops the timer and supplies continuity directly; the timeout bit is not copied
into a later generation.

Extend `TransferReadinessSnapshot` additively with
`SessionContinuityReady`, `SessionPreviousGood`, `SessionBulkTainted`,
`SessionGenerationInventoryDirty`,
`ConfigBaselinePending`, `SessionRepairPending`, `TransportEpoch`,
`RepairDebtGeneration`, and `RepairCompletedGeneration`. Populate one atomic
SessionSync-gate snapshot. `ReadyForManualFailover` requires current continuity
and ignores previous-good/timeout. Reason ordering is continuity, baseline,
receive repair, then outbound repair. The Manager's timeout field is exposed
separately by cluster status, not folded into this manual-transfer snapshot. No
REST, gRPC, helper, BPF, persisted, or event wire schema changes.

`SessionRepairPending` is the conservative OR of refused/reconcile receive
debt, `pendingReceiveAck`, `tailReceiveWindow`, table taint, an in-flight or
awaiting type-29 attempt, dirty generation inventory, a capability-refused prime, sender `forceResync`,
deferred-tail loss, and an outbound bulk awaiting either ACK. Scheduling or
writing BulkEnd/BulkAck/TailEnd clears none of these; only the exact successful
TailAck postcommits advance their matching generation.

Mixed-version authoritative reconciliation is deliberately unavailable. A new
receiver refuses an old sender's bulk without guard reset, stale reconciliation,
ACK, callback, or continuity readiness. A new sender does not send an
authoritative bulk to an old receiver and never treats its legacy 8-byte ACK as
proof; ordinary valid incrementals may continue under legacy ordering. The only
supported rolling order upgrades the standby/receiver first, then the primary/
sender while manual transfer remains blocked. New receiver plus old sender and
new sender plus old receiver both remain continuity-unready; automatic peer-loss
may use only explicit previous-good timeout doctrine. This plan does not claim
hitless manual transfer across a mixed pair.

Workstream I is too large for one activating PR. After its child issue is
approved, implement it as a reviewed stack whose final PR alone changes peer
acceptance:

1. **I-a:** pure RG validators, node-effective gate helpers, runtime-belt
   helpers, tests, and source canaries behind the same disabled activation
   constant; no commit, apply, runtime, or session-wire behavior changes.
2. **I-b:** full-replacement helper staging and concrete clustered inventory
   debt; no session-wire behavior changes.
3. **I-c:** inactive daemon identity/canonicalizer, prepared local/peer config
   transactions, authority initialization, gate/incarnation/worker/replay types,
   capability parser/encoder, credential-bound snapshot-stream schema, budgeted
   worker export cursor, the stable-slot coordinator `SyncedSessionStore`,
   explicit local-authoritative/local-auxiliary and capable/legacy-qualified
   peer authority provenance,
   slot-handle auxiliary indexes, inactive `SessionCapacityPlan` and per-worker
   total-entry ceilings, generated `userspace_sessions_v2`,
   `userspace_dnat_dynamic_v2`, and `userspace_dnat_dynamic_v2_v6`
   no-prealloc schemas plus unified forward-only migration machinery, monotonic per-worker
   delta-loss epochs, fixed non-evictable critical replay/receipt and allocator-
   predecessor arenas, mode-exhaustive predecessor adapters, fixed predecessor
   bind/descriptor/completion helper messages, capable generation-barrier wire
   layouts, ordered mutation-batch and ambiguity-journal types, the fixed
   64-worker intrusive-ready lane scheduler plus barrier/deadline coordinator,
   context-aware
   reconcile adapter, helper-lifecycle lease, map-free XDP/sched-cls quarantine
   program set, kernel-authoritative XDP/TC/TCX inventory, generated historical
   transitive-closure manifests, boot-scoped legacy execution-capsule types,
   durable link-ID-to-netns provenance records, generation-owned active-link
   pin protocol, and generation-qualified
   program/map/link migration-journal types,
   static-projection source/ELF canaries, and observability fields behind a disabled activation
   constant; legacy behavior remains active and the old XDP program/pin remains
   selected.
4. **I-d:** validator/runtime call-site activation, state-mutating helper RPC
   ownership, full heartbeat authority, lifecycle retirement/setup veto,
   producer/barrier protocol, finite replay budgets, synchronous receive
   membership, private streaming export, bounded worker mutation batches,
   protected Close-before-reuse admission, inherited capable descriptors,
   pressure barriers, and two-dimensional predecessor retirement,
   authoritative shared-store inventory, ambiguity-retaining working generation
   ledger plus all-surface cleanup/NAT escrow, side-by-side proved v2
   session-and-dynamic-DNAT map migration, compiler static-DNAT projection
   removal, eligible-hook freeze/inventory, capsule materialization, active-link
   rehoming, scheduler close/join, enforced worker/coordinator/shim/kernel-session and dynamic-DNAT
   physical capacity plus transient-tail reservations,
   dependency-preserving release/acquire tail banks, loss-epoch capture seal,
   write-fence/barrier-ordered maintenance restart, two-stage BulkAck/TailAck capture drain,
   receiver-requested bulk/repair, readiness split, RG actuator wrapper,
   mixed-version restriction, and peer activation. This PR removes the temporary
   constant and carries the full HA smoke matrix.

No rejected-config or session-admission semantic is enabled until I-a through
I-c are merged and I-d passes the complete production-path suite. Each stacked PR
must be independently buildable and revertible; an intermediate deployment
continues the old session/config-acceptance behavior rather than half-enforcing
the new protocol. I-b may independently activate its fail-closed helper-debt
hardening because it does not depend on a peer wire capability.

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
CLIs, filters, and binary cannot diverge. Workstream L does not reinterpret the
Rust event action byte or change the lifecycle payload's intentional producer
zero. Workstream I-d independently versions the private helper event envelope to
carry source snapshot generation; that transport-only prefix is not an action
field and is updated atomically in the Rust encoder and Go decoder.

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
| 2b | F (LoadOverride), H (route-map count), I-a (inactive RG validation/runtime helpers) | Mostly independent, but H/I-a consume config APIs and must rebase after 2a |
| 2c | I-b (helper debt), then I-c (inactive protocol scaffolding), then I-d (activation) | One reviewed stack, merged serially; I-d alone changes peer/session behavior and carries the HA smoke gate |
| 3 | K (routing ownership), L (lifecycle action) | Independent correctness/observability work with lower immediate blast radius |

K003-02 remains with #6548. K003-05 gets a child issue linked to #4313 but does
not claim vSRX parity. K003-12 and K003-C create no child issue.

## 6. Public API preservation

The implementation plan preserves these signatures and wire contracts:

- `(*configstore.Store).LoadOverride(string) error`
- `(*configstore.Store).LoadOverrideAs(string, string) error`
- existing CLI, REST, and gRPC load request/response shapes;
- one additive root-only offline recovery command,
  `xpfd recover-userspace-shim --migration-id <hex> --resume-forward`, with no
  rollback, object-path, or program-ID argument;
- DDNS `Updater`, manager constructor, and reconcile entry points;
- daemon direct-VIP and apply entry points;
- SNMP configuration field names and SNMPv3 wire protocol;
- route manager public methods and netlink operation interfaces;
- Rust event action byte and lifecycle payload semantics (I-d intentionally
  co-versions the private helper envelope with source generation, fixed
  pre-mutation `before` projection, optional unresolved predecessor-release
  handle on successor Open/Update, phase-1/phase-2 worker boundary frames, and the in-band
  capture-seal frame; the protected replay slot/receipt is process-local and not
  encoded on the cluster wire);
- binary RT_FLOW/security event record length and field offsets (the separately
  versioned private session-sync envelope/control frames change as stated);
- capable cluster session Open/Delete payloads include the generated fixed
  `memberReservationIdentity` and optional `sharedLeaseGroupIdentity`.
  The former owns the exact per-flow translated/reverse token; the latter owns
  allocator-config, lease target, and complete persistent source/permit scope
  without conflating a member's remote reverse key. Legacy payloads are byte-
  unchanged; the complete-bulk
  capability gates the descriptor, generated Go/Rust goldens and
  `maxCapableSessionFrameBytes` include it, and decode recomputes the canonical
  identity from the bound config rather than trusting arbitrary sender bytes.
  Every capable Open/Update whose allocator token retains predecessor debt
  carries the exact 88-byte canonical-zero-or-populated
  `tuplePredecessorDescriptor` after both fabrics negotiate
  `tuple-predecessor-v1`; it binds cross-key tuple reuse to the predecessor
  Delete's canonical key, generation, and member-identity digest. Legacy
  payloads and capable mutations with no predecessor retain zero semantics;
- migration/userspace code performs no lookup/update/delete on an old authority
  map. A historical packet invocation may still mutate its isolated old object,
  so one boot-scoped capsule pins the complete legacy program/program-array/map
  closure and no current accessor can open it. Workstream I intentionally adds the
  versioned `userspace_sessions_v2`, `userspace_dnat_dynamic_v2`, and
  `userspace_dnat_dynamic_v2_v6` pins and performs one fail-closed forward-only
  side-by-side migration rather than resizing, filtering, or deleting an old
  map under a live program (the
  private helper protocol also gains the generation-bearing before/after event
  envelope, both worker boundaries, in-band capture seal, credential-bound
  owner-snapshot stream, and fixed predecessor bind/descriptor/completion
  batches);
- legacy `dnat_table{,_v6}` retain their pinned ABI inside the isolated capsule
  for the current boot; late historical packet writes are permitted there but
  cannot become current authority. The current shim uses the new discriminator-free dynamic-only
  v2 maps; compiler-owned `flags=1` rows are never copied, deleted, or
  reintroduced. This changes no public API;
- the HA wire protocol gains seven additive message types:
  epoch-bearing `syncMsgBulkRequest`, versioned `syncMsgCapabilities`, and
  `syncMsgBulkTailPhaseEnd`/`syncMsgBulkTailEnd`/`syncMsgBulkTailAck`, plus
  `syncMsgGenerationBarrier`/`syncMsgGenerationBarrierAck`.
  The capability payload is exactly 50 bytes and includes process identity,
  local-creation capacity, receiver-baseline capacity, and tail capacity;
  mismatched fields across fabrics or failure of the combined cluster-authority
  ceiling to fit either receiver prevents capable bulk authority.
  Fully capable peers also use a capability-gated config trailer carrying the
  sender-owned generation plus canonical SHA-256 digest; mixed/legacy peers are
  sent only the existing config payload, so an old decoder never sees the new
  trailer. Type 29 is 48 bytes and carries request ID plus the requester's local
  sender epoch. Capable BulkStart is exactly 56 bytes: its original 8-byte bulk-
  epoch prefix plus a 48-byte
  `{requestID, senderConfigGeneration, senderConfigDigest}` tail. Capable
  BulkEnd and BulkAck are exactly 96 bytes: the same 56-byte prefix plus
  `{memberCount uint64, memberDigest [32]byte}`. `TailPhaseEnd` is exactly 112
  bytes: the 56-byte capable identity/config prefix followed by
  `{bankSerial uint64, phase uint8, pad [7]byte, phaseCount uint64,
  phaseDigest [32]byte}`. TailEnd and TailAck use the same 96-byte shape with
  the final fields interpreted as session-frame tail count/digest.
  Generation barrier and ACK use the exact echoed 128-byte capable-only shape
  defined above; legacy type-13/14 barriers remain exact eight-byte messages and
  cannot advance a capable generation floor or allocator predecessor.
  Legacy peers retain
  their existing 8-byte ACK on the wire, but upgraded code never treats it as
  proof of authoritative reconciliation. Legacy prepare-activation remains the
  exact one-byte RG ID; capable peers use the exact nine-byte RG ID plus nonzero
  little-endian request ID, gated by the negotiated capability. Fully capable
  failover ACKs may additionally use status value 4 as retryable busy only when
  both peers negotiated `bounded-replay-v1`; legacy peers never receive or
  interpret it;
- `CurrentHAProtocolVersion`/`SessionSyncWireVersion` do not bump for these
  additive, old-reader-ignorable message types/tails and because the changed
  config encoding is emitted only after both fabrics negotiate
  `config-epoch-digest-v1`. The negotiated capability bits, not the coarse
  heartbeat version, gate every new semantic;
  mixed peers continue ordinary incrementals but remain continuity/manual-
  transfer unready. A future incompatible base-header or existing-message
  reinterpretation still requires the normal version bump;
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
Workstream I additively extends the exported Go `TransferReadinessSnapshot` and
  internal status text with baseline/repair diagnostics. Existing fields and
methods remain source-compatible. `SetSyncReady`/`IsSyncReady` narrow their
internal meaning to validated session continuity while a separate timeout
availability bit preserves the explicit automatic-election doctrine. The
internal cluster-session adapter gains the bounded context-aware ordered
`ApplyClusterSyncBatch` operation, `ForEachClusterSynced`, plus
`context.Context` reconciliation; every repository implementation migrates in
I-c. The userspace private protocol adds
the exact 384-physical-operation `sync_session_batch` operation with explicit complete/
partial outcomes; ordinary single-session sync remains source-compatible.
Internal config callbacks return a
  typed authority/restart outcome, and `cluster.Manager` gains an immutable
  full-RG committed-authority snapshot/accessor; all repository consumers migrate in the
  same inactive-to-active stack. The internal `ClusterEvent` gains an authority
  serial; no REST, gRPC, helper, BPF, external event, or persisted schema is
  changed. Existing authentication frame types remain
unchanged; capability is the first **post-authentication** frame and auth
  HELLO/PROOF are expressly exempt from that ordering rule.
  Internal configstore APIs gain one-shot prepared peer promotion and prepared
  confirmed-rollback preview/promotion. Daemon local config paths gain the
  unexported Begin/Abort/Complete transition lease. Public management request and
  response schemas remain unchanged. The helper manager also gains an internal
  generation-bearing lifecycle observer and persistent event-callback
  registration; `localHelperGeneration` is never serialized, and helper restart
  instead retires the existing sync transport before fresh capable repair.

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
- helper-process replacement clears validated continuity and explicitly reports
  any unavoidable local session reset instead of preserving stale readiness;
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
   unchanged slots survive the helper's one full-replacement transitional
   payload. Manager-owned clustered debt contains the complete desired
   generation, owner map, helper payload, and required/confirmed fenced-slot
   sets; the status loop is its sole retry consumer. Every direct actuator,
   watchdog, status, shutdown, and helper writer linearizes through the same
   inventory transaction before any map write. Every status-bearing helper
   response has an exact process/snapshot/inventory/debt/helper-mutation lease
   and cannot apply positive control after debt starts or any mutating helper
   write begins. State-mutating helper requests retain transaction ownership
   through the actual RPC; stale response rejection is never treated as
   rollback, and ambiguous lifecycle requests force helper-process replacement.
   Authority-neutral side effects are admitted only through a finite exact
   process/snapshot registry; config, snapshot, and helper lifecycle transitions
   close and join that registry before mutation. An ambiguous side effect forces
   helper replacement and its operation-specific repair/unknown-result contract,
   so releasing the inventory transaction during its I/O cannot mutate a newer
   helper generation.
   While debt exists, no path may
   source old `m.haGroups`, positively rearm watchdog/active state, or publish
   forwarding ready. An uncertain clear disarms the helper rather than replaying
   stale pins or an older full map. Peer config preparation produces the exact
   tree/compiled pair before debt, then promotion follows
   `applySem -> haInventoryTxnMu -> Manager.mu`, so an older helper RPC
   completes and matching debt exists before a newer active candidate publishes.
8. **HA ordering:** an invalid live sync leaves active config, compiled config,
   helper maps, forwarding arm state, and applied-generation high-water
   unchanged. Fresh boot remains lifeline/default-deny. A mixed-version RG16+
   binding loudly blocks manual transfer while automatic peer-loss takeover may
   use previous-good with a stale alarm. Legal unbound RG16..255 remains
   accepted. In the explicitly protected config-authority-to-receiver
   direction, initialized authority and the shared install/apply gate admit
   sessions only outside apply, after a current-transport baseline, and at the
   exact accepted epoch of that remote sender/process before
   incarnation-qualified ordering. A
   one-fabric replacement cannot discard an already-admitted successful config
   callback, while last-fabric loss drains it before a new baseline is exposed.
   Every local-RG state/priority/weight/definition publication first marks one full ownership
   snapshot serial transitioning through the sole local-state mutation API; all
   direct writers, raw authority reads, zone-owner builders, and pre-publish
   positive actuators are canaried. Event and safety-net actuation use prepare,
   gate-stage, and final manager-publish; only final publish exposes the full
   ownership map. A callback-triggered manager transition
   may adopt the callback's successful peer epoch and independently allocated
   local record against its predecessor lease but cannot reopen authority.
   Heartbeat serializes only the complete committed state/priority/weight row.
   Config identity is sender-owned generation/digest plus daemon process
   identity; only canonical digest equality is cross-peer. Immutable sender and
   failed-receiver records distinguish replay,
   reapply, supersession, and corruption. Transport restart reads only the
   fully-applied committed-runtime ledger and swaps complete joined
   `clusterCommsEpoch` registries outside SessionSync. The daemon process identity
   and committed record survive that in-process restart. Setup/data/lifetime worker
   registries and the coordinator handle are separately closable, so no setup completion or self-join
   crosses an epoch. Every non-config protocol callback is registered with an
   exact scope/context/process lease and no old-process ACK can migrate to a
   replacement connection. Capable cold sync is receiver-requested after baseline;
   sender producers remain closed until the exact full outbound token TailAck.
   BulkStart resets no ordering or config authority. Only a capable
   same-connection window with joined successful reconciliation and validated
   tail can finally ACK, mark
   continuity ready, or discharge a uniquely correlated repair attempt. The
   serialized reserved continuity outbox preserves every true/false edge.
   Timeout availability is a separate automatic-election signal and never
   proves continuity or manual readiness.
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
12. **Wire and pinned-state portability:** no public event ABI or in-place BPF
    map resize/deletion is introduced. The additive versioned
    `userspace_sessions_v2`, `userspace_dnat_dynamic_v2`, and
    `userspace_dnat_dynamic_v2_v6` maps move together with the v2 program in one
    proved forward-only local cutover. Every current accessor ignores the old
    maps; a boot-scoped legacy capsule retains the complete historical
    fixed-point program/map graph after all XDP hooks select v2 and every owned
    legacy TC/TCX reader is detached. An old invocation may mutate only those
    isolated objects and can still execute every historical tail call. Active
    BPF links have generation-owned pins before their legacy aliases disappear.
    The private
    co-versioned Rust/Go helper
    protocol adds source generation, the export-boundary message, a
    credential-bound fixed-record snapshot stream, and fixed predecessor wire-
    bind/remote-order completion batches; startup
    rejects a helper with the old protocol before session authority opens. The
    cluster HA additions are an
    ignorable epoch-bearing resync message, a versioned capability advertisement,
    a capability-gated sender generation/digest trailer, and a length-gated
    request-ID plus sender-epoch tail on repair bulk markers and their capable
    ACK, exact generation-bearing all-fabric barrier/ACK fields, plus capability-
    only `failoverAckBusy` status value 4 under
    `bounded-replay-v1`. Legacy peers never receive or interpret that status.
    Authentication
    frames precede capability and are exempt from its
    first-post-auth ordering rule. Older peers keep parsing the original epoch
    prefix and ordinary traffic, but authoritative mixed-version bulk is not
    supported in either direction: a new receiver refuses an old sender's bulk,
    and a new sender neither sends one to an old receiver nor trusts its 8-byte
    ACK. Standby/receiver-first is the only supported rolling order, with manual
    transfer blocked until both nodes are capable.
13. **Allocation and hot-path shape:** K003-01 uses existing parsed metadata.
    Static-DNAT projection removal adds no packet-path allocation or lock. The
    v2 shim uses discriminator-free dynamic maps; static, dynamic, and miss
    fixtures are proved to reach the intended byte-identical redirect path.
    Migration population uses fixed-credit coordinator iterators and bounded
    readback state. All tuple escrow and the single
    24,576-record mutation-lane arena are startup-reserved; ledger rows keep only
    checked handles/counts rather than per-row waiter arrays.
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
19. **Canonical config identity is round-trip stable:** one pure canonicalizer
    strips annotation, inheritance, source-position, and display metadata before
    rendering exact wire text. Its digest proves only equality in that declared
    domain and is byte-stable across send, parse, persistence, and restart.
20. **Pressure and time are finite:** protocol callbacks have 64 in-flight
    slots; failover replay has one contiguous-floor 1,024-slot sparse window,
    64 nonterminal transfers, and 1,024 floor-covered completed results per
    local/remote process pair with request/commit phase results;
    duplicate waiters are capped at eight; helper side effects have 64
    process/snapshot-bound slots; snapshot worker channels hold 1,024 fixed
    records each; every worker also has 1,024 fixed tuple-release-fence slots;
    the non-evictable EventStream replay has exactly 1,024 dedicated Close slots
    per worker, two boundary slots per worker, one seal slot, and 8,192 general
    critical slots under a checked 256-MiB byte ceiling; its ordered reference
    ring reserves 8,192 entries each for critical and telemetry classes so
    telemetry cannot starve correctness traffic; allocator predecessor
    storage has exactly 1,024 records per worker plus at most one fixed
    persistent shell per record under a generated 64-MiB byte ceiling;
    receive/import batches hold 128 peer frames and at most 384 explicit
    physical mutations including stale eviction, with 64 journal/transfer-
    escrow slots sharing one generated 256-MiB ceiling; and the two capture-
    tail banks share one fixed 256-MiB checked credit pool while receive-side
    typed member/group reservation and refcount escrow has its own generated
    64-MiB checked pool.
    The same 24,576 mutation-lane records are tagged owner/waiter/dependency
    variants; `ordinaryTupleDependencyCapacity` is an alias of that arena, not a
    second allocation. At most eight variants index one translated target.
    One receive-window-owned persistent-group eviction plan serializes groups;
    each prerequisite request uses and then recycles one ordinary journal slot
    with at most 128 physical Deletes, while the final request independently
    retains the 384-operation bound. Only the group token, expiry fence, and
    checked cursor span prerequisite chunks, so memory does not scale with group
    membership.
    Cross-fabric request arrival may be out of order inside the window, but
    unseen IDs beyond its right edge are rejected without allocation and senders
    retry every allocated request/commit phase with the same body. In-flight
    callback phases and nonterminal transfer entries are never evicted;
    above-floor sparse slots cannot be reclaimed around a gap, and a full
    nonterminal ledger or unavailable exact window slot returns busy without
    mutation. Only floor-covered completed-cache entries are evictable. Every network,
    helper, consumer, and callback class has the explicit deadline or cancellable context
    defined above, including the 120/125-second Rust/Go full-export pair and the
    180-second absolute authoritative-bulk send/receive window and separate
    post-ACK 180-second two-bank tail-drain window. Per-key mutation ownership
    admits at most eight accepted higher-generation waiters from one global
    24,576-record/64-MiB fixed arena; allocator-generation
    retirement has one slot and a non-renewable 20-second deadline. Authority-
    provenance fanout has one 180-second absolute deadline. The unified
    session/dynamic-DNAT v2 migration has one journaled same-boot non-renewable
    180-second `CLOCK_BOOTTIME` deadline plus a 20-second emergency-quarantine
    deadline, fixed-credit coordinator iterators, exact map-membership/count
    readback receipts, a
    bounded eligible-hook inventory, and one fsynced `prepared`/`forwardOnly`/
    `recoveryQuarantine`/`committed` journal. Structural writers remain joined while hooks span
    generations. Timeout, identity drift, or corrupt journal state retains
    explicit migration debt and fail-closed admission/readiness; only the
    root-only exact-ID offline forward-resume command may install a new deadline.
    It never performs a userspace mutation on an old map or rolls a changed
    hook backward.
21. **Transport retirement wins setup:** both-fabric retirement sets a
    promotion veto under the registry lock before the coordinator wake. An
    already-admitted setup cannot install a replacement and prevent whole-
    transport drain. Single-fabric retirement closes/replaces only that fabric's
    generation-stamped setup lane and lost-incarnation handles; it never closes
    the surviving transport data registry. A second retirement racing that drain
    suppresses lane reopen and escalates to whole transport. The dedicated
    lifecycle coordinator is outside every worker registry and is joined last by
    external Stop.
22. **Config promotion is prepared and authority-transactional:** peer sync
    uses an opaque store-owned sealed tree/compiled/canonical/authority object,
    reserves any new local sender record, and promotes it after debt. All local
    plain, event-engine, confirmed, and automatic-rollback active mutations use
    the same opaque store preparation, reserve before mutation and Begin before
    promotion, then Abort/Complete exactly once. Store mutation generation is
    checked and advances through one exhaustive publication helper. Abort compensates every staged fence/helper/
    gate effect back to the captured prior authority before retry; a failed
    compensation remains explicit debt. Compiler-owned static DNAT is absent
    from BPF maps; the exact prepared runtime token publishes the Rust static-NAT
    snapshot and `committedRuntimeConfig` under `configRuntimePublishMu` with no
    independent static-map phase. Failure before that linearization retains the
    old runtime; failure after it is ordinary forward apply debt. Candidate
    rollback and explicit
    confirm are non-active operations. Post-promotion failure records the exact
    source/store/canonical/reserved-record/ownership receipt for recovery.
23. **Identity exhaustion never wraps:** every ABA-sensitive counter is checked.
    Ordinary allocation stops at `MaxUint64-1`, preserving one terminal
    continuity-sequence slot. Exhaustion performs a controlled fail-closed daemon
    exit; a supervisor restart creates a new process identity and boot generation
    1. No in-process process-ID rotation or record rebinding exists.
24. **A helper process is a session-state incarnation:** configuration replay
    does not restore the Rust coordinator's in-memory session maps. Every helper
    replacement publishes a false continuity edge before teardown, joins all
    old-generation installs and event callbacks, advances one checked local
    helper generation, retires the session transport, and requires fresh
    bilateral authoritative repair. Planned owner replacement transfers first;
    forced replacement explicitly alarms session loss. No prior bulk/readiness
    history can authenticate an empty replacement helper.
25. **Urgent negative authority preempts long helper work:** every authority
    mutator exposes one independently preemptible external-step lease. Demotion,
    disarm, lifecycle, and health failure close/cancel that lease without
    waiting for `haInventoryTxnMu`, order the final negative fence after any
    admitted old positive step, and make late compensation/status/publication
    impossible. Admission reopens only for the exact latest urgent serial after
    replacement, ambiguity repair, and session repair; terminal shutdown never
    reopens it. A lost mutating response is explicit replacement debt.
26. **Helper session effects retain their source:** control results and private
    EventStream frames carry helper process/snapshot plus config/ownership
    authority through final consumption. Capable bulk consumes one authenticated
    bounded owner-session stream, one sequenced boundary from every exact worker,
    and their terminal event watermark; sampling a global sequence counter is
    not a worker-drain proof. The helper source and peer-wire count/digests are
    independent end-to-end proofs. Monotonic per-worker loss epochs, not a
    consumable Boolean latch, prove both scan and tail capture lossless. A
    translated tuple remains source-reserved until its Close has a global
    EventStream enqueue receipt backed by a non-evictable, count/byte-bounded
    frame slot through cumulative ACK or terminal generation retirement. Every
    allocator mode pre-reserves a stable predecessor record before Close enqueue,
    binds ACK to it before ring visibility, and indexes it before free/refcount
    visibility; any later allocator token/Open moves or takes a checked shared-
    lease handle carrying that sequence, so cross-worker reuse cannot overtake
    release. Persistent expiry first transfers the removable lease entry into
    its arena-owned shell/deferred-free state under the same lock order; no GC
    path can erase the list anchor or clear occupancy first. Its
    bounded per-key tail coalescer retains first-before tuple dependencies and
    emits each bank as all required peer-owned releases followed by final
    acquisitions, separated by exact count/digest phase markers. The receiver
    synchronously commits each release phase into bounded typed member/group
    reservation escrow before preflighting acquisitions. Exclusive targets
    remain single-consumer while compatible persistent/shared leases preserve
    both exact untouched/released/acquired group refcounts and each member's
    distinct reverse token, including idempotent deletes with no materialized
    baseline set. A partial receive table is tainted and
    unavailable for takeover.
    Asynchronous `export_all_sessions` and shared delta buffers are never
    authoritative members.
27. **Failover replay cannot self-join or forget a gap:** ownership mutation
    handles finish before gate staging, while receipt waiters run only after
    final publication and are excluded from that serial's pre-publish join. The
    authority coordinator records terminal replay state independently of whether
    any waiter survives.
    Above-floor sparse replay slots are not evictable; nonterminal transfers and
    floor-covered completed results have separate finite stores.
28. **The coordinator store, not a worker replica, is receive authority:** the
    Rust shared synced-session store is one stable-slot/index representation
    whose checked peer-inventory serial makes a bounded inventory either exact or
    aborted. Worker tables and BPF maps are derived surfaces. Every attempted
    non-complete batch key remains represented exactly: existing keys in their
    ledger slots, disjoint replacements in fixed ambiguous staging/transition
    records while the main index retains the incumbent. A fixed 64-slot registry, one 384-record slot
    per admitted batch, retains exact before/attempted derived descriptors and
    both incumbent/attempted tuple escrow needed to clean aliases,
    kernel/BPF/worker rows, and dynamic DNAT safely. Re-inventory may
    merge authoritative rows but cannot erase that journal; cleanup completes
    before another batch and releases tuple quarantine only after every surface
    proves absent. Neither a missing worker row nor a successful prefix response
    is proof of absence.
29. **Capability capacity names real receiving surfaces:** the receiver reserves
    worker/auxiliary creation sublimits inside one shared local-plus-peer
    authority reserve, then adds transient-tail logical credit. Each
    logical credit costs two rows in the coordinator store and every fully
    replicated worker, up to four distinct keys in the one AF-agnostic userspace
    shim map, two rows in each independently populated kernel
    `sessions`/`sessions_v6` map, and one dynamic row in either DNAT family;
    configured static DNAT lives only in the Rust snapshot and consumes no map
    row. The ledger reserves peer
    baseline plus tail rows. The current 262,144-entry pin and uncapped sync
    upsert are not treated as capacity. Activation requires the versioned
    no-prealloc v2 map, per-worker total caps, slot-handle shared indexes, and a
    checked `SessionCapacityPlan`; the formerly uncapped local-tunnel upsert
    cannot borrow peer credit. Capability advertises each node's local-creation
    ceiling separately; both nodes prove their checked combined cluster
    authority fits each baseline reserve. TailAck additionally proves final
    peer presence returned below that reserve. Count reservation never excuses a
    conflicting SNAT/NAT64 translated tuple: allocator reservations are typed,
    tentative only before external mutation, and escrowed across any ambiguous
    prefix. The tuple is immutable only
    within one transport epoch. A capacity change retires and renegotiates both
    fabrics; shrinking below any authoritative or derived-surface occupancy
    fails the prepared apply before mutation rather than truncating state or
    silently preserving an over-cap table.
30. **Shim migration terminates locally:** one journal covers the v2 program,
    `userspace_sessions_v2`, and both dynamic-DNAT v2 maps. Before
    `forwardOnly`, no hook has changed and v2 may be rebuilt from the stable
    coordinator. At or after `forwardOnly`, every same-process recovery resumes
    toward the recorded target. A new process encountering any prior-process
    exactly owned hook, including no-journal legacy, `prepared`, or `committed`,
    first advances every such hook to
    the generated map-free typed drop quarantine, builds a fresh inactive v2
    successor from its new coordinator, and then advances every XDP hook to that
    successor while detaching every owned legacy TC/TCX hook. No hook rolls back
    and no recovery/userspace path inspects, repairs, flushes, or mutates an
    old/previous-target map.
    Once all XDP hooks select the final v2 generation and all owned legacy TC/TCX
    readers are absent and each v2 XDP program's complete live map-ID set equals
    the generated authority/infrastructure classification,
    frozen v2/coordinator readback passes,
    helper accessors switch atomically, and `committed` is durable, structural
    writers resume only on v2. Duplicate fixed aliases are removed only after
    exact replacement roots exist; the complete legacy execution capsule remains
    pinned for the boot without map operations. A different kernel boot ID permits fresh start only when no xpf
    BPF/helper/AF_XDP object survives; otherwise it is debt. Peer repair neither
    gates this local retirement nor authorizes rollback. A restarted empty
    coordinator intentionally produces empty v2 maps and continuity false
    instead of trusting old caches.
31. **Authority provenance is explicit:** packet/install `SessionOrigin` never
    substitutes for local-authoritative, local-auxiliary, capable-process, or
    ephemeral legacy-transport authority. Local tunnel rows may use sync-family
    mechanics but cannot enter peer inventory, export, deletion, or capacity
    classes. Promotion retains its source namespace and handoff serial and
    selects one deterministic canonical owner worker; replicas cannot multiply
    the exported baseline. Demotion moves from `Active` to exact target/serial-
    bound `HandoffExportable`, which is excluded from ordinary export but
    included exactly once in that handoff. It becomes peer authority only after
    exact capable TailAck and ownership commit; failure quarantines it rather
    than making it invisible to the only valid handoff stream. Every provenance
    change stages coordinator and worker replicas under one generation/serial,
    requires all exact worker stage/commit ACKs, and advances the coordinator
    commit point before reopening export; partial fanout is explicit debt with
    export cardinality zero.
32. **ACK postcommit precedes every successor bulk:** the TailAck writer reserves
    continuity-outbox credit before taking `writeMu`, then retains the fence
    through final write classification, gate postcommit, and outbox commit.
    Every required all-fabric barrier ACK uses
    the same fence, and maintenance BulkStart requires that complete barrier
    set. A valid successor therefore cannot exist before predecessor postcommit;
    an unbarriered start is rejected rather than deferred.
33. **Same-key mutation has one owner across fabrics:** generation admission is
    not mutation permission. One stable ledger slot CAS-owns the exact operation
    from preflight through Rust/helper and final Go/derived-surface commit; at
    most eight higher generations wait in its fixed FIFO without mutating or
    snapshotting an uncommitted predecessor. Partial/ambiguous completion keeps
    ownership and tuple escrow, cancels unstarted successors into repair, and
    admits no next owner until cleanup proves the actual incumbent.
34. **Generation compaction is barrier-qualified:** only an exact current-
    fabric generation barrier may advance `retiredGenerationFloor`. Every
    peer-wire lane allocates a barrier-visible token at admission and retains it
    through waiter/dependency/owner promotion until final commit; ACK waits for
    all tokens through G, not merely the owner set observed at marker arrival. Internal
    baseline evictions covered by that floor remove their slot; real wire
    tombstones above it remain through TailAck and until a later covering
    barrier. Baseline wire rows stage in the fixed per-batch journal and an
    old-to-new transition overlays one stale committed slot until its exact
    outcome; partial repair retains both identities there. Capacity is exactly
    baseline N plus tail reserve R, not an inferred 2N map, not 128 speculative
    ledger rows, and not permission to erase above-floor replay evidence.
35. **Cross-fabric tuple reuse carries receiver proof:** every capable
    Open/Update for a session that consumes another key's released tuple carries
    the exact predecessor key, generation, family, and member-identity digest
    until a covering barrier. It cannot mutate until the
    receiver proves the matching peer Delete/tombstone or a covering scalar
    floor plus allocator absence. Dependency records are tagged mutation-lane
    variants with eight-per-target and 24,576-global bounds; missing or
    ambiguous proof requests repair. A second physical reuse before that barrier
    is withheld behind the fixed per-target predecessor chain rather than
    emitting an unbounded descriptor chain.
36. **Every release participates in replacement escrow:** same-key release arms,
    stale evictions, and prerequisite group-member Deletes all publish their
    exact token to the bounded overlay before an acquire can consume it. An
    incompatible large shared group is removed by one serial receive-window
    plan in at-most-128-Delete chunks; only its group token, expiry fence, and
    cursor survive between chunks. Current-batch members are deleted and the
    completed group is atomically parked in bounded final escrow before the plan
    slot is reused, so multi-group cycles cannot deadlock. No group size can
    overflow the final 384-operation request or allocate per-member persistent
    state.
37. **Configured static DNAT has one authority:** the Rust immutable snapshot is
    the only configured static-NAT publication. The v2 BPF DNAT maps contain
    only coordinator-derived dynamic reverse-NAT rows and have no static flag.
    Legacy DNAT maps remain isolated retirement objects: old invocations may
    continue reading or mutating them after hook replacement, while no v2
    accessor or recovery path can consult them. The boot-scoped capsule retains
    their exact objects and transitive historical program closure. The
    unified journal and exact identities fail closed on ambiguity; no cleanup
    scan, delete, repair, or userspace execution-grace assumption exists.
38. **Allocator predecessor retirement proves both sides:** local cumulative
    EventStream ACK or an exact joined-generation terminal local receipt proves
    only local replay completion. A predecessor record, tuple-index obligation,
    or persistent shell may retire only after that local proof and an independent
    exact remote-order proof: covering frozen all-fabric generation receipt,
    current legacy same-writer ordering, administratively no-session-sync
    classification, or terminal repair. Emitting, writing, or receiving a
    capable predecessor descriptor is never a remote-order proof; it only keeps
    the successor blocked/annotated until one of those proofs exists.
    Zero/unbound wire generations and partial or stale barrier sets never satisfy
    remote order; pressure closes admission instead of recycling evidence.

## 8. Risk assessment

| Risk class | Rating | Why | Required mitigation |
|---|---|---|---|
| Behavioral regression | HIGH | Thirteen independent roots include security policy acceptance, SNMP auth, DDNS deletion, HA activation, and config loading | Separate PRs; fail-on-revert traces; strict/lenient paired tests; package-wide reruns after each config merge |
| Lifetime / borrow-checker | MEDIUM | K003-01 copies an existing parsed byte, while I-d also makes Rust-helper/event-stream process lifetime explicit and must not retain old process-owned session or callback state | Rust unit tests, clippy/build, generation-bound close/join tests, and packet/helper-restart smoke |
| Concurrency / lock ordering | HIGH | K003-16 repairs a map race, while I-d adds transport drain, all-RG producer fencing, preemptible state-mutating helper transactions, finite split protocol callbacks/replay, ordered notifications, post-commit restart, helper-session lifecycle, and joined reconciliation across two fabric loops | Enumerated lock graph including independent mutation/preemption lane, outer helper lifecycle, write fence, and continuity publisher; separate coordinator/setup/data/lifetime/event-stream ownership; setup-promotion veto; gate-owned synchronous receive state; no cross-domain or state-locked I/O/waits; self-join, stale-ACK, stale-helper-generation, urgent-mutator, raw-heartbeat-window, stale-helper-request, old-process-callback, saturation, direct-actuator, and callback-transaction race tests; inactive scaffolding review before activation |
| Performance regression | MEDIUM | K003-01 copies one existing byte on a rare flowless path; I-c adds the inactive stable-slot/index store; I-d activates it, removes compiler static-DNAT writes, and adds loss/provenance words to private control state, two boundaries per worker/export, a 1,024-slot per-worker tuple-release fence on teardown, a checked/preallocated non-evictable replay arena (256-MiB ceiling), a fixed allocator predecessor arena (64-MiB ceiling), a budgeted cold-path full-session scan, bounded ref-counted mutation batches, and a two-bank fixed-credit dependency-preserving coalescer during repair | No packet-path allocation or global predecessor lock; flow allocation retains the existing bitmap claim and adds only an atomic per-shard zero-count check in the common no-predecessor case, with one bounded sharded hash lookup only while that shard has unresolved releases; prove GRE static-hit/dynamic-hit/miss redirect byte equivalence and benchmark fixed-credit three-map v2 population/cutover plus allocator common/reuse paths; shared-store lookup/mutation p99 and max-RSS, including protected replay, predecessor, and tail escrow arenas, must stay within the explicit gate; worker export/import and release-fence draining are time-sliced away from packet processing; fixed stream/inbox/tail byte bounds, allocator-retention pressure, high-churn release/acquire coalescing and export/import/poll-tail latency benchmarks; userspace throughput baseline and K003-01 perf smoke |
| Stateful shim migration | HIGH | The current preallocated 262,144-entry `userspace_sessions` pin cannot satisfy the proved local+peer+tail alias bound, old session/DNAT maps are not authoritative coordinator state, already-running historical XDP/TC/CPUMAP code may mutate them and tail-call after link replacement, program-bearing map targets can clear when the last userspace reference disappears, and an updated BPF link detaches after its final FD/pin closes | Versioned NO_PREALLOC session and dynamic-DNAT v2 generations populated only from stable coordinator authority; complete namespace-scoped kernel hook inventory; boot-scoped legacy execution capsule retaining the fixed-point program/map graph; generation-owned active link pins; map-free XDP-drop and sched-cls-shot quarantine; fsynced forward-only journal and exact crash receipts; generated Go/Rust ABI and isolation/fail-on-revert tests |
| State/ownership corruption | HIGH | DDNS wrong-family delete, malformed/legacy cross-surface state, crash-ambiguous claim release, routing ownership loss, stale RG pins, interleaved session bulk/apply, and empty helper session tables after process replacement are explicitly stateful | Expected-surface validation including bounded pre-#2903 Surface A; exact same-family `fpb1`; classified claim release; full-generation clustered helper and helper-session debt; initialized authority; helper/transport-qualified gate; used-connection fences; cancellable joined reconcile; attempt-correlated repair; injected failure/retry tests |
| HA compatibility | HIGH | RG bindings above the 16-slot dataplane domain were previously accepted; reconnect or helper replacement can reorder callbacks and erase runtime sessions; RG1+ ownership can move without RG0; old receivers ACK reconcile failures; and old senders cannot prove sender epoch plus canonical config equivalence or uncontaminated bulk | Honest preflight/release note; complete state/priority/weight authority rows; daemon-lifetime sender identity and metadata-free canonical digest; prepared config/debt transaction; standby-first rolling restriction; no legacy ACK proof; helper-generation invalidation; continuity/timeout split; receiver-requested bilateral bulk; fresh/full/helper restart, active/active RG migration, reconnect, exhaustion, previous-good, stale-pin, failed-reconcile, mixed-pair, and repair-ABA smoke |
| Public API regression | MEDIUM | Route-map Go helpers gain required context, readiness gains additive diagnostics, and lifecycle strings change from false `deny` to `n/a` | Migrate every repository caller atomically; release notes; readiness/status tests; REST/gRPC/CLI/filter/action golden tests |
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
  clustered commit that evaluates identical local and peer-effective views also
  emits that stable warning key exactly once; a genuinely node-specific warning
  remains distinct. A
  `FormatSet` artifact reloads identically. The shipped Incus fixture is
  migrated, while an old persisted copy still boots with identical effective
  SNMP. Equal client prefixes prove `restrict` wins independent of source order;
  malformed clients never become unrestricted. Repeated community declarations
  prove correlation uses stable ordinals while the actual community, raw AST
  path, and any secret-derived hash are absent from observations, warnings,
  JSON/YAML, logs, and operational output. Community, authentication-password,
  and privacy-password sentinels prove observation-path redaction shares the
  complete AST secret classifier. A credential-only rotation still
  changes the private reconcile hash. Repeated user declarations prove
  unknown/empty/conflicting auth or privacy observations survive folding
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
  `surfaceAName` equals the stored canonical row name. It also loads both
  existing pre-#2903 empty-scope-FQDN fixtures, reconciles/adopts them into the
  current key, and proves no wire delete or degradation. It rejects zero-scope
  lookalikes, lease fields, address-family mismatch, malformed prior address,
  noncanonical row FQDN, and true nonempty canonical scope/FQDN mismatch. A
  valid row cannot be reclassified by heuristics because each constructor
  supplies the expected store surface.
  Fixed-updater tests preserve valid empty-fingerprint compatibility and refuse
  nonempty fingerprints.
  Stateful A -> B tests make forward deletion succeed and PTR deletion fail,
  retain A for the next pass, and advance the anchor only after the row is
  fully removed; A -> B -> C while A is unresolved retains and alarms. Any
  updater error causes no second-credential retry and retains ownership.
  Last-claimant no-authority asserts zero wire writes, retained row, non-nil
  error, failure counter, and alarm. Co-owned no-authority asserts claim-only
  durable release, zero provider calls, then Surface-A convergence after the B
  claim disappears. Injected pre-rename save failure restores and republishes
  the claimant; injected `PostRenameSyncError` converges memory/snapshot to the
  visible removal while alarming. Crash/reload from both possible durability
  outcomes performs zero wrong-owner provider I/O. Existing #6015 cross-surface
  ordering tests remain green;
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
  retry debt, and helper-disarm behavior are executable. A production-shaped
  helper fake performs full replacement, not patches: old `{RG1 active, RG2
  active}` -> new `{RG2 active, RG3 inactive}` proves one staged payload omits
  RG1, preserves RG2, and introduces RG3 fenced; retry replays that complete
  desired generation. Failure installs one `haInventoryDebt`; the status loop
  is its sole retry consumer and cannot replay old `m.haGroups`, rearm watchdogs, or
  publish forwarding. A newer generation atomically supersedes the debt; a late
  old retry cannot clear or publish over it, and every older unconfirmed fence
  remains required against the newest payload. Success publishes the staged owner
  inventory and clears only its exact generation. Shutdown leaves debt slots
  fenced. A blocked old helper RPC serializes against a newer config; after it
  returns, the newer debt/fences run and no late old replacement can overwrite
  them. Pause `UpdateRGActive`, `UpdateHAWatchdog`, the daemon watchdog tick,
  status refresh, and shutdown fencing before/after transaction acquisition;
  while debt exists no positive pinned write, old helper payload, readiness, or
  removed-slot update escapes. Negative clears fold into the matching debt, and
  exact debt completion wakes a level-triggered positive reconcile. Reverting
  any production writer's transaction wrapper must fail a source canary. Lock
  tests pin `applySem -> haInventoryTxnMu -> Manager.mu` and the separate brief
  `haInventoryTxnMu -> authorityMutationLane.mu` bookkeeping edge, reject every
  reverse/cross edge, and allow no helper I/O under a mutex. Pause an old
  full-replacement RPC while a newer candidate reaches promotion: the candidate
  cannot become active until the old RPC finishes and its exact debt is
  superseded, so no old helper payload can land after new active config. Preflight invokes the
  staged binary against the same operator-designated unredacted artifact/hash
  for node 0 and node 1 and covers exit 0, exit 2, redacted input, and tool
  failure; a stale valid file is explicitly outside the command's detectable
  contract and is not asserted rejected.

  Enumerate every `ControlRequest` and `ProcessStatus` path (`Status`, periodic
  poll, Compile/apply snapshot, rebind, worker-arm retry, forwarding arm,
  generation updates, and future source-canary fixtures) in the request-class
  registry. For each read-only request, pause after response, install/supersede
  inventory debt, then resume: telemetry may update only for the exact process,
  while `userspace_ctrl`, bindings, readiness, watchdog, and helper HA state
  remain fail-closed. Also capture status before each mutating request that does
  not otherwise advance snapshot/inventory state (queue, binding, forwarding,
  and rebind), complete the mutation, then release the old status response: its
  helper-mutation serial mismatch prevents positive publication. For each
  state-mutating request, pause the Rust handler
  after request receipt but before mutation while a newer config attempts to
  promote: promotion cannot pass `haInventoryTxnMu`; after the old response, the
  newer debt/replacement wins and no old positive helper state survives. Timeout
  or ambiguous write installs uncertainty debt and disarms; snapshot/control
  classes prove full helper replacement/replay, rebind/stop prove lifecycle
  replacement, and shutdown proves no same-process recovery. `sync_session`
  saturation cannot starve an HA transition and its response cannot publish
  authority. For every authority-neutral side effect, pause after registry
  admission and again after helper mutation; a config change/rebind closes
  admission, joins the exact finite handles, and cannot mutate the new snapshot
  until they finish. Fill the 64-slot registry with one active operation and 63
  queued operations, close admission, and prove every queued handle is canceled before I/O while
  only the exact in-flight operation may consume its bounded deadline. Race token
  acquisition with close and prove the phase revalidation prevents a post-close
  mutation. Hold a full export past the one-second urgent drain grace and demote:
  negative fences happen first, the helper is terminated/joined, the export is
  classified ambiguous, and replacement/repair completes without waiting 125
  seconds or exposing positive authority. In the paired ordinary config case,
  old config remains committed while the bounded export finishes. Prove the
  65th returns busy without
  I/O; non-session completion unregisters after dropping the socket and before
  stale status consumption, while a session-bearing result remains in
  `consuming` through its final all-or-nothing enqueue decision. Start a drain
  and owner export under C1, release each helper response, pause its consumer,
  promote C2, then resume: the transition either joins a complete C1 enqueue
  before C2 publication or the exact enqueue lease rejects the whole batch and
  arms repair. No returned delta is stamped with C2. Repeat with an EventStream
  frame read under C1 but callback-delayed through C2 and with a frame left in
  the kernel socket buffer: its encoded C1 snapshot generation survives pending
  replay and is rejected rather than relabeled. Moving unregister before the
  callback, returning a bare slice, reading the current config epoch at enqueue,
  or omitting the Rust generation field makes these tests fail. The consumer
  drops its socket token before SessionSync work, so join cannot deadlock on
  `haInventoryTxnMu`. Failed apply keeps
  the registry closed. Public `Status` and
  `Compile` plus transaction-held internal variants prove no non-reentrant
  reacquisition. A stale process/snapshot response is dropped entirely. When no
  debt or generation movement occurs, the same paths publish normally. Race and
  source tests prove no `Manager.mu -> haInventoryTxnMu` edge, unclassified
  request, direct socket write, nested public wrapper, or direct positive status
  application survives. A deterministic deadlock test pauses a read-only reply
  while a mutating request acquires `haInventoryTxnMu`: the reader releases
  `controlSocketToken` before lease consumption, allowing the mutator to finish;
  reversing either edge fails the lock canary.

  Consumer-lifetime tests cancel a consuming callback before its reservation,
  after reservation, and after its atomic commit. The first two publish no
  prefix; the last publishes the complete old-generation batch before the
  transition. A deliberately cancellation-blind fake consumer exceeds the
  injected urgent grace and takes the supervised fail-closed process path; no
  replacement helper or positive authority is published while it remains live.

  Authority-preemption tests pause a maximum-sized `apply_snapshot`,
  `update_ha_state`, positive `set_forwarding_state`, classifier-map publish,
  and status publication after each external-step admission and after the
  helper mutation but before response. An urgent RG demotion, whole-forwarding
  disarm, rebind, and Stop marks the exact mutator preempted without acquiring
  `haInventoryTxnMu`, closes its connection, escalates to exact-generation helper
  termination at one second, waits the current external step, and then lands the
  negative BPF/RG fence. The old mutator cannot start compensation, apply status,
  write another map, or publish after preemption. No applied failover ACK or
  peer-visible secondary row appears before the fence/process join. A fake stuck
  map step takes the supervised host-fatal path rather than a concurrent blind
  write. Reverting urgent work to acquisition of `haInventoryTxnMu`, omitting a
  mutator call site from the lane, or allowing late positive publication makes a
  deterministic test fail.
  Two coalesced urgent transitions allocate different serials; completion of the
  first cannot reopen admission. Only exact latest-serial replacement plus debt
  and session-repair completion reopens ordinary mutation, while Stop leaves the
  lane terminal even after the old mutator exits.

  Helper-lifecycle tests start from a capable standby whose helper generation
  H1 contains a completed authoritative bulk and whose continuity is true.
  Pause one SessionSync install and one event-stream callback, request H2, and
  prove `BeginHelperSessionTransition` publishes false and closes admission
  before process teardown, waits for the admitted install without holding a
  manager/helper lock, and joins or supersedes the H1 callback. The replacement
  `Coordinator::new` is observably empty; replaying config/HA status alone cannot
  restore readiness. A delayed H1 callback, ACK, bulk completion, status reply,
  old `bulkEverCompleted`, listener-bound bit, and timeout all fail the helper-
  generation token and cannot clear debt. The H2 event stream has callbacks
  installed before listener exposure and a real H2 session frame reaches the
  daemon; reverting to first-pointer-only callback wiring makes this test fail.
  Only a new H2-bound capable inbound owner bulk plus every required outbound
  owner reset two-stage bulk/TailAck completes bilateral repair and permits manual
  takeover.

  Planned-restart tests attempt a binding-plan replacement while the node owns
  live RG1 sessions. Successful committed transfer moves RG1 to the peer before
  H1 stops and preserves those flows there. Failed transfer leaves H1 and the
  previous committed config running and schedules retry; it never restarts in
  place. Forced-health-failure tests fence first, publish the ordered false edge,
  kill H1, emit exactly one typed session-reset alarm/counter transition, and
  keep positive/manual authority closed. The H2 authoritative owner snapshot,
  including an empty snapshot, reconciles stale H1 replicas from the peer only
  through a new transport and exact two-stage BulkAck/TailAck. Active/active
  tests require the inbound and outbound directions independently. Standalone forced replacement reopens
  only after canonical helper bring-up, reports explicit connection loss, and
  never claims HA continuity. A reconnect after that reset must reconcile the
  new owner snapshot before readiness.

  Process-lifecycle canaries enumerate every `exec.Cmd` start/wait/signal/kill,
  helper pointer publication, `stopLocked`-equivalent, event-stream construction,
  and binding-plan/health restart call site. Moving any path outside
  `replaceHelperProcess` fails. Lock tests pin `helperLifecycleMu` as an outer
  non-reentrant coordinator and reject SessionSync-to-Manager, Manager-to-
  SessionSync, callback-to-lifecycle, and lifecycle calls made while
  `haInventoryTxnMu`, `Manager.mu`, a socket token, `s.mu`, or `gate.mu` is held.
  `CloseAndWait` joins accept/read/ACK/pending-flush/callback handles under
  cancellation and no old process handle survives publication of H2.

  Every session-sync race test enters through encoded production receive/setup
  paths and `QueueCommittedConfig`; direct calls to a gate/debt helper are not
  sufficient. Startup tests prove runtime, the immutable nonzero local
  committed config record, callbacks, full committed RG map and manager serial,
  config-sync mode, and an explicitly initialized empty or populated zone-owner
  map are installed before `Start`. Missing authority
  or a zero/missing local sender epoch fails before bind; an initialized empty map
  allows an authoritative empty bulk to reconcile rather than silently skip.

  Full daemon boot creates one random process ID before apply, canonicalizes the
  structurally validated active tree, allocates local generation 1, and exposes
  no listener on apply failure. A cluster-comms restart reuses that exact process
  ID and immutable record. A full daemon restart creates a different process ID,
  canonicalizes persisted active state back to generation 1, and establishes a
  new baseline without comparing generations across process identities.

  Canonical-identity tables include local annotations, `InheritedFrom`, source
  positions, insignificant comments/whitespace, repeated parse/format cycles,
  peer send/apply, persistence reload, config-sync-disabled equal configs, and
  daemon restart. Annotation/display metadata changes do not change wire text or
  digest; a forwarding-hierarchy change does. Parsing canonical wire text is
  byte/digest idempotent. Reverting any path to hash raw `tree.Format()` fails.
  Inject every checked identity counter at `MaxUint64-1` and attempt one more
  ordinary allocation: admission closes, the one reserved terminal continuity
  sequence delivers/acknowledges final false, no frame/positive authority
  follows, and the daemon returns `ErrIdentityCounterExhausted`. A supervisor-style new process
  starts with new identity/generation 1; no counter wraps or rotates in process.

  Protection tests cover boot plus config-sync enable/disable in both RG0 roles.
  An unresolved boot role stays transitioning/fail-closed until a production
  ownership event completes.
  Enabling on a secondary closes admission and requires a baseline; disabling
  drains and removes only baseline debt. Protected generation-zero rows are
  refused as ordinary and bulk members. Earlier valid nonzero members remain
  installed when a later member aborts the nontransactional window, but no
  reconcile success, ACK, callback, readiness, or debt completion follows.

  Config-incarnation tests admit G2 on fabric 0, block the callback after store
  mutation, replace only fabric 0, and prove successful completion publishes G2
  for the unchanged transport/process/ownership. Queued non-admitted old-fabric work
  is dropped. The paired last-fabric test proves reconnect cannot register until
  the callback and installs drain; the new transport then requires a fresh
  baseline and may accept a lower rebooted-peer generation. A stale old token
  cannot clear it. Last-fabric loss clears current continuity while retaining
  previous-good history only for timeout-governed automatic peer-loss. Config
  failure retains previous-good and baseline debt, marks authority failed,
  advances no high-water, and retires/reconnects so the sender's immutable
  record re-pushes the same config epoch. Equal generation plus another digest is
  rejected; exact failed identity forces full reapply; a strictly newer record
  supersedes it only after full replacement success. An exact already-accepted
  replay skips store mutation but still establishes baseline/repair. Reverting
  `QueueCommittedConfig` to allocate or renumber on any send makes the test
  fail. A peer-applied epoch remains the accepted **remote** epoch; the same
  callback allocates one independent local sender epoch, and RG0 promotion
  reuses both without renumbering either. Reciprocal RG1-owned sessions stamp
  the local committed record, not the peer generation or allocation counter.
  A newer remote epoch with byte-identical canonical text/digest advances only
  the accepted remote record, preserves local annotations, and performs no store
  promotion/dataplane apply/local allocation; the same input while an exact
  failed-mutation record exists must instead run recovery.
  A same-peer-process/same-generation/different-digest declaration is refused
  before bulk/session admission. Two config-sync-disabled peers with identical
  canonical digests and different local generations complete reciprocal repair;
  different digests remain closed. A rebooted peer with a lower epoch must
  supply and fully apply matching text/digest when config sync is enabled, or
  prove exact independently committed canonical digest when it is disabled,
  before either direction reopens. A G2 transport-address change returns a restart outcome, publishes
  its lease/high-water, exits the callback, and only then lets the daemon-owned
  worker call `Stop`; the old self-join trace is a bounded passing test. A newer
  fully successful G3 outcome coalesces a queued G2 restart and the worker uses
  only G3's `committedRuntimeConfig`. Promote a failing G4 in `store.active`
  while a G3 wake waits and prove restart still uses G3. Single-fabric EOF and inline protocol violation are raised
  from production receive loops; each worker returns before the lifecycle
  coordinator joins it. Concurrent duplicate/older retire requests coalesce,
  simultaneous requests for both fabric slots are retained, and older requests
  cannot close a replacement epoch. Pause inbound and outbound setup after
  `beginSetup`, drain the epoch, and prove both exact setup handles are
  canceled/joined and cannot install; permanent accept/connect loops remain
  alive until process Stop. A single-fabric case closes only that fabric's setup
  lane and lost-incarnation data handles, lets a transport-scoped callback and
  the surviving fabric continue, then creates a higher setup generation and
  reconnects the lost fabric. Its data registry never closes. If the second
  fabric retirement arrives during the first join, the first lane is not
  reopened and whole-transport drain wins. A sharper race pauses replacement setup after
  authentication/capability but before final install, records EOF/retirement for
  both old fabric incarnations, then resumes setup: its promotion observes
  `wholeTransportPending`, closes the new socket, and the coordinator drains and
  advances the old epoch. Closing setup/data registries rejects later inserts
  without a WaitGroup Add/Wait race. `Stop` joins transport registries,
  lifetime workers, and the separately owned coordinator without a timeout
  escape. The coordinator is absent from `lifetimeWorkers`; terminal sequencing
  delivers and acknowledges final false, closes its exact completion once,
  joins lifetime workers, then closes/joins coordinator intake. Concurrent
  ordinary retirement plus Stop cannot lose or double-close that completion.
  `beginSetup` and permanent loops reject after `stopping`.

  A real `clusterCommsEpoch` test starts watchdog, heartbeat, gRPC, event-stream,
  reconcile, IPsec, and both fabric children, then restarts and asserts every old
  handle exits before any replacement is published. The replacement receives
  the exact same daemon process ID and immutable local committed config record
  and stamps its first request/session with that generation; only transport and
  connection incarnations rotate. Request and bulk wire IDs continue above the
  daemon-owned high-water rather than restarting at one under the same local/
  remote process pair; replacing only the remote daemon starts that pair's
  request IDs at one while preserving unrelated pair state;
  completed peer replay entries and reject-below floors also survive, so an old
  request cannot execute again after the in-process restart.
  Reverting construction to allocate from text fails this test. Shutdown races a queued
  restart wake and proves the daemon coordinator cannot start an epoch after
  event admission closes. The ownership canary fails when any
  `startClusterComms` goroutine omits an epoch handle.

  Protocol-lifetime tests drive remote single/batch failover request and commit,
  fence, prepare activation, DHCP, IPsec, peer-connect, and every callback in the
  source registry through encoded frames. Pause each callback, lose one fabric,
  lose the last fabric, replace the peer process, and call Stop. The declared
  connection- versus transport-scope behavior is exact, all handles join, and no
  mutation escapes process replacement. A failover ACK is written only on its
  source incarnation; forcing `sendFailoverResult` to use the current active
  connection fails the test. Colliding request IDs from two process IDs cannot
  complete the wrong waiter, while an exact duplicate joins or returns the
  bounded idempotency record without repeating the ownership mutation. Fill all
  64 in-flight callback phases, all eight waiter slots on one phase, and the
  1,024-slot sparse request window, 64-entry nonterminal transfer ledger, and
  1,024-entry floor-covered completed cache for one process pair through encoded frames.
  A request and its commit reuse one ID and normalized RG-set digest, retain
  independent cached phase results, and execute each mutation once; commit before
  a successful request or with another RG set retires the source. Deliver request
  IDs 12 then 11 on opposite fabrics and prove both execute once; leave a gap and
  prove the contiguous request floor does not skip it; retry that exact ID/body
  and prove the floor advances. A commit for a retained nonterminal request may
  execute below the request floor and an already completed commit returns its
  cached result, while an evicted terminal transaction at/below the floor is
  rejected stale rather than reconstructed. An unseen ID beyond the right edge retires without allocation. New
  work at capacity receives busy without mutation/goroutine growth; in-flight
  entries and request-applied/commit-pending transactions are never evicted.
  Fill the window with IDs above a missing low gap while the nonterminal ledger
  holds older at/below-floor transfers: the missing ID still owns its modulo
  slot, and newer work returns busy rather than evicting an above-floor terminal
  result. Completing the gap advances the floor, moves only nonterminal rows to
  their bounded ledger, and makes covered terminal results safely cache-evictable.
  Expire an exact
  transaction-key-bound owner transfer lease, record the restored terminal result, and
  prove a later commit is rejected and a new transfer needs a new ID. A ring
  with no safe floor-covered victim returns busy rather than dropping transfer state;
  replace peer process P1 while `{P1, request 1}` is commit-pending and prove
  its owner state restores before P2 admission, then let P2 allocate request 1
  and prove it cannot clear or inherit P1's lease. Repeat with two legacy
  transport epochs that both use request 1 and prove transport loss restores the
  first tagged lease before the second is admitted;
  busy is not cached and cannot advance that floor, so the same ID/body succeeds
  after capacity returns;
  an old lost-ACK retry below it is rejected rather than re-executed; and
  capacity recovers after completion. Same ID with
  another normalized body retires the source. Retry from another current fabric
  gets a cached result on its own source while the original callback never moves
  its ACK. Peer-process replacement destroys the ledger only after all old
  callback/waiter handles join and every old-process nonterminal owner transfer
  restores. Saturating the checked per-key capture-tail coalescer records
  full-bulk debt and stays memory bounded; repeated churn of one key remains one
  entry. Legacy prepare-activation accepts
  exactly one byte; capable mode accepts exactly nine bytes with nonzero LE
  request ID; cross-mode, zero-ID, and every other length are rejected. Capable
  prepare IDs 12 then 11 for one RG execute only 12, while RG2's independent ID
  cannot suppress RG1; duplicate/reconnect delivery is dropped by the fixed
  per-RG high-water without an ACK/waiter/replay-cache entry. A source
  canary rejects bare `go On...`, `context.Background`, unregistered callback
  fields, unbudgeted waiter/worker creation, and result writers without a
  callback lease.

  Receipt-worker tests enter through the real remote single and batch dispatch.
  The mutation handle returns one authority receipt and closes before
  `CompleteOwnershipTransition` joins its pre-publish set. A separately tracked
  post-publish waiter remains blocked, `Complete` stages the gate, final
  `PublishRGAuthority` completes the exact receipt, and only then may that waiter
  emit `applied` on its original connection. A join-graph assertion rejects the
  cycle `postPublishWaiter -> Publish -> Complete -> postPublishWaiter`. Source
  loss between mutation and publish suppresses the ACK but does not migrate it or
  undo the transaction; an exact retry binds a fresh waiter to the cached phase.
  Supersession, publication failure, process replacement, and Stop resolve and
  join both handle classes without leaking an owner-transfer lease.
  Cancel every waiter before publication, then complete `PublishRGAuthority`:
  the coordinator still records the terminal replay result, and a later exact
  retry returns it without a second mutation. Expiring one waiter's callback
  deadline suppresses only its ACK and does not trigger owner restoration.

  A fake-clock budget table drives each production dispatch class: two-second
  frame write; ordinary helper control at three seconds below one MiB plus one
  second per complete MiB capped at 120 seconds; owner-RG export at a five-second
  control-admission budget inside one 180-second private-stream/peer-bulk
  deadline; all-session export at
  one 120-second Rust aggregate budget inside a 125-second Go round trip;
  one-second urgent side-effect drain before helper replacement;
  session helper at two-second dial/three-second round trip; three-second
  capability setup; five-second protocol/repair start; 180-second authoritative bulk send/receive;
  post-BulkAck 180-second capture-tail drain with each 112-byte phase marker
  subject to the ordinary two-second frame-write deadline; the unified
  session/dynamic-DNAT v2 migration has one non-renewable 180-second absolute
  deadline covering writer freeze, coordinator population/readback, exact hook
  replacement, helper-handle switch, and durable commit;
  20-second failover/BulkAck/TailAck; and one-to-30-second
  config recovery backoff. The all-session test fills/drains the event queue
  between successful frames and proves the absolute budget, rather than a fresh
  five seconds per frame, stops the loop; a responsive Rust budget error records
  full-bulk debt without process replacement, while a lost Go response takes the
  ambiguous helper-replacement path. A trickle sender delivers one bulk member
  just under every per-write timeout but never reaches `BulkEnd`; the absolute
  receive deadline still cancels/joins it with no ACK. The inverse slow writer
  cannot extend the outbound deadline, and `BulkEnd` success resets only the
  exact token to the 20-second ACK budget. Each expiry
  returns its typed failure, records required debt, closes
  positive readiness, and lets lifecycle/Stop join. A cancellation-unaware fake
  is rejected from config/callback registration rather than hidden behind an
  unbounded join. Filling the continuity outbox while its consumer is blocked
  propagates bounded backpressure outside locks; terminal cancellation still
  delivers the final false edge and joins the consumer.
  Duration ownership stays in production constants; unit/integration harnesses
  inject the clock and grace value through test-only constructors rather than a
  production environment variable, so slow CI can exercise both graceful drain
  and exact one-second escalation deterministically.

  Config-transaction tests change zone ownership and config-sync mode, then
  fail after each intermediate `applyConfigLocked` stage. The gate never sees
  the delta before callback success and never reopens under old authority after
  a promoted/partially armed failure. A real Store -> daemon -> userspace peer
  test pauses after `PrepareSyncApply`, after matching helper debt/fences are
  installed, and immediately around `PromotePreparedSync`: the exact prepared
  tree/compiled identity is promoted once, its local sender record is reserved
  before visibility, and debt always precedes visibility. Prepared objects expose
  no AST/compiled pointers; mutating every map/slice in a returned immutable view
  cannot change the sealed object, staged debt, or promoted sole-owner clone. A
  store mutation-generation
  conflict leaves the store untouched but must compensate every staged fence,
  helper snapshot, and gate transition back to the captured prior authority
  before re-preparing; injected compensation failure remains fail-closed debt,
  and the unused reserved generation is burned. Reverting to direct `SyncApply`
  fails. The successful exact callback atomically
  publishes generation plus both authority fields. Local commit and rollback
  use the same begin/success/failure contract without reentrant draining.
  Production entrypoint tables cover gRPC/REST/shell plain operator commit,
  event-engine local commit, commit-confirmed, nonnil timeout rollback, and
  first-commit bootstrap rollback. Each begins immediately before its
  generation-bound promotion, reserves any new local record before promotion,
  and on conflict/error runs exact prior-authority compensation before returning
  or retrying. Tests inject each compensation step, prove a failed compensation
  leaves admission closed, and prove burned generations are never reused. Each
  success returns `OwnershipMutation` and completes only after full apply.
  Candidate `Rollback`,
  `ConfirmCommit`, and confirm cancellation prove they do not open an active
  transition. `PreviewPendingRollback` is paused before promotion while confirm
  state is superseded: no store mutation occurs and the lease aborts. Source
  canaries fail any active-store promotion without the corresponding local or
  peer transaction or when independently supplied compiled/canonical/generation
  arguments reappear. A table drives every active/candidate/compiled/rollback/
  confirm mutation and proves exactly one checked `storeMutationGeneration`
  increment on success, none on mutation-free failure, conflict after any
  intervening mutation, and pre-mutation `ErrStoreGenerationExhausted` at the
  boundary. Existing candidate-generation API tests run unchanged against the
  shared token, plus a source canary rejects a second `candidateGen` field or an
  unchecked increment.

  Static-DNAT projection-removal tests enter through every local and peer
  active-config promotion path. Instrument both maps and prove that adding,
  changing, deleting, rolling back, or replaying a destination-NAT/static-NAT
  rule performs zero `flags=1` map writes/deletes while the sealed Rust snapshot
  changes exactly at the committed-runtime publication. A store-generation
  conflict after Begin leaves the old snapshot and both dynamic maps byte-exact.
  Helper/dataplane failure before publication retains the old runtime; response
  loss after the publication readback selects the new runtime and exact ordinary
  failed-apply debt without reconstructing a static kernel row. Source canaries
  enumerate compiler/config call sites and fail on `DNATFlagStatic`,
  `writtenDNAT{,v6}`, compiler `SetDNATEntry{,V6}`, or production
  `ClearDNATStatic{,V6}`/`DeleteStaleDNATStatic{,V6}`. Interface/source canaries
  require the dynamic-only value constructor and reject a caller-settable Flags
  field at every ordinary session write site.

  Build native-GRE v4 and v6 packets for a configured static DNAT address, a
  live dynamic reverse-SNAT address, and an unmapped address. At the XDP function
  boundary, assert identical final action, XSK slot, metadata length/content,
  and fallback counters for lookup hit and miss through the redirect call; only
  the Rust snapshot may produce different NAT/policy outcomes afterward. Run the
  same proof with exact and wildcard v4 ports, exact v6 ports, ICMP identifiers,
  malformed/non-IP inner packets, local/control destinations, and strict-mode
  redirect failure. A source/ELF walker proves no branch reads a static value or
  uses a DNAT translated-value field. Reverting either the default fallthrough
  or the projection removal fails this test.

  Build and load the exact historical readers from `7a5c73986` and
  `13fa1009e^` against old session/DNAT map fixtures containing canonical legacy
  `flags=1`, live `flags=0`, unknown flags, nonzero padding, and deliberately
  partial session aliases. Exercise native and generic XDP plus TC and TCX,
  through pinned and unpinned attachments, and prove the exact packet semantics
  plus every packet-side old-map write/delete surface. Separately load test-only
  XDP and sched-cls roots that use real PROG_ARRAY maps and tail targets matching
  the historical slot/layout contract. A bounded gate immediately before each
  `bpf_tail_call` signals entry and waits for release; the target performs a
  distinctive result plus an old session/DNAT update/delete. While an invocation
  is inside that gate, duplicate-pin the complete legacy capsule, perform the
  v2/detach cutover, remove every ordinary program-array pin, close every
  ordinary FD, and kill/restart the owning process. Releasing the gate must still
  reach the exact target rather than XDP_PASS/TC_ACT_OK, and its old-map mutation
  must appear only in the capsule object. The v2 maps, v2 packet action/XSK,
  helper authority, status, and recovery decision remain byte-exact. Removing
  the capsule's PROG_ARRAY pin or omitting one occupied target makes this
  fail-on-revert trace take the historical pass fallback. The exact historical
  binaries remain unmodified and prove the generated closure includes every
  actual root/map/occupied tail target; the instrumented tail-call fixtures prove
  concurrent lifetime and user-reference retention. Exercise the historical
  root -> CPU map path separately: enqueue a packet, gate the CPUMAP program
  immediately before its `cpumap_xdp_progs` tail call, close every ordinary FD/
  pin, then release and require the target rather than XDP_PASS. Do the same for
  a populated DEVMAP and DEVMAP_HASH program edge and for one map-in-map child;
  omitting any edge type from the fixed-point walker fails before cutover. The
  current v2 shim's complete `ProgramInfo.MapIDs` set
  matches the generated classified manifest: its authority references are only
  the three v2 maps, and every other reference is one exact retained
  infrastructure object. Its dynamic maps contain only coordinator-derived
  reverse companions and never an old `flags=1`, unknown, or padded value. Add
  one extra, missing, legacy, ABI-drifted, or unclassified writable map to the
  ELF/loader, or make the kernel's `ProgramInfo.MapIDs` query unsupported, and
  prove preflight fails before a hook changes.
  Seed fixed-name legacy pins and revert one target symbol to implicit
  `PinByName`; the loader/canary must fail rather than bind the target program to
  a legacy object. Every successful target collection proves all map replacements
  by live ID after load.
  Recycle a program ID, substitute a same-tag/different-instruction program, alter
  expected attach type/BTF ID/map-ID set, and replace a pin beneath its path;
  none satisfies the full program identity or a hook receipt.

  In a privileged disposable network namespace, inventory native/generic and
  unsupported hardware-XDP reports, pinned and unpinned XDP BPF links, legacy
  netlink XDP, classic clsact BPF filters at nondefault chain/priority/handle,
  pinned and unpinned TCX, extra stale xpf hooks, and an unrelated external BPF
  program on a compiled interface. Compare the recursive root-pin walk,
  BPF-link-ID walk, RTM_GETLINK dump, RTM_GETTFILTER dump, Manager handles, and
  compiler expectations to one exact union. Missing one source, changing the
  namespace inode/ifindex generation between the two snapshots, query failure,
  duplicate occupancy, hardware mode, incomplete transitive closure, or unknown
  ownership blocks before a hook update. An unpinned legacy netlink/classic-TC
  artifact is accepted only with its exact rooted transitive closure. Inject attach churn
  between snapshots and during update; the inventory generation invalidates and
  no stale receipt commits.
  Create two namespaces with the same ifindex and attach the same program to
  TCX in both. The held-namespace `BPF_PROG_QUERY` link-ID result selects only
  its exact link; global `bpf_link_info.ifindex` cannot add the other. Repeat for
  XDP: only the held namespace's RTM program plus an exact same-boot durable
  provenance record may correlate. Pin namespace A's link, then namespace B's,
  while both have the same ifindex and program; no record or either mismatched
  record fails closed rather than updating whichever object is pinned. A true legacy
  netlink XDP attachment remains the typed no-link case.

  Start from the current fixed `links/xdp_<ifindex>` and `links/tc_<ifindex>`
  BPF-link pins with no durable namespace record and prove online migration and
  the resume command both refuse them. A controlled reboot removes the ambiguous
  kernel object; the clean-boot path attaches v2, writes and directory-fsyncs the
  new provenance record before readiness, and never reloads a historical map.
  Crash after attach/pin but before record rename or directory fsync: restart
  reports the unproven hook and requires another clean reboot, never inferring
  ownership from the still-present pin.
  Then start from a same-boot link with valid provenance. Add and verify the generation-owned pin while the legacy alias
  and held FD remain, then crash before/after its journal receipt, `Link.Update`,
  attached-program readback, target receipt, legacy-alias unlink, and final FD
  close. At every boundary at least one exact pin keeps the same link ID alive;
  after alias unlink and daemon death, reopening the generation pin proves the
  v2 program remains attached. Repeat with an initially unpinned link created by
  the current Manager; it becomes eligible only after pin/provenance durability.
  Also cover a legacy netlink XDP attachment using expected-FD replacement, classic
  TC exact detach, TCX quarantine/detach, pin-path substitution, and program/link
  ID reuse. A generation pin to a different link, a receipt without pin
  readback, or closing the last FD before the durable pin must fail the test.

  Kill xpfd while a recognized historical helper owns its control socket and old
  map FDs. `/proc/*/fdinfo` discovery, `SO_PEERCRED`, executable device/inode/
  build digest, PID start time, nonce, pidfd termination/join, and the inherited
  lifecycle lease prove that exact helper terminal and the nonblocking lock
  reacquired before v2 population. A busy lock never enters an unbounded wait
  and lock-owner PID alone never authorizes a signal. Repeat
  with PID reuse, stale socket, an unresponsive recognized helper, a pre-lease
  helper, and an unrecognized process holding an old map FD. Only the exact
  recognized process is terminated. An unknown map-FD holder cannot contaminate
  v2 and is never killed; an unresolved AF_XDP/socket owner keeps readiness
  closed. Future helpers die with the parent and fail their parent-identity
  handshake on the fork/exec race. Attempts by every packet-worker, Go session
  store, helper, config apply, and peer reverse-NAT writer during migration are
  rejected before structural authority changes.

  Crash at `prepared` temp write, file fsync, rename, directory fsync, durable
  `forwardOnly`, before/after each legacy-capsule root/map/PROG_ARRAY/tail-target
  pin and receipt, each generation-owned BPF-link pin and receipt, every
  native/generic-XDP v2 receipt and TC/TCX detach receipt,
  final v2/coordinator readback, helper-handle switch, active-manifest temp/
  fsync/rename/directory-fsync, `committed` rename/fsync, removable legacy-alias unlink,
  cancellation, Stop, and the 180-second absolute deadline. A
  same-process `prepared` record with no changed hook may rebuild v2. A same-process
  `forwardOnly` retry may reuse only its unchanged target and exact writer/
  coordinator receipts. Every new process with an exactly owned hook, including
  no-journal legacy, prior-process `prepared`, `forwardOnly`, mixed-hook,
  `recoveryQuarantine`, or `committed`, validates exact program/map identities, moves all
  exactly owned hooks to the map-free typed drop quarantine, builds a fresh inactive
  v2 successor from the restarted coordinator, advances XDP only toward that
  successor, and detaches the quarantined legacy TC/TCX hooks; no branch selects the old program, rebuilds a map behind a live
  hook, or performs a userspace lookup/update/delete on an old/previous-target
  map. Corrupt, missing,
  or identity-ambiguous records retain explicit debt and fail closed. Change the
  recorded kernel boot ID: zero surviving xpf BPF/helper/AF_XDP objects permits
  a clean archived-journal start, while any surviving or unknown object blocks.
  Advance fake `CLOCK_BOOTTIME` past the original deadline across process
  restarts: only exact typed quarantine may continue inside its separately
  persisted 20-second bound, and no successor/admission occurs. Exercise
  `recover-userspace-shim` as non-root, with a live daemon socket, wrong
  migration ID, changed boot ID, unknown hook, corrupt journal, and exact fully
  quarantined state. Only the last case atomically renews one forward deadline;
  it accepts no object path/ID and cannot cause an old-program attachment.
  A
  10,000,000-row synthetic coordinator population verifies fixed memory credits,
  bounded per-tick latency, exact three-map membership/count proofs, and deadline expiry.

  Block
  `applySem`, a post-promotion operation, and a post-arm tail, then cancel the
  exact lease: the callback receives context cancellation, returns the correct
  mutation stage within its deadline, performs no later mutation, leaves the
  digest unmarked/gate failed, and reconnect fully applies the exact or a newer
  immutable generation before baseline. Make callback-tail `cluster.UpdateConfig`
  transition the full ownership snapshot from serial S to S+1: callback success records its generation,
  digest, and authority delta against predecessor S without self-cancel or
  reopen; `Begin` joins it, stages S+1, and only final manager publish exposes
  authority. An unrelated transition has the same fail-closed adoption path.
  A committed serial that bypasses the join trips the invariant path and cannot
  erase the successful mutation record. Local false -> true sends the enabling generation; true ->
  false sends exactly one final disabling generation under the transaction;
  false -> false sends none. The peer applies each sent transition and both
  post-config session directions reconcile.

  Production daemon tests drive RG0 and RG1 promotion/demotion through both
  `watchClusterEvents` and dropped-event safety-net reconciliation. Election
  publishes a transitioning authority serial before raw `rg.State`; a goroutine
  paused in the old event-delivery window observes no committed positive
  authority and SessionSync refuses admission. During a paused demotion,
  heartbeat continues advertising the previous primary role until negative
  fencing, gate staging, and final publish finish; during promotion it continues advertising
  the previous secondary role. Boot-without-commit advertises secondary-hold.
  Pause monitor recalculation and priority/config updates immediately after the
  desired authority snapshot is published but before fencing: heartbeat keeps
  the complete old `{present,state,priority,weight}` row. In particular, it never
  emits old primary plus new weight zero; the peer cannot take the immediate
  peer-weight-zero promotion branch before the local fence. Final publish swaps
  the complete row atomically and heartbeat rows remain sorted by RG ID.
  For remote single and batch failover, pause after the BPF/VRRP fence but before
  final manager publication: `WaitFailoverApplied*` remains blocked and no
  applied ACK is emitted while heartbeat still carries the old committed row.
  Exact publication completes the receipt-bound waiter and only then permits the
  ACK; supersession/publication failure produces failed ACK plus keyed lease
  restoration rather than releasing the requester.
  The same assertions enter through manual single/batch failover,
  secondary-hold preparation, kernel self-recovery, upgrade drain, and config
  reconciliation, including every local definition creation/removal. A same-desired
  write reuses the pending serial and cannot generate an event storm. A source
  canary rejects every local `rg.State =`, `rg.LocalPriority =`, `rg.Weight =`,
  local group insert/delete, and direct
  local `sendEvent` outside `mutateLocalRGLocked` or the full-definition
  replacement boundary, and rejects heartbeat serialization from raw groups;
  peer-state writes remain
  separately typed. Its finite
  authority-read allowlist covers all `IsLocalPrimary*`, `GroupState(s)`, and
  local `ClusterEvent.NewState` shapes.
  Delayed/reordered RG events carry their original serial and cannot combine
  an old `NewState` with the newest snapshot; the safety net completes the
  newest level-triggered serial after an injected event drop.
  Demotion may fence traffic
  immediately but defers store/config/readiness publication; promotion exposes
  nothing until the gate stages and the exact manager token publishes. Injected
  supersession before prepare, between prepare and gate completion, and between
  gate completion and final publish leaves global authority transitioning; the
  stale staged gate serial cannot admit, and the newest serial is retried.
  Inject callback failure after it triggers the manager serial: `Complete`
  returns no gate permit, final publish is impossible, and exact/newer full
  config reapply is required before authority can commit. With network config
  admission still closed, the daemon recovery worker retries the in-memory
  record under `applySem`, emits no config text in diagnostics, and supplies the
  permit only on full success; restart/shutdown joins it. Timeout retains
  one level-triggered desired state, and a newer serial supersedes then re-enters
  the same coordinator. Source canaries reject direct local-RG positive actuators
  outside the wrapper and raw `IsLocalPrimary*` reads in authority-sensitive
  code. Pause promotion before final publish and prove raw `sendEvent` emits no
  GARP/NA; the exact post-publish wrapper emits it once, while a superseded token
  emits none. Boot remains unknown/fail-closed until initial authority reconciliation.
  In an active/active fixture, A owns RG1/zone Z, then RG1 moves to B while RG0
  and the TCP transport stay unchanged. The manager publishes transitioning
  before raw state, closes the global session producer/receive gate, atomically
  replaces `ZoneOwners`, and repairs both directions under the new full-map
  serial. A cannot emit Z afterward, B cannot emit before final publish, and an
  old-A authoritative bulk cannot delete B's valid Z sessions. Dropping every
  RG1 event still converges through the level-triggered full snapshot.
  Seed one promoted authority member on three workers and prove ordinary and
  handoff Header/Final membership count it once from the deterministic lowest
  live `canonical_owner_worker`; changing worker iteration order cannot change
  the digest. Lose that worker during a closed producer generation and prove all
  replicas transactionally select the next lowest survivor before export
  reopens. Demotion changes `Active` to target-process/ownership-serial-bound
  `HandoffExportable`: ordinary export and a wrong-target or wrong-serial request
  exclude it, while the exact handoff includes it once and binds the disposition
  to Header/Final. Exact TailAck plus ownership commit converts it to
  `PeerSynced`; disconnect, failed TailAck, supersession, or ownership failure
  makes it `Quarantined` with the same serial and no ordinary export. A retry
  receives a new serial, and local `Active` restoration is allowed only when
  ownership never committed away. For local/peer promotion, canonical-owner
  reassignment, demotion staging, and post-TailAck relabel, fail after
  coordinator staging and after each worker stage/commit ACK. Race stale
  promotion and worker-set generations, lose the canonical worker, and Stop
  mid-transaction. The coordinator transaction/debt remains the sole oracle,
  stale ACKs cannot commit, and export cardinality is zero until every exact
  survivor commits and exactly one afterward; split replicas never duplicate or
  silently omit a member. Fill every stable slot, pause after each bounded
  staging chunk, and prove memory remains fixed, the persisted cursor resumes
  without rescanning committed slots, and no worker inbox exceeds its declared
  capacity. A fake clock expires the absolute 180-second provenance deadline
  before staging, during stage fanout, during commit fanout, and after a worker-
  set restage; progress never renews it, export/admission remain closed, and the
  controlled recovery path retains one typed debt owner.
  Race tests assert only `s.mu -> gate.mu`, `bulkSendMu -> producerMu`,
  `continuityPublishMu -> [writeMu ->] s.mu -> gate.mu`, and the write-fence
  `writeMu -> s.mu -> gate.mu` edge; no reverse edge,
  state-locked callback/I/O/cancellation wait, or condition wait exists.
  A callback blocked after store mutation completes under the predecessor ownership before
  `ownershipGeneration` advances. The manager has already published a newer
  transitioning serial, so new admission/positive authority is closed, but the
  callback still publishes against its predecessor gate lease; `Begin` joins it
  before replacing that serial. The transition cannot strand its applied
  generation or let it finish inside the successor ownership.

  Setup tests delay each peer independently and cover new/new, new/old, old/new,
  keyed/keyed, keyed dual-accept, and unkeyed. Auth HELLO/PROOF may precede the
  capability; capability is always the first post-auth frame from upgraded code.
  An unkeyed upgraded side receiving an old keyed HELLO consumes setup frames
  until the later legacy data frame and never dispatches auth into `handleMessage`.
  An auth-consumed legacy frame is staged until after registration and authority
  initialization. Exact 50-byte length/version/flags, missing each of the five
  required bits, unknown bits, valid all-zero partial capability, any zero
  capacity with a complete bit, overflow capacity, combined-cluster-maximum-
  greater-than-either-peer-reserve, cross-fabric
  defined-bit/process/capacity mismatch, zero
  ID, duplicate,
  late/mutated capability, setup timeout, and injected entropy failure are
  covered. A symmetric `net.Pipe` proves concurrent capability writes cannot
  deadlock; canceling setup joins the tracked writer before epoch retirement.
  Entropy failure makes `Start` fail before bind and emits no type 30.
  Two capable fabrics require the
  same process ID; capable/legacy mixes and mismatches retire the transport.
  Setup admission remains charged until resolution and releases exactly once on
  success, timeout, auth failure, and capability failure.
  Capacity goldens build the exact `SessionCapacityPlan` and prove that worker
  and bounded auxiliary creation sublimits share one local-plus-peer authority
  reserve, with transient-tail credit added separately: 2x
  entries in every fully replicated worker and coordinator store, 4x distinct
  keys in the single AF-agnostic `userspace_sessions_v2` map, 2x in **each**
  persistent kernel `sessions`/`sessions_v6` map, 1x dynamic reverse-NAT rows in
  each independently populated DNAT family, bounded slot-handle
  auxiliary indexes, and baseline-plus-tail rows in the generation ledger.
  An eight-worker concrete fixture proves that every worker independently gets
  the full 2x reserve rather than dividing or multiplying the advertised peer
  count incorrectly, and derives the nonzero transient-tail ceiling from the
  tightest 1x/2x/4x residual rather than disabling the baseline because the
  preferred 262,144-row tail does not fit. Populate local and peer provenance together to the exact
  combined authority boundary, promote every peer row without changing total
  physical occupancy, and prove exact-boundary admission succeeds while one additional
  logical row fails before mutation on each physical surface. Exhaustive
  NAT/no-NAT, v4/v6, NAT64, and equal-alias
  fixtures prove four is a safe maximum and that the synthesized reverse adds no
  fifth shim key. Advertise unequal local-creation ceilings, promote the peer's
  complete authority after takeover, and prove the checked sum of both creation
  ceilings must fit **each** baseline reserve before capable authority starts.
  Exact combined-boundary export back to a restarted peer succeeds; one row
  above either reserve refuses capable authority before BulkStart. Reverting to
  a two-field capability or checking only the current node's creation ceiling
  fails this trace. A tail that transiently
  Opens before a cross-worker compensating Delete fits its dedicated reserve;
  final TailAck is withheld if `present=true` remains above the baseline
  reserve. Increase and safe decrease retire
  both fabrics and reconnect with the same process ID plus the new immutable
  tuple; an in-place changed capability is rejected. A decrease below either
  current local/peer occupancy, any derived-surface occupancy, or current ledger
  occupancy fails prepared apply before helper/config mutation and leaves the old
  transport/capacity operational. Overflow in worker-sum or any 1x/2x/4x
  conversion fails closed rather than saturating or advertising zero.

  Populate each kernel family independently to its all-v4/all-v6 2x boundary
  and prove a missing kernel-map row is a typed partial result, never successful
  continuity. Populate each dynamic-only DNAT family independently to its 1x
  boundary; one additional reverse-NAT row fails before shared/BPF/worker
  mutation and a partial map write remains typed ambiguity debt. Add, change,
  delete, roll back, and replay arbitrarily many configured static-NAT rules:
  neither advertised DNAT capacity nor either pinned map changes, because those
  rules live only in the immutable Rust snapshot. A source canary requires
  capacity accounting to include both `sessions`/`sessions_v6`, rejects any
  compiler static-key enumerator or `flags=1` capacity term, and proves all-v4
  and all-v6 dynamic occupancy independently. Seed legacy `flags=1`, dynamic,
  and malformed rows in both old maps at a full v2 dynamic boundary, with no
  historical packet invocation in this case. Prove none enters v2, no userspace
  migration operation modifies them, and v2 capacity credit derives solely from the
  stable coordinator's typed dynamic companions. Population/readback failure or
  old/v2 identity ambiguity keeps readiness closed.

  Drive `maybe_enqueue_local_tunnel_session` past its new auxiliary cap while
  normal workers and peer reserve are populated. The next new tunnel key fails
  before shared/BPF/worker publication, increments its dedicated metric, and
  does not consume peer/tail credit; refresh of an existing key remains
  idempotent. A source canary requires every non-peer shared-store forward
  origin to name either worker-local or auxiliary credit, so a future uncapped
  producer cannot bypass `SessionCapacityPlan`.

  Enumerate all eight current `SessionOrigin` values against worker local,
  promoted local, local-auxiliary, capable-peer, and legacy-transport
  provenance for forward, reverse, materialized, promoted, and worker-replica
  records. Every legal combination
  has the expected export, inventory, capacity, promotion, and delete authority;
  every illegal combination fails before shared/BPF/worker mutation. In
  particular a local tunnel row with `origin=SyncImport` and
  `provenance=LocalAuxiliary` is counted locally, omitted from peer inventory,
  cannot delete a peer row, and is not exported as a worker-owned session.
  Changing only its origin cannot change those facts. A source canary rejects
  `is_peer_synced()` in each authority-sensitive module while retaining an
  explicit allowlist for install/replication mechanics.
  Seed rows from the current and a replaced peer process: inventory includes
  both capable-process provenance classes plus an old legacy-transport class,
  preserves generation only for the current capable process, and makes absent
  old-process/legacy rows stale candidates. An empty new peer bulk removes the
  old rows; filtering only the current process fails the test. Promote a
  capable-peer row and prove the resulting local provenance retains its source
  namespace and checked handoff serial. Demote it through successful exact
  capable TailAck and ownership commit and prove it becomes peer authority for
  only that target process. Repeat with a legacy peer, no peer, failed TailAck,
  ambiguous TailAck, and invalidated ownership: positive forwarding/export
  closes, but provenance remains quarantined local authority with debt until
  exact cleanup or handoff. Reconnect cannot relabel any of those rows under a
  fresh process or transport namespace. For legacy reconnect, prove a member in
  the exact current BulkStart/End window rebinds an old-transport row, absent
  old rows reconcile away, and a delayed Open/Delete from the retired
  incarnation cannot mutate either result. Ordinary current-transport legacy
  replacement retains compatibility but never creates a capable generation or
  continuity bit.

  Unified migration tests start with a saturated old 262,144-entry
  `userspace_sessions` pin whose rows are a deliberately partial alias subset,
  both old DNAT maps containing static/dynamic/unknown rows, and a stable
  coordinator whose complete aliases and typed reverse companions deliberately
  disagree with every old map. Wrap every userspace old-map FD so any migration
  lookup/update/delete is a test failure. After
  admission closes, the fixed lane scheduler/barrier coordinator stop and join,
  all lane records recycle, and structural writers join, populate all three v2 maps from
  the one coordinator serial and prove their exact membership/count equality.
  With no historical packet invocation, old bytes remain unchanged as a useful
  diagnostic, but byte equality is not the invariant. Release paused historical
  writers after hook cutover and require their expected old-only mutations while
  every v2 membership/count proof remains unchanged. Concurrent current Open,
  Close, refresh, expiry,
  GC, allocator transfer, interface add/remove/rebind, and config apply are
  rejected before structural mutation while links span generations.

  Drive the journal through `prepared`, durable `forwardOnly`, each exact
  native/generic-XDP target receipt and TC/TCX detach receipt, final readback, helper-handle
  switch, durable active-manifest publication, and durable `committed`. Before `forwardOnly`, a failure proves no hook
  changed and permits target rebuild. From `forwardOnly` onward, fail the second
  of three interfaces and every later boundary. A same-process retry completes
  the recorded target. A new-process restart, including after `committed`, validates the recorded source/
  target full program identities, all six authority-map IDs/ABI digests, the complete
  retained-infrastructure map-ID manifest, eligible-hook digest, and
  coordinator-derived expected counts/diagnostic digests plus exact row-
  membership receipts; crashes before/after each typed quarantine-program pin
  and their durable identity record; durably enters `recoveryQuarantine`;
  crashes before/after each exact quarantine receipt; builds and records one
  fresh successor generation; and crashes before/after each XDP successor and
  TC/TCX detach receipt. Every restart completes remaining hooks forward. It never rolls a changed
  hook back, selects the old program for a new hook, rebuilds a target map behind
  a live hook, or performs a userspace lookup/update/delete on an
  old/previous-target map.
  Repeat from no-journal legacy hooks and prior-process `prepared` hooks.
  Interface-set drift, an `already attached`
  string without an exact receipt, a stale/incompatible v2 pin, a torn/corrupt/
  unknown-version journal, or all-v2 hooks without the matching record fails
  closed without guessed unlink or generation.

  Hold the bounded instrumented native/generic-XDP and TC/TCX tail-call/writer
  fixtures across final hook replacement and removable fixed-alias unlink. Each
  completes through its capsule-retained tail target and may produce its exact
  isolated packet-side map mutation; v2 bytes and behavior do not change. The
  capsule remains rooted for the rest of the boot rather than guessing when an
  old-object lifetime ended. The exact
  historical binaries run their before/after equivalence cases around the same
  transition. Swap a different object
  beneath each old pin path before unlink and prove it is reported but never
  removed; crash after a valid unlink but before its receipt and prove absent
  recovery is idempotent without recreating the pin. Then prove all XDP hooks
  select v2, every owned legacy TC/TCX reader is absent, all daemon/helper
  accessors name v2, the final v2/coordinator
  barrier passes, `committed` is durable, and subsequent structural mutations
  touch v2 alone. Peer absence, a legacy-only peer, or failed capable repair
  cannot prevent local retirement and cannot cause rollback; HA continuity
  remains false independently. Restart with no retained Rust store proves all
  three v2 maps start empty and continuity stays false rather than trusting old
  pins. Generated Go/Rust map-name, max-entry, map-flag, key/value-size,
  alias-factor, dynamic-value, complete program-map-reference manifest,
  active-accessor, hook-provenance, hook-receipt, journal-phase,
  isolated-old-object/no-userspace-old-map-access, and forward-only recovery canaries fail on one-sided
  drift.

  Cold-order tests prove no sender bulk occurs merely from `installConn` or
  `OnPeerConnected`. An unprotected or config-sync-disabled receiver requests
  after initialized registration; a protected receiver requests only after its
  successful baseline. Sender session producers remain closed until the exact
  requested bulk TailAck. A config send and ownership transition
  clear authorization and close them again. Request-ID-zero maintenance bulk is
  refused independently when either the sender's outbound or receiver's inbound
  authorization is absent and accepted only after both ends complete their
  respective requested-bulk TailAck transition. Capable config send writes the
  sender generation/digest trailer then a 48-byte peer-snapshot request with
  that same local sender epoch on one connection; receive verifies the text
  digest, captures the remote epoch, applies, commits one independently
  generated local epoch, services the request only by digest equivalence, and
  emits the reciprocal request with its own local epoch. Its 56-byte capable
  BulkStart declares that responder epoch; the 96-byte BulkEnd adds the exact
  member count/digest and the exact 96-byte BulkAck echoes it.
  Malformed trailers, zero epoch, request/config digest mismatch, and old
  8-byte type-29 input are refused in capable mode.
  Active/active fixtures prove both ownership directions re-prime. Config send,
  config receive, and ownership/transport changes clear both authorization bits.
  Simultaneous bidirectional initial requests complete without lock coupling or
  cluster-originated install/delete feedback into either outbound queue.

  Outbound tests pause every producer entrypoint, force pre-drain frames across
  both fabrics, and capture the drain token's exact used-connection set. The
  sender barriers the union of used and current-live members and revalidates the
  frozen registry before BulkStart. A used connection disappearing before the
  fence, a join/replacement, wrong-fabric ACK, timeout, or disconnect retires the
  whole transport. A late frame from a vanished used connection can never be
  followed by a bulk in that transport. Deferred ordering, pre/post-start
  overflow, direct-write failure, tail-flush failure, delete preservation,
  mandatory follow-up bulk, Stop cancellation, and producer reopening are
  fail-on-revert cases.
  Config send is paused before and after drain/fence revalidation; its authority
  generation always cancels/joins the old bulk before the config frame and no
  old-generation BulkStart can follow it. Pause an old config/request writer
  after token validation: an invalidator cannot mutate its token until the
  writer releases `writeMu`; if the invalidator owns the write fence first, the
  writer emits nothing. Pause the config writer between its
  config and request writes, then inject received config and any RG transition:
  the second token check suppresses the stale request, retires the transport,
  and ownership commit joins the old writer.

  Authoritative-source tests place ordinary opens/deletes in every captured
  worker live-delta buffer, then export a different owner-session table. Only
  records from the request-private SPSC channels become direct bulk members;
  reverting to a shared-buffer drain fails by count, key set, and digest. The
  control response is small and completes before the member stream; treating it
  as snapshot completion fails. Wrong `SO_PEERCRED`, UID, PID, nonce, helper/
  snapshot generation, private version, export ID, stream-sequence gap, frame
  type/size, second connection, early EOF, Abort, and Final-without-all-workers
  each cancel/join the exact stream and retain debt. The runtime socket remains
  mode 0600 and an old helper cannot connect after replacement.

  Delay one worker channel/WorkerDone/boundary, mutate sessions before and after
  that worker's cut, and delay EventStream callback delivery past private Final.
  Queue a pre-cut event behind worker-local producer work and prove its sequence
  is lower than that worker's boundary; replacing the boundary with a post-ACK
  `next_seq` sample makes the test fail. The sender authenticates Header, writes
  BulkStart, incrementally validates and direct-writes every member without a
  snapshot-sized allocation, verifies helper source count/digest plus the exact
  worker-set/boundary watermark, then writes a 96-byte BulkEnd carrying the
  independently computed capable-wire count/digest. The receiver rejects a
  duplicate canonical key before install, verifies its own count/digest, and
  echoes the exact 96-byte ACK. Cross-language generated goldens fail if a
  source field is omitted or if source and capable-wire digests are accidentally
  conflated.

  First-capable inventory tests seed the coordinator shared store with same-zone
  local-origin, peer-synced forward, and synthesized-reverse rows, plus divergent
  worker replicas. Only authoritative peer-synced forward rows appear; worker-
  only rows and local/reverse rows do not. Mutate, delete, and reuse stable slots
  between every scan slice: unrelated local-only churn leaves the filtered
  result exact, while any peer-domain change or origin transition aborts before
  Final and sends no type-29 request. Poison
  recovery, serial exhaustion, a wrong stream mode/serial/origin, and malformed
  free/index/slot invariants fail initialization. A source canary rejects direct
  access to the old `FastMap` representation or inventory from a worker table.
  Simultaneous local inventory and outbound owner export
  serialize on `helperSnapshotStreamMu` without confusing leases or blocking
  packet polling; cancellation releases the slot and retains baseline debt.
  Before activation, benchmark shared-session lookup, publish/replace/delete,
  reconcile snapshot/replay, and maximum-capacity memory against the current
  `FxHashMap`; reject more than 5% p99 regression or any extra full-entry copy.

  Advance one worker's `sessionDeltaLossEpoch` before sequence assignment at
  each point from export admission through scan boundary, private Final,
  phase-2 capture seal, final-bank drain, TailEnd, and TailAck. Scan-phase
  movement produces Abort/no BulkEnd; capture-phase movement produces no
  TailEnd; post-terminal movement invalidates the pending ordinary/continuity
  token and retires rather than being hidden by a resync that clears the Boolean
  loss latch. Unchanged epoch vectors round-trip through Header, WorkerDone,
  Final, boundary payloads, and Go token digest. Counter exhaustion takes the
  controlled fail-closed process path. A fail-on-revert test sets then consumes
  the old Boolean latch while leaving the epoch changed and still requires
  failure.

  A worker timeout, missing/duplicate WorkerDone or boundary, nonzero legacy
  export cap, stale helper source, EventStream gap, capture overflow,
  response-without-stream, Final-without-watermark, source or peer-wire digest
  mismatch, duplicate canonical key across workers, or config/helper transition
  suppresses BulkEnd or retires a post-start transport with repair debt. An
  empty but complete Final is authoritative; an empty incomplete/aborted stream
  is not. A source canary fails if capable bulk calls `export_all_sessions`,
  consumes its async callbacks as members, uses `drain_session_deltas`, exposes
  a full member vector/JSON result, or emits BulkEnd before private Final and the
  EventStream watermark. High-cardinality tests enforce bounded RSS with a full
  configured session population, the 180-second stream/write deadline, and the
  separate 180-second post-ACK drain deadline; heap profiling rejects one full
  Rust snapshot vector, one second Go snapshot-member vector, and per-member
  string allocation beyond the single bounded generation-ledger representation.

  Fill a worker's 1,024-record SPSC channel while the private socket is blocked:
  export scan pauses at the same cursor and packet batches continue within the
  latency budget. Fair coordinator draining prevents a busy low-ID worker from
  starving the others. More than 4,096 repeated updates to a small key set
  coalesce and complete; shared tail credit exhaustion by one additional unique
  key fails closed with bounded memory. Open/delete churn for a key not emitted
  by the snapshot still emits exactly one idempotent later-generation Delete;
  the streamed design has no baseline set on which to discard it. Drop the
  helper event connection after recording a boundary but before its cumulative
  ACK: exact replay matches the sole retained token and does not restart the
  bulk; an unknown export/worker boundary fails closed. A second export cannot
  start until the retained token is ACK-covered.
  With a full 131,072-session worker, a fake poll clock proves every export-scan
  slice stops at 256 slots or 50 microseconds and packet batches run between
  slices. Create/delete/reuse slots on both sides of the captured high-water;
  applying the scan plus coalesced tail yields exact final table truth. Reverting
  to one full-table worker-loop copy fails the latency-budget canary and
  benchmark.
  Tuple-release fence tests pause worker 0 after removing B/T but before the
  Close obtains a global EventStream enqueue receipt. Worker 1 cannot allocate T
  to A, and a forced bank detach cannot contain `Open(A,T)`. After the ordered
  protected arena accepts `Delete(B,T)`, release T, let worker 1 allocate it with that
  predecessor sequence, and force another detach: the wire contains Delete in
  the same or an earlier bank than Open. Repeat for producer backpressure,
  enqueue failure, timeout/disconnect, helper replacement, and pool SNAT,
  address-only, persistent/shared lease, deterministic CGNAT, NAT64, and NAPT64.
  Fill all 1,024 per-worker slots: expiry defers without freeing a tuple, urgent
  removal fences/fails closed, and occupancy/age telemetry rises. Releasing the
  allocator token before a valid receipt or omitting the predecessor sequence
  makes the hostile cross-worker test fail.
  Hold cumulative ACK at `d-1`, obtain Delete sequence `d`, disconnect the event
  socket, and fill every protected general, boundary, and tuple-Close slot plus
  one from multiple workers while telemetry also wraps its replay queue. The
  protected Delete remains byte-exact: with a contiguous replay it precedes any
  continued Open, while an intervening telemetry gap makes the generation
  terminal and permits no continued Open before repair. The overflow Close
  receives no sequence/receipt and retains its tuple. Repeat
  through same-helper reconnect, Stop, config-driven helper replacement, and
  forced helper death: only terminal generation teardown may discard `d`, and
  no later ordinary/capture output opens before authoritative repair.
  Independently fill the telemetry quota while critical credit is empty: one
  Close still obtains a critical ring reference and sequence in order. Filling
  the critical quota makes the next Close retain its tuple but cannot be caused
  merely by telemetry pressure; reverting to one shared quota fails this test.
  Pause after the protected Close becomes ring-visible but before its pre-
  reserved predecessor record enters the tuple index. ACK `d`, reclaim and
  reuse the protected frame slot, then resume release: the generation-stamped
  stable record has already captured the ACK, catches it up before free
  visibility, and never dereferences the recycled slot. Repeat with ACK before,
  during, and after index publication and assert no missed ACK, double
  retirement, stale-slot alias, or false predecessor. Cancel before ring
  visibility (both reservations return) and after it (the stable record remains
  ACK-addressable until publication or terminal generation join); neither path
  reuses a record under an ACK callback.
  Recycle the originating worker's pending slot after `d`, then allocate,
  rollback, reallocate, and exact-reserve T from another worker in pool PAT,
  address-only, persistent/shared-lease, deterministic-CGNAT, NAT64, and NAPT64
  modes. Pause after predecessor-record publication but before ownership becomes
  free and prove no claimant can bypass it. Fill the fixed predecessor arena;
  one extra release leaves ownership occupied. Race local cumulative ACK against
  a claim: ACK alone marks replay complete but cannot retire a remotely required
  predecessor; the claimant moves the exact record and every later capable
  Open/Update carries the descriptor until a complete covering barrier resolves
  it. No path
  returns a false zero.
  Rollback restores the same slot before free visibility. Generated capacity and
  byte canaries fail if a mode omits the predecessor adapter or silently grows a
  side map. Max-address/max-port-range configurations prove predecessor memory
  stays records+indexes+256 shards rather than scaling with every port; exact
  64-MiB including alignment succeeds and one byte/record/index slot beyond it
  rejects before allocator or worker construction.
  For a persistent/shared lease, protect Close C1 while another flow keeps the
  lease active, then admit two concurrent same-lease reuses before either Open
  enqueues. Both take checked handles to C1's high-water and cannot enqueue
  before it; rollback of one does not clear the other's handle. Add C2 before
  reuse and prove the lease carries max(C1,C2), with cumulative ACK and all
  handle discharges required before slot retirement. Locally ACK C2 while both
  handles remain outstanding: remote debt keeps it linked. Complete a covering
  barrier; lease high-water then unlinks/repoints, a third reuse does not acquire
  C2, but C2's slot cannot recycle until the first two handles discharge. Then create
  `workerCount * 1,024` two-flow shared leases, Close one flow in each, ACK every
  Close, discharge every handle, and leave the other flow in every lease active
  indefinitely with no later Open. While the peer stalls before applying the
  Deletes, the arena remains full: local ACK alone does not unlink a remotely
  required row. Complete the exact all-current-fabric barrier covering every
  assigned Delete generation. Every now-two-dimensionally-covered record
  unlinks, each high-water becomes zero, each shell transfers its physical token
  back to the still-live exact lease and recycles, and the complete predecessor
  arena is reusable. Close a flow from lease N+1 immediately afterward and
  require a fresh shell; tying shell retirement to lease idleness or local ACK
  alone makes this fail.
  Crossing 75 percent emits exactly one generation-coalesced protected
  `PredecessorPressure` event and closes Rust tuple creation before the arena is
  full; further closes do not flood the critical arena. A valid completion batch
  plus occupancy below 50 percent clears the latch. Drop or exhaust admission of
  that event and prove helper health and tuple creation remain fail-closed rather
  than relying on a telemetry poll.
  Repeat with only one fabric ACK, a wrong process ID, a replaced connection,
  G one below the last Delete, and barrier timeout: none recycles a record and
  tuple admission stays closed until terminal repair owns the debt. With session
  sync administratively absent and no peer authority in the daemon namespace,
  prove `notRequired` may recycle after local ACK; enabling sync first closes
  admission and completes authoritative initialization. Disconnect a previously
  authorized capable and legacy peer before Close creation: both records retain
  remote debt, and mere lack of a live producer never selects `notRequired`.
  Close the last flow of an unACKed persistent PAT lease, expire it through the
  allocation-triggered path and separately through chunked global/per-address
  GC, and pause after lease-index removal and before physical bit clear. Race
  cumulative ACK and another worker's claim at every point: the fixed shell and
  tuple index remain authoritative, the claimant either carries the predecessor
  or observes complete local-plus-remote resolution, and deferred-free completion cannot retire a
  record the claimant moved. Repeat for persistent NAT64/NAPT64 and address-only
  persistent members to distinct remotes; the latter clears no unrelated port
  bit and retains every member reverse predecessor. Outstanding reuse handles
  defer expiry, and deleting the lease-map entry or calling raw
  `free_translated_port` trips a source canary.
  While one predecessor is free-pending and another is moved-live, commit a
  pool/prefix/mode and worker-count change. The old allocator either drains
  before publication or remains the sole fixed retiring generation; a second
  replacement returns busy, tuple coincidence in the new pool cannot steal its
  metadata, and timeout reaches helper replacement/continuity-false repair
  rather than dropping the old arena.
  Make the first tail bank larger than the ordinary send queue and pause its
  direct writer; new events enter only the second bank. The sender drains both
  banks on the exact bulk connection, atomically observes the replacement bank
  empty, and reopens without an overtaking normal event or third allocation.
  Fill the second bank while the first is detached and prove the next unique key
  fails closed. Sustained churn through the absolute tail deadline retires the
  transport and preserves delete/repair debt; it never reports continuity or
  spins forever waiting for an empty bank.
  Start from B owning translated tuple T, then capture `Delete(B,T)`,
  `Open(A,T)`, `Open(B,U)`. Even though all three operations fit one ordinary
  128-frame batch, the detached bank emits B's release, exact release
  `TailPhaseEnd`, both final Opens, and exact acquire `TailPhaseEnd`; the receiver
  commits release escrow before preflighting A/T and installs A/T plus B/U.
  Repeat with a two-key swap, a three-key cycle, final Delete, same-key
  delete/reopen, phase boundaries at 127/128/129 frames, and the same key
  returning in a later bank. Generated private-event goldens prove Close carries B/T's exact
  pre-delete descriptor and NAT-rebind/promotion Open carries both incumbent and
  after state; generated Go/Rust capable-wire goldens prove exclusive member,
  persistent-shared group, and per-flow member reservation identities are byte-
  exact, config-derived, and included in the frame-size bound. Tampering any
  identity field or mismatching a member with its group rejects before allocator
  mutation. Reverting to today's key-only Close or after-only
  promotion fails before coalescing. Duplicate final tuple claims and a tuple held by an
  untouched peer reject without deleting the foreign row when the reservation
  member/group identity is exclusive or incompatible; local/static ownership
  always rejects. In contrast, seed two or more permit-any-remote persistent
  sessions with one byte-identical source-key/pool group sharing T. For address-
  only persistent NAT, send them to distinct remote endpoints and prove their
  per-flow reverse member keys differ while their lease-group identity remains
  byte-identical. Touch one while another remains untouched, then touch and
  release/reacquire both across separate bank boundaries: sender grouping admits
  them, escrow preserves each member token plus starting/untouched/released/
  acquired group refcounts, and receiver teardown ends at the exact live count.
  Pause after the release marker has dropped a shared lease to zero active
  members for longer than its persistent timeout but before acquire. Race
  allocation-triggered, pressure, per-address, and chunked background GC for
  PAT, NAT64/NAPT64, and address-only persistent modes: the exact group expiry
  fence was acquired before decrement, every GC path leaves lease/expiry/member/
  physical ownership intact, and acquire or ambiguity cleanup alone discharges
  it. Repeat with timeout, disconnect, helper replacement, partial release, and
  partial acquire; a stale/double fence discharge or allocator-generation
  teardown with a live fence remains typed debt and never frees the tuple.
  Repeat with partial release and acquire commits; ambiguity debt retains the
  typed group lease and every affected member token. A duplicate member reverse
  key, changed source key, target-host remote scope, pool identity, or sharing
  mode makes the same translated T reject before mutation; a distinct remote
  under permit-any changes only the member key and remains compatible. Poison
  either coordinator member ownership or group refcount versus allocator truth
  and prove the release marker fails before decrementing either. Failure
  before and after both phase-marker commits enters ambiguity escrow and never
  returns a possibly exposed tuple to local allocation. Wrong/missing/duplicate
  phase, noncontiguous bank serial, nonzero pad, count/digest mismatch, Open in
  release, Delete in acquire, or TailEnd before acquire-marker completion fails
  before the next phase mutates. A fail-on-revert coalescer that
  retains only final per-key states fails the B/T trace. Phase-2 worker
  boundaries capture mutations racing the first empty-bank observation. Delay
  the finalize control response, decode the in-band seal at sequence S, then
  deliver S+1 and S+2 mutations of the same key: the seal callback detaches the
  <=S bank before either later frame is decoded, and both later frames enter the
  closed ordinary queue. Removing the in-band callback rotation fails the test.
  Advertise a peer tail-row ceiling smaller than the local byte budget and prove
  the next unique row fails before emission while an update to an existing row
  in the same active bank still coalesces without row credit. Reappearance after
  a detached bank consumes conservative new row credit. Asymmetric logical session maxima prevent capable setup
  before BulkStart rather than failing halfway through a legitimate full source.

  Receive tests bind membership to one exact capable connection. A session frame
  on the other fabric while receiving or reconciling is a protocol violation,
  invalidates the window, and retires the transport. Config during receiving
  aborts then applies; config, ownership change, disconnect, and Stop during
  reconciliation cancel and join the worker before new authority proceeds.
  BulkStart sets table taint before the first dataplane call. Abort after zero,
  one, and many installs leaves current continuity false and blocks both manual
  transfer and previous-good automatic takeover until a fresh exact bulk
  completes baseline and tail reconciliation and TailAck postcommit clears
  taint. A prior previous-good bit alone can never authorize promotion of a
  partially mutated table. Wrong 56/96-byte
  marker lengths, repeated-prefix mismatch, member count/digest mismatch, and
  duplicate keys all fail with no ACK and persistent taint.
  Drive more than the legacy 200,000 generation-map rows through a capable
  baseline and prove every operation remains nonzero and guarded. A failed bulk
  leaves the working ledger non-authoritative and table taint set but preserves
  every observed high-water; baseline reconciliation removes unseen rows and
  final TailAck alone authorizes it. An
  absent-key tail Delete records a tombstone and rejects a delayed
  lower-generation Open. A lower-generation same-process re-bulk is rejected
  against the working ledger, while a new process namespace resets the scalar
  floor/barrier receipt and may start lower without inheriting stale rejection
  from the prior process.
  Interleave ordinary operations across both fabrics, fence them, and prove the
  bulk freezes their maximum without globally rejecting legitimate pre-fence
  cross-fabric reorder. Equal/decreasing baseline or tail generations fail;
  a partial batch retains its highest admitted wire generation and a retry from
  the same sender starts above it.
  Same-key owner tests pause an operation from fabric 0 after preflight, after
  the first Rust/helper mutation, and after helper success but before final Go
  ledger/derived-surface commit. A higher generation arriving on fabric 1 owns
  no mutation and snapshots no incumbent until the predecessor releases the
  stable-slot owner; it then derives the actual committed predecessor and
  completes. Queue generation 12 before delayed generation 11 behind owner 10
  and prove the fixed intrusive queue applies 11 then 12; arrival after 12 becomes active
  rejects 11 as stale. Reverse arrival and alternating eight-deep sequences
  preserve generation and tuple ownership; a ninth waiter returns busy before mutation.
  Fill all 24,576 global lane records across distinct keys/batches and prove one
  additional owner or waiter fails before mutation without growing any ledger
  row; releasing a completed record permits exact handle reuse without ABA.
  The generated 64-MiB arena boundary succeeds exactly and a one-byte or one-
  record overflow rejects helper/capability startup.
  A partial or response-lost owner keeps its owner descriptor and allocator
  escrow, cancels every unstarted waiter into bounded repair, and permits no
  successor after disconnect or one-fabric replacement. Cleanup plus fresh
  authoritative inventory may install the next exact owner once; a wire
  `before` projection never overrides the actual repaired incumbent. Removing
  the per-key owner CAS or releasing it at helper response rather than final Go
  commit makes each fail-on-revert trace expose overlap.
  Cross-fabric tuple-dependency tests allocate `Delete(B,T)` on fabric 1, pause
  it before receiver mutation, and deliver `Open(A,T)` on fabric 0 first. The
  Open's exact 88-byte descriptor occupies one mutation-lane dependency variant,
  performs no allocator/helper/BPF/worker mutation, and wakes only after the
  exact peer-owned B/T Delete commits or a covering scalar floor plus allocator
  proof exists. Reverse arrival applies immediately with the same result. Repeat
  with response-lost/partial Delete, missing Delete, wrong generation, digest
  tamper, local/static/wrong-peer predecessor, predecessor tombstone compaction,
  and connection/config/helper retirement; every non-exact case taints and
  requests repair rather than releasing T. Fill eight waiters on one translated
  target and all 24,576 global lane records; the next dependency returns busy
  before mutation, and tombstone/floor compaction waits for all checked handles.
  Generated Go/Rust goldens prove canonical-zero descriptor semantics and exact
  frame-size/capability negotiation; removing `tuple-predecessor-v1` from either
  fabric forces legacy single-active-fabric ordering and never emits the trailer.
  On the sender, ACK the protected EventStream Close before Go assigns its wire
  generation and prove the stable allocator record remains remotely unresolved.
  Bind the nonzero generation through the generated fixed helper batch, then
  move the checked handle into A/T. Emit A's Open on fabric 0 and a later Update
  on fabric 1 before either is received; both carry the byte-identical descriptor
  and neither resolves the record. Deliver the Update first and prove it waits
  for B/T's exact Delete just as the Open does. A stale handle, duplicate bind,
  zero generation, wrong helper/process/transport, ambiguous control response,
  successful socket write, or merely constructing bytes cannot resolve the
  record. Assert explicitly that descriptor emission plus successor-handle
  discharge still leaves B's predecessor remotely unresolved. Close A before a
  barrier, create its new fixed Close record, and prove
  T cannot move to C; it remains withheld behind the per-target chain until the
  older B predecessor resolves, with no truncated descriptor chain on wire.
  Build the two-key ordinary swap `Open(A,T2)` -> `Delete(B,T2)` and
  `Open(B,T1)` -> `Delete(A,T1)`, deliver both Opens first on different fabrics,
  and prove they occupy non-owning dependency waiters rather than A/B owner
  handles. Deliver both lower-generation Deletes afterward; each inserts ahead,
  commits without a cross-key cycle, then promotes the matching Open. Reverting
  either waiter to owner-before-dependency deadlocks the deterministic test.
  Enter that trace through the two production TCP read loops, not by calling a
  lane helper directly: both loops must return after admitting their Open, both
  later Deletes must reach the intrusive ready FIFO, and fixed executors must
  commit the Deletes and then the Opens. Deliver barrier markers before and
  after each promotion and prove the fixed barrier coordinator emits no ACK
  until every through-G token is final without occupying a read loop. Fill all
  24,576 lane records with a mix of owners, same-key waiters, and dependencies,
  then prove record 24,577 fails before enqueue or mutation; no executor waits
  on a predecessor and no goroutine/queue/channel allocation grows with the
  record count. Cancel one fabric, Stop, helper replacement, and v2 migration
  at every enqueue/run/final-commit boundary. Each closes admission first,
  drains or records exact debt, joins all 64 executors plus the barrier
  coordinator, and migration refuses map freeze until the arena and ready FIFO
  are empty with no ambiguity.
  With no
  successor, freeze G, drain both writers, and exercise the exact two-fabric
  barrier: deliver only fabric 0's marker and prove no ACK and no scalar-floor
  movement; after fabric 1's exact marker arrives, ACK callbacks wait for every
  <=G barrier-admission token through final ledger/journal commit. Admit
  `Open(A,T)@12` as a dependency waiter, pause `Delete(B,T)@10` immediately
  before, during, and after waiter promotion, and deliver both G=12 markers.
  The waiter keeps one token through promotion; partial/timeout Open completion
  emits no ACK and moves no floor. The receiver commits
  its complete frozen receipt/floor before releasing either ACK writer, and only
  the sender's complete echoed receipt remotely covers its predecessor records.
  Exercise both callback orders: local cumulative ACK before the echoed barrier,
  and complete echoed barrier before local ACK. In the latter case the retained
  namespace-qualified receipt covers the still-local-pending record and the
  later ACK performs catch-up retirement. Repeat with 129 and a full arena of
  predecessor records so the fixed 128-record barrier cursor crosses batch
  boundaries; tuple admission cannot reopen between cursor slices and no covered
  row is stranded.
  Disconnect/rejoin one fabric, return
  one ACK, leave one <=G owner or waiter partial/ambiguous, echo G-1, reorder callbacks, or
  exceed five seconds; no row recycles,
  tuple admission remains closed, and terminal repair owns the debt. Fixed-batch
  127/128/129 cases and one-byte Go/Rust layout drift fail before startup.
  Terminate an EventStream generation after a Close is protected and remotely
  ordered but before its cumulative ACK. A replacement baseline alone cannot
  recycle the record. Join the old workers, producer/I/O, replay arena, and
  allocator generation, then make authoritative repair either transfer the
  exact predecessor/token or prove and tear down every old surface. Only that
  receipt marks terminal local replay and permits retirement. Run ordinary
  maintenance immediately, without another barrier or pressure event, and prove
  the shared `localReplayComplete` predicate unlinks the record and shell. Repeat until every
  arena slot has recycled and prove an impossible old-generation ACK is never
  awaited; omitting the terminal local state leaks the first slot.
  A peer Open naming an unknown/local-owned zone or colliding with a local-origin
  backend row fails before mutation. Unknown Delete is tombstone-only and leaves
  a same-key local-origin session byte-identical; a known peer-synced Delete
  removes its forward/reverse/BPF companions.
  For pool SNAT, address-only SNAT, deterministic CGNAT, NAT64, and NAPT64,
  occupy the imported translated tuple with a different local flow and prove the
  peer Open returns a typed conflict before shared/BPF/worker mutation and emits
  no ACK. Inject failure after each successful tentative allocator reservation:
  failures before the first external mutation roll back the exact token once,
  while failures after shared/BPF/kernel/worker mutation move it to ambiguity
  escrow and make it unavailable to concurrent local allocation. A successful
  batch transfers ownership to normal peer-session teardown and a same-key
  retry is idempotent. Foreign pool/prefix provenance under a claimed
  equal config digest is a hard config/repair failure, not the current silent
  skip. Concurrent local allocation cannot enter between reservation preflight
  and batch commit.
  Replace translated tuple T with U while U is occupied and prove T plus every
  incumbent persistent/shared-lease refcount remains exact. Repeat with T==U,
  free U plus failure after every derived-surface prefix, changed address-only
  translation, persistent source-key reuse, and NAT64 reverse identity. Success
  releases T only after U is fully published; ambiguity quarantines both until
  cleanup chooses or removes the surviving state. Reverting to destructive
  `reserve_flow` or the address-only "return old tuple" shortcut fails these
  tests.
  Wire tombstones above `retiredGenerationFloor` survive TailAck and disappear
  only after a later generation-bearing all-fabric barrier covers them; aborting
  before that barrier preserves them. Fill the derived ledger capacity and prove
  the next new key fails before dataplane mutation, closes admission, and
  requests a fresh bulk rather than clearing the map or degrading to generation
  zero. Parameterize `peerForwardReserve=N` and tail reserve as 1, 127, and
  `N-1`; replace a full disjoint N-row baseline with N new keys while delayed
  lower-generation frames wait on the other fabric. The pre-bulk barrier folds
  each old high-water into the scalar floor. Inspect occupancy after every one of
  128 decodes with `R=1`: all incoming rows remain in the fixed staging index,
  committed ledger occupancy stays N, and each staged row binds one exact old-
  to-new transition rather than allocating row N+2. Inspect every physical
  Delete/Open prefix: the incumbent slot and journal retain both identities on
  ambiguity, complete success atomically rekeys it, live rows plus above-floor
  tombstones never exceed `N+R`, and every delayed frame at/below the floor is
  rejected without recreating a row. A real Delete above the floor remains a
  tombstone until a later covering barrier. Reverting to 2N storage, deleting an
  above-floor tombstone, inserting the second decoded key directly into the
  ledger, or retaining every internal eviction as a second row fails the exact
  slot/free-stack/staging-index canary.
  Pause the bound receive loop inside a real 128-frame baseline batch, enqueue
  `BulkEnd` behind it on the same TCP stream, and prove reconciliation/ACK cannot
  start until exact complete batch success decrements the token and changes all
  pending keys to installed. Exercise full, final partial, single-member, stale,
  capacity, helper-prefix, BPF-publish, cancellation, and transport-failure
  outcomes; every non-complete result invalidates the window and retains taint.
  Fill every receiving surface, then submit 128 disjoint baseline Opens that
  require 128 unseen live stale evictions. Preflight must reserve exactly 256
  lane and ambiguity-journal records; helper/shared/BPF/kernel/worker batches
  contain 128 explicit Deletes followed by 128 Opens. Fail after each physical
  mutation prefix and prove every old/new key has its own outcome, cleanup
  descriptor, allocator escrow, and stable high-water. A 129th wire Open rejects
  before the first mutation; physical record 257 remains legal only when
  derived from those 128 authenticated frames.
  Give a selected stale row retained generation G and inspect its internal
  Delete: it owns `{repairSerial,batchID,G}` with no wire generation, does not
  enter the higher-generation waiter FIFO or wire digest, and on complete
  deletion frees the stable slot because the pre-bulk scalar floor already
  covers G. Fail that Delete at every surface prefix and prove its slot/G remain
  ambiguity debt; clean it, then deliver a real later Open at G+2 followed by
  delayed G+1/G replays; only G+2 installs. Borrowing an incoming generation,
  using zero, advancing the scalar maximum without the barrier receipt, or
  erasing G before complete deletion fails the canary.
  Build the 384-operation worst case: every one of 128 incoming existing keys
  releases its own changed incumbent, and its desired tuple/member is owned by
  a different selected stale key that also releases before the Open. Build full
  translated-target permutations across that graph.
  Exercise two-way swaps, long cycles, unconsumed releases, and compatible/
  incompatible persistent groups across pool PAT, deterministic CGNAT,
  NAT64/NAPT64, and address-only persistent modes. Preflight reserves all
  member/group indexes and expiry fences without requiring a free bit; workers
  apply all 256 Deletes before 128 Opens. Failure after every one of the 384 physical
  prefixes retains exact tokens/refcounts/reverse members until origin-aware
  cleanup, and ordinary allocation cannot steal an escrowed tuple. Physical
  record 385 rejects before mutation, and 64 simultaneous worst-case batches
  consume exactly the 24,576-record global arena without hidden nodes.
  Add an incoming-only swap with existing `A/T1, B/T2` and desired
  `A/T2, B/T1`, plus 3-, 17-, and 128-key cycles where every available token
  comes from a same-key release arm and no selected stale-only key exists. Every
  release enters the shared replacement overlay, all releases commit before any
  acquire, and each acquire consumes the opposite exact token once. Fail after
  every release/acquire prefix and queue a higher-generation same-key waiter;
  ambiguity retains all tokens and the waiter cannot observe a false free tuple.
  Excluding same-key releases from the overlay makes the first two-key case fail.
  Seed one incompatible persistent-shared group with 2,129 members and then the
  configured maximum member count. Preflight installs one group plan and expiry
  fence, removes non-batch members in deterministic 128-Delete prerequisite
  requests, recycles each request's lane/journal/member-token records, leaves
  current-batch members for the final release phase, and retains only the group
  token/fence/cursor between chunks. Pause/fail at every chunk boundary,
  disconnect, replace the helper, expire the 180-second receive deadline, and
  request a second incompatible group; exactly one plan remains owned as debt,
  no tuple becomes locally allocatable, and the second plan starts only after
  the first either transfers atomically into a parked final-group record or
  reaches repair-terminal failure. Build a two-large-group cycle: current member
  X1 of G1 wants G2 while current member X2 of G2 wants G1. Delete/park X1 and
  all other G1 members, transfer G1's token/fence into fixed final escrow, reuse
  the one plan for G2, then park X2/G2 before either acquire. Both acquisitions
  consume the opposite parked token only in the final phase. Pause or fail at
  every member-delete and plan-to-park boundary, timeout, and disconnect; every
  completed park plus the one active plan remains exact debt and no circular
  wait or local free tuple appears. Reuse the plan slot for G2, then inject G1's
  stale plan generation, a parked-slot generation mismatch, duplicate cleanup,
  and timeout after G1 parks while G2 remains active. The tagged owner CAS leaves
  exactly one token/fence owner in every case and rejects the stale handle before
  mutation. Reverting to "leave current members for the
  final release" deadlocks this test. Arena/RSS stays independent of member
  count and every helper request remains at or below 128 physical Deletes.
  After a deliberately partial helper/BPF/worker result, assert
  `ledgerInventoryDirty`, refuse maintenance bulk, preserve the scalar maximum
  generation, mark every attempted key ambiguous, and preserve one fixed
  registry record per attempted key with complete before/attempted derived
  descriptors and both incumbent/attempted escrow. Require bounded origin-aware cleanup **before** fresh
  shared-store inventory or the next nonzero request. Exercise both
  an Open that reached only BPF/one worker and a Delete that disappeared from
  the shared store but remained in BPF/one worker. Re-inventory merges shared
  rows without dropping either ambiguous input key; exact revalidated deletion
  under the joined-writer recovery gate removes
  matching peer rows on every surface but preserves a same-key local row, newer
  peer generation, foreign BPF value, and malformed/unknown non-session map row.
  Only complete
  cleanup releases NAT quarantine; helper replacement rebuilds all surviving
  coordinator reservations and journal quarantine before local admission.
  Admit disjoint ordinary operations concurrently on both fabrics, make several
  results partial or response-lost, and prove each retains a distinct batch slot
  after the first failure closes new admission. Join all prior admissions, clean
  slots in batch-ID order, and reject a 65th simultaneous slot before mutation;
  no result overwrites another. A new batch after failure is refused until the
  retained registry is empty. The next full source
  replays truth, and only exact TailAck clears taint. Seed the shared backend with an additional prefix the old speculative
  ledger did not record and prove re-inventory discovers it for stale selection.
  At helper level, prove one ref-counted descriptor rather than 128 per-member
  commands reaches each captured worker, and that success waits for the exact
  worker-set acknowledgement vector. Fill one bounded import inbox, withhold one
  worker ACK, duplicate an ACK, change the worker-set generation, and cancel
  after a partial worker apply; each case returns an explicit non-complete result
  and cannot emit BulkAck or TailAck. A fake worker clock proves a queued batch
  yields to packet processing after 64 records or 50 microseconds, while a
  completion ACK cannot precede the last slice. A source canary rejects an
  unbounded worker command queue, per-member command fanout/cloning, or a helper
  response whose only guarantee is queued rather than applied.
  Block one worker after `prepare_cluster_sync_batch`, then prove status and
  urgent HA requests acquire `ServerState` while `ClusterSyncBatchWait` remains
  pending. Concurrent rebind/shutdown cancels and joins that wait before worker
  destruction; an old worker's late ACK cannot complete a replacement
  generation. Fill all 64 registry slots and prove the 65th returns busy before
  map/BPF/worker mutation. Reverting to a wait under `ServerState` must deadlock
  or fail the liveness canary.
  A source/performance canary rejects one helper RPC per member, a void helper
  outcome, an async apply, or membership-before-whole-batch-success. A
  deliberately injected nonzero token or pending key at BulkEnd retires as an
  invariant failure.
  Iterator/delete error and cancellation all suppress ACK, `bulkEverCompleted`,
  callback, continuity readiness, and debt discharge. A blocking fake proves
  `Stop` never uses the old five-second abandon path and no reconcile worker can
  touch a torn-down dataplane.
  Large v4/v6 stale sets prove iteration observes cancellation, deletes run in
  at most 256-row chunks, an early-stop nil iterator result is converted to
  `ctx.Err()`, and partial chunk completion remains repairable.
  Two-stage ACK tests make the sender return a deferred tail immediately after
  BulkAck: only the exact tail window admits it, while ordinary admission,
  continuity, maintenance authorization, and debt remain closed. Failed,
  partial, and delivered-then-disconnect BulkAck writes leave taint and publish
  no success even if a causal tail prefix installed. Each `TailPhaseEnd` flushes
  its final phase-only 128-frame batch within the 384-physical-mutation helper capacity synchronously; TailEnd is accepted
  only at the next-bank release boundary and rejects wrong session-frame count/
  digest. Send Open/Delete/Open for one key across three banks and prove each
  generation applies in wire order, every release-marker commit precedes its
  acquisition, the final Open survives, and all three session frames contribute
  to the TailEnd digest while markers do not; baseline duplicate-key rejection
  must not leak into this tail path.
  Freeze a receive window with advertised tail-row ceiling `R > 1`. Send
  `2 * R` monotonically generated session frames for one canonical key across R
  one-row banks and prove the exact frame boundary succeeds, charges one
  receiver unique-key row, accepts exactly `2 * R` phase markers, and requires
  TailEnd count `2 * R`; session frame or marker `2 * R + 1` rejects before the
  next decode/helper mutation despite the existing ledger slot. Repeat with `R`
  distinct keys and exactly two session frames per key. A parameterized window-
  unit test sets the frozen wire-byte ceiling to
  `sessionBytes + 112 * markerCount` and then one byte less, proving checked byte
  accounting runs before helper dispatch and is independent of key charging.
  Capability/window construction rejects `R` values that overflow either
  `2 * R`, either class product, their checked sum, or the generated 64-MiB
  transfer-escrow footprint. Wrong release/acquire
  phase count/digest and wrong TailEnd session count/digest at every boundary
  suppress TailAck and retain taint. The concrete B/T -> A/T+B/U trace runs with
  a batch capacity larger than the whole bank and still transfers the reservation
  only after the release marker; removing marker handling makes the test fail.
  In the zero-tail case, pause the receiver's BulkAck write after the peer has
  consumed the bytes, let the peer return TailEnd, and verify the receive phase
  advances to `tailAckWriting` without restarting the preinstalled tail
  deadline. Releasing the BulkAck syscall may mark it confirmed but cannot
  regress the phase; an injected ambiguous return wins the shared write fence
  and suppresses the waiting TailAck writer.
  Populate a maximum-size old table and stream a disjoint maximum-size baseline.
  Each new batch reclaims tombstones first and otherwise prepends enough unseen
  stale Deletes to stay within ledger/helper/BPF capacity. Include an old key in
  the same incoming batch and prove premarking prevents its eviction; deliver an
  earlier-evicted key in a later batch and prove it reinstalls by displacing only
  a still-unseen row. Pause final baseline reconciliation after one 256-row
  chunk and prove state locks/status remain live while BulkAck stays closed;
  cancellation retains taint. TailAck has no residual full-ledger scan.
  TailAck precommit provisionally opens ordinary admission, so an immediate
  causal normal frame is not dropped. Drive a real two-fabric sender through
  this ordering instead of injecting a protocol state the sender cannot reach:
  pause the receiver's TailAck writer after the peer consumes its bytes but
  while it still holds `writeMu`; let the peer begin the next maintenance cycle
  and send both required barrier requests. Both barrier-ACK writers block on
  `writeMu`, the sender observes no complete barrier set, and no BulkStart is
  emitted or accepted. Release TailAck postcommit and outbox commit; only
  then may both barrier ACKs complete and the normally authorized BulkStart
  create a second window. If config/ownership invalidation wins the fence,
  TailAck is suppressed, the barriers cannot authorize a start, and the
  transport retires. A fabricated BulkStart before the complete barrier is a
  protocol violation, while an ordinary frame during provisional admission
  remains valid. Pause each ACK
  writer before and after state revalidation. If it owns `writeMu`, config/
  ownership invalidation waits and the ACK linearizes first; if the invalidator
  owns the write fence, revalidation emits nothing. A transition between final
  write and postcommit orders false after true or suppresses stale true through
  the continuity outbox. Fill that outbox before TailAck: no TailAck byte is
  written until a slot is reserved; invalidation while waiting releases the
  reservation and emits no stale ACK. After an unambiguous TailAck write,
  injected allocation/error seams are unreachable and postcommit plus outbox
  commit complete under the held write fence. Stop joins both writers and any tail batch.

  Repair tests request on fabric 1 while fabric 0 remains preferred and prove
  the bulk is pinned to fabric 1. Unique request claim, duplicate/refusal, nil
  connection, failed write, deadline expiry, disconnect, reconnect, and delayed
  ABA completion retain or rearm the exact debt generation. A request arriving
  during an active bulk binds only a later bulk. Install the complete outbound
  token before BulkStart and pause BulkEnd `Write` while an exact BulkAck arrives;
  it binds `endingBulk` and delayed write completion cannot overwrite
  `flushingTail`.
  BulkAck rejects wrong/future bulk,
  request, fabric, connection, transport, process, ownership, sender config
  generation/digest, member count/digest, legacy length, and
  post-reconnect tuples; BulkAck starts tail but only the exact TailAck clears
  debt. Pause TailEnd `Write` while TailAck arrives and prove the same record-
  before-send race is safe.
  Fake-clock tests independently expire the 20-second
  `outboundBulkACKTimeout` and `outboundTailACKTimeout`; progress in one phase
  cannot extend the other, a trickling tail cannot extend the absolute
  180-second tail deadline, and either expiry retires the exact transport while
  preserving repair debt.
  An immediate peer returns BulkStart before the request write returns and binds
  the record-before-send `writing` attempt; delayed write completion cannot
  overwrite bound state. Ambiguous request-write failure retires the transport.
  A high-rate authenticated and unkeyed type-29 flood retains one claimed plus
  one latest pending tuple and cannot exceed one requested snapshot per
  `minimumRequestedResync`; 5-second start timeout, independent 20-second
  post-BulkEnd and post-TailEnd ACK timeouts, 30-second interval/backoff cap, and coalesced counters are
  deterministic under a fake clock.

  Readiness tests inject a reconcile error, then advance `syncReadyTimeout`.
  Continuity remains false, no bulk callback/VRRP continuity release occurs,
  baseline/repair debt stays visible, and manual transfer remains blocked. Only
  the separate timeout-availability bit changes; the existing explicit
  previous-good automatic peer-loss decision and alarm are tested independently.
  A bulk-success readiness callback is blocked while disconnect queues a
  higher-sequence false event; disconnect waits, then delivery occurs true ->
  false and no later callback reopens Manager current continuity while
  previous-good stays true. Fill the notifier outbox, pause producer P1 after it
  reserves the next slot, and start P2; P2 cannot allocate/enqueue `N+1` before
  P1 commits `N`. A full outbox applies backpressure only outside locks and
  delivers every alternating edge/ack in order. Stop joins
  the notifier without dropping its final false sequence. A source canary
  rejects production `SetSyncReady` calls outside the ordered adapter.
  New-receiver/old-sender and new-sender/old-receiver matrices both remain
  continuity-unready, never accept an 8-byte ACK as proof, and document the
  standby-first upgrade sequence. A fully upgraded pair recovers through
  baseline -> exact request -> exact bulk/reconcile -> BulkAck -> captured-tail
  reconcile -> TailAck.
  The deployment matrix does not claim an online first migration for existing
  fixed XDP BPF-link pins, because they predate namespace provenance. Each node
  is placed in secondary hold/drained, proves the online refusal, performs one
  controlled clean reboot into the new loader, and proves fresh v2 links obtain
  durable provenance before traffic/readiness. The peer remains continuity-
  unready until the ordinary fully capable repair completes.

  I-a and I-c have source/runtime canaries proving their shared activation
  constant leaves legacy config/session behavior selected. I-d removes that
  constant and must make every new
  production-path test fail when its activation hunk is reverted; no rejected-
  config or mixed-version semantic may become active in I-a through I-c.
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
  and proves they are fenced before publication and while clustered helper debt
  retries. Startup proves authority is initialized before either fabric is
  reachable. Reconnect smoke separately replaces one fabric during an admitted
  config callback and drops both fabrics during another: the first may publish
  for the unchanged transport, while the second drains before a lower new-peer
  baseline only when the remote daemon process also restarted; same-process
  reconnect retains its sender generation/replay namespace. Fabric-1 repair
  remains pinned there while fabric 0 is available.
  Event-loss injection drives RG0 and RG1 safety-net promotion/demotion through
  the same full-ownership begin/complete gate, including active/active zone
  migration. A deliberately capability-less sender/receiver,
  invalid/reconcile-failed bulk, other-fabric contamination, and blocked
  reconciliation cannot ACK, release continuity readiness, or clear debt.
  Advancing the cold-start timeout changes only timeout availability; manual
  transfer stays blocked. The supported standby-first mixed-version rollout is
  exercised in both directions, followed by full capable baseline -> request ->
  bulk -> ACK recovery. The capable path also proves equal canonical digests
  with deliberately different sender generations, plus reciprocal RG1
  ownership. A request during an active bulk
  completes only after the next qualifying bulk. Restart smoke pauses a remote
  failover callback, replaces the peer process, and proves no mutation or ACK
  escapes the old registered worker set. Separate cluster-comms restart smoke
  keeps the daemon process ID, request/bulk counters, replay floor, and canonical
  record unchanged. Helper-process restart smoke first primes standby sessions
  and continuity, then replaces only the Rust helper: packet and event-stream
  callback generations close before H1 exits, manual transfer becomes
  unavailable, H2 starts with empty runtime session maps, and config/status
  replay alone cannot reopen it. Fresh bilateral capable bulks repopulate
  standby-owned state, reconcile the new authoritative snapshot for locally
  owned RGs, and only then restore readiness. The same smoke delays one H1
  callback until after H2 connects and proves it cannot enqueue or ACK in H2;
  an H2 event proves callbacks were rebound. A planned owner restart transfers
  the RG before teardown, while an injected forced kill emits the explicit
  session-reset alarm and never silently claims flow preservation.
  Counter-exhaustion smoke delivers final false and forces a
  supervised full-process restart at generation 1.
- K003-07 requires apply/rollback validation proving a rejected commit cannot
  replace the previous helper policy snapshot.
- K003-03 requires authoritative fake/isolated DNS endpoints with operation
  logs proving every Surface-B delete used the exact same-family updater whose
  `fpb1` matched the row, no cross-family fallback occurred, partial failure
  retained the old anchor, and no-authority or failed claim-save rows caused
  zero DNS writes. Restart with a pre-#2903 Surface-A store must migrate without
  quarantine or wire delete.
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
- Widening dataplane owner capacity above slots 1..15 or migrating any pinned
  BPF map other than the in-scope unified v2 program plus
  `userspace_sessions_v2`/dynamic-DNAT-v2 cutover.
  Control definitions remain supported through 255.
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
- Changing the public/binary lifecycle event layout or retroactively assigning
  permit/deny to lifecycle events. Workstream I-d's co-versioned private
  helper-event source-generation envelope is explicitly in scope.
- Refactoring all logging formatters beyond central action applicability.
- Unrelated DDNS ownership, SNMP feature expansion, FRR rendering, or routing
  reconciliation improvements discovered while implementing a child issue.

## 11. Resolved adversarial decisions

Rounds one through thirteen closed the design choices rather than delegating them
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
   pins. The Rust helper receives one staged full replacement that preserves
   unchanged slots, omits removed slots, and introduces new slots inactive;
   manager-owned clustered debt and its sole status-loop retry consumer own that
   whole desired generation rather than per-slot patches or unpublished
   `m.haGroups`. Every direct active/watchdog/status/helper writer serializes
   through the inventory transaction before map I/O and refuses positive replay
   while debt exists. Every `ControlRequest` is classified: read-only status
   captures/revalidates an exact process/snapshot/inventory/debt lease, while a
   mutating helper RPC retains transaction ownership through Rust mutation and
   response. Stale responses may update only process-matched telemetry and
   cannot re-enable control, bindings, or readiness. Public and transaction-held
   helper variants prevent non-reentrant mutex acquisition. The actual state lock is `Manager.mu`, with no reverse acquisition
   against `haInventoryTxnMu` and no helper I/O while `Manager.mu` is held.
   Mixed-version high bindings reject fail-safe, block manual transfer,
   preserve previous-good automatic peer-loss takeover with an alarm, and
   require the two-node-view `xpfd check-config` content preflight. The command
   cannot prove artifact freshness; source-of-truth selection and config freeze
   are explicit operator prerequisites. A 256-entry owner ABI/pinned-map
   migration remains separate research.
5. Production Surface-B DDNS uses only the exact same-family current or retained
   previous updater whose nonempty existing `fpb1` matches the owned row. Anchor
   rotation happens after reconciliation and is deferred while a retained row
   depends on the old endpoint. The expected store surface is validated without
   a new disk tag and includes the exact pre-#2903 empty-scope-FQDN Surface-A
   migration shape. #6015 claim-only co-owner release occurs before
   last-claimant authority selection and becomes visible to the cross-surface
   snapshot only after a classified durable-save outcome. Fixed-constructor
   mode preserves its
   whole-store caller authority for valid empty-fingerprint rows; daemon
   production does not use that seam.
   There is no representative-updater or credential-generation fallback.
   Namespace/election and component-outcome redesign require separate research.
6. SNMPv3 intent is validated on one merged canonical root before lowering.
   Strict and tolerant input normalize every AST-equivalent `system snmp` form
   with a deprecation warning. Structured client rows preserve equal-prefix
   deny-wins, and multi-source observations prevent an invalid/conflicting
   occurrence from disappearing in a last-writer fold. Community observations
   use redacted paths and first-appearance ordinals, never the secret or a
   secret-derived identity; the private in-memory reconcile hash remains
   credential-aware so rotations apply. Compiler rejection
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
15. Session authority is initialized before network exposure. Protection is
    `config sync enabled && committed RG0 secondary`. Every local RG writer and
    state/priority/weight/definition mutation publishes one fail-closed full-map
    serial before raw state; heartbeat reads only the complete old/new committed
    wire row. Prepare, gate-stage, and final manager-publish make final publish the
    only positive visibility point. Raw readers, direct writes/events, zone-owner
    builders, and pre-publish GARP/actuators are finite source-canary domains.
    Config identity is one daemon-lifetime process namespace plus an immutable
    sender-owned generation and metadata-free canonical wire digest. The
    canonicalizer strips annotations/inheritance/source positions and is stable
    across parse/persistence/restart; digest equality, not generation equality,
    proves equality only in that declared domain. `QueueCommittedConfig` never
    allocates; Type 29 declares each requester's local epoch, capable bulk
    markers declare the responder's local epoch, and capable ACK echoes it.
    Cluster-comms restart reuses process identity, wire counters, replay floors,
    and committed record; full daemon restart creates a new identity and boot
    generation 1. Checked counter exhaustion exits fail-closed rather than
    wrapping/rekeying in process.
    Callback success always records its mutation; a callback-caused
    manager transition adopts it against the predecessor gate while authority
    stays closed. Classified failure records exact reapply identity, and either
    that record or a newer full replacement must succeed before baseline.
    Peer config is prepared once as an opaque store-owned sealed object;
    debt/fences precede exact one-shot promotion, and every local active mutation
    uses the same opaque prepare/view/promote object with explicit
    Begin/Abort/Complete ownership. One checked, process-local store mutation
    generation covers every active/candidate/compiled/rollback/confirm write;
    no independently mutable compiled tree, canonical identity, or generation
    crosses the daemon/store transaction boundary.
    Restart reads only the fully applied committed-runtime ledger and replaces a
    complete joined `clusterCommsEpoch`. SessionSync separately owns closable
    lifetime and transport worker registries, independently closable generation-
    stamped setup lanes per fabric, plus a dedicated coordinator handle;
    single-fabric retirement joins/reopens only its lane, while whole-transport
    retirement closes both lanes and vetoes setup promotion. Every protocol callback
    carries an exact process/connection/ownership lease, so setup completion,
    single-fabric retirement, callback completion, ACK routing, and Stop cannot
    self-join or cross epochs. The enumerated lock graph adds one write fence and one
    reserved continuity publisher; no state lock spans I/O, callback, or join.
    Capable cold and post-config repair are bidirectionally receiver-requested,
    fence every used/live connection and authority generation, and keep
    producers closed through one exact process/connection/bulk/request token and
    two-stage BulkAck/TailAck. Failover request/commit share one transaction ID and
    normalized RG-set record with separate phase results; prepare activation uses
    an independent per-RG high-water because it has no ACK. Owner-transfer leases
    are keyed by peer-process/legacy-transport namespace, request ID, and RG-set
    digest; process replacement restores every nonterminal lease before admitting
    the new namespace. An applied failover ACK is bound to the exact final
    full-authority publication receipt, not an earlier packet fence. Protocol
    replay, waiters, workers, and captured per-key tail state have explicit capacities,
    floors, eviction rules, and deadlines. Correctness-critical EventStream
    frames occupy a separate non-evictable count/byte arena through ACK or
    terminal generation retirement; tuple release additionally publishes one
    bounded allocator-owned predecessor record before free visibility, and
    every allocation/reserve/rollback mode preserves that record until its Open
    is ordered.
    Helper side effects occupy a finite process/snapshot registry that config and
    helper replacement close and join; response-work-heavy exports have matching
    Rust aggregate and longer Go round-trip deadlines rather than the ordinary
    request-size deadline. Bulk member installs are
    synchronous on the bound receive loop. Reconciliation/ACK workers are cancellable and joined;
    partial valid installs may remain after failure, but no failure publishes
    continuity or debt success. Mixed authoritative bulk remains unsupported,
    rolling upgrade is standby-first with manual transfer blocked, and timeout
    availability remains distinct from validated continuity. I-a through I-c
    remain inactive scaffolding; I-d alone activates these semantics after full
    smoke.
16. Rust-helper replacement is never treated as config-only recovery. A checked
    local helper generation is initialized before SessionSync exposure and is
    carried by every install/export/bulk/ACK/reconcile token. One outer lifecycle
    closes and joins SessionSync work before entering Manager teardown, while a
    process-generation event-stream registry installs callbacks before listener
    exposure and joins old callbacks before replacement publication. Replacement
    retires the whole sync transport and requires fresh bilateral capable bulk
    repair; same-daemon identity and prior bulk history do not satisfy it.
    Planned replacement transfers owned RGs first or retains the healthy old
    helper. Forced/standalone replacement explicitly reports session loss and
    reconciles stale peer replicas from the new authoritative snapshot rather
    than claiming impossible in-memory preservation.
17. Long authority-mutating helper requests remain serialized by
    `haInventoryTxnMu`, but one independent mutation lane makes them preemptible
    by urgent negative work. The urgent coordinator closes the exact connection,
    kills a nonresponsive helper generation after the one-second grace, orders
    the final BPF/RG fence after the old external step, and prevents every later
    compensation/status/publication step. Urgent fencing never waits the full
    snapshot deadline or races a blind write to the same map. Admission remains
    closed until exact latest-serial replacement and all repair complete; a
    cancellation-blind Go consumer is host-fatal rather than allowed to outlive
    helper replacement.
18. Remote failover is two-stage. A mutation handle returns and records its
    authority receipt before `CompleteOwnershipTransition`; a separately owned
    non-mutating waiter writes the result only after exact final publication and
    is excluded from that serial's pre-publish join. The authority coordinator,
    not the waiter, commits the final replay result after publication. Source
    loss or waiter timeout suppresses the ACK without migrating it, restoring
    ownership, or discarding the transaction.
19. Failover duplicate suppression uses a fixed sparse receive window above the
    contiguous floor, a separate bounded nonterminal transfer ledger, and a
    separate floor-covered completed cache. Nothing above a gap is evicted; only
    a result already made stale-safe by the floor can age out.
20. Session-bearing helper APIs use a non-escapable consuming callback and
    generation-qualified batch/stream, while private EventStream mutation frames
    carry their producing helper snapshot generation plus fixed pre-mutation
    and post-mutation authority projections. Capable bulk authenticates one
    request-private fixed-record owner-session stream, scan and final-seal
    boundaries plus monotonic loss epochs from every exact worker, and terminal event watermark. It converts and writes
    records directly between markers with source and peer-wire count/digest
    proofs. A per-worker fixed release fence retains each translated allocator
    token until its Close is globally sequenced into a non-evictable protected
    replay slot. A bounded allocator-owned predecessor record publishes before
    free visibility and stamps every capable successor Open/Update until local
    replay plus covering remote-order proof permit retirement; a second physical
    reuse is withheld meanwhile. It then flushes a fixed-credit per-key tail whose release phase
    preserves cross-key reservation dependencies before final acquisitions;
    reservation identity, not raw translated tuple, permits exact compatible
    persistent/shared-lease refcounts while exclusive or incompatible aliases
    still collide. Exact
    release/acquire phase markers force the receiver to commit release-only
    batches into bounded tuple escrow before it preflights any acquisition; one
    nominal 128-frame batch cannot erase that boundary. It never materializes
    a full Rust or Go vector. Shared delta buffers, global sequence sampling, and
    asynchronous all-session export are explicitly non-authoritative.
21. Receive-side inventory reads the coordinator's shared synced-session
    authority, not a selected packet worker. That authority becomes one paged
    stable-slot/index store with a checked mutation serial, so a streamed scan
    is exact-or-aborted without holding its mutex across backpressure or adding
    a second full entry vector. Its peer-domain serial ignores unrelated local-
    only churn but changes on every explicit peer-namespace provenance
    transition. Every key in a non-complete 384-physical-mutation helper
    batch remains either an ambiguous existing Go ledger row or a disjoint
    staged transition paired with its still-indexed incumbent, plus a full
    before/attempted descriptor in the fixed one-batch cleanup
    journal. Fresh inventory cannot erase those records; joined-writer,
    exact-value cleanup
    removes only matching peer-owned rows on shared, BPF, kernel, DNAT, and every
    worker surface, and tuple escrow is released only after absence is proved.
    Every stable key also has checked handles into one global 24,576-record
    mutation-lane arena for its cross-fabric owner retained through final Go
    commit plus at most eight mutation-free higher-generation waiters; partial
    ownership cancels successors into that same bounded repair domain without
    multiplying eight operation records by total session capacity. Read loops
    only admit records; one fixed 64-worker intrusive-ready scheduler executes
    owners, while waiters consume no worker and one fixed coordinator resolves
    deadlines/barriers. Replacement and migration close and join that complete
    execution generation before authority or maps can change.
22. Capability exposes local-creation capacity plus two receiver reserves in
    forward-logical units: durable peer-baseline rows and temporary unique tail
    mutations. Bilateral setup proves the checked sum of both creation ceilings
    fits either baseline reserve, including authority re-export after takeover.
    One checked
    `SessionCapacityPlan` treats worker/auxiliary creation as sublimits of the
    shared local-plus-peer authority reserve and adds only tail credit across every
    real physical surface: 2x coordinator
    and per-worker rows, 4x keys in the single shim session map, 2x in each
    independently populated kernel session family, 1x dynamic reverse-NAT rows
    in each independently populated DNAT family, exact shared-index
    slots, and baseline-plus-tail ledger rows. Sender
    source capacity is the negotiated combined cluster ceiling, and
    final TailAck requires peer presence at or below it. Per-tuple SNAT/NAT64
    allocator reservations remain an independent gate; collision aborts rather
    than silently skipping protection, and any token exposed to a mutation
    prefix remains escrowed through cleanup. Capacity is transport-
    epoch immutable, so rebind/config changes retire and renegotiate rather than
    mutate a live advertisement. The current session and DNAT pins migrate
    side-by-side to three versioned no-prealloc v2 maps. Old objects become an
    isolated boot-scoped execution capsule whose packet-side bytes may change
    but can never enter v2 authority; after durable `forwardOnly`, same-process
    recovery completes the recorded target while new-process recovery,
    including a boot from `committed`, moves every exactly owned hook through
    the map-free typed drop quarantine and a fresh
    coordinator-derived successor. Both select only the forward path. A durable
    `committed` record requires exact v2/coordinator readback and helper-handle
    publication before admission reopens, independently of peer repair. No old
    map is resized, copied as authority, flushed, or deleted in place. A
    prepared shrink that cannot hold any current authoritative/derived row is
    rejected before helper/config mutation.
23. Session authority is explicit provenance independent of `SessionOrigin`.
    Local worker/promoted authority, local auxiliary authority, capable peer
    process authority, and ephemeral legacy transport authority have an
    exhaustive legal transition matrix; local-tunnel `SyncImport` never makes a
    row peer inventory or delete authority. Promoted replicas name one canonical
    owner worker. Demotion first becomes target/serial-bound
    `HandoffExportable`, excluded from ordinary export but included once in the
    exact handoff; it may become capable peer authority only after exact
    handoff/TailAck and ownership commit, and failure quarantines it. One
    coordinator-owned staged/commit transaction plus exact worker ACK vectors
    makes every replica fanout externally atomic; split state keeps export shut.
24. TailAck retains the global write fence through its complete postcommit and
    continuity publication. Successor maintenance requires fresh ACKs from the
    all-current-fabric barrier writers under that same fence, so no valid
    BulkStart can precede the completed TailAck transaction.
25. Configured static DNAT has no BPF publication phase. The exact promoted
    prepared-runtime token publishes the Rust immutable snapshot and committed
    runtime. Compiler and config paths cannot write `flags=1`, and static
    cardinality is absent from map capacity. One forward-only migration moves
    the program, session map, and both discriminator-free dynamic-DNAT maps to
    v2 under a helper lifecycle lease, a stopped and joined fixed lane
    scheduler/barrier coordinator, and joined structural writers. V2 content
    derives only from one stable coordinator serial; legacy static, unknown,
    padded, or partial old-map rows are never copied or treated as authority.
    A checksummed fsynced `prepared`/`forwardOnly`/`recoveryQuarantine`/
    `committed` journal binds exact
    program/map identities, complete kernel hook inventory, generation-owned
    active-link pins, the transitive legacy execution capsule, and hook
    receipts. Once `forwardOnly` is durable, recovery only advances to v2.
    Historical XDP/TC invocations may mutate only isolated old objects and retain
    every PROG_ARRAY target for the rest of the boot; migration/recovery never
    scans, updates, deletes, repairs, or flushes those maps as authority and no
    userspace execution-grace claim is required.
26. Existing BPF XDP links predate durable network-namespace provenance and
    cannot be adopted safely from a pin: RTM reports a program ID while global
    link info reports only ifindex, so same-ifindex/same-program links in two
    namespaces are indistinguishable. Online cutover accepts only a same-boot
    attachment-time provenance record. Existing deployments therefore require
    one controlled clean reboot per node into the new loader; the deployment
    drains/holds that node, and HA continuity remains closed until capable
    repair. The resume command cannot waive or synthesize this proof.

Manual approval of this plan accepts those product choices. A material change to
any one returns that child workstream to plan review rather than being improvised
inside implementation.
