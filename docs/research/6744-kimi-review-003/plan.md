# Plan of Action - #6744: Revalidate and split `kimi-review-003`

> ## LANDED AS A RECORD — THE REVIEW LOOP IS NOT RESUMABLE
>
> This plan is preserved because its finding-by-finding evidence and its
> workstream designs are the expensive part and were about to be lost with a
> stranded branch. **It is not a live plan and must not be resumed as one.**
>
> Measured at `cadb5e90c` (2026-08-22) before landing:
>
> - The research branch `research/6744-kimi-review-003` last moved
>   **2026-08-05**; the issue's last comment is **2026-08-06**. Both are
>   ~17 days cold, and the branch is **1738 commits behind master**.
> - The issue comments describe work up to **revision 60 / hostile round 42**,
>   while the branch stops at **round 17**. Everything after round 17 was never
>   committed.
> - **Its source of truth is gone.** `/tmp/kimi-review-003.md` — the report
>   every finding derives from — no longer exists on this machine, and neither
>   do the immutable per-round artifacts the later comments cite (e.g.
>   `/tmp/6744-plan-r59-precommit-42.md`). A review loop whose reviewed
>   artifacts are unrecoverable cannot be continued, only restarted from a
>   source that no longer exists.
>
> **What was re-measured before splitting**, since a base 1738 commits behind is
> not a baseline. Of the fourteen cited source files, **eight have not been
> touched at all** since the base SHA, so their anchors still hold; six moved:
>
> | cited file | commits since base | bearing on the finding |
> |---|---|---|
> | `pkg/config/compiler_interfaces.go` | 2 | value-list reads / fab0 members — unrelated to the `Keys[0]` index (K003-04); **re-verify** |
> | `pkg/config/compiler_validate_strict_zones.go` | 5 | zone-interface gates — plausibly adjacent to K003-07; **re-verify** |
> | `pkg/configstore/store_command.go` | 2 | bracket/quote provenance — unrelated to `LoadOverride` (K003-09) |
> | `pkg/logging/ringbuf.go` | 2 | one is "guard the RT_FLOW resolver … against policy id 0" — adjacent to K003-14/15; **re-verify** |
> | `pkg/daemon/daemon_ha_vip.go` | 1 | **re-verified: K003-16 still reproduces, see below** |
> | `pkg/daemon/daemon_apply.go` | 2 | includes "background applies re-read the active config under applySem" |
>
> **K003-16 re-verified at `cadb5e90c` and still LIVE.** `daemon_apply.go:301`
> resets `d.vipWarnedIfaces = nil`; `daemon_ha_vip.go:198-208` lazy-inits, reads,
> assigns and deletes; and `daemon.go:815-818` gives the field no dedicated
> mutex. A reset landing between the nil-check and the assignment panics with
> `assignment to entry in nil map`, and two concurrent writers are a fatal
> concurrent-map-write throw.
>
> The retained root causes were split into individual issues; #6744 is closed
> referencing them. Read §2.2 for the disposition matrix and §5 for the
> per-workstream designs, and treat every anchor as "verified at
> `ad9591177`" unless the table above says otherwise.

## 1. Status

**DRAFT v20 - integrated pre-commit design review; pending immutable round-seventeen review**

- Issue: [#6744](https://github.com/psaab/xpf/issues/6744)
- Source report: `/tmp/kimi-review-003.md`
- Base: `origin/master` at `ad959117748181dabe46b8ddc2827de670380cea`
- Branch: `research/6744-kimi-review-003`
- Revision: 20
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
  release/acquire phases, proves that the sole-writer TailAck transaction and mandatory
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
- Round-sixteen plan SHA:
  `0533766f6dda9f71268314e67dc83d5ff4d6bfbb`.
- Round-sixteen verdicts: Codex `PLAN-NEEDS-MAJOR`; AGY `PLAN-READY`;
  independent non-Anthropic SMR-method fallback `PLAN-NEEDS-MAJOR`. The Claude
  Code CLI again failed before analysis at the account spend limit, so no
  Anthropic-model verdict is claimed. Round sixteen did not converge. An
  intermediate revision-17 draft tried to solve the reviewers' adjacent HA and
  state-migration concerns inside K003-10. Pre-commit snapshot 4 demonstrated
  that this had become an independently unbounded SessionSync/map/lifecycle
  redesign with multiple new proof gaps and no defensible one-root rollback
  boundary. Revision 17 therefore self-corrects the scope rather than adding
  another wire protocol or durable receipt layer: it removes the speculative
  map migration, publication-cell, cross-peer ACK, and binary-floor
  architecture. A later pre-commit composition pass showed that even the
  proposed split between 0..255 control definitions and 1..15 dataplane owners
  required a second inventory, snapshot-commit receipts, recovery debt, and
  election serialization merely to preserve otherwise-unused high-numbered
  definitions. Revision 17 therefore makes the narrower product decision the
  source report originally recommended: configured redundancy groups are
  0..15, with RG0 reserved for control and RG1..15 available to dataplane
  bindings. Pre-commit snapshot 10 then disproved that the cap itself was a
  bounded child: a safe compatibility change must also define config-bearing
  startup domination, `cluster.Manager.UpdateConfig`, pending-confirm recovery,
  a staged-binary config-store scanner, rolling-upgrade generation fencing, and
  exported API compatibility. Revision 18 therefore does not pretend those
  contracts fit in this split plan. K003-10 remains confirmed and high impact,
  but becomes a dedicated follow-on `/research` child comparing a configured
  cap, end-to-end capacity expansion, and split control/owner domains. No
  K003-10 production PR is authorized by this plan. The final topology is 13
  child issues, 12 directly engineerable PRs, and one separately gated research
  track.
- Pre-commit snapshot 11 then found residual implementation ambiguity in the
  remaining compiler work: strict configstore still had no prepare-once API,
  raw gates contradicted a global no-double-expansion claim, undefined group
  errors erased the provenance needed for the optional-peer exception,
  non-0/1 direct-node compatibility had no peer rule, and commit-confirm
  recovery could assign or arm an invalid B/M rollback target. Revision 19 adds
  one strict commit transaction with preserved error precedence, limits the
  single-expansion invariant to its prepared views, carries typed group
  provenance, preserves requested-only compatibility for other direct IDs,
  and makes pending-confirm recovery fallible with explicit first-commit and
  blocked-recovery state. It also removes the last I-owned interface/chassis
  scaffolding from B.
- Pre-commit snapshot 12 proved that the new compiler transaction still
  returned peer gates ahead of existing requested lowering, view reuse did not
  represent alias/unavailable/not-applicable states, and recovery still exposed
  a compiled active config to startup managers. It also exposed the harder
  upgrade case where the unconfirmed active tree is newly invalid but its
  confirm target is valid, nil-based first-commit result callers, the bootstrap
  plain-commit gate, and missing pending-state transitions. Revision 20 captures
  new gate errors and returns them only after existing requested/node-ID/RA
  slots, uses node-indexed resolution states, prepares both persisted artifacts
  before publication, immediately restores a valid target when the active tree
  is newly invalid, publishes nil on blocked recovery, carries typed rollback
  results, and defines the complete none/armed/blocked state machine plus its
  narrow bootstrap recovery commit.
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
| K003-10 | RG IDs beyond the 16-entry dataplane domain can commit but never become active | **LIVE; SEPARATE RESEARCH REQUIRED** | High | Medium | The heartbeat byte can encode 0..255, but the complete forwarding system cannot: BPF owner/watchdog maps and Rust owner epochs have 16 slots, while cluster election and helper publication currently consume configured definitions directly. Snapshot 10 proved that choosing a cap, widening capacity, or splitting control/owner domains requires its own upgrade, recovery, and runtime-authority design |
| K003-11 | Bond delete and tunnel clear treat every `LinkByName` failure as absence and forget ownership | **LIVE** | High | Medium | `pkg/routing/bond.go:576-589` and `pkg/routing/tunnel.go:1237-1262`; sibling XFRM code already has correct `isLinkNotFound` handling |
| K003-12 | Syslog TLS handshake has no deadline | **REFUTED** | High | None | `tls.Dialer.DialContext` derives a deadline from `NetDialer.Timeout` and applies it to `HandshakeContext`; the configured five-second timeout already bounds DNS, TCP, and TLS handshake |
| K003-13 | SNMPv3 configured protocol without required key material silently lowers the served security level | **LIVE** | High | Medium | Schema/compiler permit partial credentials; `pkg/snmp/v3.go` derives and enforces the floor from key presence rather than configured intent. This is a residual of #4897 |
| K003-14 | SESSION_OPEN/CLOSE trace and REST/SSE surfaces render an intentionally meaningless wire action 0 as `deny` | **LIVE** | High | Low | Rust lifecycle producers intentionally write zero; `pkg/logging/trace.go` and `pkg/api/sse.go` expose it as a forwarding decision |
| K003-15 | Binary SESSION_OPEN stores action 0 (`deny`) while only SESSION_CLOSE maps to `0xff` | **LIVE** | High | Low | `pkg/logging/ringbuf.go:1370-1379`; same semantic root as K003-14 and should be fixed in one workstream |
| K003-16 | `vipWarnedIfaces` reset and mutation use unrelated synchronization | **LIVE** | High | Medium | `pkg/daemon/daemon_apply.go` resets the map under `applySem`; `daemon_ha_vip.go` accesses it under other call-path locks. A reset between lazy-init/check and assignment can panic with `assignment to entry in nil map`; no external exploit or persistent corruption is proved |
| K003-C | 128 low-materiality cohort survivors | **UNACTIONABLE** | High | None | The report neither lists them nor preserves the batch artifacts. A number and category summary cannot be reproduced, deduplicated, or reviewed |

Net result: 14 live claims, one current duplicate, one refuted claim, and one
unactionable cohort. K003-14 and K003-15 are one semantic root, leaving **13
independent retained root causes**.

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
- preserve and escalate the accepted-RG/runtime-capacity defect into a
  dedicated research track rather than ship a partial HA fix.

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

Create one child issue per retained root cause, except that K003-14 and K003-15
remain one lifecycle-action workstream. Twelve bounded children produce one
implementation PR each; K003-10 produces a dedicated `/research` child and no
production PR under this plan. Land disjoint packages in parallel, but treat B
as the declared prerequisite for C and M, G as the persisted-input prerequisite
for B's recovery slice, and sequence those changes to their shared compiler and
configstore surfaces. Each child issue
carries the trace, invariants, exact tests, prerequisite set, and its own rollback
boundary.

Advantages:

- a logging semantic correction cannot hide a policy compiler regression;
- reviewers can reject a controversial compatibility choice without blocking
  the HA race or SNMP security fix;
- leaf fixes can be reverted independently, while C/M are reverted before B
  and B is reverted before G;
- smoke requirements match actual dataplane impact.

Cost: 13 child issues, 12 implementation PRs, one additional research cycle for
K003-10, and explicit merge ordering for compiler slices that share validation
entry points.

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

Every public compiler entry point calls one prepublication routine that prepares
and proves the required effective views before it returns a usable `*Config`.
This is a compiler invariant, not config-store call-site convention: strict
commit, commit-confirmed, rollback promotion, tolerant persisted load,
`Store.SyncApply`, generic compile, and direct node-aware compile cannot omit the
B/M proof or C's strict/quarantine verdict for every effective view that the
entry point's compatibility contract defines. The additional peer-effective
source-NAT proof remains strict-commit-specific as defined below.

The refactor preserves the existing two compiler phases exactly instead of
mistaking `runPreWalkGates` for the whole front end:

1. Clone and strip inactive input once, then run the current ordered
   **raw/pre-expansion** gate block once on that clone: tunnel-ID, stable-zone-ID,
   routing-instance table-ID, duplicate named blocks, duplicate NAT rule and
   rule-set names, interface-unit aliases, QinQ, and VLAN-map. Preserve its
   first error and warning order. The validators that deliberately inspect the
   union of raw group bodies continue to do so before `ExpandGroups`; no view
   preparation may rerun or reorder them.
2. Clone that proved raw tree per required effective view, expand groups with
   the correct node variables, then run the existing `runPreWalkGates` once per
   expanded view, including its single `expandInterfaceRanges` mutation. Do
   **not** move range expansion earlier or run it twice.

Generic compile retains its current requested-result semantics: first attempt
the ordinary `ExpandGroups`; only the exact undefined-`${node}` case falls back
to node 0 and emits the existing node0-fallback warning once. In addition to
that requested view, prepare node-0 and node-1 validation-only views when the
raw tree contains cluster or `${node}` state, reusing an already prepared view
only when it has the same explicit evaluation context. A direct node-aware
compile for node 0 or 1 returns the requested node and
prepares the defined opposite node as validation-only; another direct integer
retains requested-only compatibility because no two-node peer is defined. This
can require three prepared views for a generic compile; a requested-plus-one
`pair` type is therefore insufficient.

The new raw observations are collected immediately after that existing range
expansion, but they are reduced with the exact section-dispatch semantics before
any hard-gate verdict:

- `security` roots are all consumed in author order. Duplicate zone instances
  merge by name and zone-pair/global policies append, so B and M examine every
  consumed identity/container rather than inventing a last-root rule.
- C deliberately establishes the normalized SNMP fold in Workstream C as the
  new authoritative merge contract. Earlier invalid/conflicting SNMP intent is
  retained for rejection rather than called discarded input.

Encode those rules in named security/SNMP reducers shared by the gate and
section-compiler tests. A generic `FindChildren` union and a generic last-root
selector are forbidden because they do not match both sections.

Workstream B owns the neutral compiler plumbing and lands before C or M.
It must not import or name a result type owned by those later workstreams. The
baseline private types contain only the prepared root, effective node identity,
section reductions required by B, and warning state:

```go
type effectiveSectionViews struct {
    SecurityRoots []*Node
}

type effectiveNodeContext struct {
    ID  int
    Set bool
}

type effectiveCompileMode uint8

const (
    compileGeneric effectiveCompileMode = iota
    compileDirectNode
)

type effectiveCompileRequest struct {
    Mode   effectiveCompileMode
    NodeID int // meaningful only for compileDirectNode
}

type preparedCompileView struct {
    Root     *ConfigTree
    Node     effectiveNodeContext
    Sections effectiveSectionViews
    Warnings []string
    // C appends private payload fields only after B has merged.
}

type rawCompilePreparation struct {
    Root     *ConfigTree
    Warnings []string // exact existing raw/pre-expansion order
}

type effectiveValidationPolicy struct {
    StrictRequested       bool
    ValidatePeerSourceNAT bool
    ValidateHardBothNodes bool // B and M
    ValidateSNMPBothNodes bool // C: reject in strict, quarantine in tolerant
}

type effectiveCompileSet struct {
    Requested            preparedCompileView
    RequestedHardGateErr error // captured B/M or strict-C verdict
    Node                 [2]effectiveValidationOutcome // explicit node-0/node-1 resolution
}

type effectiveViewResolution uint8

const (
    viewNotApplicable effectiveViewResolution = iota
    viewPrepared
    viewAliasesRequested
    viewUnavailableOptional
    viewPreparationFailed
)

type effectiveValidationOutcome struct {
    Node           effectiveNodeContext
    Resolution     effectiveViewResolution
    View           *preparedCompileView // non-nil only for viewPrepared
    PreparationErr error
    HardGateErr    error // B/M or strict-C; never returned before requested compile
}

type peerSourceNATOutcome struct {
    Config      *Config
    LoweringErr error
}

func prepareRawCompile(
    tree *ConfigTree,
    opts compileOpts,
) (rawCompilePreparation, error)
func prepareEffectiveCompileSet(
    raw rawCompilePreparation,
    request effectiveCompileRequest,
    opts compileOpts,
) (effectiveCompileSet, error)
func validatePreparedEffectiveSet(
    set effectiveCompileSet,
    opts compileOpts,
) (effectiveCompileSet, error) // returns private gate carriers on Requested
func compileRequestedPreparedView(
    view preparedCompileView,
    opts compileOpts,
) (*Config, error)
func compilePeerSourceNATView(
    view preparedCompileView,
    opts compileOpts,
) peerSourceNATOutcome

// CompileConfigForCommit is the strict configstore/check-config transaction.
// nodeID is -1 for generic/standalone and 0 or 1 for a clustered node.
func CompileConfigForCommit(tree *ConfigTree, nodeID int) (*Config, error)
```

All public compile functions route through raw preparation, effective-view
preparation, hard-gate validation, and requested-view lowering in that order;
none recursively calls a public compile function to obtain the peer.
`compileOpts` carries an explicit `effectiveValidationPolicy`; policy is not
inferred merely because a validation-only view exists.

`CompileConfigForCommit` is the one executable strict transaction used by
`configstore.compileTreeStrict` after schema validation. It accepts only
`nodeID == -1`, `0`, or `1`; any other value is rejected before preparation.
It prepares one `effectiveCompileSet` and evaluates B/C/M on every prepared
view, but all new hard-gate failures are captured rather than returned
immediately. It first returns existing requested-view preparation errors, then
lowers the requested view, runs the existing node-identity and RA-interval
cross-checks in their current order (move those private checks from
`pkg/configstore` into `pkg/config` without changing diagnostics), returns the
captured requested B/C/M error, then the first validation-only preparation or
B/C/M error in node/gate order, and finally runs peer-effective source-NAT
validation against the already prepared peer view. Thus the current
externally observable precedence remains schema, complete requested
compilation, node identity, RA intervals, then new validation-only B/C/M and
existing peer source-NAT, while no second compiler invocation is needed.
`configstore.compileTreeStrict` and `CheckText` must call this API once
and must not pair it with `ValidatePeerEffectiveSourceNATStrict`; a source
canary pins that call graph.

The existing exported `CompileConfig`, `CompileConfigLenient`,
`CompileConfigForNode`, and `CompileConfigForNodeLenient` remain compatibility
APIs with their current signatures, requested-result semantics, and warning
posture. They acquire the action-agnostic B/M gate and C's documented strict or
tolerant behavior through the shared preparation pipeline, but they do not
silently acquire configstore-only peer-SNAT or strict post-compile checks.
Direct-node compatibility calls with node 0 or 1 prepare the opposite node for
B/C/M validation. A direct-node compatibility call with any other integer
retains its current requested-only `nodeN` expansion and has no invented peer;
tests pin that behavior. The strict commit API rejects those same non-0/1 IDs.
`ValidatePeerEffectiveSourceNATStrict` remains an exported compatibility
operation for external callers and may prepare independently; it is no longer
used after `CompileConfigForCommit`.

Effective-view preparation has exact failure semantics. It clones the proved raw
tree, expands groups for the selected node, and runs the existing
`runPreWalkGates` once, including exactly one interface-range expansion.
The node context cannot alias an unspecified generic compile to node 0. An
ordinary generic expansion carries `{Set:false}`; the exact `${node}` fallback
carries `{ID:0, Set:true}`; direct node-aware views carry their requested
`{ID, Set:true}`; and validation-only peer views carry explicit node 0 or 1.
This context describes evaluation only and does not overwrite the independently
parsed `ChassisCluster.NodeIDSet` configuration field.
Requested-view preparation uses the caller's existing strict/lenient options.
Validation-only preparation uses the existing lenient posture for unrelated
validators, discards its warnings, and never lowers or publishes a `*Config`.
Group expansion gains a private typed undefined-reference error whose `Error()`
text remains byte-for-byte compatible with today's diagnostic:

```go
type undefinedApplyGroupError struct {
    OriginalToken  string   // exact authored key, before variable substitution
    ResolvedName   string
    Path           []string // copied canonical AST path to the apply-groups node
    ExpansionStack []string // empty only for a reference authored in the candidate
}
```

Collection retains one error record per scalar or bracket-list element instead
of erasing the authored token during `resolveVars`. An exact validation-only
expansion failure is represented as an unavailable validation view only when
`errors.As` proves `OriginalToken == "${node}"`, the resolved `nodeN` group is
absent, `ExpansionStack` is empty, and the request is a validation-only node-0/1
view. This preserves the repository's accepted node0-only fixture. A literal
`apply-groups node1`, a literal or substituted missing group nested inside
another group, a requested view, and every other malformed/preparation error
remain node-qualified hard errors. Tests cover scalar, bracket-list, nested,
literal, substituted,
requested, and optional-peer cases and assert both typed fields and unchanged
human-readable diagnostics. The raw union gates still inspect every authored
group body, so a nonexistent peer group cannot hide content that exists.
Tests also pin strict, tolerant, generic, node-0/1, and other direct-node
compatibility behavior around the existing fixture.
Tests pin error precedence as existing raw-preparation, existing requested
effective-preparation, requested lowering, strict node-ID and RA checks, then
the captured requested B/C/M verdict, deferred validation-only
preparation/B/C/M errors in node and gate order, and peer-SNAT
lowering/validation. Hostile fixtures combine a requested RPM lowering failure
with (a) a requested empty identity and (b) a peer-only empty identity and prove
the existing requested error wins in both cases, matching current strict-commit
behavior while still rejecting the candidate when no earlier error exists.

B, C, and M inspect the prepared roots/section views before requested
lowering, but validation-only errors occupy the deferred precedence slot above.
Their verdict therefore does not depend on a peer `*Config`; requested
compilation can still win as it does today, while an unrelated peer lowering
error cannot suppress the already captured hard-gate verdict.

Peer-SNAT is intentionally separate because its exported compatibility contract
is narrower. Only strict commit/check and
`ValidatePeerEffectiveSourceNATStrict` request
`compilePeerSourceNATView`. It lowers the already prepared peer view with the
same lenient options used today and returns both the `Config` and
`LoweringErr`. The dedicated SNAT-only wrapper returns nil on an unrelated
peer lowering error exactly as it does today; when a peer config exists it runs
`validateSourceNATStrictView`. Ordinary hard B/M and strict-C verdicts have
already run on the prepared view and are never suppressed by that outcome.
Tolerant persisted load and `SyncApply` do not acquire a new peer-SNAT gate.
This removes the duplicate public `CompileConfigForNodeLenient` recursion
without broadening the SNAT wrapper.

The requested view alone produces the returned `*Config`. Preserve the current
warning concatenation exactly: requested-view/`compileExpanded` warnings first,
then the generic node0-fallback warning when applicable, then the raw
pre-expansion warning block in its existing internal order. Raw warnings are
computed once and appended once; validation-only views cannot publish warnings
or mutate a store. C's tolerant quarantine is attached to the requested result
from its prepared carrier after lowering. Within one compiler-pipeline
invocation, each prepared effective view is expanded and lowered at most once;
validation-only views are not lowered except for the one strict peer-SNAT check.
This does not claim global deduplication across the separate schema validator,
an external compatibility call to `ValidatePeerEffectiveSourceNATStrict`, or
the existing raw tunnel/QinQ/VLAN/alias gates that intentionally perform their
own bounded node expansions. Those gates retain their present algorithms,
error order, and warning order.

Preparation caches by the exact `effectiveNodeContext` key. An ordinary generic
`{Set:false}` view never aliases `{ID:0,Set:true}` merely because the expanded
trees compare equal; generic node0 fallback may reuse the explicit node-0
preparation because its context is already `{ID:0,Set:true}`. No canonical
serialization, secret-bearing hash, or pointer identity participates in this
decision. `effectiveCompileSet.Node[0]` and `[1]` are always populated with one
of the five resolution states, so a prepared peer, requested-view alias,
accepted optional absence, failed preparation, and out-of-contract node are
mechanically distinct. `PreparationErr` is non-nil only for
`viewPreparationFailed`; `View` is non-nil only for `viewPrepared`.
Peer-SNAT follows only the defined opposite node for commit node 0/1: it uses a
prepared view, resolves an alias to `Requested`, skips only
`viewUnavailableOptional`, and treats `viewNotApplicable` or an impossible
field combination as an internal error. Tests exercise every state and assert
that no state causes a rebuild.

The production text boundary remains `configstore.MaxConfigSize` (16 MiB).
Direct programmatic compiler calls have no byte-size cap, but preparation is
bounded to one raw clone and at most requested, node-0, and node-1 effective
contexts after that exact context deduplication; it launches no goroutines and performs
a fixed number of gate passes per AST node. Existing group depth/work budgets
remain authoritative. Add a node/group-heavy benchmark matrix at approximately
1, 8, and 16 MiB for generic and clustered commit calls, report `ns/op`,
`B/op`, and `allocs/op`, and instrument tests to assert the three-view ceiling.
The benchmark is a regression signal rather than an arbitrary timing gate; a
review must reject any implementation whose measured growth is superlinear or
whose allocation profile reveals an unbounded extra clone/pass.

The compiler gate must dominate side effects rather than merely exist in the
config store. Every raw-tree compiler entry routes through this pipeline before
returning a usable `*Config`. Downstream entry points that intentionally accept
a programmatically built typed `*Config` cannot recover raw syntax. The
config-bearing daemon apply and compile boundaries begin with pure typed B/M
belts for evidence still representable there, before any config-driven
mutation. Configless `Dataplane.Load`, shim resource loading, and attachment
preparation cannot validate a value they do not receive and are not falsely
described as proof boundaries; no B/M implementation may move additional
config-driven work into them. The old exported config-bearing bypasses become
private adapters where possible. No cross-package "proved" Boolean is trusted.
A source canary and side-effect recorder cover every remaining config-bearing
exported entry and the beginning of daemon apply.

Commit-confirm recovery is part of that proof boundary. Change
`recoverPendingConfirmLocked` to return an error and make `Load` propagate an
`ErrConfigCompile`-wrapped failure. For a non-first-commit record, compile the
persisted `PrevTree` through the tolerant compiler transaction before assigning
it to `s.active`, persisting it, or arming a timer. Tolerant historical gates
retain their warning posture, while B/M remain hard and C applies its documented
quarantine. The expired and unexpired paths consume the same prepared result;
neither recompiles the rollback target.
This recovery slice depends on Workstream G's `DB.ReadConfirm` structural
validator and merges after G; B does not duplicate persisted-AST shape checks
or pass an unvalidated JSON tree into compiler walks.

`Load` must no longer publish/return on the active-tree compile before examining
a matching confirm record. Add a pure prepare phase that reads and structurally
validates both artifacts, applies the existing control-character sanitation on
private clones, checks `GuardedHash` against the same sanitized active-tree
representation used today, and then chooses one action before mutating Store:
An empty legacy `GuardedHash` retains its current compatibility meaning and is
treated as matching; a nonempty mismatch remains stale and can never trigger
rollback or re-arm.

| Active compile | Matching confirm target | Deadline | Prepared action |
|---|---|---|---|
| valid | none or stale guarded hash | n/a | Publish active normally; stale record follows existing durable removal |
| invalid | none or stale guarded hash | n/a | Ordinary compile-failed shape: retain active tree, publish nil config, return `ErrConfigCompile` |
| any | structurally invalid record/target | any | Publish nothing; retain both files; return `ErrConfigDBUnreadable` |
| valid | valid first/non-first target | expired | Promote the precompiled target with existing persistence/removal ordering; do not require the superseded active tree to compile |
| invalid | valid first/non-first target | either | Roll back immediately as an upgrade-safety action, even if time remains; an unconfirmed config newly rejected by this binary cannot run until its timer expires |
| valid | valid non-first target | unexpired | Publish active and re-arm using the already compiled target |
| any | semantically invalid non-first target | either | Enter `PendingConfirmRecoveryBlocked`, publish nil compiled config, retain both files, and return `ErrConfigCompile` |

The first-commit target is handled by the explicit bootstrap result below. A
matching valid target is compiled at most once; the expired/immediate-rollback
path never compiles a newly invalid unconfirmed active tree merely to discard
it. No `s.active`, `s.compiled`, history, candidate, timer, journal, or
persistence mutation occurs until the complete decision is available. Tests
cover old-binary valid-target/new-binary-invalid-active upgrades for both
expired and unexpired deadlines and both B and M failures.

Replace every `confirmPrevCfg == nil` inference with explicit state:

```go
type Store struct {
    // existing fields omitted
    confirmFirstCommit bool
    confirmState       PendingConfirmState
}

type PendingConfirmState uint8

const (
    PendingConfirmNone PendingConfirmState = iota
    PendingConfirmTimerArmed
    PendingConfirmRecoveryBlocked
)

func (s *Store) recoverPendingConfirmLocked() error
func (s *Store) PendingConfirmState() PendingConfirmState
func (s *Store) CommitBlockedRecoveryGen(
    expectedCandidateGen uint64,
    expectedConfirmGen uint64,
    description string,
) (*config.Config, error)
```

`confirmFirstCommit` is captured from the pre-commit durable state when the
window is armed, written to the existing `ConfirmRecord.FirstCommit`, restored
on load, and consulted by `PromoteRollback`; nil configuration is never used as
a first-commit discriminator. A true first-commit record has the explicit empty
bootstrap target (`PrevTree != nil && len(PrevTree.Children) == 0`) and needs no
ordinary compile. A `FirstCommit:true` record with any child is inconsistent
persisted metadata and returns `ErrConfigDBUnreadable`; it is never treated as
bootstrap or compiled. A false record must have a non-nil tree and a successful
tolerant compile.

Return first-commit identity explicitly to rollback executors:

```go
type RollbackPromotion struct {
    Config      *config.Config
    FirstCommit bool
}

func (s *Store) PromoteRollbackResult(gen uint64) (RollbackPromotion, bool)

// Deprecated source-compatible wrapper. Internal callers must not use it.
func (s *Store) PromoteRollback(gen uint64) (*config.Config, bool)
```

Migrate the daemon executor and standalone CLI executor to
`PromoteRollbackResult`; both enter bootstrap only when `FirstCommit` is true,
and otherwise require a non-nil `Config`. A successful result must satisfy
exactly one of `FirstCommit` or `Config != nil`; any impossible combination is
an internal fail-closed error before store promotion. The old wrapper delegates and retains
its exact `(nil,true)` first-commit result for external source compatibility.
A source canary forbids internal calls to the wrapper and tests malformed
first-commit records, a genuinely committed empty configuration
(`FirstCommit:false`), and canonical bootstrap rollback.

If a non-first rollback target fails parsing/preflight/compilation, recovery
leaves the on-disk unconfirmed `active.json` and exact `confirm.json` bytes
unchanged, retains the parsed current tree privately as `s.active` for repair,
and sets `s.compiled=nil` before returning. It performs no candidate reset,
active write, journal success, manager publication, or timer arm. This is the
same externally visible `(active tree, nil compiled config, ErrConfigCompile)`
shape as an ordinary persisted compile failure, so `ActiveConfig()` cannot feed
cluster election, DHCP, feeds, listeners, or any other config-derived startup
manager. Rollback history still loads and `EnterConfigure` clones the retained
active tree, preserving the existing in-band repair surface. It records the target in memory with
`confirmState=PendingConfirmRecoveryBlocked`, returns `ErrConfigCompile`, and forces daemon
lifeline/default-deny. Entering blocked state increments `confirmGen`; that
generation remains stable until a listed transition resolves or replaces it.
`IsConfirmPending` and every arm/clear path use `confirmState` rather than
`confirmTimer != nil`. `confirmTimer` must be non-nil only in
`PendingConfirmTimerArmed`; blocked and none require nil. `PromoteRollback`
accepts only the armed state and rejects a blocked target.

Do not overload the current timer-based clear helper. Add a typed resolution
reason and pin the complete transition matrix. `confirmRemoveDegraded` and
`confirmResolvePendingPersist` remain orthogonal durability debt; neither is a
fourth pending state.

| Current state | Event | Next state and ordering |
|---|---|---|
| None | successful `CommitConfirmed` | Armed only after candidate compile, active persistence/promotion, explicit target/first-commit capture, generation bump, timer creation, and best-effort record write |
| Armed | nested `CommitConfirmed` | Armed with original target/first-commit bit, new generation/deadline/timer; candidate failure leaves the old state intact |
| Blocked | any `CommitConfirmed` | Blocked; typed rejection before candidate or persistence mutation |
| Armed | explicit confirm or RG0 demotion | None after timer cancellation/generation bump; durable removal failure becomes existing removal debt |
| Blocked | explicit confirm or RG0 demotion | Blocked; typed reject/false with no record removal |
| Armed | successful authoritative `SyncApply` | Existing semantics: cancel timer and enter None; remove the record only after replacement persistence, or retain `confirmResolvePendingPersist` debt on write failure |
| Blocked | `SyncApply` success or failure | Blocked; reject before parse-derived publication/history/candidate/active mutation and preserve both files |
| Armed or Blocked | strict plain-commit compile/persist failure | Same state, target, generation, timer, and files |
| Armed or Blocked | successful strict plain commit | None only after valid candidate persistence/promotion; cancel any timer, clear blocked metadata, then remove the record with existing debt on failure |
| Armed | matching timer expiry | None only through generation-checked promotion of the precompiled target and existing durable-or-retry write/removal ordering |
| Blocked | timer callback or `PromoteRollback` | Blocked no-op; timer is nil and the state is not promotable |
| Any | factory reset | None through the existing joined destructive reset, which clears timer, target, record, and debt |
| Process start + no/stale record | load | None; stale guarded hash follows existing durable-or-retry removal semantics |
| Process start + structurally malformed record | load | None in memory, retain bytes, return `ErrConfigDBUnreadable` before compiler access |
| Process start + valid target/deadline | load | Armed/re-arm if unexpired; generation-checked immediate promotion to None if expired |
| Process start + semantically invalid non-first target | load | Blocked with nil published compiled config, no timer/mutation, retained record, and `ErrConfigCompile` |

For every row, tests assert `confirmState`, `confirmTimer`, `confirmGen`,
`confirmFirstCommit`, target tree/config, both durability-debt flags, active and
candidate generations, and exact file retention/removal. Invariants require
`TimerArmed <=> confirmTimer != nil`, `Blocked => confirmPrevTree != nil &&
confirmPrevCfg == nil`, and `None => no rollback target` (durability debt may
remain).

The blocked-state operator surface is:

| Operation while recovery is blocked | Result |
|---|---|
| Successful strict plain commit of a valid candidate | Persist/promote first, then durably clear the record and blocked state; the existing daemon apply remains in lifeline until `applyConfigLocked` succeeds |
| `ConfirmCommit` / REST or gRPC confirmation | Reject with a typed blocked-recovery error and instruct the operator to enter configuration and perform a valid plain commit |
| Nested `CommitConfirmed` | Reject; it cannot replace the last-confirmed target with an unconfirmed tree |
| HA `SyncApply` or RG0 demotion | Reject/preserve; neither may confirm or delete the local recovery artifact |
| Timer/fire/`PromoteRollback` | Impossible/no-op; no timer is armed and blocked state is not promotable |
| Factory reset | Clear through the existing destructive reset transaction |
| Restart without resolution | Re-read, revalidate, and fail closed again |

Only the successful strict plain-commit path is a non-destructive recovery
action. Its existing persist-before-promote and daemon `applySem` ordering stay
unchanged; `applyConfigLocked` exits bootstrap only after successful runtime
apply. If runtime apply fails, the process remains lifeline while the now-valid
active config is available for retry/restart. Durable record-removal failure
retains the existing #5835 retry debt and degraded health rather than reporting
false recovery.

`IsConfirmPending` remains source-compatible and returns true for either armed
or blocked state, but CLI/API commit dispatch must use `PendingConfirmState`:
only `PendingConfirmTimerArmed` turns a bare commit into confirmation.
`PendingConfirmRecoveryBlocked` proceeds through the real strict plain-commit
path. Source canaries enumerate every local, REST, gRPC, event-engine, and
internal commit/confirm/demotion/sync caller so none reaches the wrong
transition by relying on timer nil/non-nil state.

The daemon bootstrap gate gets one narrow exception: `commitAndApply` may run a
plain commit while `PendingConfirmState()==PendingConfirmRecoveryBlocked`.
Every other bootstrap case still requires `commit confirmed`; blocked recovery
rejects `commit confirmed` because its last-confirmed target is invalid. The
daemon acquires `applySem`, snapshots candidate and confirm generations, and
uses `CommitBlockedRecoveryGen`, which rechecks blocked state and both
generations under `s.mu` before invoking the ordinary strict commit body. It
fails without mutation if another transition won; there is no check-then-commit
window. The exception then calls `applyConfigLocked`; bootstrap exits only on
successful apply.
This is an explicit operator recovery action, not an automatic startup path.
Background managers are not started in the blocked boot, and tests prove no
event-engine or HA callback can synthesize this commit before an operator/API
request. If apply fails after the valid store commit, the process remains
lifeline and a restart loads the now-valid active configuration normally.

Tests cover expired and unexpired invalid B and M rollback targets, explicit
first-commit rollback, nil/non-nil compiled targets, rejected direct-confirm,
new-plain-commit recovery, demotion/sync/nested-confirm preservation, removal
failure, restart without resolution, and prove
that active/candidate bytes, timer generation, persistence, journal success,
and dataplane apply remain unchanged on rejection.

After B merges, C and M extend these private structs and the single
orchestrator in dependency order. C adds its private normalized-SNMP intent
carrier; M adds its AST-shape gate. There is no registration interface,
callback list, cross-workstream result
union, or private proof token crossing package boundaries. Each dependent PR
adds one named call to the central pipeline and a source canary proving every
public entry remains routed through it. B and M always return errors. C returns
its documented reject-user result in tolerant mode and an error in strict mode.

Only B and M are unconditionally hard; C keeps the per-user tolerant
quarantine described below. A peer-only hard B/M or strict-C failure names the
effective node and rejects before promotion. Unrelated validation-only warnings
remain suppressed; an inability to prepare the peer view is not mislabeled as a
successful proof.

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
effect or a synthetic node that section dispatch later forgets. C extends the
B-owned `preparedCompileView`; it does not redeclare or own that pipeline type:

```go
// Private fields appended to B's preparedCompileView by Workstream C:
// NormalizedSNMPRoot *Node
// SNMPSources         map[SNMPObservationID][]SNMPSourceObservation
// SNMPIntent          SNMPv3IntentResult
// SNMPWarnings        []snmpCompileWarning

type snmpCompileWarning struct {
    Code          string
    CanonicalPath string
    Message       string
    Node          effectiveNodeContext
    NodeSpecific  bool
}

type SNMPObservationID struct {
    Kind    SNMPObjectKind
    Ordinal uint32 // stable first-appearance ordinal, never a secret-derived hash
}

type SNMPObjectKind uint8

const (
    SNMPObjectCommunity SNMPObjectKind = iota + 1
    SNMPObjectTrapGroup
    SNMPObjectV3User
    SNMPObjectStructuralError
)

type SNMPSourceObservation struct {
    Identity string // username/trap name, or "community[N]"; never the community
    Field    string // keyword only; never a secret value
    Path     string // every secret token replaced with "<redacted>"
    Present  bool
    Empty    bool
    Conflict bool // distinct values/selectors observed; values are not retained
}

func prepareCompileView(root *ConfigTree, opts compileOpts) (
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

SNMP intent validation and section lowering receive the same
`preparedCompileView` produced by B's compiler pipeline. Raw top-level `snmp` roots and
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

1. `prepareEffectiveCompileSet` returns the normalized root and source
   observations; C's named gate consumes each exact view and stores its private
   `SNMPv3IntentResult` on the requested prepared view for
   `compileRequestedPreparedView`. Validation-only results are verdict-only and
   never become runtime configuration.
2. The section dispatcher invokes `compileSNMP` once with
   `view.NormalizedSNMPRoot`; `compileSystem` does not lower its alias
   independently.
3. `compileSNMPv3` takes the rejected-name set and skips every
   rejected username without mutating the source AST.
4. After lowering, explicitly delete from `V3Users` every identity present in
   the compiler rejection set. Compiler rejection dominates every valid
   duplicate globally; an invalid occurrence can never be resurrected by a
   later valid occurrence.
5. The compiler reduces `SNMPWarnings` by `{Code, CanonicalPath}` plus `Node`
   only when `NodeSpecific`, then appends only the stable nonsecret `Message`
   values to the existing `Config.Warnings` string slice in deterministic
   order. It stores the structured rejection slice in an unexported field on
   the top-level `Config`. A copy-returning `SNMPV3IntentRejections` accessor is
   the only cross-package rejection reader. `SNMPConfig`, its JSON/YAML
   projections, and every REST/gRPC/CLI configuration shape remain unchanged.
6. `RuntimeEvaluation.Fingerprint` includes the sorted internal rejection
   snapshot so a metadata-only transition cannot disappear behind the unchanged-
   hash shortcut. No rejection metadata is serialized into persisted config.

The private runtime fingerprint remains deliberately credential-aware: it
consumes copied community strings and v3 passwords in process so credential
rotation restarts or updates the listener. That value is never persisted,
logged, returned by an API, or reused as an observation identity. This internal
change detector is the sole exception to the no-secret-derived diagnostic rule;
replacing it with the redacted projection would make password and community
rotation invisible.

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

type RuntimeEvaluation struct {
    config      *config.SNMPConfig
    installable map[string]validatedV3User
    rejected    []V3RuntimeRejection
    configuredCommunities int
    configured  int
    installed   int
    omitted     int
}

// Private complete descriptor consumed by key localization. Every field owns
// its storage; no pointer or byte slice aliases the source Config.
type validatedV3User struct {
    name         string
    authProtocol string
    authPassword config.Secret
    privProtocol string
    privPassword config.Secret
}

// Implemented in pkg/config so the private compiled clientNets cache can be
// copied rather than lost or aliased across the package boundary.
func CloneSNMPConfigForRuntime(cfg *SNMPConfig) *SNMPConfig

func EvaluateRuntimeConfig(
    cfg *config.SNMPConfig,
    compilerRejected []config.SNMPv3UserRejection,
) RuntimeEvaluation
func (e RuntimeEvaluation) V3Counts() (configured, installed, omitted int)
func (e RuntimeEvaluation) V3Rejections() []V3RuntimeRejection
func (e RuntimeEvaluation) Enabled(processDisabled bool) bool
func (e RuntimeEvaluation) HasTrapGroups() bool
func (e RuntimeEvaluation) Fingerprint(processDisabled bool) uint64
func (a *Agent) deriveV3Users(eval RuntimeEvaluation) map[string]*usmUser
func NewAgentWithEvaluation(eval RuntimeEvaluation) *Agent
func NewAgentWithPathsAndEvaluation(
    eval RuntimeEvaluation,
    bootsPath, engineIDPath string,
) *Agent
func (a *Agent) UpdateConfigWithEvaluation(eval RuntimeEvaluation)
```

`EvaluateRuntimeConfig` iterates sorted map keys and never dereferences a nil
value. It preserves the existing `len(Communities) > 0` listener-enable
semantics as `configuredCommunities` and carries trap-group presence so boot and
reconcile do not pair a v3 verdict with separately inspected mutable SNMP state;
community validation is not broadened in this workstream. It obtains its owned
snapshot only through `config.CloneSNMPConfigForRuntime`. That config-owned
helper deep-copies every map, pointer, slice, secret, trap target/category, v3
descriptor, `SNMPCommunity.Clients`, and the private compiled
`SNMPCommunity.clientNets` entries; it never round-trips through JSON, which
redacts secrets and omits the cache. Tests mutate every source layer after the
clone and prove `AllowsSource` on the clone retains identical allocation-free
authorization behavior.

The evaluation also deep-copies every installable descriptor and rejection
slice; all fields remain private and every accessor returns values or copies.
An Agent therefore cannot receive an evaluation for one config and a mutable
pointer to another, and a caller cannot mutate authorization state after
evaluation. `Fingerprint` is the sole hash API and is computed inside
`pkg/snmp` over the evaluation-owned snapshot, sorted compiler/runtime rejection
metadata, and `processDisabled`. It preserves the current credential-aware
behavior: community strings and v3 passwords affect the private `uint64`, but
the value is never persisted, logged, marshaled, or returned by an external
surface. The type implements no marshaler, `String`, or secret-bearing debug
projection.
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
seed the rejection map from the top-level Config's internal rejection snapshot;
an identity present
there is never installable even if a hand-built typed duplicate is valid.
Installed and rejected sets are disjoint by construction. Identity-less
structural errors key on a stable path token. Counts are computed from the
union, not by adding occurrence counts, so `Configured == Installed + Omitted`
always holds.

Runtime rejection metadata is unioned with the compiler snapshot by stable
identity (`Identity`, or `Path` when no
name exists), with deterministic sorted field-only reasons. One logical user is
counted once even if both belts reject it. Production daemon code calls
`NewAgentWithPathsAndEvaluation` and `UpdateConfigWithEvaluation`, localizes only
the private installable set before acquiring `cfgMu`, and swaps the evaluation's
owned config snapshot, localized table, and rejection snapshot together under
`cfgMu`. Password-to-key localization is deterministic for a structurally valid
descriptor and cannot downgrade security intent.

The existing `NewAgent`, `NewAgentWithBootsPath`, `NewAgentWithPaths`, and
`UpdateConfig` signatures remain compatibility wrappers. Each wrapper calls
`EvaluateRuntimeConfig(cfg, nil)` exactly once and immediately delegates to the new
evaluation API. All production daemon callers migrate in this PR, and a source
canary forbids those compatibility wrappers in `pkg/daemon`. This preserves
package compatibility without allowing boot and day-2 reconcile to recompute a
different acceptance result.

Listener behavior and diagnostics are evaluated before lifecycle selection.
Boot and day-2 reconcile use this exact flow before choosing or mutating listener
lifecycle:

```go
eval := snmp.EvaluateRuntimeConfig(
    cfg.System.SNMP,
    cfg.SNMPV3IntentRejections(),
)
desired := eval.Enabled(isProcessDisabled(cfg, "snmpd"))
// startSNMPLocked(eval) or agent.UpdateConfigWithEvaluation(eval)
```

`snmpEnabled` becomes a thin `RuntimeEvaluation.Enabled` caller,
`startSNMPLocked` accepts the evaluation rather than `*config.Config`, and trap
monitor selection uses `eval.HasTrapGroups()`. Both paths publish one structured
diagnostic containing exact configured/installed/omitted counts plus sorted
nonsecret identities, then choose start/update/stop from
`eval.Enabled(processDisabled)`, whose definition is exactly
`!processDisabled && (configuredCommunityCount > 0 || installedV3Count > 0)`.
The existing administrative disable always wins;
normalization must not restart a disabled listener. Rejected-only input
therefore publishes its result even when no Agent exists and then stops or
declines UDP/161. The boot path and day-2 reconcile consume this same decision;
the daemon and Agent may not maintain another acceptance predicate. The daemon
deletes its independent `snmpConfigHash(*config.Config)` walker and stores
`eval.Fingerprint(processDisabled)` instead. Boot and day-2 compute the
evaluation once, then use that same value for idempotence, lifecycle, and Agent
update. Unit tests pass deliberately mismatched and subsequently mutated source
configs to prove only the evaluation-owned snapshot reaches Agent state; they
also prove source/evaluation cache independence, credential-only fingerprint
changes, boot/day-2 fingerprint parity, and rejected-only transitions. Boot bind
failure and day-2 rejected-only transitions retain or stop state exactly as the
lifecycle table specifies, with no partial user-table swap.

Operational surfaces have explicit authority without a schema change.
Configuration displays keep their current configured-intent shape; they iterate
sorted map keys, use that key as the display identity, and skip nil values
safely. Existing compiler-warning output and the daemon's structured lifecycle
diagnostic make rejected-only state visible without a live Agent. An internal
Agent status snapshot reports only installed identities plus a copy of the same
rejection set, but REST, gRPC, CLI, JSON, and YAML gain no field in this
workstream and do not independently re-evaluate users. Do not infer configured
intent from derived key presence.

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
validation error. A structurally invalid `ConfirmRecord.PrevTree` also makes
`Load` return `ErrConfigDBUnreadable`, retain `active.json` and `confirm.json`,
publish no compiled active config, and arm no timer; it cannot be downgraded to
the current log-and-continue `ReadConfirm` path. This statement is limited to
the new structural verdict and does not redesign unrelated confirm-file I/O
classification.

This bounded workstream changes no `confirm.json` field, guarded hash, rollback
target classification, timer ordering, or confirmed-commit API. It only rejects
a structurally malformed nonnil `PrevTree` at the existing read boundary. The
statement is scoped to G: Workstream B explicitly owns the additive pending
state/result APIs and semantic validate-before-recovery transitions above after
G has established this structural boundary. Neither workstream adds a persisted
field. The
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

Migrate every repository safety caller to the exact helpers in the same PR: the
single-policy strict gate, composed-chain strict gate, single-policy FRR belt,
composed-chain FRR belt, and tests. Retain the currently exported
`RouteMapSequenceCount`, `ComposedChainSequenceCount`, and
`MaxRouteMapSequences` as deprecated source-compatibility wrappers/constants
with their current signatures and behavior; external Go consumers may compile
against them even though repository search finds no in-tree production caller.
Their documentation must state that they are context-free estimates and are
for compatibility only. A source canary forbids their use in config rejection
or rendering. No safety caller may compare their raw count with a separately
derived maximum. Saturating arithmetic, undefined/empty-list single-family
fallback, prefix-list family expansion, chain termination, and the one terminal
reservation must be shared by gate and renderer.

### 5.10 Workstream I - isolate K003-10 behind a follow-on research gate

K003-10 is confirmed, high-impact, and **not authorized for implementation by
this plan**. The repository exposes three different domains today: a heartbeat
byte can carry IDs through 255, BPF owner/watchdog arrays and Rust owner epochs
have 16 slots, and cluster election/publication accepts configured definitions
without the same bound. An RG above 15 can therefore commit without one complete
forwarding contract.

Snapshot 10 proved that the apparent one-line cap is not a bounded validation
fix. A safe change must decide startup ordering, configless loader ownership,
cluster publication, pending-confirm recovery, persisted rollback artifacts,
mixed-version sync, rolling-upgrade preflight, and exported API compatibility.
Those concerns have different rollback boundaries from the other K003 findings.
Create one dedicated child tracking issue and invoke `/research` on it before
any production edit or PR. The child issue must preserve the live reproducer,
the 16-slot evidence, and the three plan options below.

#### Required path comparison

1. **Cap configured RGs at 0..15.** RG0 remains control and RG1..15 remain data
   owners. This is the current provisional recommendation because it matches
   available dataplane state, but it is a compatibility change and is not
   approved until upgrade and recovery behavior converge.
2. **Widen every dataplane domain to the transport maximum.** Size and migrate
   BPF maps, Rust owner epochs, helper state, watchdog storage, session-owner
   state, and every actuator to 256 entries. Quantify memory/cache cost and map
   ABI migration; do not assume the heartbeat byte is the only bound.
3. **Split control definitions from data-owner bindings.** Keep election-only
   definitions through 255 while constraining owners to 1..15. This path must
   define which daemon loops may consume control-only groups and prove they
   cannot create permanent helper debt, stale ownership, or takeover races.

The follow-on plan may recommend path 1 only after it specifies all of these
contracts precisely:

- **Compiler semantics:** inactive RG content remains dormant and is ignored,
  matching current compiler behavior; it rejects only when activated. Raw
  identity/binding checks run after inactive pruning and node-effective group
  and range expansion. Literal binding zero stays distinguishable from typed
  omission.
- **Config-bearing dominator:** validation occurs at the first daemon
  config-apply/compile boundary, before SNMP, web, bootstrap, VRF, interface,
  fabric, helper, map, or attachment mutations. Configless `Dataplane.Load`
  and shim preparation are either proven neutral or reordered beneath a
  validated transaction; they cannot claim to validate an unavailable config.
- **Cluster publication:** a fallible validate-all-then-swap API covers
  `cluster.Manager.UpdateConfig(*ClusterConfig)` before it inserts election
  state or narrows an ID into heartbeat bytes. Partial group publication is
  forbidden.
- **Runtime belts:** each API has its own acceptance matrix. Definition/control
  writers accept 0 and 15; owner-binding writers accept 1 and 15; negative, 16,
  and 255 reject before mutation. Tests must not demand errors for valid RG0 or
  RG15 operations.
- **Persisted recovery:** `Store.Load` validates active, rollback/rescue slots,
  and `confirm.json`'s `PrevTree` before any recovered tree becomes `active`, is
  persisted, or arms a timer. Invalid recovery input retains the exact artifact
  and enters the existing compile-failed lifeline state. In-process rollback
  promotion consumes only a target compiled under the current gate and still
  has a typed defensive check; stale generation, first-commit nil, timer,
  persistence failure, and retry behavior must be explicit.
- **Upgrade preflight:** a side-effect-free command from the staged candidate
  binary scans a generation-frozen config DB, including every promotion-capable
  artifact, for both effective node views. Rolling upgrade invokes it before
  `ForceSecondary`; standalone invokes it before STOP. The design must explain
  how both nodes are checked before the first cut, how pending-confirm windows
  are excluded or validated, and how a config-generation/hash fence prevents a
  commit between scan and installation. Peer unavailable, interrupted resume,
  encrypted DB, and old-binary behavior are fail-closed cases.
- **Source compatibility:** precise transport constants may be added, but
  exported `MaxHeartbeatRedundancyGroupID` remains a deprecated alias unless a
  separately versioned API break is approved.
- **Validation:** exercise flat/hierarchical/groups/ranges/persisted/local/peer
  paths, the existing node0-only optional-group fixture, direct runtime APIs,
  RG15 IPv4/IPv6 failover, RG16 rejection, restart with pending confirm, and a
  two-node rolling upgrade with a concurrent-commit hostile.

Until that child reaches `PLAN-READY`, #6744 may create the research issue and
document the confirmed hazard, but must not ship a cap, capacity expansion,
control-only filter, runtime range check, or upgrade hook. This is a deliberate
scope boundary, not a claim that K003-10 is fixed.

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
| Local `show security log` text | keep the existing SESSION_OPEN/CLOSE forms, which already omit action |
| Local `monitor security flow` text | omit the lifecycle action token while retaining decision-event actions |
| Remote `show security log` text | omit `action=` for SESSION_OPEN/CLOSE while retaining decision-event actions |
| Remote packet/flow monitor text | omit lifecycle action text while retaining decision/drop reasons |
| REST JSON | retain required scalar field as `"n/a"` |
| SSE structured JSON | retain required scalar field as `"n/a"` |
| gRPC/protobuf | retain existing scalar field as `"n/a"` |
| Binary log | encode `0xff` for OPEN and CLOSE |

Update the existing REST/OpenAPI/protobuf and binary-format field comments to
name `n/a`/`0xff` as the lifecycle sentinel; this is documentation of an
existing scalar/byte value, not a field or wire-version change.

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
zero.

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
| 1a | A (VIP race), D (flowless ICMP), E (DDNS ownership), F (LoadOverride), K (routing ownership), L (lifecycle action) | Disjoint package/file ownership; no shared compiler prerequisite |
| 1b | I (RG domain follow-on research) | Create and dispatch the dedicated research child; it writes no production code and does not depend on B |
| 1c | G (persisted AST bounds) | Establish the `DB.ReadConfirm` shape boundary before B starts compiling recovered rollback targets |
| 2 | B (empty identities and neutral effective-view compiler pipeline) | Requires G; merge and validate this compiler foundation before any dependent compiler slice |
| 3a | H (route-map count), J (address book) | No semantic dependency on B, but shared `pkg/config` files require serial rebase/merge and the complete config test suite |
| 3b | C (SNMP intent), M (nested policy shape) | Each declares B as a prerequisite and extends the one private compiler pipeline; implement in separate worktrees but merge/rebase serially, rerunning all config tests after each |

K003-02 remains with #6548. K003-05 gets a child issue linked to #4313 but does
not claim vSRX parity. K003-12 and K003-C create no child issue.

## 6. Public API preservation

The implementation preserves all existing external RPC, REST, CLI, persisted
configuration, helper wire, event-wire, BPF map, and Rust metadata layouts.
In particular:

- `(*configstore.Store).LoadOverride(string) error` and
  `LoadOverrideAs(string, string) error` keep their signatures. Format
  classification occurs before mutation and uses existing error surfaces.
- Existing CLI, REST, and gRPC load request/response shapes do not change.
- `PendingConfirmState`/`Store.PendingConfirmState` are additive Go APIs used to
  distinguish a live timer from blocked restart recovery. Existing
  `IsConfirmPending` remains source-compatible and true for both states.
- `CommitBlockedRecoveryGen` is an additive, generation-bound daemon recovery
  entry point; it shares the ordinary strict commit implementation and is
  unusable unless state is blocked and both candidate/confirm generations
  match.
- `RollbackPromotion`/`PromoteRollbackResult` are additive typed APIs. Existing
  `PromoteRollback(uint64) (*config.Config, bool)` remains as a deprecated
  wrapper with identical results; all repository callers migrate to the typed
  result so first commit is never inferred from nil.
- Existing compiler entry-point signatures and their non-commit behavior remain
  source-compatible. Workstream B adds `CompileConfigForCommit` for the strict
  configstore/check-config transaction; the existing peer-SNAT validator stays
  exported for compatibility but is no longer called by configstore.
- Existing SNMP listener and client configuration syntax remains accepted when
  its security material is complete. `system snmp` remains a deprecated alias
  whose indistinguishable AST forms are normalized before validation.
- `SNMPConfig` JSON/YAML, CLI, REST, and gRPC projections gain no rejection
  field. Structured rejection metadata is an internal top-level Config sidecar
  exposed only through a copy-returning Go accessor and existing warning/log
  channels.
- The DDNS state-file format and updater interfaces remain stable. K003-03 uses
  the existing per-family updater/fingerprint anchors and does not add a new
  persistence version.
- Route-map rendering and sequence limits remain externally unchanged; gate and
  renderer share one internal cardinality function. Existing exported estimate
  helpers/constants remain deprecated source-compatible wrappers and are barred
  from safety decisions.
- K003-10 changes no BPF map, Rust constant, helper message, heartbeat field,
  cluster API, configured bound, loader, recovery path, or upgrade path in this
  plan. Those choices belong to its follow-on research child.
- No applied-owner inventory, recovery API, local config retry protocol,
  readiness receipt, election intent, persisted takeover marker, binary floor,
  or map migration is introduced.
- Lifecycle events retain their existing binary fields. Human formatting may
  omit inapplicable action text and structured surfaces retain the scalar field
  using the existing `n/a` representation.

The intentional compatibility changes are all fail-closed corrections:

- empty security identities, unsupported nested zone-policy containers,
  malformed persisted AST nodes, incomplete SNMPv3 security configuration,
  and destructive flat override verbs stop committing;
- repeated global address-book containers merge instead of replacing prior
  entries;
- route-map bounds use rendered cardinality rather than referenced-name count;
- transient routing lookup errors retain previous-good ownership;
- flowless readable ICMP errors receive the same global admission already used
  by the flow-backed and kernel paths; and
- lifecycle records no longer fabricate `deny` decisions.

These are not wire-version changes. Any implementation that requires a new
public schema, helper protocol, pinned-map migration, or daemon restart contract
must return to research rather than extending a child PR.

## 7. Hidden invariants the changes must preserve

1. **Fail closed before mutation.** Compiler and persistence rejection runs
   before active-store promotion, helper/map mutation, listener replacement,
   sender-epoch movement, or attachment changes. Peer rejection retains exact
   previous-good state; fresh boot remains lifeline/default-deny.
2. **Node-effective equivalence.** Security identity, policy-container, and SNMP
   gates evaluate both local and peer effective trees after the same
   apply-groups, inactive, repeated-section, and interface-range semantics used
   by lowering.
3. **No normalization alias.** Empty or malformed identities cannot collapse
   into wildcard/global state, and an unspecified generic evaluation context
   cannot alias node 0 before validation.
4. **Exact ownership.** DDNS withdrawal uses only the same-family updater whose
   fingerprint owns the row. Routing reconciliation never deletes prior state
   on a transient inability to establish replacement ownership.
5. **No partial publication.** Repeated address books merge into an isolated
   accumulator and publish only after the complete container set validates.
   `LoadOverrideAs` classifies and parses completely before candidate swap.
6. **Gate/render identity.** Route-map count and renderer expand the same
   family/product domain and reserve the same terminal row. A gate cannot admit
   a sequence set the renderer later truncates.
7. **Packet parse conservation.** K003-01 reuses the already parsed ICMP byte.
   Non-first fragments remain type zero and denied unless independently allowed;
   no new parse, allocation, lookup, or packet-path lock is introduced.
8. **Security intent dominates implementation fallback.** SNMPv3 configured
   authentication/privacy cannot silently downgrade to a lower security level.
   Invalid users remain observable through redacted compiler warnings and
   structured daemon diagnostics and cannot make a listener appear healthy.
9. **RG research gate.** K003-10 is not silently downgraded or partially fixed.
   No configured cap, map widening, control-only filtering, runtime range belt,
   recovery change, or upgrade hook ships until its dedicated research child
   converges on one end-to-end domain and rollback contract.
10. **Event semantics are type-derived.** Action applicability comes from a
    positive event-type classification, not a producer's zero byte. Existing
    real policy/filter/screen decisions retain their current values and severity.
11. **Lock order stays local.** The VIP warning fix adds one dedicated mutex
    used only by helper methods and introduces no edge with `directVIPMu`,
    `applySem`, config-store locks, or dataplane locks.
12. **Diagnostics do not leak secrets.** SNMP validation and status identify
    source/path/ordinal without logging community strings, passwords, localized
    keys, or secret-derived stable identifiers.
13. **Rejection is retryable.** Fixing the source and applying a newer valid
    generation succeeds without sticky quarantine or manual state deletion.
14. **Compiler preparation is bounded and single-transactional.** Strict
    commit/check owns at most one raw plus three context-distinct effective views,
    preserves existing error/warning order, and does not recursively compile a
    peer. Compatibility APIs outside that transaction retain their documented
    peer and node-ID semantics.

## 8. Risk assessment

| Risk | Level | Why | Required control |
|---|---|---|---|
| Security-policy widening | High | Empty identities or silently omitted nested policies can broaden access | Both-node effective-tree gates, strict+tolerant rejection, previous-good tests |
| Invalid rollback publication | High | Restart recovery currently assigns or arms a persisted target even after compile failure | G-before-B structural gate, fallible compile-before-assignment, explicit blocked/first-commit state, expired/unexpired tests |
| SNMP confidentiality/integrity downgrade | High | Configured auth/privacy can currently become weaker runtime users | Pure normalized intent validator, redacted diagnostics, packet-level security-level tests |
| DDNS ownership loss | High | Wrong-family deletion can orphan or remove records at the wrong endpoint | Fingerprint-bound same-family selection, save-failure and mixed-endpoint tests |
| HA outage | High | RG16+ definitions/bindings are accepted even though the complete runtime has only 16 slots | Preserve the confirmed reproducer; create the dedicated research child; forbid a partial implementation until compiler, startup, cluster, recovery, upgrade, mixed-version, and smoke contracts converge |
| Availability regression | Medium | ICMP and routing fixes change allow/retain behavior | Narrow packet and netlink fault-injection tests; no broad fallback |
| Configuration compatibility | Medium | Invalid shapes accepted historically will reject | Repository-history fixtures, exact diagnostics, release notes, load/boot/peer tests |
| FRR truncation/regression | Medium | Cardinality changes affect commit boundary | Property tests comparing gate count to rendered rows across AF/products |
| Concurrency regression | Medium | VIP warning map is shared by concurrent paths | Race test, helper-only access canary, `go test -race` |
| Observability compatibility | Low | Lifecycle human text changes | Golden tests for every formatter and structured/binary stability tests |
| Compiler resource amplification | Medium | Both-node proof adds bounded AST clones and gate passes at the 16-MiB input ceiling | Exact context-keyed three-view ceiling and 1/8/16-MiB time/allocation benchmarks |
| Packet-path performance regression | Low | K003-01 is the only packet-path change | Benchmark/no-allocation assertion for the flowless verdict and no new hot-path work |

Every child issue must restate its own rollback boundary. No child may absorb a
new protocol, map migration, or unrelated persistence merely because the risk
is adjacent.

## 9. Test and validation plan

### 9.1 Test-first requirement per workstream

Each implementation begins with a test that fails on current `master`, passes
after the fix, and fails again when the key correction is reverted. Tests call
real production entry points where practical; source canaries supplement but
do not replace behavioral tests.

| Workstream | Required hostile coverage |
|---|---|
| A - VIP warning race | Concurrent add/delete/read under `-race`; repeated warning suppression; canary forbidding direct map access outside helpers |
| B - empty identities/compiler transaction | Empty zone, zone-pair, scope and policy names through hierarchy/set, apply-groups, local/peer, strict/tolerant; typed undefined-group errors and all five node-view resolution states; generic, node 0/1, and other direct-node compatibility; one `CompileConfigForCommit` call with existing requested/node-ID/RA errors ahead of new peer gates; complete none/armed/blocked pending-confirm transition matrix; invalid-active/valid-target upgrade rollback, invalid-target quarantine, canonical first-commit metadata, typed daemon/CLI rollback results, blocked-bootstrap plain-commit recovery; 1/8/16-MiB preparation benchmarks and a three-context ceiling; prove no wildcard/global widening or rejected-path mutation |
| C - SNMPv3 intent | Auth-only, privacy-only, missing passwords, duplicate/conflicting users, both AST aliases, rejected-only config, reload, redacted diagnostics, and packet security-level matrix |
| D - flowless ICMP | Readable ICMPv4 error and ICMPv6 PTB/ND global admission; non-first fragment remains zero/denied; configured deny/lo0 filter still wins where designed |
| E - DDNS ownership | Distinct v4/v6 backends, disable either family and both, credential rotation, save failure, wrong fingerprint, co-owner release, delete error/success; never delete through the other family |
| F - LoadOverride | Hierarchy, complete set/deactivate, destructive delete/activate, mixed input, malformed/empty/comment-only input, every API/CLI entrypoint; candidate is byte-identical on failure |
| G - persisted AST | Empty/malformed Keys at every indexed node, active/candidate/rollback/confirm files, checksum-valid hostile JSON, both indexing belts; typed error rather than panic |
| H - route-map cardinality | IPv4, IPv6, dual-family lists, multiple communities/protocol products, chain composition, exact max and max+1; gate count equals emitted rows/property oracle |
| I - RG domain | Research artifact only: preserve the reproducer/evidence, compare all three paths, enumerate compiler/startup/cluster/recovery/upgrade/API/smoke contracts, and prove no production edit or PR is authorized before its own convergence |
| J - address books | Repeated global containers, duplicate names, mixed valid/invalid blocks, ordering and reference resolution; atomic no-partial publish |
| K - routing ownership | Bond delete and tunnel Clear distinguish netlink not-found from transient lookup failure; tracking retained on ambiguity; later retry deletes the same kernel link and clears ownership only after success/absence |
| L - lifecycle action | Every lifecycle and decision event across slog, trace, event buffer, SSE, REST/gRPC/CLI and binary decode; filters use normalized applicability |
| M - policy shape | Canonical combined form accepted; nested/partial/malformed forms rejected through hierarchy/set/persisted/peer paths; default-policy permit/deny cannot hide omission |

Cross-workstream tests additionally prove:

- all B/M action-agnostic hard gates run on every available node-effective tree,
  with the exact optional-missing-peer-group case preserved;
- strict commit/check prepares one compiler transaction, does not invoke the
  exported peer-SNAT compatibility wrapper, and never expands or lowers one
  prepared effective view twice;
- G rejects a malformed confirm target before B's recovery compiler, while B
  safely restores a valid rollback target even when the unconfirmed active
  config is newly rejected after upgrade;
- every rejected local or peer generation leaves active config, compiled state,
  helper/map calls, attachment state, and sender generation unchanged;
- duplicate checks use current open/closed issue ownership before child creation;
- documentation and examples match exact accepted syntax; and
- each child PR's tests pass with its declared prerequisites and without any
  undeclared workstream; reverse-order revert tests remove C/M before B and
  prove the remaining tree still compiles and passes its focused suites.

### 9.2 Required local gates

Run the narrow package tests first, then the repository gates appropriate to the
touched language:

```text
go test ./pkg/config ./pkg/configstore ./pkg/ddns ./pkg/snmp ./pkg/routing ./pkg/logging ./pkg/daemon ./pkg/dataplane ./pkg/cluster
go test ./pkg/config -run '^$' -bench 'BenchmarkCompileConfigForCommit_(1|8|16)MiB' -benchmem
go test -race ./pkg/daemon ./pkg/ddns ./pkg/routing
cargo test --manifest-path userspace-dp/Cargo.toml
cargo clippy --manifest-path userspace-dp/Cargo.toml --all-targets -- -D warnings
make test
```

Package subsets may be narrowed in a child PR only when its changed-file and
dependency graph proves the omitted packages are unreachable. Record exact
commands and failures in the PR. Generated-file or fixture changes also run the
repository generation/drift checks.

### 9.3 Runtime smoke requirements

- K003-01: userspace dataplane packet smoke for IPv4/IPv6 firewall-local ICMP
  errors, PMTUD, non-first fragments, and lo0/host-inbound ordering.
- K003-10: no runtime smoke is claimed by this split plan because it authorizes
  no implementation. Its follow-on research must make RG15/RG16 HA, restart,
  pending-confirm, peer-sync, and rolling-upgrade smoke an approval gate for
  whichever path it recommends.
- K003-03: integration test against two independently instrumented DNS update
  endpoints, verifying each family withdraws only from its owning endpoint.
- K003-13: SNMPv3 authNoPriv/authPriv requests against valid users and rejection
  of every configured-but-incomplete security level.
- K003-11: network-namespace/netlink fault injection proving a transient bond or
  tunnel lookup failure retains link ownership, reports the teardown error, and
  a later retry deletes the same kernel device and converges.

Other workstreams are compiler, persistence, race, or formatting changes and do
not require cluster smoke unless their implementation broadens the design.

## 10. Out of scope

- Engineering, production code, child issues, or pull requests during this
  `/research` run.
- Reimplementing #6548's local CLI fix or broadening #4313 beyond K003-05's
  concrete unsupported-policy-container rejection.
- A syslog handshake-deadline change based on the refuted K003-12 claim.
- Filing or engineering the undocumented 128-item cohort. The source report
  provides no reproducible per-item evidence for it.
- Broad AST/parser normalization across all configuration packages.
- Supporting the nested policy hierarchy as a vSRX feature; official Junos
  syntax uses the combined `from-zone X to-zone Y` container.
- Any K003-10 production change, including capping configured IDs, expanding
  active dataplane ownership, or splitting control-only groups. Its dedicated
  research child owns map/runtime capacity, compiler semantics, recovery,
  rolling upgrade, mixed-version behavior, and operational rollback.
- Any SessionSync protocol redesign, session/DNAT map migration, AF_XDP or hook
  lifecycle migration, helper-generation replacement protocol, daemon
  publication-cell architecture, persistent ACK outbox, bulk/tail protocol,
  binary rollback floor, or forward-only migration journal. Each needs an
  independently reviewed issue if a current defect and bounded design are
  proved; none may be smuggled into the K003-10 research child as an assumed
  prerequisite.
- Generalized DDNS namespace and teardown protocol: endpoint aliases/anycast,
  cross-surface linearization, publication-versus-deletion races, durable
  claimant election, legacy fingerprint migration, HTTP-provider identity, and
  duplicate-key semantics. K003-03 retains and alarms rather than guessing.
- Commit-confirm redesign beyond B's bounded validate-before-recovery state:
  crash ordering between `active.json` and `confirm.json`, guarded-hash
  semantics, downgrade, or a generalized artifact-quarantine protocol.
  K003-04/G validates embedded AST shape only; B adds no new persisted field.
- Documenting `system snmp` as canonical or adding new SNMP features. It remains
  a deprecated typed alias whose existing persisted forms must reload.
- Changing public/binary event layout or assigning permit/deny to lifecycle
  events. K003-14/15 centralizes applicability only.
- Refactoring all logging formatters, routing reconciliation, SNMP, DDNS, or
  config compilation beyond the exact retained roots.

## 11. Resolved adversarial decisions

1. Use one child issue per retained root cause, with K003-14/15 kept together
   because both arise from the same lifecycle-action classifier. The result is
   13 child issues, 12 scoped implementation PRs, and one K003-10 follow-on
   research track with no PR. B is the explicit compiler prerequisite for C and
   M, while G is the persisted-input prerequisite for B's recovery slice. Merge
   G, B, then C/M and revert in reverse order. All other implemented leaves
   remain independently revertible.
2. K003-02 is owned by #6548. K003-05 is not a vSRX parity feature; it is a live
   honesty/security defect linked to #4313 and is fixed by rejecting an
   unsupported shape. K003-12 is refuted. K003-C is unactionable.
3. Flat override accepts complete `set` and `deactivate` artifacts and rejects
   destructive `delete`/`activate` verbs. Hierarchical mode validates complete
   schema roots. All classification and parsing precede candidate replacement.
4. K003-10 is live, but no RG domain choice is approved here. A 0..15 configured
   cap is the provisional recommendation; widening to 256 and splitting
   control/owner domains remain explicit alternatives. Snapshot 10 proved each
   choice reaches startup, cluster publication, persisted recovery, and upgrade
   semantics, so a dedicated `/research` child must converge before code.
5. DDNS withdrawal uses exact same-family current/retained updater ownership and
   a matching nonempty fingerprint. No representative cross-family updater or
   credential-generation guess is allowed.
6. SNMPv3 intent is validated on one normalized merged root. Configured auth or
   privacy cannot silently downgrade; rejected users remain visible only through
   redacted source identities and cannot start a misleading healthy listener.
7. Lifecycle applicability is a positive event-type allowlist evaluated before
   formatting. Real policy/filter/screen decisions retain their current action;
   lifecycle records expose `n/a`/omission rather than fabricated deny.
8. VIP warning state uses one dedicated mutex and helper-only access, with no
   lock-order edge to dataplane or config application.
9. Persisted active, candidate, rollback, and confirm trees receive minimum
   structural validation before any indexed compiler walk. A non-first pending
   confirm target must also compile before assignment or timer arm; failure
   remains explicitly pending and forces lifeline until confirmed or replaced.
   Broader confirm crash consistency is separate research.
10. Route-map safety uses one shared rendered-cardinality/product helper and one
    terminal-row reservation. Neither raw references nor conservative wrappers
    decide admission.
11. Repeated global address books merge atomically; routing transient errors
    retain previous-good; both low/medium roots remain separately reviewable and
    may still be killed if implementation-time reproduction disproves impact.
12. Action-agnostic hard gates for empty identities and policy-container shape
    run on every available node-effective tree in strict and tolerant paths
    before publication. An absent optional `${node}` peer group remains the
    current nonfatal unavailable-view case. SNMP intent is also
    evaluated on both views: strict paths reject, while tolerant paths
    quarantine every occurrence of each invalid user before lowering/runtime
    installation and retain only redacted diagnostics. Unrelated compatibility
    warnings remain lenient.
13. Flowless ICMP passes the already parsed type only when L4 is present.
    Fragment behavior, lo0 ordering, and existing host-inbound deny semantics do
    not change.
14. Manual `/engineer 6744` approval accepts these bounded product choices only.
    A child implementation that needs a new protocol, schema, map migration, or
    materially different invariant returns to research.
