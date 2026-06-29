# pkg/config

Junos configuration parser, AST, typed data model, and compilation
pipeline. Three phases: text → AST (`ConfigTree`) → typed `Config` struct.
Handles both hierarchical (`family inet { dhcp; }`) and flat set
(`set interfaces eth0 unit 0 family inet dhcp`) syntaxes.

This is the foundation almost every other package imports. It depends on
nothing internal.

## Entry points

- `Lexer` — `lexer.go`.
- `Parser` — `parser.go`. **Hierarchical** input.
- `ParseSetCommand(input string) ([]string, error)` — `parser.go`.
  Parses one flat-set line into the path components. The caller then
  applies that path with `tree.SetPath()` to build the AST.
- `ConfigTree` — `ast.go`. Hierarchical node tree built by both shapes.
  `ast.go` owns the AST node types (`Node`, `ConfigTree`) and tree
  navigation/mutation helpers — the parser's data model.
- `setSchema` + `schemaNode` — `schema.go` (split out of `ast.go` in
  #1699). The config-mode grammar SSOT; see `docs/config-schema.md`.
  Completion / path-resolution helpers (`CompleteSetPath`,
  `CompleteSetPathWithValues`, `ResolveConsumedSetPathTokens`) live in
  `schema_complete.go`.
- `Config` — `types.go`. The fully typed result every consumer wants.
- `CompileConfig(tree) (*Config, error)` — `compiler.go`. AST-to-typed-
  struct walker. Clones the tree, expands `apply-groups` (with
  `${node}` fallback for cluster mode), then dispatches over AST
  nodes via a switch statement to fill the typed `Config`. Eleven
  `compiler*.go` files in this package, ~7.6K LOC total
  (`compiler.go` + `compiler_interfaces.go`, `compiler_routing.go`,
  `compiler_security.go`, `compiler_services.go`, `compiler_system.go`,
  `compiler_firewall.go`, `compiler_nat.go`, `compiler_ipsec.go`,
  `compiler_protocols.go`, `compiler_class_of_service.go`).
  Note: this is the **AST → typed Go struct** stage; the BPF-map
  compilation (zones, policies, NAT IDs, etc.) happens later in
  `pkg/dataplane.Manager.Compile`.
  This stage also performs a few **fail-closed semantic checks** that the
  `setSchema` typed-leaf gate cannot express. `compileFirewall` rejects a
  firewall-filter `from tcp-flags` expression the conjunctive dataplane
  matcher cannot enforce — disjunction (`|`), a negated group (`!(...)`),
  an unknown flag, or a contradictory required/forbidden pair (#3076) —
  via `ParseTCPFlagsExpression` (`tcp_flags.go`). Before this gate such an
  expression committed cleanly and the constraint was silently dropped on
  the wire (the term matched regardless of flags — a fail-open hole); a
  representable expression such as `syn & !ack` is parsed into
  required-bits + forbidden-bits masks and carried to the dataplane.
- `ValueType` — `value_type.go`. Classifies a typed leaf's value
  (`ValueRate`, `ValueByteSizeOrPercent`, `ValueEnumOf`, ...) and supplies
  the `?`-completion placeholder via `Placeholder()`. Lives here (not
  cmdtree) so `setSchema` can carry typed-leaf metadata directly;
  `pkg/cmdtree` re-exports it via aliases. See `docs/config-schema.md`.
- `SchemaValidate(tree, cfg)` + the generic walker — `schema_walk.go`.
  The #1319 commit-check gate. Descends `setSchema` against the AST (the
  SAME tree the live config-mode `set ... ?` completer walks via
  `CompleteSetPathWithValues`) and invokes each typed leaf's validator on
  its value. It is a no-op for untyped subtrees (opt-in per leaf), so
  per-subsystem typing lands incrementally without touching this walker.
  Called by `pkg/configstore.compileTree` on the apply-groups-expanded
  clone BEFORE compile, so garbage like `transmit-rate asd` fails loud at
  `commit check` even when it arrives through `groups { ... }`. (Re-homed
  from `pkg/cmdtree.SchemaValidate` in #1319 PR 1.) The gate is strict
  ONLY on the commit/commit-check path: the tolerant `Store.Load` /
  `Store.SyncApply` ingress (`compileTreeLenient`) downgrades a violation
  to a warning so a stored or peer-synced config carrying a value typed
  or range-tightened after it was persisted cannot blackout-boot a node
  or alarm-loop HA config sync (#1319 PR 2 boot safety).
- `Validate*` functions — `schema_validators.go`. Stateless string
  validators (`ValidateRate`, `ValidateByteSize`,
  `ValidateByteSizeOrPercent`,
  `ValidateInteger(min,max)`, `ValidateEnum(allowed)`,
  `ValidatePercent(min,max)`) for the typed-leaf gate. Attached to
  `setSchema` leaf `validator` fields (and `cmdtree.Node.Validator` for
  operational leaves) and dispatched by `SchemaValidate` at commit-check
  time, on the same apply-groups-expanded tree the compiler consumes, so
  garbage like `transmit-rate asd` fails loud instead of silently zeroing
  in the existing parsers. Scheduler `buffer-size` validation accepts byte
  sizes with explicit suffixes and percent values with an explicit `%`
  suffix. The compiler stores percent values separately from
  `BufferSizeBytes`; the userspace snapshot adds `buffer_size_percent`
  while preserving the legacy `buffer_size_bytes` field. The Rust
  userspace dataplane resolves percent buffers against the interface CoS
  burst pool when a scheduler is bound to an interface queue. The strict
  config pass rejects scheduler-map percent totals above 100% on one
  interface unit. xpf rejects Junos `0%` intentionally because the
  additive wire field uses zero as the legacy absent value.
  `parseBandwidthLimitStrict` / `parseBurstSizeLimitStrict` /
  `parseScaledDecimalUnitStrict` in `compiler_protocols.go` are the
  error-returning siblings of the legacy zero-return parsers — the legacy
  versions keep their "unset = 0" contract for compatibility.

## Node modifiers

- `inactive:` (`#2008` H1) — the Junos deactivate-without-delete marker.
  An operator deactivates any statement by prefixing it with `inactive:`;
  the node stays in the tree (it displays in `show configuration`,
  persists through commit/reboot, syncs to the HA peer, and can be
  re-enabled later) but is EXCLUDED from compilation/application — the
  firewall behaves as if the statement were absent. Because `:` is an
  identifier character, the lexer emits `inactive:` as a single token; the
  parser (`parser.go`) detects it as a statement's leading key and LIFTS it
  into `Node.Inactive`, leaving the node's real `Keys` (its identity)
  intact so every key match, schema walk, and group merge keeps working
  unchanged. `inactive.go` provides the single centralized strip
  (`ConfigTree.WithoutInactive`, a no-op clone-free pass when nothing is
  deactivated) that prunes inactive subtrees BEFORE group expansion and
  compilation (both `compileConfig*` entry points) and BEFORE the typed-leaf
  schema walk (`SchemaValidateWithDefinitions`). Stripping first means an
  `inactive: apply-groups foo` suppresses the inherited config, inactive
  nodes inside a `groups {}` body are pruned, the pre-expansion tunnel-id
  collision gate ignores inactive tunnel definitions, and a deactivated leaf
  with a deliberately-invalid value commits clean (Junos parks WIP). The
  ~15 compiler files and the schema gate never observe an inactive node, so
  none of them changed. All five display serializers (text, inheritance,
  set, JSON, XML) plus the `show | compare` diff re-emit the marker from the
  flag via the shared `inactivePrefix` / `xmlInactiveAttr` helpers; set form
  emits a `deactivate <path>` line (Junos `display set` convention) and
  `nodesEqual` treats a flipped `Inactive` as a difference so a pure
  activate/deactivate shows in `show | compare`. The flag round-trips
  through the persisted DB automatically — `Node.Inactive` is JSON-tagged
  `,omitempty`, so active-node on-disk output is byte-identical to
  pre-`#2008`. The `deactivate <path>` line that `display set` emits also
  round-trips through reload: `ParseSetVerb` (`parser.go`) recognizes
  `deactivate` / `activate` as real verbs and `ConfigTree.DeactivatePath` /
  `ActivatePath` (`ast_edit.go`) apply them (used by the configstore
  `LoadSet` / `LoadMerge` replay loops), so an inactive node reloads inactive
  rather than being skipped (silently reactivated) or parsed as a junk path.
  Regression coverage: `pkg/config/inactive_test.go`,
  `pkg/configstore/inactive_test.go`. The interactive standalone
  `activate` / `deactivate` config-mode verbs (editing the candidate directly,
  distinct from `load set` replay) shipped in #2051 across all four config
  surfaces (local CLI, remote CLI, gRPC, REST) on top of these primitives —
  the store wrappers `configstore.Store.DeactivateFromInput` /
  `ActivateFromInput` route through the same `applyEditLine` verb switch.

## Callers

Almost everyone. The package has no internal dependencies.

## Gotchas

The compiler must accept both AST shapes:

- Hierarchical `family inet { dhcp; }` lowers to `Node{Keys:["family","inet"]}`
  with a child `Node{Keys:["dhcp"]}`.
- Flat `set interfaces eth0 unit 0 family inet dhcp` lowers to
  `Node{Keys:["family"]}` with child `Node{Keys:["inet"]}`.

If you only handle one shape, set-syntax tests will look fine but real
hierarchical commits will break (or vice versa).

**Testing flat-set syntax:** ALWAYS use `ParseSetCommand()` + a
`tree.SetPath()` loop, NEVER `NewParser()` on a multi-line set blob. The
parser treats newlines as whitespace and merges multiple set lines into
one giant node. This trap has bitten the project repeatedly — see
CLAUDE.md.

**Security-policy terminal action is fail-closed (#3043):** `PolicyAction`'s
zero value is `PolicyPermit`, so a policy whose `then` stanza names no
terminal action (log-only/count-only or a typo'd `then`) historically
compiled to a silent PERMIT. `validatePolicyTerminalActionStrict`
(`compiler_validate_strict.go`) hard-rejects a policy that does not name
exactly one of permit/deny/reject at commit; the tolerant load/peer-sync
path downgrades to a warning AND `compilePolicy` defaults an actionless
policy's `Action` to `PolicyDeny`, so a leniently-loaded bad config fails
closed rather than open. See `docs/config-schema.md` "#3043".

**Security-policy `then log` requires session-init/session-close (#3060):**
the schema accepts a bare `then log`, and `compilePolicy` compiles it to a
non-nil `PolicyLog` with both `SessionInit` and `SessionClose` false. The
policy then REPORTS logging enabled over REST (`pkg/api/security.go`:
`Log: rule.Log != nil`), gRPC, and CLI, yet emits NO session records — on a
security appliance, audit looks active while producing nothing. Junos
requires at least one of session-init/session-close under `then log`.
`validatePolicyLogActionStrict` (`compiler_validate_strict.go`) hard-rejects
a policy (zone-pair OR global) whose `then log` names neither at commit;
rejecting the bare form moots the REST/gRPC/CLI display divergence (no
bare-log config can exist post-commit). The tolerant load/peer-sync path
downgrades to a warning (`lenientPolicyLogAction`) so an already-persisted or
peer-synced config still boots (#1960 no-brick) — a leniently-loaded bare-log
policy simply logs nothing, exactly as before. Same fail-closed-on-load
doctrine as #3043.

**Security-policy `match application` must be defined (#3144):** a policy
`match application <name>` token resolving to NONE of {predefined junos-*
application, user-defined `applications application <name>`, user-defined
`applications application-set <name>`} was previously only WARNED at commit
(`compiler_validate_warn.go`). But at runtime the userspace capability gate
(`resolveUserspaceApplicationNames` in `pkg/dataplane/userspace/capabilities.go`)
resolves the SAME name set and returns false for an unknown name →
`expandUserspacePolicyApplications` fails → the built rule carries the reserved
`__unsupported__` sentinel term → the dataplane refuses to arm that policy
(#3261, helper integrity preflight). The operator
got a green commit and a silently DISARMED policy engine on the firewall's
primary allow/deny path — a commit/apply split, fail-open.
`validatePolicyMatchApplicationsStrict` (`compiler_validate_strict.go`)
hard-rejects an undefined reference (zone-pair OR global, including every
element of a `match application [ a b c ]` list) at commit, naming the policy
scope, the policy, and the undefined token. Resolution mirrors the runtime gate
`resolveUserspaceApplicationNames`: a name resolves only if it is a predefined /
user application (`ResolveApplication` — user apps then the predefined table)
OR an `application-set` that EXPANDS to >= 1 member (`ResolveApplicationSet` +
`ExpandApplicationSet`, the exact runtime check). `any` and the empty token are
always accepted. A defined-but-EMPTY application-set (#3146) is rejected with a
distinct message: the set resolves by name but expands to zero applications, so
the runtime gate returns false and the dataplane refuses to arm — the same
fail-open class. (#2217's `validateApplicationSetMembersStrict` `continue`s on
an empty set, so this gate is the one that catches it.) The tolerant load/peer-sync path downgrades to
a warning (`lenientPolicyMatchApplications`) so an already-persisted or
peer-synced config still boots (#1960 no-brick) — the dataplane independently
refuses the policy, so a leniently-loaded bad config is no worse off, now
flagged. Distinct from #2217 (`validateApplicationSetMembersStrict`), which
rejects a dangling MEMBER of a DEFINED application-set; this gate catches a
wholly undefined top-level reference that #2217's `ExpandApplicationSet` walk
never sees. The `compiler_validate_warn.go` application warning was removed
(converted): the strict gate supersedes it on commit and the lenient gate emits
the single warning on load — eliminating both a duplicate warning and the old
24-entry builtin list's false positive on predefined apps outside it (e.g.
`junos-pingv6`, `junos-tcp-any`). Same fail-closed-on-load doctrine as
#3043/#2401.

**Security-policy address references must fully resolve (#3149, folds #3147):**
the address-book sibling of #3144/#3146. A policy `match source-address` /
`match destination-address` that names a DEFINED address-book entry (an address
or an address-set) whose recursive members DANGLE (point at an undefined
address/address-set), or that is a defined-but-EMPTY address-set, or a defined
address with no configured prefix, was previously only WARNED at commit
(`compiler_validate_warn.go`). At runtime the userspace address resolver
(`resolveUserspaceAddressBookEntry` + `expandUserspacePolicyAddresses` in
`pkg/dataplane/userspace/capabilities.go`) returns false for the same name — a
dangling member fails the WHOLE set, an empty set never sets `resolvedAny`, a
prefix-less address has an empty Value — so `expandUserspacePolicyAddresses`
fails → the built rule carries the `__unsupported_address__` sentinel → the
dataplane refuses to arm that policy. The operator got a green commit and a
silently DISARMED allow/deny path — a commit/apply split, fail-open.
`validatePolicyMatchAddressSetMembersStrict` (`compiler_validate_strict.go`)
hard-rejects such a reference (zone-pair OR global, source AND destination,
including the recursive address-set-of-address-sets case) at commit, naming the
policy scope, policy, field, and the inner failure. Resolution mirrors the
runtime resolver EXACTLY (`policyMatchAddressBookResolves` replicates
`resolveUserspaceAddressBookEntry`'s fail-closed semantics and the outer
`len(values) == 0` reject), so the commit gate and the runtime gate cannot
diverge. `any` / `any-ipv4` / `any-ipv6` / the empty token and literal CIDR/IP
tokens are passed through; a wholly-undefined token stays the domain of
`validatePolicyMatchAddressesStrict` (#2008), which runs first. **#3147
excluded-inversion safety:** the resolver runs on the same address lists the
runtime gate checks, regardless of `*-address-excluded`, so rejecting an empty /
dangling set at COMMIT is fail-CLOSED for the excluded case too — an empty
excluded set can never be committed, so it can never reach the dataplane and
invert to MATCH-ALL (the historic fail-open this constraint guards against). The
tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyMatchAddressSetMembers`) so an already-persisted or peer-synced
config still boots (#1960 no-brick) — the dataplane independently refuses to arm
such a policy, so a leniently-loaded bad config is no worse off, now flagged. The
`compiler_validate_warn.go` address-set member warning is RETAINED for the
lenient path and for unreferenced sets (which never reach the runtime gate, so
they stay warn-only). Same fail-closed-on-load doctrine as #3144/#3146.

**Zone-local address books (#3061):** Junos supports both the global
`security address-book global { ... }` and a per-zone book attached inline
under `security zones security-zone <z> address-book { address ...;
address-set ...; }`. xpf parses the zone-local shape into
`ZoneConfig.AddressBook` (`compileZones`, same entry grammar as the global
book via the shared `parseAddressBookEntries`). Resolution order follows
Junos scoping: a policy's `match source-address` resolves against its
FROM-zone book first, `match destination-address` against its TO-zone book
first, then both fall back to the global book. `resolveZoneLocalAddressBooks`
(`compiler_security.go`, run from `compileExpanded` after the name gate below)
folds every zone-local entry into the global `SecurityConfig.AddressBook`
under a `/`-separated zone-qualified internal name (`zone-local/<zone>/<name>`)
and rewrites each policy match token that resolves zone-locally to that
qualified name. A token NOT defined in the policy's zone book is left unchanged
so it resolves against the global book. The synthetic `zone-local/` namespace
is collision-proof: the lexer permits `/` in an identifier token (needed for
IP literals like `10.0.0.0/24`), but `validateAddressBookEntryNamesStrict`
(#3061, run BEFORE the fold on the pristine global book) hard-rejects `/` in
any address-book entry name (global or zone-local) and any security-zone name
at commit — matching Junos object-naming rules — so no operator-typed name can
contain `/` and therefore none can equal a synthetic name (only the NAME is
checked, never the address VALUE/prefix; the fold also skips an already-present
key as a defence-in-depth no-clobber on the tolerant load path, which warns
rather than rejects per #1960). After this pass
the entire downstream path (wire snapshot, `nameToID`,
`classifyPolicyAddresses`, the strict/warn validators, the
`resolveUserspaceAddressBookEntry` runtime resolver) keeps operating on a
single flat global book — no zone needs to be plumbed through resolution. A
name present only in zone A's book is therefore invisible to a policy in zone
B: if B's policy references it and the global book has no such entry,
`validatePolicyMatchAddressesStrict` (#2008) rejects it at commit, exactly as
Junos treats an undefined reference. NAT rule address-name references
(`source-address-name` etc.) remain global-only; zone-local resolution is
scoped to security-policy match addresses.

**An interface belongs to exactly one security zone (#3072):**
`pkg/dataplane/userspace.buildInterfaceZoneMap` builds the interface->zone
lookup by iterating zone names in SORTED order and writing each interface
(plus its base/unit aliases) first-writer-wins. An interface listed under
two zones was therefore silently accepted at commit and resolved to
whichever zone name sorts first — independent of operator intent — so
traffic was evaluated against the wrong zone's policy.
`validateZoneInterfaceMembershipStrict` (`compiler_validate_strict.go`)
hard-rejects a config that assigns the same interface to more than one
zone, naming the interface and both conflicting zones; the tolerant
load/peer-sync path downgrades to a warning
(`lenientZoneInterfaceMembership`) so an already-persisted or peer-synced
config still boots (`buildInterfaceZoneMap` keeps its deterministic
first-writer-wins resolution, so the leniently-loaded config forwards
exactly as before). Two DIFFERENT units of one physical interface in two
zones (`ge-0/0/0.0` in trust, `ge-0/0/0.1` in untrust — a valid VLAN
split) are NOT rejected; a bare physical interface and one of its units
across zones ARE (same logical interface). Same fail-closed-on-load
doctrine as #3043/#2401.

**Backup-router destination family must match the next-hop (#2911):**
`renderBackupRouter` (`pkg/frr/config_render.go`) keys the static-route
prefix keyword (`ip` vs `ipv6`) on the NEXT-HOP family (#2891/#2907). An
explicit `system backup-router <nh> destination <prefix>` whose prefix is a
DIFFERENT family than the next-hop therefore renders a mismatched-family
static — e.g. `backup-router 2001:db8::1 destination 0.0.0.0/0` →
`ipv6 route 0.0.0.0/0 2001:db8::1 250` — which frr-reload rejects, failing
the ENTIRE static config load (the exact breakage #2907 fixed for the
empty-destination case). `validateBackupRouterDst` (`compiler_system.go`)
hard-rejects an explicit family mismatch at commit, naming both addresses
and families; the tolerant load/peer-sync path downgrades to a warning
(`lenientBackupRouterDst`) so an already-persisted or peer-synced config an
older binary accepted still boots (#1960 no-brick). An EMPTY destination is
left to #2907's next-hop-family-aware default (never a mismatch); a
matched-family explicit destination passes. Same fail-closed-on-load
doctrine as #3043.

**VRRP virtual-address must fall within a unit subnet (#3013):** a
`vrrp-group <id> virtual-address <vip>` is authored under a
`family inet|inet6 address <prefix>` on an interface unit. In Junos/vSRX a
VIP outside every on-link subnet of the unit is a commit-time configuration
error; xpf accepted it and at runtime installed the VIP as a route-less host
address — return traffic sourced from the VIP has no on-link subnet
association and silently blackholes. `validateVRRPVirtualAddressSubnet`
(`compiler_validate_strict.go`) asserts each VIP is contained in the prefix
of at least one address configured on the SAME unit for the MATCHING family.
The owner / priority-255 case (VIP equals an interface address) passes for
free (an address is contained in its own subnet); a cross-family VIP (e.g. a
v4 literal authored under a v6-only address) has no matching-family subnet
and is rejected. The strict commit/commit-check path hard-rejects naming the
interface, unit, group, VIP and family; the tolerant load/peer-sync path
downgrades to a warning (`lenientVRRPVirtualAddress`) so an already-persisted
or peer-synced config an older binary accepted still boots (#1960 no-brick).
This is config-only commit-time validation — it never touches the VRRP
runtime/state machine. Same fail-closed-on-load doctrine as #2911.

**No-match default-policy is fail-closed (#3065):** the sibling of #3043
for the implicit fallback. When a flow matches NO zone-pair, global, or
default policy, the verdict is `SecurityConfig.DefaultPolicy`. Because the
`PolicyAction` zero value is `PolicyPermit`, an unset
`security policies default-policy` stanza historically compiled to
permit-all — fail-OPEN, the opposite of the Junos SRX
`default-security-policy` (deny-all). `CompileConfig` now initializes
`SecurityConfig.DefaultPolicy = PolicyDeny` (`compiler.go`), so an absent
stanza denies unmatched traffic. An operator opts back into the legacy
permit-all explicitly with `set security policies default-policy
permit-all`; `deny-all` and `reject-all` are the other accepted values
(`compilePolicies`, `compiler_security.go` — `reject-all` previously fell
through the switch and was silently ignored). The value is plumbed to the
userspace dataplane via the `ConfigSnapshot.DefaultPolicy` string
(`policyActionString` → Rust `parse_action` → `PolicyState.default_action`,
the no-match verdict). The `default-policy` leaf is a typed `ValueEnumOf`
in `schema_security.go`, so a bogus value fails `commit check`. See
`docs/config-schema.md` "#3065".
**Zone screen-profile reference is fail-closed (#3066):** a security zone's
`screen <name>` that references a screen-ids-option profile the config never
defines historically committed with a warning only, and at runtime the
userspace dataplane fails OPEN — `screen/mod.rs` returns `ScreenVerdict::Pass`
for a missing profile, silently skipping every screen check for that zone while
the operator believes screening is active. `validateScreenProfileReferencesStrict`
(`compiler_validate_strict.go`) hard-rejects an undefined screen-profile
reference at commit. Unlike the policy gates the dataplane is NOT independently
safe on the tolerant load/peer-sync path (the missing profile still fails
open), so that path only downgrades to a warning to preserve #1960 no-brick
boot — the strict commit gate, which keeps a bad reference from ever reaching
the dataplane, is the real fix.

**Reserved zone names are rejected at definition (#3055):** a `security zones
security-zone <name>` whose name is a reserved sentinel — `junos-global`, `any`,
or `junos-host` — historically compiled cleanly. `junos-global` is the
device-wide global-policy sentinel: the userspace dataplane
(`userspace-dp/src/policy.rs`) string-matches a from-zone/to-zone literally
equal to `junos-global` and reclassifies the policy as a global fallback
(`JUNOS_GLOBAL_ZONE_ID = u16::MAX`) evaluated for EVERY flow, so an
operator-defined zone of that name silently turns its zone-scoped policies into
device-wide permits across unrelated zone pairs — a security-boundary escape.
`any`/`junos-host` are reserved policy context tokens that must likewise never
be a real zone name. `validateReservedZoneNamesStrict`
(`compiler_validate_strict.go`) hard-rejects such a definition at commit. The
DEFINITION-reject set (`reservedZoneNames` = `{junos-global, any, junos-host}`)
is DELIBERATELY DISTINCT from the zone-REFERENCE exemption set
(`policyZoneSpecialTokens` = `{"", any, junos-host}`, unchanged from #2401): the
two gates are mutually reinforcing and must NOT be unified. `policyZoneSpecialTokens`
must keep OMITTING `junos-global` — a policy that *references* `from-zone
junos-global` / `to-zone junos-global` against no defined zone stays hard-rejected
(and warned) by the #2401 reference gate. Making it reference-exempt would let
the reference reach the dataplane, which (`policy.rs:1021`) then classifies it as
a device-wide global rule — re-opening the exact fail-open this gate closes.
Because the definition gate guarantees no zone named `junos-global` can exist, an
explicit `junos-global` reference is always the bug, never a legitimate
named-zone use. The tolerant load/peer-sync path downgrades the definition gate
to a warning (`lenientReservedZoneNames`) so an already-persisted or peer-synced
config an older binary accepted still boots — #1960 no-brick doctrine, same as
#3066/#2401.

**Wildcard from-zone/to-zone `any` is committed AND enforced (#3090):** an
ordinary zone-pair policy whose `from-zone` or `to-zone` is the literal Junos
wildcard `any` is a first-class enforced policy. The #2401 reference gate
exempts `any` (`policyZoneSpecialTokens`) so it is not mistaken for an
undefined-zone reference, and a `security zone` named `any` is still rejected by
`validateReservedZoneNamesStrict`. The userspace snapshot builder
(`pkg/dataplane/userspace/policies.go`) carries the literal `"any"` string
unchanged for an ordinary zone-pair policy (only `security policies global` maps
to the `junos-global` sentinel), and `PolicyState::from_snapshots`
(`userspace-dp/src/policy.rs`) routes a wildcard rule into one of three
dedicated index lists keyed for O(1) lookup:

- **from-any** — `from-zone any`, concrete `to-zone`: keyed by the concrete
  to-zone id; matches a flow into that to-zone regardless of ingress zone.
- **to-any** — concrete `from-zone`, `to-zone any`: keyed by the concrete
  from-zone id; matches a flow out of that from-zone regardless of egress zone.
- **both-any** — `from-zone any to-zone any`: matches every defined zone pair.

`evaluate_policy_result_with_icmp` consults these in Junos most-specific-first
precedence: exact `(from,to)` zone pair → single-wildcard tier (from-any /
to-any merged in config order) → both-any → `junos-global` → default policy.
There is **no N×N hot-path expansion** — the wildcard tiers are FxHashMap O(1)
probes (or a small Vec scan only when such rules exist), so a config with no
wildcard policy pays only two empty-slice probes per cold-path evaluation. A
`from-zone any to-zone junos-host` rule is also enforced on the host
(LocalDelivery) path (`evaluate_junos_host_policy`); `to-zone any` /
`from-zone any to-zone any` are intentionally NOT applied to host-bound traffic
so a broad rule cannot silently brick the management lifeline (mirroring the
existing no-global-on-host-path rule). Wildcard tiers live inside the
`from_id != 0 && to_id != 0` guard, so an unzoned flow still falls through to
the default action (#3110), exactly like a global policy. This lifts the #3018
interim commit reject (`validatePolicyWildcardZoneStrict` and its
`lenientPolicyWildcardZone` downgrade, both removed). The unrelated `any` tokens
elsewhere in a policy (`match source-address any` / `match application any`) are
unaffected.

**NAT rule-set `from`/`to` `interface`/`routing-instance` scope is fully
enforced (#3096, lifts the #3079/#3095 interim reject):** Junos NAT rule-sets
scope matched traffic with a `from`/`to` clause taking one of `zone | interface
| routing-instance`. xpf originally extracted only the `zone` children, so an
`interface`- or `routing-instance`-scoped rule-set committed cleanly but had its
scope SILENTLY DISCARDED and applied GLOBALLY (translated sessions leaked across
the routing boundary — a security/isolation failure); #3095 made that an interim
commit reject (`validateNATRuleSetScopeAST`). #3096 implements the full path:

- **Capture.** `parseNATMatchScopes` / `collectNATScopes` (`compiler_nat.go`,
  generalizing the old `parseZoneList`) read `zone`, `interface`, AND
  `routing-instance` from both AST shapes (inline + child-leaf, bracket lists
  collapsed). The from/to scope lists Cartesian-expand into one
  `NATRuleSet` / `StaticNATRuleSet` per (from-scope, to-scope) pair, mirroring
  the existing from-zone × to-zone expansion.
- **Typed model.** `NATRuleSet` gains `FromInterface`/`ToInterface`/
  `FromRoutingInstance`/`ToRoutingInstance`; `StaticNATRuleSet` gains
  `FromInterface`/`FromRoutingInstance` (static NAT has only a `from` clause).
  Exactly one of zone/interface/routing-instance is non-empty per side for a
  scoped rule-set; all-empty = match-any (global), the unchanged legacy case.
- **Snapshot + dataplane match.** The scope plumbs through the userspace
  snapshot (`from_interface`/`to_interface`/`from_routing_instance`/
  `to_routing_instance`, additive #1961 wire fields) and is enforced per-flow in
  the Rust match path: `SourceNatRule::matches` AND-s the scope against the
  flow's ingress (`from_*`) / egress (`to_*`) interface config-name and routing
  instance; DNAT (`nat/destination.rs`) and static NAT (`nat/static_nat.rs`)
  gate on the ingress identity (and, for static NAT's reverse SNAT direction,
  the egress identity — symmetric with the #2871 egress-zone gate). The Rust
  forwarding layer resolves each ifindex to its config name and VRF via
  `ifindex_to_config_name` / `ifindex_to_routing_instance`.

The `from`/`to` `zone` scope and the legitimate global (no-from/to) case are
unchanged. Cross-rule-set context-specificity ordering (Junos evaluates
interface- before zone- before routing-instance-scoped rule-sets) is NOT
implemented — xpf keeps first-match-in-list across the flat rule list, identical
to the pre-#3096 zone behavior. NPTv6 rule-sets under `security nat static`
ignore the `from` scope entirely (zone, interface, AND routing-instance) — a
pre-existing limitation of the stateless prefix-indexed NPTv6 translator, not a
regression introduced by lifting the reject. The `validateNATRuleSetScopeAST`
gate and its `lenientNATRuleSetScope` opt are removed; `interface`/
`routing-instance` are now declared under the NAT rule-set `from`/`to` in
`schema_security.go` for commit-time validation and CLI completion.

**Unsupported security-policy `match` leaves are rejected at commit (#3113,
interim):** Junos SRX security policies match traffic with a rich `match`
criteria set. Beyond the L3/L4 leaves xpf enforces, vSRX accepts unified-policy /
identity / L7 leaves like `dynamic-application`, `url-category`, and
`source-identity`. xpf's policy compiler (`compilePolicy`, `compiler_security.go`)
only switches on the supported subset — `source-address`, `destination-address`,
`source-address-excluded`, `destination-address-excluded`, and `application`; any
other `match` child fell out of the switch with NO error and was SILENTLY DROPPED
(the set-schema does not list the leaves and `schema_walk.go` returns nil for
unknown keywords by design). Dropping a match criterion WIDENS the policy: a rule
the operator wrote to match only one `dynamic-application` compiled as if that
constraint were absent — a broad L3/L4 permit/deny over every application,
permitting/denying traffic the operator never intended (a security fail-OPEN, not
a cosmetic gap). `validatePolicyMatchLeavesStrict`
(`compiler_policy_match.go`) hard-rejects a policy carrying an unsupported `match`
leaf at commit, naming the policy scope (zone-pair or global), the policy, and the
offending leaf, and directing the operator to remove it. It is an AST pre-walk in
`compileExpanded` (not a typed validator) because the unsupported leaf is exactly
what the compiler drops — by the time the typed `*Config` exists the leaf is gone
from `PolicyMatch` — and because `SchemaValidate` returns nil for unknown keywords
by design and cannot REJECT `match dynamic-application ...`. The allowlist is the
EXACT set `compilePolicy` enforces (`supportedPolicyMatchLeaves`); keep the two in
lockstep. Both zone-pair (`from-zone`/`to-zone`) and `global` policies are
covered. This is the INTERIM contract: full support for those match types (typed
fields + capability gate + Rust enforcement) is a substantial feature deferred to
a follow-up. The tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyMatchLeaves`) so an already-persisted or peer-synced config an
older binary silently accepted still boots — the leaf stays dropped (the
pre-existing behaviour), now flagged (#1960 no-brick doctrine, same as
#3018/#3055/#3060).

The #3113 gate originally inspected only the DIRECT children of `match`, which
left a multi-value-leaf ESCAPE (#3142, codex-review-067 finding 067-01). `match
application` is a `multi:true` leaf (`schema_security.go`), so the flat-set
absorber collapses every trailing non-sibling token onto the application leaf's
OWN node (`Keys[1:]` plus child sub-nodes — the #2419 collapse), not as a
sibling of `match`. So `set ... policy p match application any dynamic-application
junos:FTP` compiles to a single `application` leaf with tail tokens `[any
dynamic-application junos:FTP]`; the direct-child scan saw only the supported
`application` leaf and never the tail, so the unsupported `dynamic-application`
criterion escaped the gate and the policy silently armed as a broad application
match (`capabilities.go` short-circuits on the first `any`) — the same fail-open
#3113 closes, reached via the multi-value path. `validatePolicyMatchLeavesStrict`
now also scans the collapsed tail of a supported match leaf
(`firewallMatchValues`) and rejects any token in `unsupportedPolicyMatchLeaves`
(the KNOWN unsupported match dimensions: `dynamic-application`, `url-category`,
`source-identity`). A legitimate application VALUE is never one of those keywords,
so a real bracketed list like `match application [ junos-http junos-https ]` is
NOT over-rejected — only a known unsupported match-leaf keyword masquerading as
an application value is. Same strict-reject / lenient-warn split as #3113.

**Unsupported security-policy `then permit` children are rejected at commit
(#3114, interim):** Junos SRX `then permit` accepts action modifiers that turn a
bare permit into a permit-with-inspection or a permit-into-tunnel —
`application-services { utm-policy X; idp; }` (UTM/IDP/AppFW/SSL-proxy/SecIntel
attachment), `firewall-authentication`, `tunnel ipsec-vpn`, etc. xpf's policy
compiler (`compilePolicy`, `compiler_security.go`) handles the `then` arm by
switching only on the tokens it implements (`permit`, `deny`, `reject`, `log`,
`count`); the `permit` arm sets `pol.Action = PolicyPermit` and NEVER inspects the
permit node's children/tail, so any modifier under `then permit` fell out with NO
error and was SILENTLY DROPPED (the set-schema does not list them and
`schema_walk.go` returns nil for unknown keywords by design). Dropping a permit
service chain turns a permit-only-with-inspection rule into an UNCONDITIONAL
permit — an operator who writes `then permit application-services utm-policy
strict-web` believes traffic is inspected while xpf forwards it without the chain
(a security fail-OPEN). `validatePolicyThenPermitStrict` (`compiler_policy_then.go`)
hard-rejects a policy whose `then permit` carries an unsupported child at commit,
naming the policy scope (zone-pair or global), the policy, and the offending
modifier, and directing the operator to remove it. It is an AST pre-walk in
`compileExpanded` (not a typed validator) for the same reasons as #3113 — the
dropped modifier is gone from the typed `*Config`, and `SchemaValidate` cannot
REJECT an unknown keyword. The modifier appears either collapsed onto the permit
node's `Keys[1]` (flat set) or as a child node (hierarchical block); both shapes
are checked. The allowlist (`supportedPolicyThenPermitChildren`) is EMPTY today
because the compiler enforces no `then permit` child — keep it in lockstep with
`compilePolicy` so a future typed service chain is no longer rejected. Both
zone-pair and `global` policies are covered. This is the INTERIM contract: a typed
service-chain model + userspace capability gate + Rust enforcement is a deferred
follow-up. The tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyThenPermit`) so an already-persisted or peer-synced config an older
binary silently accepted still boots — the modifier stays dropped (the
pre-existing behaviour), now flagged (#1960 no-brick doctrine, same as #3113).

**Unsupported security-policy `then reject` children are rejected at commit
(#3115, interim — codex-review-066 finding 066-03):** the sibling of #3114 for the
`reject` arm. Junos SRX `then reject` accepts a custom reject-response `profile
<name>` and a per-packet-type reject (e.g. `tcp-reset`). `compilePolicy`'s `then`
switch `reject` arm sets `pol.Action = PolicyReject` and NEVER inspects
`t.Children`, so any modifier under `then reject` fell out with NO error and was
SILENTLY DROPPED (set-schema does not list reject children and `schema_walk.go`
returns nil for unknown keywords). Unlike #3114 this is not a fail-OPEN (reject
still rejects), but the configured custom reject response is inert — a wire-contract
/ operator-observability divergence the operator cannot detect at commit.
`validatePolicyThenRejectStrict` (`compiler_policy_then.go`) hard-rejects a policy
whose `then reject` carries an unsupported child at commit, naming the policy scope
(zone-pair or global), the policy, and the offending modifier; a bare `then reject`
(no child) still commits. It is an AST pre-walk in `compileExpanded` for the same
reasons as #3114, checks both AST shapes (`Keys[1]` flat-set / child node
hierarchical), and covers zone-pair and `global` policies. The allowlist
(`supportedPolicyThenRejectChildren`) is EMPTY today because the compiler enforces
no `then reject` child — keep it in lockstep with `compilePolicy` so a future
synthesized reject response / packet-type reset is no longer rejected. Reject-profile
support (a typed reject-response model + dataplane synthesis) is a deferred
follow-up. The tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyThenReject`) so an already-persisted or peer-synced config an older
binary silently accepted still boots — the modifier stays dropped (the pre-existing
behaviour), now flagged (#1960 no-brick doctrine, same as #3114).

**`then deny` log/count modifier wired; other collapsed deny modifiers
rejected (#3141 — codex-review-068 finding 068-01):** the deny sibling of
#3114/#3115, but NOT a pure reject. `then deny` legitimately combines with the
observability modifiers `log` (with `session-init`/`session-close`) and `count`,
which the standalone `then log`/`then count` arms already implement. A flat-set
`then deny log session-init` collapses the modifier onto the deny node
(`Keys=["deny","log","session-init"]`, no children) instead of nesting a sibling
`then log` node; `compilePolicy`'s `then` switch `deny` arm read only `t.Name()`
and silently dropped the collapsed tail, so deny-with-logging committed but
`pol.Log` was never set — the configured audit logging was inert (a deny-rule
observability / compliance failure, not a packet fail-OPEN). The fix WIRES the
collapsed `log`/`count` modifiers in `applyCollapsedDenyModifiers`
(`compiler_security.go`), so deny+log works in BOTH the flat-collapsed form and
the separate-node `then { deny; log session-init; }` form (the latter already
handled by the `log` arm); `pol.Log` flows into the policy snapshot
(`PolicyRuleSnapshot.LogSessionInit/Close`, #2508) independent of `Action`, so a
deny rule emits the configured session log. The safety net for any REMAINING
collapsed deny modifier the compiler cannot enforce is
`validatePolicyThenDenyStrict` (`compiler_policy_then.go`): it hard-rejects a
`then deny <unsupported>` modifier at commit, naming the policy scope (zone-pair
or global), the policy, and the offending modifier; a bare `then deny`,
`then deny log`, and `then deny count` still commit. AST pre-walk in
`compileExpanded`, both AST shapes, zone-pair and `global` coverage. On the
flat path the lexer flattens a modifier and its sub-tokens into one
`Keys` slice (`["deny","log","session-init","count"]`), so the gate inspects
EVERY collapsed token (`Keys[1:]`) against `recognizedCollapsedDenyToken` —
the exact `{log, session-init, session-close, count}` set
`applyCollapsedDenyModifiers` consumes — not just `Keys[1]`; checking only
the first token let a supported-leads / unsupported-trails sequence like
`then deny count evilmod` slip through silently. On the hierarchical path a
direct child of `deny` is a top-level modifier, checked against the
`supportedPolicyThenDenyChildren` allowlist (`log`/`count`); its sub-tokens
nest deeper. Keep `recognizedCollapsedDenyToken` /
`supportedPolicyThenDenyChildren` in lockstep with
`applyCollapsedDenyModifiers`. The tolerant load/peer-sync path downgrades
to a warning (`lenientPolicyThenDeny`) so an already-persisted or peer-synced
config an older binary silently accepted still boots (#1960 no-brick doctrine,
same as #3114/#3115).

**Security policies missing a required `match` criterion are rejected at commit
(#3044 — codex-review-061 finding 061-03):** Junos/vSRX requires every security
policy `match` clause to specify all three core dimensions — `source-address`,
`destination-address`, AND `application`; a policy missing any of them (or omitting
the `match` block entirely) cannot commit. xpf's policy compiler (`compilePolicy`,
`compiler_security.go`) instead treated the whole `match` block — and every leaf
within it — as OPTIONAL: each field is filled only when the leaf is present, and an
absent dimension simply left the corresponding slice empty. The userspace dataplane
then interprets an empty slice as match-ANY (`capabilities.go` returns a nil app-term
list for "no apps"; `userspace-dp/src/policy.rs` compiles an empty app list as
`match_any:true` and defaults `source/destination_*_match_any` to true when the
literal+book sets are empty). A partial policy is therefore SILENTLY broader than
typed: `match source-address corp; then permit` permits `corp -> any:any`, and a
match-less policy becomes a zone-pair-wide permit/deny. A single dropped line in an
automation template widens a narrow rule to all traffic — a fail-OPEN for a permit
policy, an over-broad block for a deny. `validatePolicyRequiredMatchStrict`
(`compiler_policy_missing_match.go`) hard-rejects a policy whose `match` omits a
required dimension at commit, naming the policy scope (zone-pair or global), the
policy, and EVERY missing dimension, and directing the operator to add it. A missing
dimension is treated DIFFERENTLY from an explicit wildcard: the operator must write
`any` (or `any-ipv4`/`any-ipv6`, an address-book name, a CIDR, a named
application/application-set) — exactly as Junos demands. `source-address-excluded` /
`destination-address-excluded` are MODIFIERS of the base address leaf, not
substitutes, so they do not by themselves satisfy the source/destination-address
requirement. It is an AST pre-walk in `compileExpanded` (not a typed validator) for
the same reasons as #3113 — a missing leaf leaves no trace in the typed `*Config`
(an empty slice is indistinguishable from an explicit-any that also resolves to
match-any), and `SchemaValidate` cannot REJECT an absence. The walk runs on the
group-expanded, inactive-pruned tree, so an apply-groups-inherited dimension counts
and an `inactive:` policy is ignored. Both zone-pair and `global` policies are
covered. The tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyMissingMatch`) so an already-persisted or peer-synced config an older
binary silently accepted still boots — the policy keeps its match-any-for-missing
compilation, now flagged (#1960 no-brick doctrine, same as #3113).

**Ambiguous secure-tunnel `bind-interface` aliases are rejected at commit
(#2933):** `security ipsec vpn <name> bind-interface` is a free-form 1-arg
string stored verbatim on the typed VPN (`compiler_ipsec.go`); the runtime
resolves it to a Linux xfrmi device name and a stable XFRM if_id via
`XFRMIfNameAndID` (`xfrmi.go`): `if_id = stIndex<<16 | (unit+1)`, unit
defaulting to 0. A bare `st0` is therefore the SAME device as `st0.0` (both
if_id 1). Two VPNs binding those two distinct strings committed cleanly but
collide at apply time — only one xfrm device can carry the if_id, so the #2929
pkg/routing guard refuses to create EITHER device and both tunnels go down with
a journal ERROR (before #2929 it silently leaked one VPN's SA onto the other's
tunnel). `validateSecureTunnelBindInterfaceAST` (`compiler_ipsec_bindiface.go`)
turns that apply-time both-down into a commit-check error: it derives the if_id
for every VPN's bind-interface and hard-rejects when two DISTINCT strings derive
the SAME non-zero if_id, naming each offending string, its VPN(s), and the
shared if_id. The gate is SURGICAL — it does NOT fire when the same string is
shared by several VPNs (one device, one if_id) nor when a bind-interface cannot
parse as `st<N>[.unit]` (if_id 0); an unambiguous map (st0.0 + st0.1, or st0 +
st1) commits cleanly. It is an AST pre-walk in `compileExpanded` so an
apply-groups-inherited bind-interface is covered and an `inactive:` VPN is
ignored. The tolerant load/peer-sync path downgrades to a warning
(`lenientSecureTunnelBindIface`) so an already-persisted or peer-synced config
an older binary accepted still boots (#1960 no-brick doctrine) — the #2929
routing guard stays the runtime backstop.

**Undefined policy community references are rejected at commit (#2881):** a
policy-statement term's `from community <name>` (rendered FRR `match community
<name>`) and `then community delete <name>` (the strip-by-list operation added
in #2848, rendered `set comm-list <name> delete`) both reference an FRR
`bgp community-list <name>` that `pkg/frr` emits ONLY from a defined
`policy-options community <name>`. With no validation a term naming an UNDEFINED
community committed cleanly, then a dangling `match community` / `set comm-list
... delete` line failed the WHOLE `frr-reload` of the managed section (a single
`vtysh -f` add-batch exits non-zero on any `CMD_WARNING_CONFIG_FAILED`), leaving
dynamic routing stale — a commit-accepted config the routing daemon cannot load.
`validatePolicyCommunityReferencesStrict` (`compiler_validate_strict.go`) runs
on the fully-compiled `*Config` (the community map is populated regardless of
authoring order) and hard-rejects an undefined `from community` / `then
community delete` reference at commit/commit-check, naming the policy, term, and
missing community. The tolerant load/peer-sync path downgrades to a warning
(`lenientPolicyCommunityRef`) so an already-persisted or peer-synced config an
older binary accepted still boots (#1960 no-brick doctrine). The gate is
SURGICAL — only NAME references are checked; `then community (set|add) <value>`
carries a community VALUE (e.g. `65000:100`), not a list reference, and a defined
community reference commits unchanged.

**Policy-referenced application protocols are validated against the dataplane
resolver (#3150 — codex-review-067 finding 067-06):** a user-defined
`set applications application <name> protocol <token>` that is REFERENCED by a
security policy or NAT rule's `match application` (or any application when
`services application-identification` is on) is hard-rejected at commit by
`validateApplicationSpecsStrict` (`compiler_validate_strict.go`) when the
protocol token is unresolvable. The bug: that gate resolved the token via the
LENIENT `validateProtocol`, which blanket-accepts ANY `junos-` prefix
(`strings.HasPrefix("junos-")`). So `protocol junos-foobar` committed cleanly,
but the dataplane resolves protocols only through `appid.ProtocolNumber`
(`pkg/appid`), which knows only the CONCRETE junos-* aliases (`junos-ping`,
`junos-tcp-any`, ...) — it rejects `junos-foobar`. The userspace policy
capability gate (`pkg/dataplane/userspace`) then disarms the snapshot
(`ForwardingSupported=false`): a commit-succeeds / apply-fails split. The fix
resolves the application's protocol through `filterProtocolResolvable` — the
same `appid.ProtocolNumber` mirror the firewall-filter `from protocol` gate
(#2175) already uses, pinned to the SSOT by the `pkg/appid` drift-guard test
`TestFilterProtocolResolvableMatchesProtocolNumber` — so a token the dataplane
cannot represent is rejected at commit. Real protocol names, numeric 0..255
values, and resolvable junos-* aliases still commit; only genuinely
unresolvable tokens reject. The lenient `validateProtocol` is unchanged and
still used by `ValidateConfig`'s warning surface (so an UNREFERENCED library
app with a bogus protocol stays a warning, not a commit error). The tolerant
load/peer-sync path downgrades the reject to a warning
(`lenientApplicationSpecs`) so an already-persisted or peer-synced config an
older binary accepted still boots (#1960 no-brick doctrine). Distinct from
#2124/#2142 (those fixed alias drift / malformed port-or-protocol specs); this
residual was specifically the strict app-spec path still using the blanket
`junos-` HasPrefix.

**Ports are valid only on a protocol the dataplane extracts ports for (#3373 —
audit finding):** the same `validateApplicationSpecsStrict` gate hard-rejects a
referenced (or app-id-enabled) `set applications application <name>` that sets
`source-port`/`destination-port` while its `protocol` is one this dataplane does
NOT extract L4 ports for. The authoritative port-bearing set is the dataplane's
own extraction predicate — `userspace-dp/src/ip_proto.rs` `has_l4_ports` ==
**TCP (6) / UDP (17)** ONLY, mirrored by `inspect.rs parse_flow_ports` (which
reads port bytes only for TCP/UDP) — NOT a name→number resolver. ICMP/ICMPv6,
GRE, OSPF, ESP, AH, VRRP, IGMP, PIM, IP-in-IP do not carry ports the dataplane
reads; **SCTP (132) is also excluded** — it has ports on the wire, but this
dataplane deliberately never extracts or rewrites them (CRC32c checksum, see the
`ip_proto.rs has_l4_ports` rationale), so an SCTP packet still presents
`dst_port`/`src_port` = 0 to the matcher. Before the gate `protocol icmp
destination-port 80` (or `protocol ospf destination-port 89`, `protocol esp
source-port 4500`, `protocol sctp destination-port 80`) committed: the port
passed `validatePortSpec` and the protocol passed `filterProtocolResolvable`,
but the runtime then compiled a port matcher indexed by the protocol number
(`userspace-dp/src/policy.rs` keys port terms on the packet's extracted
`src_port`/`dst_port`, which are 0 for any non-extracted protocol), so the term
became a NEVER-MATCH — fail-OPEN for a deny rule, fail-CLOSED for a permit rule.
Rejecting at commit is the fail-closed-correct outcome: the dataplane cannot
enforce the constraint, so refuse it rather than silently compile a never-match
term. The gate resolves the port-bearing subset inline via
`protocolIsPortBearing` (appid cannot be imported here — pkg/appid imports
pkg/config — so the subset is pinned to the `ip_proto.rs has_l4_ports` SSOT by
the drift-guard test `TestProtocolIsPortBearingMatchesDataplaneExtraction`). It
fires ONLY when a port is set AND the protocol is not in the extraction set, so
an icmp-type-constrained ICMP app with no port (junos-ping shape) and a bare
`protocol gre`/`protocol sctp` still commit. The tolerant load/peer-sync path
downgrades the reject to a warning (`lenientApplicationSpecs`) per the #1960
no-brick doctrine. Junos does not couple ports to non-port protocols, so this is
a vSRX-parity fix.

**Custom-application named ports resolve through the shared service catalog
(#3340):** a custom application's `source-port`/`destination-port` used to accept
only a hard-coded 15-name subset (`http https ssh telnet ftp ftp-data smtp dns
pop3 imap snmp ntp bgp ldap syslog`), so a valid Junos service name beyond it —
notably `domain`, the canonical alias of the already-accepted `dns` — was
rejected at commit even though the dataplane can represent the numeric port
exactly. `compileApplications` / `parseApplicationTerms` now run each port spec
through `resolveAppPort`, which resolves named ports against the **same
`junosServicePorts` catalog** (`filter_match_resolve.go`) the firewall-filter
path uses (`resolveFilterPortTokens`) — the single source of truth for Junos
service-name → port number. Resolution emits the NUMERIC form (`domain` → `53`,
`http-https` → `80-443`) so the dataplane only ever parses numerics: the Rust
`parse_port_spec` and its Go mirror `userspacePortSpecRepresentable` (the #2124
capability gate) recognize only the 15 literal names, so passing a broader name
through verbatim would commit yet be unrepresentable at apply (a commit/apply
split that disables forwarding). `resolveFilterPort` is NOT reused for this
because it splits on `-` before a whole-spec lookup, mangling hyphenated service
names (`ftp-data`, `tacacs-ds`, `kerberos-sec`); `resolveAppPort` does the
whole-spec catalog lookup first. The lookup is case-insensitive, so a mixed-case
service name resolves rather than passing through unresolved. An unresolvable
name (unknown service, out-of-range/malformed number, inverted/unresolved range)
is left verbatim so `validatePortSpec` hard-rejects it at the strict commit gate
and the tolerant load/peer-sync path downgrades it to a warning
(`lenientApplicationSpecs`, #1960 no-brick).

**Custom-application ICMP type/code constraints (#3348):** a user-defined
application whose `protocol` is the `junos-ping` / `junos-pingv6` alias now
carries the same echo-request type constraint the predefined `junos-ping`
object does (ICMP type 8 / ICMPv6 type 128, the #3020 parity). Before this fix
the alias lowered to bare ICMP with no type, so a custom `protocol junos-ping`
app projected a term the userspace matcher (and the `pkg/policymatch`
simulator) treated as match-ALL ICMP — silently widening any policy that
referenced it to every ICMP type (unreachable / redirect / timestamp / ...).
`aliasEchoICMPType` (`compiler_applications.go`) attaches the echo type on both
the top-level and inline-`term` paths, AFTER the child loop so an explicit
`icmp-type` leaf still wins; the all-ICMP aliases (`junos-icmp-all` /
`junos-icmp6-all`) stay unconstrained. The grammar now also exposes typed
`icmp-type` / `icmp-code` leaves (0..255, range-validated by the schema) on a
custom application and inline term, so an operator can author a constrained
echo / traceroute / ICMP-control app rather than only the all-ICMP widening.
`validateApplicationSpecsStrict` rejects an `icmp-type`/`icmp-code` on a
non-ICMP protocol (a never-match term, the same #3373 hazard as a port on a
non-port protocol) and an `icmp-code` without an `icmp-type` (an ambiguous
half-constraint); both downgrade to a warning on the tolerant load/peer-sync
path. `protocolIsICMPFamily` mirrors the ICMP arm of `filterProtocolResolvable`.
Two inline-`term` edge cases (the term is opaque to `SchemaValidate`): a term
listing BOTH a junos-ping alias AND an unconstrained ICMP alias dedups onto one
`icmp` term whose union is all-ICMP, so `unconstrainedICMP[proto]` suppresses the
echo narrowing (a widening INVERSION otherwise); and a malformed inline
`icmp-type`/`icmp-code` is recorded on `Application.UnknownICMP` (not silently
dropped, which would leave the term matching all ICMP) for the same strict-reject
/ lenient-warn gate.

**C struct alignment:** when mirroring C BPF structs in Go, match `sizeof`
exactly with trailing `Pad [N]byte` fields. cilium/ebpf serializes map
values in native endian, not big-endian, so use `binary.NativeEndian`
when packing IP addresses (already in network byte order on the wire).
