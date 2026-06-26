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

**Wildcard from-zone/to-zone `any` is rejected at commit (#3018, interim):** an
ordinary zone-pair policy whose `from-zone` or `to-zone` is the literal Junos
wildcard `any` historically committed cleanly — the #2401 reference gate exempts
`any` (`policyZoneSpecialTokens`) and the old comment claimed the dataplane
"treats it as match-any". It does NOT: the userspace snapshot builder
(`pkg/dataplane/userspace/policies.go`) carries the literal `"any"` string
unchanged for an ordinary zone-pair policy (only `security policies global` maps
to the `junos-global` sentinel), and `PolicyState::from_snapshots`
(`userspace-dp/src/policy.rs`) only indexes a non-global rule when BOTH zones
resolve via `zone_name_to_id.get()`. `any` is never inserted into that map, so a
`from-zone any` / `to-zone any` rule is KEPT but never indexed and never
evaluated: `from-zone any to-zone trust ... then deny` commits and looks
legitimate yet never blocks traffic (silent fail-OPEN under a permit default);
`from-zone trust to-zone any then permit` cannot permit under a deny default.
`validatePolicyWildcardZoneStrict` (`compiler_validate_strict.go`) hard-rejects
such a policy at commit, naming the policy and which side is `any`. This is the
INTERIM contract: full wildcard-zone runtime indexing (separate ordered index
lists for exact / from-any / to-any / both-any, evaluated in Junos precedence
before global/default; no N×N hot-path expansion) is a substantial dataplane
change deferred to a follow-up. The gate does NOT touch `security policies
global` (enforced via the `junos-global` sentinel) nor the unrelated `any`
tokens elsewhere in a policy (`match source-address any` / `match application
any`) — only the from-zone/to-zone slot. The tolerant load/peer-sync path
downgrades to a warning (`lenientPolicyWildcardZone`) so an already-persisted or
peer-synced config carrying a from-zone/to-zone `any` still boots — the rule was
already inert, so a leniently-loaded config behaves exactly as before, just
flagged (#1960 no-brick doctrine, same as #3066/#3055/#2401).

**NAT rule-set `from`/`to` `interface`/`routing-instance` scope is rejected at
commit (#3079, interim):** Junos NAT rule-sets scope matched traffic with a
`from`/`to` clause taking one of `zone | interface | routing-instance`. xpf's
compiler only ever extracted the `zone` children (`parseZoneList`,
`compiler_nat.go`), so an `interface`- or `routing-instance`-scoped rule-set
COMMITTED cleanly but had its scope SILENTLY DISCARDED: every caller
(`compileNATSource` / `compileNATDestination` / `compileNATStatic`) falls back to
the match-any wildcard `[]string{""}` when the returned zone list is empty, so the
rule-set applied GLOBALLY — translated sessions leaked across the routing boundary
the operator drew (a security/isolation failure, not a cosmetic gap).
`validateNATRuleSetScopeAST` (`compiler_nat_scope.go`) hard-rejects such a
rule-set at commit, naming the NAT kind, rule-set, direction, the unsupported
keyword, and its value. It is an AST pre-walk in `compileExpanded` (not a typed
validator) because the scope keyword is exactly what the compiler drops — by the
time the typed `*Config` exists the information is gone — and because
`SchemaValidate` returns nil for unknown keywords by design and cannot REJECT
`from interface ...`. This is the INTERIM contract: full interface-/
routing-instance-scoped NAT matching (preserve the scope on the typed
`NATRuleSet`, enforce it per-flow) is a substantial dataplane change deferred to a
follow-up. The gate touches ONLY the NAT rule-set from/to scope — not the
supported `from`/`to` `zone` scope, the legitimate global (no-from/to) case, nor
the unrelated `interface`/`routing-instance` keywords elsewhere (real interface
config, VRF definitions). The tolerant load/peer-sync path downgrades to a warning
(`lenientNATRuleSetScope`) so an already-persisted or peer-synced config an older
binary silently accepted still boots — it stays applied globally (the pre-existing
behaviour), now flagged (#1960 no-brick doctrine, same as #3018/#3055/#3060).

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
#3079/#3055/#3060).

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

**C struct alignment:** when mirroring C BPF structs in Go, match `sizeof`
exactly with trailing `Pad [N]byte` fields. cilium/ebpf serializes map
values in native endian, not big-endian, so use `binary.NativeEndian`
when packing IP addresses (already in network byte order on the wire).
