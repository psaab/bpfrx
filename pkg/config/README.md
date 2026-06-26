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

**C struct alignment:** when mirroring C BPF structs in Go, match `sizeof`
exactly with trailing `Pad [N]byte` fields. cilium/ebpf serializes map
values in native endian, not big-endian, so use `binary.NativeEndian`
when packing IP addresses (already in network byte order on the wire).
