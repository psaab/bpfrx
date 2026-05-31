# Config schema: the two-SSOT split (#1319)

xpf has **two** command-tree sources of truth. Knowing which one to edit
is the single most common mistake when adding CLI completion or config
validation.

## Operational tree → `pkg/cmdtree`

`run` / `show` / `clear` / `request` / `monitor` / `ping` / `traceroute`
and friends are defined in `pkg/cmdtree/tree.go` (`OperationalTree`).
Adding an operational command there propagates to all three frontends
(local CLI, remote CLI, gRPC) for tab completion and `?` help. Operational
leaves may be typed (`Node.ValueType` / `ValueDesc` / `ValueExamples` /
`Validator`).

## Config-mode grammar → `pkg/config` `setSchema`

The `set` / `delete` / `show` / `edit` configuration grammar is owned by
`config.setSchema` (a tree of `schemaNode` in `pkg/config/schema.go`), NOT by
cmdtree. `setSchema` drives **four** things off one tree:

1. **Structural completion** — what keywords are valid at each position.
2. **Flat-set token grouping** — how `set a b c d` packs into AST
   `Node.Keys` (`SetPath`, `ast_edit.go`). This is parser-critical: the
   replace-vs-container decision keys on `children == nil`.
3. **Value-slot `?` completion** — for a typed leaf, the placeholder
   (`<rate>`) + example values (`CompleteSetPathWithValues`,
   `schema_complete.go`).
4. **Commit-check validation** — the typed-leaf gate
   (`SchemaValidate` + the generic walker in `schema_walk.go`).

Because completion (3) and validation (4) read the SAME node, they cannot
drift — typing a leaf fixes both `set ... ?` help and `commit check`
rejection together.

The live config-mode completers — `pkg/cli` `completeConfigWithDesc` and
`pkg/grpcapi` `completeConfigPairs` — route `set` paths through
`config.CompleteSetPathWithValues` over `setSchema`. `cmdtree.ConfigTopLevel`
only supplies the config-mode TOP-LEVEL keywords (`set`/`delete`/`commit`/
`load`/...) plus the retained `set system dataplane` description overlay.

## How to add a config-mode typed leaf

Edit the leaf's `schemaNode` in `setSchema` (`pkg/config/schema.go`). Set:

```go
"transmit-rate": {
    args:          1,
    valueType:     ValueRate,                // placeholder + opt-in
    valueDesc:     "Bandwidth (e.g. 100k, 10m, 1g) ...",
    valueExamples: []string{"100k", "10m", "1g"},
    validator:     ValidateRate,             // commit-check
    children:      map[string]*schemaNode{   // modifiers ONLY if pre-existing
        "exact": {children: nil},
    },
},
```

Rules:

- **Fields only, do not add a `children` map just to type a leaf.** SetPath's
  grouping keys on `children == nil` (`ast_edit.go:196`); flipping a leaf to
  a container changes flat-set grouping for existing configs. The
  `TestSetPathGrouping_Golden` test in
  `pkg/config/schema_validate_test.go` guards this.
- **Only type a leaf the compiler actually consumes.** Typing a leaf the
  compiler ignores would make `commit check` reject config the compiler
  would have silently dropped — a behaviour change beyond completion/
  validation. (This is why scheduler `buffer-size temporal` was NOT carried
  over: the compiler never reads it.)
- **Validators live in `pkg/config/schema_validators.go`** and are stateless
  string-checkers reusing the compiler's parsers. Add a generic one
  (`ValidateInteger(min,max)`, `ValidateEnum([...])`) or a bespoke
  `ValidateX(raw string, cfg *Config) error`.
- The generic walker (`schema_walk.go`) needs **no** changes per leaf — it
  descends `setSchema` and validates any typed leaf it finds. Walker rows it
  handles: container/args/compoundKey/midKeyword/wildcard, the standard
  typed leaf (first token is the value, remaining tokens must be known
  modifier children), the `multi && children == nil` value-tail/range shape
  (`destination-port 20000 to 20003`, rejecting dangling/all-separator
  tails), and the cross-sibling modifier-only line (`transmit-rate exact`
  valid only when a sibling leaf supplies the rate).
- **Compiler-faithful rule (important).** The walker validates typed leaves
  exactly where the per-subsystem compiler reads them. For a named-instance
  container (e.g. `class-of-service schedulers <name> { ... }`) the compiler
  reads leaves from the instance node's CHILDREN; tokens packed into the
  instance node's own Keys beyond the name are NOT compiled, so the walker
  ignores them — it never validates, nor mis-attributes block children to,
  such packed tokens. This means malformed shorthand the compiler silently
  discards (e.g. `schedulers be transmit-rate asd` as a single node with no
  children) is intentionally NOT rejected: rejecting config the compiler
  ignores is a behaviour change beyond #1319's compiled-leaf-only scope. The
  real symptom-2 path — `set class-of-service schedulers be transmit-rate
  asd` — lands the leaf as a CHILD, where it IS compiled and IS rejected.
  This contract was converged across 7 hostile Codex review rounds; do not
  re-add packed-tail validation without re-checking compiler reachability.

## Rollout (#1319)

- **PR 1 (this work):** moved `ValueType` to `pkg/config`; added the typed
  fields to `schemaNode`; wired typed-value `?` completion into
  `CompleteSetPathWithValues`; replaced the schedulers-only hand-rolled
  walker + class-of-service early-return with the generic
  `config.SchemaValidate` walker; re-homed the schedulers typed leaves onto
  `setSchema`; retired the cmdtree config-mode overlay.
- **PR 2..N:** type one subsystem's leaves per PR (chassis cluster,
  interfaces address CIDR, firewall filter terms, system/services numeric
  knobs) with Junos-vSRX-correct ranges + a fixture proving the silent-
  coerce gap on master. No walker/infra changes after PR 1.
