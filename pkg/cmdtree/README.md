# pkg/cmdtree

Single source of truth for the **operational** CLI command tree (`run` /
`show` / `clear` / `request` / `monitor` / `ping` / ...). Used by the local
CLI, the remote CLI, and the gRPC tab-completion RPC. Adding an operational
command here automatically propagates to all three frontends.

> [!IMPORTANT]
> **Two-SSOT split (#1319).** cmdtree is the SSOT for the OPERATIONAL tree
> only. The **config-mode `set`/`delete`/`show`/`edit` grammar** — its
> structural completion, flat-set token grouping, value-slot `?`
> completion, AND the commit-check typed-leaf validation — is owned by
> `config.setSchema` in `pkg/config/ast.go`, not by cmdtree. The live
> config-mode completers (`pkg/cli` `completeConfigWithDesc`, `pkg/grpcapi`
> `completeConfigPairs`) route `set` paths through
> `config.CompleteSetPathWithValues` over `setSchema` and never consult a
> cmdtree config-grammar tree. `ConfigTopLevel` here only carries the
> top-level keyword set (`set`/`delete`/`commit`/`load`/...) plus the
> retained `set system dataplane` description overlay. See
> `docs/config-schema.md` and `pkg/config/README.md`.

## Entry points

- `Node` — `tree.go`. Tree node: description, static children,
  `DynamicFn`/`ContextDynamicFn` for config-aware completions. Optional
  typed-leaf fields (`ValueType`, `ValueDesc`, `ValueExamples`,
  `Validator`) describe the value a leaf accepts — see "Typed leaves"
  below.
- `Candidate` — `tree.go`. `(name, desc)` pair surfaced during tab
  completion.
- `OperationalTree` — `tree.go`. Canonical root for `show`, `clear`,
  `request`, `monitor`, `ping`, `traceroute`, etc.
- `ConfigTopLevel` — root for the config-mode TOP-LEVEL keywords
  (`set`/`delete`/`show`/`edit`/`commit`/`load`/...). The config-grammar
  BELOW `set` lives in `config.setSchema`, not here (see the two-SSOT note
  above). The only sub-`set` content retained in cmdtree is the
  `set system dataplane` description overlay (#785/#801 knob help).
- `KeysFromTree(tree)` — `tree.go`. Used by `pkg/cli` and `pkg/grpcapi`
  for Junos-style prefix matching.
- `WriteHelp`, `LookupDesc`, `PrintTreeHelp`, `CompleteFromTree`,
  `CompleteFromTreeWithDesc` — the helper API the three frontends consume
  for the OPERATIONAL tree (and operational typed leaves).

## Typed leaves

A `Node` with `ValueType != ValueAny` is a typed leaf: it expects exactly
one value of the declared kind at the next slot, and `?` completion
surfaces `ValueDesc` + `ValueExamples` + the placeholder
(`ValueType.Placeholder()`).

`ValueType` is defined in `pkg/config` (`config.ValueType`) and re-exported
here via aliases so cmdtree's operational leaves can carry it without a
`config → cmdtree → config` import cycle. The typed-leaf fields on `Node`
serve OPERATIONAL-tree leaves and the retained `set system dataplane`
overlay.

**Config-mode typed leaves do NOT live here.** The `class-of-service
schedulers` typed leaves (`transmit-rate`/`priority`/`buffer-size`) and the
commit-check gate moved onto `config.setSchema` + `config.SchemaValidate`
in #1319 PR 1, so the completion path and the validation path read one
tree and cannot drift. To add a config-mode typed leaf, edit `setSchema`
(see `docs/config-schema.md`), not cmdtree.

## Callers

`pkg/cli`, `pkg/grpcapi`, `cmd/cli`.

## Dependencies

`pkg/config` only.

## Gotchas

- `DynamicFn` and `ContextDynamicFn` run inside the interactive readline
  loop — they must not block on I/O, locks held by long operations, or
  network calls. Snapshot the candidate config once; iterate.
- `ContextDynamicFn` receives the words consumed so far, so completions
  can depend on earlier args (e.g. zone-pair → policy-name suggestions).
- The `tree.go` file is large by design (it's grammar). Don't refactor it
  into many small files just to reduce LOC — the single-file form is what
  makes it greppable for "where is this command defined?".
