# #1694 — GetMapStats: stale map names + filter_rules ARRAY mis-count

Status: PLAN-READY — Codex round-2 PLAN-NEEDS-MINOR (stale runtime
wording in plan.md) addressed; AGY + Claude-SMR PLAN-READY (round 1).
Reframed acceptance from "maps start reporting at runtime" to "static
descriptor-table correctness" per Codex round-1 finding.

## Round-1 review outcome + revision

- **Codex (task-mpsi2hph-dukvbl): PLAN-NEEDS-MAJOR.** All three table
  defects confirmed real. Major finding: the *current* runtime loads
  the Rust userspace shim collection plus a fixed `userspaceShimShared
  MapSpecs()` set (loader_userspace_shim.go:275) — which contains
  `sessions`, `sessions_v6`, `dnat_table`, `dnat_table_v6`, and
  counter/infra maps but **NOT** `nat_pool_configs`, `screen_configs`,
  or `filter_rules`. `Manager.Load()` (the old full-eBPF-collection
  path) is retired (loader.go:99). So the name fixes do NOT make two
  maps "start reporting at runtime today" — those maps are absent from
  `m.maps` regardless of name. The defects are real *descriptor-table*
  bugs (latent: wrong output if/when those maps are ever surfaced),
  but the v1 acceptance story was false. Also: `struct filter_rule`
  (xpf_common.h:800) has no `valid` bit — validity is
  `filter_config.num_rules/rule_start`, not slot contents, so
  value-aware counting would be a *different* metric, not a cheap
  used-count. Refinement: prefer an unexported package-level slice the
  test reads but never mutates (or a helper returning the literal)
  over a mutable exported var. **VERIFIED independently** against
  loader_userspace_shim.go:275-300 and xpf_common.h:800-820.
- **AGY (adversarial-review-mpsi2q1l-6ucrhb): PLAN-READY.** Same
  source-grounded confirmation; additionally verified CLI
  (cli_show_system.go:64-66) and gRPC (server_show.go:1811-1813)
  already discard array `UsedCount` (print "-"/`continue`); only the
  REST JSON (system.go:230) exposes raw `UsedCount`, so the
  `filter_rules` fix only improves that one path. No consumer breaks.
- **Claude-SMR: PLAN-READY**, crediting Codex's runtime-loading point
  (I had missed it). Reframed below.

### Revisions applied for v2
1. Acceptance reframed: this fixes the **static descriptor table's
   correctness**, not observable runtime output (the three maps aren't
   loaded by the shim today). The test asserts the descriptor table's
   names + countability statically — no live `m.maps`.
2. Test seam: an **unexported** package-level slice
   `mapStatsReportDescriptors` of an unexported type, read by the test,
   never mutated, never exported. `GetMapStats` ranges over it.

## Issue framing

`GetMapStats` (now in `pkg/dataplane/maps_stats.go` after the #1686
byte-identical split, originally `maps.go:2074/2075/2078`, originally
introduced in `fc6ad37d1`) carries three pre-existing correctness
defects in its `reportMaps` table:

1. `{"nat_pool_config", false}` — the real BPF map name is
   `nat_pool_configs` (plural). Verified against the setter
   `maps_nat.go:148` (`m.maps["nat_pool_configs"]`) and the C
   definition `bpf/headers/xpf_maps.h:460` (`} nat_pool_configs`).
   The map dict `m.maps` is keyed by the literal collection map name
   (`loader_userspace_shim.go:128` — `m.maps[name] = umap`), so the
   stale singular key never matches and this entry **silently never
   reports**.
2. `{"screen_profiles", false}` — the real name is `screen_configs`.
   Verified against `maps_screen.go:17` (`m.maps["screen_configs"]`)
   and `bpf/headers/xpf_maps.h:413` (`} screen_configs`). Same
   silent-never-reports failure mode.
3. `{"filter_rules", true}` — `filter_rules` is
   `BPF_MAP_TYPE_ARRAY` (`bpf/headers/xpf_maps.h:800`, `max_entries =
   MAX_FILTER_RULES`). A BPF ARRAY is pre-allocated: every index key
   exists, so `bm.Iterate()` yields all `MaxEntries` elements, making
   `UsedCount == MaxEntries` unconditionally — a misleading utilization
   number. The CLI (`cli_show_system.go`) and gRPC buffers-detail
   (`server_show.go`) already print `-`/skip array `UsedCount`, and the
   Prometheus collector (`pkg/api/metrics.go`) does not call
   `GetMapStats` at all; the only path that surfaces the raw value is
   the REST `/system/buffers` JSON (`pkg/api/system.go`). So the
   user-visible impact is confined to that JSON field.

These are confirmed present verbatim on master and pre-date the #1686
split, so they were out of scope for that pure-code-motion PR.

## Fix

Edit the `reportMaps` table in `maps_stats.go` only:

```go
{"nat_pool_configs", false},   // was "nat_pool_config" (silent miss)
{"screen_configs", false},     // was "screen_profiles" (silent miss)
...
{"filter_rules", false},       // was true; ARRAY iteration == MaxEntries
```

- Names corrected to match the BPF header names so the two array
  descriptors resolve in `m.maps` *if those maps are present* — today
  the userspace shim does not load them, so the fix is a latent
  descriptor-table correction, not new runtime output. When present
  they would report Name/Type/MaxEntries/Key/ValueSize (UsedCount
  stays 0, correct for an ARRAY — same treatment already given to the
  other arrays in the table: `zone_configs`, `policy_rules`,
  `snat_rules`, `global_counters`, `policy_counters`).
- `filter_rules` flipped to `countable:false`, matching how every
  other `BPF_MAP_TYPE_ARRAY` in the table is already handled. The
  issue offers "drop from countable set OR implement value-aware
  counting"; value-aware counting of a pre-allocated rule array would
  require decoding `struct filter_rule` to detect "unused" slots — a
  scope/maintenance burden disproportionate to a stats accessor, and
  there is no in-band "valid" flag contract to key on. `false` is the
  honest, consistent choice: report the array's capacity, not a fake
  used-count.

No signature change. `GetMapStats() []MapStats` is preserved exactly;
only the static descriptor table values change.

## Hidden invariants preserved

- Public API: `GetMapStats() []MapStats` unchanged; `MapStats` struct
  unchanged. Consumers see the same shape: the `dataPlane` interfaces
  (`apply.go:413`, `dataplane.go:406`), the CLI `show system buffers`
  renderer (`cli_show_system.go`), the gRPC buffers-detail handler
  (`server_show.go`), the `pkg/fwdstatus` builder, and the REST
  `/system/buffers` JSON (`pkg/api/system.go`). The Prometheus
  collector (`pkg/api/metrics.go`) does NOT consume `GetMapStats`.
- Iteration safety: the only `countable:true` entries remaining are
  sparse maps (`sessions`, `sessions_v6`, `address_membership`,
  `applications`, `dnat_table`, `dnat_table_v6` — `BPF_MAP_TYPE_HASH`;
  `address_book_v4/v6` — `BPF_MAP_TYPE_LPM_TRIE`), where iteration
  counting yields only live entries. No behavioral change to those.
- Missing-map tolerance: `if !ok || bm == nil { continue }` already
  guards the lookup; correcting the names makes the two descriptors
  resolve *if those maps are loaded*. They are not loaded by the
  userspace shim today, so they stay skipped at runtime — the value of
  the fix is the corrected static table, ready for whenever those maps
  are surfaced. A genuinely-absent map is unchanged (still skipped).

## Risk assessment

- Behavioral regression: LOW. The name fixes only change output if the
  renamed maps are present (they are not today); the `filter_rules`
  flip changes its UsedCount from MaxEntries to 0 if that map is
  present. No consumer asserts on the old wrong values.
- Lifetime/borrow: N/A (Go, static table edit).
- Performance: NONE on the hot path. This is a 1/s-or-slower control
  accessor. Removing `filter_rules` iteration slightly *reduces* work.
- Architectural mismatch: NONE. Target is concrete and verified.

## Test plan

- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./pkg/dataplane/...`
  green.
- New unit test exercising the corrected **static descriptor table**
  (NOT runtime output — the three fixed maps are not loaded by the
  userspace shim today; the test validates the table, which is the
  thing the bug lives in):
  - Asserts the descriptor set contains `nat_pool_configs` and
    `screen_configs` and NOT the stale `nat_pool_config` /
    `screen_profiles`.
  - Asserts `filter_rules` is in the non-countable set.
  - Asserts the countability invariant by name: the only entries
    expected countable are the sparse HASH/LPM_TRIE maps.
  - Seam: extract the function-local literal to an **unexported**
    package-level slice `mapStatsReportDescriptors` of an unexported
    type `mapStatDescriptor{name string; countable bool}`. The test
    reads it; it is never mutated, never exported, no test-only hook.
    `GetMapStats` ranges over it. Minimal mechanical extraction; no
    live BPF collection required.
- Full `go test ./...` green except the known pre-existing
  pkg/daemon socket-path-overflow sandbox failures (prove identical on
  clean master).

## Out of scope

- Value-aware ("used slot") counting for any ARRAY map.
- Adding more maps to the report set.
- Any change to `show system buffers` rendering or the Prometheus
  collector.

## Open questions for hostile review

1. Is flipping `filter_rules` to `false` the right call vs.
   value-aware counting? Is there a `struct filter_rule` "valid" flag
   that would make a real used-count cheap and correct?
2. Are `nat_pool_configs` and `screen_configs` truly ARRAYs (so
   `countable:false` is right) — verify against the header, not the
   stale comment.
3. Does any consumer (`show system buffers`, Prometheus) depend on the
   stale names being absent, or on `filter_rules` reporting MaxEntries
   as UsedCount? (i.e., would "fixing" it break a dashboard contract?)
4. Is extracting `reportMaps` to a package-level var the minimal
   testable seam, or does it over-reach for a 3-value fix?
5. Are there OTHER stale names in the same table I haven't caught
   (audit every entry against `m.maps` population)?

## Self-audit: full table vs. C header types

Every `reportMaps` entry checked against `bpf/headers/xpf_maps.h`
(post-fix names):

| name | C type | countable | correct? |
|------|--------|-----------|----------|
| sessions | HASH | true | yes (sparse) |
| sessions_v6 | HASH | true | yes |
| zone_configs | ARRAY | false | yes |
| policy_rules | ARRAY | false | yes |
| address_book_v4 | LPM_TRIE | true | yes (trie holds only inserts) |
| address_book_v6 | LPM_TRIE | true | yes |
| address_membership | HASH | true | yes |
| applications | HASH | true | yes |
| snat_rules | ARRAY | false | yes |
| dnat_table | HASH | true | yes |
| dnat_table_v6 | HASH | true | yes |
| nat_pool_configs | ARRAY | false | yes (was wrong NAME only) |
| screen_configs | ARRAY | false | yes (was wrong NAME only) |
| global_counters | PERCPU_ARRAY | false | yes |
| policy_counters | PERCPU_ARRAY | false | yes |
| filter_rules | ARRAY | **false** (fixed) | yes (was wrongly true) |

Post-fix invariant: every `countable:true` entry is HASH or LPM_TRIE
(sparse, iteration-counting valid); every `countable:false` entry is
ARRAY/PERCPU_ARRAY (pre-allocated, count == MaxEntries is meaningless).
No other stale names; no other miscounts. All 16 names resolve against
`m.maps` population keys (`loader_userspace_shim.go:128`).
