# #1686 — Split `pkg/dataplane/maps.go` into domain accessor files

**Status:** DRAFT v1 — pending adversarial plan review

## 1. Issue framing

`pkg/dataplane/maps.go` is 2113 LOC of `*dataplane.Manager` methods that
read/write the `m.maps map[string]*ebpf.Map` table populated by the retained
Rust AF_XDP shim loader. The methods mix at least nine distinct domains
(policy/zone config, sessions, NAT, screen/IDS, firewall filters, counters,
flow config, HA/fabric, hitless-restart stale cleanup, map stats) behind one
flat file. The issue asks to split it into narrow domain accessor units so each
domain's map surface is cohesive and discoverable, NOT to keep piling methods
into one file. It is promoted from #1661 backlog item 1.

## 2. Honest scope/value framing

This is a **maintainability / discoverability** refactor, not a perf change.
There is **no hot-path component**: every method here is control-plane map
management invoked from the daemon, gRPC/REST API, CLI, conntrack GC, and
cluster sync — never per-packet (per-packet forwarding is entirely in
`userspace-dp`, the Rust helper; Go never touches `m.maps` per packet). The win
is: 2113 LOC → ~10 files of 100–400 LOC each, each named for its domain, so a
reader looking for "where do we write NAT pool entries" opens `maps_nat.go`
instead of grepping a 2113-line file. It also drops the file below the
REFACTOR-tier audit threshold.

**If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.** (Here there is no perf gain at all — the
justification is purely structural cohesion + audit-tier compliance. If the
split would *fragment* cohesive logic rather than separate independent domains,
PLAN-KILL is the correct outcome per the #1544 routing.go lesson.)

## 3. The central architectural decision (the part most likely to fail review)

The issue text suggests `pkg/dataplane/maps/{session,nat,...}.go` **sub-packages**.
That is **not viable as pure code-motion** and I am explicitly NOT proposing it:

- Every method is declared on `*dataplane.Manager`, whose `maps`, `mu`, and
  `userspaceCounterOffsets` fields are **unexported**. Go does not allow methods
  on a type to be declared outside the type's own package. Moving the bodies to
  `pkg/dataplane/maps/` would force either (a) exporting `Manager.Maps`/`Mu`/
  `UserspaceCounterOffsets` and rewriting every body to take them as params, or
  (b) breaking the public API from `m.SetSessionV4(k,v)` to
  `m.Maps().Session().SetV4(k,v)` across **8 external packages** (grpcapi, api,
  cli, conntrack, cluster, daemon, fwdstatus, flowexport — verified by grep).
- Both are large-blast-radius API breaks that introduce behavioral risk for zero
  functional benefit. That is the wrong trade for a structural refactor.

**Proposed layout: same-package, domain-suffixed files** — the *exact* pattern
the maintainers already merged for this same `Manager` type when `compiler.go`
(3509 LOC) was split into `compiler_nat.go` / `compiler_filter.go` /
`compiler_iface.go` in **PR #1092 (#1044a)**. `dataplane.Manager` methods cannot
live in a subdir; the in-package domain-suffix split is the established,
already-blessed precedent for this type. The `feedback_refactor_module_dir_layout`
note warns against name-mangled flat siblings *for movable modules* — but a set
of methods on an unexported-field type is not a movable module, and the cited
counter-example there (`cli_show.go`/`cli_config.go`) was a case where a real
sub-package WAS possible. Here it is not, and #1092 is the governing precedent.

This makes the change **pure code motion**: cut method bodies verbatim, paste
into the new file, no signature/behavior change. No architectural premise to
fail at runtime.

## 4. Concrete design — file split

All files stay in `package dataplane`. `maps.go` is retained as a thin file
holding only the cross-domain key-encoding helpers shared with `compiler*.go`
(`htons`, `ipToUint32BE`, `ipTo16Bytes` — verified used by `compiler_nat.go`,
`compiler_filter.go`, `compiler.go`; they must NOT move into a domain file).
Proposed target files and their member functions (every function accounted for):

| New file | Functions moved (verbatim) | ~LOC |
|----------|---------------------------|------|
| `maps_policy.go` | SetZoneConfig, SetZonePairPolicy, SetPolicyRule, SetAddressBookEntry, SetAddressMembership, ClearAddressBookV4/V6, ClearAddressMembership, SetApplication, SetAppRange, ClearAppRanges, ClearZonePairPolicies, ClearApplications, SetDefaultPolicy, UpdatePolicyScheduleState | ~300 |
| `maps_session.go` | IterateSessions, IterateSessionsV6, IterateSessionsFrom, IterateSessionsV6From, BatchIterateSessions(+V6), BatchDeleteSessions(+V6), DeleteSession(+V6), SetSessionV4/V6, GetSessionV4/V6, SessionCount, ClearAllSessions, SeedSessionIDCounter | ~430 |
| `maps_nat.go` | SetDNATEntry(+V6), DeleteDNATEntry(+V6), ClearDNATStatic(+V6), SetSNATRule(+V6), ClearSNATRules(+V6), SetNATPoolConfig, SetNATPoolIPV4/V6, ClearNATPoolConfigs, ClearNATPoolIPs, SetSNATEgressIP, ClearSNATEgressIPs, SetStaticNATEntryV4/V6, ClearStaticNATEntries, SetNAT64Config, SetNAT64Count, ClearNAT64Configs, SetNPTv6Rule, ReadNATRuleCounter, ClearNATRuleCounters, ReadNATPortCounter, SeedNATPortCounters | ~470 |
| `maps_screen.go` | SetScreenConfig, ClearScreenConfigs, UpdateSessionCountSrc/Dst, ClearSessionCounts, SetMirrorConfig, ClearMirrorConfigs, ReadFloodCounters | ~150 |
| `maps_filter.go` | SetIfaceFilter, ClearIfaceFilterMap, SetFilterConfig, ReadFilterConfig, SetFilterRule, SetPolicerConfig, ClearPolicerConfigs, ClearFilterConfigs, ReadFilterCounters | ~120 |
| `maps_counters.go` | ReadGlobalCounter, IncrementGlobalCounter, ReadInterfaceCounters, ReadZoneCounters, ReadPolicyCounters, ClearGlobalCounters, ClearInterfaceCounters, ClearZoneCounters, ClearPolicyCounters, ClearFilterCounters, ClearAllCounters | ~250 |
| `maps_flow.go` | FlowConfigValue type, Lo0FilterNone const, SetFlowTimeout, SetFlowConfig | ~50 |
| `maps_fabric.go` | UpdateFabricFwd, UpdateFabricFwd1, UpdateRGActive, UpdateHAWatchdog, StartFIBSync, NotifyLinkCycle, SyncFabricState, BumpFIBGeneration | ~70 |
| `maps_stale.go` | DeleteStaleIfaceZone, DeleteStaleVlanIface, DeleteStaleZonePairPolicies, DeleteStaleApplications, DeleteStaleSNATRules(+V6), DeleteStaleDNATStatic(+V6), DeleteStaleStaticNAT, DeleteStaleNPTv6, DeleteStaleNAT64, ZeroStaleScreenConfigs, ZeroStaleNATPoolConfigs, DeleteStaleIfaceFilter, ZeroStaleFilterConfigs | ~390 |
| `maps_stats.go` | MapStats type, GetMapStats | ~110 |
| `maps.go` (retained) | htons, ipToUint32BE, ipTo16Bytes (shared key helpers), package import block | ~80 |

No method signatures change. No method bodies change beyond moving. Imports are
re-derived per file (`go build` / `goimports` will validate).

## 5. Public API preservation

Zero external API change. Every method remains `func (m *Manager) X(...)` in
`package dataplane`. The 8 external caller packages compile unchanged. This is
the load-bearing claim of the whole plan and the reviewers' primary verification
target: `git diff` must show pure move (deletions in maps.go == insertions in new
files, modulo per-file import headers).

## 6. Hidden invariants the change must preserve

- **Side-effect ordering within each method** — bodies move verbatim; ordering is
  trivially preserved (no reordering of statements).
- **Shared helper visibility** — `htons`/`ipToUint32BE`/`ipTo16Bytes` stay in the
  package and remain reachable from `compiler*.go`; they must not be duplicated.
- **`m.mu` lock discipline** — only `ReadGlobalCounter`/`IncrementGlobalCounter`
  take `m.mu` (counters domain); the lock lives on `Manager` and is reachable
  from any file in the package, so moving these two to `maps_counters.go` is safe.
- **`m.userspaceCounterOffsets` lazy init** — stays guarded under `m.mu` in
  `maps_counters.go`; field is unexported but same-package.
- **`m.LastCompileResult()` call** in `UpdatePolicyScheduleState` — that method is
  defined elsewhere in the package; reachable from `maps_policy.go`.
- **No new allocation / no behavior change** — pure motion.

## 7. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | **LOW** | Pure verbatim code motion; no statement reordering; same package so all symbols resolve identically. |
| Lifetime / borrow (N/A Go) | **LOW** | Go; no borrow checker. No closures captured across move boundaries. |
| Performance regression | **NONE** | Control-plane only; not per-packet. Compiler inlines identically within one package. |
| Architectural mismatch (#1544/#946-P2 dead-end) | **LOW–MED** | The risk is "fragmenting cohesive logic." Mitigation: domains are genuinely independent map families (session table vs NAT pools vs filter configs share *nothing* but `m.maps` lookups). The only cross-domain coupling is `ClearAllSessions`→NAT (dnat reverse cleanup) and `ClearNAT64Configs`→`SetNAT64Count`, both intra-NAT or session-internal; no proposed split cuts a tightly-coupled call chain. Reviewers should challenge this. |

## 8. Test plan

- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go build ./...` clean.
- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — all packages pass
  (dataplane test suite is the primary gate; it exercises these accessors).
- `go vet ./pkg/dataplane/...`.
- `git diff --stat` confirms move-only (net LOC ~flat, no logic delta).
- `make audit-check` on the rebased branch; regenerate
  `docs/refactoring-audit-current.txt` so maps.go drops off the REFACTOR tier and
  audit-check stays green on master post-merge.
- **Light no-regression smoke** on `loss:xpf-userspace-fw0/fw1` (control-plane
  change, not hot path): deploy + one v4 and one v6 iperf3 push+reverse +
  `show security flow session` and `show security nat ...` render correctly
  (verifies session/NAT/counter accessors still wire end-to-end). Full per-class
  CoS matrix is not required because no classifier/shaper/TX code is touched —
  justify in PR if reviewers disagree.

## 9. Out of scope

- Any sub-package extraction / API redesign (`m.Maps().Session()...`) — rejected
  in §3 as a non-motion API break.
- Renaming any method or changing any signature.
- Touching `compiler*.go`, `loader*.go`, or the shared key helpers' logic.
- `session_store.go` (already a separate cohesive file; not in scope).

## 10. Open questions for adversarial review (each may justify PLAN-KILL)

1. **Is the same-package domain-suffix layout the right call**, or does the
   `feedback_refactor_module_dir_layout` rule *require* a real sub-package here
   even at the cost of an 8-package API break? Is #1092 (`compiler_*.go`) a
   binding precedent or an anti-pattern that should not be repeated?
2. **Do any of the proposed domain boundaries cut a cohesive unit?** Specifically:
   `ClearAllSessions` (session file) deletes reverse DNAT entries — does that make
   it belong in NAT, or is session-ownership correct? `ReadFilterCounters` —
   counters file or filter file? `ReadFloodCounters` — screen or counters?
   `ReadNATRuleCounter`/`ReadNATPortCounter` — NAT or counters? Mis-bucketing is
   the real defect risk; challenge every ambiguous assignment.
3. **Is this churn worth it at all** given zero perf benefit? Is dropping below
   the audit tier a real maintainability win or audit-gaming? (PLAN-KILL is valid
   if the answer is "cosmetic.")
4. **Are the shared helpers** (`htons` et al.) correctly identified as
   must-stay-in-package, and is leaving them in a residual `maps.go` cleaner than a
   dedicated `mapkey_helpers.go`?
5. **Does any external caller** rely on these methods being *defined in maps.go*
   specifically (build tags, `//go:linkname`, codegen)? (I believe no — confirm.)
6. **Stale-cleanup file**: `maps_stale.go` aggregates DeleteStale*/ZeroStale* across
   *all* domains. Is a single hitless-restart file cohesive (one responsibility:
   "reconcile/GC entries not in the written-set"), or should each DeleteStale live
   beside its domain's setters? Argue both ways.
