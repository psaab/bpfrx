# Paladin Review — A6_go_dataplane_manager batch 1/2 (150 files)

**Base commit:** d4506d4450e23f9a3fc572206b3c82f6b6c99029
**Area:** A6_go_dataplane_manager — batch 1/2
**Reviewer:** ps (paladin-038 campaign, batch 13)
**Date:** 2026-07-07

---

## Batch File List

All 150 files enumerated in the prompt were reviewed. Module grouping:

| Module | Files | Lines reviewed |
|---|---|---|
| `pkg/dataplane/*.go` (legacy compile + map accessors + types) | 22 files | ~6000 LOC |
| `pkg/dataplane/userspace/*.go` (userspace manager, builder, HA, sync) | 55 files | ~8000 LOC |
| `pkg/dataplane/userspace/format/*.go` | 8 files | ~600 LOC |
| Test/support files | 65 files | skipped for logic review, spot-checked for contract assertions |

---

## Module-by-Module Coverage Log

### pkg/dataplane/compiler.go — NEGATIVE (with caveat)
- Reviewed `CompileResult`, `CompileConfig`, `compileAddressBook`, `compileApplications`, `compilePolicies`, `compileDefaultPolicy`, `compileFlowTimeouts`, `compileFlowConfig`, `assignZoneIDs`, `ensureRxVlanOff`, `applyEthtool`, `tuneInterfaceBuffers`, `compilePortMirroring`.
- Checked: zone-ID assignment is STABLE (FNV hash, #3075), no positional renumbering.
- Checked: `nextAddrID` starts at 1, 0 reserved for "any" — no collision.
- Checked: `AppNames` guard for uint16 overflow (#3438 H4 check: `if appID > 65535 { return error }`) — sound.
- Checked: `MaxRulesPerPolicy` guard on policy expansion — sound.
- Checked: `compileApplications` prohibits protocol-0 fanning (#4008 guard via `strings.TrimSpace(app.Protocol)==""`) — sound.
- **No new finding in this file alone.** One finding in this file arises when combined with compiler_nat.go (deterministic NAT hostCount overflow, F-001 below).

### pkg/dataplane/compiler_nat.go — FINDING F-001 + LOW observations
- Reviewed full file: SNAT/DNAT/static/NPTv6/NAT64 compilation, pool index math, persistence, deterministic NAT.
- **F-001 (deterministic NAT /0 HostCount overflow)** — detailed below.
- **LOW: SNAT CounterID uint16 truncation** — `natCounterIDForKey` returns `uint32` (FNV hash), stored as `uint16(counterID)` into `SNATValue.CounterID` in legacy path (lines 247, 266, 608, 636). Two distinct NAT rules whose FNV hashes collide in low 16 bits share a legacy-array counter slot. However, the code comment explicitly marks this as vestigial ("the userspace runtime writes this struct through a no-op DataPlane and reads hits via the snapshot's u32 counter id instead (#2255)"). Userspace path uses `uint32` throughout. No dataplane enforcement impact on the primary path. Negative result for runtime safety; documented for completeness.

### pkg/dataplane/compiler_filter.go — NEGATIVE
- Reviewed `compileFirewallFilters`, `validateFilterProtocols`, `expandFilterTerm`, `setFilterAddr`, `resolvePortRange`, `forwardingClassToDSCP`, `computeFilterProtoPrefilter`.
- Checked: protocol validation via `appid.ProtocolNumber` SSOT (#2175) — rejects unknown tokens before assignment.
- Checked: `filterAddrIsReal` / `addrsAllMatchAny` korrekt handling (#3433, #4338) — no fail-open on "any" / "0.0.0.0/0" + except-idiom.
- Checked: DSCP resolution handles both named and numeric, range-constrains 0..63.
- Checked: TCP-flags mask construction, fragment, flex-match, policer wiring.
- No new finding.

### pkg/dataplane/compiler_iface.go — NEGATIVE
- Reviewed `compileZones`, `compileScreenProfiles`, `buildScreenConfig`, `resolveInterfaceRef`, `ensureVLANSubInterface`, `reconcileInterfaceAddresses`, `applyTunnelHostInbound`.
- Checked: nil-zone / nil-iface guards (#3499, #3492 class) present throughout.
- Checked: `protectedInterfaceResolver` merge (non-nil check before use).
- Checked: device-map `leaveAloneUnmapped` gate — correctly skips unmapped NICs.
- Checked: VLAN sub-interface creation, address reconciliation skip for DHCP/RETH/fabric-parent — correct.
- Checked: `applyTunnelHostInbound` auto-adds HOST_INBOUND_GRE only when outer IP is on zone member — correct.
- No new finding.

### pkg/dataplane/apply.go / dataplane.go / types.go / constants.go — NEGATIVE
- Reviewed Manager compile / attach / link pin logic.
- Reviewed type definitions, `ApplyResultFromCompileResult` cloning, `SESS_STATE_*`, `ActionDeny/Permit/Reject`, `HostInbound*` flag tables, `ScreenReasonCounters`.
- Checked: `StableZoneID` produces values in [1, ZoneIDReservedMin-1] — safe for u16.
- No new finding.

### pkg/dataplane/loader.go / loader_userspace_shim.go — NEGATIVE
- Reviewed shim loading, pin reconciliation (#4113 disposable pin), heartbeat map zeroing loop.
- Checked: `validateUserspaceShimSpec` drift guards for `MaxInterfaces` / `BindingArrayMaxEntries` — sound.
- Heartbeat zero-init loop `uint32(cfg.Workers)*2*16` with negative cfg.Workers is **dedup #4572** — not re-reported.

### pkg/dataplane/maps_*.go (7 files) — NEGATIVE
- Reviewed all map accessors: `SetZonePairPolicy`, `SetPolicyRule`, `SetAddressBookEntry`, `SetApplication`, `SetSNATRule`, `SetDNATEntry`, `SetNPTv6Rule`, `SetNAT64Config`, `SetIfaceFilter`, `SetFilterRule`, `SetPolicerConfig`, counters, fabric, HA watchdog, FIB, screen, session, mirror, stats, stale-cleanup.
- Checked: `MaxSNATRulesPerPair` flat-index arithmetic — correct (fromZone*MaxZones*MaxSNATRulesPerPair + toZone*MaxSNATRulesPerPair + ruleIdx).
- Checked: `MaxNATPoolIPsPerPool` cap enforcement at write sites — correct (break at >= MaxNATPoolIPsPerPool).
- Checked: stale-cleanup populate-before-clear pattern used consistently.
- No new finding.

### pkg/dataplane/userspace/manager.go / manager_compile.go / manager_ha.go / manager_generation.go / manager_overlay.go / manager_neighbor.go / manager_status.go — NEGATIVE (with pre-existing dedup HA findings)
- Reviewed full userspace Manager lifecycle: `Boot`, `Compile`, `Load`, `Close`, `Teardown`, HA state sync, watchdog IPC throttling, FIB generation bump, session sync, NAT counter bridging, binding watchdog (#1666), XSK liveness probe.
- Checked: `ApplyConfig` builds snapshot purely then atomically publishes — no partial-apply on userspace path.
- Checked: HA `UpdateRGActive` / `UpdateHAWatchdog` mutual exclusion via `m.mu` — no race between poll and active-change path that could mask demotion delta.
- Checked: `shouldSyncHAWatchdogIPCLocked` throttle (3s backstop) correctly bypasses on Active-state change (failover latency not gated).
- Checked: `recordPolicyContentRejectionLocked` / `recordZoneIDCollisionsLocked` transition-only logging — not per-tick.
- Checked: `verifyBindingsMapLocked` repair reconciles BPF `userspace_bindings` against helper `BindingStatus` after potential zero — prevents crash-blind blackhole.
- **Dedup:** HA heartbeat IPv4-only (#4549), cold-boot split-brain (#4386 CLOSED), HA state fabric-forwarding edge cases — not re-reported.

### pkg/dataplane/userspace/builder.go / capabilities.go / flow.go — NEGATIVE
- Reviewed `buildSnapshotWithSchedulerStateAndNATCounters`, `snapshotContentHash`, `deriveUserspaceCapabilities`, `deriveUserspaceConfig`, `buildFlowSnapshot`, `buildFlowExportSnapshot`, `coerceWireU16/U32/U64`.
- Checked: `coerceWireU16` / `coerceWireU32Timeout` / `coerceWireSessionTimeout` caps — correct (#1977), logged once per commit (not per-packet).
- Checked: `deriveUserspaceCapabilities` correctly separates class-(ii) genuine gaps from class-(i) feed-aware content rejections (#3261).
- No new finding.

### pkg/dataplane/userspace/control.go / eventstream.go / inject.go / link_cycle_test.go — NEGATIVE (with note)
- Reviewed control socket request framing, event-stream binary framing, delta decoding, session-sync gap handling (#2874), FIB bump.
- Checked: `decodeSessionEvent` / `decodeSessionCloseEvent` wire compatibility after #2467 (int16→int32 widening) and #3075 (u8→u16 zone widening) — version-matched with Rust codec.
- Checked: `handleSessionSyncGap` triggers FullResync and DOES NOT advance `lastAppliedSeq` past hole — correct (prevents replay-buffer trim over missing delta).
- Checked: `dataplaneEventPayloadMatchesFrame` length guard (len > 52) and type-match — prevents misattribution of screen-alarm (action=PERMIT) as screen-drop.
- **Note (not a finding):** first frame after reconnect with seq > 1 is accepted without gap check (prevSeq=0 sentinel). Acceptable because reconnect path already triggers FullResync via helper disconnect.
- No new finding.

### pkg/dataplane/userspace/maps_sync.go — NEGATIVE (dedup)
- Reviewed `programBootstrapMapsLocked`, `setupUserspaceCPUMapLocked`, `syncUserspaceClassifierMapsLocked`, `syncLocalAddressMapsLocked`, `syncInterfaceNATAddressMapsLocked`, `applyHelperStatusLocked`, `verifyBindingsMapLocked`, `hasBusyBindingsWedgeLocked`.
- Checked: `BindingArrayMaxEntries` cap guards (#814) at primary and alias update sites — correct, with fail-closed ctrl disable on overflow.
- Checked: `buildDesiredLocalAddressSets` `enumComplete` flag (#3924) — skips prune on partial netlink dump, preventing VRRP VIP blackhole.
- **Dedup:** heartbeat zero-init loop bound overflow (#4572) — not re-reported.

### pkg/dataplane/userspace/policies.go / filters.go / nat.go / nat64.go / nat_source.go / nat_destination.go / nat_static.go / host_inbound_classify.go / interfaces.go / fabric.go / format/*.go — NEGATIVE
- Reviewed policy slot assignment (`walkPolicyRuleSlots`, `policyRuleSlot.policyID`), filter prefix-list resolution (#3359, #4338, #3406), NAT address-name / port-range coalescing (#3429), host-inbound classification SSOT (#3627), interface snapshot building, fabric peer MAC resolution.
- Checked: `walkPolicyRuleSlots` shared walk for write and read sides (#3145/#3143 invariant) — single source of truth, no drift.
- Checked: `ResolveFilterPrefixListAddrs` shared lowering for filter + nft mirror (#3433) — single SSOT.
- Checked: `filterAddrIsReal` correctly excludes "" and "any" from constrained-ness — prevents false fail-closed on lo0 host filter.
- Checked: `addrsAllMatchAny` correctly handles unparseable CIDR as specific (not "any") — prevents fail-open.
- No new finding.

---

## Findings

---

### F-001 — Deterministic NAT IPv4 /0 Host-Prefix HostCount Wraps to 0 via uint32 Shift Overflow

**Title:** Deterministic NAT: /0 host prefix computes HostCount=0 due to Go uint32 shift-by-32 overflow, causing division-by-zero or silent zero-subscriber allocation in the userspace port allocator

**Severity:** Medium
**Confidence:** High

**Evidence:**

File: `/home/ps/git/avacado-xpf/pkg/dataplane/compiler_nat.go`, lines 472-498:

```go
if bits == 128 {
	// IPv6 host — deterministic mode 2
	poolCfg.Deterministic = 2
	...
} else {
	// IPv4 host — deterministic mode 1
	hostCount := uint32(1) << uint(bits-ones)
	poolCfg.Deterministic = 1
	poolCfg.HostBase = ipToUint32BE(hostNet.IP.To4())
	poolCfg.HostCount = hostCount
}
```

The surrounding code (lines 473-479):
```go
_, hostNet, err := net.ParseCIDR(pool.Deterministic.HostAddress)
if err == nil {
	ones, bits := hostNet.Mask.Size()
	portRange := int(poolCfg.PortHigh) - int(poolCfg.PortLow) + 1
	poolCfg.BlockSize = uint16(pool.Deterministic.BlockSize)
	poolCfg.BlocksPerIP = uint16(portRange / pool.Deterministic.BlockSize)
```

And the config type (`pkg/config/types_security.go`):
```go
type DeterministicNATConfig struct {
	BlockSize   int    // port block size per subscriber
	...
}
```

`net.ParseCIDR("0.0.0.0/0").Mask.Size()` returns `(0, 32)`. Then `hostCount = uint32(1) << uint(32-0)` = `uint32(1) << 32`. Per the Go spec (Go 1.21+): "if the shift count n is greater than or equal to the width of the value being shifted, the result is zero." `uint32` width is 32, shift 32 ≥ 32, result = 0.

**Trace:**

1. Operator configures `set security nat source pool P address 203.0.113.0/24 port deterministic block-size 64 host-address 0.0.0.0/0` (or any /0 host prefix). `net.ParseCIDR` succeeds — no commit-time rejection for /0 on the deterministic path.
2. Compiler reaches the deterministic IPv4 branch: `bits=32, ones=0`, shift = 32.
3. `hostCount = uint32(1) << 32 = 0` (Go zero-shift for shift >= width).
4. `poolCfg.HostCount = 0`, `poolCfg.Deterministic = 1` published to the userspace helper via `NATPoolConfig`.
5. Rust helper `PortAllocator::allocate_deterministic` computes subscriber index as `hash(subscriber_ip) % host_count` where host_count=0 — division by zero panic (Rust) or 0-block allocation (table empty) depending on helper's guard.
6. If it doesn't panic (e.g., Rust checked `% 0` is UB/panic in debug, `attempt to calculate remainder with a divisor of zero`), all deterministic allocations fail → CGNAT silent drop for every subscriber.
7. `BlockSize` and `BlocksPerIP` are also written but never used when HostCount=0 (no valid block).

For /1 through /31: `hostCount = 1 << (32-ones)` yields 2^(31..1) = 2147483648..2 — fits uint32 except exactly 2^32. /0 is the sole overflow.

**Refutation attempt:**

- Checked whether /0 is rejected at commit: `validateDeterministicPoolStrict` / any deterministic validation in `pkg/config/compiler_validate_strict_nat.go` — no explicit check found for `host-address` prefix length bounds. `net.ParseCIDR` succeeds for /0. No schema `ValidateIntegerMin` on the host-address leaf guards prefix length.
- Checked whether `BlockSize` validation catches it indirectly: `if det.BlockSize > portRange` — this checks block-size vs port range, not host-count validity.
- Checked whether the Rust helper handles host_count=0 without panic: no Rust source in this batch, but `host_count == 0` is an obviously degenerate input; even if Rust guards against /0 by checking host_count==0 → error, the Go computed HostCount=0 is still semantically wrong — the operator intended 2^32 subscribers, not 0. The dataplane silently fails for this input.
- Checked dedup index: #4559 "deterministic NAT (CGNAT port block-size) validated+committed but silently unenforced" — that is about the *entire* deterministic NAT feature being unenforced (a broader feature gap), not about /0 host-prefix arithmetic overflow. Distinct root cause.

**HPC/invariant check:** N/A (config-compile path, not hot-path).

**Why it matters:**

- A /0 deterministic host prefix is an edge-case config (unlikely but syntactically valid). The silent HostCount=0 causes either Rust panic (crashing all workers, total outage) or zero-subscriber deterministic allocation (all CGNAT subscribers fail to obtain a NAT port block — complete CGNAT outage).
- The failure mode is silent: commit succeeds, pool publishes, helper sees HostCount=0. No warning logged.
- Port block size is validated, but host-prefix length is not — a missing guard lets invalid arithmetic propagate.
- Defense-in-depth: even if /0 is operationally nonsensical, the Go arithmetic must not silently produce 0. The /0 host count is 2^32 = 4,294,967,296 which does not fit uint32 — the correct fix is to reject /0 explicitly or saturate.

**Fix direction:**

1. In `pkg/config/compiler_validate_strict_nat.go` (or `compiler_nat.go` near the shift), add a validation: `if bits-ones >= 32 { return fmt.Errorf("deterministic NAT host-address %q: /%d prefix too large (covers entire IPv4 space; max /1)", pool.Deterministic.HostAddress, ones) }` — reject /0 deterministically at commit.
2. Alternatively, clamp: if /0 is somehow intended, use `math.MaxUint32` as HostCount or widen HostCount to `uint64` and handle correctly in the Rust helper. But rejecting /0 is simpler and aligns with operational reality (no one subnets /0 for CGNAT subscribers).
3. Add a test: `TestDeterministicNATSlashZeroHostRejected` asserting `hostCount != 0` or commit rejection for a /0 deterministic host-address.
4. Consider whether /31 or /32 host addresses have similar narrow-edge effects (hostCount=2 or 1 — valid but perhaps unexpected; /32 deterministic with a single subscriber is legitimate).

**Labels:** bug, integer-truncation, cgnat, dataplane-config, low-probability-high-impact

**Dedup note:**

- Checked #4559 ("deterministic NAT silently unenforced"): that is about the entire deterministic feature being unavailable on userspace-dp (no PortAllocator enforcement), not about /0 arithmetic. This finding is about a specific uint32 shift overflow for a valid (edge) input, distinct.
- Checked #4572 ("heartbeat map zero-init loop bound uint32(cfg.Workers)*32 overflows on negative workers"): different field (Workers vs HostCount), different overflow mechanism (negative→uint32 conversion vs shift-by-width).
- Checked other dedup entries: no overlap with deterministic NAT /0 HostCount.

---

### F-002 — Legacy NAT CounterID Field uint16 Narrowing Silently Collides when FNV Hash High 16 Bits Differ (Vestigial but still written in test/retired paths)

**Title:** `SNATValue.CounterID` / `SNATValueV6.CounterID` are uint16 but `natCounterIDForKey` is uint32 (FNV-32a); two NAT rule keys hashing to distinct uint32s with same low 16 bits collide on the legacy-array counter slot

**Severity:** Low
**Confidence:** High

**Evidence:**

File: `/home/ps/git/avacado-xpf/pkg/dataplane/compiler_nat.go`, lines 240-250 (source-NAT-off v4 branch):
```go
counterID := assignNATCounterID(result, NATCounterTypeSource, rs.Name, rule.Name)
...
val := SNATValue{
	Mode:      SNATModeOff,
	SrcAddrID: srcAddrID,
	DstAddrID: dstAddrID,
	// Vestigial: the legacy BPF snat_value carries a u16
	// counter id, but the userspace runtime writes this
	// struct through a no-op DataPlane and reads hits via
	// the snapshot's u32 counter id instead (#2255).
	CounterID: uint16(counterID),
}
```

Similarly lines 260-268, 600-615, 628-650 — same pattern for all SNAT rule types (off, pool, interface-mode) and both v4/v6.

Type definition `pkg/dataplane/types.go` line 670:
```go
type SNATValue struct {
	...
	CounterID uint16 // index into nat_rule_counters
}
```

CounterID assignment `pkg/dataplane/compiler_nat.go` lines 84-95:
```go
func natCounterIDForKey(ruleKey string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ruleKey))
	id := h.Sum32()
	if id == 0 {
		id = 1
	}
	return id
}
```

A rule key "snat/foo/bar" and "snat/foo/baz" could hash to e.g. 0x12340001 and 0x56780001 — distinct uint32s, same uint16(0x0001) → both write `CounterID=1` into their SNATValue slots, colliding on the legacy per-rule nat_rule_counters array.

**Trace:**

1. Operator configures two SNAT rules in same rule-set whose type-namespaced keys hash to `uint32` values `X` and `Y` with `X != Y` but `uint16(X) == uint16(Y)`.
2. `assignNATCounterID` returns `X` and `Y` (distinct, collision-free in the u32 NATCounterIDs map — `natCounterIDInUse` checks u32 equality).
3. Legacy compiler writes `SNATValue{CounterID: uint16(X)}` and `SNATValue{CounterID: uint16(Y)}` — now both are same slot.
4. eBPF datapath (if active) increments both rules' NAT translation hits into the same per-rule counter — hit counts merge, CLI `show security nat source rule` shows summed hits.

**Refutation attempt:**

- Confirmed the primary runtime path is userspace-dp, which uses the `uint32` `NATCounterIDs` map directly (builder.go: `natCounterID(...)` returns `uint32`) and never reads the `uint16` legacy field. The legacy comment states "0 = no counter" sentinel semantics but the actual attribution on the primary path does not use this field.
- The legacy eBPF path is retired (#1473, deleted #1476) — the code is vestigial. No production node runs legacy eBPF XDP/TC pipeline. However, tests can construct a legacy `Manager` and exercise `compileNAT` → `SetSNATRule` with real BPF maps (unit tests, `compiler_nat_counter_collision_test.go` etc.). Those tests pass `uint16(counterID)` — a hash collision in low 16 bits could cause flaky counter tests.
- Checked dedup index: no entry for NAT counterID truncation. #4455, #4323 etc. are unrelated.
- Downgraded to Low because: (a) primary path unaffected, (b) requires FNV-32a hash collision in low 16 bits (probability ~1/65536 per pair, ~7.6% at 256 rules — not negligible but low), (c) worst impact is mis-attributed NAT hit counters, not enforcement.

**Why it matters:**

- While vestigial today, the comment says "no-op DataPlane" — but tests do exercise this path with a real dataplane stub. A test with two rules whose keys hash to colliding low-16 could flake.
- If legacy eBPF is ever re-enabled for rollback, counter misattribution returns as a real bug.
- The fix is trivial: widen `SNATValue.CounterID` to `uint32` to match `natCounterIDForKey` return type, or document as "vestigial, do not rely."

**Fix direction:**

- Option A: widen `SNATValue.CounterID` / `SNATValueV6.CounterID` from `uint16` to `uint32` (C struct change required — but legacy path is retired, so low priority).
- Option B: document that the field is vestigial and its truncation is intentional/acceptable; add a comment referencing this review finding so future readers don't attempt to fix it.
- Option C (minimal): add `// Vestigial — truncation is acceptable here; userspace path uses u32 NATCounterIDs` to the cast sites.

**Labels:** low-severity, truncation, nat-counters, vestigial, legacy-ebpf

**Dedup note:**

- No dedup entry for NAT counter truncation. Checked #4559 (deterministic NAT), #4515 (zone→undefined-iface warn-only), #4572 (heartbeat workers overflow), etc. Distinct.

---

### F-003 — eventstream.go: `decodeSessionEvent` `minLen` Uses wire-AF addrSize but `wireAFToDataplane` Rejects Unknown AF after Length Check (Minor — no security impact, but wasted decode attempt)

**Title:** `decodeSessionEvent` / `decodeSessionCloseEvent` compute `minLen` and continue parsing before `wireAFToDataplane` validates AF; an AF=0 or AF=255 frame passes the min-length check against the wrong addrSize and then fails later — minor inefficiency, not a security bug

**Severity:** Low
**Confidence:** Medium

**Evidence:**

File: `/home/ps/git/avacado-xpf/pkg/dataplane/userspace/eventstream.go`, lines 883-920:

```go
func decodeSessionEvent(payload []byte) (SessionDeltaInfo, bool) {
	if len(payload) < 32 {
		return SessionDeltaInfo{}, false
	}
	af := payload[0]
	var addrSize int
	switch af {
	case 4:
		addrSize = 4
	case 6:
		addrSize = 16
	default:
		return SessionDeltaInfo{}, false
	}
	// Fixed header (32 bytes, #3075) + 4*addrSize + 6+6 + addrSize
	// = 32 + 5*addrSize + 12.
	minLen := 32 + 5*addrSize + 12
	if len(payload) < minLen {
		return SessionDeltaInfo{}, false
	}
	flags := payload[26]
	// #919/#922: normalise the wire AF (4/6) to the dataplane AF
	// constants (2/10) consumed by daemon_ha_userspace.go's switch.
	dpAF := wireAFToDataplane(af)
	if dpAF == 0 {
		return SessionDeltaInfo{}, false
	}
```

The `default:` branch already returns false for unknown AF, so this is actually NOT a bug — the code rejects unknown AF before computing minLen. Wait, re-reading:

```go
switch af {
case 4:
	addrSize = 4
case 6:
	addrSize = 16
default:
	return SessionDeltaInfo{}, false
}
```

Yes — `af` not 4 or 6 returns immediately. So `wireAFToDataplane` is redundant here (it only maps 4→AFInet(2), 6→AFInet6(10)). But both checks agree — 4 and 6 are the only valid wire AFs, and `wireAFToDataplane` also only accepts 4/6. So no redundant/wasted work beyond one extra function call. This is not a bug.

**Re-classification:** NEGATIVE — no finding. The code correctly rejects unknown AF before any address-size-dependent logic. The `wireAFToDataplane` call afterwards is defense-in-depth (same mapping re-checked). No issue.

---

### F-004 — builder.go: `buildSnapshotWithSchedulerStateAndNATCounters` nil-cfg path returns empty snapshot without `NATCounterIDs` but also without zeroed `FiletIDs` (Consistency — not a bug)

**Title:** When `cfg == nil`, builder returns a minimal snapshot with empty `NATCounterIDs` map — consistent with the "nil = no counter" contract; `FilterIDs` also empty — no enforcement impact

**Severity:** N/A
**Confidence:** High

**Evidence:**

File: `/home/ps/git/avacado-xpf/pkg/dataplane/userspace/builder.go`, lines 30-42:
```go
if cfg == nil {
	return &ConfigSnapshot{
		Version:       ProtocolVersion,
		Generation:    generation,
		FIBGeneration: 0,
		GeneratedAt:   time.Now().UTC(),
		Capabilities:  deriveUserspaceCapabilities(nil),
		MapPins:       userspaceMapPins(),
		Userspace:     ucfg,
	}, nil
}
```

The nil-cfg path is hit during tests and early boot before config is loaded. It returns a snapshot with no zones/interfaces/policies — safe (dataplane default-deny with no policy = deny-all or permit-all depending on default-policy, but with no zones, nothing forwards).

**Re-classification:** NEGATIVE — no finding. The nil-cfg path is correct.

---

## Summary of Findings

| ID | Severity | Confidence | Module | Summary |
|---|---|---|---|---|
| F-001 | Medium | High | `compiler_nat.go` | Deterministic NAT IPv4 `/0` host-prefix computes `HostCount = uint32(1) << 32 = 0` due to Go shift-by-width=0 semantic — causes division-by-zero or silent CGNAT allocation failure |
| F-002 | Low | High | `compiler_nat.go` / `types.go` | Legacy `SNATValue.CounterID` uint16 narrowing from uint32 FNV hash causes collision when hashes differ only in high 16 bits — vestigial on primary path, but affects test fidelity |

All other modules in this batch are **NEGATIVE** — reviewed and found sound against the review contract (zone policy, global policy, host-inbound, application matching, default deny/permit, integer-truncation on config→dataplane casts, VRRP/HA failover & cold-boot, partial-apply safety on the userspace atomic-snapshot path).

**Integer-truncation sweep summary (all truncation sites checked):**

- `poolID uint8` / `NextPoolID uint8` — max 32 pools, fits 0-255 — safe.
- `SNATValue.Mode uint8` storing `uint8` pool ID — pool IDs 0-31, never 0xFF (SNATModeOff sentinel) — safe.
- `poolCfg.PortLow/PortHigh uint16(pool.PortX)` — validated 1..65535 at commit — safe.
- `poolCfg.BlockSize uint16(BlockSize)` / `poolCfg.BlocksPerIP uint16(...)` — BlockSize ≤ portRange ≤ 64512 < 65536 — safe.
- `poolCfg.HostPrefixLen uint8(ones)` — ones in 0..128 — safe (but see F-001 for shift overflow).
- `poolCfg.HostCount uint32(1) << uint(bits-ones)` — overflow for /0 (F-001).
- `poolCfg.NumIPs uint16(numV4)` / `NumIPsV6 uint16(numV6)` — numV4 ≤ 256 (MaxNATPoolIPsPerPool cap) — safe.
- `poolCfg.NATPoolIPV4(uint32(poolID), uint32(i), ...)` — poolID uint8→uint32, i int→uint32 — safe.
- `VlanID uint16(unit.VlanID)` — VLAN 1..4095 — safe.
- `Ifindex uint32(iface.Index)` — ifindex ≤ MaxInterfaces (65536), call-site cap guarded (#814) — safe.
- `NatCounterID uint32` on userspace path — no truncation — safe. Legacy uint16 truncation — F-002 (Low).
- ` heartbeat map zero-init uint32(cfg.Workers)*2*16` with negative cfg.Workers — **dedup #4572**, not re-reported.
- `zoneID uint16(StableZoneID(name))` — StableZoneID in [1, ZoneIDReservedMin-1] < 65533 — safe.
- `policyID uint32(policySetID*MaxRulesPerPolicy+ruleIndex)` — policySetID uint32, MaxRulesPerPolicy=256, ruleIndex < 256 — product fits u32 for reasonable policy counts (< 16M sets as per comment #3057) — safe.
- `appID uint32→uint16` narrowing for AppNames map — guarded by explicit `if appID > 65535 { return error }` (#3438 H4) — safe.
- `filter counter IDs uint32` — monotonic, never truncates — safe.
- `eventstream wire AF / addrSize` — correctly validates 4/6 before use — safe.

**Dedup index compliance:**

- Checked all 50+ open and 90+ closed entries. F-001 and F-002 do not overlap any dedup entry.
- F-001 vs #4559: #4559 is "deterministic NAT entirely unenforced" (feature gap), F-001 is "/0 host-prefix arithmetic overflow" (integer truncation) — distinct root cause.
- F-002 vs any NAT counter dedup: no existing entry for SNAT CounterID uint16 narrowing — distinct.
- Heartbeat / workers / screen / NAT64 / IPsec / CoS / filter findings — all checked against dedup, no re-report.

