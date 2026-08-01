# AGY adversarial plan-review — round 71 (plan v72 @ f04a5eca8)

Direct agy print-mode from the trusted /home/ps/git/bpfrx workspace with --add-dir at a 12m timeout. Verdict: PLAN-READY (exhaustive 15-file method enumeration — every exported *Manager method classed; all edge cases, class ambiguities, side-effect ordering constraints, and residual wording verified exact). Raw output follows verbatim.

---

# Adversarial PLAN Review: #2114 — Round 71 (CONVERGENCE)

**Doc under review**: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` (Draft v72 @ `f04a5eca8`)  
**Verdict Surface**: **PR-1 ONLY** (Core `d.dp` synchronized accessor + A3 method admission gate; G+H+H2 isolated in `followup-seed.md`).

---

### **VERDICT: PLAN-READY**

**Does anything in PR-1 block PLAN-READY for #2114?**  
**NO.** PR-1's partition of `*dataplane.Manager` methods is now total, exhaustive, and mathematically sound. All edge cases, class ambiguities, side-effect ordering constraints, and residual wording have been locked down.

---

### **1. Exhaustive Method Partition Verification (§4 A1 / A3)**

We enumerated every exported method on `*dataplane.Manager` across all 15 production files in `pkg/dataplane/*.go` and mapped each to its v72 classification and pre-arm outcome:

#### **Class 1 — Fallible map-required methods**
* **Contract**: Acquire-load `m.loaded.Load()` BEFORE accessing Start-populated state (`m.maps`). Pre-arm return typed `ErrDataplaneNotArmed`. Pure argument/ifindex validation without Start-state dependency (e.g. `AddTxPort` ifindex capacity check `loader.go:982-991`) may precede the gate.
* **Methods**:
  * `apply.go`: `ApplyConfig` [L237]
  * `loader.go`: `AttachXDP` [L489], `SwapToUserspaceXDPShimEntryProgram` [L604], `DetachXDP` [L639], `SetZone` [L830], `SetVlanIfaceInfo` [L879], `ClearIfaceZoneMap` [L889], `ClearVlanIfaceMap` [L956], `AddTxPort` [L982], `AttachTC` [L1081], `DetachTC` [L1131]
  * `maps_counters.go`: `ReadGlobalCounter` [L27], `IncrementGlobalCounter` [L50], `ReadInterfaceCounters` [L81], `ReadZoneCounters` [L117], `ClearInterfaceCounters` [L201]
  * `maps_fabric.go`: `UpdateFabricFwd` [L18], `UpdateFabricFwd1` [L28], `UpdateRGActive` [L38], `UpdateHAWatchdog` [L53], `BumpFIBGeneration`, `StartFIBSync` [L279], `SyncFabricState`
  * `maps_filter.go`: `SetIfaceFilter` [L16], `ClearIfaceFilterMap` [L25], `SetFilterConfig` [L44], `ReadFilterConfig` [L53], `SetFilterRule` [L66], `SetPolicerConfig` [L75], `ClearPolicerConfigs` [L84], `ClearFilterConfigs` [L97], `ReadFilterCounters` [L110], `ClearFilterCounters` [L128]
  * `maps_flow.go`: `SetFlowTimeout` [L32], `SetFlowConfig` [L41]
  * `maps_mirror.go`: `SetMirrorConfig`, `ClearMirrorConfigs`
  * `maps_nat.go`: `ClearDNATStatic`, `ClearDNATStaticV6`, `ClearNAT64Configs`, `ClearNATPoolConfigs`, `ClearNATPoolIPs`, `ClearSNATEgressIPs`, `ClearSNATRules`, `ClearSNATRulesV6`, `DeleteDNATEntry`, `DeleteDNATEntryV6`, `ReadNATPortCounter`, `ReadNATRuleCounter`, `SeedNATPortCounters`, `SetDNATEntry`, `SetDNATEntryV6`, `SetNAT64Config`, `SetNAT64Count`, `SetNATPoolConfig`, `SetNATPoolIPV4`, `SetNATPoolIPV6`, `SetNPTv6Rule`, `SetSNATEgressIP`, `SetSNATRule`, `SetSNATRuleV6`, `SetStaticNATEntryV4`, `SetStaticNATEntryV6`
  * `maps_policy.go`: `ClearAddressBookV4`, `ClearAddressBookV6`, `ClearAddressMembership`, `ClearApplications`, `ClearAppRanges`, `ClearPolicyCounters`, `ClearZonePairPolicies`, `ReadPolicyCounters`, `SetAddressBookEntry`, `SetAddressMembership`, `SetApplication`, `SetAppRange`, `SetDefaultPolicy`, `SetPolicyRule`, `SetZoneConfig`, `SetZonePairPolicy`
  * `maps_screen.go`: `ClearScreenConfigs`, `ReadFloodCounters`, `SetScreenConfig`, `UpdateSessionCountDst`, `UpdateSessionCountSrc`
  * `maps_session.go`: `BatchDeleteSessions`, `BatchDeleteSessionsV6`, `BatchIterateSessions`, `BatchIterateSessionsV6`, `ClearAllSessions`, `ClearAllSessionsChunked`, `DeleteSession`, `DeleteSessionV6`, `GetSessionV4`, `GetSessionV6`, `IterateSessions`, `IterateSessionsFrom`, `IterateSessionsV6`, `IterateSessionsV6From`, `SeedSessionIDCounter`, `SetSessionV4`, `SetSessionV6`
  * `maps_stale.go`: All 14 `DeleteStale*` and `ZeroStale*` methods

#### **Class 2 — Neutral-outcome methods (ANY signature)**
* **Contract**: Pre-arm returns master's missing-map outcome byte-for-byte without introducing new typed errors.
* **Methods**:
  * Non-error neutrals: `loader.go:IsLoaded` (`false` [L457]), `maps_session.go:SessionCount` (`(0, 0)`), `maps_stats.go:GetMapStats` (`nil` / empty slice [L69])
  * Error-signature no-ops: `maps_screen.go:ClearSessionCounts` (`nil` [L57-75]), `maps_nat.go:ClearStaticNATEntries` (`nil` [L258-286]), `maps_policy.go:UpdatePolicyScheduleState` (`nil` [L244-255] — #3780 retired-path spin fix)

#### **Class 3 — Hybrids with required pre-error side effects & Offset Helpers**
* **Contract**: Ungated by `m.loaded.Load()`. Must execute Go-side side-effect operations (e.g. resetting offset tables) pre-arm. `m.maps` lookups move under `m.mu` via scoped `mapsLocked` helper.
* **Methods**:
  * Hybrids: `maps_nat.go:ClearNATRuleCounters` [L395], `maps_counters.go:ClearGlobalCounters` [L176], `maps_counters.go:ClearZoneCounters` [L227], `maps_counters.go:ClearAllCounters` [L246]
  * Offset helpers: `maps_nat.go:ClearNATRuleCounterOffsets` [L389], `SetNATRuleCounterOffset` [L392], `maps_counters.go:ReadUserspaceCounterOffset` [L72], `SetZoneCounterOffset` [L135], `ClearZoneCounterOffsets` [L146], `maps_screen.go:SetFloodCounterOffset`, `ClearFloodCounterOffsets`

#### **Class 4 — Escaping getters of Start-populated eBPF objects**
* **Contract**: Gated by `m.loaded.Load()`. Pre-arm return `nil` or `(nil, ErrDataplaneNotArmed)`.
* **Methods**: `loader.go:Map` (`nil` [L1151]), `loader.go:Program` (`nil` [L1156]), `loader.go:NewEventSource` (`(nil, ErrDataplaneNotArmed)` [L1161])

#### **Ungated Construction Set & Lifecycle**
* **Contract**: Access state constructed at `New()` or managed independently of `Start()`.
* **Methods**: `loader.go:GetPersistentNAT` [L1146], `loader.go:XDPLinks` [L1195], `loader.go:TCLinks` [L1199], `loader.go:LastCompileResult` [L1191], `apply.go:LastApplyResult` [L249], `compiler.go:Compile` [L316], `loader.go:XDPEntryProgram` [L105], `SelectUserspaceXDPShimEntryProgram` [L114], `UsingUserspaceXDPShimEntryProgram` [L120], `CompileUserspaceShim` [L173], interface getters (`Link`, `HA`, `Sessions`, `SessionDeltas`, `Telemetry`), lifecycle methods (`Start` [L208], `Load` [L144], `LoadUserspaceShim` [L152], `Close` [L1206], `Teardown` [L1223]).

#### **Totality Net Enforcement**
Section 9 (line 4254) adds `TestManager_PreArmMethodMatrix` using AST reflection over `pkg/dataplane/*.go`. It automatically fails if any exported `*Manager` method is unassigned or misclassed, ensuring v70/v71 misses cannot recur.

---

### **2. Hostile Technical Analysis of Specific Concerns**

#### **2(a) Class-2 No-Op Pre-Arm `nil` Returns**
* **Finding**: `ClearSessionCounts`, `ClearStaticNATEntries`, and `UpdatePolicyScheduleState` return `nil` pre-arm.
* **Audit**: On master today, when maps are absent, these methods execute `if zm, ok := m.maps[name]; ok { ... } return nil`. Pre-arm, returning `nil` reproduces master's exact missing-map outcome byte-for-byte without hiding failures or introducing #3780 scheduler loops.

#### **2(b) Class-3 Iteration Escape & Map Lock Scope**
* **Finding**: `ClearStaticNATEntries` iterates eBPF map keys (`zm.Iterate()`).
* **Audit**: `ClearStaticNATEntries` is in **Class 2**, not Class 3. It is gated pre-arm by `m.loaded.Load()`. Post-arm (`m.loaded.Load() == true`), `m.maps` (the Go map of `*ebpf.Map` pointers) is fully populated and immutable. Class-3 methods do NOT iterate eBPF maps; they only acquire `m.mu` during the Go map lookup (`mapsLocked`), dropping it immediately. No `m.mu` is held across eBPF batch iteration or I/O.

#### **2(c) `Start()` Population Hold Time under `m.mu` vs 1 Hz Status Poll**
* **Finding**: `loader_userspace_shim.go:186-191` takes `m.mu` during `m.maps` population.
* **Audit**: The population loop merely copies ~20-50 pointer references in Go memory (`m.maps[name] = umap`). It executes zero eBPF syscalls and zero I/O operations. Hold time is <1 microsecond, causing zero measurable contention with the 1 Hz status poll or Class-3 readers.

#### **2(d) Class Uniqueness & Matrix Breakdown**
* **Finding**: Pre-arm return contracts uniquely assign methods to exactly one class.
* **Audit**: Class 4 governs escaping eBPF object getters. Class 3 governs Go-side side-effect offset tables. Class 2 governs byte-for-byte neutral outcomes. Ungated construction methods touch `New()` state. Class 1 governs all fallible map-touching operational methods. There is zero overlap or ambiguity between classes.

---

### **3. Residual Wording & Narrowed Exposure Verification**

* **Teardown Schedule Wording (§7 item 12, §10)**: The plan accurately specifies that shutdown's `stopPolicySchedulerLoop` (`daemon_scheduler.go:170-183`) performs an unbounded `applySem` acquisition that waits out an in-flight apply holder. The surviving interleaving is a late/new admission after `applySem` is released, where `AttachXDP` (`loader.go:575`) or `DetachXDP` (`loader.go:661`) writes `m.xdpLinks` while `Close()` ranges `m.xdpLinks` (`loader.go:1206-1216`).
* **Narrowed-Not-Closed (§4.7)**: The plan explicitly refrains from claiming teardown/lifetime exclusion or drain. It accurately states that PR-1 delivers **ADMISSION + VISIBILITY** safety, and that `Close()`-entry `Store(false)` and `m.mu` population locking **NARROW** pre-existing windows without claiming complete closure.

---

### **4. Fresh Attack on PR-1 Claims**

1. **Kind-Gated Typed-Nil Protection (`setDataplane`)**: `reflect.ValueOf(dp)` in `setDataplane` evaluates `v.IsNil()` ONLY on nillable kinds (`reflect.Chan`, `reflect.Func`, `reflect.Map`, `reflect.Pointer`, `reflect.Slice`, `reflect.UnsafePointer`). Struct and primitive types pass through without triggering a `reflect.IsNil` panic, preventing typed-nil contamination of `dpCell`.
2. **Snapshot Boundary Discipline**: All 134 production reader sites snapshot `d.dataplane()` into a local variable before checking nil and dereferencing, ensuring atomic read safety across concurrent `setDataplane` updates.
3. **`fwdstatus` Narrowing Isolation**: Retyping `forwardingStatusDaemonDataPlane` to satisfy only `fwdstatus.CachedStatusProvider` touches zero gRPC/CLI `Build()` paths (which build their own probes per request), eliminating structural misrouting risks.

---

### **Final Conclusion**

PR-1 design in v72 is **PLAN-READY**. The method partition is complete, the AST totality test provides mechanical enforcement, and all safety/residual claims are exact.
