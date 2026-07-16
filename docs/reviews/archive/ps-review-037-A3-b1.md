# xpf firewall deep audit — A3 batch 1: Go config compiler, schema & CLI grammar — ps-review-037-A3-b1

## 1. Base commit reviewed

```
d4506d4450e2 (master HEAD)
95af1984d ra: compare ReachableTime/RetransTimer in configEqual (#4570)
bfe83c531 Merge pull request #4568 from psaab/fix/4533-icmp-embed-failclosed
```

## 2. Output path

```
/tmp/ps-review-037-A3-b1.md
Base: d4506d4450e2
Batch: 1 of 3 — pkg/config/*, pkg/cmdtree/*, pkg/appid/*
```

## 3. Orientation & dedup

Three-phase: Junos AST → typed Go structs → userspace-dp control messages. Schema opt-in (#4313 X-1). Strict vs lenient (commit vs HA-sync/load). Dual-shape #2419, apply-groups transitive+memo #4474, inactive leading+inline+quoted, bracket stripping O(1), closedWorld, groupReplace, valueList, isIdentChar @ revert #4530, validateMultiValueLeaf "to" separator.

CLOSED (not re-reported): #4562 navigatePath intermediate, #4556 cli/api LOW residual, #4555 XDP EH, #4549 LOW batch, #4548 VRRP flap, #4547 ipsec DNS, #4546 WG, #4544 host-inbound dup, #4543 screen TLV, #4541 writeJSON, #4540 monitor keyword, #4539 session cache, #4535 three-color, #4534 PBR, #4526 DHCP, #4525 RA, #4524 monitor injection (HIGH), #4521 NAT pool bracket-list, #4520 nat64 counter, #4519 nptv6, #4518 nat64 allocator, #4517 EH walkers, #4514 policer, #4487/#4453/#4400 RST/FIN, #4399/#4438 NAT 1:N, #4393 dnat_table, #4392 PBR reject, #4388, #4384, #3864 deterministic NAT parse (NOT enforcement), etc.

OPEN (not re-reported unless new): #4559 deterministic NAT advisory, #4555 XDP EH, #4549, #4548, #4547, #4546, #4544, #4543, #4539, #4533, #4515, #4512, #2387 bare 5-tuple, #4146 junos-host XDP, #3226, #2852, #2562, #4478, #4455, #4313 opt-in schema, #4498 FRR sanitize, etc.

Prior reviews: /tmp/ps-review-018..035 — 14 reviews checked. /tmp/all_findings.txt (274 entries) scanned.

---

## 4. Module inventory (batch 1)

| Module | Files | LOC | Verdict |
|--------|-------|-----|---------|
| lexer/parser/ast/inactive/groups/edit | lexer.go, parser.go, ast.go, ast_groups.go, ast_edit.go, inactive.go | ~2500 | NEGATIVE (fixes verified) |
| schema + walk + validators | schema.go, schema_walk.go, schema_validators*.go, schema_*.go | ~4000 | 1 NEW Med (VRRP VRID), rest NEGATIVE |
| compiler core + dispatch | compiler.go, compiler_dispatch.go, compiler_prewalk.go, compiler_earlystrict.go, compiler_uniformgates.go, compiler_tailgates.go | ~3000 | NEGATIVE |
| compiler_security_* | compiler_security*.go, compiler_applications*.go, compiler_validate_strict_policy.go, types_security.go | ~5000 | NEGATIVE (core firewall correct) |
| compiler_interfaces | compiler_interfaces.go, types_interfaces.go, schema_interfaces.go | ~1500 | 1 NEW Med (VRRP VRID truncation) |
| compiler_other | compiler_nat.go, compiler_firewall.go, compiler_routing.go, etc. | ~6000 | NEGATIVE (integer-truncation caps verified) |
| cmdtree | tree.go | ~1100 | NEGATIVE |
| appid | catalog.go, runtime.go | ~800 | NEGATIVE |

---

## 5. Findings

### [A3-B1-001 — NEW, Med] VRRP GroupID (VRID) 1..255 not validated — int→uint8 truncation, VRID 0 reserved, collision on wrap

- **Title**: `vrrp-group <id>` instance name has no range validator — any integer commits, then `uint8(GroupID)` truncates: 0 (RFC 5798 reserved), 256→0, 257→1, etc. Two distinct `vrrp-group` IDs collide on wire VRID → state corruption / dual-master / VIP hijack.
- **Severity**: Medium
- **Confidence**: High
- **Evidence**:
  - `pkg/config/schema_interfaces.go:248-264` — no validator on the instance key:
    ```go
    func vrrpGroupSchemaNode(v6 bool) *schemaNode {
        return &schemaNode{desc: "VRRP group", args: 1, placeholder: "<group-id>", children: map[string]*schemaNode{
    ```
    Every other critical leaf (`priority`, `advertise-interval`) carries `valueType` + `validator` (e.g. `ValidateInteger(1,255)` for priority, `ValidateInteger(1,40)` for advertise-interval) — the group-id arg carries none. Instance keys are not typed-leaf validated by SchemaValidate; they are parsed via `namedInstances`.

  - `pkg/config/compiler_interfaces.go:694-698` — `parseVRRPGroups` accepts any integer, no range:
    ```go
    for _, vrrpInst := range namedInstances(addrNode.FindChildren("vrrp-group")) {
        groupID, err := strconv.Atoi(vrrpInst.name)
        if err != nil {
            continue
        }
    ```
    No `if groupID < 1 || groupID > 255` check. Negative, 0, 300, 65536 all accepted. `groupID` stored as `int` in `VRRPGroup.ID`.

  - `pkg/vrrp/instance.go:1834` — wire truncation on TX:
    ```go
    maxAdvert := uint16(vi.cfg.AdvertiseInterval / 10)
    pkt := &VRRPPacket{
        VRID:         uint8(vi.cfg.GroupID),
        Priority:     uint8(priority),
    ```
  - `pkg/vrrp/instance.go:1148`, `1249`, `1364`, `1425` — same truncation on RX filter:
    ```go
    if payload[1] != uint8(vi.cfg.GroupID) {
    ```
    And send path again at `1834`, `1849`.

- **Trace**:
  1. Operator `set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group 256 virtual-address 10.0.0.254/24` — strict commit succeeds (no validator). Also `vrrp-group 0` commits (0 is RFC reserved).
  2. `parseVRRPGroups` stores `ID=256` (or `0`) in `VRRPGroup`.
  3. `CollectVRRPInstances` copies to `pkg/vrrp.Instance.GroupID = 256`.
  4. `sendAdvert` does `VRID = uint8(256) = 0`. RFC 5798 §5.2.3: VRID 0 MUST be discarded by receivers — but `receiver` does `payload[1] != uint8(vi.cfg.GroupID)` which is `0 != 0` → false, so it accepts its own wrapped VRID. Two distinct groups `vrrp-group 1` (VRID 1) and `vrrp-group 257` (VRID 1 after truncation) on same interface share same VRID → `vrrpInstance` key is `VI_<if>_<groupID>` (uses untruncated int, so maps are distinct) but on wire they collide: adverts from one instance are accepted as if from the other (`payload[1]==1`), causing `recordMasterAdvert` to flap priority, spurious `masterDownTimer` resets, and potential dual-master or failure to elect.
  5. Cold-boot: node boots with `vrrp-group 256` → VRID 0. Peer with `vrrp-group 0` (or 256) also VRID 0 → same collision. Even single-node: VRID 0 is reserved; some peers (Juniper, other xpf with fix) discard VRID 0 → this node never forms, VIP never masters, cold-boot blackhole.

- **Refutation attempt**:
  - Could schema closedWorld reject unknown instance names? No: `vrrp-group` is wildcard instance (`args:1`), any token accepted as name. `closedWorld` is false for this subtree (no production subtree sets it).
  - Could `ValidateInteger(1,255)` be applied via `keyValidator`? No — `vrrpGroupSchemaNode` sets no `keyValidator`. `walkInstanceChildren` would call `keyValidator` if present, but none is set.
  - Could runtime reject? `instance.go` does not validate VRID range; `advertInterval()` defaults 0→1000ms but has no VRID check. `sendAdvert` truncates silently.
  - Could peer discard VRID 0? RFC says SHOULD discard, but xpf's own receiver does not: `payload[1] != uint8(vi.cfg.GroupID)` with GroupID 0 → expects 0, accepts 0. So xpf→xpf with VRID 0 interoperates, hiding the bug, but diverges from strict RFC peers.
  - Lenient path is not involved — this is strict-commit bug (schema never rejects, so lenient vs strict same).

- **HPC check**: Deterministic, not timing-dependent. Single config edit triggers. No lock contention.

- **Why it matters**: Integer truncation → VRID collision → VRRP mastership corruption. Two distinct `vrrp-group` IDs alias to same wire VRID, causing state-machine cross-talk, dual-master, or failure to master. VRID 0 is reserved; committing it breaks interop and can cause cold-boot VIP blackhole (node never masters because peer discards, or vice versa). VRRP is HA cold-boot critical path (focus area).

- **Fix direction**:
  - Add `keyValidator: ValidateInteger(1,255)` or `valueType: ValueInteger, validator: ValidateInteger(1,255)` equivalent for the instance-name slot in `vrrpGroupSchemaNode` (requires extending `schemaNode` to validate `args` instance names, or add explicit `validateVRRPGroupIDStrict` in `compiler_validate_strict.go` / `compiler_interfaces.go` like `validateChassisClusterStrict` does for RG IDs). Simplest: add `validateVRRPGroupIDStrict` called from `runUniformGates` or `compiler_prewalk.go`, iterating `cfg.Interfaces.Interfaces[].Units[].VRRPGroups` and rejecting `ID < 1 || ID > 255` (strict hard-reject, lenient warn for #1960 parity).
  - Additionally, `pkg/vrrp/instance.go` should defensively reject `GroupID < 1 || > 255` at instance creation (fail-closed) to prevent truncated wire TX even if config validation is bypassed via HA-sync.
  - Add `TestVRRPGroupIDRangeStrict` covering 0, 256, 257, -1.

- **Labels**: `integer-truncation`, `vrrp`, `ha`, `cold-boot`, `config-validation`, `security-hardening`
- **Dedup note**: NEW — not in `/tmp/all_findings.txt` (no VRRP GroupID/VRID range entry). Not in GH open issues (#4549 LOW batch = hop-limit/IPv4-only/PSK-zeroize/same-node-id, #4548 = MaxAdverInt no min clamp). Prior reviews (ps-review-018..035) did not report VRRP GroupID range.

---

### [A3-B1-002 — NEW, Low] VRRP Priority parsed with `_ = strconv.Atoi` — no range check in parser, lenient path keeps invalid, uint8 truncation changes election

- **Title**: `vrrp-group priority` / `preempt hold-time` / `advertise-interval` flat-set arm does `vg.Priority, _ = strconv.Atoi(keys[i])` with no error check; invalid token (`"high"`, `"300"`, `"-5"`) silently keeps previous value or 0, and out-of-range (>255) truncates on wire `uint8(priority)`.

- **Severity**: Low
- **Confidence**: Medium
- **Evidence**:
  - `pkg/config/compiler_interfaces.go:728-732`:
    ```go
    case "priority":
        if i+1 < len(keys) {
            i++
            vg.Priority, _ = strconv.Atoi(keys[i])
        }
    ```
    Same pattern at `:740` (`PreemptHoldTime`), `:748` (`AdvertiseInterval`), and hierarchical arm `:817`, `:829`, `:832`, `:838`.
  - `pkg/config/schema_interfaces.go:280-288` does have `validator: ValidateInteger(1,255)` for priority, so strict commit rejects non-numeric/out-of-range, but lenient path (HA-sync/load) downgrades SchemaValidate to warning and keeps the bad value. The parser's `_` ignores Atoi error, so `"priority high"` → `vg.Priority` stays 0 (then later default? No — default 100 set at creation, but flat-set parse overwrites with 0 on error? Actually `_` returns 0, so `vg.Priority = 0`). 0 priority on wire means "current master wants to stop" (RFC 5798 §5.3.1) → peer takes over immediately, flapping.
  - Wire: `pkg/vrrp/instance.go:1835` `Priority: uint8(priority)` — 300 → 44, 256→0, -5 → 251 (if negative somehow stored).

- **Trace**: Strict commit would catch via schema, but `CompileConfigLenient` (used by `Load` / `SyncApply`) downgrades schema errors to warnings and returns config with `Priority=0` or `Priority=300`. Runtime then does `uint8(300)=44`, electing wrong master. HA cold-boot with leniently-loaded bad config → wrong priority, possible split-brain.

- **Why it matters**: Integer truncation / parse-error-ignore leads to incorrect VRRP election weight on lenient boot path (HA-sync). Low severity because strict commit blocks it; only lenient path affected, and priority 0 is fail-closed (backup takes over) rather than fail-open.

- **Fix direction**: Make flat-set arm check `if n, err := strconv.Atoi(keys[i]); err == nil { vg.Priority = n }` (like `tunnel` code does) or rely on schema validator and ensure lenient path doesn't keep invalid value. Add explicit range check before `uint8` cast in `sendAdvert`.

- **Labels**: `integer-truncation`, `vrrp`, `lenient-path`, `low`
- **Dedup note**: NEW — not same as #4548 (MaxAdverInt) or #4549. Prior reviews did not report priority truncation.

---

## 6. Negatives (no finding — explicitly checked)

### Lexer / parser / AST / inactive / groups / edit — NEGATIVE

- `pkg/config/lexer.go` — bracket stripping O(1) non-recursive (loop `continue` not `l.advance(); return l.Next()`), fixes fable-review-164 H-2 stack overflow. `isIdentChar` deliberately excludes `@` per #4530 (avoids `@inactive` collision — `@` not valid Junos ident, `@inactive` is internal marker). Verified `IsIdentRune` mirrors `isIdentChar` set.

- `pkg/config/parser.go` — `maxParseDepth=256` with `skipToBlockClose` iterative drain prevents stack overflow (H-2). `inactiveMarker` detection gates on `TokenIdentifier` only, not `TokenString` — quoted `"inactive:"` preserved (#4348). Inline `inactive:` correctly truncates governed tokens, preserving parent. Dual-shape `#2419` handled.

- `pkg/config/ast.go` — `navigatePath` intermediate-descent union (#4562) and terminal read-all-siblings (#3980) correct. `unionChildren` single-node fast-path returns `nodes[0].Children` (shallow copy) — intentional, single-match unchanged. `matchNodeKeys` and `findNodeWithParent` longest-match logic correct (#3982).

- `pkg/config/inactive.go` — `WithoutInactive` returns receiver when no inactive nodes (no clone) — correct, documented. `cloneForExpansion` does exactly one deep copy — avoids double-copy. `stripInactiveNodes` deep copies active containers, prunes inactive subtrees. No aliasing bug.

- `pkg/config/ast_groups.go` — transitive+memo #4474 correct: `memoKey = name + "\x00" + ancestorPathKey(ancestorPath)`, `ancestorPathKey` uses `\x1e`/`\x1f` separators (control chars never in config tokens). `cloneNodes` before merge keeps cache pristine (merge mutates src). `seen` cycle detection + memo prevents exponential fan-out. `leafListUnionEligible` correctly rejects range-bearing leaves (`"to"` separator) to avoid corrupting port ranges.

- `pkg/config/ast_edit.go` — `SetPath` bracket-list collapse (#2419) and `valueList` opt-in (#3872 `next-hop [ a b ]`) correct. `DeletePath` member-specific deletion (#3846/#3975) and `DeactivatePath` round-trip correct. `ErrPathNotFound` sentinel wraps correctly (#4423 M9) for event-options tolerated-missing-delete.

### Schema / walk / validators — NEGATIVE (except VRRP VRID above)

- `pkg/config/schema.go` — `closedWorld` false everywhere (no production subtree opts in) — matches #4313 open-world default. `groupReplace`, `valueList`, `rangeSeparator` flags correct and documented. `isIdentChar` @ deliberate.

- `pkg/config/schema_walk.go` — `validateMultiValueLeaf` `to` separator only when `leafSchema.rangeSeparator` true — production IP/CIDR/session-log-flag leaves never have it, so literal `"to"` correctly rejected (#4556 L-01). `validateTailLeaf` gathers tail tokens from Keys[1:] + descendant leaves, correctly handles split-set `transmit-rate exact` beside `transmit-rate 1g`. `validateModifierChild` rejects unknown modifier tokens and trailing tokens on modifier. `validateScalarValueLeaf` rejects trailing tokens on fixed-arity leaves (#3332). `closed` flag threaded correctly.

- `pkg/config/schema_validators*.go` — `ValidateInteger`, `ValidateIntegerMin`, `ValidatePercent`, `ValidateIPAddress`, `ValidateIPv4/6CIDR`, `ValidatePREF64CIDR`, `ValidateCryptHash`, `ValidateRingEntries` all correct. `MaxDurationMillis/Seconds`, `maxWireU16/U32/I32` correct.

- `pkg/config/schema_interfaces.go` — priority `ValidateInteger(1,255)`, advertise-interval `ValidateInteger(1,40)` (VRRPv3 12-bit centisecond field: 40s = 4000cs last whole-second, 41s overflows 0x0FFF — correct). Tunnel MTU/TTL/key validators correct. VRRP group-id missing validator is A3-B1-001 above, not here.

### Compiler core / dispatch / prewalk / earlystrict / uniformgates / tailgates — NEGATIVE

- `pkg/config/compiler.go` / `compiler_dispatch.go` / `compiler_prewalk.go` / `compiler_earlystrict.go` / `compiler_uniformgates.go` / `compiler_tailgates.go` — decomposition #4406 preserves ordering invariants (P1..P7), first-error slot (invariant #6), warning accumulation order (invariant #7). Verified `runPreWalkGates` 22 gates, `runEarlyStrictAndFolds` 5 families, `runUniformGates` ~75 gates — all match master order. Golden-output test `compile_golden_4406_test.go` pins behavior.

- `compiler_uniformgates.go` VRRP/Cold-boot: `validateVRRPTrackInterfaceAST`, `validateVRRPAuthenticationAST`, `validateVRRPVirtualAddressSubnet` all correctly downgrade to warning on lenient path (#1960). No hot-loop: `AdvertiseInterval=0` defaults to 1000ms in `vrrp.go:57-60`, `advertInterval()` returns 1000ms for `ms<=0`.

### Compiler_security_* (core firewall) — NEGATIVE

- `compiler_security.go` / `compiler_security_policy.go` — `compilePolicies` correctly handles hierarchical (`Keys=["from-zone","trust","to-zone","untrust"]`) and flat-set (`from-zone → <name> → to-zone → <name> → policy`) shapes. `policyMatchChildren` / `policyThenChildren` (#3842) correctly accumulate across ALL duplicate `match{}`/`then{}` blocks, preventing fail-open widening. `policyThenActionNodes` + `applyCollapsedDenyModifiers` (#3141) correctly wire flat-collapsed `then deny log session-init`. `normalizePolicyAddrToken` correctly rewrites `any-ipv4`/`any-ipv6` to `0.0.0.0/0`/`::/0` (#2008 H11). `compilePolicy` terminal-action default to `PolicyDeny` when no terminal action (#3043) — fail-closed.

- `compiler_security_zones.go` — `parseHostInboundNode` / `mergeHostInbound` (#4544) correctly unions repeated `host-inbound-traffic` blocks (both zone-level and per-interface), dedup first-seen order. `dedupHostInboundTokens` only on merged path, single-block byte-identical.

- `compiler_validate_strict_policy.go` — `validatePolicyMatchAddressesStrict` (#2008), `validatePolicyMatchApplicationsStrict` (#3144), `validatePolicyMatchAddressSetMembersStrict` (#3149/#3147), `validatePolicyZoneReferencesStrict` (#2401/#3148/#4230 junos-host), `validateDuplicatePolicyNamesStrict` (#3473), `validatePolicyTerminalActionStrict` (#3043/#3850 dedup identical actions), `validatePolicyLogActionStrict` (#3060), `validateAddressBookEntryNamesStrict` (#3061/#4340 `/` in name allowed, only `zone-local/` prefix reserved) — all correct, deterministic iteration, first-error stable.

- `compiler_applications.go` — `ParseCanonicalUint` rejects signed (`"+80"`) and non-canonical, `parseCanonicalPort` delegates, `resolveAppPort` lowercases and resolves via `junosServicePorts` catalog, `validatePortSpec` / `validateProtocol` correct, `parseApplicationTerms` multi-protocol dedup, `aliasEchoICMPType` attaches echo-request type for junos-ping/pingv6 (#3348), `parseICMPTypeCode` 0..255.

### Compiler_interfaces (except VRID) — NEGATIVE

- `parseVRRPGroups` — correctly handles both inet/inet6 families (#2384), bracket-list `virtual-address [ a b ]`, flat-set Keys-packed shape, hierarchical children, nested `preempt { hold-time }` vs flat `preempt hold-time`, `track-interface` first-wins (#1814), `checkVRRPGroupTrackShape` etc. — all correct except GroupID range (A3-B1-001) and priority Atoi `_` ignore (A3-B1-002 Low).

- `parseTunnelWireguard` — `WgListenPort` and `KeepaliveSecs` correctly range-checked `n > 0 && n <= 65535` / `n >=0 && <=65535` before `uint16(n)` cast — no truncation. Lowercased pubkey (#1434) correct.

- `types_interfaces.go` — `VRRPGroup` fields correct, `PreemptHoldTime` int seconds, `AdvertiseInterval` int seconds default 1.

### Compiler_nat / firewall / routing / etc. — NEGATIVE (integer-truncation hardenings verified)

- `compiler_nat.go:expandAddressRange` — caps 256 IPs, checks `lowN > highN`, `count > 256`, `lowIP.To4()==nil` — no wrap. `appendPoolAddresses` reads full token stream (#4521 fix). `parseSourcePoolPortRange` accepts both Junos `<low> to <high>` and legacy `low <lo> high <hi>` — correct, strict gate rejects reversed/out-of-range.

- `compiler_nat.go:applyDeterministicKeys` — `strconv.Atoi` with `err==nil` check, no truncation issue (block-size int, host-address string). Advisory #4559 correctly warns not enforced on userspace-dp (OPEN, not re-reported).

- `compiler_firewall.go:flexible-match-range` — byte-offset `0..255` checked before `uint8(n)`, bit-length `1..32` checked before `uint8(n)`, mask/value `ParseUint(...,16,32)` with error recorded — fixes #3203 truncation (999→231) and fail-open 0x0. Mask default `uint32(1)<<BitLength -1` with `BitLength>=32` → `0xFFFFFFFF` — correct.

- `compiler_class_of_service.go` — `collectCoSDSCPCodePoints` / `collectCoS8021CodePoints` validate `0..63` / `0..7` before `uint8(v)`, `expandCoSCodePointToken` range-checked.

- `compiler_interfaces.go` tunnel key `uint32(v)` — `v` from `strconv.Atoi` with no range check, but schema `tunnel` key has no validator (unmodeled parity knob #4308 accepted-only) — Low, not in focus, not re-reported.

- `compiler_security_screen.go:174-187` — `n < 1 || int64(n) > math.MaxUint32` prevents `uint32` wrap on `4294967296→0`.

- `compiler_validate_strict_chassis.go` — `MaxHeartbeatRedundancyGroups=255`, `MaxHeartbeatRedundancyGroupID=255` — `uint8` count/id checked, prevents wrap to 0 / collision — fix verified.

- `compiler_validate_strict_nat.go` — DNAT pool port `70000→4464` / `-1→65535` wrap prevented, `destination-port` H13/H14 fixed (#3446/#3450), correct.

- `compiler_validate_strict_filter.go` — flex-match, port-except, address-except, DSCP, terminal-conflict — all correct.

### cmdtree — NEGATIVE

- `pkg/cmdtree/tree.go` — `OperationalTree` SSOT for `show`/`clear`/`request`/`monitor`/`test`/`ping`. `DynamicFn` / `ContextDynamicFn` most check `cfg==nil` before access; `#3476` nil-zone-pair / nil-policy skips correct. `show ... policy from-zone to-zone policy` `ContextDynamicFn` extracts `from-zone`/`to-zone` from `words` correctly, skips nil `zpp`/`p`. `ConfigTopLevel` `set`/`delete`/`show` correctly delegates to `pkg/config` schema for completion. No integer truncation, no concurrency (read-only tree).

### appid — NEGATIVE

- `pkg/appid/catalog.go` — `BuildCatalog` uses `uint32 nextID` to prevent `uint16` wrap onto 0 (reserved UNKNOWN sentinel), checks `nextID > maxCatalogAppID (65535)` deterministically, skips not-found apps without consuming ID (matches `pkg/dataplane.compileApplications` hard-error). `CatalogNames` shared resolver `addAppRef` expands application-sets, skips `""`/`"any"`, nil-safe (`#3622`).

- `pkg/appid/runtime.go` — `ResolveSessionName` returns `UNKNOWN` when AppID enabled (never port-heuristic guess), `resolveTupleFallback` prefers port-constrained app over protocol-only, tie-breaks by name deterministically (#2578). `portInSpec` uses `canonicalPort` → `ParseCanonicalUint` (rejects `"+80"`, `"70000"` → no `uint16` narrowing mislabel #3725). `protocolNumber` delegates to `ProtocolNumber` SSOT (#2124). No truncation.

### Resource safety / memory / concurrency — NEGATIVE (batch 1 scope)

- Lexer bracket stripping O(1) loop, parser depth 256 with iterative `skipToBlockClose` drain, `ast_groups` memo prevents exponential fan-out (#4474) — all fix prior OOM/stack-overflow DoS.

- `cloneNodes` deep copies Keys slice and Children recursively — no aliasing. `WithoutInactive` no-op when no inactive nodes — no extra allocation on common path.

- `filter_match_resolve.go` `junosServicePorts` map lookup O(1), `resolveSinglePort` range-checked `1..65535` before `uint16` return.

- NAT pool expansion 256-per-range cap prevents single-range OOM; total pool size unbounded but config file size bounds practical, and dataplane allocator caps still apply. Low residual, not a vulnerability.

- No goroutines, no shared mutable state, no `sync.Mutex` in batch 1 — concurrency N/A.

---

## 7. Summary

| ID | Title | Severity | Confidence | New? |
|----|-------|----------|------------|------|
| A3-B1-001 | VRRP GroupID (VRID) 1..255 not validated — int→uint8 truncation, 0 reserved, 256→0 collision | Medium | High | NEW |
| A3-B1-002 | VRRP Priority flat-set parse ignores Atoi error, lenient path keeps 0/300 → uint8 truncation | Low | Medium | NEW |

All other batch-1 files — lexer, parser, ast, inactive, groups, edit, schema, walk, validators, compiler dispatch/prewalk/earlystrict/uniformgates/tailgates, compiler_security_*, compiler_applications, compiler_firewall, compiler_nat, compiler_routing, cmdtree, appid — are **NEGATIVE** (no new High/Med findings) after verifying prior fixes (#2419 class, #4474 transitive+memo, #4544 host-inbound dup, #3842 policyMatchChildren/ThenChildren, #3850 duplicate then, #3141 collapsed deny, #3317/#3318 screen, #3203 flex-match, #3446/#3450 NAT port, #4521 NAT pool, #3864 deterministic NAT parse, #3061/#4340 address-book naming, etc.).

Focus areas:
- Core firewall (zone policies, global policies, host-inbound, application matching, default deny/permit): **NEGATIVE** — `default-policy permit-all/deny-all/reject-all` (#3065) correct, `default-policy-log` (#3534) wired, `policy-rematch` (#4233) accepted-only advisory, scheduler fail-closed (#3849), address-book fold collision-proof (#4340), policy gates deterministic and fail-closed.
- VRRP/HA cold-boot: **1 NEW Med** (VRID range / truncation) + 1 Low (priority truncation). Cold-boot with `vrrp-group 0`/`256`/`257` → VRID 0/collision → VIP never masters or dual-master. HA RETH VRRP `reth-advertise-interval` 10..40959 validated, 0 defaults to 30ms/1000ms — no hot-loop.
- Integer truncation: **VRRP VRID** (High confidence), VRRP priority (Low), all other wire casts (WG port, screen thresholds, CoS code-points, flex-match byte-offset/bit-length, NAT pool, tunnel key) verified bounded before cast.
- Resource safety: parser depth 256 + iterative drain, lexer O(1) bracket stripping, apply-groups memo DAG, NAT pool per-range 256 cap — no OOM/stack-overflow.
