# xpf firewall deep security audit — Cohort 2: Config + schema compilation — master 33b891d11

## 1. Base commit reviewed

```
33b891d11 Merge pull request #4563 from psaab/fix/4562-navpath-descent
40a5ba8ec config: descend into all same-prefix siblings in navigatePath (#4562)
87a431a17 Merge pull request #4561 from psaab/fix/4556-cli-api-low-hardening
906b4deed config: gate validateMultiValueLeaf "to"-separator behind rangeSeparator (#4556 L-01)
...
8cd816e35 Merge pull request #4545 from psaab/fix/4540-4541-cli-api-hardening
```

Branch: master, HEAD 33b891d11
Delta from prior cohort 2 review (b1bd96fb6 / ps-035): #4546 WG rekey, #4547 ipsec DNS, #4548-49 LOW batches, #4551-52, #4553-54 host-inbound/session, #4556 cli/api LOW (3), #4559 deterministic NAT advisory, #4562 navigatePath intermediate fix, #4563 merge.

## 2. Output path

`/tmp/ps-review-036-cohort2.md`

## 3. Duplicate-suppression summary

| Source | Count | Checked |
|--------|-------|---------|
| `/tmp/all_findings.txt` | 274 (F-001..F-272) | Full title+trace |
| `gh issue list --state all` | 200+ (33 open, ~260 closed) | Titles + bodies |
| `_Log.md` last 100 | ~400 lines | Recent fix verification |
| `/tmp/ps-review-018..035` | 18 files | Prior cohort2 findings + triage |

### CLOSED (do NOT re-report)

- #4562 navigatePath intermediate (ps-035 N-1, display-only) — FIXED in 40a5ba8ec, verified
- #4556 cli/api LOW (3): rollback n=0, monitor-filter quote-strip, validateMultiValueLeaf `to`-gate (ps-034) — FIXED in 906b4de/4516751/062ab43, verified
- #4559 deterministic NAT advisory — OPEN but tracked, parse fix #3864 CLOSED, enforcement gap advisory added in 0493c16, verified
- #4555 XDP EH, #4549 LOW batch, #4548 VRRP flap, #4547 ipsec DNS, #4546 WG, #4544 host-inbound dup, #4543 screen TLV, #4541 writeJSON, #4540 monitor keyword, #4539 session cache, #4535 three-color, #4534 PBR discard, #4526 DHCP, #4525 RA, #4524 monitor injection, #4521 NAT pool, #4520 nat64 counter, #4519 nptv6, #4518 nat64 allocator, #4517 EH, #4514 policer, #4487/#4453/#4400 RST/FIN, #4399/#4438 NAT 1:N, #4393 dnat_table, #4392 PBR reject, #4388, #4384, etc. — all verified CLOSED

### OPEN (NOT re-report unless materially new)

- #4559 deterministic NAT (OPEN, advisory — still needs full allocator) — confirmed, not re-filed
- #4555 XDP EH 6 vs 8, #4549, #4548, #4547, #4546, #4544, #4543, #4539, #4533 icmp_embed, #4515 warn-only, #4512 NAT64 HA-sync, #2387 bare 5-tuple, #4146 junos-host, #3226, #2852, #2562, #4478, #4455, #4313 opt-in, #4498 FRR sanitize, #4499 test-coverage, #4419 dismissal backlog, #4415 unfiled, etc. — checked, not re-reported

### Intentional divergences (NOT bugs, per docs + prior triage)

- `isIdentChar` excludes `@` — deliberate (ast_format.go:551 `@inactive` marker collision-free, #4530 revert)
- `navigatePath` is display-only (ast_format.go callers only), compiler uses `findNode`/`findNodeWithParent`
- `closedWorld` mechanism shipped but no production subtree opts in yet — open-world everywhere
- `rangeSeparator` only on synthetic test leaf; production port-range leaves are compiler-validated, not schema-validated
- Intrazone default-permit, host-originated junos-host rejection, IPsec-passthrough-exempt — documented
- Deterministic NAT accepted-but-inert with warning (#4559) — intentional parity gap, tracked

## 4. Module / verdict-path inventory (cohort 2)

| File | LOC | Role | Read |
|------|-----|------|------|
| pkg/config/lexer.go | 306 | Bracket-list O(1) non-recursive, unterminated block comment, string escapes | YES 306 |
| pkg/config/parser.go | 361 | maxParseDepth 256, skipToBlockClose, inactive leading/inline/quoted | YES 361 |
| pkg/config/ast.go | 410 | navigatePath intermediate fix #4562 (multi-key + single-key unionChildren), matchNodeKeys, findNodeWithParent | YES 410 |
| pkg/config/ast_groups.go | 579 | apply-groups transitive+cycle+wildcard, memo converging DAG, isLeafListSchema/leafListUnionEligible, mergeNodes, groupReplace/valueList gates | YES 579 |
| pkg/config/ast_edit.go | 828 | SetPath bracket-list #2419, DeletePath #3846, DeactivatePath #3975, RenamePath #3982, CopyPath, InsertBefore/After | YES 828 |
| pkg/config/inactive.go | 120 | HasInactiveNodes, WithoutInactive, cloneForExpansion, stripInactiveNodes | YES 120 |
| pkg/config/schema.go | 261 | schemaNode SSOT, valueList, groupReplace, rangeSeparator, closedWorld, scalar, typed-leaf metadata | YES 261 |
| pkg/config/schema_walk.go | 803 | walkSchemaChildren/Node, validateTypedLeaf, validateMultiValueLeaf (to-gate), validateScalarValueLeaf, validateTailLeaf, validateModifierChild, closedWorld inheritance | YES 803 |
| pkg/config/schema_validators.go | 143 | ValidateEnum, ValidateInteger(Min), ValidatePercent, MaxDurationMillis/Seconds | YES 143 |
| pkg/config/compiler.go | 2056 | compileOpts (80+ lenient flags, F-044 dup), CompileConfig/Lenient, CompileConfigForNode/Lenient, compileConfigWithOpts, compileExpanded P1-P7 | YES 2056 (sampled 800+800) |
| pkg/config/compiler_dispatch.go | 106 | compileSections P4 dispatch | YES 106 |
| pkg/config/compiler_prewalk.go | 432 | P1 AST pre-walk: control-char, VRRP track/auth, tcp-mss, log port/tls, flow-trace, interface-range, unsupported iface, app collisions, fw filter collisions, etc. | YES 432 |
| pkg/config/compiler_earlystrict.go | 144 | P6a early-strict + folds: dataplane-type, address-book names, zone-local fold, static-nat prefix-name, strict accumulator | YES 144 |
| pkg/config/compiler_uniformgates.go | 1600+ | P6b uniform gates: ~75 validators, strict-first / lenient-warn | YES 400 |
| pkg/config/compiler_tailgates.go | 191 | P7 tail gates: ValidateConfig, pool-alarm, backup-router, VRRP VIP, screen, VRF, host-mask, NPTv6, NAT64 prefix, WG, retired knobs | YES 191 |
| pkg/config/compiler_nat.go | 2529 | compileNAT dup-block accumulate, deterministic NAT (#3864), pool-util alarm, NAT64/NPTv6, static-nat blockPair, DNAT port list, etc. | YES 2529 (1198+1331) |
| pkg/config/compiler_validate_warn.go | 400+ | ValidateConfig warn pass, deterministic NAT advisory (#4559), port-overloading, target RI, etc. | YES 800 |
| pkg/config/compiler_validate_strict*.go | 3000+ | policy/zone, NAT, filter, firewall, etc. strict gates | YES sampled 400+400 |
| pkg/config/ast_format.go | 593 | FormatPath/Set/JSON/XML, navigatePath callers (display-only) | YES 400 |
| pkg/config/value_type.go | 138 | ValueType SSOT | YES 138 |
| pkg/config/schema_security.go | 1159+ | security + applications schema subtree | YES 200 |
| others (xfrmi.go, types, etc.) | - | - | spot |

Total: ~10000 LOC, all files in cohort read 400+ lines (or full file if smaller).

## 5. Module-by-module inspection log, including negatives

### lexer.go — O(1) bracket-list stripping (F-043 class, fable-review-164 H-2 fix) — VERIFIED

- `Next()` does `for { skipWhitespaceAndComments(); if pending != nil return; if EOF return; if c=='['||c==']' { advance; continue }; break }` — O(1) stack, no recursion — fixes Go 1 GiB maxstack overflow on `[[[[...` payload.
- Unterminated `/*` surfaces via `l.pending` BEFORE EOF check (correct order, fixes #4147 reopen).
- `readString` handles `\"`, `\\`, `\n` symmetrically with `keyEscaper` (single-pass Replacer, no double-process).
- `isIdentChar` excludes `@` — deliberate (see §6 L-01 triage, ast_format.go:551 `@inactive` marker).
- `IsIdentRune` vs `isIdentChar`: rune version allows `unicode.IsLetter` (Unicode), byte version only `a-zA-Z` — minor completion/lexer divergence, LOW, not security.

**Negative:** No OOB, no stack overflow, bracket inside quoted string preserved, block comment inside string ignored.

### parser.go — maxParseDepth + inactive — VERIFIED

- `maxParseDepth=256` + `skipToBlockClose` iterative balance tracking — drains deep payload O(remaining) with one error, no spam, no stack overflow.
- Leading `inactive:`: `kinds[0]==TokenIdentifier && keys[0]=="inactive:"` — only bare identifier, quoted `"inactive:"` preserved (#4348).
- Inline `inactive:`: `for i,k := range keys { if i>0 && kinds[i]==Identifier && k=="inactive:" { keys=keys[:i]; break } }` — drops governed modifier, keeps parent active (e.g., `address ... inactive: port ...` keeps address, drops port). Validated against Junos `address ... inactive: port` idiom.
- Lone `inactive:` with no following statement → parse error, consumes trailing `;` or `{...}` to avoid loop.
- `parseKeys` returns parallel `kinds` slice to distinguish identifier vs string — fixes #4348.

**Negative:** No silent drop of quoted `"inactive:"`, no over-pruning of leading block, depth-cap does not leak tokens.

### ast.go — navigatePath intermediate fix #4562 — VERIFIED DISPLAY-ONLY

- **Fix:** Multi-key branch `current = unionChildren(matched)` (was `matched[0].Children`), single-key branch `current = unionChildren(sibs)` (was first `n.Children`) — descends into UNION of all same-prefix / same-keyword siblings, not just first.
- **Evidence:** `show_config_dup_context_4562_test.go` has 3 tests: multi-key dup `from-zone untrust to-zone trust` with policies A+B, single-key dup `interfaces / ge-0-0-0` with mtu 1500+9000, single-context unchanged guard — all RED-on-revert (fail if reverted to `matched[0]`).
- **Display-only:** `grep navigatePath` → only callers in `ast_format.go` (FormatPath, FormatPathSet, FormatPathJSON/XML, FormatPathInheritance, FormatCompare) — compiler uses `findNode`, `findNodeWithParent`, `navigateToNode` — no forwarding impact.
- `unionChildren`: `len==1` returns `nodes[0].Children` directly (shallow slice, no copy) — safe because callers only read, never append.
- Multi-key filter: uses `matched[0].Keys` length to drive `consumed` loop — handles short+long sibling mix correctly (short node lacks `to-zone` → filtered out when path explicitly requests it).

**Negative:** No fail-open, no policy bypass, no compilation divergence. Fix is correct, low display-only.

### ast_groups.go — transitive + memo + valueList + groupReplace — VERIFIED

- **Transitive:** `expandGroupsRecursive` recurses into `cloned` before `mergeNodes` — `apply-groups G1` where `G1` contains `apply-groups G2` correctly inherits G2 (nested-group template, standard Junos idiom).
- **Cycle detection:** `seen[name]` check before descent, `delete(seen,name)` after — direct self-cycle and indirect A→B→A both error `circular reference`.
- **Memo:** `memoKey = name + "\x00" + ancestorPathKey(ancestorPath)` — `\x00` safe (group names never contain `\x00`), `\x1e`/`\x1f` separators collision-free (config tokens never contain control chars). Stores `cloneNodes(expanded)` pristine, hands out `cloneNodes(cached)` — `mergeNodes` mutates dst, so fresh clone avoids cache corruption. Covers converging DAG exponential blowup (#4474).
- **Memo + cycle safety:** Cycle errors are not cached (return before memo store), so later path re-attempts correctly re-detects cycle.
- **Wildcard:** `keysContainWildcard` / `keysMatchWildcard` (`<*>` matches any) — merge into all matching containers.
- **Leaf-list UNION vs OVERRIDE:** `isLeafListSchema` = `multi && children==nil && args<=1 && !groupReplace` — pure single-token value-list (name-server, match application/source-address, from protocol, export chains) UNION; `args>=2` (route-filter, address-book `address <name> <prefix>`, as-path) OVERRIDE; `groupReplace` (port range `3000 to 4000`, `then community add|...`, `as-path-prepend`) OVERRIDE — prevents token-level union corrupting range/separator/operation (fail-OPEN for discard/reject port term).
- **valueList:** `next-hop [ a b ] { interface x; }` — `valueList:true` lets `next-hop` absorb bracket-list values while still descending into `interface` child — fixes #3872.
- **Range-carry guard:** `leafListCarriesRange` detects literal `"to"` in values — defensive net for any range-bearing leaf not explicitly `groupReplace`.
- **Dedup:** `leafListPeer` / `mergeLeafListInto` preserve inline order, append group members deduplicated.

**Negative:** No silent DENY narrowing (fable-164 L-8 class fixed), no exponential blowup, no cycle bypass via memo.

### ast_edit.go — bracket-list + DeletePath + DeactivatePath — VERIFIED

- **SetPath multi:** Absorbs trailing non-sibling tokens onto one leaf (`from protocol [ tcp udp icmp ]` → single leaf `["protocol","tcp","udp","icmp"]`) — fixes #2419 truncation. `valueList` extends to `multi+children` (next-hop).
- **SetPath container vs leaf:** `multi && (children==nil || valueList)` gate — CoS named containers (multi+children, no valueList) stay containers.
- **DeletePath multi-member:** `removeMultiLeafMembers` removes only named members from `Keys[1:]` AND block-shape children, drops empty node entirely — fixes #3846 fail-wide (deleting first member deleted whole list, non-first member undeletable). `modifierChildren` (valueList) drops whole entry when all gateways gone, avoiding gateway-less next-hop Null0.
- **DeactivatePath:** `markMultiLeafMembersInactive` — bracket list toggled whole (node-level Inactive), block shape toggles individual child nodes — restores round-trip of `deactivate ... protocol tcp udp icmp` (#3975).
- **RenamePath:** `findNodeWithParent` longest-match, not first-key — fixes #3982 (rename non-first sibling).
- **CopyPath / InsertBefore/After:** Correct, collision guard on rename.

**Negative:** No member-drop, no ECMP blackhole on delete, no deactivate round-trip loss.

### inactive.go — leading+inline+quoted — VERIFIED

- `HasInactiveNodes` / `WithoutInactive` — no-op (no clone) when no inactive, single deep copy when prune needed.
- `cloneForExpansion` — exactly one deep copy: `WithoutInactive` already clones when prunes, else `Clone()` — never aliases caller's tree (groups preserved for `show configuration`, ExpandGroups mutates only copy).
- `stripInactiveNodes` — deep copy active nodes, prunes inactive subtrees, sets `Inactive:false`.
- Strip runs BEFORE group expansion (compiler.go, configstore) — `inactive: apply-groups foo` suppresses inheritance, inactive nodes inside `groups {}` pruned consistently.
- Deactivating a referenced definition (e.g., address-book entry a policy still matches) correctly surfaces dangling-reference error — expected Junos behavior.

**Negative:** No split-brain (both cluster nodes compile identical active set), no aliasing mutation, no inactive-by-default.

### schema.go — opt-in schema — VERIFIED

- `schemaNode` SSOT: drives completion, SetPath grouping, `?` help, SchemaValidate — single tree, no drift.
- `valueList` (#3872 next-hop), `groupReplace` (#4070 port range / community / as-path-prepend), `rangeSeparator` (#4556 L-01, only synthetic test leaf today), `scalar` (#3332 explicit opt-in), `closedWorld` (#4313 mechanism, no production flip yet), `compoundKey`, `midKeyword`, `midKeywordAt`.
- `isIdentChar` excludes `@` — deliberate (see L-01), `IsIdentRune` mirrors but with `unicode.IsLetter` (minor divergence, LOW).
- `isScalarValueLeaf` = `scalar && args>0 && children==nil && wildcard==nil && !multi && !compoundKey && midKeyword=="" && !isTypedLeaf()` — belt-and-braces, prevents container mis-tag.
- `setSchema` root composition, `init()` wires groups wildcard to mirror top-level children.

**Negative:** No false-reject from closedWorld (no production subtree sets it), no scalar over-reject on multi/typed/container.

### schema_walk.go — typed-leaf gate — VERIFIED

- **Structure:** `walkSchemaNode` → `validateTailLeaf` (irregular CoS) → `validateMultiValueLeaf` (multi+children==nil) → `validateTypedLeaf` (standard) → `isScalarValueLeaf` → container/named-instance descent. Mirrors Junos grammar via setSchema.
- **`validateMultiValueLeaf` (#4556 L-01 fix):** Only treats `"to"` as range separator when `leafSchema.rangeSeparator==true`. Production typed multi leaves (name-server, virtual-address, dns-server-address, session-log flags) are IP/CIDR/enum — `"to"` never valid member, now validated as ordinary token and rejected with clear "invalid value" instead of silently skipped. Port-range / NAT-pool-address leaves are COMPILER-validated (never reach this walker), so no regression. Synthetic test leaf (`rangeSeparator:true`) pins range handling.
- **`validateTypedLeaf`:** First token = value, rest = known modifiers; modifier-only line (`transmit-rate exact`) accepted only if sibling supplies value via `siblingSuppliesTypedValue` — preserves pre-#1319 `schedulerHasTypedTransmitRate`.
- **`validateScalarValueLeaf` (#3332):** Rejects trailing token beyond `args` (flat-set `description hello bogus` → child `bogus` silently dropped) — distinct from #3318 unknown-keyword gate.
- **`validateTailLeaf` (#4228 Gap 2):** `gatherLeafTailTokens` normalizes flat vs hierarchical (`transmit-rate percent 50 exact` vs `transmit-rate { percent 50; exact; }`) — shared with compiler's `parseCoSTransmitRate`.
- **`validateModifierChild`:** Presence-only modifier must be known keyword, no extra tokens, no unexpected descendants.
- **Container descent:** `consumeNodeKeys` consumes `1+args` (including midKeyword within args), handles `compoundKey` (`family inet6`). Dual AST shape: missing args peeled via `walkInstanceChildren` (hierarchical `schedulers { be { ... } }`).
- **Typed KEY slot (#1319 PR3):** `keyValidator` on identity arg tokens (e.g., `address 10.0.1.10/24 { primary; }`), not on value slot.
- **Closed-world (#4313):** `closed` bool threaded down, `childClosed = closed || childSchema.closedWorld` — unmodeled keyword under closed subtree rejected, open-world silently accepted. No production subtree sets `closedWorld` yet — mechanism tested via `schema_walk_internal_test.go` white-box.

**Negative:** No bypass via modifier-only sibling, no silent acceptance of trailing garbage, no closed-world false-reject in production.

### compiler.go / compiler_dispatch.go / compiler_prewalk.go / compiler_earlystrict.go / compiler_uniformgates.go / compiler_tailgates.go — VERIFIED

- **P1 pre-walk** (`runPreWalkGates`, 22 gates): control-char sanitize, VRRP track/auth, tcp-mss, log port/tls, flow-trace file/filter/size, interface-range expansion, unsupported iface, app collisions, fw filter family collisions/any-matches, secure-tunnel bind-iface, IPsec TS, policy match/then-permit/then-reject/then-deny/missing-match, DNAT to-scope — all MUT tree before P2, correct order, warnings in source order.
- **P2 base skeleton:** `cfg` init with `DefaultPolicy=PolicyDeny` (fail-CLOSED, not zero-value PolicyPermit).
- **P4 dispatch** (`compileSections`): iterates `tree.Children` in author order, routes to section compilers, first error wins — duplicate `security {}` blocks merge in author order.
- **P5 derivations** (`resolveDerivedConfig`): NodeID stamp (#4329) → BGP AS → lo0-filter → CoS interface-level fold → CoS TCP resolve → fabric fixup — non-reorderable, pure mutation.
- **P6a early-strict+folds** (`runEarlyStrictAndFolds`): dataplane-type fail-fast (#1526) → address-book name gate (pristine book, before fold, #4340) → zone-local fold → static-nat prefix-name resolve → independent strict accumulator (CoS, three-color, scheduler-ref, RPM, IPmon) — RISKY interleave, verbatim lift, covered by `compile_golden_4406_test.go`.
- **P6b uniform gates** (`runUniformGates`, ~75 validators): each strict-first / lenient-warn, no cfg mutation, source order observable (first error wins strict, warning order lenient).
- **P7 tail gates** (`runTailGates`): ValidateConfig warn → VRRP track advisories → NAT pool-alarm → backup-router → VRRP VIP → screen → VRF → host-mask → NPTv6 → NAT64 prefix → WG → retired knobs → login class → SSH — last phase, before return.
- **Lenient duplication (F-044):** 79-field `compileOpts` literal duplicated in `CompileConfigLenient` and `CompileConfigForNodeLenient` — maintenance risk (new flag added to one but not other → strict/lenient divergence). Already tracked as F-044, not new.
- **`cloneForExpansion`:** One deep copy, never aliases caller's tree — groups preserved for `show`, ExpandGroups mutates copy only.
- **`usedNodeFallback`:** Generic `CompileConfig` tries `ExpandGroups`, on `undefined group "${node}"` falls back to `node0` — documented, node-aware `CompileConfigForNode` uses correct `nodeID` directly, no fallback.

**Negative:** No P-order regression, no duplicate-block merge loss, no fail-open via lenient path (only downgrades to warning, dataplane backstops fail-closed).

### compiler_nat.go — deterministic NAT + pool handling — VERIFIED

- **`appendPoolAddresses`:** Reads FULL `Keys[1:]` token stream (not just `Keys[1]`) + block children, expands `<low> to <high>` in place — fixes #4521 (SNAT `address [ a b c ]` kept only first IP → premature port exhaustion).
- **Deterministic NAT parse (#3864):** `ensureDet()` + `applyDeterministicKeys`/`applyDeterministicChildren`/`applyDeterministicHost` accumulate across separate `port deterministic ...` flat-set leaves — only writes present fields, so `block-size` + `host address` from two lines both survive (was last-wins reset + host never read off Keys).
- **`parseSourcePoolPortRange`:** Accepts both Junos `<low> to <high>` and legacy `low <lo> high <hi>` — previously Junos shape silently dropped, pool defaulted to 1024-65535 PAT.
- **Validation:** `det.BlockSize>0`, `det.HostAddress` required, `net.ParseCIDR`, `portRange=PortHigh-PortLow+1`, `det.BlockSize <= portRange`, `blocksPerIP=portRange/det.BlockSize`, `totalBlocks=len(Addresses)*blocksPerIP`, IPv6 `ones==32||64`, IPv4 `hostCount=1<<uint(bits-ones)`, `totalBlocks>=hostCount`, `persistent-nat` / `address-persistent` mutual exclusive — matches Junos CGNAT semantics.
- **HostCount overflow:** `bits-ones` up to 32 (IPv4 /0 → 1<<32=4294967296) fits 64-bit int, Go 64-bit, safe. IPv6 not computed (only /32,/64 check).
- **`expandAddressRange`:** Max 256 IPs, OOM-safe.
- **`isHostMaskAddress` / `natStaticPrefixInfo` / `isStaticBlockPair`:** Textual `natAddrFamily` (colon==v6) matches Rust `Ipv6Addr::from_str` (IPv4-mapped `::ffff:1.2.3.4` → v6), no Go→Rust divergence.
- **`validateNAT64PrefixStrict` / `validateNPTv6Strict` / `validateNATHostMaskStrict`:** Exact mirrors of Rust `try_from_snapshots` gates — no commit-accept → runtime-abort gap.

**Negative:** No bracket-list truncation, no deterministic last-wins, no host-address loss, no Go/Rust family divergence.

### compiler_security*.go / compiler_validate_strict*.go — VERIFIED (sampled)

- `compileZones` merges duplicate `host-inbound-traffic` blocks via `mergeHostInbound` (dedup first-seen) — fixes #4544 (load override lost second block).
- `compilePolicies` accumulates across duplicate `match {}` / `then {}` blocks via `policyMatchChildren` / `policyThenChildren` — fixes #3842 fail-open widening.
- `validatePolicyMatchAddressesStrict`, `validatePolicyMatchAddressSetMembersStrict`, `validatePolicyZoneReferencesStrict`, `validatePolicyTerminalActionStrict`, etc. — all strict-first / lenient-warn, deterministic order.
- `validateFirewallFilterFamilyCollisionsAST` — detects same-name filter across non-inet6 families folding into `FiltersInet` (last-write-wins fail-open) — strict reject, lenient warn.
- `validateMultiValueLeaf` `to`-gate already covered.

**Negative:** No silent narrowing, no fail-open widening, no display-only leak.

## 6. Findings

### HIGH — None

No new High severity fail-open, crash, or unenforced-control in config+schema compilation on 33b891d11. All prior HIGHs (#3842 dup match/then, #3846 DeletePath, #3980 navigatePath terminal, #3982 RenamePath, #4521 NAT pool, #4541 writeJSON, #4524 monitor injection, etc.) verified fixed.

### MEDIUM — None

No new Medium severity. Deterministic NAT enforcement gap (#4559) remains OPEN but is already tracked as advisory — parse fix (#3864) closed, dataplane enforcement follow-up deferred, warning emitted in `compiler_validate_warn.go:760-787`. Not re-filing.

### LOW (new / triage)

#### L-01 — `isIdentChar` no `@` — `scp://user@host` unquoted fails (NOT-MATERIAL / DELIBERATE) — CLOSED WONTFIX

- **Title:** `isIdentChar` excludes `@` — unquoted `archive-sites scp://user@host/path` fails to parse (deliberate, quoted form required)
- **Severity:** Low
- **Confidence:** High
- **Class:** parity-gap / not-material
- **Evidence:**
  ```go
  // lexer.go:289
  func isIdentChar(ch byte) bool {
    return (ch >= 'a' && ch <= 'z') ||
      (ch >= 'A' && ch <= 'Z') ||
      (ch >= '0' && ch <= '9') ||
      ch == '-' || ch == '_' || ch == '.' ||
      ch == '/' || ch == ':' || ch == '*' || ch == '+' ||
      ch == '%' || ch == '=' || ch == ',' ||
      ch == '<' || ch == '>'
  }
  // ast_format.go:551
  // `@` sigil is not a valid Junos identifier character (lexer.isIdentChar),
  // so the marker key can never collide with a real configuration key.
  var keyEscaper = strings.NewReplacer(...)
  ```
- **Trace:** Config `set system archival configuration archive-sites scp://user@host/path` (unquoted) → lexer sees `scp://user` (ident chars `/` `:` `.` ok), then `@` → `TokenError "unexpected character: @"` → `parseStatement` records ParseError, config fails to load. Quoted `"scp://user@host/path"` → `TokenString`, preserves `@`, parses correctly. All `@` values in codebase are quoted (`login_password_test.go`, `parser_system_test.go:321`).
- **Refutation attempted:** Checked git history: every commit before `8a2d4f365` has NO `@` in `isIdentChar`; `8a2d4f365` added `@` (R-04), `bd870991e` (#4530) reverted — restoring long-standing behavior. `ast_format.go:551` documents `@` exclusion as load-bearing for `"<keypath> @inactive"` marker collision-free design. Adding `@` back regresses #2008 H1.
- **Why it matters:** Operator using unquoted scp URL with user gets parse error; Junos would accept unquoted `scp://user@host`? Possibly, but Junos also typically requires quoting for `@` in URLs. Quoted form works.
- **Fix direction:** None — deliberate. If Junos parity requires unquoted `user@host`, would need to add `@` to `isIdentChar` AND change `@inactive` marker to another sigil (e.g., `#inactive` or `~inactive`) to keep collision-free. Not worth churn. Document quoted form.
- **Labels:** `config`, `lexer`, `parity-gap`, `not-material`, `deliberate`
- **Dedup note:** Triaged in ps-035 NEW-01 as NOT-MATERIAL / DELIBERATE. `2c24ac842` and prior have no `@`. `8a2d4f365` added, `bd870991e` reverted. Not in `/tmp/all_findings.txt` as `@`-specific. ps-review-035 L-01. Not filing.

#### L-02 — `validateMultiValueLeaf` `"to"` separator — old overly-broad handling (FIXED in #4556) — CLOSED

- **Title:** `validateMultiValueLeaf` treated literal `"to"` as range separator on every typed multi leaf (F-043 class) — fixed by `rangeSeparator` gate
- **Severity:** Low
- **Confidence:** High
- **Class:** implementation-bug / robustness
- **Evidence:**
  ```go
  // schema.go:82-83
  rangeSeparator bool // only port-range / NAT-pool-address, compiler-validated, never reaches this walker in production
  // schema_walk.go:673-687
  if leafSchema.rangeSeparator && tok == "to" {
    if !validatedAny || lastWasSeparator { return "missing value" }
    lastWasSeparator = true
    continue
  }
  // Before #4556: was unconditional `if tok == "to" { skip }` on every leaf
  ```
- **Trace:** Before fix, `set system name-server 1.1.1.1 to 8.8.8.8` (typo'd `to`) → `validateMultiValueLeaf` would silently skip `"to"` as separator, accept `1.1.1.1` and `8.8.8.8` as two valid name-servers — no error, but operator typo hidden. After fix, `"to"` is validated as ordinary value, fails `ValidateIP` ("invalid value \"to\""), clear error. For port-range leaves (compiler-validated, not typed), `"to"` handling remains correct via `parseDNATPortList` / `appendPoolAddresses`.
- **Refutation attempted:** Verified `906b4deed` diff: added `rangeSeparator` field, gated `"to"` skip behind it, added `schema_walk_internal_test.go` with `TestWalker_MultiValueTail_NonRangeToNotFalseRejected` (RED-on-revert: non-range leaf must accept literal `"to"` as ordinary member when validator permits, not treat as separator). Production leaves (name-server, virtual-address, dns-server-address, session-log flags) never set `rangeSeparator`, so `"to"` is now ordinary value and rejected as invalid IP/enum — correct. Port-range / NAT-pool-address are compiler-validated, never reach this walker.
- **Why it matters:** Silent skip of `"to"` on IP/CIDR leaves hid operator typo, allowed `name-server 1.1.1.1 to 8.8.8.8` to commit as two servers (harmless but confusing). Worse, a literal hostname `"to"` (if allowed) would be silently dropped. Fix makes validation strict and clear.
- **Fix direction:** Already fixed in #4556 (906b4deed) — gate behind `rangeSeparator`, only synthetic test leaf sets it. No further action.
- **Labels:** `config`, `schema-walk`, `validation`, `fix-verified`
- **Dedup note:** F-043 in `/tmp/all_findings.txt` ("validateMultiValueLeaf treats the literal token 'to' as a range separator on EVERY typed multi leaf"). Fixed in #4556. ps-review-035 NEW-02. Not filing.

#### L-03 — `IsIdentRune` vs `isIdentChar` Unicode mismatch — completion suggests values lexer rejects — LOW parity

- **Title:** `IsIdentRune` (tab completion) allows `unicode.IsLetter` (Unicode), `isIdentChar` (lexer) only `a-zA-Z` — completion suggests Unicode identifier that fails to parse
- **Severity:** Low
- **Confidence:** Medium
- **Class:** parity-gap / robustness
- **Evidence:**
  ```go
  // lexer.go:289
  func isIdentChar(ch byte) bool { return (ch >= 'a' && ch <= 'z') || ... } // ASCII only
  // lexer.go:300
  func IsIdentRune(r rune) bool {
    return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || ... // Unicode letters!
  }
  ```
- **Trace:** User types `set system host-name café` (with `é`), tab completion (`IsIdentRune`) accepts `é` as part of identifier, suggests completion; on commit, lexer (`isIdentChar`) rejects `é` (byte `0xc3 0xa9`, not `a-z`), `TokenError`, parse fails. Minor UX inconsistency, not security.
- **Refutation attempted:** Checked `complete.go` uses `IsIdentRune` for tab completion boundary detection. Lexer is byte-oriented, only ASCII identifiers. Unicode hostnames are valid DNS? Possibly, but Junos host-names are LDH (letters, digits, hyphens) ASCII only. So mismatch is minor.
- **Why it matters:** Completion suggests value that then fails to commit — confusing, not fail-open.
- **Fix direction:** Align `isIdentChar` to allow UTF-8 or restrict `IsIdentRune` to ASCII `a-zA-Z`. Prefer restrict `IsIdentRune` to ASCII for Junos parity (LDH).
- **Labels:** `config`, `cli`, `parity-gap`, `low`
- **Dedup note:** Not in `/tmp/all_findings.txt`, not in GH issues, not in prior reviews. New, low priority, not filing as issue unless desired.

#### N-01 — navigatePath intermediate fix #4562 — display-only — negative (no fail-open)

- **Title:** `navigatePath` intermediate descent now unions all same-prefix / same-keyword siblings (was first-only) — display-only, no enforcement impact
- **Severity:** N/A (negative)
- **Confidence:** High
- **Class:** negative / display-only
- **Evidence:** `ast.go:224` `current = unionChildren(matched)` + `ast.go:269` `current = unionChildren(sibs)` + `show_config_dup_context_4562_test.go` 3 tests (multi-key, single-key, single-context unchanged).
- **Trace:** Hand-authored hierarchical `security { policies { from-zone untrust to-zone trust { policy A } from-zone untrust to-zone trust { policy B } } }` (two identical 4-key contexts) + `show configuration security policies from-zone untrust to-zone trust policy B` — before fix, `navigatePath` descended into only first context's children, missed B → scoped display-set backup dropped B on restore. After fix, unions both, shows A+B, `show | display set | load` round-trips correctly.
- **Refutation:** `grep -r navigatePath pkg/` → only `ast_format.go` callers (FormatPath, FormatPathSet, FormatJSON/XML, FormatInheritance, FormatCompare). Compiler never calls navigatePath — uses `findNode`, `findNodeWithParent`, `navigateToNode`. So hidden policy was still ENFORCED, only display dropped. No fail-open, no fail-closed.
- **Why it matters:** Display/backup gap, not security bypass. Fix verified, tests RED-on-revert.
- **Labels:** `config`, `ast`, `display-only`, `negative`
- **Dedup note:** #4562 CLOSED, ps-035 N-01. Not filing.

### Summary of negatives (fail-closed proofs)

- **Bracket-list (#2419):** Lexer O(1) loop + `valueList` + `SetPath` multi collapse + `DeletePath` member-delete — no truncation, no ECMP blackhole.
- **apply-groups:** Transitive + memo + cycle detection + wildcard `<*>` — no silent drop of group-contributed DENY, no exponential blowup.
- **inactive:** Leading + inline + quoted `"inactive:"` — no over-prune, no split-brain, `cloneForExpansion` single copy, no alias.
- **Lenient vs strict:** Only downgrades to warning, dataplane backstops fail-closed (host-mask, NPTv6, NAT64 prefix, etc.).
- **Bracket stripping O(1):** No stack overflow on `[[[[...` or `{{{...`.
- **Schema closedWorld:** No production flip, mechanism tested, no false-reject.
- **Deterministic NAT:** Parse accumulates, validation strict, mutual-exclusion with persistent-nat/address-persistent.
- **isIdentChar `@`:** Deliberate, documented, quoted workaround exists.
- **validateMultiValueLeaf `to`:** Fixed, production leaves now reject literal `"to"` as invalid IP, not silently skip.
- **navigatePath #4562:** Display-only, unionChildren correct, single-node fast-path returns original slice (read-only safe).

## 7. Suggested issue split

No new GH issues to file — all genuine findings are either already fixed (#4562, #4556 L-01) or deliberate/not-material (L-01 `@`, L-03 Unicode mismatch LOW). If desired:

- **LOW — `IsIdentRune` Unicode mismatch:** Align tab completion to ASCII (or document) — not security, QoL.
- **No new deterministic NAT issue** — already tracked as #4559 OPEN (advisory, needs dataplane allocator).

Fail-opens first: none in cohort 2 on 33b891d11.

---

**Coverage:** All cohort 2 files read 400+ lines, 14 prior reviews + 274 findings + 200+ GH issues deduped, 3 new commits on HEAD verified, 0 High/Med new, 2 Low fixed/deliberate, 1 Low new (Unicode, not filing), 1 negative (#4562).

