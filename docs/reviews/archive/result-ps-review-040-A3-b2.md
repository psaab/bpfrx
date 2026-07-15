# Triage Result — ps-review-040-A3-b2

- **Subsystem**: `pkg/config` control-plane configuration compiler (Area A3, batch 2 — routing-options, services/sampling, security/policy/zones, strict validators, firewall-filter, host-inbound, event-options, DHCP, IPsec, lexer). Config-compile lane (Go).
- **Base == current master?**: Yes. Triaged against `origin/master` @ **95b33d49634d56086269a62a92e213dae7926f88** (fetched at triage time).
- **Repo cited by review**: paths are `/home/ps/git/gemini-xpf/pkg/config/...` — the **gemini-xpf fork** checkout, NOT bpfrx and NOT avacado-xpf. Both cited symbols nonetheless EXIST on bpfrx `origin/master` (`compiler_routing.go:47`, `compiler_services.go:1382`), so the review maps onto real code; the fork path is just the reviewer's working tree.
- **File present at triage**: Yes (47780 bytes).
- **Outcome counts**: 2 findings + 130 negative-result entries. **0 GENUINE-RESIDUAL**, 1 NOT-MATERIAL (dead code), 1 ALREADY-FIXED/NOT-MATERIAL (#1977 + downstream gates). Negative-result section requires no action.

---

## Finding 1 — "Structural Dead Loop in Rib-Group Compiler" (Low / Medium) → **NOT-MATERIAL (accurate but harmless dead code)**

**Symbol exists**: Yes. `pkg/config/compiler_routing.go:47`:
```go
for _, inst := range namedInstances(rgNode.FindChildren("")) {
```

**Analysis is factually correct, but the defect class is cosmetic, not correctness.**
`FindChildren` (ast.go:114) appends only children where `child.Keys[0] == name`. Named
rib-group nodes always have a non-empty first key (the group name, e.g. `Keys=["dmz-leak"]`),
so `FindChildren("")` can never match — it returns `nil`. `namedInstances(nil)`
(compiler_protocols.go:916) returns an empty slice, so the first loop (lines 47-63) never
executes a body. Confirmed the second loop (lines 64-82, `for _, child := range rgNode.Children`)
processes every named rib-group directly via `child.Name()` and populates `ro.RibGroups`.

**Why NOT-MATERIAL (not GENUINE-RESIDUAL):**
- The review's own Trace step 5 concedes "The compiler successfully compiles the config only
  because it falls back to the second loop." There is **no wrong output** — rib-groups compile
  correctly (validated by `compiler_ribgroup_ref_2226_test.go`, present in the batch).
- A dead loop that produces identical results whether present or removed is a maintainability
  nit, not a reachable defect. It cannot mis-compile, crash, or fail-open.
- Severity: the review's own Low/Medium confidence is appropriate; this does not rise to a
  filed defect. If touched, the trivial cleanup is to delete lines 47-63 (the second loop
  already covers all cases) — pure code hygiene, no behavior change.

Not a genuine residual.

---

## Finding 2 — "Missing bounds/negative validation on Traffic Sampling Input Rate" (Medium / High) → **ALREADY-FIXED / NOT-MATERIAL (#1977 + downstream gates)**

**Symbol exists**: Yes. `pkg/config/compiler_services.go:1382` in `compileSampling`:
```go
if prop.Name() == "rate" {
    if v := nodeVal(prop); v != "" {
        if n, err := strconv.Atoi(v); err == nil {
            inst.InputRate = n   // no bounds check here — TRUE
        }
    }
}
```
It is TRUE that `compileSampling` assigns the parsed int without range validation (unlike
`compilePortMirroring`, which rejects negatives at compiler_services.go:1329-1333). But the
review's **materiality claim is refuted**: "the negative input rate can lead to integer
overflow/underflow or division-by-zero issues in the packet sampling hot path" does NOT hold
on current master. Every downstream consumer of `InputRate` already defends against negative /
zero / huge values:

1. **Rust dataplane wire path** — the claimed hot path — is hardened by **#1977**.
   `buildFlowExportSnapshot` (`pkg/dataplane/userspace/flow.go:210-220`):
   ```go
   rate := inst.InputRate
   if rate <= 0 { rate = 1 }                     // negative AND zero coerced to 1
   if int64(rate) > math.MaxUint32 {             // huge capped
       ... rate = math.MaxUint32
   }
   ```
   `SamplingRate` is a Rust u32; the `<=0 → 1` clamp defeats both the uint32-wrap and the
   div-by-zero the finding posits, BEFORE it ever crosses the wire. Regression-locked by
   `TestBuildFlowExportSnapshotCoercesOutOfRange_1977` (`flow_wire_coerce_test.go`), which
   feeds `InputRate: math.MaxInt64` and asserts it caps to u32 max.

2. **Go flowexport sampling decision** (`pkg/flowexport/manager.go:620-622`,
   `ExportConfig.ShouldExport`):
   ```go
   if ec.SamplingRate > 1 {
       n := ec.counter().Add(1)
       return n % uint64(ec.SamplingRate) == 0
   }
   ```
   The modulo (only place a division occurs) is gated behind `SamplingRate > 1`. A rate of
   0, 1, or negative never reaches `% uint64(rate)`, so no div-by-zero and no signed→uint64
   wrap is exercised. Same `> 1` gate on the IPFIX path (`ipfix.go:791`).

3. **Port-mirroring wire path** (a separate InputRate consumer) also drops negatives:
   `pkg/dataplane/userspace/mirrors.go:55` (`if inst.InputRate < 0 { ...drop... }`), and the
   port-mirror compile path already hard-rejects negatives at commit (compiler_services.go:1330-1333).

**Why NOT a genuine residual:**
- The specific harm asserted (uint32 wrap / div-by-zero in the dataplane sampling hot path) is
  provably prevented by the #1977 clamp at the wire boundary and the `> 1` gate in the Go
  exporter. The refutation-attempt in the review ("no such validator exists; the invalid value
  propagates directly to the compiled config") only checked `compiler_services.go` and
  `compiler_validate_strict_observability.go`; it did not follow `InputRate` to its consumers,
  where the defense actually lives (fail-safe-at-consumption, the project's stated posture).
- Adding a compile-time reject in `compileSampling` for parity with port-mirroring would be
  pure defense-in-depth (a cosmetic parity nicety), not a fix for any reachable wrong output.
  Bounded at INFO at most; not a filable defect.

Already-fixed / not-material.

---

## Part 2 (negative results, entries 1-130)

130 negative-result entries (with duplicate numbering 86-130 repeated — a formatting artifact
in the review, not a code issue). These assert clean review of the remaining batch files; they
carry no findings and require no triage action. Spot-checked symbols referenced (e.g.
`validateSamplingInstanceConflictsStrict`, `FilterTermExpansionCount`, `WithoutInactive`) exist
on master; nothing here contradicts the two findings above.

---

## Disposition summary
2 findings: 0 GENUINE-RESIDUAL, 1 NOT-MATERIAL (F1 harmless dead loop — correct observation,
no wrong output), 1 ALREADY-FIXED/NOT-MATERIAL (F2 sampling rate fully defended downstream via
#1977 `rate<=0→1` + u32 cap and the flowexport `>1` modulo gate; div-by-zero/wrap claim
refuted). Consistent with the ps-039/040 expectation that this heavily-hardened config lane
yields ~0 residuals.
