# Triage Result — ps-review-038-A6_go_dataplane_manager-b1

**Subsystem:** A6_go_dataplane_manager (batch 1/2) — `pkg/dataplane/*.go` legacy
compiler + map accessors + `pkg/dataplane/userspace/*.go` userspace manager/HA/sync.

**Review base:** d4506d4450e23f9a3fc572206b3c82f6b6c99029
**Current origin/master:** 57d24d9aed4b64680831a1765a128921e79c00f7 (fetched)
**Base == master:** effectively — cited symbols still present at cited line
numbers on current master (no drift affecting these findings).
**Real bpfrx or avacado:** REAL bpfrx. The review cites
`/home/ps/git/avacado-xpf/...` paths (a mirror checkout name), but every cited
symbol verifies in bpfrx at the same line numbers (compiler_nat.go:493 shift,
types.go:610/620 uint16 CounterID, eventstream.go:801 decodeSessionEvent). Not
an avacado confabulation.

**Outcome counts:** 0 GENUINE-RESIDUAL · 0 DUP · 0 ALREADY-FIXED ·
2 NOT-MATERIAL (F-001, F-002) · 2 NEGATIVE (F-003, F-004, self-reclassified by
the reviewer) · 0 CONFABULATED-symbol.

---

## F-001 — Deterministic NAT /0 host-prefix `HostCount = uint32(1)<<32 = 0` — NOT-MATERIAL

**Review severity:** Medium/High-confidence. **Disposition:** NOT-MATERIAL
(dead-code arithmetic; runtime impact refuted; claimed exploit path
confabulated; subsumed by OPEN #4559).

**Symbol exists — YES.** `pkg/dataplane/compiler_nat.go:493`:
`hostCount := uint32(1) << uint(bits-ones)`. For an IPv4 `/0` host-address
(`net.ParseCIDR("0.0.0.0/0").Mask.Size()` → `ones=0, bits=32`), the else branch
(bits != 128) computes `1 << 32`. Go shift-≥-width semantics yield 0. The
arithmetic quirk is real in isolation.

**Why NOT-MATERIAL — the runtime impact is refuted at three layers:**

1. **The computed value is written through a no-op DataPlane.** `compileNAT`
   runs on the live path only via `Manager.CompileUserspaceShim`
   (`pkg/dataplane/loader.go:169`), which passes `compilerDP :=
   userspaceShimCompileDataplane{...}`. That type's `SetNATPoolConfig`
   (`pkg/dataplane/loader.go:374-376`) is `{ return nil }` — a pure no-op. So
   `poolCfg.HostCount = 0` at compiler_nat.go:496 is written via
   `dp.SetNATPoolConfig(...)` (lines 411/524) into a discarded struct. It never
   reaches the live dataplane. This is the exact "userspace runtime writes this
   struct through a no-op DataPlane" contract the file's own comments cite.

2. **There is no live consumer of HostCount.** The review's Trace step 5 asserts
   the Rust helper `PortAllocator::allocate_deterministic` computes
   `hash(subscriber_ip) % host_count` → division-by-zero panic. That symbol does
   NOT exist: `grep -rn 'deterministic|host_count|allocate_deterministic|% host'
   userspace-dp/src/nat/` returns only unrelated "deterministic ordering / sticky
   index" comments — zero CGNAT block-allocation logic. The claimed panic path is
   **confabulated** (the review even admits "no Rust source in this batch" and
   speculates). No panic, no CGNAT outage.

3. **The whole deterministic-NAT feature is already tracked as inert.** OPEN
   issue **#4559** ("nat: deterministic NAT (CGNAT port block-size)
   validated+committed but silently unenforced on userspace dataplane") states
   verbatim: compiler_nat.go:473-496 is "BPF-compiled ... DEAD (retired plane)"
   and deterministic allocation is "ABSENT from `nat_source.go` (0 refs) and
   `userspace-dp/src/nat/*` (0 CGNAT/block-size logic)." A `/0` config commits
   clean and, like every deterministic config, falls back to round-robin/sticky
   SNAT — it does NOT panic or drop.

**Relationship to #4559:** F-001 is a sub-consideration of #4559, not a distinct
reachable bug. The review argues "distinct root cause" (arithmetic vs feature
gap), but the *consequence* it claims (runtime panic/CGNAT outage) exists only
in the hypothetical world where deterministic allocation IS implemented — which
is exactly the #4559 work. When #4559 is implemented, the /0 (and /31, /32) host
counts must be handled; that guard belongs to that feature PR. Standalone on
current master the line produces an unconsumed 0. **Not filed separately** —
folds into #4559's implementation checklist.

**Why not a Low residual either:** a Low residual still needs a reachable
consequence on the live path. Here the value is discarded at the no-op DataPlane
boundary and has no live reader, so there is no observable behavior to fix
outside of the #4559 feature work.

---

## F-002 — Legacy `SNATValue.CounterID` uint16 narrows uint32 FNV hash — NOT-MATERIAL / DELIBERATE-vestigial

**Review severity:** Low/High-confidence (self-acknowledged vestigial).
**Disposition:** NOT-MATERIAL (documented vestigial field, no live-path impact).

**Symbol exists — YES.** `pkg/dataplane/types.go:610` (`SNATValue.CounterID
uint16`) and `:620` (`SNATValueV6.CounterID uint16`); `natCounterIDForKey`
returns `uint32` (`compiler_nat.go:84`); casts `uint16(counterID)` at
compiler_nat.go:247, 266, 604, 632. Low-16-bit FNV collision → shared legacy
counter slot is arithmetically real.

**Why NOT-MATERIAL:**
- These `SNATValue` structs are written ONLY through the same no-op
  `userspaceShimCompileDataplane` (loader.go SetSNATRule family return nil). The
  live userspace path attributes NAT hits via the u32 `NATCounterIDs`
  snapshot map (types.go:171 `CounterID uint32`), never the uint16 legacy field.
  The code comment at the cast sites documents this exactly (#2255: "reads hits
  via the snapshot's u32 counter id instead").
- The legacy eBPF datapath that would consume `SNATValue.CounterID` is retired
  (#1373/#1476) and hard-rejected at commit and runtime. No production node runs
  it.
- Worst self-stated impact is "flaky counter unit tests" on a ~1/65536-per-pair
  collision — a test-fidelity nit, not a runtime enforcement or security issue.

The reviewer already downgraded to Low and offered "document as vestigial" as an
acceptable remedy — i.e. the finding is effectively a DELIBERATE, already-
documented truncation. Not a genuine residual.

---

## F-003 — eventstream `decodeSessionEvent` AF check ordering — NEGATIVE (self-reclassified)

The reviewer opened this then reclassified to NEGATIVE mid-finding after
re-reading the code. Confirmed: `decodeSessionEvent`
(`pkg/dataplane/userspace/eventstream.go:801`) rejects unknown AF in the
`default:` branch of the `switch af` BEFORE any address-size-dependent length
math; `wireAFToDataplane` (eventstream.go:791) is a redundant defense-in-depth
re-check that maps only 4→2 / 6→10. No bug. NEGATIVE, agreed.

---

## F-004 — builder nil-cfg snapshot — NEGATIVE (self-reclassified)

Reviewer reclassified to NEGATIVE. The `cfg == nil` early-boot/test path returns
a minimal snapshot (no zones/policies) — safe, no enforcement impact. NEGATIVE,
agreed.

---

## Adjacent observation (NOT a review finding, not filed)

The same deterministic block at `compiler_nat.go:479` does
`portRange / pool.Deterministic.BlockSize` with no visible zero-guard on
`BlockSize`. If `BlockSize == 0` reaches this line, Go integer div-by-zero
panics — and unlike HostCount, this executes on the compile path itself (before
the no-op write), so it would be live IF BlockSize could be 0 at apply time. The
review did not raise this, and it is out of scope for this batch's triage;
flagged here only so it is not lost. A confirming check of the commit-time
BlockSize>0 validator (`pkg/config/compiler_validate_strict_nat.go`) is the
follow-up if anyone wants to chase it — but it belongs to the #4559 feature
surface, same as F-001.

---

## Dispositions summary

| ID | Review sev | Disposition | Why |
|---|---|---|---|
| F-001 | Medium | NOT-MATERIAL | HostCount=0 written via no-op DataPlane (loader.go:374); no live Rust consumer (claimed `allocate_deterministic` panic confabulated); whole feature inert per OPEN #4559 |
| F-002 | Low | NOT-MATERIAL / vestigial | uint16 legacy field written via no-op DP; live path uses u32 NATCounterIDs; documented #2255; eBPF retired |
| F-003 | Low | NEGATIVE | Self-reclassified; AF rejected before length math |
| F-004 | N/A | NEGATIVE | Self-reclassified; nil-cfg path correct |

**Genuine residuals: 0.** This is the #4572/A2 pattern the prompt flags — a
headline exploit (Rust `% host_count` panic) already neutralized upstream by the
no-op DataPlane boundary + the absent deterministic allocator. Both substantive
findings land in dead/vestigial legacy-compiler code whose output the live
userspace-dp never reads.
