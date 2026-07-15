# Triage Result — ps-review-038-A3_go_config_cli_tree-b2

- **Subsystem:** A3_go_config_cli_tree (batch 2/3, 150 files, all under `pkg/config/`)
- **Review base:** `d4506d4450e23f9a3fc572206b3c82f6b6c99029`
- **Triaged against master SHA:** `57d24d9aed4b64680831a1765a128921e79c00f7` (origin/master, fetched)
- **Real bpfrx or avacado:** Real bpfrx symbols. Review cites `/home/ps/git/avacado-xpf/pkg/config/...` paths, but every cited symbol
  (`compiler_protocols.go` peer-as/local-as, `firewall_filter_expand.go:FilterTermExpansionCount`,
  `compiler_security_policy.go` global from-zone/to-zone) exists byte-for-byte in bpfrx on master. Audit ran on an avacado
  checkout; findings map to genuine bpfrx code. NOT confabulated.
- **Outcome counts:** 3 findings → 1 GENUINE-RESIDUAL (Low), 1 NOT-MATERIAL, 1 ALREADY-FIXED. Plus ~20 module CLEAN negatives (no action).

---

## F-01 — BGP ASN negative/overflow truncation via `Atoi → uint32` — **GENUINE-RESIDUAL (Low)**

**Symbol exists:** Yes.
- `pkg/config/compiler_protocols.go:214` `proto.BGP.LocalAS = uint32(v)` (top-level local-as, `Atoi(child.Keys[1])`).
- `:307` group `peer-as` → `peerAS = uint32(n)`; `:314` group `local-as` → `groupLocalAS = uint32(n)`.
- `:467` neighbor `peer-as` → `neighbor.PeerAS = uint32(n)`; `:473` neighbor `local-as` → `neighbor.LocalAS = uint32(n)`.
All use `strconv.Atoi` with no negative/overflow guard before the `uint32` cast.

**Reachable-path verification (weight-verify):** I traced every upstream gate that could neutralize this and found a real,
verifiable **asymmetry** gap — the codebase clearly *intended* to range-validate ASN but covered only `local-as`, not `peer-as`:

- **Schema layer** (`pkg/config/schema_routing.go`, the strict commit-time validator):
  - `:318` top-level `local-as` → `{args:1, placeholder}` — **NO valueType, NO validator**.
  - `:336` group `peer-as` → `{args:1, placeholder}` — **NO validator**.
  - `:337` group `local-as` → `valueType: ValueInteger, validator: ValidateInteger(1, 4294967295)` — **validated**.
  - `:371` neighbor `peer-as` → `{args:1, placeholder}` — **NO validator**.
  - `:372` neighbor `local-as` → `ValidateInteger(1, 4294967295)` — **validated**.
  So `peer-as` (group + neighbor) and top-level `local-as` accept any single token; `ValidateInteger` (which would reject
  anything `< 1`, i.e. negative or 0) is applied ONLY to the `local-as` variants.
- **Compiler strict gate** (`compiler_validate_strict_routing.go:449 validateBGPNeighborPeerASStrict`, wired at
  `compiler_uniformgates.go:1170`): rejects **only** `n.PeerAS == 0` (RFC 7607 AS0). It does NOT range-check — the header
  comment explicitly says "only 0 is rejected here." An out-of-range input that wraps to any non-zero value passes.

**Crafted input / scenario:**
- `set protocols bgp group ext neighbor 1.2.3.4 peer-as 4294967297` → `Atoi("4294967297")` = `4294967297` (64-bit int, no
  error) → `uint32(4294967297)` = **1** → passes `PeerAS != 0` → FRR renderer emits `neighbor 1.2.3.4 remote-as 1`.
  The operator's intended-but-typoed ASN silently miscompiles to a *different valid ASN*.
- `... peer-as -1` → `Atoi("-1")` = -1 → `uint32(-1)` = **4294967295** → passes `!= 0` → `remote-as 4294967295`.
Junos rejects both at commit (ASN range check); xpf accepts and renders a wrong-but-valid FRR config.

**Severity reasoning — why Low (not higher, not INFO):**
- Not higher: no security bypass, no crash, no fail-open of a security policy. The blast radius is one BGP session's config;
  the wrapped value is a *valid* 4-byte ASN so FRR accepts it and the session simply fails to establish against the real peer
  (ASN mismatch in OPEN) — a self-evident, operator-visible failure, not a silent forwarding compromise.
- Not INFO/NOT-MATERIAL: it is genuinely reachable on the **commit (strict) path** — `peer-as` has no schema validator at all,
  so the truncation is not gated by any upstream guard. It is a real silent miscompile of an operator-typed value that Junos
  would reject, and the fix target is an obvious asymmetry (the sibling `local-as` leaves already carry the exact validator).

**Dedup:** Novel. Not covered by the #4517-#4581 backlog (which includes heartbeat uint32 #4572/#4434, icmp_embed #4533,
dhcp leaseTime #4526, ra max-adv #4525, nptv6 host-bits #4519, vrrp hop-limit #4548, etc.) nor the open set
(#2387/#4455/#4478/#4498/#4549/#4555/#4559/#4565/#4566/#4569/#4573/#4576/#4577/#4578/#4579). None touch BGP ASN validation.
`bgp_neighbor_peeras_2963_test.go` / #2963 covers only the `PeerAS == 0` reject, which is the very gate that lets the
wrapped-non-zero value through.

**Fix (lane: go):** Add `valueType: ValueInteger, validator: ValidateInteger(1, 4294967295)` to the two `peer-as` leaves
(`schema_routing.go:336` group, `:371` neighbor) and to top-level `local-as` (`:318`) — mirroring the `local-as` group/neighbor
leaves. Optionally belt-and-braces the compiler sites to use `strconv.ParseUint(v, 10, 32)` instead of `Atoi`+`uint32()`.

---

## F-02 — `FilterTermExpansionCount` uint32 truncation — **NOT-MATERIAL**

**Symbol exists:** Yes — `pkg/config/firewall_filter_expand.go:52` `return uint32(nSrc * nDst * nDstPorts * nSrcPorts)`.

**Why NOT-MATERIAL (unreachable before resource exhaustion):**
- To truncate, the product of the four `len()` factors must exceed `uint32` max (4,294,967,295). The reader/expander pair
  (`pkg/dataplane.expandFilterTerm`, pinned equal by `TestFilterTermExpansionCountMatchesExpand`) *materializes* a slice of
  `FirewallFilterRule` with length == that product. Reaching >4.29e9 rules requires hundreds of GB of allocation — the process
  OOMs long before any truncation is observable. The review itself concedes "would OOM before truncation in practice."
- The intermediate product is computed in Go `int`, which is **64-bit on every supported xpf platform** (amd64/arm64 Linux —
  the AF_XDP/XDP dataplane is 64-bit-only). The review's "32-bit int overflow" caveat does not apply; there is no int overflow,
  only the final `uint32` cast, which is exact for every value below 4.29e9.
- Below 4.29e9 the cast is lossless, so there is no sub-threshold counter-drift risk either.

Not a residual: the only failure mode is an unreachable-in-practice OOM, not a correctness bug on any realizable config.

**Dedup:** N/A (no material finding). #3459 (counter-slot stride SSOT) is the *reason* the function exists, not a truncation bug.

---

## F-03 — Global policy `match from-zone`/`to-zone` bracket-list silently drops zones — **ALREADY-FIXED (#4415)**

**Symbol exists:** Yes — `pkg/config/compiler_security_policy.go:240-256` reads only `m.Keys[1]` (single value) for global
`from-zone`/`to-zone`.

**Why ALREADY-FIXED (the F-03 miscompile cannot reach the compiler):**
- `pkg/config/schema_security.go:292-293` tag the global-policy match leaves with **`scalar: true`**:
  ```
  "from-zone": {desc:..., args:1, scalar:true, valueHint:ValueHintZoneName, ...}
  "to-zone":   {desc:..., args:1, scalar:true, valueHint:ValueHintZoneName, ...}
  ```
  The `scalar` fixed-arity gate (`schema.go:isScalarValueLeaf` / `schema_walk.go:522 validateScalarValueLeaf`, #3332)
  hard-rejects any trailing tokens at commit. A bracket-list collapses (#2419 lexer) to `Keys=["from-zone","trust","untrust"]`
  — `untrust` is a trailing token → **commit rejected**, so the single-value compiler read at `:247/:254` never silently drops
  a second zone; it only ever sees a validated single zone.
- This is exactly finding #4415-L12, fixed and pinned by `pkg/config/schema_global_zone_list_4415_test.go`: cases
  "from-zone list rejected" (`match from-zone [ trust dmz ]`) and "to-zone list rejected" assert rejection; "single from-zone
  accepted" asserts the scalar path. The test header documents the pre-fix bug as *exactly* F-03's scenario ("the compiler kept
  only 'a' and SILENTLY [dropped the rest]... a security-relevant miscompile") and the fix ("Tagging the leaves `scalar: true`").

The compiler's single-value read is correct-by-contract for a scalar-validated leaf. F-03's premise (bracket-list reaching the
compiler and dropping zones) was closed by #4415 before this review's base — the `scalar:true` markers are present on master.

---

## Negative-result modules (batch CLEAN claims spot-checked, no residual)

The review's ~20 CLEAN module writeups (compiler_prewalk/security/*/system/services, host_inbound_*, natpool, dup_host_local,
event_options_*, freetext, inactive/lexer/parser/lifeline, filter_match_resolve) are consistent with master; the two
supporting audit tables (integer-truncation, Keys OOB) correctly mark `filter_match_resolve.go` port casts SAFE
(range-checked before `uint16`) and the WG listen-port/keepalive casts SAFE (bounds-guarded). No additional residual surfaced
in the negatives that the three findings didn't already cover.

---

### Disposition summary
3 findings: 1 GENUINE-RESIDUAL (F-01, Low, go) · 1 NOT-MATERIAL (F-02, uint32 truncation OOM-first/64-bit-int) · 1 ALREADY-FIXED (F-03, #4415 `scalar:true`).
