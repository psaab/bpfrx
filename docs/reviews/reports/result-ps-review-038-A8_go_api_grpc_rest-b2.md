# Triage result — ps-review-038-A8_go_api_grpc_rest-b2

- **Subsystem**: A8_go_api_grpc_rest (pkg/grpcapi — batch 2/2, 82 files: show/routing/sessions handlers + FRR vtysh boundary)
- **Review base**: d4506d4450 (declared) — **verified vs current origin/master 57d24d9aed4b64680831a1765a128921e79c00f7** (fetched this run)
- **Codebase**: real bpfrx (all cited symbols present and byte-identical to the review's excerpts on current master)
- **Outcome counts**: 3 findings → 2 GENUINE-RESIDUAL (1 LOW-MED, 1 LOW), 1 NOT-MATERIAL. 0 CONFABULATED, 0 DUP, 0 ALREADY-FIXED, 0 NEGATIVE-flips.

The reviewer's own NEGATIVE sections (server_sessions.go truncation guards, server_show.go dispatcher, zones/text renderers, secret redaction) were spot-checked at the boundary and hold; not re-litigated finding-by-finding since they assert clean.

---

## F-001 — vtysh command construction from unvalidated BGP neighbor IP (GetBGPStatus) — **GENUINE-RESIDUAL, LOW-MED** (reviewer said Medium)

**Symbol exists**: YES.
- `pkg/grpcapi/server_routing.go` (default arm of GetBGPStatus): `ip := strings.TrimPrefix(req.Type, "received-routes:")` → `s.frr.GetBGPNeighborReceivedRoutes(ip)`; identical for `advertised-routes:` and `neighbor:`. No `net.ParseIP` on any arm.
- `pkg/frr/vtysh.go` GetBGPNeighborReceivedRoutes/AdvertisedRoutes/Detail: guard is only `ip == ""`, then `Vtysh("show bgp neighbor " + ip + " received-routes")`.
- `realExecutor.Vtysh` = `exec.CommandContext(ctx, "vtysh", "-c", command)` — **no OS shell** (confirmed). Classic shell metachars ($(), ;, |, backtick) are inert.

**Reachable path**: The local gRPC listener binds 127.0.0.1:50051 with only `configLockInterceptor` — **no authentication** (verified: `server.go:238`; the `fabricAuthUnaryInterceptor`/`fabricAllowlistUnaryInterceptor` at `server.go:297`/`fabric_auth.go:250` are on the **cluster fabric listener only**, not the local one). Any local process can call `GetBGPStatus` with `req.Type = "received-routes:<arbitrary>"`. `ip` is raw and may contain spaces/newlines.

**Why it is real but LOW-MED, not Medium/High**:
1. **No OS shell** eliminates command-injection-into-shell. Impact is limited to what FRR's own vtysh parser will accept.
2. **The dangerous variant is newline chaining**, not the "vrf pivot": FRR `show bgp neighbor` syntax puts the `vrf NAME` qualifier *before* `neighbor`, so `show bgp neighbor 10.0.0.1 vrf default received-routes` is malformed → FRR rejects → error, not a cross-VRF leak (the review's headline "VRF pivot" is the weaker/likely-invalid vector). The material vector is `ip = "1.1.1.1\nconfigure terminal\nrouter bgp 65000\n..."` — **iff** `vtysh -c` splits its argument on embedded newlines and executes each line (FRR historically does; **not verifiable here — vtysh is not installed** — the reviewer also flagged this "not confirmed"). If it does, this is a bypass of the config-path sanitize belt.
3. **Blast-radius is strongly bounded by the same-channel config RPCs**: the *same* unauthenticated local channel already exposes `Commit`/`CommitConfirmed`/`SetConfig` (`server_config.go:186/227`). An attacker who can reach 127.0.0.1:50051 already has **total, root-level control of the firewall** (arbitrary config commit). A raw-vtysh injection therefore grants **no new trust-boundary crossing** — it is strictly a defense-in-depth gap on an already-total-compromise channel.
4. **Marginal capability over the config path**: config RPCs are sanitized (`sanitizeFRRValue` + `validateNodesControlChars`, #4097/#1798 — strip/reject control chars incl. newline). The vtysh show path is *not* sanitized, so it is the one FRR channel that lets raw newline-bearing FRR CLI through and leaves no commit-audit trail. That marginal delta (FRR-native commands xpf doesn't model + stealth) is the only genuine escalation, hence LOW-MED rather than LOW.

**Dedup**: NOVEL. No existing issue for operational-vtysh neighbor-IP validation (`git log --grep` only returns unrelated c4012535e "gate group AF by neighbor IP version"). The config-path FRR sanitize belt (#4482/#4481/#4498/#4097) covers commit/frr.conf render, NOT `GetBGPNeighbor*`. Not in the #4517-#4581 CLI/API-hardening range. Consistent with the session's CLI/API-hardening posture (harden localhost-bounded input boundaries anyway).

**Fix (lane=go)**: add `if net.ParseIP(ip) == nil { return "", fmt.Errorf("invalid neighbor IP %q", ip) }` at the three `pkg/frr/vtysh.go` BGP wrappers (and mirror for any Detail method taking an IP); optionally return `codes.InvalidArgument` from `server_routing.go`. Trivial, matches the project's boundary-validation pattern.

---

## F-002 — showTestRouting silently drops malformed/unknown selector keys (parity gap vs #3696 showTestPolicy) — **GENUINE-RESIDUAL, LOW**

**Symbol exists**: YES — `pkg/grpcapi/server_show_routes_text.go` `showTestRouting`: the `for _, kv := range strings.Split(params, ",")` loop has `if len(parts) != 2 { continue }` and a `switch parts[0]` with cases `dest`/`instance` and **no default arm** → unknown keys silently dropped. Byte-identical to the review excerpt on current master.

**Reachable path**: operator-driven diagnostic. `req.Topic = "test-routing:dest=10.0.0.0/24,instnace=dmz"` (typo `instnace`) → `instance` stays `""` → falls into `GetRoutes()` (main table) instead of `GetVRFRoutes("dmz")` → returns a **main-table result for a VRF query with no warning**. A bare typo `destinat=...` → `dest` stays `""` → "Missing dest parameter" with no hint.

**Why LOW (not higher)**: no security bypass — the "attacker" is the operator's own typo. Impact is a **misleading diagnostic** (wrong routing table shown silently) during troubleshooting. Valid inputs work correctly; only malformed/typo'd selectors misbehave. It is a real parity gap: the sibling `showTestPolicy` was hardened in #3696 (tracks parseErr/seen/unknown-key, reports before evaluating) and this sibling was not.

**Dedup**: NOVEL. #3696 fix is documented for `showTestPolicy` only; no dedup entry covers `showTestRouting`. Not in the #4517-#4581 range.

**Fix (lane=go)**: mirror the #3696 pattern — track a `parseErr` on `len(parts)!=2 || empty part` and on unknown `parts[0]` (default arm), report and return before the lookup.

---

## F-003 — showRoutePrefix LastIndex modifier extraction "fragile" — **NOT-MATERIAL** (reviewer self-refutes)

**Symbol exists**: YES — `pkg/grpcapi/server_show_routes_text.go` `showRoutePrefix` uses `strings.LastIndex(prefixAndMod, " ")` + a `switch candidate {case "exact"/"longer"/"orlonger"}` to peel a trailing modifier.

**Disposition**: NOT-MATERIAL, and the reviewer's own refutation establishes this: for the only "edge" input (`route-prefix:10.0.0.0/ 8`, space inside the CIDR) the trailing token `"8"` is not in the modifier switch, so `prefix` stays the malformed `"10.0.0.0/ 8"` → `FormatRouteDestination` fails CIDR parse → **empty result, never a wrong route**. Confidence Low, "no security impact," reviewer explicitly says "Close as informational." All well-formed inputs (v4/v6 CIDR, with/without modifier) parse correctly. There is no crafted input that yields a wrong or unsafe result — fail-safe by construction. Not a genuine residual.

**Dedup**: n/a (no bug to dedup).

---

## Genuine residuals (novel, reachable, not dup/fixed)

- **F-001** (LOW-MED, go): unvalidated BGP neighbor IP concatenated into root-executed `vtysh -c` in `pkg/frr/vtysh.go` GetBGPNeighborReceivedRoutes/AdvertisedRoutes/Detail, fed from `server_routing.go` GetBGPStatus default arm — reachable from the unauthenticated localhost gRPC channel; bypasses the config-path sanitize belt. Bounded because the same channel already exposes `Commit`. Fix: `net.ParseIP` guard at the three vtysh wrappers.
- **F-002** (LOW, go): `showTestRouting` in `pkg/grpcapi/server_show_routes_text.go` silently drops unknown/malformed selector keys (no default arm), so a typo'd `instance=` silently returns the main routing table instead of the VRF — parity gap vs #3696-hardened `showTestPolicy`. Fix: mirror the #3696 parseErr/unknown-key reporting.
