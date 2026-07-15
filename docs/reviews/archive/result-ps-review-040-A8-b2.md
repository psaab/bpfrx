# Triage Result — ps-review-040-A8-b2

- **Subsystem**: gRPC control-plane surface (`pkg/grpcapi`) — config/status/session/NAT/cluster RPCs
- **Base == master?**: Yes. Triaged against **origin/master @ `95b33d49634d56086269a62a92e213dae7926f88`** (fetched at triage time). NOTE: local HEAD `0160fbfb9` is BEHIND origin/master; the working tree still has the pre-#4658 monolithic `server_diag.go`. Every cited symbol was read via `git show origin/master:` so this triage reflects true master (post-#4658 `server_diag_system_action.go` split, post-#4588 vtysh hardening).
- **Repo**: real `psaab/xpf` (bpfrx) — not the avacado fork.
- **Outcome counts**: 6 findings → **1 GENUINE-RESIDUAL (LOW)**, **1 ALREADY-FIXED**, **4 NOT-MATERIAL**.

---

## Finding 1 — Unbounded alloc/sort in `showSessionsTop` (rated High) → NOT-MATERIAL

**Symbol exists?** Yes. `pkg/grpcapi/server_show_flow.go` `showSessionsTop` builds `var entries []topEntry`, appends one struct (5 formatted strings) per non-reverse session across `IterateSessions` + `IterateSessionsV6`, then `sort.Slice` over all of them, truncating to 20. Confirmed on origin/master.

**Why NOT-MATERIAL (not High):**
- This is an operator-invoked diagnostic `show ... sessions-top` on the loopback gRPC listener (`127.0.0.1:50051`), an authenticated/trusted control-plane path. It is self-inflicted latency, not an untrusted-reachable DoS. Even over the fabric listener the caller is a PSK-authenticated (#4107) trusted cluster peer.
- The O(N) materialize-then-sort pattern is the SAME pattern the entire `show`/`GetSessions` family already uses to walk the session table; `showSessionsTop` is not an outlier that introduces a new hazard.
- The min-heap suggestion is a legitimate micro-optimization, but the finding describes no wrong output and no untrusted trigger — it is a perf nicety, not a defect. Severity High is unjustified; this does not rise to a filed bug.

---

## Finding 2 — DHCP delegated prefixes hidden when IA_NA leases empty (rated Medium) → NOT-MATERIAL (premise false)

**Symbol exists?** Yes. `pkg/grpcapi/server_dhcp.go` guard `if !attached && len(resp.Leases) > 0` at line 59. Confirmed.

**Why NOT-MATERIAL / not reproducible on master:**
- The finding's premise ("if the Kea server has zero IA_NA leases, `resp.Leases` remains empty") is wrong on two counts.
  1. **Wrong data source**: `GetDHCPLeases` reads `s.dhcp` — the embedded DHCPv6 **client** Manager (`pkg/dhcp`), NOT the Kea DHCP **server** (`pkg/dhcpserver`). `Leases()`/`DelegatedPrefixes()` are the appliance's own acquired leases/PDs.
  2. **The client always stores a lease record, even PD-only.** In the acquisition path (`pkg/dhcp/dhcp.go` ~L1478) a `Lease{Interface, Family: AFInet6, ...}` is created even when no IA_NA address is present (PD-only branch sets `LeaseTime` from the first prefix). `commitLease` (`pkg/dhcp/commit.go` L121) writes `m.leases[key] = lease` **unconditionally** (the `Address.IsValid()` guard only skips the kernel-address apply, not the map store).
- **Paired-delete invariant**: every v6 deletion of `m.leases` is paired with `delete(m.delegatedPDs, iface)` (dhcp.go L400/L1191/L1228). The only unpaired `delete(m.leases)` sites (L765/L806/L867 `abandonLeaseAfterNAK`) are DHCPv4-only paths (no PDs). Therefore `Leases()` is NEVER empty while `DelegatedPrefixes()` is non-empty.
- **Net effect**: for a PD-only client the lease record (Family AFInet6 == 6 → "inet6", matching Interface) is in `resp.Leases`; the attach loop finds it (`lease.Family == "inet6" && lease.Interface == dp.Interface`) and sets `attached = true`, so the PD IS displayed. The `!attached && len(resp.Leases) > 0` branch is not the sole display path, and the "zero leases + present PD" state does not arise.
- Removing the guard (the proposed fix) would be harmless but fixes nothing reachable. Not material.

---

## Finding 3 — Vtysh command injection via BGP neighbor IP (rated Medium) → ALREADY-FIXED (#4588)

**Symbol exists?** Yes, but the review quotes the PRE-fix code.

**Why ALREADY-FIXED:**
- `pkg/grpcapi/server_routing.go` (default case) now validates at the trust boundary: `received-routes:` and `advertised-routes:` and `neighbor:` all do `if net.ParseIP(ip) == nil { return InvalidArgument }` BEFORE calling the frr wrapper. Comment explicitly cites #4588 and notes the unauthenticated-loopback rationale.
- `pkg/frr/vtysh.go` adds the load-bearing belt: `GetBGPNeighborReceivedRoutes`/`GetBGPNeighborAdvertisedRoutes`/`GetBGPNeighborDetail` each `if net.ParseIP(ip) == nil { return err }` before concatenating into `vtysh -c`. `net.ParseIP` rejects newlines, spaces, and empty — killing the `1.1.1.1\nconfigure terminal\n...` injection the finding describes.
- Both the handler and the wrapper were hardened in the #4517-#4685 range (#4588). The review is stale-base.

---

## Finding 4 — O(N) `netlink.LinkByIndex` loop in arp/ipv6-neighbors (rated Medium) → NOT-MATERIAL

**Symbol exists?** Yes. `pkg/grpcapi/server_show_status.go` arp/ipv6-neighbors cases call `netlink.LinkByIndex(n.LinkIndex)` per neighbor, and `writeNeighSummary` (`server_helpers.go` L342) does the same. Confirmed on origin/master.

**Why NOT-MATERIAL (not Medium):**
- Operator-invoked diagnostic (`show arp`, `show ipv6 neighbors`) on the trusted loopback listener. Not untrusted-reachable.
- The neighbor table is naturally bounded by the kernel neighbor GC (`gc_thresh3`, default ~1024); `LinkByIndex` is a lightweight netlink lookup. Worst-case is tens of ms of self-inflicted latency on a rare show command — an annoyance, not a timeout/DoS.
- The `LinkList` + `map[int]string` optimization is valid but this is a perf nicety on a trusted, bounded path — no wrong output, no untrusted trigger. Does not rise to a filed defect.

---

## Finding 5 — O(N) `net.InterfaceByName` loop in `buildSessionFilter` (rated Low) → NOT-MATERIAL

**Symbol exists?** Yes. `pkg/grpcapi/server_sessions.go` (~L421) loops `for ifName, ifc := range f.cfg.Interfaces.Interfaces { net.InterfaceByName(resolvedParent) }`. Confirmed on origin/master.

**Why NOT-MATERIAL:**
- The loop is over **configured** interfaces (`f.cfg.Interfaces.Interfaces`), bounded by config size — typically a few dozen — NOT the session table. It is O(config), not O(sessions).
- This cost is negligible relative to the actual session-table iteration `GetSessions` performs. The review itself rates it Low and concedes `net.InterfaceByName` "is fast." A per-config-interface syscall on a trusted operator query is not a control-plane hazard.

---

## Finding 6 — Missing node-ID validation in `cluster-failover:<rgID>:node<N>` (rated Low) → GENUINE-RESIDUAL (LOW)

**Symbol exists?** Yes — on origin/master it lives in `pkg/grpcapi/server_diag_system_action.go` (post-#4658 split), lines ~314-337 (the review cited the pre-split `server_diag.go:1034`, which is now the stale local working-tree path).

**Why GENUINE (and why only LOW):**
- Confirmed asymmetry: the sibling `cluster-failover-data:node<N>` path (same file, L265-269) validates `cluster.IsSupportedClusterNodeID(targetNode)` right after `strconv.Atoi` and returns `InvalidArgument` on an out-of-range node. The `cluster-failover:<rgID>:node<N>` path (L336) parses `targetNode` but only checks `targetNode != s.cluster.NodeID()` — an out-of-range `node99` from a **local loopback** request (where `peerForwardedFromContext(ctx)` is false) falls straight into `s.proxyPeerSystemAction(ctx, req)`, dialing the peer over the fabric.
- Reachable: the fabric-listener interceptor `parseProxiedFailoverAction` (`server.go` L356-392) DOES validate `IsSupportedClusterNodeID`, so a malicious/malformed peer-proxied request is rejected — but that interceptor is NOT on the loopback listener, so a local operator/CLI-issued malformed node ID bypasses it.
- **Bounded blast radius → LOW**: the trigger is a trusted local operator on the loopback control plane (destructive verbs are separately gated by the server.go allowlist). The only consequence is ONE wasted authenticated peer gRPC dial, which the peer's own handler then rejects (`peerForwardedFromContext == true` → `FailedPrecondition "forwarded cluster failover target node N is not local"`). No security breach, no state corruption, no availability event, no unbounded churn (single dial per request). This is a cheap-to-fix validation-consistency nit, not a High/Medium. LOW is the correct severity (matches the review's own rating).
- **Fix**: after `targetNode, err := strconv.Atoi(nodeStr)`, add `if !cluster.IsSupportedClusterNodeID(targetNode) { return InvalidArgument }` — mirroring the `cluster-failover-data:node` path — so both loopback failover verbs reject out-of-range node IDs before any peer dial.

---

## Summary

The gRPC surface is well-hardened (consistent with ps-038 core-scope results). The one HIGH and two of the MEDIUMs are either already-fixed (F3, #4588) or rest on false premises / trusted-diagnostic perf niceties (F1/F2/F4/F5). The single genuine residual (F6) is a LOW validation-asymmetry with a one-wasted-peer-dial blast radius on a trusted local path.
