# Session History — 2026-02-19

Prompts and tasks from the February 19-20 development session.

## 1. Add Junos-Style CLI Help and Tab Completion

> Implement the following plan: Add Junos-Style CLI Help and Tab Completion

Single-file change to `pkg/cmdtree/tree.go`:
- Added sub-command children to `ping`, `traceroute`, `monitor traffic`
- Added filter sub-commands to `show security flow session`, `show security log`, `clear security flow session`
- Added full argument chain to `test policy` (from-zone → to-zone → source-ip → destination-ip → destination-port → protocol)
- Added `instance` to `test routing`
- Updated ~40 descriptions to match Junos wording conventions
- Added DynamicFn closures for zones, interfaces, and routing instances
- Added `terse` to `show security zones`, `global`/`policy-name` to `show security policies`, `alarms`/`routing-engine` to `show chassis`
- Updated 18 config mode command descriptions

**Commit:** `4369c85`

## 2. Fix Ping Streaming (Real-Time Output)

> ping doesn't echo immediately the results it waits until the entire command finishes

Root cause: gRPC `Ping` and `Traceroute` RPCs were unary, using `CombinedOutput()` which buffers all output.

Fix:
- Changed proto to `stream PingResponse` / `stream TracerouteResponse`
- Implemented `streamDiagCmd()` server-side with `bufio.Scanner` line-by-line streaming
- Updated remote CLI client to use `stream.Recv()` loop

**Commit:** `faac503`

## 3. VPP Dataplane Assessment

> can you formulate a plan to and the viability using vpp as a dataplane for the router and how we could implement it or leverage it with xdp to improve performance. Then document and checkin that plan

Created `docs/vpp-dataplane-assessment.md` (initially 8 sections):
1. VPP Architecture Overview
2. Feature Coverage vs bpfrx Requirements
3. Performance Comparison
4. Integration Strategies (A: full replacement, B: hybrid XDP+VPP, C: selective acceleration, D: DPDK worker)
5. Go Control Plane Integration (GoVPP)
6. Operational Considerations
7. Risk Assessment
8. Recommendation

**Commit:** `38ea955`

## 4. WireGuard and VPN/Tunnel Analysis

> can you also examine wireguard and other similar technologies with vpp and add that to the doc and how that plays into the decision

Added sections 9-12 to the VPP assessment:
9. WireGuard and VPN Technologies (performance tables: VPP WG 34-204 Gbps vs kernel 3-5 Gbps)
10. Tunnel Technologies and XDP Compatibility (the encryption boundary — XDP can't see decrypted traffic)
11. WireGuard Integration Options for bpfrx (5 options A-E with effort estimates)
12. Impact on VPP Adoption Decision

**Commit:** `925e928`

## 5. VRRP with VPP

> can we implement vrrp using vpp? if so add this to the documentation about how you would do it

Added section 13 (293 lines):
- VPP VRRPv3 plugin overview (RFC 5798, production since VPP 20.05)
- Current bpfrx keepalived architecture and pain points
- GoVPP API integration examples
- Implementation approach (Backend interface, instance mapping, event-driven failover, VIP kernel mirroring)
- Trade-offs table (VPP VRRP vs keepalived)
- Sync group limitation and workaround via cluster election

**Commit:** `7bef3ae`

## 6. VPP Linux CP (Pseudo-Interfaces for FRR)

> could vpp create a pseudo interface so that FRR etc could understand VPP? document this as well

Added section 14 (271 lines):
- Linux CP plugin architecture (TAP mirrors, lcp_itf_pair three-way mapping)
- Traffic split (transit never touches TAP; only control-plane/management punted)
- Bidirectional synchronization (lcp-sync VPP→Linux, linux-nl Linux→VPP)
- FRR route flow (FRR → kernel → netlink → VPP FIB, 175K routes/sec)
- Sub-interfaces, VLANs, tunnels, IPsec/XFRM integration
- Management traffic punt path and namespace isolation
- Known limitations and caveats
- Production deployments (IPng, TNSR, Coloclue, VyOS)
- Comparison table with bpfrx's current networkd model

**Commit:** `2e9cc0e`

## 7. Update Executive Summary

> now update the executive summary to reflect all the new sections

Updated executive summary with VRRP/HA finding, Linux CP finding, and section index table.

**Commit:** `dc5314e`

## 8. Fix Ping VRF Name and Placeholder Completion

> root@bpfrx-fw# run ping google.com routing-instance tunnel-vr → Invalid VRF name
> also, run ping 1.1.1.1 ? does not give me any help for options

Two bugs fixed:
1. **VRF name:** gRPC/HTTP handlers used routing instance name directly (`tunnel-vr`) but kernel VRF device is `vrf-tunnel-vr`. Added `vrf-` prefix in 4 handlers.
2. **Placeholder completion:** Added `<angle-bracket>` node recognition as positional wildcards in `CompleteFromTree`, `CompleteFromTreeWithDesc`, and `LookupDesc`. Unmatched words consumed by placeholder nodes keep sibling options available for `?` help.

**Commit:** `3ab2a1d`
