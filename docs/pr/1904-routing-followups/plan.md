# #1904 + #1905 — routing follow-ups from the #1884 research

One combined lane: both defects were found during the #1884 research
(AGY r5 / Codex r5 for #1904; Codex r1 F2-class for #1905), both are
Go pkg/routing-adjacent, and both mechanisms were already ratified by
the #1884 reviewers. PR #1903 merged the #1884 reconcile; this lane
builds directly on its code.

## Defect 1 (#1904) — step 0a binds the literal `.N` name for unit>0 RI tunnel members

`routing-instances <ri> interface gr-0/0/0.1` is normalized by
`riMemberLinuxName` (pkg/daemon/daemon_run.go, SHARED since #1884
between the step-0a bind loop in daemon_apply.go and the RIListMember
scan in `collectAppliedTunnels`) to the literal `gr-0-0-0.1`. But the
compiler names unit>0 per-unit tunnel devices with the `uN` scheme
(`pkg/config/compiler_interfaces.go`: `linuxName + "u" + unitNum`), so
the kernel device is `gr-0-0-0u1` and the 0a `BindInterfaceToVRF`
fails interface-not-found for every unit>0 tunnel list member.
Pre-existing (predates #1884; #1884 deliberately kept exact 0a parity
in the shared helper so the veto could never claim binds 0a does not
perform).

### Fix

Resolve list entries through `cfg.TunnelNameMap()` INSIDE the shared
`riMemberLinuxName` helper (signature gains a `tunMap` parameter; both
callers build the map once from the SAME cfg). Exact parity with the
real device-naming scheme holds **by construction**: `TunnelNameMap`
returns the compiler-assigned `TunnelConfig.Name` verbatim for
per-unit tunnels — the same field `ApplyTunnels` uses to create the
kernel device — so the normalization cannot diverge from what the
tunnel manager actually names. Because the helper is shared, the fix
carries 0a and the tunnel manager's veto/observation automatically
(the Codex r5 exact-parity requirement).

Non-tunnel refs keep the literal transform (`LinuxIfName` + unit-0
collapse) **byte-identical**. The issue's fix-direction phrase named
`cfg.ResolveKernelIfName` "(which maps via TunnelNameMap)"; this plan
implements exactly its tunnel branch (the TunnelNameMap lookup) and
deliberately NOT the full resolver, because the full resolver would
silently activate binds 0a has never performed for non-tunnel refs —
`reth0` → physical member, `st0.0` → verbatim XFRM name (today's code
strips to `st0`), `irb.0` → bridge device, unmodeled `foo.0` →
suffix-preserving fallback. Each of those is a behavior change to
live VRF membership outside the ratified #1904 defect (unit>0 tunnel
members) and needs its own ratification if wanted.

### Tests (netlink-free, daemon package)

- `riMemberLinuxName` unit cases: unit>0 ref with a tunMap entry →
  `uN` device name; unit-0 / bare / non-tunnel refs unchanged
  (replaces the #1884 "exact 0a parity" test that pinned the OLD
  broken literal `.1` form, whose comment already said "the shared
  helper guarantees both move together when 0a is fixed").
- `collectAppliedTunnels`: a unit-1 per-unit tunnel (`gr-0-0-1u1`)
  listed as `gr-0/0/1.1` in a vrf-type RI gets `RIListMember` set —
  proving the veto now covers unit>0 devices.

## Defect 2 (#1905) — WG tun leaks configured link-local addresses removed from config

`applyWireguardTunLocked` calls the shared `reconcileLinkAddrsLocked`
with the `nil` applied-set sentinel, which skips ALL link-local
deletion ("the kernel manages fe80"). A CONFIGURED fe80 on a wgN
tunnel later removed from config therefore leaks forever — the device
is persistent (#1432 S2a / AGY Hazard B) and never recreated. The
GRE/IPIP anchor path fixed exactly this in #1884 via the per-link
`appliedAddrs` record; the WG branch was deliberately left
byte-identical at the time.

### Fix

Pass and store the same applied-addresses record on the WG branch:

```go
t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
    link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
```

The shared helper already implements the configured-vs-autoconf
split and the failed-delete retry (#1884 r2 Codex F4). Semantics
inherited from the ratified GRE branch:

- First apply after daemon restart (adoption): `appliedAddrs[wg0]` is
  nil → no link-local deletion that pass; configured fe80s are
  recorded, so the SECOND apply onward can reconcile them away.
  A pre-existing/foreign fe80 is never recorded, never deleted.
- Same-address-configured-AND-kernel-generated edge: while configured
  it is tracked; on removal from config it is deleted once (it was
  ours); if the kernel re-adds it by addrconf, the re-added copy is
  untracked and never touched again — converges to "kernel address
  survives". Identical to the GRE-branch semantics ratified in #1884.
- WG tunnels removed from config entirely: the S2a known limitation
  (device leaks until S6 teardown, #1434) extends to the appliedAddrs
  entry — retained alongside the leaked device, so a later re-add
  keeps accurate tracking. Bounded by the device leak itself.

`Apply` calls `ensureReconcileStateLocked` before the per-tunnel loop,
so `t.appliedAddrs` is always non-nil when the WG branch runs.

### Tests (pkg/routing, fakeLinkOps per package patterns)

- Configured fe80 removed from config reconciles away; kernel
  autoconf fe80 on the same wgN survives; the non-LL address stays.
- Adoption pass: fe80 present on the device before the first apply is
  never deleted.
- Failed fe80 delete is retained in the applied set and retried on
  the next apply (parity with the GRE-branch retry test).

## Gates

- `go build ./...`, full `go test ./...` (GOCACHE=/dev/shm), `-race`
  on pkg/routing (+ pkg/daemon).
- Live on the loss userspace cluster under the lock protocol:
  (a) unit>0 tunnel member in a routing-instance shows `master
  vrf-<ri>` in `ip link`; (b) configure an fe80 on a wg tun, commit,
  remove, commit → address gone; kernel-autonomous fe80 untouched.

## Docs

The module contracts here are the godoc blocks themselves
(`riMemberLinuxName`, `applyWireguardTunLocked`,
`reconcileLinkAddrsLocked`) — all updated in place. No standalone
Markdown module doc covers WG address reconcile or step-0a binding
(checked docs/wireguard-interop.md, docs/wg-interop-runbook.md).
