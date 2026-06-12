# Claude SMR hostile code review — PR #1903 r1 (head 8b209528714b)

Verdict: **MERGE-READY** (one self-found divergence already fixed in
8b209528714b — the WG nil-IP address skip; details below).

## Required worked traces

**T1 — unrelated commit ⇒ no destructive netlink ops on gr-X.**
applyConfig → ApplyTunnels(same desired). A.1: desired == oldOwned ⇒
removal loop deletes nothing. Per-tunnel: `adopting=false`;
`applyAnchorLocked`: LinkByName → existing TUN(NO_PI, persistent) ⇒
reuse, `created=false`; `reconcileAnchorMTULocked`: tc.MTU==0 ∧
!adopting ⇒ no write. `finishTunnelLocked`: LinkSetUp (idempotent —
IFF_UP on an up link emits no netdev event), AddrList ⇒ want==existing
⇒ zero AddrAdd/AddrDel; claim: stanza/list per config — observation
path issues only LinkByName reads. NET: zero LinkDel/LinkAdd/Addr
mutations; ifindex stable. **Honesty note**: the apply still performs
read-class netlink calls plus one idempotent LinkSetUp per tunnel per
commit — identical in kind to the pre-existing WG branch; the #1884
contract (no flap, no churn, no reader death) is about the destructive
ops, and the live validation confirmed zero journal flap events and
ifindex 97 stable across commits.

**T2 — tunnel rename / re-key ⇒ contract behavior.**
Rename gr-0/0/0→gr-0/0/1: old name ∈ oldOwned ∖ desired ⇒ A.1 stops
keepalive (no-op for anchors), LinkDel, clears appliedAddrs/appliedRI;
new name adopting=true ⇒ fresh create. Clean delete→create — exactly
the #1887 tombstone→respawn contract, the only Rust-visible signal.
Re-key on an ANCHOR: Source/Destination/Key live only in the dataplane
snapshot — the kernel anchor is untouched (reuse), the snapshot
pipeline (#1873 ids + #1887 live state) handles the semantic change.
Re-key on the LEGACY branch: `legacyTunnelMatches` returns false
(IKey/OKey) ⇒ delete+recreate + keepalive restart via the `created`
trigger. All three match plan §5/§7.

**T3 — daemon restart ⇒ adopted, not flapped.** ownedNames empty ⇒
no removals; existing anchor passes `anchorReusable` ⇒ reuse with
`adopting=true`; MTU normalized only if it differs from the desired
value; claim re-recorded from the live observation (stanza bind or
master==vrf-list). Live-validated: ifindex 97 and `master vrf-sfmix`
identical across `systemctl restart xpfd` — the list-bind retention
(A.5 veto/observation) exercised against real kernel state.

## Self-found divergence (fixed)

**SMR-c1 (fixed in 8b209528714b)**: the extracted shared address
helper would delete a stale `netlink.Addr` with a nil IP; the
pre-#1884 WG block's delete condition required `a.IP != nil`. One
defensive `continue` restores byte-identity and protects all branches
from deleting an unclassifiable address.

## Audit results (held)

- A.5 ordered claim procedure matches plan v9 branch-for-branch:
  bind-success-only stanza claims (r7), observation fallback after a
  failed stanza bind reaches the r8 overlap cell
  (`reconcileVRFClaimLocked` calls `observeListClaimLocked` on the
  bind-failure path), master-observed list transfer (r6), `vrf-`
  prefix (r4 AGY), lapse table: clear only on
  unbind-success/mismatch/not-found/master==0; retain on transient
  LinkByName error and LinkSetNoMaster failure.
- A.1: `oldOwned` snapshot taken before `next` is installed; the
  `adopting` flag derives from it for BOTH anchor reuse paths
  (plain + EEXIST — pinned by
  TestTunnelAnchorEEXISTRaceOnOwnedNameNoMTUWrite); failed LinkDel
  retains via `next[name] = true`; appliedAddrs/appliedRI deleted only
  after successful/no-op removal; clearLocked resets all three maps.
- Lock discipline: all new state under `t.mu`; `state.mu` is read
  briefly nested under `t.mu` (same nesting GetStatus uses);
  keepaliveLoop never takes `t.mu` — no inversion;
  `stopKeepaliveLocked` cancels + drains (#848) + deletes the entry.
- Legacy comparison: field list + exclusions exactly per A.6; the
  kernel-shaped fixtures in TestLegacyTunnelKernelPopulatedFieldsIgnored
  pin PMtuDisc/Tos exclusion.
- MTU cells: created-with-config (anchor + legacy), owned-reconcile
  (tc.MTU>0), adoption-only 1500 (anchor only — the legacy branch has
  no 1500 normalization, kernel GRE defaults are 1476/1462), owned
  tc.MTU==0 never touched. All pinned in tests 2/6b analogues.
- Keepalives: legacy-only (anchor branch stops any leftover runner on
  mode flip); normalized identity; retained-down skip pinned by
  TestLegacyKeepaliveDownSkipsLinkSetUp.
- Daemon plumbing: `riMemberLinuxName` is the single normalization
  used by 0a AND the scan (exact 0a parity pinned by
  TestRIMemberLinuxNameExact0aParity including the unit>0 `.1`-vs-`u1`
  cell, follow-up #1904); MTU precedence unit-overrides-interface;
  additive fields verified consumer-safe in research r3.
- Public API: ApplyTunnels/ClearTunnels/GetTunnelStatus/
  GetKeepaliveState signatures unchanged; Clear keeps
  delete-everything semantics.

## Residuals (documented, accepted)

Restart-window leaks (stale anchors / configured-LL / RI claims
orphaned while the daemon was down), same-name external replacement
between applies (today-parity), WG configured-LL leak (#1905), 0a
unit>0 naming (#1904).
