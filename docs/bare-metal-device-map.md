# Bare-metal interface device-map (#1956)

xpf's default interface handling is **positional**: at startup it enumerates
every PCI NIC, sorts virtio-first then by PCI bus address, and assigns vSRX
names by enumeration index (`fxp0`, `em0`, `ge-{fpc}-0-{n}`). Unconfigured
NICs are renamed and brought down. That is correct for the appliance image and
controlled-topology VMs, but it is hazardous on real bare metal:

- **Unstable naming** — adding a card, a BIOS bus renumber, or onboard +
  add-in + BMC-NIC ordering shifts the index→name binding, so `ge-0/0/3`
  silently becomes a different physical port.
- **Claims everything** — a real host has NICs xpf must not touch: a
  BMC/IPMI shared NIC, a storage/cluster fabric, the admin's own management
  path. Positional mode renames them all and, if unconfigured, forces them
  `always-down`.

The **device-map** is an opt-in stanza that fixes both: it binds each xpf
logical name to a NIC by **stable identity** (PCI bus address, with a
permanent-MAC fallback), and leaves everything not named entirely alone.

## Quick start (console / IPMI session)

On bare metal you are on the **console** (serial / IPMI SoL / local KVM).
xpf does NOT fabricate an `fxp0` or grab a NIC for DHCP in device-map mode —
the console is your lifeline.

1. List the NICs (no PCI-address archaeology required):

   ```
   > show chassis device-map candidates
   PCI address      Permanent MAC      Current name   Link
   -----------      -------------      ------------   ----
   0000:05:00.0     a0:36:9f:00:11:22  eno1           up
   0000:09:00.0     a0:36:9f:00:11:30  enp9s0         up
   0000:0a:00.0     a0:36:9f:00:11:31  enp10s0        down

   Example:
     set chassis device-map interface ge-0/0/3 pci 0000:05:00.0
     set chassis device-map unmapped-interface-policy leave-alone
   ```

2. Author the map (copy-paste the PCI addresses):

   ```
   set chassis device-map interface ge-0/0/3 pci 0000:09:00.0
   set chassis device-map interface ge-0/0/4 pci 0000:0a:00.0
   set chassis device-map unmapped-interface-policy leave-alone
   ```

   `leave-alone` (the default when a map exists) means every NIC NOT named
   above — your BMC NIC, storage fabric, etc. — is never renamed, never
   brought down, never touched.

3. Commit with the safety timer, then confirm from a still-reachable session:

   ```
   commit confirmed 5
   ... verify reachability + forwarding ...
   commit check        # or just `commit` to confirm
   ```

4. Verify the resolved bindings:

   ```
   > show chassis device-map
   Device-map (unmapped-interface-policy: leave-alone):

   Logical      Identity (key)           Resolved kernel   Status
   -------      --------------           ---------------   ------
   ge-0/0/3     0000:09:00.0             enp9s0→ge-0-0-3   bound
   ge-0/0/4     0000:0a:00.0             enp10s0→ge-0-0-4  bound
   ```

The renames take effect at next boot (and persist deterministically via the
written `.link` files). The bring-down reconcile honors `leave-alone`
immediately on commit.

## Identity keys

| Key | Stable across | Use |
|-----|---------------|-----|
| `pci <DDDD:BB:DD.F>` | reboot, kernel-name renumber, RETH virtual-MAC flip, firmware update | **Primary.** Durable for onboard/PF NICs. |
| `mac <xx:xx:xx:xx:xx:xx>` | reslot, bus renumber | **Fallback.** Compared against the *permanent* MAC, never the running MAC. |
| `key <pci-then-mac\|mac-then-pci\|pci\|mac>` | — | Resolution order. Default `pci-then-mac`. |

- **Topology-change refusal.** If the PCI address matches but the present
  NIC's permanent MAC differs from the entry's `mac`, the binding is
  **REFUSED** (a card was swapped into that slot) rather than silently
  hijacking the wrong NIC. Re-pin the entry.
- **PCI moved.** If the PCI address misses but the permanent MAC hits, xpf
  binds via the MAC fallback and flags it in `show` (`bound (via MAC
  fallback — PCI moved, re-pin)`).
- **No permanent MAC** (common on some VFs/virtio): the entry binds PCI-only
  and `show` marks it `(PCI-only, unverified)`; `key mac` is rejected.
- **RETH members are PCI-only.** A RETH member's MAC alternates
  physical↔virtual, so its entry must be PCI-keyed (`key mac` is rejected at
  commit). It keeps `.link` `OriginalName=` matching as before.

## `unmapped-interface-policy`

- **`leave-alone` (default in device-map mode):** NICs with no entry are
  invisible to xpf — never renamed, never `always-down`, never
  address-stripped. This is the bare-metal-safe default.
- **`manage-down`:** reproduces today's claim-all behavior (bring
  unconfigured NICs down). Choose this only if you want xpf to own the whole
  box.

The #1922 management lifeline / protected set is always honored regardless of
the policy — an explicit map can NAME the management NIC but can never remove
it from protection.

## Safety: commit pre-flight & rollback

A commit that changes the device-map runs a **node-local pre-flight** against
the present hardware while you are still connected:

- A `REFUSED` (topology-changed) entry is rejected.
- A map that would move the live management NIC's name onto a different port
  (or steal the management name) is rejected.
- `commit confirmed` validates BOTH the candidate AND the rollback target
  (the config restored on timeout), so a confirmed-commit timeout reverts to
  a known-safe config and applies it unconditionally (no split-brain).

## HA clusters

The device-map is **per-node** (hardware differs between nodes). Use
apply-groups: `groups node0 { chassis device-map { ... } }` /
`groups node1 { ... }`, which the existing config-sync `${node}` machinery
carries. Each node resolves its own section against its own hardware. In
cluster mode, a logical name's FPC slot must align with the node-id
(`ge-7/0/x` is node 1) — a mismatch is rejected at commit.

When the primary pushes a config whose device-map section would strand the
**passive** node's management on next boot, the passive node raises a loud
HA-config-sync alarm (the config is still applied so the stores stay
consistent and the lifeline keeps it reachable now) — fix the map on the
primary and re-sync before rebooting the passive node. (A distributed
pre-commit validation RPC that prevents this at commit time on the primary is
a planned follow-up.)

## Migration & rollout

- Existing appliances/VMs: no map → positional mode → bit-identical behavior.
  Zero migration.
- The baked image ships NO default map (it has no per-box identities at bake
  time). Authoring a device-map is a post-install operator action.

## Scope (this is bare-metal only)

The device-map binding primitive is forward-compatible with the #1958
substrate-binding umbrella (a pluggable identity key), but THIS feature is
scoped to bare metal: no container alias-mode, no platform-profile.
