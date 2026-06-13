# xpf deployment examples

Copy-paste recipes for getting interfaces into an xpf appliance VM,
across the three NIC backings — **host bridges (virtio)**, **SR-IOV
VFs**, and **whole physical cards (VFIO passthrough)** — for both
standalone and HA-pair deployments.

**The naming contract is positional** (matches `assignName()` in
`pkg/daemon/linksetup.go`): the order you attach NICs is the order they
are named.

```
                 standalone           cluster node 0      cluster node 1
   NIC 1   ->     fxp0   (mgmt)        fxp0                fxp0
   NIC 2   ->     ge-0/0/0             em0  (HA control)   em0
   NIC 3   ->     ge-0/0/1             ge-0/0/0            ge-7/0/0
   NIC 4   ->     ge-0/0/2             ge-0/0/1            ge-7/0/1
   NIC N   ->     ge-0/0/(N-2)         ge-0/0/(N-3)        ge-7/0/(N-3)
```

(Under the hood the guest sorts `(virtio-first, then PCI bus)` so the
mgmt/control links are robustly `fxp0`/`em0`; that equals pure position
whenever virtio NICs sit on lower PCI slots than passthrough cards —
i.e. every normal layout. The only divergence is a passthrough card on
a *lower* slot than a virtio NIC; verify with `show interfaces terse`.)

## Two ways to deploy

**Recommended — YAML + `xpf-deploy.py`:** one file describes the whole
appliance; the tool checks each interface's declared `role` against its
position, builds the day-0 drive, and launches. A cluster is two files.

```bash
scripts/deploy/xpf-deploy.py --dry-run examples/deploy/standalone.yaml   # preview
scripts/deploy/xpf-deploy.py           examples/deploy/standalone.yaml   # launch
scripts/deploy/xpf-deploy.py examples/deploy/ha-fw0.yaml examples/deploy/ha-fw1.yaml  # HA pair
```

**Imperative — `xpf-launch.sh`:** the same thing as one command line
with ordered `--nic` flags (no YAML). Good for one-offs and scripting.

| File | What it is |
|---|---|
| `standalone.yaml` / `ha-fw0.yaml` / `ha-fw1.yaml` | **YAML deployment definitions** (role-validated) |
| `standalone.conf` | 3-NIC LAN→WAN NAT firewall config (check-config-valid) |
| `ha-pair.conf` | one config for both HA nodes (check-config-valid for `-node-id 0` and `1`) |
| `show-host-nics.sh` | inventory host PFs/VFs/PCI-addresses/bridges → values for the recipes |
| `ha-bridges.sh` / `ha-sriov.sh` / `ha-physical.sh` | runnable imperative HA launchers, one per NIC backing |

Both paths accept `--dry-run` to preview the exact `incus` commands.
Per-interface backings: `net:` (incus managed network), `bridge:`,
`macvlan:`, `sriov:` (incus-allocated VF, MAC pinned host-side), `pci:`
(VFIO passthrough of a PF or specific VF; `,mac=` pins a VF),
`physical:`.

```bash
examples/deploy/show-host-nics.sh        # see what your host has
```

---

## The interface map (both deployments)

```
                 standalone           HA member (node-id present)
   NIC #1   ->   fxp0   (mgmt DHCP)    fxp0   (mgmt DHCP)
   NIC #2   ->   ge-0/0/0              em0    (HA control link)
   NIC #3   ->   ge-0/0/1              ge-X/0/0   (fabric member -> fab0/fab1)
   NIC #4   ->   ge-0/0/2              ge-X/0/1   (LAN member  -> reth1)
   NIC #5   ->   ge-0/0/3              ge-X/0/2   (WAN member  -> reth0)
```

`X` = `0` on node 0, `7` on node 1 (vSRX FPC convention — same physical
port, two per-node names; that's why `ha-pair.conf` lists both).

---

## Host preparation

### Bridges

```bash
# A plain Linux bridge (attach your uplink/host ports to it as needed):
sudo ip link add br-lan type bridge && sudo ip link set br-lan up
sudo ip link add br-wan type bridge && sudo ip link set br-wan up
# …or an incus managed network (gives DHCP/NAT for labs):
incus network create lan
# The two HA point-to-point links must carry nothing else:
incus network create ha-control ipv4.address=none ipv6.address=none
incus network create ha-fabric  ipv4.address=none ipv6.address=none
```

### SR-IOV VFs

```bash
# Carve VFs on a PF (persists until reboot; make it a systemd unit or
# udev rule for permanence). mlx5_core gives native XDP in the VF;
# Intel iavf VFs are generic-XDP only.
echo 4 | sudo tee /sys/class/net/enp8s0/device/sriov_numvfs
examples/deploy/show-host-nics.sh        # confirm VFs + read their PCI addrs
```

`sriov:<PF>` lets incus pick a free VF and pin its MAC on the PF before
passthrough — stable across host reboots. To pass a *specific* VF by
PCI address instead, use `pci:<vf-addr>,mac=02:..` (the launcher
resolves the parent PF and pins the MAC; **never** omit `mac=` on a
VF — it randomizes every host reboot).

### Whole physical cards (VFIO passthrough)

```bash
sudo modprobe vfio-pci                    # incus binds the device for you
examples/deploy/show-host-nics.sh         # read the PCI column per card
```

Whole-PF passthrough gives the guest the card's real driver (native
XDP) but claims the entire NIC — its VFs become unusable elsewhere, and
the host loses that port. Passthrough devices can't be hot-added, so
the launcher adds them while the VM is stopped (handled).

---

## Standalone recipes

All use `standalone.conf` (NIC #1 mgmt, #2 LAN=ge-0/0/0, #3 WAN=ge-0/0/1).

```bash
# Bridges (virtio) — works anywhere:
scripts/deploy/xpf-launch.sh --name fw1 --conf examples/deploy/standalone.conf \
    --nic net:mgmt --nic bridge:br-lan --nic bridge:br-wan

# SR-IOV dataplane (mgmt stays virtio):
scripts/deploy/xpf-launch.sh --name fw1 --conf examples/deploy/standalone.conf \
    --nic net:mgmt --nic sriov:enp8s0 --nic sriov:enp9s0

# Whole physical cards for the dataplane (mgmt virtio — recommended):
scripts/deploy/xpf-launch.sh --name fw1 --conf examples/deploy/standalone.conf \
    --nic net:mgmt --nic pci:0000:b7:00.0 --nic pci:0000:b7:00.1

# Everything physical incl. fxp0 (see determinism caveat below):
scripts/deploy/xpf-launch.sh --name fw1 --conf examples/deploy/standalone.conf \
    --nic pci:0000:01:00.0 --nic pci:0000:b7:00.0 --nic pci:0000:b7:00.1
```

Mixed is fine and common — e.g. mgmt on a bridge, LAN on a VF, WAN a
whole card — as long as every **virtio** NIC (`net:`/`bridge:`/`macvlan:`)
comes **before** every **hardware** NIC (`sriov:`/`physical:`/`pci:`).
The guest names virtio-backed interfaces first regardless of slot, so a
virtio role listed after a hardware role would take a *lower* name and
scramble the map; the launcher rejects that order.

---

## HA-pair recipes

Each runnable script launches **both** nodes (only `--name`/`--node-id`
differ); the config is `ha-pair.conf`, valid for both personalities.

```bash
examples/deploy/ha-bridges.sh     # all bridges/virtio
examples/deploy/ha-sriov.sh       # virtio mgmt/control/fabric + SR-IOV dataplane
examples/deploy/ha-physical.sh    # every interface a passthrough card
```

Equivalent explicit form (what `ha-sriov.sh` runs):

```bash
for n in 0 1; do
  scripts/deploy/xpf-launch.sh --name "fw$n" --node-id "$n" \
      --conf examples/deploy/ha-pair.conf \
      --nic net:mgmt --nic net:ha-control --nic net:ha-fabric \
      --nic sriov:enp8s0 --nic sriov:enp9s0
done
```

Two-host clusters: run the script on each host with `NODES=0` on one and
`NODES=1` on the other, and point the per-node PCI/PF variables at that
host's hardware. The `ha-control`/`ha-fabric` links must be real L2
segments between the two hosts (VLAN, direct cable, or a shared bridge).

---

## Full physical cards (libvirt, pinned PCI order)

The launcher names hardware devices `hw00,hw01,…` in `--nic` order so
they sort after the virtio `eth0N` group; within the hardware class the
guest then orders by PCI bus. For an **all-physical** build where you
want fully contractual ordering of fxp0/em0/fab/ge independent of how
incus assigns PCI slots, libvirt lets you pin the guest PCI slot of
every device — the most deterministic choice:

```xml
<!-- virsh edit xpf-fw0 — fragment; one <hostdev> per card, slots ascending -->
<hostdev mode='subsystem' type='pci' managed='yes'>      <!-- fxp0  -->
  <source><address domain='0x0000' bus='0x01' slot='0x00' function='0x0'/></source>
  <address type='pci' domain='0x0000' bus='0x01' slot='0x01' function='0x0'/>
</hostdev>
<hostdev mode='subsystem' type='pci' managed='yes'>      <!-- em0   -->
  <source><address domain='0x0000' bus='0x01' slot='0x00' function='0x1'/></source>
  <address type='pci' domain='0x0000' bus='0x01' slot='0x02' function='0x0'/>
</hostdev>
<!-- …fab, ge-LAN, ge-WAN at slots 0x03, 0x04, 0x05 -->
```

The guest `<address>` slot numbers are what fix the enumeration order
(and therefore fxp0/em0/ge-X/0/N), independent of the host source
addresses. For SR-IOV VFs under libvirt, prefer
`<interface type='hostdev'>` with an explicit `<mac address=…/>` so
libvirt pins the VF MAC on the PF before assignment.

Attach the day-0 config drive the usual way:

```bash
scripts/image/make-config-drive.sh -n 0 -o fw0-day0.iso examples/deploy/ha-pair.conf
virsh attach-disk xpf-fw0 fw0-day0.iso sdz --type cdrom --config
```

---

## Always verify the realized map

Whatever backing you chose, the post-boot truth is one command:

```bash
incus exec fw0 -- cli -c "show interfaces terse"      # incus
virsh console xpf-fw0   # then: cli -c "show interfaces terse"   (libvirt)
```

If a port landed on the wrong name, reorder the `--nic` list (incus) or
adjust the guest `<address>` slots (libvirt) and redeploy. Make this
check part of the deploy runbook — it's the contract's acceptance test.
