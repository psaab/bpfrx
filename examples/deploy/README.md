# xpf deployment examples

Everything here is driven by one Python tool — `scripts/deploy/xpf-deploy.py`
— across the three NIC backings (**bridges/virtio**, **SR-IOV VFs**,
**PCI passthrough**), both standalone and HA, on **incus or libvirt**.
No shell scripts.

```bash
scripts/deploy/xpf-deploy.py inventory                              # what NICs does this host have?
scripts/deploy/xpf-deploy.py deploy --dry-run examples/deploy/standalone.yaml   # preview
scripts/deploy/xpf-deploy.py deploy         examples/deploy/standalone.yaml     # launch
```

(`xpf-deploy.py <file>.yaml` is shorthand for `deploy <file>.yaml`.)

## The naming contract is positional

The order you attach NICs is the order they are named (matches
`assignName()` in `pkg/daemon/linksetup.go`):

```
                 standalone           cluster node 0      cluster node 1
   NIC 1   ->     fxp0   (mgmt)        fxp0                fxp0
   NIC 2   ->     ge-0/0/0             em0  (HA control)   em0
   NIC 3   ->     ge-0/0/1             ge-0/0/0            ge-7/0/0
   NIC 4   ->     ge-0/0/2             ge-0/0/1            ge-7/0/1
   NIC N   ->     ge-0/0/(N-2)         ge-0/0/(N-3)        ge-7/0/(N-3)
```

You write the `role` you expect at each position; the tool computes the
real name and refuses to launch on a mismatch — a miswired definition
fails on your laptop, not in production. (The guest applies a
`virtio-first` tiebreaker so mgmt/control stay `fxp0`/`em0`; identical
to pure position in every normal layout. Confirm with `show interfaces
terse` after boot.)

## Files

| File | Topology | Backing |
|---|---|---|
| `standalone.yaml` | standalone | all bridges (simplest) |
| `standalone-sriov.yaml` | standalone | mgmt bridge + SR-IOV VF dataplane |
| `standalone-passthrough.yaml` | standalone | mgmt bridge + PCI passthrough (incus **and** libvirt) |
| `ha-fw0.yaml` / `ha-fw1.yaml` | HA pair | all bridges |
| `ha-fw0-sriov.yaml` / `ha-fw1-sriov.yaml` | HA pair | bridges + SR-IOV VF dataplane |
| `standalone.conf` / `ha-pair.conf` | — | the `xpf.conf` shipped on the day-0 drive (check-config-valid) |

## How you declare SR-IOV vs physical: the `backing`

Each interface has a `backing` (and a `source`, plus optional `mac`).
That is the switch — the tool never guesses:

| `backing` | `source` is | incus device | libvirt | XDP |
|---|---|---|---|---|
| `net` | managed-net name | `nic network=` | `--network network=` | virtio (vhost) |
| `bridge` | host bridge | `nic nictype=bridged` | `--network bridge=` | virtio (vhost) |
| `macvlan` | host dev | `nic nictype=macvlan` | `--network type=direct` | virtio (vhost) |
| `sriov` | **PF name** | `nic nictype=sriov` (incus carves a VF, pins MAC) | `<PF>-vfpool` network | mlx5 native / iavf generic |
| `pci` | **PCI address** | `pci address=` (VFIO) | `--hostdev` / hostdev-network | native (real driver) |
| `physical` | host dev | `nic nictype=physical` | `--hostdev` | native (real driver) |

- **`sriov:<PF>`** = "give me a VF off this PF" — incus allocates a free
  VF and pins its MAC. incus convenience.
- **`pci:<addr>`** = "pass through this exact PCI device" — a whole PF
  (native XDP, claims the card) or one specific VF (add `,mac=` and the
  tool pins it on the parent PF). **`pci:<vf-addr>,mac=` deploys
  identically on incus and libvirt** — use it when one definition must
  serve both.

`xpf-deploy.py inventory` prints PF names, per-PF VFs, and PCI addresses
ready to drop into `source`.

## incus vs libvirt

Both run the *same* qcow2 and *same* day-0 drive; only the VM/NIC
declaration differs. Pick with `--hypervisor` (default `incus`):

| | incus | libvirt / KVM |
|---|---|---|
| **Best for** | quick, scriptable, VM fleets; the project's own test cluster | existing `virsh` shops; fine-grained guest PCI control |
| **Tool action** | runs `incus init` + `device add…` + `start` end-to-end | emits a `virt-install` command you run |
| **NIC ordering** | device-name order (`dev00…`) → PCI slot → positional name | `--network`/`--hostdev` order → persisted `<address>` slots (pin in `virsh edit` for full control) |
| **SR-IOV auto-VF** | `nictype=sriov parent=<PF>` | one-time `<forward mode='hostdev'>` VF pool (tool prints the XML) |
| **SR-IOV specific VF** | `pci:<vf-addr>,mac=` | `pci:<vf-addr>,mac=` (same definition) |
| **Console** | `incus exec <vm> -- cli` | `virsh console <vm>` then `cli` |

The same passthrough definition deploys either way:

```bash
scripts/deploy/xpf-deploy.py                       examples/deploy/standalone-passthrough.yaml
scripts/deploy/xpf-deploy.py --hypervisor libvirt  examples/deploy/standalone-passthrough.yaml
```

## YAML schema

```yaml
appliance:
  name:     fw0            # required — instance name
  mode:     standalone     # standalone | cluster
  node_id:  0              # required iff cluster (0|1); stamps the day-0 drive
  image:    xpf-appliance  # incus image alias / libvirt qcow2 basename
  cpu:      4
  memory:   4GiB           # 4GiB | 4096MiB | 4096 (MB)
  config:   standalone.conf  # xpf.conf for the day-0 drive (path relative to this file)
interfaces:                # ORDERED — position is the name
  - role:    fxp0          # expected name; checked against position, fails on mismatch
    backing: bridge        # net | bridge | macvlan | sriov | pci | physical
    source:  br-mgmt       # net/bridge/dev name, or PCI address for pci:
    mac:     02:bf:72:..   # optional; pins the VF/virtio MAC (recommended for VFs)
```

## No-YAML path: `launch`

Same result without a file:

```bash
scripts/deploy/xpf-deploy.py launch --name fw1 --config standalone.conf \
    --nic bridge:br-mgmt --nic sriov:enp8s0 --nic pci:0000:09:00.0,mac=02:bf:72:00:00:01
```

Cluster member: add `--mode cluster --node-id 0`.

## Host preparation

```bash
# Bridges
sudo ip link add br-lan type bridge && sudo ip link set br-lan up
incus network create ha-control ipv4.address=none ipv6.address=none   # HA links carry nothing else
incus network create ha-fabric  ipv4.address=none ipv6.address=none

# SR-IOV VFs (persists until reboot; make a systemd unit for permanence)
echo 4 | sudo tee /sys/class/net/enp8s0/device/sriov_numvfs
scripts/deploy/xpf-deploy.py inventory          # confirm VFs + read PCI addrs

# PCI passthrough
sudo modprobe vfio-pci                            # incus/libvirt bind the device
scripts/deploy/xpf-deploy.py inventory          # read the PCI column
```

mlx5 VFs get native XDP; Intel iavf VFs are generic-mode only. Whole-PF
passthrough gives native XDP but claims the entire card.

## HA pair

A cluster is two YAML files passed together (one tool invocation):

```bash
scripts/deploy/xpf-deploy.py examples/deploy/ha-fw0-sriov.yaml examples/deploy/ha-fw1-sriov.yaml
incus exec fw0 -- cli -c "show chassis cluster status"
```

Both nodes share `ha-pair.conf`; only `node_id` (stamped on the day-0
drive) and the ge FPC (`0` vs `7`) differ. Two-host cluster: run the
tool on each host with that node's file and its local PFs/PCI addresses.

## Full physical cards on libvirt — pinned guest PCI order

`xpf-deploy.py --hypervisor libvirt` emits `virt-install` with NICs in
positional order. For an all-passthrough build where you want
contractual ordering of `fxp0`/`em0`/`ge` independent of how libvirt
assigns slots, pin guest `<address>` slots after creation:

```xml
<!-- virsh edit <vm> — one <hostdev> per card, guest slots ascending -->
<hostdev mode='subsystem' type='pci' managed='yes'>
  <source><address domain='0x0000' bus='0x09' slot='0x00' function='0x0'/></source>
  <address type='pci' domain='0x0000' bus='0x01' slot='0x01' function='0x0'/>   <!-- fxp0 -->
</hostdev>
<!-- …em0, fab, ge-* at ascending guest slots 0x02, 0x03, … -->
```

The guest `<address>` slot numbers fix the enumeration order. For SR-IOV
VFs under libvirt, `pci:<vf-addr>,mac=` (hostdev-network, MAC pinned
before assignment) is preferred over a bare `<hostdev>`.

## Always verify the realized map

```bash
incus exec fw0 -- cli -c "show interfaces terse"     # incus
virsh console fw0   # libvirt → then: cli -c "show interfaces terse"
```

If a port landed on the wrong name, reorder the interface list (or pin
libvirt guest slots) and redeploy. Make this the acceptance test in
your runbook.
