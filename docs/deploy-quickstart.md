# xpf deployment quickstart

How to get from a baked image (`docs/install-images.md`) to a running
firewall — standalone or HA pair — with the interface story spelled
out. Written for the operator who deploys these at scale: every
decision here is a table you write once and use twice.

## The 60-second mental model

xpf names interfaces at first boot (`enumerateAndRenameInterfaces()` →
`linksetup.go`), exactly like vSRX, by sorting NICs **(driver class,
then PCI bus)**: ALL virtio-backed NICs first, THEN all hardware-backed
NICs. Within each class, your launch order sets the names. So as long
as you list every virtio role before every hardware role (the launcher
enforces this), the position table holds:

| Position | Standalone | Cluster member (`node-id` present) |
|---|---|---|
| 1st NIC | `fxp0` (mgmt, DHCP) | `fxp0` (mgmt, DHCP) |
| 2nd NIC | `ge-0/0/0` | `em0` (HA control link) |
| 3rd NIC | `ge-0/0/1` | `ge-X/0/0` |
| Nth NIC | `ge-0/0/(N-2)` | `ge-X/0/(N-3)` |

(`X` = 0 on node 0, 7 on node 1 — the vSRX FPC convention. One
physical port, two per-node names; HA configs mention both.)

So a deployment is fully described by one ordered table:

| # | hypervisor side | xpf name | role in xpf.conf |
|---|---|---|---|
| 1 | bridge `br-mgmt` | fxp0 | mgmt zone, DHCP |
| 2 | bridge `br-lan` | ge-0/0/0 | lan zone, 192.168.1.1/24 |
| 3 | SR-IOV VF of `enp9s0f0` | ge-0/0/1 | wan zone, DHCP |

You encode the left half in the launch command and the right half in
the day-0 `xpf.conf`. They meet at the row number. That's the whole
contract.

**What makes the order deterministic:**

- **Guest driver-class sort (the load-bearing rule).** `linksetup.go`
  gives every `virtio_net` NIC sort-key 0 and every other driver
  sort-key 1, then sorts by (key, PCI bus). So virtio-backed interfaces
  are *always* named before hardware-backed ones, regardless of which
  PCI slot the hypervisor hands them. List all virtio roles
  (`net:`/`bridge:`/`macvlan:`) before all hardware roles
  (`sriov:`/`physical:`/`pci:`); the launcher rejects the reverse.
- **Within a class, name order pins PCI order.** The launcher names
  virtio devices `eth00, eth01, …` and hardware devices `hw00, hw01, …`
  (zero-padded, `e` < `h`); incus places devices on the PCI bus in
  lexicographic device-name order, so launch order → bus order within
  each class. The same name→bus mechanism is what the project's own
  `test/incus/cluster-setup.sh` relies on.
- **libvirt**: `--network`/`--hostdev` order on the `virt-install`
  command line becomes persisted `<address>` PCI slots in the domain
  XML. Once defined, the order never drifts (the mechanism Palo Alto
  VM-Series documents for the same positional contract). For full
  control of the hardware-class order, pin guest `<address>` slots
  (see the libvirt recipe in `examples/deploy/README.md`).
- **Audit, don't trust**: after first boot,
  `incus exec fw1 -- cli -c "show interfaces terse"` (or the same via
  `virsh console`) prints the realized mapping. Make it part of the
  deploy runbook.

## Prerequisites

- A baked image: `make image` → `dist/xpf-<ver>.qcow2` (+ incus
  metadata tarball). See `docs/install-images.md`.
- For day-0 drives on the build host: `xorriso` and (recommended) an
  `xpfd` binary so configs are rejected at build time, not on the
  appliance console.

```bash
incus image import dist/xpf-<ver>.incus-metadata.tar.gz \
    dist/xpf-<ver>.qcow2 --alias xpf-appliance
```

## Standalone in three commands (incus)

```bash
# 1. Write the config — examples/deploy/standalone.conf is a working
#    LAN->WAN NAT firewall (3 NICs: mgmt, lan, wan). Edit, then gate it:
xpfd check-config examples/deploy/standalone.conf

# 2+3. Launch (builds + attaches the day-0 drive, adds NICs in order, starts):
scripts/deploy/xpf-launch.sh --name fw1 --conf examples/deploy/standalone.conf \
    --nic net:mgmt --nic bridge:br-lan --nic bridge:br-wan
```

First boot: the day-0 loader validates the config with the real
commit-check gate, installs it as `/etc/xpf/xpf.conf`, and xpfd commits
it. A rejected config logs loudly
(`journalctl -u xpf-day0-config`) and leaves the box factory-default
(fxp0 DHCP + console root login) — fix the conf, rebuild the ISO,
reboot.

No config? Omit `--conf`. The box boots factory-default and you
configure on the console (`incus exec fw1 -- cli`), vSRX-style.

Worked recipes for every backing (bridges / SR-IOV / whole physical
cards) across standalone and HA, plus host-prep and a libvirt
pinned-PCI-order recipe, live in **`examples/deploy/README.md`**. Run
`examples/deploy/show-host-nics.sh` to inventory your host first.

### NIC spec forms

`scripts/deploy/xpf-launch.sh --nic` accepts, in deployment-table order:

| Spec | Backing | When |
|---|---|---|
| `net:<name>` | incus managed network | labs, mgmt networks |
| `bridge:<br>` | existing host bridge | classic deployments |
| `macvlan:<dev>` | macvlan off a host NIC | quick WAN attach |
| `sriov:<PF>[,mac=..]` | incus-allocated VF | VF dataplane, incus picks the VF and **pins the MAC host-side** |
| `pci:<addr>[,mac=..]` | VFIO passthrough (whole PF or a specific VF) | max performance / native XDP |
| `physical:<dev>` | whole host netdev | dedicated NIC without VFIO |

## Standalone on libvirt/KVM

Same table, expressed as `virt-install` argument order:

```bash
scripts/image/make-config-drive.sh -o fw1-day0.iso my.conf

virt-install --name fw1 --memory 4096 --vcpus 4 \
    --import --disk path=xpf-<ver>.qcow2 \
    --disk path=fw1-day0.iso,device=cdrom \
    --network bridge=br-mgmt \
    --network bridge=br-lan \
    --network type=direct,source=eno2,source_mode=bridge \
    --osinfo ubuntu26.04 --noautoconsole
```

For SR-IOV VFs under libvirt use `<interface type='hostdev'>` (or a
`<forward mode='hostdev'>` VF pool network) **with an explicit
`<mac address=…/>`** — libvirt then programs the VF MAC on the PF
before passthrough and it stays stable across host reboots. Avoid bare
`<hostdev>` for VFs: an unpinned VF gets a fresh random MAC every host
boot.

## HA pair

One config file, two day-0 drives that differ only in `node-id`, two
VMs launched with **identical NIC tables**. The pair needs two
point-to-point links between the nodes (HA control = `em0`, fabric =
`ge-X/0/0`) — give them dedicated networks/bridges that carry nothing
else.

```bash
# Networks once per host (lab shape; production = real L2 segments):
incus network create ha-control ipv4.address=none ipv6.address=none
incus network create ha-fabric  ipv4.address=none ipv6.address=none

# Gate BOTH personalities of the one config:
xpfd check-config -node-id 0 examples/deploy/ha-pair.conf
xpfd check-config -node-id 1 examples/deploy/ha-pair.conf

# Launch the pair — same flags except --name/--node-id:
scripts/deploy/xpf-launch.sh --name fw0 --node-id 0 --conf examples/deploy/ha-pair.conf \
    --nic net:mgmt --nic net:ha-control --nic net:ha-fabric \
    --nic bridge:br-lan --nic bridge:br-wan
scripts/deploy/xpf-launch.sh --name fw1 --node-id 1 --conf examples/deploy/ha-pair.conf \
    --nic net:mgmt --nic net:ha-control --nic net:ha-fabric \
    --nic bridge:br-lan --nic bridge:br-wan

# Verify:
incus exec fw0 -- cli -c "show chassis cluster status"
```

The wiring (both nodes identical):

```
            NIC#  fw0 name   fw1 name   network        purpose
            1     fxp0       fxp0       mgmt           OOB mgmt, DHCP
            2     em0        em0        ha-control     heartbeats + config/session sync
            3     ge-0/0/0   ge-7/0/0   ha-fabric      cross-chassis forwarding
            4     ge-0/0/1   ge-7/0/1   br-lan         reth1 member
            5     ge-0/0/2   ge-7/0/2   br-wan         reth0 member
```

`examples/deploy/ha-pair.conf` carries the matching `groups
node0/node1`, RETH definitions, redundancy groups, and
interface-monitors — both `xpfd check-config -node-id {0,1}` gates
pass on it as shipped.

## Performance: which NIC backing for the dataplane?

The image guarantees the kernel side (>= 6.18, verifier-passing AF_XDP
shim). The NIC driver the VM sees decides the rest:

| Backing | Guest driver | AF_XDP mode | Notes |
|---|---|---|---|
| whole-PF VFIO passthrough (i40e/ice/mlx5) | vendor PF | native, fastest | claims the entire NIC |
| mlx5 SR-IOV VF | mlx5_core | **native** | the loss-cluster reference shape |
| Intel SR-IOV VF | iavf | generic only (~3-4x slower) | works, but know what you bought |
| virtio bridge | virtio_net | native (vhost) | fine for labs and modest WANs |

Rule of thumb: virtio for mgmt and anything under a few Gb/s; mlx5 VFs
or PF passthrough for line-rate dataplane ports.

## Fleet pattern (many sites, few humans)

The text config is the deployable artifact. Treat it like code:

```
configs/
  site-a/fw.conf      # standalone
  site-b/ha.conf      # pair
deploy.tsv            # name  image  node-id  conf  nic1  nic2  nic3 ...
```

1. **CI gate**: `xpfd check-config` (both `-node-id`s for HA confs) on
   every change. The same binary gate runs again on the appliance, so
   a green pipeline cannot ship a config the box would refuse.
2. **Deploy**: loop `xpf-launch.sh` over the rows of `deploy.tsv`.
   Idempotence is incus-level: the instance either exists or is
   created; replacements are new instances (see Upgrades).
3. **Upgrade**: replace-image model — deploy a new VM from the new
   image with the same conf + node-id, swap traffic (HA pairs: replace
   secondary → failover → replace primary). `/etc/xpf/xpf.conf` (+
   `node-id`) is the only state to carry.
4. **Recover**: instances are cattle. Console for `rollback 1`,
   redeploy for anything worse (`docs/install-images.md` Recovery).

## Troubleshooting

| Symptom | Look at |
|---|---|
| day-0 config not applied | `journalctl -u xpf-day0-config` — shows the verbatim commit-check rejection; box is still factory-default, fix + reboot |
| NIC roles shifted | `cli -c "show interfaces terse"` vs your table; a `pci:` spec ordered before a virtio spec, or a third-party device added between deploys, changes bus order |
| VF dataplane port dead after host reboot | unpinned VF MAC rotated — pin it (`sriov:` spec, `pci:…,mac=`, or libvirt `<mac>`) |
| no mgmt after commit | hypervisor console → `cli` → `rollback 1`, `commit` |
| HA pair split-brain / no sync | `show chassis cluster status`; verify NIC#2 of both VMs share a dedicated L2 with nothing else on it |
