# xpf deployment quickstart

From a baked image (`docs/install-images.md`) to a running firewall —
standalone or HA — with one Python tool, `scripts/deploy/xpf-deploy.py`.
The comprehensive reference (every backing, schema, recipes) is
`examples/deploy/README.md`; this is the fast path.

## The 60-second mental model

xpf names interfaces **by position** (`assignName()` in `linksetup.go`),
exactly like vSRX. (`assignName()` returns the Linux link name in dash
form — `ge-0-0-0`; config and CLI use the slash form — `ge-0/0/0` — and
the config layer translates between them. The tables below use the
slash/CLI form.)

| Position | Standalone | Cluster node 0 | Cluster node 1 |
|---|---|---|---|
| 1 | `fxp0` (mgmt) | `fxp0` | `fxp0` |
| 2 | `ge-0/0/0` | `em0` (HA control) | `em0` |
| 3 | `ge-0/0/1` | `ge-0/0/0` | `ge-7/0/0` |
| N | `ge-0/0/(N-2)` | `ge-0/0/(N-3)` | `ge-7/0/(N-3)` |

So a deployment is one ordered table: each interface gets a **role**
(the name above), a **backing** (`bridge`/`sriov`/`pci`/…), and a
**source** (bridge name, PF name, or PCI address). You write it once as
YAML; the tool validates the role↔position match, builds the day-0
config drive, and launches the VM with the NICs attached in order.

(The guest applies a `virtio-first` tiebreaker so mgmt/control stay
`fxp0`/`em0`; identical to pure position in every normal layout. Verify
with `show interfaces terse`.)

## Prerequisites

```bash
# Import the baked image (see docs/install-images.md):
incus image import dist/xpf-<ver>.incus-metadata.tar.gz \
    dist/xpf-<ver>.qcow2 --alias xpf-appliance
# The deploy tool needs: python3 + PyYAML, xorriso, and (recommended) an
# xpfd binary in PATH/cwd so the day-0 config is validated at build time.
```

## Standalone in two commands

```bash
scripts/deploy/xpf-deploy.py inventory                              # see your NICs/VFs/bridges
scripts/deploy/xpf-deploy.py deploy examples/deploy/standalone.yaml # build drive + launch
```

`standalone.yaml` is a working 3-NIC LAN→WAN NAT firewall (mgmt, LAN,
WAN). Edit it for your host, or use a backing-specific sample:
`standalone-sriov.yaml` (VF dataplane) or `standalone-passthrough.yaml`
(PCI passthrough — deploys on incus *and* libvirt). Add `--dry-run` to
print the exact commands first.

First boot: the day-0 loader re-validates the config with the real
commit-check gate, installs it as `/etc/xpf/xpf.conf`, and xpfd commits.
A rejected config logs loudly (`journalctl -u xpf-day0-config`) and
leaves the box factory-default (fxp0 DHCP + console login).

### No YAML? Use `launch`

```bash
scripts/deploy/xpf-deploy.py launch --name fw1 --config examples/deploy/standalone.conf \
    --nic bridge:br-mgmt --nic bridge:br-lan --nic bridge:br-wan
```

## libvirt instead of incus

The same definition, `--hypervisor libvirt` — the tool emits a
`virt-install` command (NIC order = guest PCI-slot order = positional
names):

```bash
scripts/deploy/xpf-deploy.py --hypervisor libvirt deploy examples/deploy/standalone-passthrough.yaml
```

See `examples/deploy/README.md` for the full incus-vs-libvirt
comparison and the SR-IOV VF-pool / pinned-guest-PCI details.

## HA pair

A cluster is two YAML files in one invocation:

```bash
# Create EVERY network the HA YAMLs reference as a source (br-mgmt,
# ha-control, ha-fabric, br-lan, br-wan) so they deploy unedited:
incus network create br-mgmt    ipv4.address=10.167.0.1/24 ipv4.nat=true ipv6.address=none
incus network create ha-control ipv4.address=none ipv6.address=none
incus network create ha-fabric  ipv4.address=none ipv6.address=none
incus network create br-lan     ipv4.address=none ipv6.address=none
incus network create br-wan     ipv4.address=none ipv6.address=none
scripts/deploy/xpf-deploy.py examples/deploy/ha-fw0.yaml examples/deploy/ha-fw1.yaml
incus exec fw0 -- cli -c "show chassis cluster status"
```

Both nodes share `ha-pair.conf`; only `node_id` (stamped on the day-0
drive) and the ge FPC (`0` vs `7`) differ. `ha-fw0-sriov.yaml` /
`ha-fw1-sriov.yaml` are the VF-dataplane variants. Two-host cluster: run
the tool on each host with that node's file and its local PFs.

## Performance: which backing for the dataplane?

The image guarantees the kernel side (≥6.18, verifier-passing AF_XDP
shim). The NIC the VM sees decides the rest:

| Backing | Guest driver | AF_XDP mode | Notes |
|---|---|---|---|
| `pci:` whole PF (i40e/ice/mlx5) | vendor PF | native, fastest | claims the entire NIC |
| `sriov:` / `pci:` mlx5 VF | mlx5_core | **native** | the loss-cluster reference shape |
| `sriov:` / `pci:` Intel VF | iavf | generic only (~3-4× slower) | works, but know it |
| `bridge:` / `net:` | virtio_net | generic-class | fine for labs / modest WANs (`inventory` hints `no (generic)`) |

virtio for mgmt and anything under a few Gb/s; mlx5 VFs or PF
passthrough for line-rate ports.

## Fleet pattern (many sites, few humans)

The YAML + `xpf.conf` are the deployable artifacts — treat them as code:

1. **CI gate**: `xpfd check-config` on every `*.conf` change (the same
   gate runs again at first boot, so a green pipeline can't ship a
   refusable config).
2. **Deploy**: `xpf-deploy.py deploy site-*/appliance.yaml` (one or many).
3. **Upgrade**: replace-image — deploy a new VM from the new image with
   the same YAML + config, swap traffic (HA: replace secondary →
   failover → replace primary). `xpf.conf` + `node_id` are the only
   carried state.
4. **Recover**: cattle. Console for `rollback 1`, redeploy otherwise.

## Troubleshooting

| Symptom | Look at |
|---|---|
| day-0 config not applied | `journalctl -u xpf-day0-config` — verbatim commit-check rejection; box stays factory-default, fix + reboot |
| NIC roles shifted | `cli -c "show interfaces terse"` vs your YAML; an interface added between deploys changes order |
| VF dataplane dead after host reboot | unpinned VF MAC rotated — set `mac:` on the interface |
| no mgmt after commit | hypervisor console → `cli` → `rollback 1`, `commit` |
| HA split-brain / no sync | `show chassis cluster status`; confirm the `em0` link is a dedicated L2 carrying nothing else |
