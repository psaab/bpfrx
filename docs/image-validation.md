# xpf appliance image validation runbook (#1879)

How to prove a baked appliance image is shippable. There are **three
tiers**, in increasing fidelity. Tier 1 is automated and gates the bake;
Tiers 2–3 are functional and must be run by hand (they push real traffic
and need test endpoints, so they are not part of the offline bake gate).

> **What each tier proves — read this first.**
> - **Tier 1 (first-boot gate):** the image *boots*, ships exactly one
>   ≥6.18 kernel with the full driver set, the AF_XDP shim passes the
>   in-guest verifier, the factory sshd posture holds, and the day-0
>   loader installs/commits a valid config and rejects an invalid one.
>   It does **NOT** forward a single packet.
> - **Tier 2 (standalone forwarding):** a deployed appliance actually
>   routes + NATs LAN→WAN traffic. This is the "does it work as a
>   firewall/router" proof.
> - **Tier 3 (HA forwarding + failover):** a two-node cluster forwards
>   traffic and survives a node failure with sub-second cutover.
>
> "Boots + verifier-passes" (Tier 1) is necessary but NOT sufficient.
> Do not call an image shippable on Tier 1 alone.

## Prerequisites (build/test host)

- Bake toolchain: `libguestfs-tools`, `qemu-utils`, `xorriso`, Go, cargo.
- KVM access: be in the `kvm` group (or run under `sg kvm`) — otherwise
  libguestfs falls back to TCG (works, ~5× slower). Confirm:
  `sg kvm -c 'test -w /dev/kvm && echo ok'`.
- `incus` with a VM-capable storage pool (e.g. `vm-pool`, btrfs/zfs/lvm;
  `dir` works on recent incus). `incus storage list`.
- Passwordless `sudo` (the bake raises `RLIMIT_MEMLOCK` for qemu io_uring).
- Python 3 + PyYAML for `scripts/deploy/xpf-deploy.py`.

## Bake the image

```bash
sg kvm -c 'python3 scripts/image/bake.py'      # full bake + Tier-1 gate
# or, to iterate the boot test without re-baking:
sg kvm -c 'python3 scripts/image/bake.py --skip-validate'
```

Artifacts land in `dist/`: `xpf-<ver>.qcow2`, `xpf-<ver>.incus-metadata.tar.gz`,
`SHA256SUMS`, `xpf-<ver>.manifest`. Verify: `(cd dist && sha256sum -c SHA256SUMS)`.

---

## Tier 1 — automated first-boot gate (`validate.py`)

Run automatically by `bake.py` (unless `--skip-validate`), or standalone:

```bash
QCOW=dist/xpf-<ver>.qcow2 ; META=dist/xpf-<ver>.incus-metadata.tar.gz
sg incus-admin -c "XPFD=$PWD/xpfd python3 scripts/image/validate.py \
    --qcow2 $QCOW --metadata $META all"
```

It imports the image into local incus and boots three throwaway VMs on a
dedicated NAT network (`xpf-image-net`); none touch the shared cluster,
and all are deleted on exit. Scenarios:

| Scenario | Proves |
|---|---|
| **a** no config drive | factory boot; kernel ≥6.18 + `-generic` flavor + mlx5/i40e driver set; exactly one kernel; `init_on_alloc=0` on the booted cmdline; **in-guest `xpfd verify-dataplane` PASS**; `fxp0` DHCP; sshd listening with `PermitRootLogin prohibit-password` + `PermitEmptyPasswords no`; no stray `/etc/xpf/xpf.conf` or stamp |
| **b** valid day-0 drive | config validated + installed (`0600`) + committed (hostname applied, CLI shows it); a reboot does **not** re-apply (stamp honored) |
| **c** invalid day-0 drive | commit-check REJECT logged, nothing installed, no stamp, factory bootstrap still reachable |

**Pass:** `Validation complete.` with all selected scenarios PASS. Any
`FAIL:` line blocks the bake.

---

## Tier 2 — standalone forwarding + NAT (functional, manual)

Proves a deployed appliance actually routes and SNATs LAN→WAN. Fully
self-contained on one incus host: the appliance is the L3 gateway, the
LAN/WAN segments are pure L2 bridges, and interface SNAT means the WAN
endpoint needs no route back.

### Topology

```
   incus NAT net          xpf appliance VM (from the baked image)
   xpf-rtr-mgmt ──── NIC1 → fxp0      mgmt, DHCP (admin reaches it here)
                     NIC2 → ge-0/0/0  LAN  10.66.1.1/24  fd66:1::1/64
   xpf-rtr-lan ───────────┘
                     NIC3 → ge-0/0/1  WAN  10.66.2.1/24  fd66:2::1/64
   xpf-rtr-wan ───────────┘
     │                              │
   lanhost (ctr)                  wanhost (ctr)
   10.66.1.10/24 gw .1            10.66.2.10/24  (iperf3 -s)
   fd66:1::10/64                  fd66:2::10/64
```

NIC order = interface name (positional contract); all virtio bridges →
the userspace AF_XDP dataplane runs native XDP via vhost (same forwarding
path as mlx5 VFs, just virtio).

### Host networks

```bash
incus network create xpf-rtr-mgmt ipv4.address=10.166.0.1/24 ipv4.nat=true ipv6.address=none
incus network create xpf-rtr-lan  ipv4.address=none ipv6.address=none   # L2 only; appliance is gw
incus network create xpf-rtr-wan  ipv4.address=none ipv6.address=none
```

### Router config (`/tmp/router-test.conf`)

Static LAN/WAN (the shipped `standalone.conf` uses WAN-DHCP, awkward for a
closed loop). Validate before use: `xpfd check-config /tmp/router-test.conf`.

```
interfaces {
    fxp0     { unit 0 { family inet { dhcp; } } }
    ge-0/0/0 { unit 0 { family inet { address 10.66.1.1/24; } family inet6 { address fd66:1::1/64; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.66.2.1/24; } family inet6 { address fd66:2::1/64; } } }
}
security {
    zones {
        security-zone mgmt { interfaces { fxp0; } host-inbound-traffic { system-services { ssh; ping; } } }
        security-zone lan  { interfaces { ge-0/0/0.0; } host-inbound-traffic { system-services { ssh; ping; } } }
        security-zone wan  { interfaces { ge-0/0/1.0; } host-inbound-traffic { system-services { ping; } } }
    }
    policies { from-zone lan to-zone wan { policy allow-out {
        match { source-address any; destination-address any; application any; }
        then { permit; } } } }
    nat { source { rule-set lan-to-wan { from zone lan; to zone wan;
        rule snat  { match { source-address 0.0.0.0/0; } then { source-nat { interface; } } }
        rule snat6 { match { source-address ::/0; }      then { source-nat { interface; } } } } } }
}
system { host-name xpf-rtr; dataplane-type userspace; }
```

### Deploy definition (`/tmp/router-test.yaml`)

```yaml
appliance:
  name: xpf-rtr
  mode: standalone
  image: xpf-appliance
  cpu: 4
  memory: 4GiB
  config: /tmp/router-test.conf
  pool: vm-pool
interfaces:
  - {role: fxp0,     backing: net,    source: xpf-rtr-mgmt}
  - {role: ge-0/0/0, backing: bridge, source: xpf-rtr-lan}
  - {role: ge-0/0/1, backing: bridge, source: xpf-rtr-wan}
```

### Run

```bash
incus image import dist/xpf-<ver>.incus-metadata.tar.gz dist/xpf-<ver>.qcow2 --alias xpf-appliance
python3 scripts/deploy/xpf-deploy.py /tmp/router-test.yaml

# Test endpoints (containers; reachable via the incus agent regardless of L3)
incus launch images:debian/13 lanhost --network xpf-rtr-lan
incus launch images:debian/13 wanhost --network xpf-rtr-wan
incus exec lanhost -- ip addr add 10.66.1.10/24 dev eth0
incus exec lanhost -- ip -6 addr add fd66:1::10/64 dev eth0
incus exec lanhost -- ip route add default via 10.66.1.1
incus exec lanhost -- ip -6 route add default via fd66:1::1
incus exec wanhost -- ip addr add 10.66.2.10/24 dev eth0
incus exec wanhost -- ip -6 addr add fd66:2::10/64 dev eth0
incus exec wanhost -- sh -c 'apt-get install -y iperf3 >/dev/null 2>&1; iperf3 -s -D'

# Wait for the appliance + confirm the interface map
incus exec xpf-rtr -- cli -c "show interfaces terse"   # fxp0 / ge-0/0/0 / ge-0/0/1

# Forwarding + NAT, v4 and v6
incus exec lanhost -- ping  -c3 10.66.2.10
incus exec lanhost -- ping6 -c3 fd66:2::10
incus exec lanhost -- iperf3 -c 10.66.2.10 -t 5
incus exec lanhost -- iperf3 -c fd66:2::10 -t 5

# Prove it ROUTED + NAT'd (not just L2):
incus exec xpf-rtr -- cli -c "show security flow session"      # LAN→WAN sessions w/ translation
incus exec wanhost -- timeout 5 tcpdump -ni eth0 -c3 'src 10.66.2.1'  # SNAT source = appliance WAN
```

### Pass criteria
- v4 + v6 ping succeed; iperf3 moves nonzero throughput both families.
- `show security flow session` shows the forwarded flows with interface SNAT.
- `wanhost` sees traffic sourced from `10.66.2.1` / `fd66:2::1` (SNAT confirmed, not bridged).

### Cleanup
```bash
incus delete -f xpf-rtr lanhost wanhost
incus network delete xpf-rtr-mgmt xpf-rtr-lan xpf-rtr-wan
incus image delete xpf-appliance
rm -f /tmp/router-test.yaml /tmp/router-test.conf /tmp/xpf-rtr-day0.iso
```

---

## Tier 3 — HA pair forwarding + failover (functional, manual)

Proves a two-node cluster forwards and survives a node failure. Same idea
as Tier 2 but two appliances sharing reth interfaces, plus dedicated
`em0` (control) and fabric L2 segments.

### Networks
```bash
incus network create xpf-ha-mgmt    ipv4.address=10.167.0.1/24 ipv4.nat=true ipv6.address=none
incus network create xpf-ha-control ipv4.address=none ipv6.address=none   # em0, point-to-point
incus network create xpf-ha-fabric  ipv4.address=none ipv6.address=none   # fabric
incus network create xpf-ha-lan     ipv4.address=none ipv6.address=none   # reth1 members
incus network create xpf-ha-wan     ipv4.address=none ipv6.address=none   # reth0 members
```

### Deploy (the shipped HA examples + their day-0 node-ids)
```bash
python3 scripts/deploy/xpf-deploy.py examples/deploy/ha-fw0.yaml examples/deploy/ha-fw1.yaml
# (point each YAML's interface sources at the xpf-ha-* networks; both nodes
#  attach NICs in the SAME order: mgmt, control, fabric, lan, wan)
```

### Verify + failover
```bash
incus exec fw0 -- cli -c "show chassis cluster status"          # RG0/1/2 primary/secondary
# start a long transfer LAN→WAN through the cluster VIP, then:
incus restart fw1            # or: incus stop fw0 (kill the RG-1 primary)
# assert: the transfer survives with a sub-second gap; cluster re-elects;
#         no session loss for the synced flows.
```

### Pass criteria
- Cluster forms (RGs have a primary/secondary); LAN→WAN forwards through the reth VIP.
- A node failure causes a sub-second cutover; an in-flight TCP transfer survives (session sync + fabric forwarding).
- `make test-failover` on the loss cluster remains the canonical timing gate; this Tier-3 run proves the *image* boots into a working cluster.

### Cleanup
Delete `fw0`/`fw1` and the five `xpf-ha-*` networks.

---

## Honest scope

- Tiers 2–3 here run on **virtio** NICs (local incus bridges). That
  exercises the full forwarding/NAT/HA control path but **not** mlx5/i40e
  native-XDP line-rate behavior — for line-rate numbers use the loss
  userspace cluster's SR-IOV smoke matrix (`docs/`), which tests the
  *deployed binaries*, not a baked image.
- The image is hardware-agnostic for these tiers: `verify-dataplane`
  and forwarding run against the image's own kernel + the userspace
  dataplane, so local KVM is a faithful functional venue.
- None of these tiers touch the shared `loss` cluster; Tier-1 and the
  functional tiers use dedicated throwaway instances + networks.
