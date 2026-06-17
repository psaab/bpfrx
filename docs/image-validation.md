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
| **a** no config drive | factory boot; kernel ≥6.18 + `-generic` flavor; `linux-modules-extra` present (checked via the Mellanox driver dir as the sentinel — the broader mlx5/i40e set rides with it); exactly one kernel; `init_on_alloc=0` on the booted cmdline; **in-guest `xpfd verify-dataplane` PASS**; `fxp0` DHCP; sshd listening with `PermitRootLogin prohibit-password` + `PermitEmptyPasswords no`; no stray `/etc/xpf/xpf.conf` or stamp |
| **b** valid day-0 drive | config validated + installed + committed (hostname applied, CLI shows it); reboot does **not** re-apply (stamp honored). *(The loader installs the config `0600`; the scenario asserts it exists and is non-empty, not the mode.)* |
| **c** invalid day-0 drive | commit-check REJECT logged, nothing installed, no stamp, factory bootstrap still reachable |

**Pass:** `Validation complete.` with all selected scenarios PASS. Any
`FAIL:` line blocks the bake.

---

## Tier 2 — standalone forwarding + NAT (functional, manual)

Proves a deployed appliance actually routes and SNATs LAN→WAN. Fully
self-contained on one incus host: the appliance is the L3 gateway, the
LAN/WAN segments are pure L2 bridges, and interface SNAT means the WAN
endpoint needs no route back.

> **VENUE NOTE (updated 2026-06-17, #1921 RESOLVED).** The earlier warning
> here — that the AF_XDP userspace dataplane could not forward over
> **virtio** NICs in a plain incus VM (helper looping on `libxdp private
> bind: Device or resource busy` against virtio multi-queue, L3 transit
> yielding 0 sessions) — described the **#1921 bug, now fixed**. The cause
> was threefold: a rebind double-stop EBUSY loop and a physical+unit
> candidate double-bind (#1927), plus the actual transit outage — a
> standalone node replaying 16 phantom inactive HA groups so the helper
> gated all transit as HA-inactive and dropped it after XSK RX (#1929,
> guard startup HA replay behind `if m.clusterHA`). With both merged,
> virtio multi-queue AF_XDP forwards on a plain incus VM (proven: AUTO
> bind flags=0 + the HA-gate fix forwards 5000 pps). Tier 2 forwarding
> assertions therefore now run on incus/virtio as well as on a real
> AF_XDP NIC venue (**mlx5 SR-IOV VFs** — the loss userspace cluster — or
> **i40e PF passthrough** — the standalone test VM). Treat a virtio
> `Device or resource busy` rebind loop or `0 sessions` transit as a
> regression of #1921, not an expected venue limitation.

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

NIC order = interface name (positional contract). Names are shown in
config/CLI slash form (`ge-0/0/0`); the Linux link name is the dash form
(`ge-0-0-0`) that `assignName()` produces — the config layer translates
between them. NOTE (per the venue note above, #1921 resolved): incus/virtio
multi-queue AF_XDP now converges and forwards, so this topology validates
transit forwarding as well as control-plane + day-0 + interface bring-up.
A virtio bind loop / 0-session transit here is a #1921 regression, not a
venue limitation; mlx5-VF / i40e-PF remain the line-rate venues.

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
# Tools: iperf3 client on lanhost, iperf3 server + tcpdump on wanhost.
incus exec lanhost -- sh -c 'apt-get update -qq && apt-get install -y iperf3 >/dev/null 2>&1'
incus exec wanhost -- sh -c 'apt-get update -qq && apt-get install -y iperf3 tcpdump >/dev/null 2>&1; iperf3 -s -D'

# Wait for the appliance + confirm the interface map
incus exec xpf-rtr -- cli -c "show interfaces terse"   # fxp0 / ge-0/0/0 / ge-0/0/1

# Forwarding + NAT, v4 and v6
incus exec lanhost -- ping  -c3 10.66.2.10
incus exec lanhost -- ping6 -c3 fd66:2::10
incus exec lanhost -- iperf3 -c 10.66.2.10 -t 5
incus exec lanhost -- iperf3 -c fd66:2::10 -t 5

# Prove it ROUTED + NAT'd (not just L2):
incus exec xpf-rtr -- cli -c "show security flow session"      # LAN→WAN sessions w/ translation
incus exec wanhost -- timeout 6 tcpdump -ni eth0 -c3 'src 10.66.2.1'    # v4 SNAT source = appliance WAN
incus exec wanhost -- timeout 6 tcpdump -ni eth0 -c3 'src fd66:2::1'    # v6 SNAT source = appliance WAN
```

### Pass criteria
- v4 + v6 ping succeed; iperf3 moves nonzero throughput both families.
- `show security flow session` shows the forwarded flows with interface SNAT.
- `wanhost` sees traffic sourced from `10.66.2.1` (v4) AND `fd66:2::1` (v6) — SNAT confirmed for both families, not bridged.

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

Create the networks the shipped HA YAMLs actually reference as interface
`source`s — `br-mgmt`, `ha-control`, `ha-fabric`, `br-lan`, `br-wan`
(`examples/deploy/ha-fw0.yaml`/`ha-fw1.yaml`). Use these exact names so the
YAMLs deploy unedited; `br-mgmt` is NAT (admin + fxp0 DHCP), the rest are
L2-only point-to-point/segment bridges:

```bash
incus network create br-mgmt    ipv4.address=10.167.0.1/24 ipv4.nat=true ipv6.address=none
incus network create ha-control ipv4.address=none ipv6.address=none   # em0, point-to-point
incus network create ha-fabric  ipv4.address=none ipv6.address=none   # fabric
incus network create br-lan     ipv4.address=none ipv6.address=none   # reth1 members
incus network create br-wan     ipv4.address=none ipv6.address=none   # reth0 members
```

### Deploy (the shipped HA examples, unedited)
```bash
python3 scripts/deploy/xpf-deploy.py examples/deploy/ha-fw0.yaml examples/deploy/ha-fw1.yaml
# Both nodes attach NICs in the SAME order (mgmt, control, fabric, lan, wan)
# and share ha-pair.conf; only node_id (day-0 drive) + the ge FPC differ.
```

### Verify + failover
```bash
incus exec fw0 -- cli -c "show chassis cluster status"          # RG0/1/2 primary/secondary
# ha-pair.conf gives node 0 priority 200 / node 1 priority 100 for RG1 (WAN)
# and RG2 (LAN), so fw0 is the data-path PRIMARY. To exercise failover you
# must take down the PRIMARY (fw0), not the secondary:
# start a long transfer LAN→WAN through the reth VIP, then:
incus stop fw0               # kill the RG1/RG2 primary; fw1 must take over
# assert: the transfer survives with a sub-second gap; fw1 becomes primary
#         for RG1/RG2; no session loss for the synced flows. Then restart
#         fw0 and confirm failback (preempt) or steady secondary per config.
```

### Pass criteria
- Cluster forms (RGs have a primary/secondary); LAN→WAN forwards through the reth VIP.
- A node failure causes a sub-second cutover; an in-flight TCP transfer survives (session sync + fabric forwarding).
- `make test-failover` on the loss cluster remains the canonical timing gate; this Tier-3 run proves the *image* boots into a working cluster.

### Cleanup
Delete `fw0`/`fw1` and the five `xpf-ha-*` networks.

---

## Honest scope

- **virtio IS a forwarding venue (since #1921 fixed, 2026-06-17).** On local
  incus/virtio bridges the AF_XDP dataplane now binds virtio multi-queue and
  forwards transit traffic; the earlier `Device or resource busy` bind loop /
  0-session transit (observed 2026-06-15) was the #1921 bug, fixed in #1927
  (rebind double-stop + physical+unit double-bind) and #1929 (standalone
  phantom-HA-group transit gate). So Tiers 2–3 on virtio validate boot +
  day-0 + interface bring-up + control-plane reachability AND transit
  forwarding/NAT/HA. *Line-rate* numbers still require a real AF_XDP NIC —
  the loss userspace cluster's mlx5 SR-IOV VFs, or i40e PF passthrough on the
  standalone test VM — because virtio caps below line rate; but functional
  forwarding correctness is now testable on virtio. The loss SR-IOV smoke
  matrix (`docs/`) tests the *deployed binaries*; an image-based forwarding
  test can run on virtio for correctness and on a NIC venue for throughput.
- The image is hardware-agnostic for these tiers: `verify-dataplane`
  and forwarding run against the image's own kernel + the userspace
  dataplane, so local KVM is a faithful functional venue.
- None of these tiers touch the shared `loss` cluster; Tier-1 and the
  functional tiers use dedicated throwaway instances + networks.
