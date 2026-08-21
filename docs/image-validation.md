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

**Base-image trust anchor (#4904 B).** The Ubuntu cloud image is fetched from a
mirror and authenticated against a repo-PINNED SHA256 (`PINNED_BASE_SHA256` in
`bake.py`, Canonical-GPG-verified) — NOT just the `SHA256SUMS` fetched from the
same mirror endpoint (which authenticates nothing against a compromised mirror).
A pin mismatch aborts the bake. An UNPINNED release (e.g. an `XPF_BASE_RELEASE`
override or `XPF_UBUNTU_AUTODISCOVER=1` with no matching pin) is refused unless
you set `XPF_ALLOW_UNPINNED_BASE=1` (a non-publishable dev bake) or supply a
reviewed `XPF_BASE_SHA256=<digest>`. The authenticated base digest + source URL
+ `base_image_pinned` flag are bound into the signed `xpf-<ver>.manifest`.

**`--skip-validate` is marked non-publishable (#4904 A).** A `--skip-validate`
bake still signs, but the signed `xpf-<ver>.manifest` records `validated: false`
(a full bake records `validated: true`). `scripts/dist/publish.py` refuses any
image whose provenance is not `validated: true`, so an unvalidated dev/emergency
image can never carry a release signature past the fail-closed publish boundary.

**An `XPF_ALLOW_UNPINNED_BASE=1` (unpinned) bake is likewise non-publishable
(#5815).** Such a bake signs `base_image_pinned: false` into the same
`xpf-<ver>.manifest` — its own authenticated metadata says the Ubuntu base was
NOT anchored to a reviewed trust-anchor digest. `scripts/dist/publish.py`'s
`gate_provenance` REQUIRES `base_image_pinned: true` symmetrically with
`validated: true`, so a fully signed but unpinned dev image cannot be released
via the normal gate (there is no `--allow-unpinned` override — that is the
point). The check is fail-CLOSED on a MISSING `base_image_pinned` key too: an
old or tampered sidecar that does not assert pinning is refused rather than
default-allowed.

---

## Tier 1 — automated first-boot gate (`validate.py`)

Run automatically by `bake.py` (unless `--skip-validate`), or standalone:

```bash
QCOW=dist/xpf-<ver>.qcow2 ; META=dist/xpf-<ver>.incus-metadata.tar.gz
sg incus-admin -c "XPFD=$PWD/xpfd python3 scripts/image/validate.py \
    --qcow2 $QCOW --metadata $META all"
```

It imports the image into local incus and boots throwaway VMs on a
dedicated NAT network (`xpf-image-net`); none touch the shared cluster,
and all are deleted on exit. The incus alias and every scenario instance
are **namespaced with a per-run ID** (`xpf-image-validate-<run>` /
`xpf-image-<run>-a…e`), and every teardown is **ownership-gated**: the
harness tags each instance it creates with `user.xpf-owner=<run>` and
force-deletes ONLY objects carrying that tag (and only the alias it
imported). So a concurrent bake, or an unrelated same-named VM/image, is
never destroyed — before this the constant `xpf-image-validate` alias and
`xpf-image-a…e` instances were force-deleted at import/launch/cleanup with
no run-ID or ownership check (#4905-D).

`--keep` retains the run's instances, alias, and network for post-mortem
inspection. It now ALSO retains the per-run scratch directory
(`xpf-validate-<rand>`) and prints its path: scenarios attach host-side
day-0 config drives / ISOs from that directory to the VMs, so deleting it
while keeping the VMs would leave each retained instance referencing a
source that can no longer be reopened on restart (codex-182 A10-b03-C01).

Scenarios:

| Scenario | Proves |
|---|---|
| **a** no config drive | factory boot; kernel ≥6.18 + `-generic` flavor; `linux-modules-extra` present (checked via the Mellanox driver dir as the sentinel — the broader mlx5/i40e set rides with it); exactly one kernel; `init_on_alloc=0` on the booted cmdline; **in-guest `xpfd verify-dataplane` PASS**; `fxp0` DHCP; sshd listening with `PermitRootLogin prohibit-password` + `PermitEmptyPasswords no`; no stray `/etc/xpf/xpf.conf` or stamp |
| **b** valid day-0 drive | config validated + installed + committed (hostname applied, CLI shows it); reboot does **not** re-apply (stamp honored). *(The loader installs the config `0600`; the scenario asserts it exists and is non-empty, not the mode.)* |
| **c** invalid day-0 drive | commit-check REJECT logged, nothing installed, no stamp, factory bootstrap still reachable |
| **d** resized disk (#1925) | first-boot root auto-grow fills a 20 GiB root disk — root **partition** + ext4 fs both grow past the 8 GiB bake floor, `/etc/xpf/.root-grown` stamped, idempotent across a reboot, ESP still mounted, `verify-dataplane` still PASS; a control instance at the exact bake size proves the grow is a clean no-op (`growpart` NOCHANGE) |

**Pass:** `Validation complete.` with all selected scenarios PASS. Any
`FAIL:` line blocks the bake.

---

## Tier 2 — standalone forwarding + NAT (functional, manual)

Proves a deployed appliance actually routes and SNATs LAN→WAN. Fully
self-contained on one incus host: the appliance is the L3 gateway, the
LAN/WAN segments are pure L2 bridges, and interface SNAT means the WAN
endpoint needs no route back.

> **VENUE NOTE (measured 2026-08-21 from a baked image; #1926).** Plain
> **virtio** in an ordinary incus VM IS a valid venue for the Tier-2
> *functional* forwarding assertions below. The earlier "virtio delivers
> 0 frames to the XSK" warning here is retired — see
> "Recorded Tier-2 result" for the run that replaces it.
>
> The claim it rested on (#1961) was root-caused to a Go↔Rust snapshot
> **wire-type** bug for DSCP/code-point lists, fixed in **PR #1976** plus
> the `NUM_WIDTH` siblings in **#1978**. Its "sustained virtio stall"
> follow-on was retracted by its own author as a test-environment defect:
> three firewall VMs were answering the same gateway IPs on the same
> bridges, so the client's gateway ARP flipped mid-flow. The warning text
> was written one day BEFORE #1976 landed and was never revisited, so it
> outlived its evidence by two months.
>
> What virtio does NOT give you is a **line-rate** number: the ceiling
> below is a few Gbit/s on a single flow, an order of magnitude under a
> real AF_XDP NIC. Performance claims still belong on **mlx5 SR-IOV VFs**
> (the loss userspace cluster) or **i40e PF passthrough** (the standalone
> test VM's WAN). Tier 2 does not ask for one — it asks whether the
> appliance routes and NATs at all.
>
> **The one trap to avoid** is the one that caused the #1961
> misdiagnosis: make sure no other firewall VM answers the same gateway
> IPs on the same bridges. Run `incus list` first. The private
> `10.66.1.0/24` / `10.66.2.0/24` segments below exist precisely to keep
> this run isolated.

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
between them. This topology on plain incus/virtio validates the full
Tier-2 set: control-plane + day-0 + interface bring-up AND transit
forwarding/NAT (measured, #1926 — see "Recorded Tier-2 result"). Only
line-rate numbers need mlx5-VF / i40e-PF.

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

### Recorded Tier-2 result (2026-08-21, #1926)

First recorded pass. Run on ordinary **incus/virtio** on a dev host — no
SR-IOV, no PF passthrough, no shared-cluster lock.

| | |
|---|---|
| Image | `xpf-userspace-forwarding-ok-20260402-bfb00432-10859-gf93215641.qcow2` |
| `git_commit` | `f93215641` (master `e344c9df5` + the three bake fixes below) |
| Base | Ubuntu 26.04 cloud image, `9dc7c536…`, Canonical-GPG-verified |
| Guest kernel | `7.0.0-30-generic` |
| Venue | incus VM, 3× virtio NIC, `xpf-rtr-{mgmt,lan,wan}` |

Deployed from the baked qcow2 via `xpf-deploy.py` with the day-0 drive —
**not** pushed binaries. Results:

- **v4 ping** 10.66.1.10 → 10.66.2.10: replies, 0.35–0.43 ms.
- **v6 ping** fd66:1::10 → fd66:2::10: replies, 0.31–0.33 ms.
  (The *first* echo of a cold flow is lost in both families while the
  session installs — `icmp_seq=1` missing, `seq=2,3` fine. A warm flow is
  0% loss; see the discriminator below.)
- **iperf3 v4** 2.98 Gbit/s (5 s), **4.29 Gbit/s** sustained over 30 s.
- **iperf3 v6** 3.94 Gbit/s (5 s), **3.02 Gbit/s** sustained over 30 s.
- **`show security flow session`**: LAN→WAN flows with interface SNAT —
  `In: 10.66.1.10 --> 10.66.2.10;icmp / Out: 10.66.2.10 --> 10.66.2.1;icmp`
  and the `fd66:` equivalent translating to `fd66:2::1`.
- **`show security flow statistics`**: `Packets received: 3033032`,
  `Packets dropped: 0` — the direct refutation of the retired warning's
  `Packets received: 0`.
- **wanhost tcpdump**: ICMP *and* TCP sourced from `10.66.2.1` /
  `fd66:2::1`; the LAN host's own address never appears on the WAN
  segment. SNAT confirmed for both families and both protocols.

**Discriminator — this is the xpf dataplane, not the guest kernel.**
Interface SNAT alone already rules the kernel out (`nft list ruleset`
shows no NAT table — only xpf's own RST-suppression and host-inbound
counters). Made explicit anyway, matching the method that settled #1961:
with `net.ipv4.ip_forward=0` **and** `net.ipv6.conf.all.forwarding=0` set
on the appliance, ping stayed at **0% loss** and iperf3 still moved
**4.29 Gbit/s (v4)** and **3.02 Gbit/s (v6)** over 30 s. Kernel forwarding
disabled, traffic still crossing: the AF_XDP userspace dataplane carried
it.

**Not proven by this run**, and deliberately not claimed:
line rate (virtio ceilings at a few Gbit/s on one flow — use mlx5-VF or
i40e-PF for a performance number), and Tier 3 / HA from an image.

Two defects observed during the run, tracked separately — neither affects
the result above:

- Tier-1 scenario **a** fails on this image: on a factory boot with no
  config drive, nothing brings the NIC up (the bake purges cloud-init and
  netplan), so xpfd's bootstrap lifeline finds no default route, declines
  to identify a management NIC, and leaves the port down and unrenamed —
  no `fxp0`, no DHCP. Tier 2 is unaffected because it supplies a day-0
  config, which takes xpfd out of bootstrap and into full interface
  takeover.
- `show security flow session` lists the ICMP sessions but omits TCP ones,
  while `show security flow statistics` counts them (`Current sessions:
  10` against a rendered `Total sessions: 2`). A display-path gap, not a
  forwarding one — the TCP flows demonstrably forward and SNAT.

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

- **virtio IS a functional forwarding venue; it is not a performance one
  (measured 2026-08-21, #1926).** Tier 2 passes end-to-end on ordinary
  incus/virtio — v4+v6 ping, iperf3 both families, interface SNAT
  confirmed on the wire — from a booted baked image, with the guest's own
  `ip_forward` disabled to prove the AF_XDP dataplane carried it. See
  "Recorded Tier-2 result". What virtio cannot give you is a line-rate
  number: it ceilings at a few Gbit/s on a single flow, so performance
  claims still need the loss cluster's mlx5 SR-IOV VFs or i40e PF
  passthrough.

  This bullet previously asserted the opposite, on #1961's "XSK receives
  0 frames" finding. That finding was a Go↔Rust snapshot wire-type bug
  (fixed in #1976/#1978), and its "sustained stall" follow-on was
  retracted by its author as a gateway-IP/ARP collision between three
  firewall VMs. The text was written the day before the fix landed and
  went unrevisited for two months; treat the dated "re-confirmed" note it
  carried as a caution about re-confirming against a moving tree, not as
  evidence.
- The **image vs. deployed binaries** distinction still matters. The loss
  SR-IOV smoke matrix exercises binaries pushed onto already-running VMs;
  it never boots the baked qcow2. The recorded Tier-2 result above is an
  image-based proof and is the thing that closes that gap — on virtio. An
  image-based proof *on an SR-IOV venue* is still unrun.
- None of these tiers touch the shared `loss` cluster; Tier-1 and the
  functional tiers use dedicated throwaway instances + networks.
