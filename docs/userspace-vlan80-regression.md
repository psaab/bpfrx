# Userspace Cluster VLAN 80 Regression

Date: 2026-03-09

Environment:
- isolated userspace HA cluster on `loss`
- firewalls:
  - `loss:bpfrx-userspace-fw0`
  - `loss:bpfrx-userspace-fw1`
- test host:
  - `loss:cluster-userspace-host`
- tracked config:
  - [ha-cluster-userspace.conf](/home/ps/git/codex-bpfrx/docs/ha-cluster-userspace.conf)

## Symptom

From `loss:cluster-userspace-host`, IPv4 traffic toward VLAN 80 destinations fails:

```text
ping -c 2 172.16.80.200
From 10.0.61.1 icmp_seq=1 Destination Host Unreachable
From 10.0.61.1 icmp_seq=2 Destination Host Unreachable
```

The same failure is visible directly on `loss:bpfrx-userspace-fw0`:

```text
ping -c 3 -W 1 172.16.80.1
3 packets transmitted, 0 received, 100% packet loss
```

So this is not a LAN policy or session-sync symptom. The firewall itself cannot
resolve the IPv4 VLAN 80 peer.

## What Is Confirmed Working

The isolated userspace firewall is configured correctly at the interface and route
level:

- `ge-0-0-2.80` exists and is `UP`
- `172.16.80.8/24` is present on `ge-0-0-2.80`
- connected route exists:

```text
172.16.80.0/24 dev ge-0-0-2.80 proto kernel scope link src 172.16.80.8
```

The isolated userspace cluster does have working WAN reachability after the VF
move to `0000:65:01.4` / `0000:65:01.5`:

- `cluster-userspace-host -> 1.1.1.1`: works
- `cluster-userspace-host -> 2001:559:8585:80::200`: works
- `cluster-userspace-host -> 2001:559:8585:80::200` via `iperf3 -P 1`: works

The original non-userspace loss cluster still reaches VLAN 80 over both IPv4 and IPv6:

```text
incus exec loss:bpfrx-fw0 -- ping -c 1 -W 1 172.16.80.1
```

That succeeds, and the original cluster has live VLAN 80 neighbor entries:

```text
172.16.80.200 lladdr ba:86:e9:f6:4b:d5 STALE
172.16.80.1 lladdr 00:10:db:ff:10:01 DELAY
2001:559:8585:80::200 lladdr ba:86:e9:f6:4b:d5 STALE
```

## Wire Evidence

Capture on `loss:bpfrx-userspace-fw0` while pinging `172.16.80.1`:

```text
tcpdump -ni ge-0-0-2 -e -vvv vlan 80 and (arp or icmp)

02:bf:72:16:01:00 > ff:ff:ff:ff:ff:ff, vlan 80, ARP, Request who-has 172.16.80.1 tell 172.16.80.8
02:bf:72:16:01:00 > ff:ff:ff:ff:ff:ff, vlan 80, ARP, Request who-has 172.16.80.1 tell 172.16.80.8
02:bf:72:16:01:00 > ff:ff:ff:ff:ff:ff, vlan 80, ARP, Request who-has 172.16.80.1 tell 172.16.80.8
```

No ARP replies were observed.

For IPv6 on the same isolated interface, neighbor discovery does work:

```text
2001:559:8585:80::200 lladdr ba:86:e9:f6:4b:d5 REACHABLE
ping -6 -c 2 2001:559:8585:80::200
2 packets transmitted, 2 received
```

This is the key finding:

- the isolated userspace firewall is emitting correctly tagged VLAN 80 ARP requests
- no IPv4 ARP reply returns to the firewall on that interface
- IPv6 ND on that same interface does complete

## What This Rules Out

This does **not** look like:

- a missing connected route
- a LAN-to-WAN policy deny
- a session-sync issue
- a general userspace helper forwarding-resolution bug
- a DHCP/RA issue on `reth1`
- a general WAN VF outage

Those are higher-layer problems. The current failure is below that: VLAN 80 neighbor
discovery is not completing for IPv4 on the isolated userspace firewall.

## Important Context

The original loss cluster and the isolated userspace cluster do **not** use the same
WAN VF pair.

Original loss cluster:
- `0000:65:00.2`
- `0000:65:00.3`

Isolated userspace cluster:
- `0000:65:01.4`
- `0000:65:01.5`

Current VM device state confirms that:

- `loss:bpfrx-fw0` uses WAN VF `0000:65:00.2`
- `loss:bpfrx-userspace-fw0` uses WAN VF `0000:65:01.4`

That original VF difference mattered earlier, and moving the isolated userspace
cluster to `65:01.4/65:01.5` restored general WAN + IPv6 behavior. The remaining
failure is narrower than the original regression report.

There is also a live address asymmetry on VLAN 80:

- original cluster primary IPv4 on VLAN 80: `172.16.80.7`
- isolated userspace cluster IPv4 on VLAN 80: `172.16.80.8`

Read-only comparison against the original cluster shows:

```text
bpfrx-fw0 (172.16.80.7) -> ARP reply received from 172.16.80.200
bpfrx-userspace-fw0 (172.16.80.8) -> no ARP reply from 172.16.80.200
```

On the original cluster, tcpdump shows the full ARP exchange:

```text
Request who-has 172.16.80.200 tell 172.16.80.7
Reply 172.16.80.200 is-at ba:86:e9:f6:4b:d5
```

On the isolated userspace cluster, tcpdump shows only the requests:

```text
Request who-has 172.16.80.200 tell 172.16.80.8
```

## Current Best Reading

Based on current evidence, the remaining regression is below the firewall routing/policy layer:

1. VLAN 80 is configured on the isolated userspace firewall.
2. IPv6 ND on VLAN 80 works.
3. The firewall emits VLAN 80 ARP requests for `172.16.80.200`.
4. No ARP reply is seen for `172.16.80.8`.
5. The original cluster does receive ARP replies for `172.16.80.7`.

So the most likely fault domain is:

- an environment-side IPv4 ARP asymmetry specific to the isolated cluster’s `.8` address
- host-side or network-side policy that differs between `.7` and `.8`
- or an upstream device state that is independent of the userspace dataplane code

## Follow-Up Checks

1. Capture VLAN 80 traffic on the `loss` host side for VF `0000:65:01.4` while the
   isolated firewall ARPs for `172.16.80.200`.
2. Check whether any upstream host/network policy is keyed to `172.16.80.7` vs `.8`.
3. Verify whether `172.16.80.200` itself still owns/responds on IPv4 to `.8`.
4. Keep the userspace dataplane investigation separate from this lab-side ARP asymmetry.

## Status

This file is historical evidence from the broken state.

That regression is now closed for the isolated userspace cluster:

1. unsupported userspace HA configs were moved back onto the legacy XDP
   dataplane, so they no longer bind AF_XDP/XSK state and perturb forwarding
2. the isolated cluster is now deployed from the tracked repo config instead of
   a stale `/tmp/ha-cluster-userspace.conf`
3. the tracked config restores fast RA timing on `reth1`, which keeps the
   LAN host's IPv6 default route fresh enough for repeatable testing

Current repeatable validation is documented in
[userspace-ha-validation.md](/home/ps/git/codex-bpfrx-userspace-wip/docs/userspace-ha-validation.md).
