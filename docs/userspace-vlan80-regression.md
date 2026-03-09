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

From `loss:cluster-userspace-host`, traffic toward VLAN 80 destinations fails:

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
resolve or reach VLAN 80 peers.

## What Is Confirmed Working

The isolated userspace firewall is configured correctly at the interface and route
level:

- `ge-0-0-2.80` exists and is `UP`
- `172.16.80.8/24` is present on `ge-0-0-2.80`
- connected route exists:

```text
172.16.80.0/24 dev ge-0-0-2.80 proto kernel scope link src 172.16.80.8
```

The original non-userspace loss cluster still reaches VLAN 80:

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

This is the key finding:

- the isolated userspace firewall is emitting correctly tagged VLAN 80 ARP requests
- no reply returns to the firewall on that interface

## What This Rules Out

This does **not** look like:

- a missing connected route
- a LAN-to-WAN policy deny
- a session-sync issue
- a userspace helper forwarding-resolution bug
- a DHCP/RA issue on `reth1`

Those are higher-layer problems. The current failure is below that: VLAN 80 neighbor
discovery is not completing on the isolated userspace firewall.

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

That difference matters because the original cluster still has working VLAN 80
adjacency while the isolated userspace cluster does not.

## Current Best Reading

Based on current evidence, the regression is below the firewall routing/policy layer:

1. VLAN 80 is configured on the isolated userspace firewall.
2. The firewall emits VLAN 80 ARP requests.
3. No VLAN 80 ARP replies are seen back on that WAN VF.
4. The original cluster still receives VLAN 80 replies on a different WAN VF pair.

So the most likely fault domain is:

- isolated userspace cluster WAN attachment
- host-side VF wiring / switch exposure for the `65:01.4/65:01.5` pair
- or some regression that changed which WAN VF pair the isolated cluster should use

## Follow-Up Checks

1. Compare the historical working userspace cluster WAN VF assignment against the
   current `/tmp/bpfrx-loss-userspace.env`.
2. Capture VLAN 80 traffic on the `loss` host side for VF `0000:65:01.4` while the
   isolated firewall ARPs.
3. If the isolated userspace cluster previously used the `65:00.x` pair, move it
   back to the known-good WAN VF pair and retest.
4. If the WAN VF pair is correct, inspect host-side switchdev/trust/VLAN settings for
   `mlx0` `virtfn10` / `virtfn11`.

## Status

This is documented evidence, not a fix.

At the moment:
- original cluster VLAN 80: working
- isolated userspace cluster VLAN 80: broken
- current proof: ARP requests leave the isolated firewall, replies do not return
