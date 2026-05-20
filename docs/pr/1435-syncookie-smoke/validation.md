# PR #1435 Userspace SYN-Cookie Smoke

Date: 2026-05-19

Commit under test: `eeb541ee`

Cluster: `test/incus/loss-userspace-cluster.env`

Runtime version on both peers:
`userspace-forwarding-ok-20260402-bfb00432-1406-geeb541ee`

This is the dedicated smoke set required by the #1374 gate. It is
separate from the phase-cycle throughput smoke because the gate needs
packet-level SYN-cookie evidence.

## Temporary Config

The smoke applied this temporary config, then removed it before the end
of the run:

```text
set system root-authentication encrypted-password "$6$rounds=5000$pr1435$synckey"
set security flow syn-flood-protection-mode syn-cookie
set security zones security-zone lan screen pr1435-syncookie
set security screen ids-option pr1435-syncookie tcp syn-flood attack-threshold 1
set security screen ids-option pr1435-syncookie tcp syn-flood source-threshold 1
set security screen ids-option pr1435-syncookie tcp syn-flood destination-threshold 1
```

The active firewall reported:

```text
Screen profile: pr1435-syncookie
  TCP SYN flood protection: attack-threshold 1
  Applied to zones: lan
```

## SYN-ACK Challenge

Command shape:

```text
hping3 -S -p 65000 -c 20 -i u10000 172.16.50.1
```

Observed result:

```text
20 packets transmitted, 14 packets received, 30% packet loss
flags=SA
```

The client tcpdump captured userspace-generated SYN-ACK replies from
`172.16.50.1:65000` to the LAN client.

Counters after the first challenge probe:

```text
SYN-cookie challenges          15
SYN-cookie SYN-ACK sent        15
SYN-cookie ACK RST sent        0
SYN-cookie budget drops        0
SYN-cookie ACK valid           0
SYN-cookie ACK invalid         0
SYN-cookie bypass              0
```

## Valid ACK RST

The validated-ACK proof used a fake LAN source IP at L2 so the Linux
client kernel would not race the raw ACK with an unsolicited RST.

Observed packet exchange:

```text
10.0.61.250:41413 > 172.16.50.1:65000 flags=A
172.16.50.1:65000 > 10.0.61.250:41413 flags=RA
```

Counter delta:

```text
SYN-cookie ACK RST sent        0 -> 1
SYN-cookie ACK valid           0 -> 1
SYN-cookie budget drops        0 -> 0
```

This closes the "validated ACK emits bounded RST" gate and proves reply
budget accounting is surfaced while replies are admitted.

## Random ACK Drop

Probe:

```text
10.0.61.250:41500 > 172.16.50.1:65000 flags=A
seq=2882400001 ack=305419896
```

Counter delta:

```text
SYN-cookie ACK invalid         0 -> 1
```

No RST was observed for the invalid ACK.

## Retransmitted SYN Admission

The probe completed a valid cookie ACK, then retransmitted the same SYN.

Observed packet exchange:

```text
10.0.61.251:41619 > 172.16.50.1:65000 flags=A
172.16.50.1:65000 > 10.0.61.251:41619 flags=RA
10.0.61.251:41619 > 172.16.50.1:65000 flags=S
```

Counter delta:

```text
SYN-cookie ACK RST sent        1 -> 2
SYN-cookie ACK valid           1 -> 2
SYN-cookie bypass              0 -> 1
```

This proves the post-ACK validated-client cache admits the client's next
SYN through the normal policy/NAT/session path instead of issuing another
cookie challenge.

## HA Failover Acceptance

Node0 minted the cookie first. Then RG1 and RG2 were moved to node1:

```text
Manual failover completed for redundancy group 1 (transfer committed)
Manual failover completed for redundancy group 2 (transfer committed)
```

Cluster state before the ACK:

```text
Redundancy group: 1
node1  100      primary
node0  200      secondary

Redundancy group: 2
node1  100      primary
node0  200      secondary
```

The ACK was then sent to node1 with the cookie minted on node0.

Observed packet exchange:

```text
10.0.61.252:41723 > 172.16.50.1:65000 flags=A
172.16.50.1:65000 > 10.0.61.252:41723 flags=RA
```

Node1 counters:

```text
SYN-cookie challenges          0
SYN-cookie SYN-ACK sent        0
SYN-cookie ACK RST sent        1
SYN-cookie budget drops        0
SYN-cookie ACK valid           1
SYN-cookie ACK invalid         0
```

This proves a standby/new-active peer can validate a cookie it did not
mint locally.

## Cleanup

The temporary screen and root-auth config were removed after the smoke:

```text
commit complete: 6 statement(s) changed (0 added, 6 removed)
No screen profiles configured
No root authentication configured
```

Final cluster state:

```text
Redundancy group: 0
node0  200      primary
node1  100      secondary

Redundancy group: 1
node0  200      primary
node1  100      secondary

Redundancy group: 2
node0  200      primary
node1  100      secondary
```

## Phase-Cycle Smoke

`./scripts/userspace-phase-cycle.sh` also passed on `eeb541ee`.

Highlights:

```text
runtime mode: supported
active firewall: loss:xpf-userspace-fw0
IPv4 TTL probe: ok
IPv4 mtr: ok
IPv6 TTL probe: ok
IPv6 mtr: destination unresolved warning only
IPv4 iperf: 21.267 / 23.420 / 23.236 Gbps
IPv6 iperf: 22.999 / 23.061 / 23.042 Gbps
```
