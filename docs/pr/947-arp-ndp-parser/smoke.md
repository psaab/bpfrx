# #947 cluster smoke

Captured 2026-04-29 on `loss:xpf-userspace-fw0/fw1` userspace cluster
after deploying commit `74d25948` (#947 ARP/NDP parser extraction).

## Throughput gates (all clear)

| Test | Gate | Result |
|---|---|---|
| iperf-c P=12 | ≥ 22 Gb/s | **23.4 Gb/s, 0 retx** ✓ |
| iperf-c P=1  | ≥ 6 Gb/s  | **6.94 Gb/s, 0 retx** ✓ |
| iperf-b P=12 | ≥ 9.5 Gb/s, 0 retx | **9.58 Gb/s, 0 retx** ✓ |

## Test suite

`cargo test --release`: **825 passed, 0 failed, 2 ignored.**
- 814 prior tests unchanged.
- 11 new unit tests in `parser.rs`.

## Behavior preservation

The classification enum (`ArpClassification::{NotArp, OtherArp,
Reply}`) preserves the prior caller contract that ANY ARP frame is
recycled (ARP doesn't transit through the firewall) but only replies
update the dynamic neighbor cache + kernel neighbor table. Codex
investigation flagged this as a swap-vulnerable area — the explicit
enum makes the intent compiler-checked.

The NDP NA path was simpler — fall through to normal IPv6 forwarding
either way. The only behavior preserved is "if Target Link-Layer
Address option is present, learn the MAC."

## Test command transcripts

```
$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5203 -P 12 -t 10'"
[SUM]   0.00-10.00  sec  27.3 GBytes  23.5 Gbits/sec    0             sender
[SUM]   0.00-10.01  sec  27.3 GBytes  23.4 Gbits/sec                  receiver

$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5203 -P 1 -t 5'"
[  5]   0.00-5.00   sec  4.04 GBytes  6.94 Gbits/sec    0            sender

$ sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -c 'iperf3 -c 172.16.80.200 -p 5202 -P 12 -t 10'"
[SUM]   0.00-10.00  sec  11.2 GBytes  9.58 Gbits/sec    0             sender
```
