# Userspace Dataplane Debug Map

This is the compact file/function map for active debugging on current `master`.
Use it when forwarding is broken, throughput collapses after startup, or the
XDP shim and Rust helper disagree about who owns the packet.

## 1. Start Here

- XDP redirect and fallback decisions:
  - [userspace-xdp/src/lib.rs](/home/ps/git/codex-bpfrx/userspace-xdp/src/lib.rs)
- Go lifecycle, capability gate, and helper control:
  - [pkg/dataplane/userspace/manager.go](/home/ps/git/codex-bpfrx/pkg/dataplane/userspace/manager.go)
- Rust control loop and worker bring-up:
  - [userspace-dp/src/main.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/main.rs)
- Rust AF_XDP forwarding hot path:
  - [userspace-dp/src/afxdp.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs)
- Session installation and NAT reverse lookup:
  - [userspace-dp/src/session.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/session.rs)
  - [userspace-dp/src/nat.rs](/home/ps/git/codex-bpfrx/userspace-dp/src/nat.rs)
- Go-side HA/session-sync bridge:
  - [pkg/daemon/daemon.go](/home/ps/git/codex-bpfrx/pkg/daemon/daemon.go)

## 2. Symptom To File Map

### Packets never reach `bpfrx-userspace-dp`

Look at:
- [manager.go#L98](/home/ps/git/codex-bpfrx/pkg/dataplane/userspace/manager.go#L98)
- [manager.go#L202](/home/ps/git/codex-bpfrx/pkg/dataplane/userspace/manager.go#L202)
- [lib.rs#L279](/home/ps/git/codex-bpfrx/userspace-xdp/src/lib.rs#L279)
- [lib.rs#L526](/home/ps/git/codex-bpfrx/userspace-xdp/src/lib.rs#L526)

Questions:
- Did Go choose `xdp_userspace_prog` or `xdp_main_prog`?
- Is the capability gate forcing legacy fallback?
- Is the XDP shim redirecting, cpumap-passing, tail-calling, or dropping?

### Helper is up but bindings never become live

Look at:
- [manager.go#L2202](/home/ps/git/codex-bpfrx/pkg/dataplane/userspace/manager.go#L2202)
- [main.rs#L1228](/home/ps/git/codex-bpfrx/userspace-dp/src/main.rs#L1228)
- [main.rs#L1405](/home/ps/git/codex-bpfrx/userspace-dp/src/main.rs#L1405)
- [afxdp.rs#L1862](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs#L1862)

Questions:
- Did bootstrap maps get programmed correctly?
- Did the helper apply the snapshot and arm forwarding?
- Did AF_XDP bind or rebind fail after a link cycle?

### Session opens but reply traffic dies

Look at:
- [afxdp.rs#L4204](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs#L4204)
- [afxdp.rs#L3421](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs#L3421)
- [session.rs#L246](/home/ps/git/codex-bpfrx/userspace-dp/src/session.rs#L246)
- [nat.rs#L23](/home/ps/git/codex-bpfrx/userspace-dp/src/nat.rs#L23)

Questions:
- Is the helper parsing the authoritative 5-tuple from metadata or from the mutated frame?
- Is reverse NAT lookup hitting `nat_reverse_index`?
- Are rebuilt L4 ports coming from the session tuple or from stale frame bytes?

### Throughput starts high then falls to zero

Look at:
- [afxdp.rs#L1862](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs#L1862)
- [afxdp.rs#L1978](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs#L1978)
- [afxdp.rs#L5147](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs#L5147)
- [docs/afxdp-packet-processing.md](/home/ps/git/codex-bpfrx/docs/afxdp-packet-processing.md)

Questions:
- Is TX backpressure starving RX fill-ring replenishment?
- Are `pending_tx_local` or `pending_tx_prepared` growing without draining?
- Are completions being reaped fast enough to recycle frames?

### Idle softirq burn or AF_XDP stall

Look at:
- [docs/userspace-afxdp-idle-softirq-starvation.md](/home/ps/git/codex-bpfrx/docs/userspace-afxdp-idle-softirq-starvation.md)
- [afxdp.rs#L1978](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs#L1978)
- [afxdp.rs#L5014](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs#L5014)

Questions:
- Is the fill ring draining to zero?
- Are AF_XDP RX buffer allocation errors climbing?
- Are we spinning in backpressure without refilling?

### HA/session-sync looks wrong

Look at:
- [manager.go#L2127](/home/ps/git/codex-bpfrx/pkg/dataplane/userspace/manager.go#L2127)
- [daemon.go#L2798](/home/ps/git/codex-bpfrx/pkg/daemon/daemon.go#L2798)
- [daemon.go#L3002](/home/ps/git/codex-bpfrx/pkg/daemon/daemon.go#L3002)

Questions:
- Is forwarding armed on the actual primary?
- Are session deltas being drained from Rust and mirrored into Go/cluster sync?
- Is owner RG being preserved or falling back to zone-based sync?

## 3. Short Packet-Path Checklist

1. Did Go arm userspace forwarding?
   - [manager.go#L2127](/home/ps/git/codex-bpfrx/pkg/dataplane/userspace/manager.go#L2127)
2. Did the XDP shim redirect this packet to AF_XDP?
   - [lib.rs#L279](/home/ps/git/codex-bpfrx/userspace-xdp/src/lib.rs#L279)
3. Did the Rust worker parse the expected tuple?
   - [afxdp.rs#L4204](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs#L4204)
4. Was there a session hit, shared hit, or NAT-reverse hit?
   - [session.rs#L213](/home/ps/git/codex-bpfrx/userspace-dp/src/session.rs#L213)
   - [session.rs#L246](/home/ps/git/codex-bpfrx/userspace-dp/src/session.rs#L246)
5. Did NAT and FIB resolution produce a valid egress?
   - [nat.rs#L211](/home/ps/git/codex-bpfrx/userspace-dp/src/nat.rs#L211)
6. Did TX enqueue and drain without starving fill-ring recycle?
   - [afxdp.rs#L5147](/home/ps/git/codex-bpfrx/userspace-dp/src/afxdp.rs#L5147)

## 4. Validation And Capture Workflow

Use:
- [userspace-ha-validation.md](/home/ps/git/codex-bpfrx/docs/userspace-ha-validation.md)
- [userspace-perf-compare.md](/home/ps/git/codex-bpfrx/docs/userspace-perf-compare.md)
- [.codex/skills/iperf-grpc-tcpdump/SKILL.md](/home/ps/git/codex-bpfrx/.codex/skills/iperf-grpc-tcpdump/SKILL.md)

That workflow gives you:
- runtime mode detection
- sustained-throughput detection
- perf capture on the active userspace firewall
- synchronized firewall-side and server-side tcpdump when `iperf3` collapses
