# Userspace AF_XDP Idle Softirq Starvation

## Symptom

On `loss:bpfrx-userspace-fw0`, the isolated userspace cluster could show nearly 100% softirq CPU with no intentional test traffic:

- `ksoftirqd/0..3` near 100%
- `%si` near 100%
- `bpfrx-userspace-dp` itself at low single-digit CPU

This looked like the host was spinning in the kernel while the Rust dataplane was mostly idle.

## What Was Actually Wrong

There were two separate bugs.

### 1. AF_XDP RX fill-ring starvation

The helper burned through its initial XSK RX fill stock and was not keeping the fill ring replenished aggressively enough.

Evidence from `ge-0-0-2` on `bpfrx-userspace-fw0`:

- `rx_xsk_packets` plateaued around the initial fill budget
- `rx_xsk_buff_alloc_err` then increased by millions in a few seconds
- `/proc/softirqs` `NET_RX` climbed rapidly even with no meaningful forwarding load

That means mlx5/NAPI was repeatedly trying to allocate AF_XDP receive buffers and failing. The kernel softirq path stayed hot even though there was little real work for the Rust helper to do.

### 2. Shared-UMEM restart regression

The fill-ring fix added spare RX frames per binding, which increased the per-worker UMEM size from a power-of-two value to a non-power-of-two value.

Before the spare-frame change, a worker with two `8192`-entry bindings had a total UMEM descriptor budget of `16384`, which mlx5 accepted.

After the spare-frame change, the same worker used `28672` descriptors. mlx5 then rejected `fq/cq` creation with `EINVAL`, so the helper came up disarmed or unbound after restart.

Symptoms of the restart regression:

- helper showed `Bound bindings: 0/8`
- helper showed `Enabled: false`
- bindings reported `configure AF_XDP rings: create fq/cq: Invalid argument`

## Fixes

### Fill-ring starvation fix

Implemented in commit `aefed32`:

- added spare per-binding RX fill frames
- changed fill draining to replenish from both:
  - recycled RX frames
  - spare fill frames
- stopped treating a temporary zero insert as a hard runtime error

Code: [userspace-dp/src/afxdp.rs](/home/ps/git/codex-bpfrx-userspace-wip/userspace-dp/src/afxdp.rs)

### Shared-UMEM ring-size fix

Implemented in commit `5086741`:

- rounded shared UMEM `fill_size` / `complete_size` to a power of two before `fq_cq()` creation
- kept the spare-frame design without breaking AF_XDP bring-up on mlx5

Code: [userspace-dp/src/afxdp.rs](/home/ps/git/codex-bpfrx-userspace-wip/userspace-dp/src/afxdp.rs)

## Verification

After both fixes on `bpfrx-userspace-fw0`:

- helper re-armed and rebound successfully:
  - `Enabled: true`
  - `Bound bindings: 8/8`
  - `XSK-registered bindings: 8/8`
- idle `NET_RX` drift became small over 2 seconds
- `rx_xsk_buff_alloc_err` stayed flat over 2 seconds
- short traffic test from `cluster-userspace-host` to `172.16.80.200` showed live userspace forwarding again:
  - `~14.17 Gbps`
  - helper `RX/TX/session/NAT` counters advanced normally

## Operational takeaway

For this branch, shared-UMEM AF_XDP on mlx5 has two hard constraints:

1. The fill ring must keep a spare stock of RX buffers available, not just recycled frames.
2. Shared UMEM `fill_size` / `complete_size` must remain power-of-two values acceptable to mlx5.

If either constraint is violated, the branch can appear either:

- alive but pinned in `ksoftirqd`, or
- clean but silently fallen back out of the userspace dataplane.
