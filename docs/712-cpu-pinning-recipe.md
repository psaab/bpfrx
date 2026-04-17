# CPU pinning + IRQ isolation recipe for xpfd (#712 Option A)

This doc is operator-facing. It describes the CPU layout xpfd expects on
hosts of 2, 4, 6, and 8+ cores — specifically which CPUs carry NIC
hardware interrupts, which carry kernel housekeeping, and which run the
userspace-dp workers. It also spells out what is **not** in the recipe:
those are either deferred to a separate option in #712 or out of scope.

Read `docs/cos-validation-notes.md` §"CPU pinning layout for the loss
lab" before applying this recipe — the loss userspace lab measurement
found that `CPUAffinity=` alone is a no-op on that hardware because
userspace-dp re-pins its workers internally. The recipe below is
written assuming that ceiling is eventually lifted (either by Option B
kernel cmdline, by a cgroup cpuset under Option D, or by a worker-pin
fix in #742). Until then, treat the recipe as design intent rather than
as something to cargo-cult onto a running firewall.

## What the recipe covers

| Layer | Where it is set | Knob |
|---|---|---|
| xpfd systemd unit CPU mask | `test/incus/xpfd.service` `[Service] CPUAffinity=` | Moves Go main + dp auxiliary threads off the NIC-IRQ CPUs. Does **not** move userspace-dp workers today. |
| NIC IRQ affinity | `/proc/irq/<n>/smp_affinity_list` at boot | Writes `0` (or `0-1`) into every mlx5/virtio-net completion IRQ so the kernel does not deliver them to worker CPUs. |
| Housekeeping CPU set | Implicit: the complement of `CPUAffinity=` | `ksoftirqd`, `kworker`, `chrony`, `sshd`, `systemd-journald`, and most other non-xpfd processes remain free to use the non-worker CPUs. |

## What the recipe does NOT cover

The following are **explicitly out of scope** for the recipe and belong
to either later options in #712 or to a future follow-up issue. Do not
add them as a "while we're here" change.

- `isolcpus=`, `nohz_full=`, `rcu_nocbs=` on the kernel cmdline. That is
  Option B (#712 retry or follow-up). It requires a kernel cmdline
  change and a reboot, so deployment shape has to be opted in.
- `SCHED_FIFO` / `chrt` on worker threads. That is Option C. It needs a
  watchdog story before it is safe to ship.
- cgroup v2 `cpuset.cpus` / `cpu.max`. That is Option D. Softer than
  isolcpus but still needs a deployment decision about which cpuset
  holds which process.
- `ethtool --set-rxfh-indir …` or `ethtool -L` to reshape RSS. That is
  orthogonal and affects where NIC IRQs fire on the hot path. Worth a
  separate issue if the NIC-IRQ → worker-CPU collision matters after
  Option A / B / D lands.

If you think you need one of these levers to make Option A stick, file
a new issue and cite this doc. Don't silently widen scope.

## Layout per CPU budget

The constants in the "Used by" column match the current userspace-dp
default (`--workers 4`, see `test/incus/cluster-setup.sh` → each VM
launches xpf-userspace-dp with 4 workers). Adjust if you change
`--workers`.

### 2-core host

Does not fit the recipe. xpfd needs at least one CPU for its Go
controller and one for the dataplane worker; reserving even one CPU for
IRQ + housekeeping leaves zero for the worker. Run without pinning and
accept the jitter. Consider scaling the host up.

### 4-core host (CPUs 0..3)

| CPU | Role | Who runs there |
|---|---|---|
| 0 | NIC IRQ + housekeeping | mlx5/virtio-net completion IRQs, `ksoftirqd/0`, `kworker/0:*`, systemd, journal, chrony |
| 1 | xpfd control plane | Go daemon main + ancillary goroutines (config reader, gRPC, CLI), xpf-userspace-dp aux threads (state-writer, event-stream, slowpath, neigh-monitor) |
| 2 | dp worker 0 | `xpf-userspace-w0` |
| 3 | dp worker 1 | `xpf-userspace-w1` |

With 4 userspace-dp workers, two workers share CPUs 2-3. Set
`--workers 2` if the hot-path latency of sharing a CPU is worse than
parallelism lost.

Unit directive:
```
CPUAffinity=1 2 3
```

IRQ pin (run at boot or via `ExecStartPre=`):
```
for irq in $(grep -E 'mlx|virtio.*-input|virtio.*-output' /proc/interrupts | awk -F: '{print $1}'); do
  echo 0 > /proc/irq/$irq/smp_affinity_list
done
```

### 6-core host (CPUs 0..5) — the loss userspace lab

| CPU | Role | Who runs there |
|---|---|---|
| 0 | NIC IRQ + housekeeping | Heaviest mlx5_comp* RX IRQ (comp0 at ~800 M over the run); ksoftirqd/0 |
| 1 | NIC IRQ + housekeeping | Second-heaviest mlx5 comp IRQ (comp1 at ~900 M); ksoftirqd/1; chrony; systemd |
| 2 | xpfd control + worker 0 | xpfd Go main + aux; `xpf-userspace-w0` |
| 3 | worker 1 | `xpf-userspace-w1` |
| 4 | worker 2 | `xpf-userspace-w2` |
| 5 | worker 3 | `xpf-userspace-w3` |

Unit directive:
```
CPUAffinity=2 3 4 5
```

IRQ pin at boot: pin NIC completion IRQs to CPUs 0-1:
```
for irq in $(grep -E 'mlx|virtio.*-input|virtio.*-output' /proc/interrupts | awk -F: '{print $1}'); do
  echo 0-1 > /proc/irq/$irq/smp_affinity_list
done
```

**Measured effect on the loss lab:** no-op, see
`cos-validation-notes.md` §"CPU pinning layout for the loss lab". The
recipe is the right layout for the hardware; the userspace-dp worker-pin
logic needs to honour the inherited affinity (new follow-up issue) or
the kernel cmdline needs isolcpus (Option B, also a follow-up) before
the layout lands as a win.

### 8-core host (CPUs 0..7)

| CPU | Role | Who runs there |
|---|---|---|
| 0-1 | NIC IRQ + housekeeping | All mlx5/virtio completion IRQs; ksoftirqd/0-1; systemd; chrony |
| 2 | xpfd control plane | Go daemon main + gRPC + dp aux threads |
| 3 | reserve / BGP | BGP / FRR / DHCP listener; no hot-path worker |
| 4-7 | dp workers 0-3 | One worker per CPU, 1:1 |

Unit directive:
```
CPUAffinity=2 3 4 5 6 7
```

IRQ pin at boot:
```
for irq in $(grep -E 'mlx|virtio.*-input|virtio.*-output' /proc/interrupts | awk -F: '{print $1}'); do
  echo 0-1 > /proc/irq/$irq/smp_affinity_list
done
```

## Verification

After applying the recipe, verify the mask made it through systemd:

```
# Process-level affinity mask (hex: 0x3c = CPUs 2-5, 0xfc = CPUs 2-7)
taskset -p $(pgrep -x xpfd)
taskset -p $(pgrep -f xpf-userspace-dp)

# Per-thread allowed CPU list
for tid in $(ls /proc/$(pgrep -f xpf-userspace-dp | head -1)/task); do
  comm=$(cat /proc/$(pgrep -f xpf-userspace-dp | head -1)/task/$tid/comm)
  aff=$(awk '/Cpus_allowed_list/ {print $2}' \
            /proc/$(pgrep -f xpf-userspace-dp | head -1)/task/$tid/status)
  echo "  $tid $comm cpus_allowed=$aff"
done

# Which CPU each thread is currently executing on
ps -eTo pid,tid,comm,psr,pcpu | grep -E 'xpfd|xpf-userspace|ksoftirq'

# NIC IRQ → CPU map
grep -E 'mlx|virtio.*input|virtio.*output' /proc/interrupts
```

Expected after a fresh apply on a 6-core host:
- `taskset -p` of xpfd → mask `0x3c` (CPUs 2-5)
- Per-thread `cpus_allowed`: all xpfd + dp aux threads show `2-5`
- Per-thread `cpus_allowed` for `xpf-userspace-w[0-3]`: **today** shows
  `0 / 1 / 2 / 3` because of the worker-pin logic in
  `userspace-dp/src/afxdp/neighbor.rs::pin_current_thread()`. After that
  logic is fixed, expect `2 / 3 / 4 / 5`.
- `psr` under load: non-worker threads on 2-5; workers on 0-3 today, on
  2-5 after the fix.

## Known blocker: worker-pin logic overrides systemd CPUAffinity

`pin_current_thread(worker_id)` in
`userspace-dp/src/afxdp/neighbor.rs` calls
`sched_setaffinity(0, … CPU_SET(worker_id % nproc))`. On a process
whose `CPUAffinity=` is `2 3 4 5`, `available_parallelism()` reports 4
(correct), but the loop pins to absolute CPU `worker_id % 4` — i.e.
CPU 0, 1, 2, 3 — not to the 0th, 1st, 2nd, 3rd CPU of the allowed set.
The result: the hot-path workers ignore systemd's mask.

Recipe options until that logic is fixed:

- **Leave `CPUAffinity=` unset.** This is what
  `test/incus/xpfd.service` ships today (see `#712 Option A` comment
  in the unit file). The recipe is design intent, not live policy.
- **Set `CPUAffinity=` anyway and pay the cost.** Non-worker threads
  move off the NIC-IRQ CPUs; workers stay put. On the loss lab this
  was measured as no better than unpinned (slightly worse within
  noise); on larger hosts with more CPUs the non-worker-thread share
  is small enough that the cost is invisible but so is the win.
- **Wait for the follow-up that fixes `pin_current_thread` to pick the
  Nth allowed CPU.** That is a one-line change to the helper; it is
  called out as a blocker here rather than folded silently into this
  recipe because it widens the scope beyond a systemd unit edit.

## Refs

- #712 — umbrella CPU pinning issue. This recipe implements Option A.
- `docs/cos-validation-notes.md` — measurement methodology and the
  no-op finding on the loss lab.
- `userspace-dp/src/afxdp/neighbor.rs::pin_current_thread` — the
  worker-pin call site that blocks Option A landing as a
  measurable win.
