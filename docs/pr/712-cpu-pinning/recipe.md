# CPU pinning + IRQ isolation recipe for xpfd (#712 Option A)

This doc is operator-facing. It describes the CPU layout xpfd expects on
hosts of 2, 4, 6, and 8+ cores — specifically which CPUs carry NIC
hardware interrupts, which carry kernel housekeeping, and which run the
userspace-dp workers. It also spells out what is **not** in the recipe:
those are either deferred to a separate option in #712 or out of scope.

Read `docs/cos-validation-notes.md` §"CPU pinning layout for the loss
lab" and §"CPU pinning retry post-#740" before applying this recipe.

The first attempt (#737) measured `CPUAffinity=` as a no-op because
userspace-dp re-pinned its workers to absolute CPUs 0..N-1 via
`sched_setaffinity`. That was fixed in #740; workers now pick the Nth
entry of the inherited mask. The retry (#741) re-ran the measurement
with the fix in place and confirmed that workers land on the intended
CPUs 2-5 — but no aggregate metric moved by the #712 thresholds on the
6-core loss lab. The recipe below is kept as design intent; it is
validated as correctly applied, not as a measurable win on this
hardware. The next lever is Option B (kernel cmdline `isolcpus=` +
`nohz_full=`, tracked at #739).

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

**Measured effect on the loss lab:** no-op, in both phases.

- **First attempt (#737):** workers ignored the mask via
  `pin_current_thread`'s absolute-CPU bug; the measured deltas
  confirmed the bug rather than the pinning.
- **Retry (#741) after #740 fix:** workers correctly pin to CPUs 2-5
  (`taskset -p` reports `0x3c`, per-thread `Cpus_allowed_list=2-5`,
  `psr` under load ∈ {2,3,4,5}). Rerun of the 3 × 30 s × 16-flow iperf3
  fixture still showed no aggregate metric moving by the #712
  thresholds. Rate ratio went from 1.37× → 1.40× (+2%, within noise),
  retrans 210 k → 234 k (+11%, within noise), per-flow CoV mean
  16.8% → 16.2% (-0.6 pp, within noise), CoV max 26.8% → 28.5%
  (+1.7 pp, within noise). Per #712's keep/revert/defer table the
  directive was reverted.

The recipe is the right layout for the hardware; on a 6-core VM where
every CPU already carries NIC IRQ load (comp0..5 spread 1-per-CPU on
both mlx5 and virtio queues), moving workers to a subset of CPUs that
still share IRQ load with the kernel does not reduce jitter. The next
lever is Option B (kernel cmdline `isolcpus=` + `nohz_full=`) which
removes kernel timer + softirq work from the worker CPUs entirely —
tracked at #739.

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

Expected after a fresh apply on a 6-core host, post-#740:
- `taskset -p` of xpfd → mask `0x3c` (CPUs 2-5)
- Per-thread `cpus_allowed`: all xpfd + dp aux threads show `2-5`
- Per-thread `cpus_allowed` for `xpf-userspace-w[0-3]`: shows
  `2 / 3 / 4 / 5` — the #740 fix makes `pin_current_thread` pick the
  Nth entry of the allowed mask, so workers land inside the unit-level
  mask.
- `psr` under load: all non-worker threads on 2-5; workers on 2/3/4/5
  one-to-one.
- Verified live on 2026-04-17 during the #741 retry.

## Historical blocker: worker-pin logic overrode systemd CPUAffinity

Before #740, `pin_current_thread(worker_id)` in
`userspace-dp/src/afxdp/neighbor.rs` called
`sched_setaffinity(0, … CPU_SET(worker_id % nproc))`. On a process
whose `CPUAffinity=` was `2 3 4 5`, `available_parallelism()` reported
4 correctly, but the loop pinned to absolute CPU `worker_id % 4` —
i.e. CPU 0, 1, 2, 3 — not to the 0th, 1st, 2nd, 3rd CPU of the allowed
set. The result: hot-path workers ignored systemd's mask.

**Fixed in #740.** `pin_current_thread` now calls `sched_getaffinity`,
enumerates the allowed CPUs, and pins to `allowed[worker_id % count]`.
Verified live during the #741 retry — workers report
`cpus_allowed_list=2-5` and `psr ∈ {2,3,4,5}` under load.

The blocker is not on the layout any more; it is on the hardware.
On a 6-core VM where NIC IRQs distribute one-per-CPU across all 6
CPUs (mlx5_comp0..5 and virtio-input.0..5 each carry hundreds of
millions of interrupts per run), moving workers onto a subset of
CPUs that still share IRQ load with the kernel does not reduce
jitter. The layout is correct; the hardware needs a stronger lever
to surface the improvement — see #739 for Option B kernel cmdline
(`isolcpus=` / `nohz_full=` / `rcu_nocbs=`) which actually evicts
timers and RCU callbacks from worker CPUs.

## Refs

- #712 — umbrella CPU pinning issue. This recipe implements Option A.
- `docs/cos-validation-notes.md` — measurement methodology and the
  no-op finding on the loss lab (both attempts).
- #737 — first attempt at Option A; measured no-op because of the
  worker-pin bug.
- #740 — fix for `pin_current_thread` to pick the Nth entry of the
  allowed mask.
- #741 — retry of Option A after #740; measured no-op on aggregate
  metrics despite workers now landing on CPUs 2-5 as intended.
- #739 — Option B kernel cmdline (`isolcpus=` + `nohz_full=`), the
  next lever to try on this hardware.
