# xpf-userspace-fw deploy verification

Runbook for verifying a fresh build on `loss:xpf-userspace-fw`. This is the
only cluster in active scope. Every deploy — full master, single-commit
cherry-pick, revert — runs through the same five checks in the same order.

## Why this exists

`loss:xpf-userspace-fw` runs mlx5 SR-IOV VFs on kernel 7.0.0-rc7+.
Forwarding-path changes that look safe on other test beds (virtio on a
Debian-stable kernel, for example) have broken on this cluster in ways
that show up only under live traffic. A checked-in runbook that names
the four things that actually distinguish "healthy" from "silently
broken" means:

- a deploy regression is caught in under a minute, not after the
  operator hits a bug by surprise,
- any future contributor can redeploy and verify without reverse-
  engineering the signals from commit messages,
- the verification references the same commands the codebase already
  ships, so it stays runnable as the repo changes.

The first time this mattered was the #767 regression: a freshly-deployed
post-#759 build dropped forwarding to zero on mlx5, and the diagnostic
steps below were how we confirmed the rollback. Subsequent deploys use
the same procedure.

## Prerequisites

- `source ~/.sshrc` on the dev host so `gh` + `incus` auth work.
- The target cluster is `loss:xpf-userspace-fw` (node0 + node1). Primary
  is determined by VRRP priority; current convention is node0 at
  priority 200, node1 at 100.
- `loss:cluster-userspace-host` is up with address `10.0.61.102/24`
  and default route `10.0.61.1` (the RG1 VIP on xpf-userspace-fw).
- iperf3 server listens on `172.16.80.200` ports 5201 (iperf-a class
  — 1 Gbps `transmit-rate exact`) and 5202 (iperf-b — 10 Gbps).
- CoS config from `test/incus/cos-iperf-config.set` must be committed
  on the primary. `test/incus/apply-cos-config.sh loss:xpf-userspace-fw0`
  is the canonical applier. Re-apply after any deploy because the
  deploy path wipes config (see `docs/engineering-style.md`
  project-specific reminder).

## Deploy

```bash
source ~/.sshrc
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

Rolling deploy: secondary first, primary second. Wait for
`==> Deploy complete for xpf-userspace-fw0.` before starting the
verification. Then re-apply the CoS config (see Prerequisites).

## The five checks

### 1. Sanity ping

```bash
sg incus-admin -c "incus exec loss:cluster-userspace-host -- ping -c 5 -W 2 172.16.80.200"
```

**Pass**: 0% loss, RTT ≤ 1 ms (typical 0.3–0.5 ms on this topology).

**Fail indicators**:
- Loss > 0% after the first packet (ARP settle is allowed on packet 1).
- RTT jumps to tens or hundreds of milliseconds. The #767 regression
  showed 279 ms / 346 ms / 33% loss — if you see this, jump straight
  to Rollback.

### 2. Single-flow throughput (`-P 1`)

```bash
sg incus-admin -c "incus exec loss:cluster-userspace-host -- iperf3 -c 172.16.80.200 -P 1 -t 30 -p 5201 -i 3"
```

**Pass**: every 3-second interval reports non-zero throughput. The
flow should settle somewhere around 1.5–1.7 Gb/s on current master
(#760 overshoot is still open; a single flow is not yet held at the
1 Gbps `transmit-rate exact` cap). Retrans per 30 s should be
≤ ~250 K with no sustained stalls.

**Fail indicators**:
- Any 3 s interval reporting 0 bps (the #767 signature is an entire
  30 s run at 0 bps after the connection handshake).
- Aggregate avg ≤ 500 Mb/s — that's not the pre-existing overshoot
  pattern, it's a different broken mode.
- Receiver bytes ≠ sender bytes by more than ~5%.

### 3. Parallel fair-share throughput (`-P 16`)

```bash
sg incus-admin -c "incus exec loss:cluster-userspace-host -- iperf3 -c 172.16.80.200 -P 16 -t 30 -p 5201 -i 3"
```

This is the workload #754 was measured on. Per-stream distribution
matters as much as aggregate.

**Capture**:

- aggregate throughput across all 16 streams,
- per-stream mean / min / max / stddev / CoV%,
- retrans per stream.

**Pass**: aggregate ~1.5 Gb/s or higher (not yet held at cap — see
#760), per-stream CoV ≤ ~30% (tighter is better; bimodal
distribution — e.g. 7 flows at one rate and 9 at another — is a
failure mode the #754 fix in #768 should prevent).

**Fail indicators**:
- Any stream returning 0 bps for ≥ 3 s while others transmit — that
  indicates per-flow starvation which #768 was supposed to end.
- Bimodal distribution of the #754 shape (roughly two distinct rates
  that flows pin to).
- Aggregate below ~700 Mb/s while ECN marking is firing frequently —
  classic over-throttle pattern.

### 4. No error spam in the journal

```bash
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- journalctl -u xpfd --since '30 sec ago' --no-pager" \
  | grep -iE 'error|fail|warn|DBG SEG_MISS|connection refused|key too big'
```

**Pass**: empty or only VRF-rebind / neighbor-resolution INFO lines.

**Fail indicators**:
- `DBG SEG_MISS[N]: ...` printed repeatedly — the Rust helper is
  hitting a segmentation-fallback path. This was the fingerprint of
  the #767 regression on mlx5.
- `ha watchdog write failed ... connection refused` looping — the
  helper died and isn't being restarted.
- `failed to compile dataplane` — the compile-time fault path from
  #758 (post-#766 /health should also return 503 in this case; spot
  check via `curl -fsS http://127.0.0.1:8080/health` if available).
- `userspace dataplane status sync failed ... key too big for map`
  — the original #756 BPF-map-cap crash reappearing.

### 5. CoS counter health

```bash
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- /usr/local/sbin/cli -c 'show class-of-service interface reth0'"
```

Snapshot the iperf-a queue (queue 4) counters before the tests and
again after a 30 s run. Compute deltas.

**Pass** (post-#768 baseline, single 30 s `-P 1` flow):

- `Drops: flow_share` delta: 0 or very low (tens, not thousands).
- `Drops: buffer` delta: 0.
- `Drops: ecn_marked` delta: roughly 0.5–1.5% of packets sent. At
  ~850 K pps sustained for 30 s, this is ~100 K–300 K marks.
  Anything >> 1 M marks per 30 s is the pre-#768 over-marking
  pattern — file or re-open a #754 follow-up.

**Fail indicators**:

- `Queued pkts` non-zero at the end of the test — queue is stuck
  parked when it should be empty. Cross-check against `Next wake`
  (huge future ns values are a known bad sign).
- `Drops: flow_share` in the millions — admission rejecting so
  aggressively that TCP can't progress.
- `peer_pps` / `owner_pps` both zero while traffic was flowing —
  the queue isn't actually being serviced by the userspace-dp worker;
  the packets went via fallback. Check `userspace_fallback_stats`
  (`bpftool map dump pinned /sys/fs/bpf/xpf/userspace_fallback_stats`)
  for which fallback reason fired.

## Pass criteria (summary)

All five checks pass in order. Any single-check failure stops the
verification and triggers Rollback before further investigation.

## Rollback

The last known-good build for this cluster is `e8e7533a` (pre-#759
master + #768 ECN tune applied on top). Keep a locally-built binary
from that tag handy during any risky deploy. Rebuild from source
is ~30 seconds:

```bash
git checkout e8e7533a -- .
make build
make build-userspace-dp
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
  ./test/incus/cluster-setup.sh deploy all
```

Re-apply CoS config after rollback deploys too — same as the
forward-deploy path.

Confirm recovery with check 1 and check 2 only; full verification
can wait until after the regression is diagnosed.

## References

- #767 — the regression that motivated this runbook; mlx5 + kernel
  7.0.0-rc7 incompatibility with #759's DEVMAP_HASH conversion.
- #756, #759 — the fix that introduced the #767 regression; context
  for why future deploys need this check.
- #754, #768 — the ECN threshold tune whose effect is measured by
  check 5.
- #760 — the single-flow overshoot. Expected-to-fail-to-cap behaviour
  in check 2 and check 3 until this is fixed.
- `docs/cos-validation-notes.md` — the decision tree for mapping
  CoS counter patterns to root causes. Check 5's "fail indicators"
  cross-reference that document.
- `test/incus/cos-iperf-config.set` — the CoS fixture checks 2–5
  depend on.
- `test/incus/apply-cos-config.sh` — applier that survives
  deploy-wipes-config.
