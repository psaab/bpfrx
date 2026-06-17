# #1930 INC-2 (external HA kernel-rolling) — validation

## Unit / logic (green)
- `go build ./...`, `go vet`, gofmt clean (my files).
- pkg/upgrade self-recovery: 7 tests (recover-after-grace, active-lease-suppress,
  expired/other-node lease, not-drained no-op, unhealthy-peer no-op,
  timer-reset-on-lapse).
- pkg/cluster + pkg/upgrade full suites green (HA suite, no regression).
- `xpf-deploy.py kernel-roll --dry-run`: full sequence verified
  (lease-on-both → drain → arm+reboot → poll promoted== → rejoin → release;
  node0 then node1; correct node-ids + lease JSON).

## Cluster no-regression (loss userspace cluster, serialized lock cell)
- INC-2 binary DEPLOYED to both nodes (verify-dataplane PASS gate); `make
  cluster-deploy` succeeded.
- Post-deploy LIVE cluster state (direct evidence of NO failover regression from
  the INC-2 self-recovery loop + cluster predicates):
  - fw0 RG0 = PRIMARY, Takeover-ready: yes, Transfer-ready: yes; node1 secondary.
  - HA protocol matched both nodes; sync clean; build g9d11d8ee6 on both.
  - fw0 → iperf target (172.16.80.200) = 0% packet loss (the dataplane forwards
    with the INC-2 binary).
- `make test-failover` could NOT complete its iperf phase: its preflight `die`d
  at "Cannot reach iperf3 target" because the target fixture
  `userspace-wan80-vf-host` is STOPPED and cannot start — its SR-IOV VF pool
  (eno6v3) is held by another agent's RUNNING `t1921-*` VMs (shared-host SR-IOV
  contention, NOT an INC-2 effect; I must not touch another agent's VMs). The
  failover MECHANISM is healthy (fw0 primary + takeover-ready + forwards); only
  the iperf reachability precheck is blocked by the external resource conflict.

## Cross-node kernel reboot-roll (bench/manual — documented per directive)
A true cross-node kernel reboot-roll reboots BOTH nodes in sequence on the
SHARED loss cluster — disruptive to other agents and gated on the same SR-IOV
target being up. The per-node boot mechanics (firmware-cleared BootNext one-shot,
promote-on-success / fail-rollback through a real reboot) are ALREADY
live-proven on the standalone Ubuntu 26.04 UEFI Secure-Boot VM in INC-1
(docs/pr/1930-inc1-kernel-channel/live-validation.md). INC-2 adds only the
cross-node SEQUENCING (lease, drain, version-check, rejoin, never-both-down),
whose logic is covered by the unit tests + the driver dry-run. A full live
cross-node roll is bench/manual: stand up a private two-VM HA pair (not the
shared loss cluster) with the target host up, then
`xpf-deploy.py kernel-roll --node A --node B --version <ver>` and confirm the
peer keeps forwarding across each node's reboot. Recorded as the remaining
manual step; not run here to avoid disrupting the shared cluster + the
unavailable SR-IOV target.
