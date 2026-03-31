## Userspace XDP Mode And Cold-Start Findings

Date: March 30, 2026

This note separates two different forwarding problems that were showing up as
"userspace forwarding is broken" on the HA lab:

1. a real XDP attach-mode / AF_XDP bind-mode correctness bug
2. a separate first-probe cold-start drop on the active owner

They are related operationally, but they are not the same bug.

### 1. XDP attach mode and AF_XDP bind mode were inconsistent

#### What was happening

On the userspace HA lab, one interface could fail native XDP attach:

- `ifindex=4` logged `native XDP not supported`

The old compiler behavior then downgraded the whole userspace dataplane to
generic XDP instead of only the failed interface.

At the same time, the userspace helper chose AF_XDP zero-copy vs copy mode from
the NIC driver name alone. That meant:

- `mlx5` interfaces in `xdpgeneric` mode could still be treated as zero-copy
- the helper would attempt the wrong bind strategy for the actual attach mode

#### Why that broke forwarding

When the dataplane fell back to `xdpgeneric`, helper bind policy still assumed:

- `virtio_net` => copy/auto
- `mlx5` => zero-copy

That is only valid when the interface is actually running native XDP. Under
generic XDP, the helper must not blindly reuse the native/zero-copy path.

The result on the HA lab was straightforward:

- traffic to `172.16.80.200` from `cluster-userspace-host` failed in steady
  state
- local connectivity from the firewall itself could still work
- cluster control-plane state looked healthy even though forwarding was broken

#### Fixes

Two fixes address this:

- `#294` / PR `#295`
  - the helper now checks actual XDP attach mode with `bpf_xdp_query()`
  - if attach mode is generic:
    - `virtio_net` stays on the generic-safe path
    - non-virtio interfaces are forced to copy mode instead of zero-copy
- `#293` / PR `#296`
  - native attach failure now falls back to generic per interface
  - it no longer forces all userspace interfaces to generic mode

#### Validated behavior

With the `#295` + `#296` stack deployed:

- `ge-7-0-0` remained `xdpgeneric`
- `ge-7-0-1` and `ge-7-0-2` stayed native `xdp`
- helper bind logs matched that split:
  - interface `4`: copy mode
  - interfaces `5` and `6`: zero-copy
- forwarded host traffic to `172.16.80.200` recovered

This was the main steady-state forwarding break.

### 2. Cold-start first-probe loss is a separate bug

#### What is still happening

Even after the attach-mode / bind-mode fix, the active owner still shows a
first-probe drop when the path is cold.

Clean live repro on the `#296` baseline:

1. `RG1` primary on `node1`
2. delete the owner neighbor entry for `172.16.80.200` on `ge-7-0-2.80`
3. send one host ping from `cluster-userspace-host`

Observed result:

- first ping: loss
- immediate second ping: success
- neighbor reappears as `STALE` / `REACHABLE`

So the remaining issue is no longer "steady-state forwarding is broken." It is:

- first forwarded packet to a cold destination can still be lost
- the path then warms and traffic succeeds

#### Likely code gap

Issue `#288` remains the strongest code-level explanation:

- `retry_pending_neigh()` only checked `dynamic_neighbors`
- normal forwarding resolution uses the full neighbor view through
  `lookup_neighbor_entry(...)`

That mismatch means a buffered pending-neighbor packet can still miss a usable
neighbor entry that is already visible through the forwarding snapshot.

#### Current fix candidate

Local commit:

- `3e80b425` `userspace: retry pending neighbor packets from full view`

Change:

- `retry_pending_neigh()` now resolves neighbor MACs through the same full-view
  lookup used by normal forwarding resolution

Unit coverage:

- `pending_neighbor_retry_uses_snapshot_neighbor_view`

#### Validation status

The unit test is solid.

Live validation is not complete enough to call this fixed yet.

Reason:

- the cleanest live repro for `#288` is a helper restart where the kernel still
  retains the destination neighbor entry, but the helper's dynamic-neighbor map
  starts empty
- in the current lab, the restart sequence has not preserved that neighbor
  state consistently enough to prove or disprove the fix directly

So the honest current state is:

- diagnosis: narrowed and defensible
- code fix: written and unit-tested
- live proof: not yet complete

### Operational takeaway

These findings should be treated separately during HA testing:

1. `#295` + `#296` are correctness fixes that should be part of the failover
   test baseline
2. the cold-start first-probe drop is still an open issue and should be tracked
   independently from the XDP bind-mode bug

If HA tests still show a one-packet cold miss after `#295` + `#296`, that is
not evidence that the bind/XDP-mode fix regressed. It is a different bug class.
