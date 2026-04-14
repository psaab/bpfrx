# Manual Failover Transfer-Commit Validation

Date: 2026-04-02

Validated commit:

- `310a2399` `cluster: preserve transfer-out override until commit`

Related PRs:

- `#396` manual failover request/ack handshake
- `#397` manual failover transfer commit

Related issue:

- `#398` manual failover still times out while requester is in bulk sync receive

## Goal

Validate that manual redundancy-group moves no longer depend on heartbeat
observation for completion after `#397`.

## Environment

- env: `test/incus/loss-userspace-cluster.env`
- cluster: `xpf-userspace-fw0` / `xpf-userspace-fw1`
- branch under test: `origin/master`
- requester / target commands run with local `cli`

## What Was Tested

### 1. Initial live attempt while requester was still in bulk receive

Command:

```bash
incus exec loss:xpf-userspace-fw0 -- \
  cli -c 'request chassis cluster failover redundancy-group 0 node 0'
```

Result:

- failed
- requester returned:
  - `rpc error: code = FailedPrecondition desc = timed out waiting for peer failover ack for redundancy group 0`

Why it failed:

- the requester (`fw0`) was still in reconnect bulk receive
- the peer (`fw1`) kept retrying pre-failover admission
- each retry failed on the session-sync barrier because the requester did not
  answer barrier acks during that bulk window

Representative logs:

- requester `fw0`:
  - `cluster sync: bulk receive progress epoch=4 sessions=64`
  - `cluster sync: bulk receive progress epoch=4 sessions=128`
  - `cluster sync: bulk receive progress epoch=4 sessions=192`
- responder `fw1`:
  - `cluster: bulk sync not acked yet, verifying peer readiness via barrier`
  - `cluster: waiting to admit manual failover ... err="session sync not ready before demotion: peer not responding to barrier: timed out waiting for session sync barrier ack ..."`

This is a separate residual problem and is tracked in `#398`.

Artifacts:

- `/tmp/rg0-transfer-commit-validation-20260402-093415`
- `/tmp/rg0-transfer-commit-validation-rerun-20260402-093552`

### 2. Settled-cluster RG0 move from `node1 -> node0`

Precondition:

- `fw0` takeover-ready `yes`
- `fw1` primary for `RG0`
- bulk receive complete on `fw0`

Command:

```bash
incus exec loss:xpf-userspace-fw0 -- \
  cli -c 'request chassis cluster failover redundancy-group 0 node 0'
```

Result:

- success
- command output:
  - `Manual failover completed for redundancy group 0 (transfer committed)`
- post-state:
  - `fw0` primary for `RG0`
  - `fw1` secondary for `RG0`

Runtime proof that this did not wait for heartbeat observation:

- on `fw0` the logs show, in the same second:
  - `cluster sync: failover ack received ... status=0`
  - `cluster: primary transition rg=0`
  - `cluster sync: failover commit sent to peer`
  - `cluster sync: failover commit ack received ... status=0`
- on `fw1` the logs show:
  - `cluster sync: remote failover request received rg=0 req_id=3`
  - `cluster: manual failover rg=0`
  - `cluster sync: failover result sent ... status=0`
  - `cluster sync: remote failover commit received rg=0 req_id=3`
  - `cluster sync: failover result sent ... msg_type=18 ... status=0`

That is the new request/ack/commit/commit-ack protocol doing the completion,
not delayed heartbeat re-evaluation.

Artifact:

- `/tmp/rg0-transfer-commit-validation-settled-rerun-20260402-093809`

### 3. Reverse settled-cluster RG0 move from `node0 -> node1`

Command:

```bash
incus exec loss:xpf-userspace-fw1 -- \
  cli -c 'request chassis cluster failover redundancy-group 0 node 1'
```

Result:

- success
- command output:
  - `Manual failover completed for redundancy group 0 (transfer committed)`
- post-state:
  - `fw1` primary for `RG0`
  - `fw0` secondary for `RG0`

This confirmed the new transfer-commit path works in both directions and left
the cluster back on the original `RG0` owner.

Artifact:

- `/tmp/rg0-transfer-commit-validation-reverse-20260402-093830`

## Conclusion

`#397` does what it was supposed to do on a settled cluster:

1. manual RG moves no longer complete by waiting for heartbeat observation
2. completion happens on explicit sync-channel failover ack and failover
   commit ack
3. both directions succeed immediately for `RG0`

What is still not fixed:

1. manual failover can still be rejected before the new transfer protocol runs
2. the blocker is the pre-failover admission path while the requester is in
   active reconnect bulk receive
3. that residual gap is tracked in `#398`

## Practical reading of the result

The new transfer-commit design is valid.

The remaining failure mode is no longer "manual failover depends on heartbeat
timing". The remaining failure mode is "manual failover admission still depends
on session-sync bootstrap state".
