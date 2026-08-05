# Codex hostile plan review - round 16

**Verdict: PLAN-NEEDS-MAJOR**

Review target: detached, locked, clean checkout at
`0533766f6dda9f71268314e67dc83d5ff4d6bfbb`.

## Findings

1. **BLOCKER - the historical object closure is mutable after its receipt.**
   Keeping object references does not freeze topology-bearing map entries. An
   unknown holder can change a `PROG_ARRAY`, `CPUMAP`, `DEVMAP`, or map-in-map
   edge after the capsule walk; a paused historical invocation can then miss its
   tail call and take the legacy `XDP_PASS` fallthrough. External topology
   writers must be excluded before the walk and the closure must be revalidated
   after the freeze.
2. **BLOCKER - shared derived BPF keys lack last-owner semantics.** Persistent
   any-remote-host flows can share a translated tuple and therefore one DNAT
   key. Session aliases likewise have 1:N ownership. Per-session deletion can
   remove a key still needed by another live session. The design needs bounded
   derived-key owner sets/refcounts, canonical value selection, insert-first/
   delete-last transitions, and migration set semantics.
3. **BLOCKER - baseline and tail have conflicting execution owners.** The plan
   both queues mutations to fixed scheduler workers and invokes the same batches
   synchronously from the receive loop. Literal composition double-applies
   operations. An inline interpretation also blocks heartbeat decoding during a
   valid multi-thousand-chunk bulk and causes the peer to close the connection.
4. **BLOCKER - `expectedAttachType` is not observable program identity.** Linux
   `bpf_prog_info` and cilium/ebpf `ProgramInfo` do not report the program's
   load-time expected attach type. Hook attach type is link/query context and
   cannot identify unattached tail-call or device-map children.
5. **BLOCKER - hook discovery omits formerly managed interfaces.** Limiting TCX
   queries to currently compiled ifindices misses a valid provenance-recorded
   attachment on an interface removed from current config. The query universe
   must include every live interface plus pinned, provenance, and Manager-held
   candidates, with classic-TC coverage too.
6. **BLOCKER - dependency-waiter expiration has no terminal transition.** The
   plan specifies neither duration, clock, nor start point. Retaining the
   admission token after timeout blocks the barrier needed for repair; recycling
   it silently loses an admitted operation. A typed transfer into terminal
   repair debt is required.
7. **BLOCKER pending product decision - complete HA exceeds the 10M map ceiling
   at nine workers.** With the documented arithmetic, nine workers require
   10,485,760 shim rows before nonzero tail reserve. The plan must impose an
   approved creation/worker cap, enlarge or restructure the map, or explicitly
   drop support for that topology.
8. **BLOCKER - config publication lacks a same-connection paired-write API.**
   `QueueCommittedConfig` cannot guarantee config plus type-29 request on one
   exact connection under one continuous `writeMu`. Reusing current helpers
   either recursively locks or allows connection replacement between writes.

Workstreams A-H and J-M were accepted. Workstream I is blocked by the eight
findings above. Round-15 release/acquire phases, handoff export, static-DNAT
authority, promoted ownership, and ordinary same-key serialization were
accepted as materially addressed.

Final verification found detached HEAD at the exact target, with empty staged
and unstaged diffs. The reviewer modified no files.
