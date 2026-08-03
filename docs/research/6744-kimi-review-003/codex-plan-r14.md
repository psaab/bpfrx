# Codex hostile plan review - round 14

**Verdict: PLAN-NEEDS-MAJOR**

Review target: detached, locked, clean checkout at
`df53c23111385e84178d4025788468e82b58d31a`.

## Findings

1. **CRITICAL - v2 migration can permanently wedge because cleanup requires a
   repair that cannot occur.** The plan keeps the undersized legacy map in the
   dual-publish set until capable repair, but standalone nodes and mixed-version
   peers cannot complete capable repair. After cutover, 65,536 four-alias
   sessions fill the 262,144-row legacy map; the next valid v2 admission makes
   legacy publication fail permanently. Retire legacy dual-publish after every
   link uses v2, old-program leases join, and a local barrier proves v2. Peer
   repair may gate continuity, but not obsolete-map retirement.
2. **CRITICAL - NAT reservations are released after mutations may already have
   escaped.** A shared/BPF/worker prefix can survive a partial batch while the
   plan rolls the tuple reservation back, allowing a local flow to reuse the
   still-live peer tuple. Reservations must be escrowed across ambiguity until
   all-surface cleanup or transferred to the surviving session.
3. **HIGH - the authoritative export has no mechanical proof against
   worker-local delta loss.** A full worker delta ring can drop a post-scan
   Delete before sequence allocation; another resync can consume the Boolean
   loss latch, after which a contiguous boundary incorrectly certifies a stale
   snapshot. Use a monotonic per-worker loss epoch captured at export admission
   and proved unchanged at WorkerDone, or emit Abort for any observed loss.
4. **HIGH - the receiving-topology capacity proof omits occupants and production
   maps.** `dnat_table{,_v6}` hold static compiler rows in addition to dynamic
   reverse-SNAT rows, and config apply writes new static rows before deleting
   stale rows. The plan also omits the persistent `sessions` and `sessions_v6`
   surfaces from occupancy/readback/shrink tests. Reserve static DNAT occupancy
   additively and explicitly inspect/test both kernel session families.

Workstreams A-H and J-M were accepted. Workstream I was blocked by the four
findings above.

Final checkout verification remained detached and clean at the exact target;
staged and unstaged diffs were empty and the reviewer modified no files.
