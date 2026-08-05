# Claude SMR / independent fallback plan review - round 16

The Claude Code CLI was attempted against the immutable checkout but failed
before analysis with this account error:

```text
You've hit your monthly spend limit - raise it at claude.ai/settings/usage?from=cc_cli_limit_message
```

No Anthropic-model verdict is claimed. The verdict below is from a separately
identified, non-Anthropic independent SMR-method fallback.

**Independent fallback verdict: PLAN-NEEDS-MAJOR**

Review target: detached, locked, clean checkout at
`0533766f6dda9f71268314e67dc83d5ff4d6bfbb`.

## Findings

1. **CRITICAL - existing startup cleanup destroys evidence before inventory and
   capsule creation.** `LoadUserspaceShim` and `CompileUserspaceShim` unlink
   legacy map pins and TC links, while userspace `Manager.Compile` removes XDP
   pins before the new migration controller could inventory, retain, or journal
   them. A final `PROG_ARRAY` user reference can disappear and an unproved hook
   can be detached into apparent absence.
2. **CRITICAL - durable `Link.Update` contradicts native AF_XDP restart.** The
   production mlx5 path intentionally performs a fresh XDP attach so the driver
   initializes XSK receive queues from the new fill ring. Updating a retained
   link after daemon/helper replacement can leave native RX dead even though
   program, map, and journal checks pass.
3. **HIGH - hook inventory misses stale hooks on off-config interfaces.** TCX
   queries cover only currently compiled managed ifindices. A prior-generation
   attachment on a still-live interface removed from configuration can remain
   executable and absent from every declared discovery source.

All scheduler liveness, receive-barrier, graph traversal, historical-write
isolation, exact v2 proof, static-DNAT authority, tuple escrow, tail ordering,
capacity, deadline, and config/RG/helper contracts were otherwise accepted.
Workstreams A-H and J-M were accepted; Workstream I remains blocked.

Final verification found detached HEAD at the exact target, with empty staged
and unstaged diffs. The fallback reviewer modified no files.
