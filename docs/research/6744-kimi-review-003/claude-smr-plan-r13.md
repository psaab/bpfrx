# Claude CLI attempt and independent fallback

The Claude Code CLI was invoked for round 13 but stopped before analysis with
the account monthly-spend-limit error:

```text
You've hit your monthly spend limit - raise it at claude.ai/settings/usage?from=cc_cli_limit_message
```

No Anthropic-model verdict exists for this round. The review below is an
independent, non-Anthropic SMR-method fallback and is not represented as a
Claude verdict.

# Independent SMR review

PLAN-NEEDS-MAJOR

## Findings

1. **Critical, blocking: helper side-effect lifetime ends before downstream
   session effects become generation-safe.**

   Under config C1, `export_owner_rg_sessions` or `drain_session_deltas`
   completes and validates its response. The helper registry entry is already
   removed. Pause before the daemon queues the returned deltas. A C2 transition
   closes the empty registry, promotes C2, and reopens SessionSync. The C1 caller
   resumes and queues its stale open/delete into current SessionSync, which
   stamps C2 authority. The peer cannot reject a C1 session invalidated by C2.

   Revision 13 unregisters at response decode/completion before later
   consumption (`plan.md:1264`, `plan.md:1274`, `plan.md:1328`), while the
   current APIs return unqualified deltas
   (`pkg/dataplane/userspace/manager_status.go:202`,
   `pkg/dataplane/userspace/protocol_ha.go:118`). Their callers queue those
   results later (`pkg/daemon/daemon_ha_userspace_export.go:51`,
   `pkg/daemon/daemon_ha_userspace_stream.go:438`) and SessionSync stamps the
   then-current config epoch (`pkg/cluster/sync_conn_gen.go:130`).

   The asynchronous EventStream has the same larger hole: frames may remain
   pending after helper completion (`pkg/dataplane/userspace/eventstream.go:938`)
   and callbacks then read the new active config
   (`pkg/daemon/daemon_ha_userspace_stream.go:199`). Workstream I needs a
   source-generation/authority token carried through final enqueue or a
   transition-drained event watermark.

2. **High, blocking: the userspace authoritative-bulk source has no executable
   completion contract.**

   The capable sender can close the producer gate, write `BulkStart`, invoke the
   existing full export, receive a successful control response, and write
   `BulkEnd` before Go consumes the Rust event-stream frames. Those callbacks
   enter the ordinary producer path outside the direct bulk window, so the
   receiver can reconcile an empty or partial set and ACK it.

   Revision 13 requires direct ordered members between `BulkStart` and
   `BulkEnd` (`plan.md:2944`) but retains `export_all_sessions` without defining
   a final sequence, count, or callback-applied watermark (`plan.md:1898`). Its
   Go API returns only an error (`pkg/dataplane/userspace/manager_ha.go:240`),
   while Rust returns after enqueueing deltas
   (`userspace-dp/src/afxdp/ha/export.rs:192`). Existing source already records
   that this asynchronous export cannot delimit an authoritative reconcile
   snapshot (`pkg/cluster/sync.go:409`, `pkg/cluster/sync_bulk.go:26`).

   The plan must bind an immutable owner-RG export result to
   `pendingOutboundBulk` and direct writes, or define a request-scoped terminal
   EventStream watermark. Implementors cannot be asked to invent this contract.

## A-M disposition

| Workstream | Disposition |
|---|---|
| A | PLAN-READY |
| B | PLAN-READY |
| C | PLAN-READY |
| D | PLAN-READY |
| E | PLAN-READY |
| F | PLAN-READY |
| G | PLAN-READY |
| H | PLAN-READY |
| I | PLAN-NEEDS-MAJOR: both findings above |
| J | PLAN-READY |
| K | PLAN-READY |
| L | PLAN-READY |
| M | PLAN-READY |

## Checkout verification

- `pwd=/home/ps/git/xpf-worktrees/6744-plan-r13-review`
- `HEAD=34619216673f66b1180274b50877f40628556999`
- detached HEAD
- worktree and index clean
- plan length: 4,653 lines
- no files modified

Fallback reviewer agent: `019fc922-c521-77f3-a1d6-a4a78b20f01e`.
