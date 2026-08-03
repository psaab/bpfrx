# Claude SMR / independent fallback review - round 11

## Claude Code CLI attempt

The Claude Code CLI was invoked against immutable plan commit
`e316e5b0c193f844289a6a6aeb505929108a550a`, but failed before analysis:

```text
You've hit your monthly spend limit · raise it at claude.ai/settings/usage?from=cc_cli_limit_message
```

No Anthropic-model verdict exists for this round.

## Independent SMR-method fallback

Reviewer agent: `019fc8a6-0743-7dd3-8f23-d26873d7c21b`

This is explicitly an independent non-Anthropic SMR-method fallback, not an
Anthropic verdict. The reviewer verified a clean detached checkout at
`e316e5b0c193f844289a6a6aeb505929108a550a`, read all 2,918 plan lines and the
relevant production source, and made no file, branch, issue, or PR changes.

### Verdict

`PLAN-NEEDS-MAJOR`

### Material blockers

1. **A successful config callback can invalidate its own authority lease.**
   The callback can reach `cluster.UpdateConfig`, which runs election and
   publishes manager serial `S+1`, while the callback was admitted under `S`.
   Rejecting completion after the store/dataplane mutation splits the applied
   config from `acceptedConfigGen`, zone owners, and config-sync mode. The
   callback must join/adopt its child authority transition rather than discard
   a successful mutation.
2. **Exact same-generation replay has no enforceable sender or receiver state.**
   Production `QueueConfig` allocates on every send and revision 11 declared no
   digest/text/stage ledger. Sender-owned immutable committed config and an
   exact receiver failure record are required, together with supersession and
   context ownership rules.
3. **The lifecycle coordinator has no closable setup/data/lifetime worker
   partition.** Pre-registration authentication/capability work can fall outside
   the last-fabric drain, while one reusable WaitGroup can race Add against
   Wait or remain held by permanent loops.
4. **The restart worker can select promoted-but-uncommitted config and overlap
   old epoch workers.** It must consume an immutable fully applied runtime
   ledger and own/join every old cluster-comms descendant before starting a
   replacement epoch.
5. **The readiness notifier can invert sequence order under full-queue
   backpressure.** Allocating sequence under the gate and enqueueing after
   unlock allows `N+1` to enter before blocked `N`; serialized reservation is
   required before sequence publication.
6. **The bulk/repair token ledger is structurally incomplete.** Request records
   lacked process/config identity, no exact pending outbound-bulk token existed,
   and concrete timeout/rate limits were missing. Every causal completion needs
   exact transport/connection/process/role/authority/config/bulk/request/debt
   equality and bounded pressure.
7. **RG0 snapshot publication misses raw writers and direct positive acts.**
   Manual/batch failover, transfer completion, kernel hold, synchronous GARP,
   and direct daemon actuators can bypass a transition published only by normal
   election. Every local RG0 mutation must use one serialled manager API and
   every positive act must wait for exact final publication.

### Conditional approvals

The reviewer found workstreams A-H and J-M source-aligned and found the
helper-debt model, config/write ordering, ACK precommit, record-before-send,
bidirectional repair, dual-fabric fencing, capability setup, readiness split,
mixed-version restrictions, and inactive-first implementation stack coherent
subject to the blockers above.

### Required disposition

Round 11 does not converge. Revision 12 must close every blocker above and every
additional source-grounded Codex blocker before another immutable review.
