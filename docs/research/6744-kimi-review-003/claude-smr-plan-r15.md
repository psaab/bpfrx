# Claude SMR / independent fallback plan review - round 15

The Claude Code CLI was attempted against the immutable checkout but failed
before analysis with the account monthly-spend-limit error. No Anthropic-model
verdict is claimed. The verdict below is from a separately identified,
non-Anthropic independent SMR-method fallback.

**Independent fallback verdict: PLAN-NEEDS-MAJOR**

Review target: detached, locked, clean checkout at
`47b32a033e756316e5c24ba1e74442e58047968a`.

## Findings

1. **CRITICAL - static-DNAT mutation is not atomic with config promotion.** A
   successful map transition can be followed by a mutation-free
   `PromotePreparedActive` generation conflict, leaving old active config with
   new static DNAT. The inverse ordering can leave new active config with old
   DNAT after rollback. One transaction must span static-map mutation, store
   promotion, compensation, and failed-apply debt on local and peer paths.
2. **HIGH - promoted authority has no unique export owner.** Promoted rows are
   replicated to every worker, but `LocalAuthoritySource::Promoted` identifies
   no canonical worker. Provenance-only worker export therefore emits duplicate
   canonical members. Define one canonical promoted owner or explicitly
   non-exportable replicas, including worker loss/rebind behavior.
3. **HIGH - same-key ordinary mutations across fabrics lack an in-flight
   ordering state machine.** A higher generation can mutate the helper while a
   lower generation has not committed its Go ledger/journal result, allowing
   reversed completion or an incorrect predecessor descriptor. Reserve a key
   through final commit/discharge or define a bounded generation-CAS
   predecessor chain.

Workstreams A-H and J-M were accepted. Workstream I is blocked by the three
findings above. No additional blocker was found in v2 crash recovery,
worker-loss epochs, the in-band seal, tail frame/byte limits, authority
namespace transitions, capacity factors, or TailAck/barrier ordering.

Final verification found the checkout locked, detached, and clean at the exact
target; staged and unstaged diffs were empty. No file, issue, or PR was modified.
