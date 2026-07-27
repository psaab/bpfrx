VERDICT: PLAN YES (third attempt — first two hit AGY infra timeouts, documented retries)


### Q1: v0 evidence + owner-echo commit — SOUND
- **Evidence**: `docs/research/6461-blind-rst/plan.md:4139-4185`, `docs/research/6461-blind-rst/plan.md:4313-4341`, `docs/research/6461-blind-rst/plan.md:4388-4395`, `docs/research/6461-blind-rst/plan.md:5399-5418`
- **Analysis**: 
  1. *Flag Handling*: For path (a), `min(own_max, 0) = 0` governs the repair class, but the capability record itself arrives in the authenticated `CAPABILITY_CONFIRM` frame (`plan.md:3990, 4068-4070`), exchanging bit 0 (identity enforcement) and bit 1 (lease input) so non-repair flags intersect normally (`plan.md:5417`). Path (b) arrives recordless (`min(own_max, absent) = v0`), so all flags remain 0.
  2. *ACK-Loss Asymmetry*: `CAPABILITY_DECISION` (ID 33) and `CAPABILITY_DECISION_ACK` (ID 34) commit before session dispatch (`plan.md:4193-4196`: `hello → proof → wrapper → CONFIRM declarations → CAPABILITY_DECISION + ACK → slot install → session dispatch/cold-prime`). If the ACK is lost in transit, the owner times out and closes the stream (`plan.md:4198, 4225-4235`). No session frame or cold-prime data dispatches in the RTT window prior to slot installation.

### Q2: RW-fence cutoff + Prepared→Applied — SOUND
- **Evidence**: `docs/research/6461-blind-rst/plan.md:4737-4788`, `docs/research/6461-blind-rst/plan.md:4913-4944`
- **Analysis**:
  1. *Hot-Path Cost & Bounding*: Admissions acquire read permits prior to NAT allocation (`poll_descriptor/mod.rs:2142`) through publication and journal receipt. The fence write-side drains in-flight workers, while new admissions receive `drop-without-RST` without blocking (`plan.md:4748-4756`).
  2. *Fence Deadline under Load*: A fence deadline failure triggers a clean abort (`plan.md:4782-4788`), unsealing the fence, retaining Primary ownership on A, and bumping the repair obligation (`poll_descriptor/mod.rs:2449`). It does not proceed unsealed while demoting.
  3. *Prepared Replay vs. Lease Expiry*: Replays of `Prepared` state run prior to election or status answers (`plan.md:4924-4926`). Lease expiry auto-restoration checks the commit record (`plan.md:4951-4954`) and revalidates with the peer before promotion, preventing stale re-election.

### Q3: Heartbeat fencing + reconciliation truth — SOUND
- **Evidence**: `docs/research/6461-blind-rst/plan.md:4599-4613`, `docs/research/6461-blind-rst/plan.md:5069-5094`
- **Analysis**:
  1. *Liveness-Only & Partitioned Owner*: The heartbeat carries sender incarnation and retired-incarnation generation (`plan.md:5077-5079`). Unvalidated/retired incarnations are treated as liveness-only and ignored during elections until quiescence + reseed + fence clearance (`plan.md:5080-5083`). A still-live partitioned owner requires external fencing (`plan.md:5085-5088`), demoting itself on sight when the surviving node advertises retirement.
  2. *Post-Release Await*: Synchronous config apply performs side-effect-free PURE validation (`daemon_apply_tail.go:42`), enqueues an immutable snapshot generation, and awaits the specific generation's completion after permit release (`plan.md:4605-4609`). The drainer re-reads desired state dynamically, and promotion re-checks include detach/tombstone generations (`plan.md:4609-4613`).

### New Traces Folded Open in v9.9.54.21
None. The v9.9.54.21 refinements resolve all open boundary conditions without creating new race paths.
