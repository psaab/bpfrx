VERDICT: PLAN YES


### Q1 (cohort root + dual slots)
**SOUND**
- **File:Line Evidence**: `docs/research/6461-blind-rst/plan.md:5233–5256`, `5256–5265`, `5266–5277`, `5210–5212`
- **Analysis**:
  - Aliases/companions carry only the `cohort_id` tag and are resolved by following the tag to the forward session row cohort ROOT, taking the root's `(commit_bit, payload)` verdict (`:5246–5249`). Publication writes all dependencies first (`smp_wmb` barrier) and flips the root bit last (`:5250–5255`).
  - Single-value `userspace_sessions` map uses dual slots with an atomic `ACTIVE-SLOT SELECTOR` (`:5256–5265`). Schema migration runs under a loader-version pin with dual-write or snapshot + delta catch-up (`:5266–5275`).
  - Reverse-path/fragment lookups and flow-cache entries tag with `cohort_id` and follow the root (`:5275–5277`). Packet-matchable state rides the staging namespace where packets never match staged/pre-commit state (`:5210–5212`), eliminating cached pre-commit visibility windows.

---

### Q2 (quiescence proof + ledger schema)
**SOUND**
- **File:Line Evidence**: `docs/research/6461-blind-rst/plan.md:5927–5946`, `5837–5869`
- **Analysis**:
  - Release of an excess RG fence requires a generation-tagged `QUIESCENCE PROOF` verifying quiescence across VRRP instance state, VIP ownership, dataplane forwarding, and session ownership (`:5936–5939`). Any apply error retains the whole fence (`:5940–5941`). Proof reading and fence transitions are serialized with election (`:5942–5945`), preventing race windows between proof generation and fence removal.
  - The ledger schema is cluster-config-carried with records `(authority incarnation, retirement generation, target incarnation, scope, state)` operating under monotone `Active → Cleared` transitions (`:5850–5853`). Merge is UNION by record identity `(authority incarnation, generation)` (`:5854–5857`), and full-config absence/replacement never erases runtime ledger state (`:5860–5865`).

---

### Q3 (RELEASE_PENDING + conditional sequences + notice lifecycle + atomic replacement)
**SOUND**
- **File:Line Evidence**: `docs/research/6461-blind-rst/plan.md:5182–5198`, `4461–4478`, `4121–4137`, `4158–4175`
- **Analysis**:
  - `CLOSING/RELEASE_PENDING` is persisted before canonical unpublication as an allocation-retaining, non-publishable record (`:5192–5194`). On crash/restart recovery, rehydration finishes the release and never republishes (`:5194`).
  - Sequence is `CONDITIONAL`: `CAPABILITY_DECISION` and ACK fire iff the negotiated class is v2 (`min() >= 2`) (`:4461–4470`). Decision phase completes before session dispatch / cold-prime (`:4477–4480`).
  - Keyed notice store persists before summary/PONR, waking on insertion, merge, adoption, capability activation, and retry (`:4128–4131`). Lifecycle transitions via `Pending → InFlight → AwaitingClearance` CAS (`:4132–4136`).
  - Reissued retirements explicitly name `supersedes = (old_authority_incarnation, old_retirement_generation)` (`:4164–4166`). Receiver B installs F2 and ACKs it before F1 tombstone is written (`:4166–4169`), executed as a crash-recoverable stage ledger (`:4170–4172`).

---

### NEW Traces Folded Open in v9.9.54.29

1. **Per-Cohort Root Single Bit Flip for Multi-Value Cohorts** (`docs/research/6461-blind-rst/plan.md:5233–5256`)
   - *Trace*: Updating distinct BPF map entries across separate `bpf_map_update_elem` calls exposes intermediate state to packets mid-flip.
   - *Resolution*: Data values carry only `cohort_id` tag; forward row acts as single cohort ROOT containing `(commit_bit, payload)` flipped last behind an `smp_wmb` barrier.

2. **Quiescence Validation on Partial Configuration Apply Failures** (`docs/research/6461-blind-rst/plan.md:5928–5946`)
   - *Trace*: Config apply failing VRRP validation while stripping an RG from cluster membership satisfies membership set equality while the VRRP master instance remains live.
   - *Resolution*: Fencing release requires quiescence proof across all surfaces (VRRP, VIP, dataplane, session ownership); any apply error retains the complete fence.

3. **Cluster-Carried Ledger Schema Union Merge** (`docs/research/6461-blind-rst/plan.md:5841–5869`)
   - *Trace*: Config-sync using scalar generations permits delayed predecessor updates to overwrite successor state or erase ledger fences upon full-config sync.
   - *Resolution*: Ledger section is normative and additive, keying records by `(authority incarnation, generation)` with monotone `Active → Cleared` transitions and union merge by identity.

4. **`RELEASE_PENDING` Tombstone Crash Ordering** (`docs/research/6461-blind-rst/plan.md:5185–5198`)
   - *Trace*: Expiry removing canonical session before NAT release leaves live `INSTALLED` receipts on crash, causing mandatory restart rehydration to republish expired sessions.
   - *Resolution*: Persist `CLOSING/RELEASE_PENDING` prior to canonical removal so recovery completes teardown rather than republishing.

5. **Conditional Protocol Sequence Gating** (`docs/research/6461-blind-rst/plan.md:4462–4470`)
   - *Trace*: Unconditionally emitting frame 33 `CAPABILITY_DECISION` forces transcript-v2 pairs negotiating repair-v1 into reconnect loops.
   - *Resolution*: Frame 33 emission/expectation is conditional on mutually derived tentative v2 (`min() >= 2`).

6. **Notice Store Insertion Edge Wake** (`docs/research/6461-blind-rst/plan.md:4121–4132`)
   - *Trace*: Notice inserted while capability Bit 6 is already active produces no edge trigger, causing its summary to fence the target indefinitely.
   - *Resolution*: Delivery state machine wakes on insertion, merge, adoption, activation, and retry.

7. **Predecessor-Named Atomic Fence Replacement** (`docs/research/6461-blind-rst/plan.md:4159–4175`)
   - *Trace*: Tombstoning predecessor fence F1 before installing F2 creates a fence-free window; installing F2 without explicit predecessor reference leaves F1 permanently fenced if authority restarts.
   - *Resolution*: Reissue names `supersedes = (old_authority_incarnation, old_retirement_generation)`; receiver installs F2 and ACKs prior to writing F1 tombstone via idempotent stage ledger.
