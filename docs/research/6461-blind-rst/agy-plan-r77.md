VERDICT: PLAN YES


### Q1 (stable root + CAS): SOUND
- **Evidence:** `docs/research/6461-blind-rst/plan.md`: lines 5337–5365, 5368–5374, 5378–5380, 5408–5415, 8067–8074, 8096–8099.
- **Rationale:** The plan specifies that every cohort of a family shares a stable `root_id` derived from the canonical forward key's identity (lines 5337–5350). Publication serializes on an `EXPECTED-ROOT CAS` where an unexpected value causes backoff and reconciliation (lines 5351–5357). Exactly one publisher (the minting worker) confirms every domain before the root flip (lines 5358–5360), and independent-selector/per-value commit clauses are retracted (lines 5362–5365). Under 5-tuple reuse after family expiry, the root version counter is monotone and never reusable (lines 5408–5412). All dependent rows tag `(cohort_id, version)` and are visible only if `root.active_cohort_id == tag.cohort_id && root.version == tag.version` (lines 5369–5371). Old shadow rows carrying `(old_cohort_id, old_version)` fail version matching against the new family's root version and are identity-fenced for reclamation when no longer referenced by the root or any live dependent (lines 5378–5379, 5412–5415).

---

### Q2 (replacement protocol v2 + ledger TLV): SOUND
- **Evidence:** `docs/research/6461-blind-rst/plan.md`: lines 4104–4106, 4124–4136, 4143–4150, 4633–4645, 6030–6061, 6674–6685, 8075–8089.
- **Rationale:** Protocol versioning for capability bits (including BIT 6 for retirement-extension v2) uses the deterministic `MAX-COMMON-VERSION` `min(own_max, peer_max)` negotiation (lines 4633–4645, 6674–6685). Frame 42 (`FENCE_REPLACE_ACK`) is 40 bytes (lines 4104–4106, 8075–8076) and requires negotiated version ≥ 2 under active BIT 6 (lines 4124–4132). Peers negotiating v1 get the external-fencing fallback rather than partial replacements (lines 4126–4128). Section-3 ledger TLVs envelope byte-exact records carrying explicit `state` (0=Active, 1=Cleared) in the record (lines 6030–6040, 8081–8084). Frame 43 (`LEDGER_ACK`) is 16 bytes (lines 6040-6043, 8084-8085) and floors compaction strictly below the acknowledged high-water for `Cleared` records only (lines 6043–6047). When RG3 is removed and re-added, the re-added RG3 receives a new authority-issued `rg_incarnation` carried in synced config (lines 6048–6061), so stale fence records with the old `rg_incarnation` persist until cleared and compacted below the high-water without matching the new instance (lines 8059–8060, 8076–8088).

---

### Q3 (drain commit + cache revalidation + store floor): SOUND
- **Evidence:** `docs/research/6461-blind-rst/plan.md`: lines 5390–5412, 6120–6129, 6196–6220, 8089–8105.
- **Rationale:** The drain fence is held by a helper-side conditional commit of `(proof_generation, watermark)` (lines 6196–6198). Go lifts eligibility only after the helper's commit succeeds (lines 6206–6208). Any intermediate publish, retain, release, or shared-hit materialization (`session_glue/mod.rs:1092`) invalidates `proof_generation` (lines 6203–6205, 6216–6220), causing a racing commit to fail and reopening the proof. Bounded drain deadlines or failures abort the proof and reopen admissions without clearing the retirement fence (lines 6210–6215). Flow-cache hits tag `(cohort_id, version)` and revalidate against the root's current `(active_cohort_id, version)` via a single root read (lines 5390–5405), with monotone, non-reusable root versioning (lines 5408–5412). Notice-store tombstones compact below the acknowledged receiver/ledger high-water only after every attempt for that namespace is retired, maintaining a durable replay floor (lines 6120–6129, 8101–8105).

---

### NEW Traces Folded Open in v9.9.54.31

1. **Frame 42 Size Specification Error** (`plan.md:4104-4106`, `plan.md:8075`):
   - *Trace:* v9.9.54.30 specified `FENCE_REPLACE_ACK` (Frame 42) as 36 bytes, which contradicted the 5×u64 field layout (`authority_incarnation`, `target_incarnation`, `new_retirement_generation`, `supersedes_authority_incarnation`, `supersedes_retirement_generation`).
   - *Resolution:* Corrected to exactly 40 bytes (5×u64).

2. **Section 3 Ledger Record Missing State Field** (`plan.md:6037-6040`, `plan.md:8081-8084`):
   - *Trace:* v9.9.54.30 omitted the explicit state byte from the "byte-exact" ledger record payload, making it impossible for a receiver to distinguish `Active` from `Cleared` records during deserialization.
   - *Resolution:* Added explicit `state u8 (0 = Active, 1 = Cleared)` into the byte-exact record header (`plan.md:6034`).

3. **Capability Confirm Order Relative to Slot Install** (`plan.md:4307-4313`, `sync_conn.go:130`):
   - *Trace:* Phrasing suggesting capability exchange ran "post-install" contradicted `sync_conn.go:130` where immediate `ClockSync`/cold-prime dispatch follows wrapper installation.
   - *Resolution:* Clarified that `CAPABILITY_CONFIRM` occurs inside the authenticated wrapper before slot installation.
