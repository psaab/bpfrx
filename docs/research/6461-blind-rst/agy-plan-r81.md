VERDICT: PLAN NO


### Q1 (transfer CAS + selector): SOUND
* **Evidence:** `docs/research/6461-blind-rst/plan.md:6680-6687`, `docs/research/6461-blind-rst/plan.md:5717-5728`, `docs/research/6461-blind-rst/plan.md:8819-8833`
* **Analysis:** The lookup captures the drain generation $G$ inside the same read/RCU lock section that clones the session entry (`plan.md:6680-6681`). The transfer CAS validates $\{global\ intent, discovered\ RG, lookup\ generation\ G, drain\ still\ open\ at\ G\}$ before the entry can be used (`plan.md:6682-6687`), preventing lifts from racing between lookup and transfer. For double-buffered root records, the selector flip is the atomic commit point; readers checking checksums fall back safely or take the documented operator-visible error/slow path (`plan.md:5720-5728`).

---

### Q2 (predecessor vector + floor ACK): UNSOUND
* **Evidence:** `docs/research/6461-blind-rst/plan.md:4186-4195`, `docs/research/6461-blind-rst/plan.md:6530-6537`, `docs/research/6461-blind-rst/plan.md:8835-8844`
* **Analysis:**
  1. **Frame size bound:** `supersedes_count u8` (`plan.md:4186`) permits up to 255 predecessor tuples (over 4 KB). Under rapid operator churn merging many predecessors into one replacement, the resulting Frame 41/42 can exceed the maximum frame size of the sync channel. No frame-chunking mechanism or vector length upper bound is specified to guarantee transport safety and ACK atomicity.
  2. **Digest canonicalization & domain separation:** `vector_digest` is defined as `BLAKE2s-64` over the raw vector bytes (`plan.md:6534`). The plan omits specifying a canonical sort order (e.g., ascending by `rg_id`) for vector entries, causing identical vector sets serialized in different orders to produce mismatched digests and drop valid ACKs. It also lacks explicit domain-separation tags for the digest.

---

### Q3 (shared preflight + backfill): UNSOUND
* **Evidence:** `docs/research/6461-blind-rst/plan.md:4090-4106`, `docs/research/6461-blind-rst/plan.md:4145-4162`, `docs/research/6461-blind-rst/plan.md:4168-4174`, `docs/research/6461-blind-rst/plan.md:8847-8857`
* **Analysis:**
  1. **Ambiguous preflight lease discipline:** The text states "the promotion RE-VALIDATES the token inside the linearization ... OR the lease is HELD from preflight through promotion" (`plan.md:4157-4162`). Providing an un-adjudicated operative choice leaves promotion semantics underspecified. Furthermore, token re-validation only checks `config generation` rather than binding full candidate content hash identity, allowing generation collisions under concurrent promotion paths.
  2. **Backfill runtime adoption:** When upgrading a cluster with existing runtime RGs lacking an incarnation, the backfill assigns a new incarnation $I$ (`plan.md:4098-4103`). The design does not specify whether the initial adoption ($0 \to I$) is a free assignment or if it triggers a quiesced remove/re-add transaction, creating ambiguity on convergence (`plan.md:4168-4174`).

---

### NEW Traces Folded Open in v9.9.54.35

1. **Two-Copy Active Selector Mutation Race (`docs/research/6461-blind-rst/plan.md:5718-5726`)**
   * *Mechanism:* The writer writes copy A, checksums A, writes copy B, checksums B, and flips the selector to A last.
   * *Trace:* When the active selector currently points to B (the old committed copy), the writer updates copy B with *new* data before flipping the selector to A. A concurrent reader reading selector=B while copy B is being overwritten will read a torn/partially updated payload in B, causing checksum failures or unexpected reads of new data prior to the selector flip.

2. **Unsorted Floor Vector Digest Mismatch (`docs/research/6461-blind-rst/plan.md:6531-6537`)**
   * *Mechanism:* `FLOOR_SYNC_ACK` carries `vector_digest = BLAKE2s-64(rg_id, rg_incarnation, contiguous_high_water)`.
   * *Trace:* If sender and receiver iterate over multi-RG floor sync states in different key orders, `vector_digest` computation yields divergent hashes for equivalent vectors, causing spurious ACK rejections and stalled floor compactions.

3. **Unbounded Predecessor Vector Frame Overflow (`docs/research/6461-blind-rst/plan.md:4186-4195`)**
   * *Mechanism:* Frames 41 and 42 append `(supersedes_count u8, (authority_incarnation, retirement_generation) × count)`.
   * *Trace:* A sequence of $N$ merges can expand `supersedes_count` toward 255 entries without an explicit protocol max-count constraint, causing the frame payload to exceed max frame buffers and terminate the sync connection.
