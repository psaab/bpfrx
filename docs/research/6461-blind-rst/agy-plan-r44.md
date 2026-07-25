AGY r44 review — infra ledger: out1 timeout, out2 timeout, out3-q12 timeout, out4-q45 timeout (4 documented timeouts). The r44 mechanism set (rejection convergence, preflight ordering, §5.8 consolidation + setup ownership + helper replace, one deadline + quarantine) is fully covered by the r45 review below, which evaluates the same mechanisms at v9.9.36 against the same code.

=== AGY r45 (full, subsumes r44) ===
VERDICT: PLAN YES

### Q1 (rejection convergence): SOUND
- **Evidence:** `docs/research/6461-blind-rst/plan.md:1727-1748`
- **Analysis:** 
  - **Set Bounds & Availability:** The pending-rejection set is latched per cohort (deduplicated by `(flow key, SessionIdentity)`) and bounded by shared-table capacity (`plan.md:1729-1731`). Blind packets cannot pin readiness down because they fail earlier at identity/generation validation before reaching reservation (`plan.md:1731-1734`). Wide-config skew causing missing standby cohorts properly degrades HA readiness as designed (`plan.md:1734-1737`).
  - **Release Path Coverage:** Total coverage is guaranteed by placing a single notification hook at the hold cell's zero-transition point (`plan.md:1737-1742`), which is the single release path shared by reap, rollback, GC, migration, and conversion.

---

### Q2 (preflight ordering): SOUND
- **Evidence:** `docs/research/6461-blind-rst/plan.md:1708-1718`
- **Analysis:** 
  - **In-flight Commit Drain:** Freezing admissions halts *new* commits while letting in-flight slow-path commits complete (`plan.md:1710-1712`). That completed drain *is* the quiesce step (`plan.md:1712-1713`).
  - **Preflight Precision:** Because local table size $L$ cannot change during the frozen interval post-drain, repeating the capacity and NAT-conflict preflight inside the frozen interval counts all drained in-flight commits exactly (`plan.md:1713-1715`).

---

### Q3 (§5.8 consolidation + setup ownership + helper replace): SOUND
- **Evidence:** `docs/research/6461-blind-rst/plan.md:1348-1354`, `docs/research/6461-blind-rst/plan.md:1500-1511`, `docs/research/6461-blind-rst/plan.md:3666-3718`
- **Analysis:** 
  - **Wire Schema & Capabilities:** Section 5.8 consolidates all repair frames, capability fields, markers, and receipt/discharge logic (`plan.md:3666-3718`). `JOURNAL-END` is enforced as the sole valid discharge predicate (`plan.md:3706-3708`), discarding delayed pre-obligation ACKs.
  - **Setup Ownership:** The address-ordered owner dials a single tie-broken connection carrying both directional reset triples (`plan.md:1348-1351`).
  - **Helper Replace & Epoch Validation Cost:** Helper `replace(slot, T1, T2, token_epoch)` is atomic (`plan.md:1505-1509`). On unreachable helper, the transaction fails completely without mutating slot state, leaving T1 live for retry. Epoch check cost on publication is a single atomic load (`plan.md:1509-1511`), incurring negligible overhead on the hot path.

---

### Q4 (one deadline + quarantine): SOUND
- **Evidence:** `docs/research/6461-blind-rst/plan.md:1757-1776`, `docs/research/6461-blind-rst/plan.md:2450-2459`
- **Analysis:** 
  - **One Deadline & Generation Retention:** A single deadline encompasses quiesce, handoff, and join (`plan.md:1758-1763`). Upon expiry, rebuild aborts safely and retains old generations until actual worker exit (`plan.md:1765-1768`).
  - **Operability & Terminal State:** Retaining old generations makes the terminal state recoverable via subsequent reconcile retries with fresh generations (`plan.md:1772-1774`). The state is operator-visible through existing reconcile-stage reporting (`plan.md:1770-1772`). Force-killing stuck workers is explicitly rejected to avoid kernel-state corruption (`plan.md:1774-1776`).
  - **Quarantine & Supersession:** The quarantine state resides within the canonical `synced` lock domain (`plan.md:2450-2453`), ensuring publication and cancellation are executed within a single critical section. Different-identity publication triggers terminal supersession, purging old quarantine entries (`plan.md:2453-2459`).

---

### Open Traces / New Issues
None. The consolidated mechanisms in v9.9.35/v9.9.36 close all analyzed race conditions without opening new unhedged traces.
AGY EXIT: 0
