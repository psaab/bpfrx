I will check our current permissions to determine if we can read the repository files.
I will request read permission for the target repository to view the files needed for our plan review.
I will read the round-2 verdict file `docs/research/1879-install-simplify/agy-plan-r2.md` first to check the exact comments and requirements from the previous round.
I will search for `SAFE-BOOTSTRAP` in `docs/research/1879-install-simplify/plan.md` to locate the relevant section of the plan.
I will view the contents of `docs/research/1879-install-simplify/plan.md` starting around line 540 to examine the daemon work and the `SAFE-BOOTSTRAP` steps.
I will search for `9. Tests` or unit test sections in the plan to check the test specifications.
I will read the test plan section (lines 840-965) of `docs/research/1879-install-simplify/plan.md`.
### 1. Verification of Required Change 1: PCI-Keyed Lifeline Tracking & Dynamic Resolution

* **SAFE-BOOTSTRAP step 1 (lines 617–623):** The plan explicitly specifies that the lifeline record is keyed by PCI bus address (with MAC address as a tiebreaker for non-PCI NICs) instead of interface name. It defines that the protected-set evaluation dynamically resolves the recorded PCI address to the device's current name at compile/reconcile time.
* **Step 2 (lines 635–637):** Configures `xpfd` to record the PCI bus address + MAC of the default-route interface to `/etc/xpf/lifeline-interface` at first start.
* **Step 4a (lines 717–721):** Configures `enterBootstrapMode` to match the post-rename interface name via the PCI-keyed record, ensuring that even if NIC names persist after a rollback, the lifeline `.network` file is correctly generated under the renamed name.
* **Section 9 Tests (lines 857–858, 860–864):** Specifies unit tests for "PCI-keyed lifeline resolution across a rename" and integration test **T1** (*rollback-restores-lifeline*) validating both DHCP and static management configurations post-rollback.

Required Change 1 is fully and adequately specified.

---

### 2. Verification of Required Change 2: Rollback-to-Empty Bootstrap Persistence

* **Step 0 second bullet (lines 595–608):** Restricts the rollback from writing an empty committed tree to the config store. It introduces a "committed-generation marker / absence of active record" to distinguish a system that has "never-successfully-committed" from one where the operator deliberately committed an empty config.
* **Step 3 Predicate (lines 659–677):** Formulates the no-committed-config predicate cases. It guarantees that the post-rollback-from-first-commit state stays in bootstrap mode, and explicitly notes that the predicate is stable across daemon restarts (i.e., restarting after a timed-out first commit stays in bootstrap mode).
* **Section 9 Tests (lines 849–851, 855–857):** Incorporates unit tests for the five-case predicate matrix, as well as a restart stability check (*restart-after-timed-out-first-commit stays bootstrap*).

Required Change 2 is fully and adequately specified.

---

### 3. Confirmation of No New Holes

The edits made in v3 successfully resolve the round-2 findings without introducing new regression vectors or logical loops:
* The decision to defer the exact representation of the committed-generation marker and the mechanism of the address snapshotting is appropriate for a research-level plan, as the plan defines clear correctness constraints and establishes must-pass tests (e.g., T1 and the `applySem` serialization test) to validate the engineering phase.
* Persisting interface renames across rollback while dynamically resolving the lifeline via PCI/MAC address ensures the system avoids risky name-reversion link cycles while preserving operator reachability.

---

PLAN-READY
