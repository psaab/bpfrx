### Round 1 Required Changes Verification

1. **Daemon-side `SetCentralRollbackHandler` Registration**: **Addressed.** Section 5 (SAFE-BOOTSTRAP step 0, lines 559-567) explicitly specifies registering the rollback handler unconditionally in the daemon process, wired to `d.applyConfig`.
2. **Protected Management Interface Exemption**: **Addressed.** Section 5 (SAFE-BOOTSTRAP step 1, lines 575-589) defines the protected set as a union of the `management-interface` leaf, the default `fxp0`, and the `lifeline-interface` record. It moves enforcement to the networkd/dataplane compiler reconcile layer outside the config tree itself.
3. **Honest M1 Cost Split**: **Addressed.** Section 5 (Path D, lines 519-527) splits the phase into M1a (Debian packaging/wrapper, ~3-5 days) and M1b (SAFE-BOOTSTRAP daemon logic + fixes + tests, ~1-2 weeks).

---

### Adversarial Findings on New v2 Mechanisms

#### 1. [Critical] docs/research/1879-install-simplify/plan.md:580
* **Title**: Lifeline Rename Mapping Gap during Rollback-to-Empty
* **Details**: If the lifeline interface is not `fxp0` (e.g., `eth1` at PCI slot 1) and gets renamed to `em0` during the first commit, the lifeline record in `/etc/xpf/lifeline-interface` will still store the original name `eth1`. When a commit-confirmed timeout rolls back the store to the empty tree, the `system management-interface` leaf is absent. The protected set is evaluated as `{fxp0, eth1}`. However, since the interface is currently named `em0`, it is excluded from the protected set. Reconciling the empty configuration will treat `em0` as unmanaged, stripping its IP addresses and bringing the link down, causing an operator lockout.
* **Mitigation**: Track the lifeline interface by its PCI bus address (e.g., `0000:05:00.0`) in the record, and resolve its current name dynamically during protected-set compilation.

#### 2. [High] docs/research/1879-install-simplify/plan.md:626
* **Title**: Reboot after Rollback Hazard (Case 4 Predicate loophole)
* **Details**: A timeout rollback to the synthesized bootstrap config writes an empty tree `{}` to the config DB. On a subsequent daemon restart, Case 4 of the predicate ("empty active DB (committed-but-empty tree) → NOT bootstrap") will classify the state as NOT bootstrap. The restarted daemon will exit bootstrap mode, rename all PCI NICs, and perform a full networkd/dataplane takeover on an empty configuration, causing links to cycle and potentially locking out the operator.
* **Mitigation**: Treat a completely empty configuration tree as equivalent to the initial bootstrap state (bootstrap mode = true), or record a persistent flag/metadata in the database indicating whether a valid configuration has ever been successfully committed.

---

### Verdict

PLAN-NEEDS-REVISION: 1. Track the lifeline interface via its PCI bus address or dynamically resolve its renamed name during protected-set compilation to prevent lockout on rollback-to-empty. 2. Classify a completely empty config tree as bootstrap mode (or track a persistent "has-ever-committed" flag) so that a rollback-to-empty state remains in bootstrap mode across daemon restarts.
