# AGY adversarial plan-review — round 27 (plan v27 @ 554c61356)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (5/5 folds FOLDED; 3 fresh attacks FAILED). Raw output follows verbatim.

---

(A) Fold verification:

1. FOLDED — `pkg/configstore/db.go:242-253`, `pkg/configstore/crypto.go:307-314,457-465`, and `docs/research/2114-nat-pool-alarm-dp-race/plan.md:833,1846,2081,2240,3636,4045`.
2. FOLDED — `docs/research/2114-nat-pool-alarm-dp-race/plan.md:791,841,1879,1889,4122`.
3. FOLDED — `pkg/configstore/crypto.go:443-465,473-479` and `docs/research/2114-nat-pool-alarm-dp-race/plan.md:845,1853,2094,2104,2236,2635,3635,4044`.
4. FOLDED — `pkg/configstore/crypto.go:34-35`, `pkg/configstore/store.go:302-305`, `pkg/daemon/daemon.go:1047-1052`, and `docs/research/2114-nat-pool-alarm-dp-race/plan.md:855,2089,2387`.
5. FOLDED — `pkg/configstore/store_commit.go:611-628`, `pkg/configstore/store_persist.go:397-401`, and `docs/research/2114-nat-pool-alarm-dp-race/plan.md:862-881,1946,2432,2991`.

(B) Fresh attacks:

- Hypothesis: Transient ACTIVE-side read failure (e.g. EACCES during a background rewrite) during a W restore attempt causes the generalized active-side gate to mis-classify and terminalize.
  Outcome: FAILED — `pkg/configstore/crypto.go:446-449` and `docs/research/2114-nat-pool-alarm-dp-race/plan.md:2016-2020,2087`. Transient active I/O errors are classified as TRANSIENT by the taxonomy; `persistRetryLoop` (`store_persist.go:397-428`) withholds the repair action for that pass, retains the debt, and retries without terminalizing.

- Hypothesis: After a process restart, `armedArmID` resets to `""` and process-local D debts are discarded; a post-restart interleave can recreate the "D alive beside a live window" state.
  Outcome: FAILED — `pkg/configstore/store_persist.go:140-253` and `docs/research/2114-nat-pool-alarm-dp-race/plan.md:1889,2266,2516-2523`. Boot recovery total order reads `confirm.json` before accepting commits. Any surviving readable, unexpired window re-arms immediately, setting `s.armedArmID = rec.ArmID` and restoring D suppression. Unreadable records at boot set the `RESTART-RECOVERY-OWED` latch with no D debt created.

- Hypothesis: Key-class failures vs. non-key-class permanent envelope errors are ambiguous or improperly surfaced during `ReadConfirm`.
  Outcome: FAILED — `pkg/configstore/crypto.go:307-356,443-465` and `docs/research/2114-nat-pool-alarm-dp-race/plan.md:2105-2107`. Key-dependent decryption failures (`gcm.Open` AEAD authentication failure and `len(data) != 32` key length errors) are cleanly wrapped by `ConfirmRecordKeyClassError`. Plaintext envelope version/PRF structural mismatches are non-key-class permanent errors, correctly taking the repair-write exemption because the payload is unparseable regardless of master key state.

Verdict: PLAN-READY
