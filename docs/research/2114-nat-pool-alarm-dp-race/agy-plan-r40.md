# AGY adversarial plan-review — round 40 (plan v40 @ 6cabbbe0a)

Direct agy print-mode invocation from the trusted workspace with --add-dir (see reviewer-ids.md infra notes). Verdict: PLAN-READY (6/6 folds FOLDED; 2 fresh attacks FAILED). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED — `store.go:738-746` confirms active persist failure sets `ActivePersistDegraded` while holding `confirm.json`, `cluster/sync.go:594-616` confirms local synchronous apply loop drain, and `plan.md:5513-5516` requires `ConfirmDebtKindMask == 0` AND `persistDegraded == false`.
2. FOLDED — `daemon_run.go:157-177` confirms `config-load-bootstrap` completes before manager/cluster init, and `plan.md:5504-5510` requires peer full-state clean preflight before peer stop and local startup prior to peer restart.
3. FOLDED — `daemon_ha_sync.go:774-785` confirms fabric fallback when control fields are unconfigured, and `plan.md:1486,3540,5508-5510` explicitly drops `down em0` in favor of universal process fencing.
4. FOLDED — `db.go:254-281` confirms unmarshal validation rejects degenerate records missing `Deadline` or `PrevTree` before checking `Resolved`, and `plan.md:5534-5540` specifies offline dead-record repair as removal preferred in all cases.
5. FOLDED — `db.go:284-315` confirms `DeleteConfirm` requires directory fsync via `rbSyncDir` after `rbRemove`, and `plan.md:5535-5537` specifies durable offline removal via `rm` followed by `sync -f` on `.configdb/`.
6. FOLDED — `store_commit.go:736-746` confirms `ConfirmCommitAs` checks pending confirm status, `cli_config.go:266-280` confirms bare commit falls through to ordinary promotion when no confirm is pending, `bootstrap.go:77-78` confirms active config suppresses `xpf.conf` import, and `plan.md:5524-5533` explicitly forbids bare commit probes after expiry.

(B) Fresh attacks:
- Peer preflight TOCTOU race: Hypothesis: A peer sync initiated between preflight and process stop could corrupt local state after local fence check. Outcome: FAILED — In-flight wire syncs drain synchronously within the local loop backoff pass (`cluster/sync.go:594-616`), unsent peer queue state dies with the stopped peer process, the local node re-checks full state (`plan.md:5513-5516`), and peer restart occurs strictly after local classification completes (`daemon_run.go:157-177`).
- Staged-config commit after expiry on clustered configurations: Hypothesis: Staging and committing an expired clustered configuration would fail due to runtime rejection. Outcome: FAILED — `plan.md:5528-5533` explicitly divides the runbook into stage+commit for non-clustered configurations and restart-into-clustered-config / `xpf.conf` boot-import for FirstCommit+cluster configurations (`bootstrap.go:321-334`).

(C) Structure confirmation:
The §4.7 delivery structure stands as a two-unit split (PR-1 core deliverable; follow-up issue for G+H+H2) with AGY's r28 (A) dissent recorded verbatim (`plan.md:4385-4429`).

Verdict: PLAN-READY
