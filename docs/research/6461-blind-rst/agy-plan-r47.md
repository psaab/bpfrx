VERDICT: PLAN YES

### Q1 (discharge sweep): SOUND
* **Evidence:** `docs/research/6461-blind-rst/plan.md:1481-1485`, `1978-1985`, `3907-3923`, `4341-4345`.
* **Verification:** Receiver inbound obligation and readiness clear **only** upon applying the exact `JOURNAL_END` frame carrying `(repair_id, journal_epoch, terminal_seqno)` (`plan.md:1481-1482`, `1978-1980`). Sender outbound obligation and cold-prime latch clear **only** upon receiving the matching full-triple `JOURNAL_ACK` from the receiver (`plan.md:1483-1484`, `1980-1982`, `3919-3923`). A bare `BulkAck(u64)` or `BulkEnd` write never clears either obligation, readiness, or the latch (`plan.md:1484-1485`, `1985`, `3907-3911`, `3922-3923`). No straggler discharge clauses remain in the plan.

### Q2 (family-transaction permit): SOUND
* **Evidence:** `docs/research/6461-blind-rst/plan.md:1615-1632`.
* **Verification:** The family-transaction permit is **helper-issued** (`plan.md:1617`). Go acquires it at the first family write (identified by canonical key), and the Rust helper tracks outstanding permits within the same transaction context as `replace(slot, T1, T2, token_epoch)` (`plan.md:1618-1623`). Because map writes are helper-owned state, placing permit tracking on the helper side ensures reverse/DNAT writes across the IPC boundary (`session_store.go:284`, `:289`, `manager_ha.go:1125`) are covered. Replacement drain availability cost is strictly bounded: `replace(T1, T2)` drains or CAS-invalidates permits under a µs-ms deadline per three sequential map writes (`plan.md:1624-1629`), preserving availability while preventing partial-family overwrites via token-conditional CAS per preimage (`plan.md:1629-1632`).

### Q3 (reset-lane confinement): SOUND
* **Evidence:** `docs/research/6461-blind-rst/plan.md:1367-1411`.
* **Verification:** The control lane runs a strict RESET-ONLY parser accepting only HELLO/capability + fixed-size `RESET_GEN`/`RESET_ACK` (`plan.md:1368-1376`). The capability is restricted to authenticated peers (`plan.md:1377-1380`). Incarnation freshness is lifecycle-bound and state-machine locked: a peer restart mid-lane terminates the connection/lane (TCP reset or silence teardown), forcing a fresh lane re-handshake with the new incarnation (`plan.md:1384-1387`). Any delayed `RESET_ACK` with an old incarnation arriving on a new lane is discarded because the frame's incarnation must match the active lane's bound incarnation (`plan.md:1387-1390`). The incarnation transition is controlled under a single mutex (`s.mu`) with an explicit `{current, pending, retired}` state machine (`plan.md:1391-1410`), ensuring retired incarnations are never readopted and old-incarnation frames cannot pass.

### Q4 (convergence sweep): SOUND
* **Evidence:** `docs/research/6461-blind-rst/plan.md:600-750` (§5.2), `3855-3935` (§5.8).
* **Verification:** §5.2 (dataplane demote gate & anchor proofs) and §5.8 (HA wire schemas, transaction permits, & terminal discharge markers) form a fully closed stack. Out-of-window or un-baselined RST/FIN packets cannot demote sessions; SNAT mid-flow swaps are prevented by eliminating unvalidated session reaps; HA desynchronization and tuple reissue race conditions are closed via helper-issued transaction permits, token-epoch validation, and full-triple `JOURNAL_END`/`JOURNAL_ACK` obligations.

---

### v9.9.39–v9.9.41 Trace Folds Summary

1. **Helper-Side Permit Control Across IPC Boundary (v9.9.40, SMR F1)**
   * *Code Reference:* `pkg/dataplane/userspace/session_store.go:274, :284, :289`, `manager_ha.go:1125, :1779`.
   * *Fold:* Storing family permits on the Go side left reverse and DNAT IPC writes outside the drain check. Permit acquisition was moved to helper-issued state tracked inside the helper's `replace(slot, T1, T2, token_epoch)` transaction context (`plan.md:1617-1623`).

2. **Peer Incarnation Mid-Lane Restart & Transition Interleaving (v9.9.40–v9.9.41, SMR F2 / Codex H2)**
   * *Code Reference:* `sync_conn.go:388`, `sync_admission.go:66`, `heartbeat.go:624`.
   * *Fold:* Async connection accepts allowed overlapping setups to interleave and regress process nonces. Closed by binding freshness to the lane lifecycle and placing the peer incarnation transition (`{current, pending, retired}`) under `s.mu` lock, keeping per-incarnation reset-generation high-water marks (`plan.md:1384-1410`).

3. **Full-Triple `JOURNAL_ACK` Terminal Return Frame (v9.9.41, Codex B1/B2)**
   * *Code Reference:* `sync_conn.go:194`, `sync_bulk.go:282`, `sync_conn_read.go:249`.
   * *Fold:* Receiver obligations cleared on `JOURNAL_END`, but sender outbound obligations and cold-prime latches lacked a dedicated return frame and risked clearing on bare `BulkAck(u64)`. Closed by introducing `JOURNAL_ACK(repair_id, journal_epoch, terminal_seqno)` flowing receiver $\rightarrow$ sender as the sole discharge point (`plan.md:1481-1485`, `3912-3923`).
AGY EXIT: 0
