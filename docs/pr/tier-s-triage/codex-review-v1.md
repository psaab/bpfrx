# Codex round-1 PLAN review — Tier S triage v1

Task ID: task-mostsgxe-8k0bzb
Codex session ID: 019df8e8-79d7-7df1-93c8-6eaafe67b029

---

**Overall: PLAN-NEEDS-MAJOR**

| Issue | Verdict | Review |
|---|---|---|
| #774 | REFRAME-NEEDED | Close-as-written is not defensible. The 25 Gb/s shaper target is distinct from #775's 22 Gb/s campaign gate. The plan itself quotes the author saying to leave #774 open for shared-UMEM activation, and 23.4-23.47 Gb/s still does not hit 25. If closing, close as "current-lab 25G target blocked/wontfix by cross-NIC UMEM constraints," not "18G ceiling beaten." |
| #775 | AGREE | The 22 Gb/s gate is genuinely cleared. Post-#917 evidence shows 23.47 Gb/s, and later smokes reproduce ~23.4 Gb/s after #942/#947. Caveat: I found repeated short-smoke evidence, not a fresh 600s run in local docs, so the close comment should cite the author's "target met" statement plus reproduced ≥22 Gb/s, not overclaim a new 600s campaign. |
| #776 | REFRAME-NEEDED | The technical constraint is real: cross-NIC shared UMEM is blocked, same-device shared UMEM is not baseline-safe, and current worker startup passes `shared_umem=false`. But closing #776 while #774 says the remaining gap is "tracked as #776" loses the only visible tracker. Either keep #776 open as the topology constraint tracker, or create/link explicit successor trackers before closing it wontfix-on-current-lab. |
| #777 | AGREE | Keep. Latest local profile still has `poll_binding_process_descriptor` at 9.45%. #1145 touched this function after that profile, but it was a small redundant-slice cleanup with no hard perf reprofile. Next action should still be fresh `perf annotate` on current master. |
| #779 | REFRAME-NEEDED | Keep, but the `flow_key.clone()` hypothesis is stale as the lead fix. Current common direct path mostly moves the key via `take()`; clones remain in request construction, segmentation, and prepared-to-local fallback paths. The issue should first annotate/measure current `enqueue_pending_forwards` before prescribing `Arc<SessionKey>`. |
| #781 | AGREE | Keep for fresh measurement. The original 9.67M/506M counters are stale/cumulative; local cold/post counter files show `tx_xsk_full` flat, and current #778 diagnostic shows `rx_xsk_buff_alloc_err=899`, `tx_xsk_full=0`. Fresh 30-60s delta counters should decide close-as-mitigated vs fix. |

Key blocker: the plan's closure set closes both #774 and #776, while using #776 as the rationale for why #774's remaining 25G gap is handled. That is internally inconsistent and would erase the 25G/current-lab constraint trail.

---

# Gemini Pro 3 — failed (rate-limit, 5th today)
