# codex-review-177 triage — aggregate result

189-finding whole-repo Codex audit, base d22789fa6 (~3300 commits stale).
Triaged by an area fleet (triage-177-A: A1-A4, -B: A5-A7, -C: A8-A10) plus a
HIGH suggested-split pass (triage-177H). Per-slice ledgers:
/tmp/result-codex-177-A.md, -B.md, -C.md, -high.md.

Outcome: ~164 issues filed (#5031-#5197 range), high genuine rate
(triage-177-C measured 46/52 = 88%, matching Codex ~90% expectation; 0
already-fixed / 0 retired-path in the A8-A10 slice). Filed set skews material:
~39 security, ~19 vsrx-parity, only ~11 priority:very-low.

Known dedup (F-vs-H overlap — triage-177H re-grouped the same findings the area
fleet filed by F-id): closed 6 straight dups #5126→#5035, #5129→#5105,
#5132→#5037, #5133→#5036, #5136→#5039, #5137→#5043. Kept #5127/#5128/#5130/
#5131/#5134/#5135/#5138 as genuine HIGH the F-fleet missed (verify at drive
time). OUTSTANDING AUDIT: triage-177-A's A1 dataplane filings vs the heavy A1
merges (#5000/#4805/#4828/#4963/#5008/#5017) for any already-fixed over-file —
dedup at drive time.

Marker set: review processed; findings are backlog to drive security-first.
