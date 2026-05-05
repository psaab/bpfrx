# Codex round-2 PLAN review — Tier S triage v2

Task ID: task-mosu0l9o-sa5vw1
Codex session ID: 019df8ee-3df3-7140-87cb-9467c0b23a94

---

**Verdict: PLAN-NEEDS-MINOR**

Findings:

1. plan.md "current master" should be "latest measured master `b029e91c`" — local origin/master is `dab78ef6`. #915 runtime CoS changes landed after `b029e91c`. Keep the comments for #777/#779/#781 requiring fresh measurement on actual current master.

2. Aggregate bookkeeping is stale: "Tier S: 3 close, 3 stay open" + "16 close, 19 stay open" still reflects v1. With v2 it should be "Tier S: 2 close, 4 stay open" + aggregate "15 close, 20 stay open."

3. Open question about closing #776 as wontfix is stale and contradicts the v2 table. Remove or reword to ask whether keeping #776 is sufficient without successor issues.

4. Minor wording risk on #774: avoid sounding like "25 Gb/s is impossible forever." `shared-umem-plan.md:237` says cross-NIC AF_XDP memcpy is unavoidable but leaves "make the existing memcpy cheaper" as an optimization path. Safer closure framing: current #774 umbrella is not actionable on this lab; #776 preserves the structural copy/topology trail.

Round-1 check: all four substantive blockers are addressed. #774 is no longer closed as "ceiling beaten"; #776 is kept, preserving the cross-NIC constraint trail; #779 no longer prescribes stale `Arc<SessionKey>` before annotate; #781 is kept behind a fresh counter-rate gate. The close/keep set itself is internally consistent: close #774/#775, keep #776/#777/#779/#781.
