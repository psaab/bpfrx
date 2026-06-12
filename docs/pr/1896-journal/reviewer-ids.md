# #1896 reviewer task ids

## Plan round 1
- Codex: task-mqb7hkc4-hkmyrl (job record lost — "No job found"; re-dispatched)
- Codex re-dispatch: task-mqb83szu-4frg8k (reviews plan + draft journal.go)
- AGY: adversarial-review-mqb7hxhl-e7opzl
- Claude SMR: in-conversation (deltas recorded in plan.md section 6)
- AGY plan verdict: PLAN-NEEDS-CHANGES (4 findings, all adopted — plan.md section 7)

## Code round 1
- Codex: task-mqb8lh83-o1n2vr (PR #1909 diff @ 1c4f93416; earlier ids
  task-mqb7hkc4-hkmyrl / task-mqb83szu-4frg8k / task-mqb8dre0-xjm2ub
  lost — early "No job found" is a startup artifact, poll status first)
- AGY r1: adversarial-review-mqb8e55p-i1vm4s — NEEDS-CHANGES (F1
  Critical cap bypass on newline-terminated over-cap lines, F2 Medium
  maxSegments=0 deletes live journal, F3 Low hash-path test gaps) —
  all fixed in 1c4f93416
- AGY r2 (re-verify): adversarial-review-mqb8nht4-lqfgin — MERGE-READY
  (all three r1 fixes verified closed; reviewer re-ran suite -race)
- Claude SMR: in-conversation worked trace (commit→append→rotation→
  read→rollback correlation→torn-line recovery) — pass
- Copilot: attempt 1 quota-limited; retries 1 and 2 posted
- Codex: UNAVAILABLE this session — 6 documented attempts
  (task-mqb7hkc4-hkmyrl, task-mqb83szu-4frg8k, task-mqb8dre0-xjm2ub,
  task-mqb8lh83-o1n2vr [ran 1m42s then killed], task-mqb8rrqj-dfpf3k,
  + registry probes); the shared one-job-global companion runtime is
  owned by a concurrently active agent whose dispatches kill foreign
  jobs; per-repo jobs dir empty. Recommend a Codex pass post-merge or
  when the runtime frees up.

## Live validation (loss userspace cluster, lock cells)
- deploy + CoS re-apply OK
- 14.5 MB legacy fat v1 journal rotated INTACT to .config.journal.1 on
  first append; current segment 304 B..1 KB compact v2
- 3 commits + rollback-1 commit: complete; v2 lines carry config_hash
- `show system commit history`: merges legacy (.1) + v2 entries, 50
  rows, 59 ms wall incl. CLI/gRPC
- systemctl restart over the rotated journal: active, history intact
