Verdict: **PLAN-NEEDS-MAJOR**, borderline **PLAN-KILL** if the next revision keeps the same hot-path cost and lands without the mixed-workload fixture.

Findings, highest severity first:

- **Homogeneous “no-op” claim is not proven and is probably false.** The plan says homogeneous elephants should trip both signals, but the proposed target is `2 × transmit_rate / active` in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/docs/pr/747-glide-ecn/plan.md:157). A fair saturated flow averages roughly `1 × fair-share`, not `>2 ×`. That means `rate_above` can be false while `depth_above` is true, suppressing today’s ECN marks. This contradicts the plan’s expected zero delta in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/docs/pr/747-glide-ecn/plan.md:320) and risks falling back to drops despite the current ECN purpose documented in [admission.rs](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/userspace-dp/src/afxdp/cos/admission.rs:249).

- **Hot-path cost is understated and hits the wrong queues as written.** Current promotion sets `queue.flow_fair = queue.exact`, including `shared_exact`, in [admission.rs](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/userspace-dp/src/afxdp/cos/admission.rs:495). The plan also says shared_exact updates the new arrays despite never reading them in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/docs/pr/747-glide-ecn/plan.md:230). So iperf-c/shared_exact can pay the DIV cost for no semantic value. Also this is not just “one DIV”: target-rate calculation adds another variable divide in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/docs/pr/747-glide-ecn/plan.md:160), plus `item_len * 1e9 / dt` in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/docs/pr/747-glide-ecn/plan.md:126).

- **The proposed EWMA update site is architecturally wrong.** “Where `flow_bucket_bytes` increments” maps to generic queue mutation, not necessarily new admission. `account_cos_queue_flow_enqueue` is used by push paths in [accounting.rs](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/userspace-dp/src/afxdp/cos/queue_ops/accounting.rs:8); `push_front` restores rollback items in [push.rs](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/userspace-dp/src/afxdp/cos/queue_ops/push.rs:136), and demotion reinserts existing queued packets via `cos_queue_push_back` in [cos_classify.rs](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/userspace-dp/src/afxdp/tx/cos_classify.rs:600). Counting those as arrivals corrupts the rate signal. This belongs in admission, probably as a candidate EWMA computed with caller `now_ns`, committed only on accept.

- **EWMA staleness/bootstrap is not safe enough for an AND gate.** The plan’s “within 0.1% in ~24 packets” claim in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/docs/pr/747-glide-ecn/plan.md:107) is wrong: `(7/8)^24` still leaves about 4% error. More importantly, stale-low EWMA can suppress ECN on a returning elephant until hard drops, while stale-high bucket state can false-mark a mouse that hashes into a previously hot bucket. That directly attacks the intended fix.

- **Memory math is stale.** The repo uses `COS_FLOW_FAIR_BUCKETS = 4096`, not 1024, in [cos.rs](/home/ps/git/bpfrx/.claude/worktrees/747-glide-ecn/userspace-dp/src/afxdp/types/cos.rs:103). Two `[u64; 4096]` arrays are **64 KB per queue**, about **9.2 MB** at the plan’s 6×4×6 scale, not 2.3 MB. `Box<[u64; 4096]>` reduces struct/cache footprint but not total memory; it is a locality tradeoff, not a fix.

Answers to the requested checks:

1. Operator value: plausible, but unproven. Do not land without the heterogeneous fixture.
2. Hot path: unacceptable as scoped. Must gate update to owner-local-exact or prove perf with smoke/perf.
3. EWMA staleness: current rationale fails. Needs idle reset/sample-validity/candidate logic.
4. AND vs OR: AND matches the false-positive goal, but raw AND is unsafe without a valid rate signal.
5. Memory: acceptable only after recalculating at 4096 buckets and confirming cache effects.
6. Fixture: blocking, not follow-up. This change is otherwise unobservable or misleading.
7. #784/#785: shared_exact marking contract stays, but update cost leaks there; owner-local exact can regress by under-marking.
8. Update site: not queue_ops. Use admission-scoped admit/offered-rate semantics explicitly.
9. Architecture: real problem, not just refactor cosplay, but v1 is speculative hot-path policy.
10. Glide: CE bits are the sender-visible signal; Accurate ECN sender work is out of scope and not required for this firewall-side decision.

I would not start implementation from this plan. Rewrite it around a measured candidate-rate admission helper, fix the 4096-bucket math, and make the mixed workload plus P=12 fairness/perf smoke mandatory gates.

Codex session ID: 019df616-b804-7681-bcdb-1ca94ac6893c
Resume in Codex: codex resume 019df616-b804-7681-bcdb-1ca94ac6893c
