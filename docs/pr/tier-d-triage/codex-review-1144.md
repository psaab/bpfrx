# Codex hostile PLAN review — Tier D issue #1144

Source rollout: `rollout-2026-05-04T23-53-19-019df6e9-9f8e-72e0-bbff-04784549759a.jsonl`

---

Verdict: PLAN-KILL.

Caveat: `gh issue view 1144 --repo psaab/xpf --json title,body` is blocked here by network policy (`socket: operation not permitted`), and I found no local copy of the issue body. This review is against the triage’s #1144 summary plus current local `master`.

Findings:

- `userspace-dp/src/afxdp.rs` no longer exists. The live path is split across [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:31), [worker/lifecycle.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/worker/lifecycle.rs:18), and [neighbor_dispatch.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor_dispatch.rs:47).
- The claimed cost is not steady-state per-packet. Established TCP/UDP checks the flow cache before session/policy/NAT/FIB work at [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:138). The contested setup happens only in the `MissingNeighbor` branch at [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:1869).
- The triage slightly understates the setup cost: current code does more than FastMap/slab insert. It installs a `MissingNeighborSeed`, publishes shared state, writes BPF session/conntrack/DNAT entries at [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:1981). Still, that is unresolved-neighbor cold path, not the measured hot path.
- The safe pattern already shipped: create transient session seed, buffer in `pending_neigh`, retry after neighbor resolution. See [poll_descriptor.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/poll_descriptor.rs:2038) and [neighbor_dispatch.rs](/home/ps/git/bpfrx/userspace-dp/src/afxdp/neighbor_dispatch.rs:47).
- Deferral has a hard ordering invariant: session/NAT state must exist before the buffered SYN can produce a SYN-ACK. The cold-start doc explicitly records the previous failure and fix at [docs/userspace-cold-start-resolution.md](/home/ps/git/bpfrx/docs/userspace-cold-start-resolution.md:150).

Minor wording correction for the triage: “defer until after neighbor resolves” is not inherently wrong if it installs before retry TX, but that would require rebuilding `retry_pending_neigh` into a full policy/NAT/session-install path. That is not the issue’s simple refactor, has no measured hot-path win, and does not rescue #1144.
