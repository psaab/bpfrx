# Codex hostile PLAN review — Tier D issue #1187

Source rollout: `rollout-2026-05-04T23-21-22-019df6cc-605f-72c1-bc2a-e9282c738d26.jsonl`

---

Verdict: **PLAN-NEEDS-MAJOR**

KILL is not defensible for #1187. The triage overclaims that the premise is simply wrong.

Findings:

- `BindingLiveState` absolutely still exists on `master`, with many `AtomicU64` counters: `master:userspace-dp/src/afxdp/umem/mod.rs:197`.
- The main RX telemetry path is already buffered: `poll_descriptor` increments `BatchCounters`, then `counters.flush(&binding.live)` publishes at poll exit, not per packet.
- But the issue claim still partially holds: hot-path `BindingLiveState` atomics remain. Examples:
  - redirect path does a per-redirect `redirect_sample_counter.fetch_add`: `master:userspace-dp/src/afxdp/umem/mod.rs:855-887`
  - TX completions publish `tx_completions.fetch_add` on the worker path: `master:userspace-dp/src/afxdp/tx/rings.rs:51-67`
  - TX drain publishes `tx_packets`, `tx_bytes`, and owner-profile bytes from hot TX paths: `master:userspace-dp/src/afxdp/tx/drain.rs:192-213`
  - owner-profile submit/kick telemetry uses atomics, intentionally single-writer but still read by snapshots: `master:userspace-dp/src/afxdp/umem/profile.rs:11-153`
- The prescribed pattern has only partially shipped. `WorkerTelemetry`, `BatchCounters`, and `OwnerProfile*Writes` reduce or isolate some costs, but they are not a complete double-buffered telemetry design.
- The “Coordinator polls counters at 1Hz” claim is unsupported. Status refresh is called on many control requests and state writes, not only a fixed 1Hz loop: `master:userspace-dp/src/server/helpers.rs:14-31`, `master:userspace-dp/src/server/handlers.rs:413-415`.
- I could not verify the issue body or lab NUMA topology: `gh issue view 1187 --json title,body` and `incus exec loss:xpf-userspace-fw0 ...` both failed with sandbox network `socket: operation not permitted`.

Required plan change: replace `KILL` with a major rewrite. The defensible conclusion is: “some #1187 concerns are stale or partially mitigated, but hot-path `BindingLiveState` atomics still exist, so killing the issue on premise alone is wrong.”
