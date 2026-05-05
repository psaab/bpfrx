# Codex hostile PLAN review — Tier D issue #947

Source rollout: `rollout-2026-05-04T23-20-41-019df6cb-bfc3-76d1-a123-a69703f22d0d.jsonl`

---

Verdict: PLAN-KILL.

The triage’s KILL holds. On `origin/master` (`dab78ef6`), `userspace-dp/src/afxdp.rs` does not exist; AF_XDP is a module directory with `parser.rs`, `ethernet.rs`, `poll_descriptor.rs`, `poll_stages.rs`, `gre.rs`, `icmp.rs`, `tunnel.rs`, etc. The old issue premise did exist historically: pre-`74d25948`, the ARP/NDP byte parsing lived around `afxdp.rs:894-1014`. But #947 itself already shipped the extraction: `74d25948` added `parser.rs`, `5b21878f` added shared Ethernet constants and `#[inline(always)]`, and merge `52581996` landed it as PR #962.

Current call sites also do not save the issue. `poll_descriptor.rs` still runs per packet, but it calls `stage_link_layer_classify()`, which delegates to `parser::classify_arp()` and `parser::parse_ndp_neighbor_advert()`. There is no `ProtocolParser` implementation or boxed strategy dispatch in production; `git grep ProtocolParser` only finds the `parser.rs` comment explicitly rejecting `dyn ProtocolParser` because vtable dispatch would hit a per-packet path.

One minor doc correction: the triage should cite #947 / PR #962 as the shipped parser extraction, not “#959/#964 decomposition.” That does not change the outcome. The requested Strategy-trait refactor should stay killed; the useful extraction already shipped in the hot-path-compatible shape.
