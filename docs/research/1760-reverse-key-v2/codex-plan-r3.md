# Codex plan-review r3 — task-mq923td0-p9fu4m (verbatim)

Verdict: PLAN-NEEDS-MINOR

Finding: the coverage claim is slightly too broad. install_helper_local_session_on_miss is real and bypasses publish_shared_session (forwarding/mod.rs:1099, :1120; caller poll_descriptor/mod.rs:818, SessionOrigin::LocalMiss, LocalDelivery, is_reverse=false).
Adjudication: a local-delivery session can share the exact on-wire tuple K with a transit SNAT reply, but not as the same secondary nat_reverse_index key — for transit, reverse_wire_key builds remote:dst_port -> iface_ip:src_port (key.rs:154); a local packet to the interface installs that tuple as its PRIMARY key, while its own reverse index is the opposite direction (session/mod.rs:1399). Operationally direct session lookup runs before NAT reverse lookup (session_glue/mod.rs:911 precedes :1015). So: outside W3's shared-NAT displacement domain, but NOT outside tuple-shadowing risk. The plan should scope W3'/W-lite to forward-NAT-vs-forward-NAT collisions, or document the local-delivery primary-shadow case as a separate blind/open case. W5 as written does not close it.

No other production transit forward-NAT creation path bypasses publish_shared_session: normal forward install publishes at poll_descriptor:1311, MissingNeighborSeed at :2466, SharedPromote at promote.rs:124, HA sync at ha.rs:262, tunnel-local sessions at tunnel.rs:306 before UpsertLocal fanout.

W3' false positives: no blocker — same logical republish/RG migration/HA re-sync has displaced.key == entry.key; SharedPromote republishes the same resolved key (promote.rs:116); a different entry.key at the same shared NAT key is a real competing forward session.

W-lite acceptable as a reduced ship only after the local-delivery caveat is folded in. Honesty does not require W5 in the same PR; v3 already labels W5 optional and documents the standing window (plan.md:310). The document just needs the scoped wording so "only remaining blind case" is not overstated.

Codex session ID: 019eb526-e283-71c1-89b0-3bd13a877198
