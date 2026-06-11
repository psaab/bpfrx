# Codex plan review r1 — #1736 S2b (task-mq90vuiv-xy6e79)

Verdict: PLAN-NEEDS-MAJOR (reviewed research/1736-wg-interop @ 2bad95123500)

1. P4 rekey trace semantically wrong: kernel WG does not time-rekey as
   responder at 165 s; both keep_key_fresh() sites gate on
   i_am_the_initiator (send.c / receive.c + timers.c receive-cancel). xpf
   DOES switch TX after a peer-driven rekey (peer.rs:109 rotate_session;
   engine.rs:703 try_encap reads peer.current). Rewrite P4 around the
   actual REJECT_AFTER_TIME-driven behavior.
2. P5 "shim lands both fragments in the kernel" not supported: parse_ipv4
   ignores frag_off (lib.rs:1113), wg_steer_to_kernel needs
   flow_dst_port == wg_port (lib.rs:1236); non-first fragment misses the
   kernel-steer path. Kernel-wg outer fragmentation itself is real
   (socket.c send4: ignore_df=1, df=0). Suggested default expectation:
   clean drop. [SMR r1 S2: partially refuted — the general
   local-destination session-miss path lib.rs:567 delivers frag-2 to the
   kernel; clean success is the expected mechanism.]
3. Path A HA secondary not harmless: configured endpoint causes immediate
   initiation (wg_control.rs:144) + timer redrive (wg_control.rs:238);
   same WG identity on two nodes; endpoint roaming can move the peer to
   fw1 and blackhole the VIP path. Needs secondary suppression.
4. P3 endpoint-removal is a session-tearing identity-tuple rebuild
   (forwarding_build/tunnels.rs:77, wg.rs:85, coordinator/mod.rs:508) —
   assert fresh thread/handshake, not an in-place role flip.
5. Telemetry too thin: recent_exceptions only (protocol/control.rs:311,
   protocol.go:539); many WG drops debug-only (wg_control.rs:486).
   Require tcpdump both ends, wg show all dump, journald, post-phase
   health checks.
6. Teardown leaks on fw1: config synced, TUN persistent + untracked
   (tunnel.go:348); delete/verify wg0 on BOTH nodes + preflight stale
   device check.
7. Path choice: A unsafe until secondary behavior controlled; consider B
   for protocol phases + reduced-A smoke. [Plan v2: rejected — node0-group
   scoping closes the hazard class at the config layer; see §4 rebuttal.]

Kernel sources cited: wireguard-linux messages.h, send.c, timers.c, socket.c.
