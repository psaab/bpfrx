# Claude SMR hostile plan review — #1736 S2b, round 1

Reviewer: Claude (domain SMR: WireGuard protocol semantics, AF_XDP dataplane,
HA cluster operations). Target: plan.md v1 @ 2bad9512.

## Verdict: PLAN-NEEDS-MAJOR

Independently verified the plan against the code and the live cluster. Three
findings overlap Codex r1; finding S3 is NEW evidence (live cluster check)
that upgrades Codex's finding 3 from "needs suppression" to "mandatory,
TAI64N-poisoning class"; finding S2 PARTIALLY REFUTES Codex's finding 2 with
shim file:line evidence.

### S1 (MAJOR, agrees with Codex 1) — P4 rekey trace is wrong on kernel semantics

wireguard-linux gates BOTH time-based rekey triggers on
`keypair->i_am_the_initiator`:

- send.c `keep_key_fresh()`: initiator-only REKEY_AFTER_TIME (120 s) rekey on
  send.
- receive.c `keep_key_fresh()`: initiator-only last-minute rekey at
  REJECT_AFTER_TIME − KEEPALIVE_TIMEOUT − REKEY_TIMEOUT (165 s) on receive.

With the P1 session xpf-initiated, the kernel is the handshake RESPONDER and
will NEVER time-rekey. The actual recovery path is: at t≈180 s the kernel's
per-packet `wg_birthdate_has_expired(..., REJECT_AFTER_TIME)` checks
invalidate the keypair; the next kernel SEND finds no valid keypair, stages
the packet, and fires `wg_packet_send_queued_handshake_initiation` — i.e. an
expiry-driven re-handshake with a bounded traffic gap, not a seamless 165 s
rekey. xpf-side TX switch after the peer-driven handshake IS real
(`peer.rs:109` rotate_session replaces `current`; `engine.rs:703` try_encap
reads `peer.current`) — Codex verified the same.

Required P4 redesign: two sub-phases.
- P4a (xpf-initiated session): run ≥210 s; assert a bounded outage around
  t≈180 s (gap ≤10 s, recovery via kernel-initiated handshake) and 0 loss
  outside the expiry window.
- P4b (kernel-initiated session, runs naturally after the responder-role
  phase): run ≥180 s; assert a SEAMLESS rekey at ~120-135 s
  (REKEY_AFTER_TIME + handshake jitter; kernel is initiator) — loss <1%,
  no multi-second gap, `latest-handshakes` advances mid-run.
This is strictly better evidence: it captures both the S5-hole-bounded case
and the spec-clean case.

### S2 (MAJOR correction to Codex 2) — non-first fragments DO reach the kernel; P5 "clean success" is the likely outcome, not bogus

Codex correctly notes the WG early-return cannot match a non-first fragment
(`parse_ipv4` ignores `frag_off`, lib.rs:1095+, garbage L4 ports at
lib.rs:1113; `wg_steer_to_kernel` needs `flow_dst_port == wg_port`,
lib.rs:1236-1241). But Codex missed the GENERAL local-destination fallback:
on session-table miss the shim checks `is_local_destination(&parsed)` and
returns `cpumap_or_pass` (lib.rs:567-579). A non-first fragment of the WG
datagram has dst 10.0.61.1 (locally owned) → session miss (its
garbage-parsed 5-tuple matches no session, collision probability negligible)
→ kernel. The first fragment reaches the kernel via the WG gate. Kernel IP
reassembly then delivers the COMPLETE datagram to the control thread's
UdpSocket → decap succeeds. Kernel-wg outer DF=0 (socket.c `send4` passes
df=0, `skb->ignore_df=1`) makes the trigger deterministic.

So P5's outcome (i) is the EXPECTED mechanism, with (ii) clean-drop as the
acceptable alternative if e.g. an unrelated session-table hit or strict-mode
branch intervenes. The plan must document this mechanism precisely (frag-1
via WG gate, frag-2 via local-dst miss path) and the harness must RECORD
which outcome occurred — but flipping the default expectation to "clean
drop" (Codex 2) is not supported by the shim code.

### S3 (BLOCKER, new live evidence; upgrades Codex 3) — fw1 secondary interference is real and TAI64N-poisoning class

Verified live on the cluster (2026-06-10):

```
fw1# ip -br -4 addr | grep ge-7-0-1
ge-7-0-1  UP  169.254.2.2/32 10.0.61.1/24
```

The SECONDARY also carries 10.0.61.1/24 (VRRP backup keeps the address;
only ARP/virtual-MAC mastership differs). Config is cluster-synced, so
without scoping BOTH nodes spawn a WG control thread with the SAME static
identity and BOTH can route to the peer:

1. fw1 initiates (immediate bring-up, wg_control.rs:147-150) sourced from
   10.0.61.1; the peer's msg2 goes to 10.0.61.1 = the VRRP virtual MAC =
   fw0, whose engine has no matching initiation index → dropped. fw1 never
   completes → re-initiates every 1 s forever (wg_control.rs:77,245).
2. Worse: fw1's initiations carry TAI64N timestamps for the SAME static key.
   The kernel peer keeps a per-peer timestamp high-water; fw1's timestamps
   ratchet it. If fw1's whitened clock runs ahead of fw0's, fw0's OWN later
   re-handshakes (restart, P3, expiry recovery) are REJECTED as replays —
   intermittent, clock-skew-dependent interop failure that would be
   misdiagnosed as an engine bug.

Mitigation (must be in the plan, not a runbook footnote): scope the wg0
stanza under `groups node0 { interfaces wg0 {...} }` (the canonical config
already uses `apply-groups "${node}"`, docs/ha-cluster-userspace.conf:61) so
only node0 compiles it. Preflight + post-commit assert: fw1 has NO wg0 TUN,
NO :51820 bind, NO wg control thread. If groups-expansion turns out to drop
the `tunnel wireguard` subtree (the #1796/#1797 dual-AST-gap class), that is
a NEW S2b finding to file and the harness is blocked on it — do NOT fall
back to both-nodes config.

### S4 (minor, agrees with Codex 4) — P3 must assert fresh-thread/fresh-handshake

Endpoint is part of the engine identity tuple (forwarding_build/wg.rs:85);
removing it rebuilds the engine and restarts the thread (coordinator/
mod.rs:508), dropping live sessions. P3 already flushes the peer; it must
also EXPECT the session drop and assert a fresh handshake, not a role flip.

### S5 (minor, agrees with Codex 5/6) — evidence + teardown hardening

Add: tcpdump on peer AND fw0 (`udp port 51820`) per phase; `wg show all
dump` snapshots; journald slice; post-phase health = status RecentExceptions
free of `wg_*` + fast-path ping. Teardown: with node0 scoping the TUN leak
is fw0-only, but teardown must still VERIFY both nodes have no wg0 and the
stanza is gone from the synced config.

### S6 (minor, own finding) — peer provisioning needs a mgmt NIC

The peer VM's only planned NIC is the VLAN-3667 VF; `apt install
wireguard-tools` and incus-agent reachability are smoother with a second
`incusbr0` NIC (the fw VMs' fxp0 pattern). Add eth1=incusbr0 to the
provision step (also de-risks VF teething: the harness can always reach the
VM).

## Cross-check of Codex r1 findings

- Codex 1: CONFIRMED (S1).
- Codex 2: PARTIALLY REFUTED (S2) — clean-success path is real via
  lib.rs:567; keep dual-outcome.
- Codex 3: CONFIRMED + UPGRADED (S3) — live evidence; TAI64N poisoning.
- Codex 4: CONFIRMED (S4).
- Codex 5: CONFIRMED (S5) — but the peer-side `wg show` remains the primary
  interop oracle; xpf counters stay an S6-filed finding.
- Codex 6: CONFIRMED, subsumed by node0 scoping + both-node verify (S5).
- Codex 7 (Path B for protocol phases): REJECTED as primary — with S3's
  mandatory node0 scoping the hazard class is closed at the config layer;
  a standalone pair would add a second environment and still not discharge
  the canonical-cluster acceptance. Keep A; record B as optional debug
  adjunct only.
