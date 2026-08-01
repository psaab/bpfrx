# Codex hostile plan-review — round 117 (v10.32.0, reviewed at 41e54d3ea5ee)

Reviewer: Codex (same thread, 2026-07-31). Verdict: PLAN NO (3B/3H/1M).
Headline: the matched-session token could not encode its required
provenance; `fwd_companion_epoch` had neither a complete producer path
nor a safe lifecycle; the state-keyed OPENING rule still rejected
ACK-bearing segments that possess the strong proof (asymmetric-SYN-ACK
repair starvation). Folded as v10.33.0. Round-116 dispositions: r116-1
UNRESOLVED; r116-2 UNRESOLVED; r116-3 RESOLVED; r116-4 UNRESOLVED;
r116-5 UNRESOLVED; r116-6 UNRESOLVED; r116-7 UNRESOLVED; r116-8
UNRESOLVED.

## Verbatim review

PLAN NO

1. **BLOCKER — The token cannot encode its required provenance.** Its
normative type remains `Option<(SessionKey, NatDecision, bool
/*is_reverse*/, u64 /*epoch*/)>`, yet the forward-wire path requires an
additional `no-anchor-learn` marker. Current resolution discards that
provenance when `ForwardSessionMatch` becomes a canonical lookup, so the
commit hook cannot distinguish it. Use a named token with separate
orientation and provenance fields. Code trace:
`userspace-dp/src/session/entry.rs:208-213`,
`userspace-dp/src/session/lookup.rs:253-292`,
`userspace-dp/src/afxdp/shared_ops.rs:507-560`;
plan:1935-1937,1960-1969.

2. **BLOCKER — `fwd_companion_epoch` has neither a complete producer
path nor a safe lifecycle.** The common fresh flow installs F and R
through positional `install_with_protocol_with_origin`; `SessionInstall`
is not present on that reverse-install path, despite the plan naming it
as the carrier. HA import separately queues F then R, and F can refuse
against a local predecessor while R succeeds, so R cannot safely bind to
whichever same-key forward happens to exist. Legitimate promotion/HA
refresh also advances F's epoch while R retains the old value. "Refresh
at each committed hop" cannot repair that safely: rebinding after
mismatch defeats ABA protection; refusing forever strands reverse
learning. Specify explicit F-epoch carriage on the positional fresh-R
install, an unbound import state, and atomic reciprocal epoch updates
only for proven same-family transitions. Code trace:
`userspace-dp/src/afxdp/poll_descriptor/mod.rs:2449-2458,2777-2787`,
`userspace-dp/src/session/ctx.rs:8-17`,
`userspace-dp/src/session/install.rs:113-152,310-323`,
`userspace-dp/src/afxdp/ha/session_import.rs:215-223`,
`userspace-dp/src/session/mod.rs:1384-1397,1642-1665`; plan:2003-2024.

3. **BLOCKER — The OPENING rule still rejects packets that possess the
stated strong proof.** The proof is knowledge of an ACK inside the
immutable exact SYN interval; the public SYN bit contributes no entropy.
Therefore an ACK/PSH-ACK whose ACK exact-proves that interval has the
same off-path resistance, but v10.32 categorically skips it. Because
`find_forward_nat_match` is read-only, repeated legitimate reverse ACKs
neither install R nor establish/touch F; F can expire on its OPENING
clock and lose the live NAT mapping after an asymmetric SYN-ACK path.
Accept every ACK-bearing segment that exact-proves the interval, while
rejecting out-of-interval or non-ACK packets. Code trace:
`userspace-dp/src/session/lookup.rs:222-250`,
`userspace-dp/src/afxdp/shared_ops.rs:638-665`,
`userspace-dp/src/session/expire.rs:296-320,468-523`;
plan:900-912,1270-1277.

4. **HIGH — The state-keyed site-2b function is incomplete for Shared
matches.** `SyncedSessionEntry` carries no `established` or OPENING
timing state, while `lookup_forward_nat_across_scopes` can return a
shared-only row or a shared row shadowing a local placeholder. The
document simultaneously says ESTABLISHED/import pickup remains
master-verbatim and that Shared refuses, without defining the
non-closing shared-only cases. Treating all Shared as established
permits an OPENING publication to bypass proof; refusing all Shared
changes master's non-closing repair behavior. State the complete `(scope,
origin/state, flags)` table. Code trace:
`userspace-dp/src/afxdp/worker/mod.rs:375-401`,
`userspace-dp/src/afxdp/shared_ops.rs:638-665`,
`userspace-dp/src/session/install.rs:359-381`; plan:1277-1300.

5. **HIGH — Capacity-refused site-2b acceptance lacks a complete
transaction.** The document explicitly preserves the forward flag-only
establishment update when reverse installation refuses, but does not
equivalently state that an accepted close still marks the forward
family. This matters for SYN-ACK+FIN/RST, where establishment promotion
is forbidden and the close mark is the only forward mutation. The
installer returns before mutation at capacity, while current publication
runs only under `installed`; the new forward close transaction must be
explicitly independent of that boolean. Also define whether a
proof-passing, install-refused packet receives a forward-bound commit
token or intentionally contributes no anchor sample. Code trace:
`userspace-dp/src/session/install.rs:123-125`,
`userspace-dp/src/afxdp/shared_ops.rs:857-893`; plan:1320-1339,1941-2002.

6. **HIGH — The memory/performance accounting is materially wrong and
internally inconsistent.** On the target ABI, `SessionKey` is 40 bytes
and `NatDecision` 44 bytes; the declared tuple plus orientation/epoch
occupies about 96 bytes, not 48. Thus the cache increase is roughly
384 KiB per 4,096-entry binding before enclosing-layout effects, not
192 KiB. Section 8 also still says "No `FlowCacheEntry` change."
Separately, §5.1 labels the shown 40-byte `TcpSeqAnchor` as 48 bytes,
while §5.8 correctly places the additional 8-byte companion epoch
outside it; the overview's 5.2 MiB/worker conflicts with §8's 6.3 MiB.
Require `size_of` assertions for the anchor, entry delta, token, and
`FlowCacheEntry`, then update the cache-line/performance gate. Code
trace: `userspace-dp/src/session/key.rs:9-17`,
`userspace-dp/src/nat/mod.rs:90-103`,
`userspace-dp/src/afxdp/flow_cache.rs:5-14,201-224`;
plan:345-350,543-578,1702-1706,2579,2586.

7. **MEDIUM — The cache identity check is not before all hit effects as
claimed.** By the proposed check point, `lookup_counted` has already
LRU-promoted the descriptor, incremented hits, stamped activity, and
added packet bytes; the existing validity test has also read
`cached.decision`. An identity mismatch then falls through after
recording a false hit and mutating telemetry. Use a peek →
identity/validity check → commit-hit API, or explicitly scope the
promise to forwarding/policy effects and test the telemetry behavior.
Code trace: `userspace-dp/src/afxdp/flow_cache.rs:1023-1039`,
`userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:94-133`;
plan:1991-1998.

Round-116 dispositions: r116-1 UNRESOLVED; r116-2 UNRESOLVED; r116-3
RESOLVED; r116-4 UNRESOLVED; r116-5 UNRESOLVED; r116-6 UNRESOLVED;
r116-7 UNRESOLVED; r116-8 UNRESOLVED.
