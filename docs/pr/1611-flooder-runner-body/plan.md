# #1611 — cold-path flooder runner body (AF_PACKET + sendmmsg)

**Status**: v4 — Codex r1 PLAN-KILL findings addressed (sendmmsg
wording + 3 Mpps premise via PACKET_QDISC_BYPASS + CAP_NET_RAW
smoke). AGY r1 PLAN-NEEDS-MINOR items inlined (PACKET_QDISC_BYPASS,
blocking smoke gate, ENOBUFS silent, yield_now backoff, IFF_UP
check, frame buffer alignment). Claude SMR r1 PLAN-NEEDS-MINOR
items inlined (sendmmsg wording, RFC 6864 ID note, ifindex-0
failure, AF_PACKET TX → AF_XDP RX topology note).

Codex r1 (task-mpovfie0-6vc58v) PLAN-KILL findings, addressed in
v3:
- BLOCKING (sendmmsg partial-retry off by one) — v2 reworked the
  loop to "refill from scratch every iteration" so the off-by-one
  question doesn't arise. Codex's alternative "retry from N" is
  also acceptable; v3 documents both options below.
- MAJOR (3+ Mpps premise not proven) — v3 adds PACKET_TX_RING
  optional fallback knob `--use-tx-ring` and a BLOCKING smoke
  gate at ≥3 Mpps (was best-effort in v2).
- MAJOR (no integration syscall coverage) — v3 adds an `#[ignore]`
  integration test `test_open_af_packet_raw_smoke` requiring
  `CAP_NET_RAW`, gated by env var so unit-test runs skip it.

## Issue framing

#1607 step-1 (PR #1613, squash-merged as `260ff8721`) shipped the
Cargo skeleton at `test/incus/cold-path-flooder/src/main.rs` —
arg parsing, cohort validation, xorshift PRNG primitive, frame
size constants, and 9 cargo unit tests. The runner body itself
(AF_PACKET socket + frame assembly + sendmmsg loop + TSC sampling
+ JSON summary) was DEFERRED to this issue per AGY r4 axis 4
PLAN-NEEDS-MAJOR resolution so the step-1 review surface stayed
focused on plan-coherency, not 600 lines of new socket / sendmmsg
plumbing.

This issue ships the runner body **only**. Scale Target table
population (step-3) lands in #1612, which depends on this issue's
binary plus the wire-protocol counter additions also deferred from
step-1.

## Honest scope/value framing

The flooder is a **test harness**, not dataplane code. The win is
measurement methodology — without per-packet 5-tuple randomization,
iperf3's 1-flow-per-stream cache-hits on the first packet and the
remaining ~99.999% of packets bypass the cold path under test. The
absolute scale of the win is: enables the entire cold-path
measurement program (Scale Target tables for the JIT compiler
sizing exercise in `docs/userspace-jit-design.md`).

A wrong runner — checksum errors, frame-size errors, MAC source
wrong, kernel-rejected frames — invalidates every measurement
downstream. The runner correctness gate is therefore tight: every
field must match the v2-r4 plan §4.2.3 wire-byte spec.

If reviewers conclude the runner architecture itself is wrong
(e.g., SOCK_RAW + sendmmsg can't hit 5 Mpps single-core, or the
TSC measurement plumbing should land here not in #1612),
PLAN-KILL or PLAN-NEEDS-MAJOR is an acceptable verdict.

## What's already shipped / partially batched

Step-1 (PR #1613, `260ff8721`):
- `Args::parse()` — full CLI flag surface incl. `--iface --dst-mac
  --src-mac --dst-ip --dst-port-base --dst-port-span
  --src-ip-base --src-ip-span --src-port-span --duration-secs
  --warmup-secs --frame-bytes --batch --seed --cohort`.
- u128 cohort-cap overflow guard.
- 4× zero-span/zero-batch/oversized-batch validation.
- `Xorshift64` PRNG struct + `next()` method.
- 9 cargo unit tests, including the `unbounded_default_uses_full_2_to_16_spans`
  cardinality test and the u128 overflow witness.
- Pre-imported but `#[allow(unused_imports)]`'d: `CString`,
  `c_int`, `c_void`, `ptr`, `Instant` — explicitly held for this
  issue's runner body so the step-2 commit stays focused on logic.

The stub `main()` body exits with EX_OSERR (71) and a loud STUB
message on stderr, so a harness keying off `$?` will treat the
step-1 binary as failure. This must be replaced wholesale by the
runner body.

## Concrete design

### Out of scope for this PR — deferred to #1612

- Wire protocol additions (`WorkerColdPathCounters` /
  `WorkerColdPathAtomics` / `WorkerRuntimeStatus.cold_path_*` /
  `clock_source`) — these are dataplane-side and live in the
  Rust↔Go protocol. #1612.
- Prometheus emitter for the new counters. #1612.
- `cold_path_microbench.sh` orchestrator. #1612.
- Scale Target table population in `docs/userspace-jit-design.md`.
  #1612.
- Adding `--src-port-base` / `--dst-port-base-validate` knobs
  beyond what AGY r3 step-2 minor concerns require. This PR adds
  exactly two knobs: `--src-port-base` (to skip reserved port 0)
  and a `dst_port_base + dst_port_span <= 65536` validator (to
  prevent silent u16 wrap).
- IPv6 path (`--ipv6` flag with 64-B IPv6 frame). The plan v2-r4
  §4.2.3 lists IPv6 as part of step-2 runner body, but the
  AddressBookSnapshot dual-stack work landed in #1606 and
  exercising IPv6 here would expand review surface significantly.
  Land IPv4-only here, file follow-up for IPv6.

### In scope for this PR

**Topology note** (Claude SMR r1 axis 9): the flooder runs on
`loss:cluster-userspace-host` and the AF_PACKET TX traffic
arrives at the firewall via normal Ethernet. The firewall-side
AF_XDP RX socket on `ge-0-0-1` sees every frame — AF_PACKET
TX and AF_XDP RX live on independent kernel paths on the two
ends of the wire. The flooder is NOT trying to inject directly
into an AF_XDP socket on the same host as the dataplane.

1. **AF_PACKET SOCK_RAW socket setup** on `--iface`:
   - `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` — caller
     needs `CAP_NET_RAW`; refuse to start otherwise with a
     specific errno-coded message.
   - **`PACKET_QDISC_BYPASS` enabled** (AGY r1 finding 2): a
     one-line `setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS,
     &1u32, 4)` skips the kernel qdisc layer entirely. Per
     `man 7 packet`: "available since Linux 3.14", which is far
     below the loss cluster's kernel floor. This is the
     "simple mitigation" path Codex r1 asked for without the
     complexity of full PACKET_TX_RING + mmap.
   - `bind()` to `sockaddr_ll { sll_family=AF_PACKET,
     sll_protocol=htons(ETH_P_ALL), sll_ifindex=<idx> }`.
   - `SO_SNDBUF` set to `frame_bytes * batch * 256` to absorb
     burst submission.
   - Resolve `--iface` to ifindex via `if_nametoindex(3)`. If
     it returns 0 (the documented "not found" sentinel), fail
     with `"interface '<name>' not found — check `ip link show`"`.
     No implicit fallback (Claude SMR r1 MINOR-3).
   - **`IFF_UP` check** via `ioctl(SIOCGIFFLAGS)` (AGY r1
     finding C): if the interface is DOWN, the kernel silently
     accepts AF_PACKET TX and drops; the harness sees 0 pps.
     Fail fast with `"interface '<name>' is DOWN — run 'ip link
     set <name> up' first"`.
   - Auto-fill `args.src_mac` from `ioctl(SIOCGIFHWADDR)` if the
     CLI default `[0; 6]` is in effect.
   - When `args.dst_mac` is still default `[0xff; 6]` (broadcast),
     fail fast with a clear error: "specify --dst-mac; ARP
     resolve is not implemented in this step (and is unnecessary
     for the loss userspace cluster where the peer MAC is
     stable; #1612 documents it)." Per AGY r3, ARP-resolve in
     this binary is gratuitous complexity.

2. **Per-packet 5-tuple generation** via existing `Xorshift64`:
   ```rust
   let s = prng.next();
   let src_ip_off  = (s as u32) % args.src_ip_span;
   let src_port_v  = (((s >> 16) as u32) % args.src_port_span) as u16;
   let src_port    = args.src_port_base.saturating_add(src_port_v);
   let dst_port_v  = (((s >> 32) as u32) % args.dst_port_span) as u16;
   let dst_port    = args.dst_port_base.saturating_add(dst_port_v);
   let src_ip      = Ipv4Addr::from(args.src_ip_base.wrapping_add(src_ip_off));
   ```
   - **Reserved port 0 handling** (AGY r3 step-2 minor 2):
     `--src-port-base` defaults to **1024** (start of ephemeral
     range). The xorshift modulo span is added to `src_port_base`,
     so src_port=0 is never emitted. Justification:
     `metadata_tuple_complete()` at
     `userspace-dp/src/afxdp/frame/inspect.rs:207` rejects TCP/UDP
     flows with `src_port==0`, sending them down a different code
     path that bypasses the policy cold path under measurement.
     This contradicts the task prompt's "include port 0" guidance,
     but the codebase + AGY r3 are aligned: port 0 IS a different
     code path and measuring it would skew the histogram.
     - The plan SMR-r1 author will flag this as a deliberate
       deviation from the parent task prompt with the inspect.rs:207
       evidence cited. Reviewers may overrule.
     - To preserve the operator's ability to deliberately measure
       port-0 behavior, `--src-port-base 0` is permitted (no
       lower-bound guard); the safe default of 1024 is what
       step-3 (#1612) measurements use.
   - **dst_port overflow guard** (AGY r3 step-2 minor 1): add
     `if dst_port_base as u32 + dst_port_span > 65536` ⇒ Err.
     This also prevents silent u16 wrap into the privileged
     port range (1..1024) when an operator passes a large span
     by mistake.
   - The dst port is `dst_port_base + (xorshift % dst_port_span)`,
     which for the default span=1 = 5201 exactly (matches iperf-a
     port classifier). The default is preserved as 5201.

3. **Frame assembly — true 64 B Ethernet frames**:
   Layout (§4.2.3):
   ```
   Byte 0-5    dst MAC (--dst-mac)
   Byte 6-11   src MAC (--src-mac, or ioctl-resolved)
   Byte 12-13  0x0800 (IPv4 ethertype, big-endian)
   Byte 14-33  IPv4 header (no options):
     v=4, ihl=5, tos=0, total_len=50 (be), id=randomized (be),
     flags=DF, frag_off=0, ttl=64, proto=17 (UDP),
     csum=COMPUTED, src=src_ip (be), dst=args.dst_ip (be).
   Byte 34-41  UDP header:
     src_port=src_port (be), dst_port=dst_port (be),
     len=30 (be), csum=0 (UDP-over-v4 csum is optional per RFC 768).
   Byte 42-63  UDP payload, fixed magic
     b"XPF-COLD-PATH-MIN64\n\0\0" — 22 bytes exact, pads to 64.
   ```
   IPv4 header checksum: compute once per packet via folded 16-bit
   one's-complement sum over the 20-byte header. Cheap (~5 ns).
   ID field randomized from the same xorshift stream. With
   IPv4 flags=DF (Don't Fragment) set, per RFC 6864 §4.2
   "atomic datagram" semantics the ID field is unconstrained
   — random is fine and no kernel reassembly / rate-limit path
   keys off duplicates (Claude SMR r1 MINOR-2).

4. **sendmmsg(batch=32)** loop (Claude SMR r1 MINOR-1 wording,
   AGY r1 finding A/B):
   - One `mmsghdr` array of size `batch` allocated once, before the
     hot loop, **aligned to 64-byte cache line** (AGY r1 finding D)
     via `#[repr(align(64))]` on the frame-buffer struct. Each
     `mmsghdr` points to a per-slot `iovec` pointing to a per-slot
     64-byte frame buffer. Reuse buffer slots — only the variable
     fields (src IP, src/dst port, IPv4 csum) need mutation per
     packet.
   - Per-iteration: PRNG-refill all `batch` slots (PRNG advances
     `batch` times during prepare, not N); call
     `sendmmsg(fd, msgs.as_mut_ptr(), batch as u32, 0)` which
     returns N ∈ [0, batch] on success or -1 on hard error.
   - Per `man 2 sendmmsg`: the first N messages in `msgvec` were
     sent successfully; the kernel never partially-sends a single
     message. On return value N:
     `tx_packets += N; if N == batch { tx_batches += 1; } else { err_partial += 1; }`.
     Refill from scratch on the next iteration — the unsent
     `batch - N` slots' PRNG values are safely discarded without
     affecting downstream pseudorandom distribution (xorshift64 is
     stateless modulo the 64-bit register).
   - **Error handling — hot path** (AGY r1 finding A):
     - `EAGAIN` ⇒ `std::thread::yield_now()` then resubmit
       (AGY r1 finding B: 5ms sleep would drop ~15k packets of
       TX opportunity). Increment `err_eagain` counter.
     - `ENOBUFS` ⇒ treated IDENTICAL to EAGAIN (silent, no log,
       yield_now, increment `err_eagain` counter). AGY r1 finding A:
       a logging storm at 3 Mpps would collapse the hot loop.
     - `EINTR` ⇒ immediate resubmit, no counter increment.
     - `EPERM` ⇒ hard exit (1) with the CAP_NET_RAW hint message.
     - Any other errno ⇒ **on first occurrence only**, log to
       stderr; increment `err_other` counter for all
       occurrences (rate-limit-by-first-log keeps stderr quiet
       in the hot loop). After the run ends, the final summary
       emits the count + the first observed errno code.
   - Bookkeeping per second on a separate thread? No — keep
     single-threaded; print a JSON-line every 1s from the same loop
     (cost: 1 `clock_gettime` per packet on the rate-check branch,
     amortized via predicate on `tx_packets & 0xFFF == 0`).

5. **Duration + warmup**:
   - Capture `start = Instant::now()`. While now-start < warmup,
     emit packets but DROP them from the summary counts. After
     warmup, count packets, batches, sendmmsg errors. Stop at
     `now - start >= warmup + duration`.

6. **JSON output**:
   - **Per-second JSON-lines to stderr** during run (operator
     visibility):
     ```json
     {"t":1.0,"pps":4892341,"batches":152886,"err_eagain":0,"err_other":0}
     ```
   - **Final summary JSON to stdout** (machine-readable, picked up
     by the #1612 harness):
     ```json
     {"version":1,"cohort":"unbounded","duration_secs":30,
      "warmup_secs":2,"frame_bytes":64,"batch":32,
      "tx_packets":146770230,"tx_batches":4586569,
      "avg_pps":4892341,"err_eagain":0,"err_other":0,
      "src_ip_base":"10.42.0.0","src_ip_span":65536,
      "src_port_base":1024,"src_port_span":65536,
      "dst_ip":"172.16.80.200","dst_port_base":5201,
      "dst_port_span":1,"seed":123456,
      "clock_source":"not-used-in-1611"}
     ```
     `clock_source` is a placeholder string for #1611 — the field
     name is reserved so the #1612 harness contract is stable. TSC
     measurement of the cold path lives in #1612 (dataplane-side).
     The flooder does not sample TSC itself in this PR.

7. **TSC handling for the flooder process**:
   - This PR does NOT add `--use-tsc`/`--use-clock-gettime` flags
     to the flooder. The flooder's loop-driver clock just needs
     ~1ms accuracy to manage the 30s duration and 1-second JSON
     emit cadence. `Instant::now()` (which uses
     CLOCK_MONOTONIC under the hood) is fine.
   - The TSC plumbing the issue mentions ("per-packet TSC
     timestamps", "refuse to start without invariant_tsc") was a
     misreading of the parent task prompt vs the plan v2-r4 §4.3
     spec. Plan v2-r4 places TSC measurement INSIDE the dataplane
     (the `ColdPathSampler` helper at
     `userspace-dp/src/afxdp/cold_path_hist.rs`). The flooder
     does not need TSC — it just generates packets. Per-packet
     TSC at 5+ Mpps from a userland process would itself cost
     ~50 ns/packet of overhead with zero measurement value.
   - The plan SMR-r1 author will surface this as a deliberate
     scope narrowing from the parent task prompt; reviewers may
     overrule.

8. **Unit tests** added (target 9 → ≥14):
   - `frame_assembly_default_v4_is_exactly_64_bytes`
   - `frame_assembly_ipv4_total_len_field_is_50` (matches plan
     §4.2.3 byte-accounting; protects against IHL/total-len drift)
   - `frame_assembly_udp_len_field_is_30`
   - `frame_assembly_ipv4_csum_matches_rfc1071` — golden-value
     check against a known-csum test vector.
   - `src_port_zero_never_emitted_with_default_base` — emit 1024
     packets with default `src_port_base=1024`, assert every
     emitted src_port >= 1024.
   - `dst_port_overflow_rejected_by_validator` — passing
     `dst_port_base=60000 dst_port_span=10000` returns Err.
   - `dst_port_base_plus_span_eq_65536_allowed` — boundary case.
   - `mmsghdr_array_layout_size` — `sizeof(mmsghdr) == sizeof(libc::mmsghdr)`
     pinning so any libc-crate type-drift fails CI.
   - `partial_sendmmsg_advances_correctly` — fake socket FD,
     simulate `sendmmsg` returning N < batch, assert next iteration
     starts at offset 0 again with fresh frames.

### 4.5 PACKET_QDISC_BYPASS (Codex r1 MAJOR + AGY r1 finding 2)

Codex r1 challenged the "≥3 Mpps single-core via plain
sendmmsg(32)" premise, citing kernel docs that point to
`PACKET_TX_RING` + `PACKET_QDISC_BYPASS` for high-rate user-space
flood generators. AGY r1 finding 2 ruled that
`PACKET_TX_RING` is overkill for a test harness (hundreds of LOC
of unsafe mmap state) but `PACKET_QDISC_BYPASS` is a clean
one-line `setsockopt` that adds significant per-syscall headroom
by skipping the kernel qdisc layer.

**v4 adopts `PACKET_QDISC_BYPASS` as the default** (no opt-in flag):

```rust
unsafe {
    let one: u32 = 1;
    let ret = libc::setsockopt(
        fd,
        libc::SOL_PACKET,
        libc::PACKET_QDISC_BYPASS,
        &one as *const u32 as *const libc::c_void,
        std::mem::size_of::<u32>() as libc::socklen_t,
    );
    if ret != 0 {
        // Don't hard-fail — older kernels may not have the option.
        // The harness still runs through the qdisc; the smoke gate
        // will catch the rate shortfall.
        eprintln!("warning: PACKET_QDISC_BYPASS setsockopt failed: {} \
                   (kernel < 3.14?) — continuing through qdisc",
                  std::io::Error::last_os_error());
    }
}
```

Per `man 7 packet`:
> `PACKET_QDISC_BYPASS (since Linux 3.14)` — By default, packets
> sent through packet sockets go through the kernel's qdisc
> layer. This option can be used to bypass the qdisc layer.

The loss userspace cluster runs kernels well above 3.14 so the
setsockopt succeeds in normal operation.

**PACKET_TX_RING** was considered and rejected in v4 per AGY r1
finding 2: the mmap state machine adds significant unsafe-code
risk for a test harness, and PACKET_QDISC_BYPASS provides the
headroom Codex r1 was asking for at one line of code. If the
≥3 Mpps blocking smoke gate fails even with PACKET_QDISC_BYPASS,
PACKET_TX_RING is the documented follow-up (filed at PR merge
time).

## Public API preservation

The cold-path-flooder binary IS the public API surface. Step-1
shipped the CLI flag set; this PR adds `--src-port-base` and is
otherwise backward-compatible. Pre-existing flags retain their
defaults. The exit-71 STUB tag from step-1 disappears (this PR
replaces it with the real loop). Downstream harnesses keying off
`$? == 71` to detect the stub will now see `$? == 0` on success
or a specific errno on failure — DESIRED behavior shift.

## Hidden invariants the change must preserve

1. **Workspace exclusion** — Cargo.toml stays outside the
   userspace-dp + userspace-xdp workspaces. A flooder build
   regression must NOT block dataplane builds. Verified by
   `find . -name Cargo.toml | xargs grep -l cold-path-flooder`
   should return only the flooder's own Cargo.toml.

2. **Frame size invariant** — the existing
   `const _: () = assert!(...)` compile-time check for the bounded
   cohort cap remains in place. Add a matching
   `const _: () = assert!(FRAME_V4_TOTAL == 64)` where
   `FRAME_V4_TOTAL = ETH + IPv4 + UDP + PAYLOAD`.

3. **Default port 5201** — must remain the iperf-a class port to
   keep the harness aligned with `cos-iperf-config.set`.

4. **No CAP_NET_RAW silent failure** — the AF_PACKET socket
   syscall returns EPERM in this case. The error path must include
   `"--- HINT: re-run with sudo or grant CAP_NET_RAW ---"` so the
   harness operator can immediately diagnose.

5. **No CoS-state mutation** — the flooder is pure transmit; it
   does not touch xpfd state or CoS config. Confirm by grep
   for any control-socket / gRPC / Prometheus client calls in
   the flooder — should be NONE.

## Risk assessment

| Class | Severity | Why |
|---|---|---|
| Behavioral regression risk | **MEDIUM** | sendmmsg semantics (partial-submit handling, EAGAIN) are easy to misread. Mitigated by `partial_sendmmsg_advances_correctly` unit test + integration smoke. |
| Lifetime / borrow-checker risk | **LOW** | Single-thread; `mmsghdr` array is owned by the loop scope. No `Arc` / `RwLock`. |
| Performance regression risk | **N/A** | This is a test binary; the existing dataplane is untouched. |
| Architectural mismatch risk | **LOW** | The architectural premise (AF_PACKET + sendmmsg + per-packet xorshift 5-tuple) was reviewed across 5 rounds in #1607. This PR implements; the premise has been settled. |

## Test plan

- `cargo build --release -p cold-path-flooder` (NOTE: not part of
  workspace; build via direct manifest path).
- `cd test/incus/cold-path-flooder && cargo build --release && cargo test --release`.
- New unit-test count: ≥14 (was 9).
- Per-test 5/5 flake check on the most-likely-flaky test
  (`partial_sendmmsg_advances_correctly`).
- Go suite from workspace root: no impact expected (binary is
  isolated). Verify with `go test ./... 2>&1 | tail -3` for
  confirmation.
- Smoke matrix (loss userspace cluster, both passes A and B,
  v4 + v6 push + reverse + per-class CoS 5201-5206). Smoke is
  required because we ship a new test tool that exercises the
  cluster — confirm CoS / HA invariants aren't disturbed by the
  test binary's existence.
- **Real-traffic smoke** — additional gate beyond the standard
  matrix: build flooder on `loss:cluster-userspace-host`, run
  for 30 s against `172.16.80.200:5201`, confirm:
  - Flooder achieves **≥2.5 Mpps single-core** — BLOCKING gate
    per Codex r1 MAJOR + AGY r1 finding 3. AGY r1 recommended
    2.5 Mpps (vs Codex's 3 Mpps) as a realistic
    virtio-VM-with-qdisc-bypass threshold; v4 adopts 2.5 Mpps.
    If the sendmmsg + PACKET_QDISC_BYPASS path can't hit 2.5 Mpps,
    the PR is BLOCKED — PACKET_TX_RING follow-up is filed and
    measurement work on #1612 cannot begin.
  - Dataplane does NOT crash, fail-closed, or OOM.
  - `journalctl -u xpfd` shows no new ERROR-level log lines
    during the flood.
  - Throughput on parallel iperf3 5201 (started 5 s into the
    flood) drops as expected (cold-path saturates), but reverts
    to baseline ≤2 s after the flood stops.
- **`#[ignore]` CAP_NET_RAW integration smoke** (Codex r1 MAJOR):
  a Rust `#[test] #[ignore]` test in the flooder crate that
  opens `AF_PACKET / SOCK_RAW`, binds to `lo`, sends a single
  64-byte frame, verifies clean exit + bytes counter ==
  frame_bytes. Skipped by default (requires root + env var
  `XPF_RUN_RAW_SOCKET_TESTS=1`); run manually via
  `XPF_RUN_RAW_SOCKET_TESTS=1 sudo -E cargo test --release -- --ignored test_open_af_packet_raw_smoke`
  on the cluster host alongside the real-traffic smoke.

## Out of scope (explicitly)

- Wire-protocol additions for cold-path counters. #1612.
- Prometheus emitter. #1612.
- `test/incus/cold-path-microbench.sh` harness. #1612.
- Scale Target table population. #1612.
- IPv6 flooder path. Follow-up issue (file at PR-merge time).
- `--tx-mbps` rate-limit knob — listed in plan v2-r4 line 215 as
  step-2 scope, but it requires per-packet token-bucket which
  expands review surface. Defer to a follow-up; default unbounded
  loop is the JIT-planning target anyway.
- `--ipv4 | --ipv6` flag from plan v2-r4 line 216. Defer with
  IPv6 follow-up.
- `--output-json <FILE>` flag from plan v2-r4 line 217. Defer —
  step-3 harness will redirect stdout to a file.
- ARP-resolve for `--dst-mac`. Plan v2-r4 documents this as
  optional; for the loss userspace cluster the peer MAC is
  stable and operator-known. Fail-fast on missing `--dst-mac`
  is simpler and avoids a whole ARP state machine.

## Open questions for adversarial review

1. **sendmmsg max practical batch**: We assert `batch <= 1024`
   in step-1 validation, and the plan §4.2.1 says batch=32 is the
   line-rate gate. Should we lower the upper bound to a kernel-
   verified value? `UIO_MAXIOV = 1024` per `man 7 socket`, so
   1024 is the kernel-enforced cap. Reviewers should confirm.

2. **IPv4 ID field randomization**: The IPv4 ID is part of frag
   reassembly; some kernels rate-limit ICMP-frag-needed on
   duplicate-ID streams. Is per-packet xorshift-derived ID OK?
   AGY r3 didn't flag this; reviewers may want to confirm there's
   no kernel-side rate-limit drop path that biases the histogram.

3. **--src-port-base default**: I'm defaulting to 1024 (ephemeral
   range start) to avoid reserved port 0. This contradicts the
   parent task prompt which says "NOT skipping port 0 (reserved
   port 0 IS in the iteration to verify the firewall handles
   it)". But `metadata_tuple_complete` at inspect.rs:207 short-
   circuits TCP/UDP flows with src_port=0 onto a different code
   path, which IS what we want to AVOID measuring. Which trumps
   — task prompt or codebase reality? My read: codebase reality.
   Reviewers may overrule.

4. **No TSC in the flooder**: Plan v2-r4 §4.3 puts TSC sampling
   in the DATAPLANE (`userspace-dp/src/afxdp/cold_path_hist.rs`),
   not the flooder. The parent task prompt mentions TSC in the
   flooder context — I read this as a misreading of the v2-r4
   plan. Reviewers should confirm: should the flooder do its
   own TSC sampling, or is the dataplane-side
   `ColdPathSampler` the only TSC consumer?

5. **No IPv6 in this step**: AddressBookSnapshot dual-stack
   landed in #1606 so the dataplane can match v6. But the
   flooder's frame-assembly path doubles (v4 + v6 separate code
   paths) and the unit-test surface grows ~6 tests. Defer to a
   follow-up issue, or land here? My read: defer — JIT-planning
   data wants v4 first; v6 measurements can land later.

6. **Real-traffic smoke vs simulation**: The runner body smoke is
   the FIRST time we'll see whether sendmmsg from a userland Rust
   binary on the loss cluster host can sustain ≥3 Mpps single-
   core. If it can't, the harness design is wrong and we need to
   rethink before #1612. Reviewers should weigh whether the
   smoke gate is sufficient.

7. **Drop of `--cohort=bounded` measurement value**: The bounded
   regime fills the session table and measures install +
   replicate. The JIT-planning Scale Target is the unbounded
   regime per AGY r3 axis 1. Should the bounded regime stay or
   be retired? My read: keep it — diagnostic value for
   isolating install+replicate cost is real and the code cost is
   modest.
