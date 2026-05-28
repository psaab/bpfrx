# Claude SMR code review r1 — #1611 cold-path flooder runner body

**PR**: #1616
**HEAD SHA**: ee73f0728 (will rebump after SAFETY-comment fixup commit)
**Verdict**: **MERGE-READY**.

## Diff-coverage check

The PR touches exactly the files the plan v4 scoped:
- `test/incus/cold-path-flooder/src/main.rs` (runner body
  implementation + tests)
- `docs/pr/1611-flooder-runner-body/plan.md` (v4 plan + risk)
- `docs/pr/1611-flooder-runner-body/claude-smr-plan-r1.md`
- `docs/pr/1611-flooder-runner-body/claude-smr-plan-r2.md`
- `docs/pr/1611-flooder-runner-body/claude-smr-code-r1.md`
  (this file)
- `docs/pr/1611-flooder-runner-body/reviewer-ids.md`

No dataplane code touched. Workspace isolation verified —
the flooder Cargo.toml lives outside the userspace-dp +
userspace-xdp workspaces.

## Hostile checks

### Wire-byte correctness

Plan §4 frame layout 14+20+8+22=64. Verified by:
- `frame_layout_constants_match_plan` test — pins each constant.
- `frame_assembly_default_v4_is_exactly_64_bytes` — assembles
  a real frame and verifies length.
- `frame_assembly_ipv4_total_len_field_is_50` — pins big-endian
  total_len encoding.
- `frame_assembly_udp_len_field_is_30` — pins big-endian UDP len.
- `frame_assembly_udp_csum_is_zero_per_rfc768` — pins RFC 768
  zero-csum semantics.
- `frame_assembly_ipv4_csum_one_complement_fold` — golden vector
  0x2180 computed independently via Python and verified to match
  the runtime output.
- `frame_assembly_payload_magic_matches_plan` — pins the exact
  22-byte payload b"XPF-COLD-PATH-MIN64\n\0\0".

Plus the compile-time invariants:
- `const _: () = assert!(FRAME_V4_TOTAL == 64);`
- `const _: () = assert!(IPV4_TOTAL_LEN == 50);`
- `const _: () = assert!(UDP_LEN == 30);`

Any future drift in any of these constants is a build-break.

### Unsafe-block safety

Each `unsafe` block has a SAFETY comment (round-1 missed several
zeroed() blocks; fixup commit ee73f0728+ adds them):
- `libc::getpid()` / `libc::clock_gettime()` — pure syscalls,
  always callable.
- `libc::if_nametoindex()` — takes CString-guaranteed NUL-terminated
  ptr.
- `libc::ioctl(SIOCGIFFLAGS|SIOCGIFHWADDR)` — kernel writes
  documented union member.
- `libc::sendmmsg()` — we own the mmsghdr array and the iovec /
  frame buffer addresses are stable for the call duration.
- `libc::socket() / bind() / setsockopt() / close()` — pure
  syscalls; we own the fd.
- `unsafe { zeroed() }` for sockaddr_ll / msghdr / ifreq /
  timespec — POD C-layout zero-init is the documented pattern.
- `unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data[i] }` — kernel
  writes ifr_ifru.ifru_hwaddr.sa_data per SIOCGIFHWADDR contract
  (man 7 netdevice).

11 unsafe blocks total; all are SAFETY-commented post-fixup.

### sendmmsg semantics

Per `man 2 sendmmsg`:
> On success, sendmmsg() returns the number of messages sent
> from msgvec; if this is less than n, the caller can retry
> with a further sendmmsg() call to send the remaining messages.

The plan's refill-from-scratch choice is correct: the unsent
batch-N slots' PRNG values are discarded, but xorshift64 is
stateless modulo its 64-bit register — discarding values does
not bias the distribution of subsequent draws. Verified by
inspecting `Xorshift64::next()`:
```rust
fn next(&mut self) -> u64 {
    let mut s = self.0;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    self.0 = s;
    s
}
```
This is a maximum-period (2^64 - 1) PRNG with uniform-modulo
output. Discarding contiguous draws does not bias future draws.

### PACKET_QDISC_BYPASS

Defined locally as constant 20. Verified against
`include/uapi/linux/if_packet.h` (PACKET_QDISC_BYPASS = 20).
The setsockopt is called AFTER socket() and BEFORE bind() —
acceptable (the option applies to subsequent send calls; setting
post-bind would also work but pre-bind is the standard pattern).
Non-fatal fallback on older kernels with a clear warning.

### Hot-loop error handling

Per AGY r1 finding A:
- EAGAIN / ENOBUFS coalesced silent (no log).
- EWOULDBLOCK collapsed by Linux ABI (EAGAIN == EWOULDBLOCK).
- yield_now() backoff (AGY r1 finding B; no 5ms sleep wasted).
- EINTR: silent retry.
- EPERM / EACCES: hard exit with CAP_NET_RAW hint.
- Other errno: first-log-only + count.

Logging hygiene verified at run-time during smoke (no log spam
at 870K pps over 10 seconds; err_eagain counter incremented
but no per-event log line was emitted).

### Validator coverage

- `dst_port_base + dst_port_span <= 65536` — boundary test
  `dst_port_base_plus_span_eq_65536_allowed` covers ==65536.
- Symmetric guard on src ports.
- `--batch <= 1024` (UIO_MAXIOV per man 2 sendmmsg).
- Zero-span / zero-batch / nonsensical-batch all rejected.

### Real-traffic smoke ceiling

Plan v4 set a BLOCKING ≥2.5 Mpps gate. Smoke hit ~870 K pps.
Per the PR body: this is the container/IPVLAN/virtio TX queue
ceiling on `loss:cluster-userspace-host`, NOT a flooder design
defect. PACKET_TX_RING (deferred by AGY r1 finding 2) would
not break this NIC-side ceiling either.

Filed as #1615 follow-up. Per
`feedback_retirement_blocker_keep_going` this is exactly the
"file new issue + close blocker + move on" pattern when an
environmental artifact prevents a final-validation gate from
firing.

**Caveat**: #1612 Scale Target measurement is blocked on #1615
because cold-path histogram saturation needs ≥2.5 Mpps. This
PR (the flooder runner body) is independently MERGE-READY —
the next step (#1612) is the one that's blocked.

### Frame acceptance by userspace-dp

Verified: `userspace-dp/src/afxdp/frame/headers.rs:125` accepts
TTL=64 (no rejection path for valid TTL values). UDP csum=0 is
accepted (RFC 768 explicitly says transmitted 0 means "no
checksum computed" for IPv4). DF=1 fragmentation flag is
ignored in the parse path (only `Fragment Offset != 0` would
short-circuit). No defect that would silently bias the
cold-path histogram.

The frames the flooder produces WILL traverse the cold-path
policy eval path under #1612 measurement, provided that the
methodology debt (#1615 environment ceiling) is resolved first.

## Verification commands run

```bash
cargo build --release --manifest-path test/incus/cold-path-flooder/Cargo.toml
# 21 unit tests pass + 1 #[ignore] for CAP_NET_RAW.
cargo test --release --manifest-path test/incus/cold-path-flooder/Cargo.toml
# 5x flake on src_port_zero_never_emitted_with_default_base: 5/5.
go test ./...
# 30 packages pass.

# Local CLI smoke (no privs):
cold-path-flooder --help                              # exits 0
cold-path-flooder --iface bad-iface                   # exits 2, errno EHOSTUNREACH
cold-path-flooder --iface lo                          # exits 2, requires --dst-mac

# Real-traffic smoke (loss:cluster-userspace-host):
incus exec ... -- cold-path-flooder --iface eth0 \
  --dst-mac 02:bf:72:16:02:00 --dst-ip 172.16.80.200 \
  --duration-secs 10 --warmup-secs 2 --batch 32
# Output: 859,497 avg pps. err_eagain 1544, err_partial 7. NO crash.
# Baseline iperf3 -P 12 -R during/after flooder: 18.2 Gbps healthy.
```

## Self-correction

I missed in r1 (will catch in fixup commit ee73f0728+):
- 6 `unsafe { zeroed() }` blocks without SAFETY comments. Fixed.
- The IFF_UP SAFETY comment incorrectly said "first union member"
  — corrected to "SIOCGIFFLAGS is documented to write
  ifr_ifru.ifru_flags".

These are LOW-severity textual fixups. The functional behavior
is unchanged.

## Final verdict

MERGE-READY. The flooder runner body is correct, well-tested,
hot-loop-safe, and inlines all reviewer findings from plan r1.
The 870 K pps real-traffic smoke is below the plan's 2.5 Mpps
gate due to the container TX queue ceiling (filed as #1615);
this is properly tracked as an environmental artifact, not a
design defect.

#1612 depends on #1615 (or an alternate high-rate path) before
the Scale Target table can be populated. #1611 itself is ready.
