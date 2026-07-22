# XSK Zero-Copy Rebind Test

Standalone AF_XDP reproducers used to isolate a zero-copy rebind bug from the
xpfd dataplane. They load their **own** minimal XDP redirect program
(`xdp_pass_redirect.c`), bind an AF_XDP socket, receive for a few seconds, cycle
the link, rebind, and compare receive counts.

Status: Inconclusive — cannot fully isolate from the xpfd daemon (the daemon's
status loop overwrites the xskmap/binding entries while co-resident). Retained as
diagnostic tooling.

## Tools

| File | Binary | AF_XDP path |
|------|--------|-------------|
| `libbpf_xsk_test.c` | `libbpf-xsk-test` | libbpf `xsk_socket__create` |
| `libbpf_xsk_shared_test.c` | `libbpf-xsk-shared-test` | libbpf `xsk_socket__create_shared` (owner + secondary) |
| `main.rs` | `xsk-rebind-test` | `xdpilone` (pure-Rust AF_XDP) |

## Build

```bash
make                 # builds the two C tools with -Wall -Wextra -Werror
cargo build --release   # builds the Rust tool (xsk-rebind-test)
make regen-obj       # rebuild xdp_pass_redirect.o from source (see below)
```

The XDP object is **compiled into** every binary — the C tools embed it through a
generated header (`xdp_pass_redirect_obj.h`, produced by `xxd -i`), the Rust tool
via `include_bytes!`. It is loaded with `bpf_object__open_mem` and never read from
a filesystem path. If a newer `elfutils`/`libbpf` rejects the committed
`xdp_pass_redirect.o`, refresh it with `make regen-obj` (needs `clang` with the
BPF target; the arch include dir supplies `<asm/types.h>`).

## Run (root, against a live interface)

```bash
sudo ./libbpf-xsk-test <iface> <queue> [copy|zerocopy]
sudo ./libbpf-xsk-shared-test <owner-iface> <owner-queue> \
        [<secondary-iface> <secondary-queue>] [copy|zerocopy]
sudo ./xsk-rebind-test <iface> <queue> [--copy]
```

Exit codes: `0` PASS, `1` FAIL, `2` INCONCLUSIVE (the link DOWN/UP cycle did not
run, so the rebind phase was skipped).

> **These tools attach XDP to and cycle the link of a live interface.** They now
> refuse to replace an XDP program already on the interface (`UPDATE_IF_NOEXIST`)
> and only detach their own program (`REPLACE` + `old_prog_fd`), so pointing one
> at the firewall's dataplane interface aborts cleanly instead of stripping its
> XDP program. Do not point them at an interface carrying production traffic —
> the link is bounced.

## Safety & correctness hardening (#4906)

These are root tools run against the live firewall interface, so a cohort of
safety/false-result defects (Codex review 175, C175-HC-001/025/069/081/090/091/
095/101) were fixed:

- **HC-001** — unchecked `fork()` + unconditional `kill(child,9)`: on `fork()`
  failure `child==-1` made cleanup call `kill(-1,SIGKILL)` (host-wide as root).
  Now `fork()` is checked and the kill is guarded on `child>0`.
- **HC-025** — predictable `/tmp/xdp_pass_redirect.o`: the Rust tool wrote it as
  root (symlink-clobber hazard) and the C tools loaded a world-writable-namespace
  path with no inode/mode check. Now the object is embedded and loaded from memory
  (`bpf_object__open_mem`) — no filesystem path, no TOCTOU.
- **HC-101** — replace-and-detach a live XDP program: attach used flags `0`
  (silently replacing whatever was there) and detach removed prog `-1`
  unconditionally; a panic after attach skipped cleanup. Now attach uses
  `XDP_FLAGS_UPDATE_IF_NOEXIST` (never clobber) and detach uses `XDP_FLAGS_REPLACE`
  + `old_prog_fd` (remove only ours); the Rust tool wraps this in an RAII guard so
  it detaches even on panic.
- **HC-090** — rebind ran even if the link cycle never happened: `system()` /
  `.status().ok()` ignored `ip link` failures (and `system()` interpolated the
  interface name into a shell). Now the link cycle is a checked, shell-free
  `fork`/`exec` (Rust: `Command` + `status().success()`); phase 2 is skipped and
  the result is `INCONCLUSIVE` if the cycle did not complete.
- **HC-091** (Rust) — the UMEM was `munmap`'d while the socket/UMEM owners were
  still alive. They are now scoped so every owner drops before the `munmap`.
- **HC-081** — uninitialized phase counters could print `PASS`: `rx1`/`rx2` were
  declared past `goto cleanup`, so an early failure read indeterminate values.
  They are initialized before any goto. **Fail-on-revert:** the Makefile builds
  with `-Werror -Wjump-misses-init`, so reverting this makes the build fail;
  `test/xsk-repro/selftest-compile.sh` runs that gate under `make selftest`.
- **HC-069** — frame recycling without preserving received UMEM addresses: the C
  loop released RX descriptors before reading them and used the completion-ring
  accessor (`comp_addr`) on the RX ring; the Rust loop never `release()`d the
  reads (so `ReadRx`'s `#[must_use]` Drop cancelled the peek and re-read the same
  descriptors) and re-inserted the original offsets regardless of what was
  consumed. Now both read the RX descriptor addresses first, release, and recycle
  exactly the consumed (chunk-aligned) frames.
- **HC-095** — the shared-UMEM secondary socket was created but never read, so
  PASS reflected only the owner. The secondary now has its own (disjoint) UMEM
  frames primed, is polled and recycled, and its receive count is folded into
  PASS/FAIL; a distinct secondary interface also gets the redirect program.
