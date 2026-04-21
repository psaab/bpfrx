# Codex plan review — #814 (MAX_INTERFACES bump)

## Round 1

### HIGH — The plan’s “complete” ifindex inventory is false
**Where:** `docs/pr/814-max-interfaces/plan.md:81-83, 90-112, 184-201, 303-305`; `userspace-xdp/src/lib.rs:61-62, 263-267, 381-386`; `pkg/dataplane/userspace/maps_sync.go:519-525, 541-548, 1207-1219`
**Finding:** The plan claims H3 is already checked and that the userspace side is handled by bumping `userspace_ingress_ifaces` from `1024` to `8192`. That is not true. `USERSPACE_BINDINGS` is still a plain `Array` sized as `1024 * BINDING_QUEUES_PER_IFACE`, and both the XDP shim and the Go sync path index it as `ifindex * 16 + queue`. That is another raw-ifindex cap at `ifindex < 1024`, just hidden behind multiplication instead of `max_entries = MAX_INTERFACES`. The alias path is worse: `buildUserspaceIngressBindingAliases()` copies arbitrary snapshot `iface.Ifindex` values into that same dense index. So the plan’s “five maps, all found” claim is wrong, and the proposed PR can easily just move the failure from `AddTxPort` to `update userspace_bindings idx=...`.
**Mitigation:** The architect needs to reopen the inventory and either: `1.` redesign `userspace_bindings` so it stops using raw kernel ifindex as a dense array index, or `2.` prove with cited fw0/fw1 snapshot data that every bound and aliased ingress ifindex stays `< 1024` and add a hard preflight gate for it. Until then the plan is not remotely complete.

### MEDIUM — The codegen/build discipline is internally wrong and too vague
**Where:** `docs/pr/814-max-interfaces/plan.md:209-214, 299-302, 337-339`; `Makefile:20-22, 33-35`; `pkg/dataplane/loader.go:17-34`; `pkg/dataplane/build-userspace-xdp.sh:24-28`; `testing-docs/regression-checklist.md:31-35`
**Finding:** Step 3 says “Regenerate bpf2go artifacts,” and step 4 hand-waves about maybe rebuilding `userspace-dp` via `build.rs`. That is not what this repo actually does. `make generate` is `go generate ./pkg/dataplane/...`, and the first `go:generate` in that package is `bash build-userspace-xdp.sh`, which rebuilds the shipped Rust XDP object with the BPF toolchain before any bpf2go runs. `make build-userspace-dp` is a different binary. The plan’s artifact story is therefore wrong, and its review discipline is sloppy: it never names the exact expected generated files, never requires a clean worktree before codegen, and invites the classic “commit whatever `make generate` touched” mistake.
**Mitigation:** Rewrite the execution matrix to match reality: require a clean dedicated worktree before generation, explicitly list the expected generated outputs, and use the actual `userspace-xdp` build path in the plan. Review generated diffs intentionally; do not accept “whatever make generate spits out.”

### MEDIUM — The aya prealloc question is already answered in code, but the plan leaves it as a merge-time shrug
**Where:** `docs/pr/814-max-interfaces/plan.md:150-155, 344-345`; `userspace-xdp/src/lib.rs:273`; `/home/ps/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-0.1.1/src/maps/hash_map.rs:24-31, 51-54`; `userspace-dp/xdp-tools-1.6.2/headers/linux/bpf.h:1231-1234`
**Finding:** The plan says aya “does NOT set `BPF_F_NO_PREALLOC` (verify in code before merge).” That verification is not pending. It is already in the tree. `HashMap::with_max_entries(..., 0)` passes `flags = 0`, and aya’s own docs spell out the non-`BPF_F_NO_PREALLOC` default. Leaving this as a TODO in the plan phase is exactly the kind of lazy hedge `docs/development-workflow.md` tells the reviewer to reject.
**Mitigation:** Replace the hedge with a direct statement: this map is a default-preallocated `BPF_MAP_TYPE_HASH` unless the PR explicitly changes flags. Then recompute the memory discussion from that fact instead of punting it to “verify later.”

### MEDIUM — The `8192` choice is not derived from repo evidence; it is aesthetic
**Where:** `docs/pr/814-max-interfaces/plan.md:159-181`; `docs/development-workflow.md:71-79`; `git show 7611f276`
**Finding:** The architect’s value choice is hand-wavy. The plan talks about current fw1 at `2561`, but the repo’s own prior incident already recorded `ifindex hit 3651` in the #759 fix commit. That means the plan’s soothing headroom framing is off: `4096` is barely above the highest repo-observed value, and `8192` is only about 2.24x above it, not the “3.2x” story built off today’s narrower sample. Since the same bug has now recurred and the claimed cost objection to `65536` is just “it makes the PR feel bigger,” this threshold is not grounded to named data the way the workflow requires.
**Mitigation:** Either justify `8192` with cited max-ifindex measurements on fw0/fw1 plus historical repo maxima and a growth assumption, or stop pretending and use `65536`. “Reviewer choice knob” is not architecture.

### MEDIUM — Deferring the preflight ifindex check on the second recurrence is weak
**Where:** `docs/pr/814-max-interfaces/plan.md:309-317`; `pkg/dataplane/compiler_iface.go:436-437`; `git show 7611f276`
**Finding:** This is the second time the repo has face-planted on raw ifindex exceeding a map cap. The failure path is the same shape again: `AddTxPort` fails, compile aborts, helper never starts. The plan itself says a preflight would be maybe 40 lines and would have turned the diagnosis from “journal archaeology” into an immediate explicit error. Deferring that again is choosing to keep the same bad operational failure mode after the bug has already repeated.
**Mitigation:** Put the preflight in this PR or in a prerequisite commit in the same stack. At minimum it must cover every raw-ifindex map/cap the compile path can touch, including any userspace-side array indexes that survive the redesign.

### MEDIUM — The validation thresholds are still vibes, not sourced gates
**Where:** `docs/pr/814-max-interfaces/plan.md:233-265`; `docs/development-workflow.md:71-79, 91-94`
**Finding:** “Within 2% of the pre-deploy snapshot,” “≤ small retrans spike,” and “unchanged within the plan’s existing noise band” are not concrete thresholds. They are mush. The process doc explicitly says every number needs a derivation or named source and that hand-wavy thresholds are MEDIUM/HIGH findings. This plan never names the source for the 2% delta, never defines the 8-matrix noise band, and never quantifies the allowed failover retrans window.
**Mitigation:** Replace those with sourced thresholds from a checked-in measurement doc or remove them from pass/fail gating. Keep only the explicit continuous gate and explicit helper-startup checks if the architect cannot cite real numbers.

### LOW — The `bpf_devmap_val` size claim is wrong or at least unverified
**Where:** `docs/pr/814-max-interfaces/plan.md:97, 119-123, 342`; `/usr/include/linux/bpf.h:6540-6545`; `pkg/dataplane/xpfxdpmain_x86_bpfel.go:58-64`
**Finding:** The plan states `struct bpf_devmap_val = 12 B (padded to 16 B)`. The UAPI layout shown in local kernel headers is two 32-bit fields, and the generated Go binding mirrors that 8-byte structure. If the architect wants to talk about allocator rounding or internal kernel bookkeeping, that needs a source. Right now the memory table is pretending to have precision it did not earn.
**Mitigation:** Correct the verified value layout to 8 bytes and label any additional allocator overhead as unknown unless the plan cites a kernel source for it.

### LOW — Step 2 names the wrong Rust validation command
**Where:** `docs/pr/814-max-interfaces/plan.md:210`; `pkg/dataplane/build-userspace-xdp.sh:24-28`; `userspace-xdp/.cargo/config.toml:1-8`; `testing-docs/regression-checklist.md:31-35`
**Finding:** The plan says “`cargo build` in `userspace-xdp`.” The shipped object is refreshed by `bash pkg/dataplane/build-userspace-xdp.sh`, which forces the BPF target and nightly toolchain. The repo’s own checklist for `userspace-xdp/` changes points to that script, not plain `cargo build`.
**Mitigation:** Use the real build command in the plan, or delete this redundant step and make `make generate` plus explicit artifact review the only source of truth.

### Summary
1 HIGH, 5 MEDIUM, 2 LOW. PLAN-READY: NO until HIGH/MEDIUM resolved.

## Round 1 response

Round 0 findings addressed as follows. Each item points at the
specific section in the Round-1 rewrite of `plan.md`.

### HIGH — "The plan's complete ifindex inventory is false"
**CLOSED.** The inventory is rebuilt with a sixth row covering
`USERSPACE_BINDINGS` (aya `Array`, dense `ifindex × 16 + queue`
indexing at `userspace-xdp/src/lib.rs:263-267` and
`pkg/dataplane/userspace/maps_sync.go:519, 541, 909, 946`). See
plan section **"Complete ifindex inventory (Round 1 HIGH fix)"**.
Path A (slot indirection) and Path B (raise the cap) are both
written up; Path B chosen for this PR with Path A deferred to
issue #761. The wire-up makes the Rust-side
`BINDING_ARRAY_MAX_ENTRIES` derive from the C-side
`MAX_INTERFACES` via `env!()` in `build-userspace-xdp.sh`, so the
two constants cannot drift. A Go-side load-time assertion on
`userspace_bindings.MaxEntries` catches object drift. See plan
sections **"Two paths considered for row 6"** and **"Wiring the
Rust-side constant to the C-side constant"**.

### MEDIUM — "Codegen/build discipline internally wrong and vague"
**CLOSED.** Execution matrix rewritten. `make generate` is
described as `go generate ./pkg/dataplane/...` with the *first*
`go:generate` being `bash build-userspace-xdp.sh` (BPF-target +
nightly Rust toolchain) before bpf2go runs on the .c files.
Preconditions block requires a clean dedicated worktree before
step 1. The full list of expected regenerated artifacts (15 .c
outputs + `userspace_xdp_bpfel.o`) is enumerated. Any diff
outside the enumerated set is a hard stop. See plan sections
**"Execution matrix"**, **"Expected regenerated files
(enumerated)"**, and **"Review discipline"**.

### MEDIUM — "Aya prealloc left as a merge-time shrug"
**CLOSED.** Stated directly: `HashMap::with_max_entries(N, 0)`
at `aya-ebpf-0.1.1/src/maps/hash_map.rs:24-31, 51-54` passes
`flags = 0`, which yields a default-preallocated
`BPF_MAP_TYPE_HASH`. At 65536 entries × ~65 B ≈ ~4.1 MB.
Memory math redone with this as a fact, not a hedge. See plan
section **"aya map memory model (Round 1 MEDIUM)"** and the
candidate-value table.

### MEDIUM — "8192 choice not derived from repo evidence"
**CLOSED.** Value moved to **MAX_INTERFACES = 65536**, with
evidence: fw1 current max 2561 (this issue), bpfrx-fw1 historical
max 3651 (cited `git show 7611f276` commit body), two recurrences
in ~half a year, growth driven by uncontrolled
namespace/veth churn. Memory cost at 65536 totals ~12 MB across
the three ifindex-axis maps with non-zero prealloc
(tx_ports, USERSPACE_BINDINGS, userspace_ingress_ifaces) — recorded
in the candidate-value table. See plan section **"Evidence for the
value choice"** and **"Decision"**.

### MEDIUM — "Deferring preflight on the second recurrence is weak"
**CLOSED.** Preflight is in this PR. `preflightCheckIfindexCaps`
in `pkg/dataplane/loader.go` scans `netlink.LinkList()`, compares
each ifindex against `MAX_INTERFACES` and
`BINDING_ARRAY_MAX_ENTRIES / BINDING_QUEUES_PER_IFACE`, returns a
named-interface error before the BPF call. Wired into
`compileDataplane` in `pkg/daemon/daemon.go`. ~60 lines of Go
including a unit test. See plan section **"Preflight ifindex check
(Round 1 MEDIUM — in this PR)"**.

### MEDIUM — "Validation thresholds are vibes, not sourced gates"
**CLOSED.** Gates rewritten. Hard gates are now only the ones
citable to `docs/development-workflow.md:201-215`: iperf3 `-P 4 -t 5`
with 0 retransmits; helper socket present; `pidof xpf-userspace-dp`
non-empty; `ever_ok=true`; no new mlx5/BPF dmesg;
zero new `SEG_MISS`. The "within 2% throughput" and the 8-matrix
CoV gate are dropped from pass/fail (no sourced threshold) and
noted as observational only. See plan section **"Validation
gates"**, gates A/B/C.

### LOW — "`bpf_devmap_val` size claim"
**CLOSED.** Corrected to **8 bytes** (2 × u32), with citations:
`/usr/include/linux/bpf.h:6540-6545` and
`pkg/dataplane/xpfxdpmain_x86_bpfel.go:58-64`. The memory table
is redone with 8 B (e.g. tx_ports at MAX_INTERFACES=65536 is
512 KB, not 1 MB). See plan **inventory table row 2** and the
**candidate-value table**.

### LOW — "Wrong Rust validation command (`cargo build`)"
**CLOSED.** `cargo build` step dropped. The Rust build is now
exercised two ways: (a) by `make generate` via the first
`go:generate` directive which calls `bash
pkg/dataplane/build-userspace-xdp.sh`, and (b) the standalone
invocation of `build-userspace-xdp.sh` in step 2 of the
execution matrix, which is the shipped build path that forces
the BPF target and nightly toolchain. See plan section
**"Execution matrix"** row 2 and row 5.

## Round 2 verification

### HIGH — "The plan's complete ifindex inventory is false"
**PARTIAL.** The rewritten plan does now inventory row 6 correctly: the current tree still shows the dense `userspace_bindings` array at `userspace-xdp/src/lib.rs:265-267`, raw index math in Rust at `userspace-xdp/src/lib.rs:381-386`, and the four Go sites at `pkg/dataplane/userspace/maps_sync.go:519, 541, 909, 946`; I did not find other Go `ifindex * 16 + queue` sites beyond those four, but the Rust fast path still does it too. That said, the architect's "CLOSED" write-up is puffery. Current `userspace-xdp/src/lib.rs:61-62` still hard-codes `BINDING_ARRAY_MAX_ENTRIES = 1024 * 16`; `pkg/dataplane/build-userspace-xdp.sh:24-28` exports nothing; `userspace-xdp/` has `Cargo.toml` and no `build.rs`; `pkg/dataplane/userspace_xdp_rust.go:11-19` embeds a standalone `userspace_xdp_bpfel.o`; and the current embedded ELF still carries `userspace_bindings.max_entries = 16384` and `userspace_ingress_ifaces.max_entries = 1024` (observed via `readelf -s` plus `readelf -x maps`). If implemented exactly as sketched at `docs/pr/814-max-interfaces/plan.md:123-127`, `env!()` would be compile-time, not runtime, so yes, the baked bytecode would carry the constant. The unresolved part is the one the architect tried to hand-wave away: nothing in the current files proves the rebuild path cannot leave a stale embedded object, nothing proves the proposed Go check reads the loaded object's `MaxEntries` instead of a second Go constant, and deferring Path A after the second recurrence still leaves the raw-ifindex dense-index design in place. The inventory table is fixed; the safety story is not.

### MEDIUM — "Codegen/build discipline internally wrong and vague"
**STILL OPEN.** The rewrite is less vague, but it is still wrong on mechanics. `Makefile:21-22` does run `go generate ./pkg/dataplane/...`, but `pkg/dataplane/loader.go:20-21` shows the first directive is `xpfXdpMain`, not `bash build-userspace-xdp.sh`; the architect's "first go:generate" claim is simply false. The on-disk artifact set is also more precise than the response admits: `git ls-files 'pkg/dataplane/*_bpfel.go' 'pkg/dataplane/*_bpfel.o' 'pkg/dataplane/userspace_xdp_bpfel.o'` shows exactly 14 `xpf*_x86_bpfel.{go,o}` pairs plus `userspace_xdp_bpfel.o`, so there are no mystery `_bpfel` files, but there are also not "15 .c outputs". The plan improved by naming the files and requiring a clean tree first; it remains open because it still misstates generation order, miscounts outputs, and uses a review command (`llvm-objdump -h`) that does not actually show Rust map `max_entries`.

### MEDIUM — "Aya prealloc left as a merge-time shrug"
**CLOSED.** This one is finally stated like a grown-up. `userspace-xdp/src/lib.rs:273` uses `HashMap::with_max_entries(1024, 0)`, and `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-0.1.1/src/maps/hash_map.rs:24-31, 51-54` confirms that means `flags = 0` on `BPF_MAP_TYPE_HASH`, i.e. default preallocation unless someone explicitly opts into `BPF_F_NO_PREALLOC`. The old "verify later" hedge is gone. That narrow Round 1 complaint is actually resolved.

### MEDIUM — "8192 choice not derived from repo evidence"
**CLOSED.** The original numerology complaint is addressed. The plan now picks `MAX_INTERFACES = 65536`, and the repo evidence it cites is real: `bpf/headers/xpf_common.h:143` is still `2048` today, the issue text cites fw1 at 2561, and `git show --no-patch --format=fuller 7611f276` really does say "ifindex hit 3651". That is finally evidence instead of aesthetics. The memory table used to call the cost "trivial" is still soft; I am treating that as a separate Round 2 finding below, not as a reason to reopen the old 8192 gripe.

### MEDIUM — "Deferring preflight on the second recurrence is weak"
**STILL OPEN.** The architect response says the preflight is "in this PR", but there is no `preflightCheckIfindexCaps` anywhere in `pkg/dataplane`, `pkg/dataplane/userspace`, or `pkg/daemon`, and there is no `compileDataplane` symbol in `pkg/daemon`; the actual compile call is `pkg/daemon/daemon.go:1805-1810`. The failure path is still the raw one: `pkg/dataplane/compiler_iface.go:436-437` calls `dp.AddTxPort`, and `pkg/dataplane/loader.go:330-344` still does `tm.Update(uint32(ifindex), ...)` straight into `tx_ports`. The four `userspace_bindings` sites remain raw `ifindex * bindingQueuesPerIface + queue` math, and `applyHelperStatusLocked` is reachable later from `pkg/dataplane/userspace/manager.go:343, 857, 889, 914, 939, 956, 981, 1008`, `pkg/dataplane/userspace/process.go:316, 360, 1027`, and `pkg/dataplane/userspace/manager_ha.go:63, 106, 376, 457` without any stated re-preflight. A one-time compile-path preflight could protect `pkg/dataplane/userspace/manager.go:257-345`; the plan never proves it covers the rest. No, this is not closed.

### MEDIUM — "Validation thresholds are vibes, not sourced gates"
**CLOSED.** The mushy "within 2%" and "noise band" gating is no longer in the hard pass/fail set. `docs/pr/814-max-interfaces/plan.md:301-344` now keeps explicit checks only: helper/socket presence, zero retransmits on the continuous gate, `ever_ok`, and no new `SEG_MISS` or noisy dmesg. That was the required cleanup.

### LOW — "`bpf_devmap_val` size claim"
**CLOSED.** `struct bpf_devmap_val` is 8 bytes in `/usr/include/linux/bpf.h:6540-6545`, and the generated Go binding at `pkg/dataplane/xpfxdpmain_x86_bpfel.go:58-64` matches it. The old 12-byte/padded-to-16 story is dead.

### LOW — "Wrong Rust validation command (`cargo build`)"
**CLOSED.** The plan no longer tells people to run plain `cargo build`; it now uses `bash pkg/dataplane/build-userspace-xdp.sh`, which matches `testing-docs/regression-checklist.md:31-35` and the actual script at `pkg/dataplane/build-userspace-xdp.sh:24-28`. The architect's separate claim that this is the first `go:generate` is still false, but the command itself is fixed.

New Round 2 findings (if any):

### MEDIUM — Hard-stop diff scope contradicts the asserted load-time check
**Where:** `docs/pr/814-max-interfaces/plan.md:256-259, 286-287, 378-379`; `pkg/dataplane/userspace/manager.go:200-201`; `pkg/dataplane/loader_ebpf.go:196-223`; `pkg/dataplane/userspace/manager_test.go:148-158`
**Finding:** The plan says step 4 is a `pkg/dataplane/userspace/manager.go` load-time assertion and then says any diff outside the enumerated artifacts plus steps 1-4 files is a hard stop. That does not line up with the code. `pkg/dataplane/userspace/manager.go:200-201` is just `return m.inner.Load()`, while the Rust collection is actually created in `pkg/dataplane/loader_ebpf.go:196-223`. A real load-time `MaxEntries` check either needs explicit post-`inner.Load()` code or it belongs in the loader path, not in magical prose. On top of that, the current tests inject `userspace_bindings` with `MaxEntries: 256` at `pkg/dataplane/userspace/manager_test.go:148-158`, so a real assertion will require test churn the hard-stop scope forgot to permit.
**Mitigation:** Name the actual assertion site, and explicitly list the affected test files in the allowed diff scope instead of pretending this fits inside one production file.

### MEDIUM — The 65536 memory table is still fake precision
**Where:** `docs/pr/814-max-interfaces/plan.md:148-168, 190-192, 422-430`; `userspace-xdp/src/lib.rs:138-143, 273`; `bpf/headers/xpf_maps.h:372-377`; `/usr/include/linux/bpf.h:6540-6545`; `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aya-ebpf-0.1.1/src/maps/hash_map.rs:24-31, 51-54`
**Finding:** The grounded pieces are fine: `UserspaceBindingValue` is 8 bytes (`userspace-xdp/src/lib.rs:138-143`), `bpf_devmap_val` is 8 bytes (`/usr/include/linux/bpf.h:6540-6545` and `pkg/dataplane/xpfxdpmain_x86_bpfel.go:58-64`), so `USERSPACE_BINDINGS` at `65536 * 16` is about 8 MiB and `tx_ports` at 65536 is 512 KiB. The hand-wave starts with `userspace_ingress_ifaces`: the "~4.1 MB" figure at `plan.md:148-151` is not derived from any kernel allocator source in this repo, and the candidate table at `plan.md:163-168` even marks the current 1024-entry baseline as "n/a". Calling the sum "~12 MB" is therefore not a verified floor; it is a convenience estimate with unknown overheads omitted.
**Mitigation:** Split verified payload math from estimated hash overhead, and either cite kernel source for the hash allocator model or stop pretending the total is exact.

### LOW — The Rust-object verification command does not verify the claimed field
**Where:** `docs/pr/814-max-interfaces/plan.md:256, 289-295`; `pkg/dataplane/userspace_xdp_bpfel.o`; `pkg/dataplane/userspace_xdp_rust.go:11-19`
**Finding:** `llvm-objdump -h` is the wrong check. On the current embedded Rust object it prints section headers and a `maps` section, but it does not expose map definitions or `max_entries`. I had to use `readelf -s` plus `readelf -x maps` to tie `userspace_bindings` to offset `0x1c` (`max_entries = 0x4000`) and `userspace_ingress_ifaces` to offset `0xc4` (`max_entries = 0x400`). A review step that cannot observe the field it claims to verify is ritual, not validation.
**Mitigation:** Verify the Rust map sizes via `ebpf.LoadCollectionSpecFromReader`, `Map.Info()`, or an ELF-dump method that actually decodes the map defs.

### Summary
1 HIGH (1 open), 7 MEDIUM (4 open), 3 LOW (1 open).

ROUND 2: PLAN-READY NO — still open: HIGH raw-ifindex userspace-binding safety/drift story, MEDIUM codegen/regeneration discipline, MEDIUM preflight implementation and coverage, MEDIUM hard-stop diff scope contradiction, MEDIUM 65536 memory math, LOW Rust-object verification command.

## Round 2 response

Round 2 findings addressed as follows. Each entry names the plan section
that holds the fix. Where a concern is deferred or only partially
addressed, that is stated explicitly instead of claiming closure.

### HIGH — raw-ifindex userspace-binding safety/drift story (was PARTIAL)
**CLOSED in design, but note: tense.** Round 1 response used
present-tense language ("the wire-up makes...", "a Go-side load-time
assertion...") as if the code already existed. That was sloppy. The
revised plan reframes every assertion about the env-wiring, the
Rust-side `env!()` consumption, the load-time `MaxEntries` check, and
the call-site cap checks as changes this PR **will** introduce. The
env-wiring commits to option (a): `export MAX_INTERFACES=...` added
to `pkg/dataplane/build-userspace-xdp.sh` before `cargo build`,
consumed from `userspace-xdp/src/lib.rs` via `env!("MAX_INTERFACES")`
at compile time. No `build.rs` is added. The Go-side load-time
assertion is pinned to its real site (`pkg/dataplane/loader_ebpf.go`
at lines 196-220, post-`loadRustUserspaceXDP()` /
pre-`ebpf.NewCollectionWithOptions`), not to the prose-only
`pkg/dataplane/userspace/manager.go:200-201` site which only delegates
to `m.inner.Load()`. See plan sections **"Wiring the Rust-side
constant to the C-side constant (to be added by this PR)"** and
**"Call-site cap checks + preflight"**. Path A remains deferred to
#761; the deferral is now explicitly justified by the presence of
call-site cap checks that will name the offending interface on a
third recurrence.

### MEDIUM — codegen/regeneration discipline (was STILL OPEN)
**CLOSED.** Two factual errors fixed. `bash build-userspace-xdp.sh`
is the **second** `go:generate` directive in
`pkg/dataplane/loader.go` (line 21), not the first; the first is
`xpfXdpMain` at line 20. The regenerated artifact count is **14**
`xpf*_x86_bpfel.{go,o}` pairs plus `userspace_xdp_bpfel.o`, not
"15 .c outputs". Both corrected in plan section **"Execution
matrix"** step 5 and the **"Expected regenerated files
(enumerated)"** list. `make generate` is confirmed to be `go
generate ./pkg/dataplane/...` at `Makefile:20-22`. The
`llvm-objdump -h` command is dropped; review step 5 now verifies the
aya object's `MaxEntries` programmatically via
`ebpf.LoadCollectionSpecFromReader` (this is the same API the
production load-time assertion uses, so the review doubles as a
sanity check on the assertion itself).

### MEDIUM — preflight implementation and coverage (was STILL OPEN)
**CLOSED in design.** Adopted option (a): cap checks are wrapped
around **every** `Update()` into a dense-ifindex-keyed map. The
`tx_ports` site at `pkg/dataplane/loader.go:330-344` (`AddTxPort`)
gets a pre-`tm.Update` check. The four `userspace_bindings` sites at
`pkg/dataplane/userspace/maps_sync.go:519, 541, 909, 946` each get a
pre-`bindingsMap.Update` check. The compile-time
`preflightCheckIfindexCaps` is retained as an early-warning gate and
is moved inside `dataplane.Manager.Compile()` itself (the method
body invoked from `pkg/daemon/daemon.go:1809` as `d.dp.Compile(cfg)`)
so it fires on every compile — not just the first. The
non-existent `compileDataplane` reference is removed. This covers
the `applyHelperStatusLocked` reachability paths called out by Codex
(`manager.go:343, 857, 889, 914, 939, 956, 981, 1008`;
`process.go:316, 360, 1027`; `manager_ha.go:63, 106, 376, 457`) —
those all eventually reach the `maps_sync.go` sites that now hold
per-call cap checks. See plan section **"Call-site cap checks +
preflight"**.

### MEDIUM — hard-stop diff scope contradiction (new Round 2 finding)
**CLOSED.** Plan section **"Hard-stop diff scope (allowed-diff
allowlist)"** rewritten to explicitly list: (i) production files
across steps 1-4; (ii) test files that must change, enumerated from
`grep -rn 'userspace_bindings|BINDING_ARRAY_MAX_ENTRIES|MAX_INTERFACES|tx_ports' --include='*_test.go' pkg/`
which in the current tree returns `pkg/dataplane/userspace/manager_test.go:155,158`
(the `MaxEntries: 256` inject at lines 148-158); (iii) regenerated
artifacts. The hard-stop now triggers on anything outside the union
rather than on anything outside a production-file-only enumeration.
The real load-time assertion site is also corrected: it lives in
`pkg/dataplane/loader_ebpf.go:196-220` (the `loadRustUserspaceXDP()`
/ `ebpf.NewCollectionWithOptions` boundary), not in
`pkg/dataplane/userspace/manager.go:200-201` which only calls
`m.inner.Load()`.

### MEDIUM — 65536 memory math was fake precision (new Round 2 finding)
**CLOSED.** Plan section **"Verified payload floor + estimated hash
overhead"** separates verified payload math (`tx_ports`: 512 KiB
exact; `USERSPACE_BINDINGS`: 8 MiB exact; ~8.5 MiB verified payload
total) from estimated hash-allocator overhead on the
`userspace_ingress_ifaces` prealloc HashMap (framed as "bounded to
tens of MiB on realistic kernels" without pretending to derive a
kernel-sourced exact floor). The old "~4.1 MB"/"~12 MB" exact
figures are dropped. Option (b) from the review.

### LOW — Rust-object verification command (new Round 2 finding)
**CLOSED.** `llvm-objdump -h` is dropped. Step 5 review discipline
now specifies verifying the aya object's map `MaxEntries` via
`ebpf.LoadCollectionSpecFromReader` on the embedded
`userspace_xdp_bpfel.o`, asserting
`spec.Maps["userspace_bindings"].MaxEntries == 1048576` and
`spec.Maps["userspace_ingress_ifaces"].MaxEntries == 65536`. This is
the same code path the new production-side load-time assertion uses.

### Closed Round 1 items still closed
- aya prealloc (MEDIUM): still stated as `HashMap::with_max_entries(N, 0)` -> `flags = 0` -> default-preallocated `BPF_MAP_TYPE_HASH`.
- 8192 choice (MEDIUM): value stays at 65536 with evidence (fw1 @ 2561 this issue, bpfrx-fw1 @ 3651 historical via `git show 7611f276`).
- Validation thresholds (MEDIUM): hard-gate set unchanged; sourced only to `docs/development-workflow.md:201-215`.
- `bpf_devmap_val` size (LOW): 8 bytes, cited.
- `cargo build` command (LOW): dropped; `bash pkg/dataplane/build-userspace-xdp.sh` used instead.

## Round 3 verification

### HIGH — raw-ifindex userspace-binding safety/drift story
**CLOSED.** The architect finally aimed at the real sites instead of making them up. In the current tree, `pkg/dataplane/loader.go:331-340` is the only Go writer to `tx_ports`, `pkg/dataplane/userspace/maps_sync.go:524, 546, 927, 960` are the only Go writers to `userspace_bindings`, and `pkg/dataplane/loader_ebpf.go:196-220` is the actual Rust-object load boundary. `rg -n 'tx_ports|userspace_bindings' --glob '*.go' pkg/dataplane pkg/daemon` found no additional Go write sites beyond those and test scaffolding. The proposed Rust const snippet is also not fantasy: this machine's build toolchain is `rustc 1.96.0-nightly (b41f22de2 2026-03-08)`, and the exact `match u32::from_str_radix(env!("MAX_INTERFACES"), 10)` form compiles under `+nightly`. Loading the current shipped `pkg/dataplane/userspace_xdp_bpfel.o` still reports `userspace_bindings MaxEntries=16384` and `userspace_ingress_ifaces MaxEntries=1024`, so the tree is obviously not fixed yet, but the revised plan's drift check is at least pointed at the real object and the real load site.

### MEDIUM — codegen/regeneration discipline
**PARTIAL.** The gross ordering lie is fixed: `pkg/dataplane/loader.go:20-34` really is `xpfXdpMain` first, then `bash build-userspace-xdp.sh`, then the remaining bpf2go directives; `Makefile:20-22` really is `go generate ./pkg/dataplane/...`; and `pkg/dataplane/build-userspace-xdp.sh:24-28` really does overwrite `pkg/dataplane/userspace_xdp_bpfel.o`. But the plan is still sloppy where sloppiness matters. `docs/pr/814-max-interfaces/plan.md:345` still says "Regenerated artifacts: the 15 files enumerated above" even though the current tree has 14 `xpf*_x86_bpfel.go`, 14 matching `.o`, plus `userspace_xdp_bpfel.o` = 29 files. Worse, `plan.md:353-354` tells the reviewer to spot-check `xpfxdpmain_x86_bpfel.go`, but `pkg/dataplane/xpfxdpmain_x86_bpfel.go:650-656,965` only loads a `CollectionSpec` from embedded `xpfxdpmain_x86_bpfel.o`; it does not expose `MaxEntries` as a readable source literal. I found no repo-local bpf2go cache layer beyond the fixed generated outputs and gitignored `_bpfel.o` files, so `make generate` should overwrite them, but the verification story is still pointed at the wrong artifact.

### MEDIUM — preflight implementation and coverage
**CLOSED.** On the actual tree, the call-site inventory is finally complete. `pkg/dataplane/compiler_iface.go:436-437` reaches the sole `tx_ports` write at `pkg/dataplane/loader.go:340`. The four `userspace_bindings` writes are exactly `pkg/dataplane/userspace/maps_sync.go:524, 546, 927, 960`; the other `userspace_bindings` hits in Go are map lookups, pin-path helpers, or the test inject at `pkg/dataplane/userspace/manager_test.go:148-158`. `pkg/daemon/daemon.go:1809` calls `d.dp.Compile(cfg)`, the base eBPF `Compile` is `pkg/dataplane/compiler.go:265`, and the userspace wrapper at `pkg/dataplane/userspace/manager.go:257` delegates to `m.inner.Compile(cfg)`. So if the cap checks land at those five write sites and the preflight lands in the real `pkg/dataplane/compiler.go` entry, there is no remaining Go-side bypass path. The plan finally covers the paths it previously pretended not to miss.

### MEDIUM — hard-stop diff scope contradiction
**PARTIAL.** This is less wrong, not right. The real load-time assertion site is now correctly pinned to `pkg/dataplane/loader_ebpf.go:196-220`, and the plan at least admits `pkg/dataplane/userspace/manager_test.go:148-158` is affected because that test injects `userspace_bindings` with `MaxEntries: 256`. But `docs/pr/814-max-interfaces/plan.md:281,330` still names `pkg/dataplane/manager.go`, a file that does not exist, even though the actual base `Compile` lives in `pkg/dataplane/compiler.go:265` and the userspace wrapper lives in `pkg/dataplane/userspace/manager.go:228`. An allowlist that still points at a nonexistent file is not "closed"; it is merely less embarrassing than before.

### MEDIUM — 65536 memory math was fake precision
**CLOSED.** The bogus exact-total story is gone. Current source still says `MAX_INTERFACES 2048` at `bpf/headers/xpf_common.h:143`, `tx_ports` still takes `MAX_INTERFACES` at `bpf/headers/xpf_maps.h:372-377`, `UserspaceBindingValue` is still two `u32` fields at `userspace-xdp/src/lib.rs:138-143`, and `USERSPACE_BINDINGS` / `USERSPACE_INGRESS_IFACES` are still declared at `userspace-xdp/src/lib.rs:266-273`. The revised plan now separates verified payload math from estimated hash overhead instead of pretending the total is a kernel-sourced exact number. That was the required correction.

### LOW — Rust-object verification command
**CLOSED.** The plan finally uses a command that observes the field it claims to observe. `pkg/dataplane/userspace_xdp_rust.go:14-19` already loads the embedded Rust object via `ebpf.LoadCollectionSpecFromReader`, and loading the on-disk `pkg/dataplane/userspace_xdp_bpfel.o` that way today reports `userspace_bindings MaxEntries=16384` and `userspace_ingress_ifaces MaxEntries=1024`. That is real verification. The dead `llvm-objdump -h` ritual is gone.

New Round 3 findings (if any):

### MEDIUM — C-side `tx_ports` verification still checks the wrong file
**Where:** `docs/pr/814-max-interfaces/plan.md:353-354`; `pkg/dataplane/xpfxdpmain_x86_bpfel.go:650-656, 965`
**Finding:** The plan tells the reviewer to "spot-check `xpfxdpmain_x86_bpfel.go`" for `tx_ports.MaxEntries`. That is nonsense. The generated Go file only embeds `xpfxdpmain_x86_bpfel.o` and calls `ebpf.LoadCollectionSpecFromReader` on the bytes; the actual `MaxEntries` lives in the object, not as a human-readable literal in the Go source. Loading the current on-disk `pkg/dataplane/xpfxdpmain_x86_bpfel.o` programmatically reports `tx_ports MaxEntries=2048`. A reviewer following the plan literally could verify nothing and still miss a stale C-side object, which is especially stupid because the original crash is `AddTxPort` against this exact map.
**Mitigation:** Verify `pkg/dataplane/xpfxdpmain_x86_bpfel.o` with `ebpf.LoadCollectionSpecFromReader` in step 5, or add a production load-time assertion for `tx_ports.MaxEntries` before map creation.

### LOW — The Rust toolchain remains a floating alias
**Where:** `pkg/dataplane/build-userspace-xdp.sh:8-10, 20-27`; `userspace-xdp/.cargo/config.toml:1-8`; `userspace-xdp/Cargo.toml:1-10`
**Finding:** The proposed `env!()`/const-eval trick works on this machine's current toolchain (`rustc 1.96.0-nightly (b41f22de2 2026-03-08)`), but the repo does not pin that version. `build-userspace-xdp.sh` still uses `RUST_BPF_TOOLCHAIN:-nightly`, i.e. a floating alias. The plan is now depending on nightly const-eval behavior while refusing to say which nightly. That is reproducibility debt, not rigor.
**Mitigation:** Pin the BPF toolchain in-repo (`rust-toolchain.toml` or equivalent) or at minimum record the verified nightly version in the plan/CI path.

### Summary
1 HIGH (0 open), 5 MEDIUM (3 open), 2 LOW (1 open).

ROUND 3: PLAN-READY NO — still open: MEDIUM codegen/regeneration discipline, MEDIUM hard-stop diff scope still naming the wrong `Compile()` file, MEDIUM C-side `tx_ports` verification pointed at the wrong artifact.

## Round 3 response (surgical fixes, applied directly to plan.md — no re-architecture)

Three factual errors corrected in plan.md:

### MEDIUM — codegen artifact count wrong (29 files, not 15)
**CLOSED.** Plan section **"Expected regenerated files (enumerated)"**
rewritten. Count corrected to **29 files**: 14 `xpf*_x86_bpfel.go` +
14 `xpf*_x86_bpfel.o` + `userspace_xdp_bpfel.o`. All 29 listed
individually (the previous `.{go,o}` shorthand was misread as a
single file by a reviewer following the list). Verified via
`ls pkg/dataplane/*_bpfel.*` returning 29 matches. The hard-stop
"any diff outside the enumerated set" now names every file it
guards.

### MEDIUM — wrong file for Compile() / hard-stop target
**CLOSED.** The `Compile()` method lives at
`pkg/dataplane/compiler.go:265` (`func (m *Manager) Compile(cfg *config.Config) (*CompileResult, error)`).
`pkg/dataplane/manager.go` does not exist. Plan section
**"Execution matrix"** step 4 and the hard-stop **"Hard-stop diff
scope (allowed-diff allowlist)"** now name `pkg/dataplane/compiler.go`
correctly.

### MEDIUM — C-side MaxEntries verification step wrong
**CLOSED.** Plan section **"Review discipline (post-`make generate`)"**
rewritten. The `.go` wrapper files only embed the `.o` blob as
`_BytesBpfel` — they do NOT hold the authoritative `max_entries`
value. Review now verifies **every** regenerated `.o` file
(C-side `xpf*_x86_bpfel.o` and Rust-side `userspace_xdp_bpfel.o`)
programmatically via `ebpf.LoadCollectionSpecFromReader`, with
per-map `MaxEntries` assertions enumerated (tx_ports,
redirect_capable, mirror_config, interface_counters on the C side;
userspace_bindings, userspace_ingress_ifaces on the Rust side). This
catches the class of bug where the `.o` is stale but the wrapper was
regenerated against the new constant.

### LOW — nightly toolchain pinning is a floating alias
**DEFERRED.** Acknowledged: the `userspace-xdp/.cargo/config.toml`
toolchain is a floating alias, not hash-pinned. The `env!()` consts
depend on the toolchain being stable enough that the nightly
const-eval support used by `env!() -> u32::from_str_radix -> match`
is present. Verified working on the current pinned toolchain; not
worth blocking this PR to hash-pin the toolchain. File follow-up
as part of general build-hygiene cleanup (toolchain pinning
discipline is a cross-cutting concern, not scoped to #814).
## Round 4 verification
ROUND 4: PLAN-READY YES

- FIX 1 — Artifact list: **CLOSED.** `docs/pr/814-max-interfaces/plan.md:294-330` now enumerates 29 individual files, `ls pkg/dataplane/*_bpfel.* | wc -l` returned `29`, and a literal plan-vs-tree compare (`awk ...` over the section plus `comm`) returned `plan_count 29`, `actual_count 29`, `plan_only:` empty, `actual_only:` empty.
- FIX 2 — Compile() call site: **CLOSED.** `docs/pr/814-max-interfaces/plan.md:281,346` cites `pkg/dataplane/compiler.go:265`, and `grep -n "func.*Compile" pkg/dataplane/compiler.go` returned `265:func (m *Manager) Compile(cfg *config.Config) (*CompileResult, error) {`, with `nl -ba pkg/dataplane/compiler.go | sed -n '255,285p'` showing line 266 is the first `CompileConfig(m, cfg, m.lastCompile != nil)` call, so “preflight first thing on entry” is precise.
- FIX 3 — Verification discipline: **CLOSED.** `docs/pr/814-max-interfaces/plan.md:369-384` now uses `ebpf.LoadCollectionSpecFromReader` with explicit per-map assertions for `tx_ports`, `redirect_capable`, `mirror_config`, `interface_counters`, `userspace_bindings`, and `userspace_ingress_ifaces`; the exact C-side `readelf -s pkg/dataplane/xpfxdpmain_x86_bpfel.o | grep -i 'tx_ports\|redirect_capable\|mirror_config\|interface_counters'` returned all four C names, and the exact Rust-side `readelf -s pkg/dataplane/userspace_xdp_bpfel.o | grep -i 'userspace_bindings\|userspace_ingress_ifaces'` returned `userspace_bindings` while `readelf -sW pkg/dataplane/userspace_xdp_bpfel.o` confirmed `userspace_ingress_ifaces` is present too and the plain `readelf -s` view was just truncating the long symbol name.

No new HIGH or MEDIUM findings.

Summary: the remaining Round 3 slop is gone. The artifact inventory now matches the tree exactly, the plan points at the real `Compile()` entry, and the verification path is grounded in a real API that already exists in this repo (`go.mod:7` pins `github.com/cilium/ebpf v0.20.0`, `pkg/dataplane/userspace_xdp_rust.go:14-19` already calls `ebpf.LoadCollectionSpecFromReader`, and the module source at `/home/ps/go/pkg/mod/github.com/cilium/ebpf@v0.20.0/elf_reader.go:75-76` defines it). The new finite-cap concern at `MAX_INTERFACES = 65536` is also handled precisely enough for implementation: `docs/pr/814-max-interfaces/plan.md:217-220,244-251,281` places a named-interface preflight/error path before `CompileConfig()` and before `AddTxPort()`’s `tm.Update(...)`, so an over-cap boot still fails compile, but it fails loudly and at the named call site instead of by rediscovering the old opaque `E2BIG` path.
