# Codex code review — #814 (MAX_INTERFACES bump)

## Round 1

### MEDIUM — Regenerated `.o` MaxEntries unverifiable in sandbox
**Where:** `pkg/dataplane/xpfxdpmain_x86_bpfel.go:650-656`, `pkg/dataplane/userspace_xdp_rust.go:11-16`, `docs/pr/814-max-interfaces/plan.md:369-384`
**Finding:** The 15 regenerated `.o` blobs' `tx_ports` / `redirect_capable` / `mirror_config` / `interface_counters` `MaxEntries` values could not be independently verified via ELF decode in the sandbox (BTF map defs not surfaced by available tools; `/tmp` read-only blocked `LoadCollectionSpecFromReader`). The un-regenerated `.go` wrappers are benign — they `//go:embed` the blobs — but the C-side cap values themselves are unverified.
**Mitigation:** Run the planned `LoadCollectionSpecFromReader` sweep in a writable environment, or add a CI/production assertion that reads each embedded spec and checks `MaxEntries`.

### LOW — Drift error messages omit the header path
**Where:** `pkg/dataplane/loader_ebpf.go:206-219`
**Finding:** Drift error messages omit the header path `bpf/headers/xpf_common.h`, making diagnosis harder when the assertion fires in production.
**Mitigation:** Add the header path to both error strings.

### LOW — constants.go hand-mirrored without enforcement
**Where:** `pkg/dataplane/constants.go:3-32`
**Finding:** Hand-mirrored constants remain manual. The plan called for a `//go:generate` tie or equivalent CI extraction; the implementation has only comments.
**Mitigation:** Generate `constants.go` from `xpf_common.h` or add a CI check that extracts the C `#define` values and compares them to the Go literals.

### LOW — Watchdog overflow branches untested
**Where:** `pkg/dataplane/userspace/maps_sync.go:930-985`, `pkg/dataplane/userspace/maps_sync_cap_test.go`
**Finding:** New tests cover `applyHelperStatusLocked` cap guards but do not cover the watchdog overflow branches (warn-and-skip, not return). The watchdog paths at lines ~909 and ~946 are untested.
**Mitigation:** Add unit tests for `verifyBindingsMapLocked()` that exercise primary and alias over-cap paths.

### Summary
0 HIGH, 1 MEDIUM, 3 LOW. ROUND 1: MERGE NO.

Affirmative positives (not findings, worth recording):
- `env!()` const-eval shape in `userspace-xdp/src/lib.rs:62-71` matches the plan.
- `AddTxPort` cap-before-map-exist reordering is safe in production (load precedes compile in `pkg/daemon/daemon.go`).
- All four `maps_sync.go` guard sites correctly placed.
- No cap checks appear on packet hot paths.

## Round 2 verification

ROUND 2: MERGE YES

- **Fix 1 (header path in drift errors)** — CLOSED. Both `loader_ebpf.go:210` and `loader_ebpf.go:218` now cite `bpf/headers/xpf_common.h`.
- **Fix 2 (`TestMaxInterfacesMatchesCHeader`)** — CLOSED. The regex `(?m)^#define\s+MAX_INTERFACES\s+(\d+)` correctly captures the decimal value and the test fails if C and Go diverge. Correctly won't match `MAX_INTERFACES_EXTENDED`. Won't match parenthesized or `U`-suffix forms (acceptable).
- **Fix 3 (watchdog test)** — PARTIAL. The test reaches the primary over-cap skip branch at `maps_sync.go:934-938`, but `m.lastSnapshot` is never set, so the alias skip branch at `maps_sync.go:980-985` stays uncovered. No new HIGH/MEDIUM — this residual gap is a LOW and does not block merge.
- **Fix 4 (`.o` MaxEntries sweep)** — CLOSED. Independent `LoadCollectionSpecFromReader` verification confirmed all 14 C-side `.o` files at `65536` and `userspace_xdp_bpfel.o` at `userspace_bindings=1048576`, `userspace_ingress_ifaces=65536`.

No new HIGH or MEDIUM findings. One residual LOW (alias branch coverage) is non-blocking.

Final counts: 0 HIGH, 0 MEDIUM, 1 LOW (deferred). MERGE YES.
