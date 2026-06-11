# Claude SMR hostile code review — PR #1869 r1

Scope: 9 commits over origin/master (engineer/1864-toolchain-pin @
03d67d228). I attacked the implementation against the converged plan
r4 contracts, with emphasis on bash correctness, the verify-only
invariant, and the regenerated artifact's provenance.

## Findings

### F1 (Critical, FIXED in 03d67d228) — pgrep -x can never match xpf-userspace-dp

The deploy pre-flight's worker-core derivation used
`pgrep -x xpf-userspace-dp`; the name is 16 chars, past the 15-char
kernel comm truncation `pgrep -x` matches against — derivation would
ALWAYS fail to the nice-only fallback, silently nullifying the AGY r2
F7 / Codex r2 F3 mitigation. Found by running the snippet; bash even
warns. Fixed with `pidof -s` (cmdline-based long-name matching) plus
removal of a dead `|| return 1` on a `pgrep|head` pipeline (pipeline
status is head's, always 0).

### F2 (Verified, holds) — strict TOML parse edge cases

`wc -l <<<""` counts 1, so the exactly-one check alone would accept an
empty parse; the conjoined `-n` test rejects it
(build-userspace-xdp.sh: `[[ "$(wc -l ...)" -eq 1 && -n ... ]]`).
Duplicate channel keys → 2 lines → fail. channel key outside
`[toolchain]` → in_tc false → not counted. Verified by execution
during the gate runs.

### F3 (Verified, holds) — verify-only invariant

`verifyUserspaceShimSpecWithShrink` does `validateUserspaceShimSpec` →
`spec.Copy()` → optional shrink → bare `ebpf.NewCollection(vspec)` →
`coll.Close()`. No PinByName/PinPath/MapReplacements anywhere in the
call graph (grep: the only setters remain in
loadUserspaceShimObjectsOnce / loadOrCreatePinnedShimMapWith, not
reachable from the verify path). cmd/xpfd's verify-dataplane calls
only VerifyEmbeddedUserspaceShim.

### F4 (Verified, holds) — set -e / exit-code plumbing

`set +e; run_verifier; VERIFY_RC=$?; set -e` captures 0/3/99/other;
sudo passes the child's exit code through; the case arms cover all
four classes and every non-0 leaves the tracked .o untouched (install
is after the case AND after the unpinned-override check). shimverify
exit contract (0/2/3/1) matches the deploy/docs contract; usage exit 2
unreachable from the script (always exactly one arg).

### F5 (Verified, holds) — lib.rs rewrites

Read the committed hunks: heartbeat guard clause unchanged,
`wrapping_sub` exact on the evaluated path; packet_len explicit
compare case-equal with saturating_sub for >, ==, < — matches the plan
§4B derivation. Object regenerated through the gate; PASS recorded; my
independent rebuild reproduced md5 057ecde6 (clean
`git diff --exit-code`).

### F6 (Accepted residual) — testdata REJECT object is toolchain-frozen

The shrink-equivalence test's REJECT arm depends on the preserved
object rejecting on FUTURE kernels too. If a future verifier raises
the cap or prunes better, the test fails loudly and the artifact needs
refreshing — that is a feature (it signals the threat model changed),
documented in the test comment.

### F7 (Note) — verify-dataplane runs before flag parsing

Positional subcommand handled before flag.Parse and before the
unknown-command rejection, consistent with version/cleanup. No daemon
code path can be entered by the pre-flight.

## Verdict

**MERGE-READY** at 03d67d228 (F1 fixed in-branch; all other contracts
verified against the code). Pending: Codex + AGY + Copilot rounds and
the parent's guarded deploy smoke.
