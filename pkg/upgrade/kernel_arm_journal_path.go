package upgrade

import (
	"errors"
	"fmt"
	"path/filepath"
)

// ── the kernel channel's journal path is not an operator choice (#6631) ──
//
// `--journal` is defined on EVERY `xpfd upgrade kernel` verb, `arm` included
// (cmd/xpfd/upgrade_kernel.go). For the kernel channel that flag is
// diagnostic-only, and arming with a non-default value produced a candidate
// that was STRUCTURALLY UNPROMOTABLE — it booted, ran unverified, and the next
// plain reboot reverted it, with no signal anywhere.
//
// WHY IT CANNOT BE FIXED BY TEACHING THE GATE THE PATH. There is no channel to
// tell it one. Three would be needed and none exists:
//
//   - ARGUMENT: xpf-kernel-promote.service is
//     `ExecStart=/usr/local/sbin/xpf-kernel-promote` with no operands, and the
//     script parses no argv of its own — it has no `$1`, no `$@`, no getopts.
//     So even an operator drop-in overriding ExecStart has nothing to pass to.
//   - ENVIRONMENT: neither promote unit mentions a journal in any form. The
//     only Environment= is the pinned PATH.
//   - THE INNER EXEC: the gate runs `"$XPFD" upgrade kernel promote` with no
//     --journal, so the Go half reads DefaultKernelJournalPath regardless of
//     what armed the candidate.
//
// And the flag moves BOTH files, not one: ArmRecordPath derives the sidecar
// from the journal's DIRECTORY, so the gate finds neither file and takes its
// quiet "nothing to promote" branch rather than the loud ARMED-without-record
// refusal. That is precisely the benign-skip laundering #6601 otherwise worked
// to eliminate — a safe failure direction (no promotion) reported as an
// ordinary boot.
//
// So the honest place to fail is the operator's terminal, at the moment they
// ask. Arming is a preflight and is retryable; a candidate kernel that boots
// unverified is not. This is the same shape as recordPromoteBinary, which
// refuses to arm when it cannot establish WHICH xpfd must verify the candidate.

// ErrKernelJournalUnpromotable marks an arm-time refusal: the candidate would
// be recorded in a journal the boot-time promotion gate does not read, so it
// could never be verified and never promoted.
//
// It is deliberately NOT ErrKernelChannelUnavailable. That sentinel means "use
// LANE 2 instead" and cmd/xpfd maps it to exit 2, which an orchestrator reads
// as a legitimate channel-unavailable fallback. This is an operator input
// error on a channel that is perfectly available — exit 1, fix the command.
var ErrKernelJournalUnpromotable = errors.New("kernel journal path is not promotable")

// bootGateJournalPath is the journal path the BOOT-TIME promotion gate reads.
//
// It is the compiled-in default because that is the literal truth: the gate
// hardcodes `/var/lib/xpf/kernel-upgrade.state` (scripts/image/xpf-kernel-promote)
// and TestPromoteScriptJournalMatchesGo pins the shell constant equal to
// DefaultKernelJournalPath, so this is not a second source that could drift.
//
// It is a package VAR, not a const, for one reason: a test that legitimately
// arms against a t.TempDir() journal is modelling a box whose gate reads THAT
// path, and saying so is more honest than a boolean that switches the check
// off. Nothing outside this package can reach it, so production is structurally
// incapable of relaxing the constraint. TestBootGateJournalPathIsTheProductionDefault
// pins its value so a leaked override cannot make the guard vacuous.
var bootGateJournalPath = DefaultKernelJournalPath

// checkArmJournalPromotable refuses an arm whose journal the boot gate will
// never read.
//
// The comparison is lexical (filepath.Clean on both sides) rather than a
// symlink resolution: EvalSymlinks touches the filesystem and fails on a box
// where /var/lib/xpf does not exist yet, which would turn a first arm on a
// fresh install into a refusal. Clean absorbs the spellings that actually
// occur (`//var/lib/...`, a trailing `/.`) and anything more exotic gets a
// message naming the exact path required, so it is actionable rather than a
// brick.
func (r *KernelRunner) checkArmJournalPromotable() error {
	if filepath.Clean(r.cfg.JournalPath) == filepath.Clean(bootGateJournalPath) {
		return nil
	}
	return fmt.Errorf("%w: refusing to arm against journal %s. The boot-time "+
		"promotion gate is a systemd oneshot with a hardcoded ExecStart and no "+
		"way to be told a journal path, so it always reads %s — and the arm-record "+
		"sidecar beside it. A candidate armed here would boot, run UNVERIFIED, "+
		"never be promoted, and revert on the next plain reboot, with the gate "+
		"reporting an ordinary boot. Re-run without --journal (or with --journal %s). "+
		"For the kernel channel --journal is diagnostic-only; it remains usable on "+
		"the read-only verbs and on the non-kernel `xpfd upgrade` verbs",
		ErrKernelJournalUnpromotable, r.cfg.JournalPath,
		bootGateJournalPath, bootGateJournalPath)
}
