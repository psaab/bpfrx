package upgrade

import (
	"errors"
	"go/ast"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #6631: `xpfd upgrade kernel arm --journal <non-default>` produced a
// STRUCTURALLY UNPROMOTABLE candidate.
//
// The Go side honoured the flag — the journal went to <path> and
// ArmRecordPath derived the sidecar from its DIRECTORY, so both files landed
// there. The boot gate hardcodes both locations, found neither, took its
// benign "nothing to promote" branch, and exited quiet. The candidate booted,
// ran UNVERIFIED, was never promoted, and reverted on the next plain reboot,
// with the gate's log reading like an ordinary boot.
//
// UNREACHABLE, NOT MERELY AWKWARD. There is no channel by which the path could
// reach the gate, and all three that would be needed are absent:
// xpf-kernel-promote.service is `ExecStart=/usr/local/sbin/xpf-kernel-promote`
// with no operands and the script parses no argv of its own; neither promote
// unit mentions a journal in any form; and the gate's inner exec is
// `"$XPFD" upgrade kernel promote` with no --journal, so the Go half reads the
// compiled-in default regardless. Even an operator drop-in overriding ExecStart
// has nothing to pass to.
//
// So the refusal belongs at ARM time, in the operator's terminal, at the moment
// they ask. Arming is a preflight and is retryable; a candidate kernel booting
// unverified is not.
//
// FAIL-ON-REVERT: delete the checkArmJournalPromotable call from Arm and
// TestKernelArmRefusesANonDefaultJournalPath_6631 fails as an assertion.

// newKernelRunnerAtJournal builds a runner at an explicit journal path WITHOUT
// telling the guard that the boot gate reads it.
//
// This is the inverse of newKernelRunner, which models a healthy box by moving
// the gate's path to match. Here the mismatch IS the fixture, so it must not be
// papered over.
func newKernelRunnerAtJournal(t *testing.T, f *fakeKernelSystem, journal string) *KernelRunner {
	t.Helper()
	r, err := NewKernelRunner(KernelConfig{
		JournalPath: journal,
		Sys:         f,
		Logf:        func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewKernelRunner: %v", err)
	}
	return r
}

// TestBootGateJournalPathIsTheProductionDefault is the ANTI-VACUITY guard for
// every other test in the package.
//
// newKernelRunner overrides bootGateJournalPath to the test's own temp journal,
// which is what lets ~30 arm tests keep working. That override is only safe
// because production cannot perform it: the var is unexported, so cmd/xpfd and
// pkg/daemon are structurally incapable of relaxing the constraint, and the
// compiled-in value is the one the boot gate actually reads.
//
// If this ever fails, either a test leaked an override past its t.Cleanup or
// the default drifted — and in the second case every arm on a real appliance
// would refuse.
func TestBootGateJournalPathIsTheProductionDefault_6631(t *testing.T) {
	if bootGateJournalPath != DefaultKernelJournalPath {
		t.Fatalf("bootGateJournalPath = %q, want the compiled-in default %q. "+
			"Either an override leaked past a t.Cleanup (making the #6631 guard "+
			"vacuous for the tests that follow) or the default drifted from the "+
			"path scripts/image/xpf-kernel-promote hardcodes.",
			bootGateJournalPath, DefaultKernelJournalPath)
	}
	// The shell gate's own constant is pinned equal to this by
	// TestPromoteScriptJournalMatchesGo, so the guard compares against the path
	// the gate really reads rather than a second source that could drift.
	if DefaultKernelJournalPath != "/var/lib/xpf/kernel-upgrade.state" {
		t.Fatalf("DefaultKernelJournalPath = %q; the boot gate hardcodes "+
			"/var/lib/xpf/kernel-upgrade.state", DefaultKernelJournalPath)
	}
}

// TestKernelArmRefusesANonDefaultJournalPath is the core #6631 assertion.
//
// Three things are checked, and they fail for different reasons, so none is
// redundant: that the arm REFUSED, that it refused for THIS reason rather than
// tripping some later guard by accident, and that it refused before touching
// anything.
func TestKernelArmRefusesANonDefaultJournalPath_6631(t *testing.T) {
	f := newFakeKernelSystem()
	journal := filepath.Join(t.TempDir(), "elsewhere", "kernel-upgrade.state")
	r := newKernelRunnerAtJournal(t, f, journal)

	err := r.Arm("6.18.5-12-generic")
	if err == nil {
		t.Fatalf("Arm against %s succeeded. That candidate is structurally "+
			"unpromotable: the boot gate reads only %s, so it would boot, run "+
			"UNVERIFIED, and revert on the next plain reboot (#6631)",
			journal, bootGateJournalPath)
	}

	// WHICH check fired. Without this the test passes just as happily if the
	// arm died in preflight for an unrelated reason — a negative test that
	// passes for the wrong reason is indistinguishable from one that works.
	if !errors.Is(err, ErrKernelJournalUnpromotable) {
		t.Fatalf("Arm failed with %v, which is not an ErrKernelJournalUnpromotable "+
			"refusal — some other guard rejected this, and the #6631 constraint "+
			"is not the thing being asserted", err)
	}
	// The message must name the constraint, not just the outcome: an operator
	// who is told "refused" without being told the gate reads a fixed path
	// cannot act.
	if !strings.Contains(err.Error(), bootGateJournalPath) {
		t.Errorf("refusal %q does not name %q, the path the boot gate reads — "+
			"the operator has nothing to act on", err, bootGateJournalPath)
	}

	// Refused BEFORE any mutation. Arming installs a kernel, writes BootNext
	// and reboots; a refusal that arrived after some of that would leave the
	// box in a state nothing cleans up.
	if len(f.calls) != 0 {
		t.Errorf("the refusal came AFTER %d system call(s) %v — it must precede "+
			"every mutation (#6631)", len(f.calls), f.calls)
	}
	if f.rebooted {
		t.Error("Arm rebooted despite refusing")
	}
	if _, statErr := os.Stat(journal); !os.IsNotExist(statErr) {
		t.Errorf("a journal was written at %s despite the refusal (stat err %v)",
			journal, statErr)
	}
	if rec := ArmRecordPath(journal); func() bool { _, e := os.Stat(rec); return e == nil }() {
		t.Errorf("an arm-record sidecar was written at %s despite the refusal", rec)
	}
}

// TestKernelArmJournalRefusalIsNotChannelUnavailable pins the SENTINEL choice,
// which is an exit-code contract rather than a cosmetic one.
//
// cmd/xpfd maps ErrKernelChannelUnavailable to exit 2, which the xpf-deploy
// kernel-roll orchestrator reads as "this box cannot use LANE 1, fall back to
// LANE 2" — an outcome it proceeds past. A mistyped flag must not look like
// that. It is exit 1: fix the command and re-run.
func TestKernelArmJournalRefusalIsNotChannelUnavailable_6631(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunnerAtJournal(t, f, filepath.Join(t.TempDir(), "k.state"))

	err := r.Arm("6.18.5-12-generic")
	if err == nil {
		t.Fatal("Arm succeeded against a non-default journal (#6631)")
	}
	if errors.Is(err, ErrKernelChannelUnavailable) {
		t.Fatalf("the #6631 refusal reports ErrKernelChannelUnavailable (%v), so "+
			"cmd/xpfd exits 2 and an orchestrator reads an operator input error as "+
			"a legitimate channel-unavailable fallback", err)
	}
}

// TestKernelArmAtTheBootGateJournalStillSucceeds is the ANTI-OVER-REACH
// control. A guard that refused every arm would be a total outage of the
// kernel channel and would satisfy every negative test above, so the positive
// case has to be asserted explicitly.
func TestKernelArmAtTheBootGateJournalStillSucceeds_6631(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f) // models a box whose gate reads the test journal

	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm at the gate's own journal path refused: %v — the #6631 "+
			"guard has over-reached and no kernel can be armed at all", err)
	}
	if !f.rebooted {
		t.Fatal("Arm did not reach the reboot; the guard interrupted the happy path")
	}
	if bootGateJournalPath != r.cfg.JournalPath {
		t.Fatalf("fixture is not modelling the intended box: gate reads %q, "+
			"runner journals to %q", bootGateJournalPath, r.cfg.JournalPath)
	}
}

// TestKernelArmToleratesAnEquivalentSpelling: the comparison is lexical, so it
// must at least absorb the spellings that occur in practice rather than
// refusing a path that IS the gate's path written differently.
//
// This is where an over-strict guard would bite a real operator: `--journal`
// typed with a doubled slash or a trailing `/.` names the same file, and
// refusing it would be a refusal with no defect behind it.
func TestKernelArmToleratesAnEquivalentSpelling_6631(t *testing.T) {
	f := newFakeKernelSystem()
	journal := filepath.Join(t.TempDir(), "kernel-upgrade.state")
	withBootGateJournal(t, journal)

	dir, base := filepath.Split(journal)
	spelled := dir + "." + string(filepath.Separator) + base // <dir>/./<base>
	if filepath.Clean(spelled) != journal {
		t.Fatalf("fixture error: %q does not clean to %q", spelled, journal)
	}

	r := newKernelRunnerAtJournal(t, f, spelled)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm refused %q, which is the gate's own path written "+
			"differently: %v", spelled, err)
	}
}

// TestArmJournalGuardIsScopedToTheKernelArmPath pins the SCOPE the issue asks
// for: `--journal` stays legitimate for the read-only kernel verbs and for the
// non-kernel `xpfd upgrade` verbs, so the guard must have exactly one caller.
//
// A behavioural test cannot state this — "no other code path is affected" is a
// claim about absence, and the binary channel's own journal tests passing only
// shows that the paths they happen to cover are unaffected. Counting the
// callers in the source says it directly.
func TestArmJournalGuardIsScopedToTheKernelArmPath_6631(t *testing.T) {
	_, files := parseUpgradeTree(t, upgradeTreeRoot(t))

	type site struct{ file, fn string }
	var sites []site
	for path, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "checkArmJournalPromotable" {
					sites = append(sites, site{path, fd.Name.Name})
				}
				return true
			})
		}
	}

	if len(sites) != 1 {
		t.Fatalf("checkArmJournalPromotable has %d callers %v, want exactly 1. "+
			"The kernel channel's journal constraint must not spread to the "+
			"read-only verbs or to the non-kernel `xpfd upgrade` journal, where "+
			"--journal is legitimate (#6631).", len(sites), sites)
	}
	if sites[0].fn != "Arm" {
		t.Fatalf("checkArmJournalPromotable is called from %s, want Arm — the "+
			"refusal is scoped to arming, not to the flag (#6631)", sites[0].fn)
	}

	// The two channels journal to different files; conflating them is how a
	// kernel-scoped constraint would leak onto the binary channel.
	if DefaultJournalPath == DefaultKernelJournalPath {
		t.Fatalf("the binary channel and kernel channel share journal path %q",
			DefaultJournalPath)
	}
}
