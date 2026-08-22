package upgrade

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #6622: a kernel-promote gate refusal left no durable record.
//
// The gate exits 0 on every path (deliberately — a non-zero exit trips
// OnFailure= and reboots the box over what may be a transient packaging
// window), and the unit is Type=oneshot with RemainAfterExit=yes. So
// `systemctl status xpf-kernel-promote` reads SUCCESS and stays active even
// when the gate REFUSED and the armed candidate is running unverified. The only
// signal was a journald line, time-limited by rotation.
//
// #6601 is what made it worth closing: it converted "maybe run a stale binary"
// into "refuse", which is right, but it made refusal a REACHABLE outcome rather
// than a hypothetical one.
//
// FAIL-ON-REVERT: delete the record_refusal call from the gate's refuse() and
// the python harness's refusal-record tests fail; delete the ReadRefusalRecord
// call from ReadChannelStatus and TestChannelStatusSurfacesTheRefusal_6622
// fails as an assertion.

var refusalRecordPathRE = regexp.MustCompile(`(?m)^REFUSAL_RECORD="([^"]+)"`)

// TestPromoteScriptRefusalRecordPathMatchesGo is the CROSS-LANGUAGE canary,
// the sibling of TestPromoteScriptArmRecordPathMatchesGo.
//
// The gate is POSIX sh and hardcodes the path; Go derives it from the journal
// path. If they drift, the gate writes a record nothing reads and
// `show system kernel-upgrade` reports no refusal on a box that refused —
// which is the exact failure this issue is about, reintroduced through the
// back door.
func TestPromoteScriptRefusalRecordPathMatchesGo_6622(t *testing.T) {
	data, err := os.ReadFile(promoteScriptPath(t))
	if err != nil {
		t.Fatalf("read promote script: %v", err)
	}
	m := refusalRecordPathRE.FindSubmatch(data)
	if m == nil {
		t.Fatal(`no REFUSAL_RECORD="..." assignment in the promote script; the ` +
			"refusal record's location is no longer assertable from Go (#6622)")
	}
	got, want := string(m[1]), RefusalRecordPath(DefaultKernelJournalPath)
	if got != want {
		t.Fatalf("the gate writes its refusal record to %q but Go reads it from "+
			"%q. A refusal would leave a trace nothing surfaces.", got, want)
	}
}

// writeRefusal writes a record beside journal, the way the gate does.
func writeRefusal(t *testing.T, journal, body string) string {
	t.Helper()
	p := RefusalRecordPath(journal)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write refusal record: %v", err)
	}
	return p
}

// TestReadRefusalRecordAbsentIsNotAnError: no record is the ordinary state.
// Reporting it as an error would make every healthy box's status carry a
// WARNING line, which trains an operator to ignore the line that matters.
func TestReadRefusalRecordAbsentIsNotAnError_6622(t *testing.T) {
	rec, err := ReadRefusalRecord(filepath.Join(t.TempDir(), "kernel-upgrade.state"))
	if err != nil {
		t.Fatalf("absent record reported an error: %v", err)
	}
	if rec.Recorded {
		t.Fatal("absent record reported Recorded=true")
	}
}

// TestReadRefusalRecordCarriesTheResolutionFacts is the issue's central
// acceptance criterion: "the record carries the resolution facts, not just
// 'refused'".
//
// The ExecStart value deliberately contains BOTH a '=' and a ';' — that is what
// systemd's rendering looks like, and a parser that split on every '=' or
// stopped at the first would mangle exactly the field an operator needs to see
// to diagnose a stale unit.
func TestReadRefusalRecordCarriesTheResolutionFacts_6622(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "kernel-upgrade.state")
	execStart := "{ path=/opt/relocated live/xpfd ; argv[]=/opt/relocated live/xpfd ; ignore_errors=no }"
	writeRefusal(t, journal, strings.Join([]string{
		"version=1",
		"disposition=refused",
		"refused_at=2026-08-21T04:05:06Z",
		"boot_id=1f2e3d4c-0000-1111-2222-333344445555",
		"journal_state=armed",
		"unit=xpfd.service",
		"load_state=loaded",
		"main_pid=0",
		"control_group=/system.slice/xpfd.service",
		"exec_start=" + execStart,
		"reason=the arming recorded /a/xpfd but the unit resolves /b/xpfd",
		"cause=xpfd.service IS known to systemd",
		"advice=Fix xpfd.service so its ExecStart names the live xpfd",
		"unknown_future_key=ignored",
	}, "\n")+"\n")

	rec, err := ReadRefusalRecord(journal)
	if err != nil {
		t.Fatalf("ReadRefusalRecord: %v", err)
	}
	if !rec.Recorded {
		t.Fatal("a present record read as Recorded=false")
	}
	for _, tc := range []struct{ field, got, want string }{
		{"Disposition", rec.Disposition, "refused"},
		{"JournalState", rec.JournalState, "armed"},
		{"Unit", rec.Unit, "xpfd.service"},
		{"LoadState", rec.LoadState, "loaded"},
		{"MainPID", rec.MainPID, "0"},
		{"ControlGroup", rec.ControlGroup, "/system.slice/xpfd.service"},
		{"ExecStart", rec.ExecStart, execStart},
		{"BootID", rec.BootID, "1f2e3d4c-0000-1111-2222-333344445555"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.field, tc.got, tc.want)
		}
	}
	if rec.At.IsZero() {
		t.Errorf("refused_at %q did not parse; the record's timestamp is the "+
			"thing that survives journal rotation", rec.AtRaw)
	}
	if rec.At.UTC().Format(refusalTimeLayout) != "2026-08-21T04:05:06Z" {
		t.Errorf("At = %v, want 2026-08-21T04:05:06Z", rec.At)
	}
	if !strings.Contains(rec.Reason, "/b/xpfd") || rec.Cause == "" || rec.Advice == "" {
		t.Errorf("reason/cause/advice not all populated: %+v", rec)
	}
}

// TestReadRefusalRecordUnparseableTimeStillReports: an early-boot clock can be
// wrong or unset, and a record whose timestamp cannot be parsed must still be
// REPORTED. Dropping it would hide a refusal because of a clock — and the bad
// clock is itself worth seeing.
func TestReadRefusalRecordUnparseableTimeStillReports_6622(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "kernel-upgrade.state")
	writeRefusal(t, journal, "disposition=refused\nrefused_at=not-a-time\nreason=x\n")

	rec, err := ReadRefusalRecord(journal)
	if err != nil {
		t.Fatalf("ReadRefusalRecord: %v", err)
	}
	if !rec.Recorded {
		t.Fatal("an unparseable timestamp suppressed the whole record")
	}
	if rec.AtRaw != "not-a-time" {
		t.Errorf("AtRaw = %q, want the original text preserved", rec.AtRaw)
	}
	if !rec.At.IsZero() {
		t.Errorf("At = %v, want zero for an unparseable value", rec.At)
	}
}

// TestReadRefusalRecordFieldlessFileIsAnError: "absent" is acted on as a
// positive statement ("the gate did not decline"), so it must not be reachable
// by mis-parsing a file that is PRESENT. Same rule ReadArmRecord applies.
//
// Two shapes, because they fail differently. The first has no separator at all.
// The second is the one that actually caught a defect while this was written:
// a file whose only '=' lines carry keys the reader does not know. Counting
// '='-bearing lines rather than RECOGNISED ones let that parse as a refusal
// with every field empty, rendering a REFUSED banner made entirely of dashes —
// worse than the error it displaced. (The first draft of this test could not
// see it: its own fixture text contained the literal "key=value".)
func TestReadRefusalRecordFieldlessFileIsAnError_6622(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"no separator at all", "this file has no recognisable fields\n"},
		{"only unknown keys", "colour=blue\nshape=round\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			journal := filepath.Join(t.TempDir(), "kernel-upgrade.state")
			writeRefusal(t, journal, tc.body)

			rec, err := ReadRefusalRecord(journal)
			if err == nil {
				t.Fatalf("a present-but-unparseable record read as %+v with no "+
					"error; a refusal would silently report as 'no refusal' (#6622)", rec)
			}
			if rec.Recorded {
				t.Error("Recorded=true alongside an error")
			}
		})
	}
}

// TestReadRefusalRecordToleratesUnknownKeysAlongsideKnownOnes is the
// companion over-reach guard: the tightening above must reject a file with ONLY
// unknown keys without rejecting a NEWER gate that adds fields to a record
// still carrying the ones this reader knows.
func TestReadRefusalRecordToleratesUnknownKeysAlongsideKnownOnes_6622(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "kernel-upgrade.state")
	writeRefusal(t, journal,
		"disposition=refused\nsome_field_from_a_newer_gate=x\nreason=y\n")

	rec, err := ReadRefusalRecord(journal)
	if err != nil {
		t.Fatalf("a record carrying an unknown field alongside known ones was "+
			"rejected: %v — an older reader must not refuse a newer gate's "+
			"record", err)
	}
	if !rec.Recorded || rec.Reason != "y" {
		t.Fatalf("known fields lost: %+v", rec)
	}
}

// TestChannelStatusSurfacesTheRefusal is the WIRING assertion, and it is the
// one that matters: the reader existing is worth nothing if the status surface
// never calls it.
//
// `show system kernel-upgrade`, the console CLI and the remote `cli` all render
// through RenderChannelStatus, and pkg/daemon's status RPC reads through
// ReadChannelStatus, so asserting here covers all of them without this package
// reaching into pkg/cli or pkg/grpcapi.
func TestChannelStatusSurfacesTheRefusal_6622(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "kernel-upgrade.state")
	writeRefusal(t, journal, strings.Join([]string{
		"disposition=refused",
		"refused_at=2026-08-21T04:05:06Z",
		"journal_state=armed",
		"unit=xpfd.service",
		"load_state=not-found",
		"main_pid=0",
		"exec_start=",
		"reason=the arm record is ABSENT but a candidate is ARMED",
		"advice=Re-arm from the live xpfd",
	}, "\n")+"\n")

	st := ReadChannelStatus(journal, nil)
	if st.ReadErr != nil {
		t.Fatalf("ReadChannelStatus: %v", st.ReadErr)
	}
	if !st.Refusal.Recorded {
		t.Fatal("ReadChannelStatus did not pick up the refusal record — the " +
			"operator surface still reports nothing after a gate refusal (#6622)")
	}

	var b strings.Builder
	RenderChannelStatus(&b, st)
	out := b.String()
	for _, want := range []string{
		"REFUSED",
		"2026-08-21T04:05:06Z",
		"the arm record is ABSENT but a candidate is ARMED",
		"not-found",
		"Re-arm from the live xpfd",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered status omits %q — an operator reading it still "+
				"cannot tell the gate declined or why.\n%s", want, out)
		}
	}
	// A field systemd could not answer must render as "-" rather than as a
	// blank an operator reads as "nothing wrong here".
	if !strings.Contains(out, "ExecStart:   -") {
		t.Errorf("an empty ExecStart did not render as '-':\n%s", out)
	}
}

// TestChannelStatusDistinguishesIndeterminateFromRefused: they are different
// events. A refusal names a condition the operator can fix; an indeterminate
// says the gate could not even establish whether anything was armed. Folding
// them would tell an operator to fix a unit when the problem is an unreadable
// journal.
func TestChannelStatusDistinguishesIndeterminateFromRefused_6622(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "kernel-upgrade.state")
	writeRefusal(t, journal, "disposition=indeterminate\nreason=journal unreadable\n")

	var b strings.Builder
	RenderChannelStatus(&b, ReadChannelStatus(journal, nil))
	out := b.String()
	if strings.Contains(out, "REFUSED") {
		t.Errorf("an indeterminate record rendered as a REFUSAL:\n%s", out)
	}
	if !strings.Contains(out, "did NOT run") {
		t.Errorf("an indeterminate record did not say the gate did not run:\n%s", out)
	}
}

// TestNoRefusalRendersNothing is the ANTI-NOISE control. The record is only
// useful if a healthy box is silent about it — a status that always printed a
// refusal section would teach an operator to skip it.
func TestNoRefusalRendersNothing_6622(t *testing.T) {
	var b strings.Builder
	RenderChannelStatus(&b, ReadChannelStatus(filepath.Join(t.TempDir(), "k.state"), nil))
	out := b.String()
	for _, unwanted := range []string{"REFUSED", "Promotion gate:"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("a box with no refusal record printed %q:\n%s", unwanted, out)
		}
	}
}

// TestRefusalRecordSharesTheArmRecordsLifetime: a refusal describes a specific
// armed candidate. One that outlived its journal would accuse the next boot of
// a decline that happened to a candidate no longer in flight — the same reason
// the arm record is cleared with the journal.
func TestRefusalRecordSharesTheArmRecordsLifetime_6622(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	journal := r.cfg.JournalPath
	if err := os.MkdirAll(filepath.Dir(journal), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := writeRefusal(t, journal, "disposition=refused\nreason=x\n")

	if err := r.clearKernelJournal(); err != nil {
		t.Fatalf("clearKernelJournal: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the refusal record survived the journal clear (stat err %v). "+
			"It would be reported against whatever is armed next.", err)
	}
}

// TestArmingClearsAPriorRefusal: a refusal from a PRIOR candidate must not read
// as a verdict on the one just armed.
//
// Cleared where the new arm record is WRITTEN rather than at the top of Arm, so
// an arm that fails preflight leaves the previous refusal intact — which is
// exactly what an operator diagnosing that failure needs on screen.
func TestArmingClearsAPriorRefusal_6622(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	journal := r.cfg.JournalPath
	if err := os.MkdirAll(filepath.Dir(journal), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := writeRefusal(t, journal, "disposition=refused\nreason=a prior candidate\n")

	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a prior refusal survived a successful arm (stat err %v); it "+
			"would be rendered against the candidate just armed", err)
	}
}
