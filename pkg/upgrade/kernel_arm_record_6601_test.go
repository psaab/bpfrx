package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #6601 r6 MAJOR. Every prior design inferred "which xpfd is live" from ambient
// state, and each signal in turn proved stale-able. The last one broke
// concretely: a DISABLED unit still reports LoadState=loaded with MainPID=0, so
// a leftover default unit whose drop-in named an OLD version passed the
// arm-time check and its stale ExecStart was accepted at boot.
//
// The arming is the authority: it IS an xpfd, so it knows the live binary by
// construction. These tests pin that the record is written, is the thing the
// gate reads, and that nothing falls back to inference.

func withArmingBinaryResolver(t *testing.T, fn func() (string, error)) {
	t.Helper()
	orig := resolveArmingBinary
	t.Cleanup(func() { resolveArmingBinary = orig })
	resolveArmingBinary = fn
}

func newRecordRunner(t *testing.T) (*KernelRunner, string) {
	t.Helper()
	dir := t.TempDir()
	journal := filepath.Join(dir, "kernel-upgrade.state")
	return &KernelRunner{cfg: KernelConfig{JournalPath: journal}}, journal
}

// TestRecordPromoteBinaryWritesBothRecords: the journal field and the sidecar
// must come from the SAME resolved value. They exist separately only because
// the boot gate is POSIX sh and cannot parse JSON.
func TestRecordPromoteBinaryWritesBothRecords(t *testing.T) {
	r, journal := newRecordRunner(t)
	live := fakeXpfd(t, filepath.Join(t.TempDir(), "versions", "vB"), 0)
	withArmingBinaryResolver(t, func() (string, error) { return live, nil })

	j := &KernelJournal{}
	if err := r.recordPromoteBinary(j); err != nil {
		t.Fatalf("recordPromoteBinary: %v", err)
	}
	if j.PromoteBinary != live {
		t.Fatalf("journal PromoteBinary = %q, want %q", j.PromoteBinary, live)
	}
	got, err := ReadArmRecord(journal)
	if err != nil {
		t.Fatalf("ReadArmRecord: %v", err)
	}
	if got != live {
		t.Fatalf("sidecar = %q, want %q — the two records must not diverge", got, live)
	}
}

// TestRecordPromoteBinaryFailsClosed is MINOR-1: a preflight that cannot
// establish readiness must REFUSE. The previous arm-time check permitted a
// probe error or an empty answer, so an unverifiable layout stayed armable
// exactly when the system could not be interrogated. Arming is retryable; an
// unverified candidate kernel is not.
func TestRecordPromoteBinaryFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		bin  string
		err  error
	}{
		{"resolver error", "", errors.New("no /proc")},
		{"empty path", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, journal := newRecordRunner(t)
			withArmingBinaryResolver(t, func() (string, error) {
				if tc.err != nil {
					return "", tc.err
				}
				return tc.bin, validateGateBin(tc.bin)
			})
			j := &KernelJournal{}
			err := r.recordPromoteBinary(j)
			if err == nil {
				t.Fatalf("recordPromoteBinary succeeded with an unresolvable arming " +
					"binary; the arm must fail CLOSED (#6601 r6 MINOR-1)")
			}
			if !errors.Is(err, ErrKernelPromoteBinaryUnresolvable) {
				t.Fatalf("error does not wrap the sentinel: %v", err)
			}
			if _, serr := os.Stat(ArmRecordPath(journal)); serr == nil {
				t.Fatal("a sidecar was written despite the refusal")
			}
		})
	}
}

// TestReadArmRecordAbsentMeansNothingArmed: absence is a definitive statement,
// not a diagnosis problem. The record is written by arming and removed with the
// journal, so no record == no candidate == the one state in which not running
// the gate is harmless.
func TestReadArmRecordAbsentMeansNothingArmed(t *testing.T) {
	got, err := ReadArmRecord(filepath.Join(t.TempDir(), "kernel-upgrade.state"))
	if err != nil {
		t.Fatalf("absent record must not be an error: %v", err)
	}
	if got != "" {
		t.Fatalf("absent record returned %q", got)
	}
}

// TestReadArmRecordMalformedIsAnErrorNotAbsence: "absent" is acted on as
// "nothing armed", so it must not be reachable by mis-parsing a file that IS
// present — that would silently skip the gate for an armed candidate.
func TestReadArmRecordMalformedIsAnErrorNotAbsence(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty", ""},
		{"whitespace", "   \n"},
		{"relative", "./xpfd\n"},
		{"bare name", "xpfd\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			journal := filepath.Join(dir, "kernel-upgrade.state")
			if err := os.WriteFile(ArmRecordPath(journal), []byte(tc.body), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, err := ReadArmRecord(journal)
			if err == nil {
				t.Fatalf("malformed record %q parsed as %q; a present-but-unusable "+
					"record must ERROR, never read as 'nothing armed'", tc.body, got)
			}
		})
	}
}

// TestClearKernelJournalClearsTheArmRecord: if the sidecar outlived the
// journal, every subsequent ordinary boot would find a record pointing at a
// candidate that no longer exists and refuse.
func TestClearKernelJournalClearsTheArmRecord(t *testing.T) {
	r, journal := newRecordRunner(t)
	live := fakeXpfd(t, t.TempDir(), 0)
	withArmingBinaryResolver(t, func() (string, error) { return live, nil })
	if err := r.recordPromoteBinary(&KernelJournal{}); err != nil {
		t.Fatalf("recordPromoteBinary: %v", err)
	}
	if err := os.WriteFile(journal, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	if err := r.clearKernelJournal(); err != nil {
		t.Fatalf("clearKernelJournal: %v", err)
	}
	if _, err := os.Stat(ArmRecordPath(journal)); !os.IsNotExist(err) {
		t.Fatalf("arm record survived the journal clear (err=%v); every later "+
			"ordinary boot would refuse", err)
	}
}

// TestVerifyPromoteBinaryMatchesRecord is the Go half of the cross-check.
func TestVerifyPromoteBinaryMatchesRecord(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}

	t.Run("match", func(t *testing.T) {
		if err := VerifyPromoteBinaryMatchesRecord(self); err != nil {
			t.Fatalf("same binary reported a mismatch: %v", err)
		}
	})
	t.Run("mismatch reverts", func(t *testing.T) {
		if err := VerifyPromoteBinaryMatchesRecord("/nonexistent/other/xpfd"); err == nil {
			t.Fatal("an undesignated binary was allowed to authorize the promotion")
		}
	})
	// An older build's journal has no recorded value. Refusing would strand an
	// in-flight candidate across an upgrade, and the outer hop already refuses
	// when it has no usable record to select from.
	t.Run("empty record tolerated", func(t *testing.T) {
		if err := VerifyPromoteBinaryMatchesRecord(""); err != nil {
			t.Fatalf("empty (pre-r6) record treated as a mismatch: %v", err)
		}
	})
}

var armRecordPathRE = regexp.MustCompile(`(?m)^ARM_RECORD="([^"]+)"`)

// TestPromoteScriptArmRecordPathMatchesGo is the CROSS-LANGUAGE canary for the
// record's location. The boot gate is POSIX sh and hardcodes the path; Go
// derives it from the journal path. If they drift, arming writes a record the
// gate never reads — and the gate would then skip every boot as "nothing
// armed", silently, which is precisely the laundering this round removes.
func TestPromoteScriptArmRecordPathMatchesGo(t *testing.T) {
	data, err := os.ReadFile(promoteScriptPath(t))
	if err != nil {
		t.Fatalf("read promote script: %v", err)
	}
	m := armRecordPathRE.FindSubmatch(data)
	if m == nil {
		t.Fatal("no `ARM_RECORD=\"...\"` assignment in the promote script; the " +
			"record location is no longer assertable from Go")
	}
	got := string(m[1])
	want := ArmRecordPath(DefaultKernelJournalPath)
	if got != want {
		t.Fatalf("promote script reads the arm record from %q but Go writes it to "+
			"%q. Arming would record where the gate never looks, and the gate "+
			"would skip every boot as 'nothing armed'.", got, want)
	}
}

// TestPromoteScriptSelectsFromTheRecordNotInference guards the design itself:
// the record must be consulted, and the inference helpers must not be able to
// select a binary on their own. `try_candidate` may still run — it feeds the
// cross-check — but the executed path has to come from the record.
func TestPromoteScriptSelectsFromTheRecordNotInference(t *testing.T) {
	data, err := os.ReadFile(promoteScriptPath(t))
	if err != nil {
		t.Fatalf("read promote script: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, `XPFD="$RECORDED"`) {
		t.Error("the gate never assigns the executed binary from the arm record; " +
			"selection has drifted back to inference (#6601 r6)")
	}
	// The cross-check must refuse on disagreement rather than prefer one side.
	if !strings.Contains(src, `"$CROSS" != "$RECORDED"`) {
		t.Error("no record-vs-unit disagreement check; a stale leftover unit " +
			"could again select an older binary (#6601 r6 MAJOR)")
	}
	// Nothing may re-introduce a compiled-default fallback.
	for _, banned := range []string{
		`try_candidate /usr/local/sbin/xpfd`,
		`try_candidate /var/lib/xpf/versions/current/xpfd`,
	} {
		if strings.Contains(src, banned) {
			t.Errorf("compiled-default inference reintroduced: %s", banned)
		}
	}
}

// promoteScriptPath locates the boot-time gate from this package's directory.
func promoteScriptPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	p := filepath.Join(wd, "..", "..", "scripts", "image", "xpf-kernel-promote")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("promote script not found at %s: %v", p, err)
	}
	return p
}
