package upgrade

import (
	"os"
	"strings"
	"testing"
)

// writeRawExec overwrites path with exactly data and forces the executable bit,
// leaving a REGULAR + EXECUTABLE file whose only defect is its CONTENT. This is
// the #6409 corruption shape: it clears validateRestorableVersion's regular-
// file and exec-bit metadata checks, so the ELF content gate is the sole
// remaining discriminator — the fail-on-revert isolation the test relies on.
func writeRawExec(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	// Defeat any restrictive umask so the exec bit is definitely set: metadata
	// must pass, leaving the content gate as the reason for any refusal.
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestValidateRestorableVersion_ContentGate is the #6409 matrix: a lockstep
// rollback binary that is a REGULAR file with the EXECUTABLE bit but whose
// CONTENT is not a kernel-executable ELF image (arbitrary text chmod'd 0755, an
// empty file, a truncated header) is NOT a startable rollback target. The flip
// drop-in execs the literal versions/<ver>/xpfd path, so systemd's execve of a
// non-ELF file fails and strands the daemon after STOP exactly like a missing
// binary. validateRestorableVersion must reject it, and restorableCurrentTarget
// must classify it present-but-broken (ver=="", present==true) so a cut refuses
// under any first-cut sanction.
//
// FAIL-ON-REVERT: remove the elfHeaderParseable content gate from
// validateRestorableVersion (revert to the metadata-only regular+exec checks)
// and each corrupt-content subtest's binary passes as restorable -> ver becomes
// "1.0.0" -> the `ver != ""` assertions go clean ASSERTION RED. The
// valid-ELF-control subtest guards the other direction: the gate must not
// over-reject a genuine ELF rollback runtime.
func TestValidateRestorableVersion_ContentGate(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"arbitrary-text-chmod-0755", []byte("this is not an ELF binary\n")},
		{"empty-file", nil},
		{"truncated-elf-magic-only", []byte{0x7f, 'E', 'L', 'F'}},
		{"partial-header", append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1}, make([]byte, 8)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeSystem(t, "2.0.0")
			r, cfg := testEnv(t, fs)
			writeCompleteVersionDir(t, cfg, "1.0.0") // valid ELF lockstep set...
			// ...then corrupt the CONTENT of the first lockstep binary while
			// keeping it a regular executable file.
			writeRawExec(t, firstLockstepBinPath(t, cfg, "1.0.0"), tc.data)

			// Direct predicate: must refuse, and specifically on the content gate.
			verr := r.validateRestorableVersion("1.0.0")
			if verr == nil {
				t.Fatalf("validateRestorableVersion accepted a lockstep binary with "+
					"non-executable content (%s); execve would fail and strand the "+
					"daemon after STOP (#6409)", tc.name)
			}
			if !strings.Contains(verr.Error(), "not a parseable ELF image") {
				t.Fatalf("refusal is not the #6409 content gate: %v", verr)
			}

			// Integration: `current` -> this dir must resolve present-but-broken.
			if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
				t.Fatal(err)
			}
			ver, present := r.restorableCurrentTarget()
			if ver != "" {
				t.Fatalf("%s: corrupt-content lockstep binary wrongly accepted as a "+
					"restorable target %q (#6409)", tc.name, ver)
			}
			if !present {
				t.Fatalf("%s: wrongly classified as ABSENT (sanctionable); a present-but-"+
					"unstartable rollback target must report present=true (#6409)", tc.name)
			}
		})
	}

	t.Run("valid-elf-control-proceeds", func(t *testing.T) {
		// Control: an untouched complete dir (writeCompleteVersionDir emits a
		// parseable ELF per binary) IS restorable — the content gate must not
		// over-reject a genuine native rollback runtime.
		fs := newFakeSystem(t, "2.0.0")
		r, cfg := testEnv(t, fs)
		writeCompleteVersionDir(t, cfg, "1.0.0")
		if verr := r.validateRestorableVersion("1.0.0"); verr != nil {
			t.Fatalf("valid ELF lockstep set wrongly refused by the #6409 content gate: %v", verr)
		}
		if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
			t.Fatal(err)
		}
		ver, present := r.restorableCurrentTarget()
		if ver != "1.0.0" || !present {
			t.Fatalf("valid ELF current: got (%q,present=%v), want (\"1.0.0\",true)", ver, present)
		}
	})
}

// TestRun_CorruptContentCurrentRefusesEvenWhenSanctioned is the #6409 INIT
// integration case, mirroring the #6374 non-executable variant: a `current`
// whose rollback runtime's lockstep binary is a regular executable file with
// NON-ELF content is not systemd-startable, so it is a present-but-broken
// rollback target that must refuse before STOP even under a first-cut sanction.
// A content-blind check (metadata only) would STOP into an unstartable rollback
// state — the #6374/#6409 hazard.
//
// FAIL-ON-REVERT: drop the elfHeaderParseable gate -> the text-content xpfd is
// accepted as restorable, the cut records it and reaches STOP -> the
// no-live-mutation assertions go RED.
func TestRun_CorruptContentCurrentRefusesEvenWhenSanctioned(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	writeCompleteVersionDir(t, cfg, "1.0.0")
	writeRawExec(t, firstLockstepBinPath(t, cfg, "1.0.0"), []byte("not-an-elf-image\n"))
	if err := os.Symlink("1.0.0", currentLinkPath(cfg)); err != nil {
		t.Fatal(err)
	}

	err := r.Run(Options{AllowNoRollbackFirstCut: true}) // SANCTIONED
	if err == nil {
		t.Fatal("expected refuse-before-STOP on a current whose rollback xpfd has " +
			"non-ELF content, even when sanctioned")
	}
	if !strings.Contains(err.Error(), "refuse-before-STOP") {
		t.Fatalf("error is not the refuse-before-STOP guard: %v", err)
	}
	assertNoLiveMutation(t, fs, "a present-but-unstartable (non-ELF content) rollback target")
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Error("a journal was persisted despite refusing a non-ELF-content rollback target")
	}
}
