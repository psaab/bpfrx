package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #5452 (HIGH security): the kernel A/B arm path used the candidate version and
// the running kernel's `uname -r` string RAW in a /boot glob + os.RemoveAll, a
// /lib/modules os.RemoveAll, an `apt-get purge linux-image-<ver>`, and the GRUB
// slot-selector script — with no safe-segment validation. candidateVersion="*"
// globbed "/boot/*-*" into RemoveAll (arbitrary /boot deletion -> unbootable),
// a ".." traversed the modules delete, and a quote/newline in the uname string
// injected GRUB directives. ValidateKernelSegment now fails CLOSED at Arm and
// defensively before the delete/GRUB sites. These tests are RED-on-revert: with
// the production validation removed, the "*"/".."/quote cases delete or inject.

func TestValidateKernelSegment(t *testing.T) {
	valid := []string{
		"6.18.0-xpf1-amd64",
		"6.18.5-12-generic",
		"6.8.0-rc2-amd64",
		"5.10.0+deb11u1-amd64",
		"6.1.0~bpo-amd64",
		"6.18.0_variant",
	}
	for _, v := range valid {
		if err := ValidateKernelSegment("kernel version", v); err != nil {
			t.Errorf("ValidateKernelSegment(%q) = %v, want nil (a real uname -r must pass)", v, err)
		}
	}

	invalid := []string{
		"",            // empty
		"*",           // glob star -> /boot/*-* wildcard
		"?",           // glob single
		"6.18.0-[ab]", // glob class
		".",           // lone "." -> /lib/modules/. == /lib/modules (whole-tree delete)
		"..",          // traversal (/lib/modules/.. == /lib)
		"../etc",      // traversal
		"6.18/0",      // path separator
		"a..b",        // embedded ".."
		"-amd64",      // leading '-' parses as an option
		"6.18\"x",     // double quote -> GRUB injection
		"6.18\nset x", // newline -> GRUB directive injection
		"6.18\\x",     // backslash
		"6.18 0",      // space
		"6.18\t0",     // tab
		"6.18\x00",    // NUL / control char
	}
	for _, v := range invalid {
		if err := ValidateKernelSegment("kernel version", v); err == nil {
			t.Errorf("ValidateKernelSegment(%q) = nil, want an error (unsafe segment must fail closed)", v)
		}
	}
}

// Arm must reject an unsafe candidate version up front — no preflight, no
// install, no reboot. RED-on-revert: without the Arm-path validation, a "*"
// candidate walks preflight/install/arm and reboots.
func TestArm_RejectsUnsafeCandidateVersion(t *testing.T) {
	for _, bad := range []string{"*", "../etc", "6.18\"x", "-amd64"} {
		f := newFakeKernelSystem()
		r := newKernelRunner(t, f)
		err := r.Arm(bad)
		if err == nil {
			t.Fatalf("Arm(%q) = nil, want a rejection", bad)
		}
		if f.rebooted {
			t.Errorf("Arm(%q) rebooted despite an unsafe candidate", bad)
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "install:") {
				t.Errorf("Arm(%q) installed the candidate despite an unsafe segment (%q)", bad, c)
			}
		}
		j, _ := r.loadKernelJournal()
		if j.State != KernelStateInit {
			t.Errorf("Arm(%q) advanced journal to %s, want it untouched (INIT)", bad, j.State)
		}
	}
}

// seedForeignBootKernels lays down /boot files for OTHER (known-good) kernels
// under a temp fsRoot. A candidateVersion="*" glob ("/boot/*-*") would match
// all of them; the prune must never delete them.
func seedForeignBootKernels(t *testing.T, root string) []string {
	t.Helper()
	bootDir := filepath.Join(root, "boot")
	if err := os.MkdirAll(bootDir, 0755); err != nil {
		t.Fatalf("seed boot dir: %v", err)
	}
	var paths []string
	for _, name := range []string{
		"vmlinuz-6.18.5-10-generic",
		"initrd.img-6.18.5-10-generic",
		"config-6.18.5-10-generic",
		"vmlinuz-6.18.5-9-generic",
	} {
		p := filepath.Join(bootDir, name)
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		paths = append(paths, p)
	}
	return paths
}

// PruneInactiveSlot must reject a glob-metacharacter candidate before touching
// apt or the filesystem. RED-on-revert: without the validation the "*" candidate
// globs "/boot/*-*" and os.RemoveAll deletes every seeded kernel file.
func TestPruneInactiveSlot_RejectsGlobCandidate(t *testing.T) {
	root := t.TempDir()
	const knownGood = "6.18.5-10-generic"
	boot := seedForeignBootKernels(t, root)

	aptCalled := false
	sys := &realKernelSystem{
		fsRoot:         root,
		pkgInstalledFn: func(string) (bool, error) { return true, nil },
		aptGetFn: func(...string) error {
			aptCalled = true
			return nil
		},
	}

	err := sys.PruneInactiveSlot("xpf-B", knownGood, "*")
	if err == nil {
		t.Fatal("PruneInactiveSlot(candidate=\"*\") = nil, want a rejection")
	}
	if aptCalled {
		t.Error("apt-get was invoked with an unsafe candidate (would purge linux-image-*)")
	}
	for _, p := range boot {
		if _, statErr := os.Stat(p); statErr != nil {
			t.Errorf("%s deleted by a glob-candidate prune (%v) — arbitrary /boot deletion", p, statErr)
		}
	}
}

// A ".." candidate must be rejected before os.RemoveAll("/lib/modules/..")
// (which resolves to "/lib"). RED-on-revert: without the validation the prune
// deletes the parent tree.
func TestPruneInactiveSlot_RejectsTraversalCandidate(t *testing.T) {
	root := t.TempDir()
	// Seed /lib/modules and a sibling so a "/lib/modules/.." == "/lib" RemoveAll
	// would be observable.
	libDir := filepath.Join(root, "lib", "modules", "6.18.5-10-generic")
	if err := os.MkdirAll(libDir, 0755); err != nil {
		t.Fatalf("seed lib/modules: %v", err)
	}
	sys := &realKernelSystem{
		fsRoot:         root,
		pkgInstalledFn: func(string) (bool, error) { return false, nil },
		aptGetFn:       func(...string) error { return nil },
	}
	err := sys.PruneInactiveSlot("xpf-B", "6.18.5-10-generic", "..")
	if err == nil {
		t.Fatal("PruneInactiveSlot(candidate=\"..\") = nil, want a rejection")
	}
	if _, statErr := os.Stat(filepath.Join(root, "lib", "modules")); statErr != nil {
		t.Errorf("/lib/modules removed by a \"..\" traversal prune (%v)", statErr)
	}
}

// A lone "." candidate must be rejected before os.RemoveAll("/lib/modules/.")
// (which resolves to "/lib/modules" itself -> deletes the WHOLE modules tree).
// A "." is in the charset and is neither empty nor "..", so the charset scan
// alone would let it through — hence the explicit "." guard. RED-on-revert:
// without the guard the prune deletes every installed kernel's modules.
func TestPruneInactiveSlot_RejectsLoneDotCandidate(t *testing.T) {
	root := t.TempDir()
	otherKernel := filepath.Join(root, "lib", "modules", "6.18.5-10-generic")
	if err := os.MkdirAll(otherKernel, 0755); err != nil {
		t.Fatalf("seed lib/modules: %v", err)
	}
	sys := &realKernelSystem{
		fsRoot:         root,
		pkgInstalledFn: func(string) (bool, error) { return false, nil },
		aptGetFn:       func(...string) error { return nil },
	}
	err := sys.PruneInactiveSlot("xpf-B", "6.18.5-10-generic", ".")
	if err == nil {
		t.Fatal("PruneInactiveSlot(candidate=\".\") = nil, want a rejection")
	}
	if _, statErr := os.Stat(filepath.Join(root, "lib", "modules")); statErr != nil {
		t.Errorf("/lib/modules removed by a \".\" prune (%v) — whole modules tree wiped", statErr)
	}
	if _, statErr := os.Stat(otherKernel); statErr != nil {
		t.Errorf("/lib/modules/6.18.5-10-generic removed by a \".\" prune (%v)", statErr)
	}
}

// WriteSlotSelector must reject an injection-carrying uname string and NOT write
// the selector. RED-on-revert: without the validation the quote/newline is
// Sprintf'd into the GRUB directive and the .selector file is written.
func TestWriteSlotSelector_RejectsInjection(t *testing.T) {
	for _, bad := range []string{
		"6.18.5-10-generic\"\nset root=(hd0)",
		"6.18.5-10\ngeneric",
		"*",
	} {
		root := t.TempDir()
		sys := &realKernelSystem{fsRoot: root}
		if err := sys.WriteSlotSelector("xpf-B", bad); err == nil {
			t.Errorf("WriteSlotSelector(unameR=%q) = nil, want a rejection", bad)
		}
		selPath := filepath.Join(root, "boot/efi/EFI", "xpf-B", "xpf.selector")
		if _, statErr := os.Stat(selPath); statErr == nil {
			t.Errorf("WriteSlotSelector wrote a selector from an unsafe uname %q (GRUB injection)", bad)
		}
	}
}

// A valid uname string writes a selector that reads back the version.
func TestWriteSlotSelector_ValidRoundTrips(t *testing.T) {
	root := t.TempDir()
	const good = "6.18.0-xpf1-amd64"
	sys := &realKernelSystem{fsRoot: root}
	if err := sys.WriteSlotSelector("xpf-B", good); err != nil {
		t.Fatalf("WriteSlotSelector(valid) = %v, want nil", good)
	}
	got, err := sys.ReadSlotSelector("xpf-B")
	if err != nil {
		t.Fatalf("ReadSlotSelector: %v", err)
	}
	if got != good {
		t.Errorf("selector round-trip = %q, want %q", got, good)
	}
}
