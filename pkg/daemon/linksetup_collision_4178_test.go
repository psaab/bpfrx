package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNICFabric models a set of live interfaces keyed by a stable physical id
// so a rename test can (a) reject a rename whose TARGET name is already live
// (EEXIST, like the kernel) and (b) verify which physical NIC ends up at each
// final name. Its rename method is the injected rename primitive.
type fakeNICFabric struct {
	nameToID map[string]string // CURRENT kernel name -> stable physical NIC id
}

func (f *fakeNICFabric) rename(from, to string) error {
	id, ok := f.nameToID[from]
	if !ok {
		return errors.New("ENODEV: " + from)
	}
	if _, taken := f.nameToID[to]; taken {
		return errors.New("EEXIST: " + to) // kernel refuses a name already in use
	}
	delete(f.nameToID, from)
	f.nameToID[to] = id
	return nil
}

func (f *fakeNICFabric) idAt(name string) string { return f.nameToID[name] }

func readLinkOriginalName(t *testing.T, dir, target string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, linkPrefix+target+".link"))
	if err != nil {
		t.Fatalf("read .link for %s: %v", target, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "OriginalName=") {
			return strings.TrimPrefix(line, "OriginalName=")
		}
	}
	t.Fatalf(".link for %s has no OriginalName=", target)
	return ""
}

// TestRenamePositionalEnumerationShiftNoCorruption is the #4178 regression: an
// enumeration shift (a NIC added at a LOWER PCI bus) must not corrupt the
// .link OriginalName= chain or EEXIST-strand a rename. It reproduces the
// finding's trace: prior boot A->fxp0, B->ge-0-0-0; a new NIC C appears at a
// lower bus; on reboot udev applies the .link files so A is at "fxp0" and B is
// at "ge-0-0-0", and enumeration is bus-sorted C, A, B.
//
// Reverting renamePositional to the old single-pass loop (recover OriginalName
// AFTER writing earlier .links + no collision break) makes this RED: fxp0 stays
// on A because C -> fxp0 EEXISTs, ge-0-0-0 ends up EMPTY, C is stranded on its
// kernel name, and ge-0-0-0's .link records C's kernel name instead of A's true
// original.
func TestRenamePositionalEnumerationShiftNoCorruption(t *testing.T) {
	dir := withTempLinkDir(t)

	// Prior boot recorded the rename database: A -> fxp0 (OriginalName=enpA),
	// B -> ge-0-0-0 (OriginalName=enpB).
	_, _ = writeLinkFile("fxp0", "enpA")
	_, _ = writeLinkFile("ge-0-0-0", "enpB")

	// Live state on THIS boot after udev applied those .link files, plus the
	// new NIC C at its kernel name.
	fab := &fakeNICFabric{nameToID: map[string]string{
		"fxp0":     "A",
		"ge-0-0-0": "B",
		"enpC":     "C",
	}}

	// Enumeration is bus-sorted: C (new, lowest bus), then A (fxp0), then B.
	nics := []pciNIC{
		{name: "enpC"},
		{name: "fxp0"},
		{name: "ge-0-0-0"},
	}

	if changed, _ := renamePositional(nics, 0, false, fab.rename); !changed {
		t.Fatal("expected changed=true on an enumeration shift")
	}

	// Every NIC lands on the RIGHT final name — no EEXIST stranding.
	if got := fab.idAt("fxp0"); got != "C" {
		t.Fatalf("fxp0 should be the new NIC C, got %q (fabric=%v)", got, fab.nameToID)
	}
	if got := fab.idAt("ge-0-0-0"); got != "A" {
		t.Fatalf("ge-0-0-0 should be A (shifted down one slot), got %q (fabric=%v)", got, fab.nameToID)
	}
	if got := fab.idAt("ge-0-0-1"); got != "B" {
		t.Fatalf("ge-0-0-1 should be B (shifted down one slot), got %q (fabric=%v)", got, fab.nameToID)
	}
	// Nothing stranded on a kernel or temp name.
	for name := range fab.nameToID {
		if name != "fxp0" && !strings.HasPrefix(name, "ge-0-0-") {
			t.Fatalf("a NIC is stranded on a non-final name %q: %v", name, fab.nameToID)
		}
	}

	// The .link OriginalName= chain is UNCORRUPTED: each records the TRUE
	// pre-rename kernel name of the physical NIC now wearing that name. The
	// load-bearing assertion is ge-0-0-0 -> enpA (A's real kernel name): the
	// old single-pass loop corrupted this to enpC.
	if got := readLinkOriginalName(t, dir, "fxp0"); got != "enpC" {
		t.Fatalf("fxp0 .link OriginalName should be C's kernel enpC, got %q", got)
	}
	if got := readLinkOriginalName(t, dir, "ge-0-0-0"); got != "enpA" {
		t.Fatalf("ge-0-0-0 .link OriginalName should be A's TRUE kernel enpA "+
			"(single-pass corrupts it to enpC), got %q", got)
	}
	if got := readLinkOriginalName(t, dir, "ge-0-0-1"); got != "enpB" {
		t.Fatalf("ge-0-0-1 .link OriginalName should be B's kernel enpB, got %q", got)
	}
}

// TestRenamePositionalFirstBootNoTempRenames proves the collision-safe rename
// does NOT disturb the normal path: a fresh box whose NICs still wear kernel
// names gets a straight rename to fxp0/ge-0-0-X with no temp renames and no
// EEXIST, and the OriginalName= chain records each NIC's kernel name.
func TestRenamePositionalFirstBootNoTempRenames(t *testing.T) {
	dir := withTempLinkDir(t)

	fab := &fakeNICFabric{nameToID: map[string]string{
		"enp5s0": "A",
		"enp6s0": "B",
		"enp7s0": "C",
	}}
	nics := []pciNIC{{name: "enp5s0"}, {name: "enp6s0"}, {name: "enp7s0"}}

	if changed, _ := renamePositional(nics, 0, false, fab.rename); !changed {
		t.Fatal("first boot must report changed")
	}
	// No xpf-tmp-* name ever appears (no collisions on a fresh box).
	for name := range fab.nameToID {
		if strings.HasPrefix(name, "xpf-tmp-") {
			t.Fatalf("first boot must not need a temp rename, saw %q: %v", name, fab.nameToID)
		}
	}
	if fab.idAt("fxp0") != "A" || fab.idAt("ge-0-0-0") != "B" || fab.idAt("ge-0-0-1") != "C" {
		t.Fatalf("first-boot straight rename mismatch: %v", fab.nameToID)
	}
	if got := readLinkOriginalName(t, dir, "ge-0-0-0"); got != "enp6s0" {
		t.Fatalf("ge-0-0-0 .link OriginalName should be enp6s0, got %q", got)
	}
}

// TestRenamePositionalSteadyStateNoChurn proves operator priority #1 (no
// churn): a second run with every NIC already at its target name performs no
// rename and reports unchanged, so the normal no-collision path is untouched
// by the collision-safe discipline.
func TestRenamePositionalSteadyStateNoChurn(t *testing.T) {
	withTempLinkDir(t)
	_, _ = writeLinkFile("fxp0", "enp5s0")
	_, _ = writeLinkFile("ge-0-0-0", "enp6s0")

	renames := 0
	rename := func(from, to string) error { renames++; return nil }
	nics := []pciNIC{{name: "fxp0"}, {name: "ge-0-0-0"}}

	if changed, _ := renamePositional(nics, 0, false, rename); changed {
		t.Fatal("steady state must report unchanged (no churn)")
	}
	if renames != 0 {
		t.Fatalf("steady state must issue no renames, got %d", renames)
	}
}
