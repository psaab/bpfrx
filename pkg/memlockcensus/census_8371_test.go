package memlockcensus

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// repoRoot walks up to the directory holding go.mod, so the scan reads the
// tree rather than a path baked in at authoring time.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}

var funcLine = regexp.MustCompile(`^func\s+([A-Za-z0-9_]+)`)

// selfFile is this scanner's own path. See the exclusion in scanTree.
const selfFile = "pkg/memlockcensus/census_8371_test.go"

// scanTree returns every (file, test) that calls rlimit.RemoveMemlock, read
// from the tree rather than from the registry — so the two can disagree.
func scanTree(t *testing.T) []Site {
	t.Helper()
	root := repoRoot(t)
	// git grep rather than a filepath.Walk: it honours .gitignore, so a stale
	// worktree artifact or a vendored copy cannot inflate the census.
	out, err := exec.Command("git", "-C", root, "grep", "-l", "rlimit.RemoveMemlock()", "--", "pkg/**/*_test.go").Output()
	if err != nil {
		t.Fatalf("git grep: %v", err)
	}
	var got []Site
	for _, rel := range strings.Fields(string(out)) {
		// This package's own file is excluded, and the reason is not
		// convenience. It contains `rlimit.RemoveMemlock()` twice — once in
		// TestMemlockGuardsAreInertHere, which CALLS it to report whether the
		// privilege exists, and once inside this scanner, which greps for the
		// literal. Neither is a guard whose protection is conditional; the
		// first is the report and the second is the instrument.
		//
		// This shipped broken and turned master red, and the reason it passed
		// pre-merge is worth recording: `git grep` reads TRACKED files only, and
		// the file was still untracked when the suite was run in the authoring
		// worktree. The scanner could not see itself until the commit landed —
		// so the pre-merge green was real and was measuring a tree that no
		// longer existed a moment later. A scanner that reads the index must be
		// exercised against a tree where its own file is committed.
		if rel == selfFile {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		fn := ""
		for _, line := range strings.Split(string(b), "\n") {
			if m := funcLine.FindStringSubmatch(line); m != nil {
				fn = m[1]
			}
			if strings.Contains(line, "rlimit.RemoveMemlock()") && fn != "" {
				got = append(got, Site{File: rel, Test: fn})
			}
		}
	}
	sort.Slice(got, func(i, j int) bool {
		if got[i].File != got[j].File {
			return got[i].File < got[j].File
		}
		return got[i].Test < got[j].Test
	})
	// One row per (file, test): a test calling RemoveMemlock twice is still one
	// conditional guard, and counting the calls would make the registry a
	// measure of style rather than of coverage.
	var uniq []Site
	for i, s := range got {
		if i == 0 || got[i-1] != s {
			uniq = append(uniq, s)
		}
	}
	return uniq
}

// TestMemlockCensusMatchesTheTree is the gate: the set of memlock-gated guards
// cannot change without being recorded (#8371).
//
// Both directions matter and they fail differently. A guard added without a row
// grows the inert set silently — the exact way this reached 42. A row without a
// guard is a dead entry that makes the registry overstate what is conditional,
// which is the same false-record harm one surface over.
func TestMemlockCensusMatchesTheTree(t *testing.T) {
	tree := scanTree(t)

	// Positive control on the scanner itself. If the scan comes back empty the
	// registry check below would pass vacuously for an empty registry and fail
	// confusingly for a full one; either way the number is about the scanner,
	// not the tree.
	if len(tree) == 0 {
		t.Fatal("the scan found NO memlock-gated tests, which cannot be right while " +
			"the registry holds entries — the git grep pattern or the pathspec has " +
			"stopped matching, and every verdict below would be about the scanner")
	}

	key := func(s Site) string { return s.File + "\t" + s.Test }
	inReg := map[string]bool{}
	for _, s := range Registry {
		inReg[key(s)] = true
	}
	inTree := map[string]bool{}
	for _, s := range tree {
		inTree[key(s)] = true
	}

	var added, removed []string
	for _, s := range tree {
		if !inReg[key(s)] {
			added = append(added, s.File+" -> "+s.Test)
		}
	}
	for _, s := range Registry {
		if !inTree[key(s)] {
			removed = append(removed, s.File+" -> "+s.Test)
		}
	}

	if len(added) > 0 {
		t.Errorf("#8371: %d memlock-gated guard(s) exist in the tree but are NOT in the "+
			"registry:\n  %s\n\nA guard that skips on RemoveMemlock provides no protection "+
			"where the privilege is unavailable, and the package still reports ok — so a "+
			"reviewer who greps for it concludes the defect is guarded when it may not be. "+
			"Before adding a row, ask whether the test NEEDS a real BPF map: #8370 moved "+
			"four of its own below the privilege boundary using the fakeCtrlMap seam and "+
			"they now execute unprivileged. Record it here only if it genuinely needs the "+
			"kernel.", len(added), strings.Join(added, "\n  "))
	}
	if len(removed) > 0 {
		t.Errorf("#8371: %d registry row(s) name a guard that no longer exists:\n  %s\n\n"+
			"Delete the row. A dead entry makes the registry overstate how much of the "+
			"suite is environment-conditional, which is a false statement in the record "+
			"the registry exists to be.", len(removed), strings.Join(removed, "\n  "))
	}
}

// guardReadiness is what this environment can actually do, measured rather
// than inferred (#9337).
//
// The census used to answer "can the guards run here?" with
// `rlimit.RemoveMemlock() == nil` alone. That is a DIFFERENT question. Raising
// the memlock rlimit needs CAP_SYS_RESOURCE (and on a modern kernel BPF objects
// are charged to memcg, so it often succeeds unprivileged and means nothing);
// what the guards need is to CREATE a BPF map, which needs CAP_BPF. Measured:
// with only the memlock rlimit raised, the census reported "memlock is
// available here — all 42 registered guards execute" and every guard then
// failed at `map create: operation not permitted`.
//
// A CI leg built to that advice would set XPF_REQUIRE_MEMLOCK_GUARDS=1, be told
// the environment was ready, and go red with 42 map-creation errors that look
// nothing like the defects the guards exist to catch. So the probe now performs
// the FIRST OPERATION EVERY GUARD PERFORMS, and reports three states rather
// than two.
type guardReadiness struct {
	// memlockErr is rlimit.RemoveMemlock()'s result. Kept because a guard's
	// own first line is still `if err := rlimit.RemoveMemlock(); err != nil {
	// t.Skipf(...) }` — a non-nil value here is why they SKIP.
	memlockErr error
	// mapErr is a trivial ebpf.NewMap()'s result: the capability the guards
	// actually consume. Non-nil with memlockErr nil is the trap above — the
	// guards stop skipping and start FAILING.
	mapErr error
}

func probeGuardReadiness() guardReadiness {
	r := guardReadiness{memlockErr: rlimit.RemoveMemlock()}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		r.mapErr = err
		return r
	}
	_ = m.Close()
	return r
}

// ready reports whether the registered guards will actually execute here.
func (r guardReadiness) ready() bool { return r.memlockErr == nil && r.mapErr == nil }

// guardCapabilityAdvice is the remedy line. CAP_BPF is named first because it
// is the binding one: CAP_SYS_RESOURCE alone raises the rlimit and leaves every
// map create failing with EPERM, which is strictly worse than skipping because
// the census reports READY on the way in (#9337).
const guardCapabilityAdvice = "Run as root, or with CAP_BPF (plus CAP_SYS_RESOURCE on kernels " +
	"that still charge BPF memory to the memlock rlimit — pre-5.11). CAP_SYS_RESOURCE " +
	"ALONE IS NOT ENOUGH: it raises the rlimit, so the guards stop skipping and start " +
	"failing at `map create: operation not permitted`. `make test-memlock-guards` runs " +
	"them under sudo."

// describe renders the report for a NOT-ready environment. It is a method on
// the measurement rather than inline prose so the two states that used to be
// one — cannot raise memlock, and can raise memlock but cannot create a map —
// are named differently in the output a reader acts on.
func (r guardReadiness) describe() string {
	var b strings.Builder
	switch {
	case r.memlockErr != nil:
		fmt.Fprintf(&b, "#8371: memlock is NOT available here (%v), so the following %d "+
			"guards SKIP and their packages still report ok:\n", r.memlockErr, len(Registry))
	default:
		fmt.Fprintf(&b, "#9337: memlock IS available here but BPF map creation is NOT "+
			"(%v). This is the WORST of the three states: the following %d guards no "+
			"longer skip — they FAIL, at map creation, with an error that looks nothing "+
			"like the defect each one exists to catch:\n", r.mapErr, len(Registry))
	}
	for _, s := range Registry {
		fmt.Fprintf(&b, "  %s -> %s\n", s.File, s.Test)
	}
	fmt.Fprintf(&b, "\nEach names a real defect it does not protect against in this "+
		"environment. %s", guardCapabilityAdvice)
	return b.String()
}

// TestMemlockGuardsAreInertHere reports, by name, which guards did not run in
// THIS environment — and fails instead of reporting when the environment is
// declared to be one that must execute them.
//
// It deliberately does not fail by default. Turning every developer's
// `make test-go` red for an environment property they cannot change produces a
// gate everyone learns to ignore, which is worse than the silence it replaces.
// XPF_REQUIRE_MEMLOCK_GUARDS=1 is for a privileged leg (`make
// test-memlock-guards`), where a run that stops executing them IS a regression.
func TestMemlockGuardsAreInertHere(t *testing.T) {
	r := probeGuardReadiness()
	required := os.Getenv("XPF_REQUIRE_MEMLOCK_GUARDS") == "1"

	if r.ready() {
		t.Logf("#8371: memlock AND BPF map creation are available here — all %d "+
			"registered guards execute.", len(Registry))
		return
	}

	report := r.describe()
	if required {
		t.Fatalf("%s\n\nXPF_REQUIRE_MEMLOCK_GUARDS=1 declared this environment must "+
			"execute them, and it did not.", report)
	}
	t.Log(report)
}

// TestReadinessIsNotMemlockAlone9337 is the cell the old predicate fails.
//
// It is a unit test on the measurement, not on the machine, deliberately: the
// state it pins — memlock raised, CAP_BPF absent — cannot be produced from
// inside a test process that does not have CAP_SETPCAP, and a check that can
// only run where the defect is absent is not a check.
func TestReadinessIsNotMemlockAlone9337(t *testing.T) {
	mapEPERM := errors.New("map create: operation not permitted")

	cases := []struct {
		name      string
		r         guardReadiness
		wantReady bool
		why       string
	}{
		{
			name: "memlock_and_map_create_both_available",
			r:    guardReadiness{}, wantReady: true,
			why: "the only state in which the registered guards actually execute",
		},
		{
			name: "memlock_raised_but_no_CAP_BPF",
			r:    guardReadiness{mapErr: mapEPERM}, wantReady: false,
			why: "MEASURED (#9337): raising only the memlock rlimit made the census " +
				"report READY and every guard then failed at map creation. A readiness " +
				"predicate that cannot see this sends a privileged leg into 42 failures " +
				"that look nothing like the defects the guards catch",
		},
		{
			name: "no_memlock",
			r:    guardReadiness{memlockErr: errors.New("operation not permitted")}, wantReady: false,
			why: "the guards skip; this is the state the census was built for",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.ready(); got != tc.wantReady {
				t.Fatalf("ready() = %v, want %v — %s", got, tc.wantReady, tc.why)
			}
		})
	}

	// The report for the map-create state must not read like the memlock one:
	// "they SKIP" and "they FAIL" call for different actions, and the census's
	// whole value is that the message names what is actually wrong.
	skipReport := guardReadiness{memlockErr: errors.New("operation not permitted")}.describe()
	failReport := guardReadiness{mapErr: mapEPERM}.describe()
	if !strings.Contains(skipReport, "SKIP") {
		t.Errorf("the no-memlock report does not say the guards SKIP:\n%s", skipReport)
	}
	if !strings.Contains(failReport, "FAIL") {
		t.Errorf("the no-CAP_BPF report does not say the guards FAIL — a reader told "+
			"they SKIP will look for silence and find 42 red cells:\n%s", failReport)
	}
}

// TestRemedyTextNamesTheCapabilityTheGuardsNeed9337 pins the correction itself.
//
// The census used to say "Run as root or with CAP_SYS_RESOURCE to execute
// them." That advice is not merely incomplete — followed exactly, it produces
// an environment the census calls READY and the guards cannot run in. A wrong
// diagnostic is worse than a missing one.
func TestRemedyTextNamesTheCapabilityTheGuardsNeed9337(t *testing.T) {
	if !strings.Contains(guardCapabilityAdvice, "CAP_BPF") {
		t.Fatalf("the remedy text does not name CAP_BPF, which is the capability BPF "+
			"map creation actually requires:\n%s", guardCapabilityAdvice)
	}
	if !strings.Contains(guardCapabilityAdvice, "ALONE IS NOT ENOUGH") {
		t.Fatalf("the remedy text does not record that CAP_SYS_RESOURCE alone is "+
			"insufficient. That is the half a reader acts on and gets wrong:\n%s",
			guardCapabilityAdvice)
	}
}

// TestTheScannerExcludesItselfAndOnlyItself pins the exclusion that unbroke
// master, in both directions.
//
// The forward half: this package's own file must not be censused. It contains
// `rlimit.RemoveMemlock()` twice — the report calls it, the scanner greps for
// the literal — and neither is a guard whose protection is conditional.
//
// The reverse half is the one that matters. An exclusion is a hole, and a hole
// widened by one character stops the census seeing an entire package. So the
// constant is asserted to name a file that EXISTS and to be a single file, not
// a prefix or a directory — the two ways this would silently grow.
func TestTheScannerExcludesItselfAndOnlyItself(t *testing.T) {
	root := repoRoot(t)

	if _, err := os.Stat(filepath.Join(root, selfFile)); err != nil {
		t.Fatalf("selfFile %q does not exist: %v — an exclusion naming a path that "+
			"is not there excludes nothing, and would have gone unnoticed", selfFile, err)
	}
	if !strings.HasSuffix(selfFile, "_test.go") {
		t.Errorf("selfFile %q is not a single _test.go file. A directory or prefix "+
			"here would silently drop every guard beneath it from the census, which "+
			"is the failure this whole package exists to prevent", selfFile)
	}

	// The scan must still see guards in the tree — an exclusion that swallowed
	// everything would leave the census trivially satisfied by an empty
	// registry, which reads exactly like a clean tree.
	tree := scanTree(t)
	if len(tree) < 40 {
		t.Fatalf("the scan found only %d guards after the self-exclusion; it saw "+
			"%d before this change landed. The exclusion is too wide.",
			len(tree), len(Registry))
	}
	for _, s := range tree {
		if s.File == selfFile {
			t.Errorf("the scanner censused itself (%s -> %s) — the exclusion is not "+
				"taking effect", s.File, s.Test)
		}
	}
}
