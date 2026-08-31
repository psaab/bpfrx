package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf/link"
)

// #7547: AttachXDP/DetachXDP are read-modify-write sequences whose atomicity
// rests on a claim in a comment (loader.go: "the link maps are
// lifecycle-serialized ... under the daemon's applySem") that nothing tested.
//
// #6740 made every INDIVIDUAL map access safe. It deliberately did NOT put the
// syscall under the lock — l.Close() must not run under the mutex the 1 Hz
// status path needs — so the sequence is guarded read, UNLOCKED Close, guarded
// delete. That is correct and must stay; a wider m.mu would reintroduce exactly
// what #6740 removed.
//
// What follows is therefore not a fix. It is the two things the claim was
// missing: an executable statement of the hazard, and a census of the callers
// the safety actually depends on.

// countingLink7547 is a link.Link that touches no kernel state and records
// whether two goroutines are ever inside Close() at the same instant.
//
// The embedded interface is nil, so any method other than the two overridden
// here panics rather than silently succeeding — which is what keeps this fake
// from quietly absorbing a call the real sequence makes.
type countingLink7547 struct {
	link.Link
	closes  atomic.Int64
	unpins  atomic.Int64
	inClose atomic.Int64
	overlap atomic.Bool
	release chan struct{}
}

func (f *countingLink7547) Unpin() error { f.unpins.Add(1); return nil }

func (f *countingLink7547) Close() error {
	if f.inClose.Add(1) > 1 {
		f.overlap.Store(true)
	}
	if f.release != nil {
		<-f.release
	}
	f.inClose.Add(-1)
	f.closes.Add(1)
	return nil
}

// TestDetachXDPIsNotSelfSerializing7547 is a DELIBERATE TRIPWIRE pinning
// today's behaviour, in the same spirit as #6790's misclassification cell.
//
// It asserts that DetachXDP does NOT serialize itself: two concurrent calls for
// one ifindex both Unpin() and both Close() the SAME handle, with both
// goroutines inside Close simultaneously. That is not a hypothetical — it is
// what this cell measures.
//
// WHY THAT MATTERS, in the real thing rather than in this fake: cilium/ebpf's
// FD.Close is idempotent SEQUENTIALLY (`if fd.raw < 0 { return nil }`) but
// Disown() writes fd.raw with no lock and no atomic, so two concurrent closes
// are a DATA RACE on fd.raw and issue two unix.Close(N) calls on the same fd
// number. The second either fails EBADF or, if that number has been reused in
// between, closes an unrelated file. So this is a correctness hazard, not a
// noisy one — conditional entirely on whether two callers can be concurrent,
// which is what the census below is about.
//
// IF THIS CELL EVER REDS: someone added per-ifindex exclusion, which is the fix
// the issue contemplates. That is a GOOD change. Invert this cell, and consider
// whether TestEveryAttachDetachCallerIsSerialized7547 can be relaxed — it
// exists only because this property holds.
func TestDetachXDPIsNotSelfSerializing7547(t *testing.T) {
	m := New()
	fl := &countingLink7547{release: make(chan struct{})}
	m.setXDPLink(7547, fl)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = m.DetachXDP(7547) }()
	}
	// Hold both goroutines inside Close so the overlap is observed rather than
	// raced for. A bounded spin, not a sleep: if the second never arrives the
	// release below unblocks the first and the assertions report what happened.
	for i := 0; i < 1_000_000 && fl.inClose.Load() < 2; i++ {
	}
	close(fl.release)
	wg.Wait()

	if got := fl.closes.Load(); got != 2 {
		t.Errorf("Close() called %d times, want 2 — the fixture did not drive two "+
			"concurrent detaches through the sequence, so this cell measured nothing", got)
	}
	// Simultaneity is a bonus observation, not the assertion. The load-bearing
	// fact is that Close() ran TWICE on one handle; whether the two calls
	// overlapped depends on scheduling. Reported rather than asserted — and
	// deliberately NOT a t.Skip, which after the Errorf above would muddle a
	// real failure with an unobserved nicety.
	t.Logf("closes=%d unpins=%d overlapped=%v",
		fl.closes.Load(), fl.unpins.Load(), fl.overlap.Load())
}

// serializingAuthority records, for each call site of AttachXDP/DetachXDP, what
// actually prevents two of them running concurrently. This is the census the
// #7547 claim was missing: the safety is a property of the CALLERS, so it has
// to be asserted where the callers are.
//
// Keyed "<pkg-relative path>:<enclosing func>".
var serializingAuthority = map[string]string{
	// Measured, not assumed — the census below rejected an earlier hand-written
	// version of this map, which is the point of having it.
	//
	// Neither Compile nor CompileUserspaceShim takes m.applyMu; that mutex
	// guards apply.go's generation bookkeeping, not these sequences. So within
	// pkg/dataplane there is NO in-package serialization at all, and the entire
	// safety of both sites is the daemon's applySem around applyConfigLocked —
	// which is exactly the claim #7547 was filed to test.
	"pkg/dataplane/compiler.go:Compile":                                   "daemon applySem (applyConfigLocked holds it; Compile takes no lock of its own)",
	"pkg/dataplane/loader.go:attachUserspaceShimXDP":                      "daemon applySem (reached via CompileUserspaceShim from the same apply path)",
	"pkg/dataplane/userspace/manager_compile.go:syncInterfaceAttachments": "userspace Manager m.mu (applyCompiledSnapshot holds it for the whole call) AND the daemon applySem above it",
}

// TestEveryAttachDetachCallerIsSerialized7547 is the guard the issue asks for.
//
// The atomicity of these sequences is not a property of the functions — the
// tripwire above shows they do not serialize themselves — it is a property of
// their CALLERS. A property of call sites silently stops holding when a new
// call site appears, and nothing in the suite would notice: the new caller
// compiles, passes vet, and passes every existing test.
//
// So this enumerates the call sites and requires each to be registered with the
// authority that serializes it. Adding a caller without adding a row reds, and
// writing the row forces the author to name what makes their call safe.
//
// Deliberately EXACT in both directions: a stale row for a call site that no
// longer exists is worse than no row, because it reads as coverage.
func TestEveryAttachDetachCallerIsSerialized7547(t *testing.T) {
	// BOTH packages that call these, not just this one. An earlier version of
	// this census scanned only pkg/dataplane and would have missed
	// pkg/dataplane/userspace's DetachXDP loop entirely — the very call site
	// #7547 names as the one that runs while the 1 Hz status path does. A
	// census that cannot see a caller is worse than none.
	roots := []string{".", "userspace"}
	found := map[string]bool{}
	fset := token.NewFileSet()
	var scannedFiles int
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("read %s: %v", root, err)
		}
		pkgPath := "pkg/dataplane"
		if root != "." {
			pkgPath = filepath.Join(pkgPath, root)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
			if err != nil {
				t.Fatalf("parse %s/%s: %v", root, name, err)
			}
			scannedFiles++
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					ce, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					se, ok := ce.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if se.Sel.Name != "AttachXDP" && se.Sel.Name != "DetachXDP" {
						return true
					}
					// link.AttachXDP is cilium/ebpf's constructor, not our method.
					if id, ok := se.X.(*ast.Ident); ok && id.Name == "link" {
						return true
					}
					found[pkgPath+"/"+name+":"+fd.Name.Name] = true
					return true
				})
			}
		}
	}
	// Non-vacuity: a scan that parsed nothing, or a matcher that stopped
	// matching, would otherwise report an empty set that trivially agrees with
	// an empty expectation.
	if scannedFiles < 5 {
		t.Fatalf("scanned only %d production files in pkg/dataplane; the census is "+
			"not reading the package it claims to audit", scannedFiles)
	}
	if len(found) == 0 {
		t.Fatal("found ZERO AttachXDP/DetachXDP call sites in pkg/dataplane. Either " +
			"they moved, or the matcher stopped matching — both are a broken census, " +
			"not a clean tree")
	}

	for _, site := range sortedKeys7547(found) {
		if _, ok := serializingAuthority[site]; !ok {
			t.Errorf("%s calls AttachXDP/DetachXDP with no registered serializing "+
				"authority.\n"+
				"  These are read-modify-write sequences that release the lock across\n"+
				"  l.Close() (#6740 — the syscall must not run under the mutex the 1 Hz\n"+
				"  status path needs), so two concurrent calls for one ifindex both\n"+
				"  Close() the SAME handle. cilium/ebpf's FD.Close races on fd.raw and\n"+
				"  double-closes the fd number, which can close an unrelated reused fd.\n"+
				"  Add a row to serializingAuthority naming what prevents concurrency\n"+
				"  at THIS call site — or add per-ifindex exclusion (#7547).", site)
		}
	}
	for _, site := range sortedKeys7547(mapOfKeys7547(serializingAuthority)) {
		// Rows for non-call-sites (interface declarations, the method itself)
		// are documentation and are exempt from the reverse check.
		if !found[site] {
			t.Errorf("serializingAuthority registers %s, but no such call site exists "+
				"in pkg/dataplane any more. A stale row reads as coverage; remove it "+
				"or correct the location.", site)
		}
	}
}

func sortedKeys7547(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mapOfKeys7547(m map[string]string) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
