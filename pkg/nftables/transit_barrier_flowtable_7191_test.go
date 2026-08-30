package nftables

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #7191: plan §6 calls for a flowtable disable as the third leg of the barrier.
// No code implements it, deliberately — xpf creates no flowtable, so there is
// nothing to flush, and machinery to disable something that never exists would
// be inert code that reads as coverage.
//
// This pins the assumption so that comment cannot rot into a false claim. If
// anyone adds a real flowtable, this reds and the barrier owes a third leg.
//
// Comments are STRIPPED before scanning. The transit_barrier.go doc comment
// discusses flowtables at length, so an unstripped scan would match its own
// prose and pass forever — the exact way a source-scanning guard is satisfied
// by the text that documents it.
func TestNoFlowtableIsEverCreated7191(t *testing.T) {
	root := ".."
	var hits []string
	scanned := 0

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && (info.Name() == "testdata" || info.Name() == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		scanned++
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j]
			}
			low := strings.ToLower(code)
			// The nftables Go API spellings for creating one.
			if strings.Contains(low, "flowtable") {
				hits = append(hits, path+":"+itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// Anti-vacuity: if the walk scanned nothing, the assertion below is
	// meaningless and would pass on an empty tree.
	if scanned < 50 {
		t.Fatalf("scanned only %d production Go files — the walk is broken, so the "+
			"no-flowtable assertion below proves nothing", scanned)
	}
	if len(hits) > 0 {
		t.Errorf("a flowtable now exists in production code, so the #7191 transit "+
			"barrier owes its third leg (an offloaded flow can forward independently "+
			"of both ip_forward and the forward-hook drop):\n  %s",
			strings.Join(hits, "\n  "))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
