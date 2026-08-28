package config

// system_packed_and_duplicate_6956_6957_test.go — #6956 and #6957.
//
// TWO DEFECTS, TWO ROOTS, fixed in one change because they sit in one function.
// The shapes are what separate them, and each fixture asserts its own shape
// first so a future parser change cannot silently turn one into the other:
//
//	#6956  system host-name fw1;   Keys=[system host-name fw1]  children=0
//	       -> the value is on the ANCESTOR's own Keys; the child walk never runs.
//
//	#6957  system { login {…} login {…} }   Keys=[system]  children=2
//	       -> both children ARE walked; the second reallocation discards the first.
//
// A packed tail never read is not the same defect as two children read and then
// overwritten, and a shared diff must not imply a shared cause.

import (
	"strings"
	"testing"
)

func compile6956(t *testing.T, cfg string) *Config {
	t.Helper()
	tree, perr := NewParser(cfg).Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	out, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile: %v", cerr)
	}
	return out
}

func systemNode6956(t *testing.T, cfg string) *Node {
	t.Helper()
	tree, perr := NewParser(cfg).Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	for _, top := range tree.Children {
		if len(top.Keys) > 0 && top.Keys[0] == "system" {
			return top
		}
	}
	t.Fatal("no `system` node")
	return nil
}

// TestPackedSystemHostNameCompiles6956 is the headline cell for #6956.
//
// An EMPTY host name is the failure default of this path, so a test expecting
// "" would constrain nothing. Assert the populated value, and assert the two
// spellings agree.
func TestPackedSystemHostNameCompiles6956(t *testing.T) {
	// Premise: the two spellings really do produce different shapes. If the
	// parser ever normalises one into the other, the packed cell below becomes
	// a duplicate of its control and this says so rather than passing quietly.
	packed := systemNode6956(t, "system host-name fw1;")
	if len(packed.Keys) != 3 || len(packed.Children) != 0 {
		t.Fatalf("packed shape = Keys%v children=%d, want Keys[system host-name fw1] "+
			"children=0 — the whole defect is that a child walk sees NOTHING here",
			packed.Keys, len(packed.Children))
	}
	nested := systemNode6956(t, "system { host-name fw1; }")
	if len(nested.Keys) != 1 || len(nested.Children) == 0 {
		t.Fatalf("nested shape = Keys%v children=%d, want Keys[system] with the value "+
			"as a CHILD", nested.Keys, len(nested.Children))
	}

	for _, tc := range []struct{ name, cfg string }{
		{"packed", "system host-name fw1;"},
		{"nested", "system { host-name fw1; }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := compile6956(t, tc.cfg).System.HostName; got != "fw1" {
				t.Fatalf("HostName = %q, want \"fw1\". An empty host name commits "+
					"clean and silently: the management TLS certificate subject, "+
					"syslog's origin field and the CLI prompt all key on it, and "+
					"`display set` output plus vSRX migration paths produce exactly "+
					"this spelling (#6956)", got)
			}
		})
	}
}

// TestPackedSystemHostNameWithABody6956 is the case the two-shape split could
// hide: a packed tail AND a nested block on the same node. The packed value
// must survive the child walk that the block triggers.
func TestPackedSystemHostNameWithABody6956(t *testing.T) {
	cfg := compile6956(t, "system host-name fw1 {\n  login { user alice { class read-only; } }\n}")
	if cfg.System.HostName != "fw1" {
		t.Errorf("HostName = %q, want \"fw1\" — a packed tail must not be dropped "+
			"just because the node also has children (#6956)", cfg.System.HostName)
	}
	if cfg.System.Login == nil || len(cfg.System.Login.Users) != 1 {
		t.Errorf("the nested block must still compile alongside the packed tail")
	}
}

// TestTwoSiblingLoginBlocksKeepBothUsers6957 is the headline cell for #6957.
//
// The two blocks carry DIFFERENT users deliberately. With the same user in
// both, the count is 1 either way and the cell passes against unfixed code —
// the defect is invisible unless the fixture can distinguish "merged" from
// "last one won".
func TestTwoSiblingLoginBlocksKeepBothUsers6957(t *testing.T) {
	// Premise: the parser really does produce two sibling `login` children.
	sys := systemNode6956(t, "system {\n  login { user alice { class read-only; } }\n  login { user bob { class operator; } }\n}")
	logins := 0
	for _, ch := range sys.Children {
		if ch.Name() == "login" {
			logins++
		}
	}
	if logins != 2 {
		t.Fatalf("fixture produced %d `login` children, want 2 — without two "+
			"siblings there is no overwrite to detect", logins)
	}

	cfg := compile6956(t, "system {\n  login { user alice { class read-only; } }\n  login { user bob { class operator; } }\n}")
	if cfg.System.Login == nil {
		t.Fatal("System.Login is nil — no users compiled at all")
	}
	var names []string
	for _, u := range cfg.System.Login.Users {
		names = append(names, u.Name)
	}
	// Assert BOTH names, not the count. A count of 2 is also satisfied by the
	// same user twice, and by the wrong user surviving alongside a duplicate.
	joined := strings.Join(names, ",")
	for _, want := range []string{"alice", "bob"} {
		if !strings.Contains(joined, want) {
			t.Errorf("user %q is missing (got %v). The FIRST block's users were "+
				"discarded, and `reconcileAbsentLoginUsers` treats the compiled set "+
				"as authoritative — so they are not merely absent from the running "+
				"config, they are deprovisioned from the box by a commit that "+
				"reported success (#6957)", want, names)
		}
	}
}

// TestTwoSiblingLoginBlocksMergeClasses6957 covers the other accumulating field
// in the same arm. Users and classes are appended by different loops, so a fix
// that repaired only one would leave the other reducing to the last block.
func TestTwoSiblingLoginBlocksMergeClasses6957(t *testing.T) {
	cfg := compile6956(t, "system {\n"+
		"  login { class ops-a { permissions view; } }\n"+
		"  login { class ops-b { permissions view; } }\n"+
		"}")
	if cfg.System.Login == nil {
		t.Fatal("System.Login is nil")
	}
	var names []string
	for _, c := range cfg.System.Login.Classes {
		names = append(names, c.Name)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"ops-a", "ops-b"} {
		if !strings.Contains(joined, want) {
			t.Errorf("class %q is missing (got %v) — classes accumulate through a "+
				"different loop than users, so the allocation fix has to cover "+
				"both (#6957)", want, names)
		}
	}
}

// TestSingleLoginBlockUnchanged6957 is the over-reach control.
//
// Allocating once instead of per-block must not make a LATER block accumulate
// onto a stale struct across separate compiles, and the ordinary single-block
// config must be bit-identical to before. Without this, "allocate once" and
// "never allocate" are not distinguished.
func TestSingleLoginBlockUnchanged6957(t *testing.T) {
	cfg := compile6956(t, "system {\n  login {\n    user alice { class read-only; }\n    user bob { class operator; }\n  }\n}")
	if cfg.System.Login == nil || len(cfg.System.Login.Users) != 2 {
		t.Fatalf("the ordinary single-block spelling must still compile both users")
	}
	// A SECOND, independent compile must not inherit the first's users.
	again := compile6956(t, "system {\n  login { user carol { class operator; } }\n}")
	if n := len(again.System.Login.Users); n != 1 {
		t.Errorf("a fresh compile has %d users, want 1 — state leaked across "+
			"compiles, which allocating once must not introduce", n)
	}
}
