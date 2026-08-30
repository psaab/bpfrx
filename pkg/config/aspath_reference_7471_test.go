package config

import (
	"strings"
	"testing"
)

// aspath_reference_7471_test.go — #7471.
//
// `from as-path <name>` naming an as-path that was never defined committed
// clean: CompileConfig nil, no warning, SchemaValidate nil.
//
// xpf renders `match as-path NOPE` and renders no `bgp as-path access-list
// NOPE`. FRR ACCEPTS that — `route_match_aspath_compile` stores the string and
// `as_list_lookup` returns NULL at evaluation, yielding RMAP_NOMATCH — so the
// term never matches and nothing complains at any layer.
//
// On `then reject` that is FAIL-OPEN: the routes the operator meant to block
// are accepted by the next term or the policy default. On `then accept` it
// silently blackholes routes meant to be admitted.
//
// This is the OPPOSITE consequence from the community gate, whose message says
// the reference "would fail frr-reload". Here frr-reload succeeds. Copying that
// message would send an operator looking for a load error that never happens,
// which is why the two gates are separate rather than one walk over both.

func compileASPath7471(t *testing.T, lines []string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	return CompileConfig(tree)
}

// THE DEFECT, on the shape that is fail-open.
func TestDanglingFromASPathIsRejected7471(t *testing.T) {
	_, err := compileASPath7471(t, []string{
		"set policy-options policy-statement P1 term t1 from as-path NOPE",
		"set policy-options policy-statement P1 term t1 then reject",
	})
	if err == nil {
		t.Fatal("`from as-path NOPE` with no definition committed clean. FRR accepts the " +
			"rendered `match as-path` and resolves it to NULL, so the term never matches " +
			"and a `then reject` becomes fail-open — the routes the operator meant to " +
			"block are accepted (#7471)")
	}
	for _, want := range []string{"P1", "t1", "NOPE", "NEVER MATCHES", "fail-open"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the rejection does not mention %q, so it does not tell the operator "+
				"which reference is wrong or what it costs them: %v", want, err)
		}
	}
	// It must NOT claim frr-reload fails. That is the community gate's
	// consequence and is false here.
	if strings.Contains(err.Error(), "fail frr-reload") {
		t.Errorf("the message claims frr-reload would fail. It does not — FRR accepts a "+
			"`match as-path` naming an undefined list. Copying the community gate's "+
			"wording sends the operator looking for a load error that never happens: %v", err)
	}
}

// TIGHTENING CELL: a DEFINED as-path must still commit clean.
//
// Without this, a gate that rejected every `from as-path` would satisfy the
// cell above and make the feature unusable.
func TestDefinedFromASPathStillCommits7471(t *testing.T) {
	_, err := compileASPath7471(t, []string{
		`set policy-options as-path AP1 "^65000 "`,
		"set policy-options policy-statement P1 term t1 from as-path AP1",
		"set policy-options policy-statement P1 term t1 then reject",
	})
	if err != nil {
		t.Fatalf("a term referencing a DEFINED as-path must commit clean: %v", err)
	}
}

// EVERY entry must be walked, not just the first. `from as-path` is
// `multi: true`, so a term can carry several — and the dangling one is exactly
// as likely to be second as first.
func TestEveryFromASPathEntryIsWalked7471(t *testing.T) {
	_, err := compileASPath7471(t, []string{
		`set policy-options as-path AP1 "^65000 "`,
		"set policy-options policy-statement P1 term t1 from as-path AP1",
		"set policy-options policy-statement P1 term t1 from as-path SECOND",
		"set policy-options policy-statement P1 term t1 then reject",
	})
	if err == nil {
		t.Fatal("a term whose FIRST as-path is defined and whose SECOND is not committed " +
			"clean — the walk stops at the first entry (#7471)")
	}
	if !strings.Contains(err.Error(), "SECOND") {
		t.Errorf("the rejection names the wrong entry: %v", err)
	}
}

// ...and every TERM, not just the first.
func TestEveryTermIsWalked7471(t *testing.T) {
	_, err := compileASPath7471(t, []string{
		`set policy-options as-path AP1 "^65000 "`,
		"set policy-options policy-statement P1 term t1 from as-path AP1",
		"set policy-options policy-statement P1 term t1 then accept",
		"set policy-options policy-statement P1 term t2 from as-path LATER",
		"set policy-options policy-statement P1 term t2 then reject",
	})
	if err == nil {
		t.Fatal("a dangling as-path in the SECOND term committed clean (#7471)")
	}
	if !strings.Contains(err.Error(), "LATER") || !strings.Contains(err.Error(), "t2") {
		t.Errorf("the rejection does not name the second term's reference: %v", err)
	}
}

// The tolerant ingress must WARN, not brick: an already-persisted or
// peer-synced config carrying the typo enforced nothing before this gate and
// enforces nothing now (#1960).
func TestDanglingFromASPathIsLenientOnTheTolerantPath7471(t *testing.T) {
	tree := &ConfigTree{}
	for _, l := range []string{
		"set policy-options policy-statement P1 term t1 from as-path NOPE",
		"set policy-options policy-statement P1 term t1 then reject",
	} {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand: %v", err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant path must not brick on a config that was already inert: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "policy as-path reference") {
			found = true
		}
	}
	if !found {
		t.Errorf("the tolerant path accepted the dangling reference and said NOTHING. "+
			"Downgrading to a warning is the no-brick contract; downgrading to silence "+
			"is the defect. warnings=%v", cfg.Warnings)
	}
}
