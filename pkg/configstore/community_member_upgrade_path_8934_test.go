package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestNarrowRejectDoesNotBrickAnExistingConfig8934 measures the UPGRADE PATH
// for the #8934 community-member reject, rather than reasoning about it.
//
// `members "@evil"` is accepted at commit TODAY, so a persisted config may
// already carry one. If the reject also fired on the LOAD path it would turn a
// running-but-broken node into a non-starting one — a different failure from
// the one being fixed, and a worse one to meet in the field.
//
// The split that prevents that is the #1960 no-brick doctrine: `Store.Load`
// (store_persist.go) and the rollback paths compile through
// `compileTreeLenient`, which downgrades a gate violation to a warning, while
// only `CheckText` runs `compileTreeStrict`. This cell pins BOTH halves,
// because the fix is only safe while they stay different.
func TestNarrowRejectDoesNotBrickAnExistingConfig8934(t *testing.T) {
	const bad = `policy-options { community C1 { members "@evil"; } }`

	// HALF ONE — the fix. The operator-driven strict commit refuses it.
	if _, err := CheckText(bad, 0); err == nil {
		t.Error("CheckText ACCEPTS a community member containing `@`. That is " +
			"the #8934 defect: it renders `bgp community-list standard C1 " +
			"permit @evil` into frr.conf, which FRR rejects at load, failing " +
			"the ENTIRE frr-reload.")
	} else if !strings.Contains(err.Error(), "@") {
		t.Errorf("CheckText refused it but not for the character: %v. Asserting "+
			"only that it failed would pass if some unrelated gate started "+
			"rejecting the fixture.", err)
	}

	// HALF TWO — the no-brick property, measured on the FUNCTION Store.Load
	// actually calls, not on a reasoned equivalent.
	tree, perrs := config.NewParser(bad).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs[0])
	}
	s := newTestStore(t)
	cfg, err := s.compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("the TOLERANT path REFUSES an already-persisted `@` member "+
			"(%v). A node that committed one before this gate existed would "+
			"now fail to boot: the reject must stay commit-only (#1960 "+
			"no-brick, #8934).", err)
	}
	if cfg == nil {
		t.Fatal("tolerant compile returned no config; the warning assertion " +
			"below would be vacuous")
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "@") || strings.Contains(strings.ToLower(w), "community") {
			warned = true
			break
		}
	}
	if !warned {
		t.Errorf("the tolerant path accepted the `@` member and said NOTHING "+
			"(%d warnings). Booting through is correct; doing it silently is "+
			"not — the operator gets no signal that a community-list will be "+
			"omitted from frr.conf (#8934).", len(cfg.Warnings))
	}
}
