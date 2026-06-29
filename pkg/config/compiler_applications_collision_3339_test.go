package config

import (
	"strings"
	"testing"
)

// #3339 (Codex review 080 M07/M08): the application compiler silently overwrote
// application / application-set definitions on a name collision (last-write-wins
// map writes) instead of rejecting at commit, letting policy expansion and the
// AppID catalog resolve a name to different definitions. These tests pin the
// strict reject at commit (CompileConfig) and the lenient downgrade-to-warning
// on the tolerant load / peer-sync path (CompileConfigLenient).

// buildTreeFromSet (shared with ipsec_proposal_ref_test.go) builds a candidate
// ConfigTree from flat `set` commands the way the configstore does
// (ParseSetCommand + SetPath), NOT NewParser — the parser merges newlines and
// would collapse separate set lines into one node.

// M07: an application and an application-set sharing a name. The set-command
// config tree keeps these as distinct stanzas (different keywords), so both
// reach the compiler and the application-set silently overwrites the
// application's map entry.
func TestApplicationVsApplicationSetNameCollisionRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application web protocol tcp",
		"set applications application web destination-port 80",
		"set applications application-set web application junos-https",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of application/application-set name collision, got nil")
	}
	if !strings.Contains(err.Error(), "web") ||
		!strings.Contains(err.Error(), "BOTH an application and an application-set") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// M07 variant: a MULTI-TERM application <X> mints an implicit application-set
// <X>; an explicit `application-set <X>` then silently replaces it. This is the
// exact implicit-set-overwrite case from the issue.
func TestImplicitSetOverwrittenByExplicitSetRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application multi term t1 protocol tcp destination-port 80",
		"set applications application multi term t2 protocol udp destination-port 53",
		"set applications application-set multi application junos-http",
	})

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of explicit set overwriting implicit multi-term set, got nil")
	}
	if !strings.Contains(err.Error(), "multi") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Duplicate application definition (same name twice). Survives as distinct AST
// siblings on a hierarchical representation; built here directly so the gate is
// exercised independently of how the tree was produced.
func TestDuplicateApplicationDefinitionRejected(t *testing.T) {
	tree := &ConfigTree{Children: []*Node{
		{Keys: []string{"applications"}, Children: []*Node{
			{Keys: []string{"application", "dup"}, Children: []*Node{
				{Keys: []string{"protocol", "tcp"}, IsLeaf: true},
			}},
			{Keys: []string{"application", "dup"}, Children: []*Node{
				{Keys: []string{"protocol", "udp"}, IsLeaf: true},
			}},
		}},
	}}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of duplicate application definition, got nil")
	}
	if !strings.Contains(err.Error(), "application \"dup\"") ||
		!strings.Contains(err.Error(), "defined 2 times") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Duplicate application-set definition (same name twice).
func TestDuplicateApplicationSetDefinitionRejected(t *testing.T) {
	tree := &ConfigTree{Children: []*Node{
		{Keys: []string{"applications"}, Children: []*Node{
			{Keys: []string{"application", "a1"}, Children: []*Node{
				{Keys: []string{"protocol", "tcp"}, IsLeaf: true},
			}},
			{Keys: []string{"application-set", "dupset"}, Children: []*Node{
				{Keys: []string{"application", "a1"}, IsLeaf: true},
			}},
			{Keys: []string{"application-set", "dupset"}, Children: []*Node{
				{Keys: []string{"application", "junos-http"}, IsLeaf: true},
			}},
		}},
	}}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of duplicate application-set definition, got nil")
	}
	if !strings.Contains(err.Error(), "application-set \"dupset\"") ||
		!strings.Contains(err.Error(), "defined 2 times") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// M08: two terms generating the same per-term application name. Built as
// distinct term siblings (the hierarchical shape) so both reach
// parseApplicationTerms and the later overwrites the earlier.
func TestDuplicateTermGeneratedNameRejected(t *testing.T) {
	tree := &ConfigTree{Children: []*Node{
		{Keys: []string{"applications"}, Children: []*Node{
			{Keys: []string{"application", "app"}, Children: []*Node{
				{Keys: []string{"term", "dup", "protocol", "tcp", "destination-port", "80"}, IsLeaf: true},
				{Keys: []string{"term", "dup", "protocol", "udp", "destination-port", "53"}, IsLeaf: true},
			}},
		}},
	}}

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of duplicate term generated name, got nil")
	}
	if !strings.Contains(err.Error(), "app-dup") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Valid distinct names commit cleanly: an application, a same-config
// application-set with a DIFFERENT name, a multi-term application whose implicit
// set name is not reused, and a user application shadowing a predefined junos-*
// application (the legitimate shadow case must NOT be rejected).
func TestDistinctApplicationNamesCommit(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application web protocol tcp destination-port 80",
		"set applications application-set webset application web",
		"set applications application-set webset application junos-https",
		"set applications application multi term t1 protocol tcp destination-port 80",
		"set applications application multi term t2 protocol udp destination-port 53",
		// A user application shadowing a predefined name is legitimate, not a
		// collision: there is no application-set with this name.
		"set applications application junos-ssh protocol tcp destination-port 22",
	})

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: unexpected error on distinct names: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3339") {
			t.Fatalf("unexpected #3339 collision warning on a valid config: %q", w)
		}
	}
}

// parseHier (shared with vrrp_track_test.go) parses a hierarchical (braced)
// config string. A hierarchical parse can emit MULTIPLE top-level sibling
// `applications {}` nodes; the compiler compiles every one, so the collision
// gate must aggregate across all of them.

// Collision SPLIT across two top-level `applications {}` blocks: an application
// in the first block, an application-set of the same name in the second. The
// compiler compiles both blocks, so this must be rejected — a walker that
// stopped at the first `applications` node missed it.
func TestApplicationVsApplicationSetCollisionSplitAcrossBlocks(t *testing.T) {
	tree := parseHier(t, `
applications {
    application web {
        protocol tcp;
        destination-port 80;
    }
}
applications {
    application-set web {
        application junos-https;
    }
}
`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of app/app-set collision split across applications blocks, got nil")
	}
	if !strings.Contains(err.Error(), "web") ||
		!strings.Contains(err.Error(), "BOTH an application and an application-set") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Duplicate application definition split across two `applications {}` blocks.
func TestDuplicateApplicationDefinitionSplitAcrossBlocks(t *testing.T) {
	tree := parseHier(t, `
applications {
    application dup {
        protocol tcp;
        destination-port 80;
    }
}
applications {
    application dup {
        protocol udp;
        destination-port 53;
    }
}
`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of duplicate application split across blocks, got nil")
	}
	if !strings.Contains(err.Error(), "application \"dup\"") ||
		!strings.Contains(err.Error(), "defined 2 times") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Duplicate application-set definition split across two `applications {}` blocks.
func TestDuplicateApplicationSetDefinitionSplitAcrossBlocks(t *testing.T) {
	tree := parseHier(t, `
applications {
    application a1 {
        protocol tcp;
        destination-port 80;
    }
    application-set dupset {
        application a1;
    }
}
applications {
    application-set dupset {
        application junos-http;
    }
}
`)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of duplicate application-set split across blocks, got nil")
	}
	if !strings.Contains(err.Error(), "application-set \"dupset\"") ||
		!strings.Contains(err.Error(), "defined 2 times") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Two distinct `applications {}` blocks with non-colliding names commit cleanly
// — the aggregation must not over-reject legitimately split definitions.
func TestDistinctApplicationNamesSplitAcrossBlocksCommit(t *testing.T) {
	tree := parseHier(t, `
applications {
    application web {
        protocol tcp;
        destination-port 80;
    }
}
applications {
    application ssh {
        protocol tcp;
        destination-port 22;
    }
    application-set webset {
        application web;
        application ssh;
    }
}
`)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: unexpected error on distinct names split across blocks: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#3339") {
			t.Fatalf("unexpected #3339 collision warning on a valid split config: %q", w)
		}
	}
}

// Lenient path (load / peer-sync) must WARN, not brick: an already-persisted
// colliding config still compiles, with the collision surfaced as a warning.
func TestApplicationNameCollisionLenientWarns(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application web protocol tcp destination-port 80",
		"set applications application-set web application junos-https",
	})

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: collision must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "web") && strings.Contains(w, "#3339") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #3339 collision warning on the lenient path, got: %v", cfg.Warnings)
	}
}
