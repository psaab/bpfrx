package config

import (
	"strconv"
	"strings"
	"testing"
)

// #6766 (opus-review-001 R23): a single-valued `icmp-type` / `icmp-code` leaf
// repeated with a CONFLICTING value inside one inline application `term` was
// last-writer-wins with no commit error. parseApplicationTerms tracked
// conflicting repeats for destination-port / source-port / timeout / alg (the
// #3366 framework) but declared no set flags for the ICMP leaves, so each
// repeat silently overwrote the pointer; the term subtree is opaque to
// SchemaValidate (`term` is args:1, children:nil), and the strict structure
// gate only sees Application.DuplicateTermLeaves — which the inline parser
// never populated for ICMP. A referenced DENY application therefore enforced
// only the LAST type/code: a deny authored `icmp-type 8` then `icmp-type 3`
// denied only type 3, and echo traffic fell through to a later permit or the
// default permit (a silent narrowing of the deny match). The direct-body path
// already tracks ICMP conflicts (#5574); this is the inline-term analogue.
//
// Shapes: packed flat-set (flatTreeFromSets — one `set` line carrying the
// repeat), hierarchical (hierTree — sibling repeats), and apply-groups (a
// group-authored packed term merged into the stanza). All three reassemble to
// the same parseApplicationTerms token stream via applicationTermKeys.

// Core fail-on-revert, packed flat-set shape: a conflicting icmp-type /
// icmp-code repeat inside one inline term must be REJECTED at commit, with the
// error naming the leaf. Revert the duplicate tracking and the second value
// silently overwrites the first (last-writer-wins), CompileConfig succeeds, and
// this assertion goes RED.
func TestApplicationTermICMPDup_FlatSet_Rejected(t *testing.T) {
	cases := []struct {
		name string
		term string
		leaf string
	}{
		{"icmp-type", "term t1 protocol icmp icmp-type 8 icmp-type 0", "icmp-type"},
		{"icmp-code", "term t1 protocol icmp icmp-type 3 icmp-code 1 icmp-code 2", "icmp-code"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, unrefAppOnly("dup", c.term)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to REJECT conflicting duplicate %q inside a term", c.leaf)
			}
			if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), c.leaf) {
				t.Fatalf("error should name the duplicate leaf %q, got: %v", c.leaf, err)
			}
		})
	}
}

// Hierarchical shape: the same conflict authored as sibling statements inside a
// brace-block term must reject too (the compiler reassembles both AST shapes
// through applicationTermKeys).
func TestApplicationTermICMPDup_Hierarchical_Rejected(t *testing.T) {
	cases := []struct {
		name string
		body string
		leaf string
	}{
		{"icmp-type", "term t1 { protocol icmp; icmp-type 8; icmp-type 0; }", "icmp-type"},
		{"icmp-code", "term t1 { protocol icmp; icmp-type 3; icmp-code 1; icmp-code 2; }", "icmp-code"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := hierTree(t, "applications {\n    application dup {\n        "+c.body+"\n    }\n}\n")
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to REJECT conflicting duplicate %q inside a hierarchical term", c.leaf)
			}
			if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), c.leaf) {
				t.Fatalf("error should name the duplicate leaf %q, got: %v", c.leaf, err)
			}
		})
	}
}

// apply-groups shape: a group-authored term carrying the conflicting repeat is
// cloned into the applications stanza by ExpandGroups; the merged config must
// reject exactly like a directly-authored one (apply-groups is one of the load
// paths that produces duplicate term leaves in practice).
func TestApplicationTermICMPDup_ApplyGroups_Rejected(t *testing.T) {
	cases := []struct {
		name string
		term string
		leaf string
	}{
		{"icmp-type", "term t1 protocol icmp icmp-type 8 icmp-type 0", "icmp-type"},
		{"icmp-code", "term t1 protocol icmp icmp-type 3 icmp-code 1 icmp-code 2", "icmp-code"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t,
				"set groups g applications application dup "+c.term,
				"set apply-groups g")
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to REJECT an apply-groups term with conflicting %q", c.leaf)
			}
			if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), c.leaf) {
				t.Fatalf("error should name the duplicate leaf %q, got: %v", c.leaf, err)
			}
		})
	}
}

// Fail-on-revert (security-adjacent): a REFERENCED deny application whose
// inline term carries conflicting `icmp-type` values must be rejected at
// commit. Revert the fix and the term silently keeps only the LAST value
// (type 3), so the deny no longer covers echo (type 8) — that traffic falls
// through to the default permit. Proven two ways: (1) strict CompileConfig
// rejects; (2) on the lenient path (which still compiles, downgrading the
// reject to a warning) the compiled term demonstrably enforces ONLY the last
// type — the silent narrowing the strict gate exists to prevent.
func TestApplicationTermICMPDup_ReferencedDeny_StrictRejects_LenientNarrows(t *testing.T) {
	src := `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy blockit {
                match {
                    source-address any;
                    destination-address any;
                    application badapp;
                }
                then {
                    deny;
                }
            }
        }
        default-policy {
            permit-all;
        }
    }
}
applications {
    application badapp {
        term t1 {
            protocol icmp;
            icmp-type 8;
            icmp-type 3;
        }
    }
}
`
	tree := hierTree(t, src)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT a referenced deny app with a conflicting inline icmp-type")
	} else if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), "icmp-type") {
		t.Fatalf("error should flag the conflicting icmp-type duplicate, got: %v", err)
	}

	// Characterize the underlying keep-last narrowing the gate protects against:
	// the lenient path still compiles (no-brick), and the compiled term carries
	// ONLY the last value — echo (type 8) is no longer denied, so it falls
	// through to the default permit.
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient path must NOT brick on a conflicting inline icmp-type: %v", lerr)
	}
	app := cfg.Applications.Applications["badapp-t1"]
	if app == nil {
		t.Fatalf("term application badapp-t1 missing on lenient path; have %v", appNames(cfg))
	}
	if app.ICMPType == nil || *app.ICMPType != 3 {
		got := "nil"
		if app.ICMPType != nil {
			got = strconv.Itoa(int(*app.ICMPType))
		}
		t.Fatalf("keep-last narrowing characterization: want ICMPType=3 (the silently-retained "+
			"last value), got %s", got)
	}
}

// Guard against over-rejection of the value-aware idempotent path: an ICMP leaf
// repeated with the SAME value is harmless (no value is silently lost) and must
// COMMIT — only a CONFLICTING (different-value) repeat is rejected. Flip the
// duplicate detection to value-blind (reject any repeat regardless of value)
// and this assertion goes RED.
func TestApplicationTermICMPDup_Idempotent_Accepted(t *testing.T) {
	cases := []struct {
		name     string
		term     string
		wantType uint8
		wantCode *uint8
	}{
		{"same-icmp-type", "term t1 protocol icmp icmp-type 8 icmp-type 8", 8, nil},
		{"same-icmp-code", "term t1 protocol icmp icmp-type 3 icmp-code 1 icmp-code 1", 3, u8p(1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, unrefAppOnly("idem", c.term)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("an idempotent same-value repeat must COMMIT (only a "+
					"conflicting different-value repeat is rejected), got: %v", err)
			}
			app := cfg.Applications.Applications["idem-t1"]
			if app == nil {
				t.Fatalf("term application idem-t1 missing; have %v", appNames(cfg))
			}
			if app.ICMPType == nil || *app.ICMPType != c.wantType {
				t.Fatalf("the single icmp-type value must survive, want %d got %v", c.wantType, app.ICMPType)
			}
			if c.wantCode == nil {
				if app.ICMPCode != nil {
					t.Fatalf("no icmp-code authored, want nil got %d", *app.ICMPCode)
				}
			} else if app.ICMPCode == nil || *app.ICMPCode != *c.wantCode {
				t.Fatalf("the single icmp-code value must survive, want %d got %v", *c.wantCode, app.ICMPCode)
			}
		})
	}
}

// The tolerant load / peer-sync path (CompileConfigLenient) must NOT brick on a
// conflicting inline-term ICMP repeat an older binary persisted — it downgrades
// the reject to a warning so the daemon still boots (#1960 no-brick). Revert
// the lenient downgrade and this goes RED.
func TestApplicationTermICMPDup_Lenient_DowngradesToWarning(t *testing.T) {
	tree := flatTreeFromSets(t, unrefAppOnly("dup",
		"term t1 protocol icmp icmp-type 8 icmp-type 0")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must NOT fail on a conflicting inline icmp-type (no-brick): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application structure") && strings.Contains(w, "duplicate") &&
			strings.Contains(w, "icmp-type") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path must record a downgrade warning naming icmp-type; warnings: %v", cfg.Warnings)
	}
}
