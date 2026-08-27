package config

import (
	"strings"
	"testing"
)

// #5574: a DIRECT (scalar) custom `applications application <name>` body assigns
// each scalar leaf straight into a single typed field. Before this fix a
// repeated CONFLICTING direct leaf (protocol tcp; protocol udp;
// destination-port 22; destination-port 53; ...) was last-writer-wins: only the
// FINAL value was enforced, with no commit error, so a deny referencing the app
// covered FEWER protocol/port combinations than authored and could fall through
// to a permit / default-permit (a fail-open under-match). This is the
// direct-body analogue of the #3366 inline-`term` duplicate detection.
//
// IMPORTANT — why these tests parse HIERARCHICALLY (hierTree), not flat-set.
// The direct scalar leaves (protocol / destination-port / ...) are declared
// `args:1, children:nil, non-multi` in setSchema, so `tree.SetPath` REPLACES a
// single-value leaf (last-wins) at the AST level: two flat `set` lines collapse
// to ONE node before the compiler runs, so flat-set cannot reproduce the drop.
// The bug is reachable only when the AST carries duplicate SIBLING leaves — a
// hierarchical config file / paste, an apply-groups merge, or a peer-synced
// serialized config. The hierarchical parser preserves both siblings, which is
// exactly what those load paths produce, so hierTree is the correct (and only)
// shape that exercises this compiler path. This deliberately deviates from the
// "flat-set only" CLAUDE.md testing gotcha, which governs flat-set token
// grouping — not a duplicate-sibling drop that flat-set structurally cannot
// carry.

// Core fail-on-revert: each conflicting direct scalar leaf must be REJECTED at
// commit, with the error naming the offending leaf. Revert the direct-scalar
// conflict tracking and the repeat silently keeps only the LAST value,
// CompileConfig succeeds, and this assertion goes RED.
func TestApplicationDirectConflict_EachScalarLeaf_Rejected(t *testing.T) {
	cases := []struct {
		name string
		body string
		leaf string
	}{
		{"protocol", "protocol tcp; protocol udp; destination-port 22;", "protocol"},
		{"destination-port", "protocol tcp; destination-port 22; destination-port 53;", "destination-port"},
		{"source-port", "protocol tcp; source-port 1024; source-port 2048;", "source-port"},
		{"inactivity-timeout", "protocol tcp; inactivity-timeout 300; inactivity-timeout 600;", "inactivity-timeout"},
		{"timeout", "protocol tcp; timeout 300; timeout 600;", "timeout"},
		{"icmp-type", "protocol icmp; icmp-type 8; icmp-type 0;", "icmp-type"},
		{"icmp-code", "protocol icmp; icmp-type 3; icmp-code 1; icmp-code 2;", "icmp-code"},
		{"alg", "protocol tcp; destination-port 21; alg ftp; alg dns;", "alg"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := hierTree(t, "applications {\n    application conflict {\n        "+c.body+"\n    }\n}\n")
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to REJECT conflicting direct %q", c.leaf)
			}
			if !strings.Contains(err.Error(), "conflicting duplicate") || !strings.Contains(err.Error(), `"`+c.leaf+`"`) {
				t.Fatalf("error should name the conflicting leaf %q, got: %v", c.leaf, err)
			}
		})
	}
}

// Fail-on-revert (security-adjacent): a REFERENCED deny application with
// conflicting direct scalars must be rejected at commit. Revert the fix and the
// app silently keeps only the LAST value (protocol=udp, destination-port=53), so
// the deny no longer covers tcp/22 — it would fall through to the default
// permit. Proven two ways: (1) strict CompileConfig rejects; (2) on the lenient
// path (which still compiles, downgrading the reject to a warning) the compiled
// app demonstrably enforces ONLY the last value — the silent keep-last drop.
func TestApplicationDirectConflict_Referenced_DenyUnderMatch(t *testing.T) {
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
        protocol tcp;
        protocol udp;
        destination-port 22;
        destination-port 53;
    }
}
`
	tree := hierTree(t, src)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT a referenced deny app with conflicting direct scalars")
	} else if !strings.Contains(err.Error(), "conflicting duplicate") {
		t.Fatalf("error should flag the conflicting duplicate, got: %v", err)
	}

	// Characterize the underlying keep-last drop the gate protects against: the
	// lenient path still compiles (no-brick), and the compiled app carries ONLY
	// the last value — the tcp/22 combination the operator authored is gone, so a
	// deny keyed on this app would under-match. This assertion is what the strict
	// gate exists to prevent from ever committing.
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient path must NOT brick on a conflicting direct app: %v", lerr)
	}
	app := cfg.Applications.Applications["badapp"]
	if app == nil {
		t.Fatalf("application badapp missing on lenient path; have %v", appNames(cfg))
	}
	if app.Protocol != "udp" || app.DestinationPort != "53" {
		t.Fatalf("keep-last drop characterization: want protocol=udp destination-port=53 "+
			"(the silently-retained last values), got protocol=%q destination-port=%q",
			app.Protocol, app.DestinationPort)
	}
}

// Flat-set reachability: the ONE direct-scalar leaf that also reproduces via
// flat `set` commands is `protocol`, when leaves are COMBINED on one line
// (`set applications application foo protocol tcp destination-port 80`). The
// combined form places `protocol` mid-path, so SetPath emits a distinct
// `protocol tcp` / `protocol udp` sibling container per line instead of the
// terminal-leaf REPLACE it applies to a standalone `set ... protocol udp`. This
// is the common vSRX flat-set authoring style, so the conflict must be caught
// here too. (The other scalars are collapsed by SetPath's terminal-leaf replace
// or nested under the protocol container on the flat path, so they are covered
// by the hierarchical cases above — the shape config load / paste / peer-sync
// produces.)
func TestApplicationDirectConflict_FlatSetProtocol_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application foo protocol tcp destination-port 80",
		"set applications application foo protocol udp destination-port 80")
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to REJECT a flat-set combined-leaf protocol conflict")
	}
	if !strings.Contains(err.Error(), "conflicting duplicate") || !strings.Contains(err.Error(), `"protocol"`) {
		t.Fatalf("error should name the conflicting protocol leaf, got: %v", err)
	}
}

// Scope: an UNREFERENCED conflicting direct app must ALSO reject — the structure
// gate is a definition-time grammar error (all user apps), like #3366 mixed and
// #3352 term-leaf, not the reference-scoped semantic spec gate.
func TestApplicationDirectConflict_Unreferenced_Rejected(t *testing.T) {
	tree := hierTree(t, `
applications {
    application lonely {
        protocol tcp;
        protocol udp;
        destination-port 22;
    }
}
`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT an unreferenced conflicting direct app")
	} else if !strings.Contains(err.Error(), "conflicting duplicate") {
		t.Fatalf("error should flag the conflicting duplicate, got: %v", err)
	}
}

// Guard against over-rejection of the idempotent path: a direct scalar restated
// with the SAME value is harmless (no value is silently lost) and must COMMIT —
// only a CONFLICTING (different-value) repeat is rejected. Flip the detection to
// value-blind (reject any repeat) and this assertion goes RED.
func TestApplicationDirectConflict_IdempotentRestate_Accepted(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"same-protocol", "protocol tcp; protocol tcp; destination-port 22;"},
		{"same-destination-port", "protocol tcp; destination-port 22; destination-port 22;"},
		{"same-source-port", "protocol tcp; source-port 1024; source-port 1024;"},
		{"same-alg", "protocol tcp; destination-port 21; alg ftp; alg ftp;"},
		// inactivity-timeout / timeout are aliases for the same field; both set to
		// 1800 is idempotent, not a conflicting override.
		{"timeout-alias-same-value", "protocol tcp; inactivity-timeout 1800; timeout 1800;"},
		// icmp / junos-icmp-all normalize to the same protocol, so restating one
		// as the other is not a real conflict.
		{"protocol-alias-normalizes-same", "protocol icmp; protocol junos-icmp-all;"},
		{"same-icmp-type", "protocol icmp; icmp-type 8; icmp-type 8;"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := hierTree(t, "applications {\n    application idem {\n        "+c.body+"\n    }\n}\n")
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("an idempotent same-value restate must COMMIT (only a "+
					"conflicting different-value repeat is rejected), got: %v", err)
			}
		})
	}
}

// Guard: a single-valued direct app (each scalar set exactly once) commits
// cleanly — the gate fires only on a CONFLICTING repeat, never on a well-formed
// direct body.
func TestApplicationDirectConflict_SingleValued_Accepted(t *testing.T) {
	tree := hierTree(t, `
applications {
    application good {
        protocol tcp;
        destination-port 22;
        source-port 1024-65535;
        inactivity-timeout 1800;
    }
}
`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a single-valued direct app must commit cleanly: %v", err)
	}
	app := cfg.Applications.Applications["good"]
	if app == nil {
		t.Fatalf("application good missing; have %v", appNames(cfg))
	}
	if app.Protocol != "tcp" || app.DestinationPort != "22" {
		t.Fatalf("single-valued app must keep its values, got protocol=%q destination-port=%q",
			app.Protocol, app.DestinationPort)
	}
}

// The tolerant load / peer-sync path (CompileConfigLenient) must NOT brick on a
// conflicting direct app an older binary persisted — it downgrades the reject to
// a warning so the daemon still boots (#1960 no-brick). Revert the lenient
// downgrade and this goes RED.
func TestApplicationDirectConflict_Lenient_DowngradesToWarning(t *testing.T) {
	tree := hierTree(t, `
applications {
    application badapp {
        protocol tcp;
        protocol udp;
        destination-port 22;
    }
}
`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must NOT fail on a conflicting direct app (no-brick): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application structure") && strings.Contains(w, "conflicting duplicate") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient path must record a downgrade warning; warnings: %v", cfg.Warnings)
	}
}
