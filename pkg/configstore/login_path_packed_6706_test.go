package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// The pkg/config gate tests drive CompileConfig directly. This file drives
// CheckText — the REAL operator gate: the same strict parse LoadOverride uses,
// then compileTreeStrict, which is what every `commit`, `commit check` and
// `xpfd check-config` runs (typed-leaf SchemaValidate on the expanded view,
// then the strict compile). A gate that fires in the compiler but is
// short-circuited by an earlier stage of this pipeline would look fixed in
// pkg/config and still ship the hole; the packed `system login` shapes below
// reach the compiler untouched by SchemaValidate, so this is where that is
// pinned rather than assumed.
//
// Measured at the parent commit, every ancestor-packed shape here committed
// GREEN through this exact call.
const (
	loginPathSystemLineMarker = "is written on the `system` statement line"
	loginPathLoginLineMarker  = "is written on the `login` statement line"
	loginInstanceLineMarker   = "written on the instance line"
)

// TestLoginPathPackedRejectedByCommitCheck_6706 is the operator-path binder.
//
// FAIL-ON-REVERT: drop the matching `len(...Keys) > 1` arm from
// config.collectLoginPackedFindings and the corresponding sub-test goes RED on
// "commit check ACCEPTED it".
func TestLoginPathPackedRejectedByCommitCheck_6706(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		marker string
	}{
		{
			name:   "system line",
			text:   "system login user alice class read-only;\n",
			marker: loginPathSystemLineMarker,
		},
		{
			name:   "login line",
			text:   "system { login user alice class read-only; }\n",
			marker: loginPathLoginLineMarker,
		},
		{
			// The reviewer's whole-file case: not a one-liner in isolation but
			// a config file whose entire RBAC section is written this way.
			name:   "a whole config file written at the system level",
			text:   "system login user alice class read-only;\nsystem login class noc permissions view;\n",
			marker: loginPathSystemLineMarker,
		},
		{
			// The pre-existing arm, re-asserted here so a fold that
			// generalised the walk into the ancestor levels and lost the
			// instance level cannot pass this file.
			name:   "instance line (the arm that already worked)",
			text:   "system { login { user alice class read-only; } }\n",
			marker: loginInstanceLineMarker,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, nodeID := range []int{-1, 0, 1} {
				cfg, err := CheckText(tt.text, nodeID)
				if err == nil {
					t.Fatalf("node %d: commit check ACCEPTED it — System.Login=%v, warnings=%v",
						nodeID, cfg.System.Login, cfg.Warnings)
				}
				if !strings.Contains(err.Error(), tt.marker) {
					t.Fatalf("node %d: rejected by a DIFFERENT gate (want %q):\n  %v",
						nodeID, tt.marker, err)
				}
			}
		})
	}
}

// TestLoginPathPackedCommitCheckOverReach_6706 is the guard: the shapes the
// operator gate must keep ACCEPTING. It stays green under a revert of either
// ancestor arm, so it cannot be satisfied by the defect it guards against.
func TestLoginPathPackedCommitCheckOverReach_6706(t *testing.T) {
	accept := []struct{ name, text string }{
		{"nested spelling", "system { login { user alice { class read-only; } } }\n"},
		{"deactivated whole stanza", "inactive: system login user alice class read-only;\n"},
		{"deactivated login block", "system { inactive: login { user alice class read-only; } }\n"},
		{"deactivated instance", "system { login { inactive: user alice class ops; } }\n"},
		{"a non-login system statement line", "system host-name fw1;\n"},
	}
	for _, tc := range accept {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CheckText(tc.text, -1); err != nil {
				t.Fatalf("commit check rejected config it must accept: %v", err)
			}
		})
	}
}

// TestLoginPathPackedRuntimeFailOpen_6706 states WHY the `system`-line arm is
// the one that matters, in the terms the runtime uses rather than by quoting
// the gate's own message back at itself.
//
// System.Login == nil is what pkg/daemon applyCLILoginClass early-returns on,
// leaving pkg/cli's userClass empty — its legacy no-RBAC mode, where
// checkPermission returns nil for every command and showConfigRedacted returns
// false. The distinguishing fact is that the OPERATOR CONFIGURED RBAC and
// landed there anyway; asserting `Login == nil` for a config that says nothing
// about login would prove nothing.
//
// This runs against the gate's LENIENT twin, because the strict path now
// rejects: it is the residual on the tolerant load / peer-sync ingress (#1960
// no-brick), which still admits the config, and therefore the state a node that
// persisted one under an older binary boots into. config.CompileConfigLenient
// is the compile leg Store.compileTreeLenient delegates to on a standalone
// node (s.nodeID < 0) — the Store wrapper adds the schema-warning downgrade,
// not a second compile.
func TestLoginPathPackedRuntimeFailOpen_6706(t *testing.T) {
	const text = "system login user alice class read-only;\n"

	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant ingress must not brick (#1960): %v", err)
	}
	if cfg.System.Login != nil {
		t.Fatalf("System.Login is no longer nil for a system-line packed stanza (%+v) — "+
			"if the drop was fixed by UNPACKING rather than rejecting, the gate rationale "+
			"in compiler_system_login_gates.go must be rewritten", cfg.System.Login)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, loginPathSystemLineMarker) {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("the tolerant ingress admitted a config that compiles System.Login == nil "+
			"and said nothing; warnings: %v", cfg.Warnings)
	}
}
