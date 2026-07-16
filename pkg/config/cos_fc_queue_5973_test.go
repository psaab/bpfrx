package config

import (
	"strings"
	"testing"
)

// #5973: the `class-of-service forwarding-classes queue <N> <fc>` parse site
// (compiler_class_of_service.go) previously SILENTLY DROPPED a queue token that
// strconv.Atoi could not parse (`strconv.Atoi -> continue`): the
// forwarding-class -> queue mapping never bound and CompileConfig returned nil
// with no operator error — the same mis-bind / fail-open class #5963/#5933
// closed on adjacent CoS slots, and inconsistent with the sibling fairness
// rss-expectation queue parse (which hard-rejects
// `err != nil || queue < 0 || queue > 255`).
//
// The `queue` schema node (schema_cos.go) carries no keyValidator, so
// SchemaValidate accepts a non-numeric token; the compiler is the only gate.
// The fix rejects the strconv-error token at strict commit and warns on the
// tolerant load / peer-sync path (opts.lenientCoSForwardingClassQueue — the
// same #4594 flag the downstream forwarding-class queue-RANGE gate uses).
//
// Division of labour: a PARSEABLE but out-of-range value (e.g. 999) or a
// negative one still flows to the downstream #4594 range gate
// (validateClassOfServiceForwardingClassQueueStrict), which already rejects it
// (see compiler_cos_fc_queue_4594_test.go). This site closes the ONE case that
// gate can never see — a strconv error means the FC never binds, so there is no
// Queue int left to range-check.
//
// Flat-set MUST be built with ParseSetCommand/SetPath (flatTreeFromSets), never
// NewParser (CLAUDE.md "Testing flat set syntax").
//
// FAIL-ON-REVERT (load-bearing): restore the silent `strconv.Atoi(...); if err
// != nil { continue }` at the parse site → the reject test compiles the
// malformed queue clean (accept + silent drop) → its assertion goes RED. The
// out-of-range 999 case is NOT part of this guard (it survives the revert via
// the downstream #4594 gate); only the strconv-error tokens below prove the
// revert.

// cosBadQueueTokens is the set of queue tokens strconv.Atoi rejects — the exact
// tokens that hit the previously-silent `continue`. The compiler error always
// quotes the raw token via `queue %q`, so `want` is that quoted form.
var cosBadQueueTokens = []struct {
	name string
	tok  string
	want string
}{
	{"non-numeric", "abc", `"abc"`},
	{"integer-overflow", "99999999999999999999", `"99999999999999999999"`},
}

// TestCoSForwardingClassQueue5973_Reject proves a forwarding-class queue token
// that strconv.Atoi cannot parse is REJECTED at strict commit (CompileConfig)
// instead of silently dropped.
func TestCoSForwardingClassQueue5973_Reject(t *testing.T) {
	for _, tc := range cosBadQueueTokens {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t,
				"set class-of-service forwarding-classes queue "+tc.tok+" iperf-video")
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a malformed forwarding-class queue %q (silent FC drop); want reject", tc.tok)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must name the bad queue token %s: %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "class-of-service forwarding-classes") {
				t.Fatalf("error must name the subsystem (class-of-service forwarding-classes): %v", err)
			}
		})
	}
}

// TestCoSForwardingClassQueue5973_ValidBinds guards against over-rejection: a
// VALID queue (including the 0 and 255 boundaries) still compiles AND binds the
// forwarding-class -> queue mapping (semantics unchanged for the good case).
func TestCoSForwardingClassQueue5973_ValidBinds(t *testing.T) {
	cases := []struct {
		tok  string
		want int
	}{
		{"0", 0},
		{"7", 7},
		{"255", 255},
	}
	for _, tc := range cases {
		t.Run("queue-"+tc.tok, func(t *testing.T) {
			tree := flatTreeFromSets(t,
				"set class-of-service forwarding-classes queue "+tc.tok+" iperf-video")
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected a valid forwarding-class queue %s: %v", tc.tok, err)
			}
			fc := cfg.ClassOfService.ForwardingClasses["iperf-video"]
			if fc == nil {
				t.Fatalf("forwarding-class iperf-video never bound for valid queue %s", tc.tok)
			}
			if fc.Queue != tc.want {
				t.Fatalf("forwarding-class iperf-video queue = %d, want %d", fc.Queue, tc.want)
			}
		})
	}
}

// TestCoSForwardingClassQueue5973_LenientWarns proves the tolerant load /
// peer-sync path (CompileConfigLenient) does NOT hard-error on a strconv-error
// queue token: it downgrades to a deterministic warning naming the bad token so
// an already-persisted or peer-synced config still BOOTS (#1960 no-brick). The
// malformed queue is inert (the FC does not bind), exactly as before the gate.
func TestCoSForwardingClassQueue5973_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set class-of-service forwarding-classes queue abc iperf-video")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient hard-rejected a malformed forwarding-class queue (want warn): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `"abc"`) && strings.Contains(w, "class-of-service forwarding-class") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile produced no malformed forwarding-class queue warning; got %v", cfg.Warnings)
	}
	// The malformed queue must remain inert — the FC never bound.
	if fc := cfg.ClassOfService.ForwardingClasses["iperf-video"]; fc != nil {
		t.Fatalf("malformed queue must not bind the forwarding-class on the lenient path; got %+v", fc)
	}
}
