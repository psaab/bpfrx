package config

import (
	"strings"
	"testing"
)

// vrrpTimerTreeHier8483 builds ONE hierarchical config tree from an inner
// vrrp-group spelling. It is deliberately hierarchical: the defect under test
// is invisible through `set`, because SetPath normalizes packed tokens into
// schema-structured children and every flat-set spelling is already gated. A
// fixture built the way most config tests are built cannot see this — the
// finding this file guards was first recorded as FALSE for exactly that reason.
func vrrpTimerTreeHier8483(t *testing.T, inner string) *ConfigTree {
	t.Helper()
	src := `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24 { ` +
		inner + ` } } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

// TestPackedVRRPTimersAreRangeGated8483 is the #8483 gate. The rows form a
// table whose MIDDLE rows are the ones that can fail: an all-reject gate passes
// the reject rows, and an absent gate passes the accept rows. Only a table
// carrying both can distinguish a working gate from either degenerate one.
func TestPackedVRRPTimersAreRangeGated8483(t *testing.T) {
	const vip = `virtual-address 10.0.1.100/24 `
	rows := []struct {
		name    string
		inner   string
		wantErr string // "" = must COMMIT
	}{
		// The defect: packed hierarchical one-liners that SchemaValidate
		// accepts because walkInstanceChildren consumes the property as an
		// unvalidated identity token.
		{
			name:    "packed advertise-interval 256 is rejected",
			inner:   `vrrp-group 1 ` + vip + `advertise-interval 256;`,
			wantErr: "advertise-interval 256",
		},
		{
			// Property order must not matter: the packed tokens land on the
			// instance node's Keys in source order, and a gate that read only
			// a fixed offset would pass this row while failing the one above.
			name:    "packed advertise-interval FIRST is rejected",
			inner:   `vrrp-group 1 advertise-interval 256 ` + vip + `;`,
			wantErr: "advertise-interval 256",
		},
		{
			// 41 s (4100 cs) is the first value that overflows the 0x0FFF wire
			// mask. Pinning the boundary rather than a comfortable 256 is what
			// stops a later "round it up to 60" from passing this test.
			name:    "packed advertise-interval 41 is rejected at the wire boundary",
			inner:   `vrrp-group 1 ` + vip + `advertise-interval 41;`,
			wantErr: "advertise-interval 41",
		},
		{
			// A negative survives strconv.Atoi and reaches uint16 arithmetic.
			name:    "packed advertise-interval -5 is rejected",
			inner:   `vrrp-group 1 ` + vip + `advertise-interval -5;`,
			wantErr: "advertise-interval -5",
		},
		{
			name:    "packed preempt hold-time 9999 is rejected",
			inner:   `vrrp-group 1 ` + vip + `preempt hold-time 9999;`,
			wantErr: "preempt hold-time 9999",
		},

		// CONTROLS. Each one fails if the gate over-reaches, and together they
		// are what makes the reject rows above mean something.
		{
			name:  "packed advertise-interval 5 still commits",
			inner: `vrrp-group 1 ` + vip + `advertise-interval 5;`,
		},
		{
			// The inclusive upper bound. A gate written with `>=` instead of
			// `>` rejects this row while every reject row above still passes.
			name:  "packed advertise-interval 40 still commits at the boundary",
			inner: `vrrp-group 1 ` + vip + `advertise-interval 40;`,
		},
		{
			// THE row that a naive mirror of the priority gate fails. Zero is
			// not out of range, it is the compiler's "unset" sentinel, and
			// pkg/vrrp substitutes the 1 s default for it. A gate that rejected
			// 0 would refuse every vrrp-group that does not configure a timer
			// — which is nearly all of them, including the shipped
			// docs/ha-cluster-userspace.conf.
			name:  "a group with NO timers configured still commits",
			inner: `vrrp-group 1 ` + vip + `priority 200;`,
		},
		{
			name:  "packed preempt hold-time 30 still commits",
			inner: `vrrp-group 1 ` + vip + `preempt hold-time 30;`,
		},
		{
			name:  "braced in-range spelling still commits",
			inner: `vrrp-group 1 { virtual-address 10.0.1.100/24; advertise-interval 5; preempt { hold-time 30; } }`,
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			tree := vrrpTimerTreeHier8483(t, row.inner)
			_, err := CompileConfig(tree)
			if row.wantErr == "" {
				if err != nil {
					t.Fatalf("must commit, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("must be rejected, but committed clean")
			}
			if !strings.Contains(err.Error(), row.wantErr) {
				t.Fatalf("rejected for the wrong reason\n  want substring: %q\n  got: %v",
					row.wantErr, err)
			}
		})
	}
}

// TestPackedVRRPTimerGateIsLenientOnLoad8483 pins the #1960 no-brick side. A
// config an older binary accepted and PERSISTED must still boot after upgrade,
// so the tolerant path warns instead of failing. Without this the gate turns
// every already-committed packed one-liner into an unbootable node — the gate
// would be strictly worse than the defect it fixes.
func TestPackedVRRPTimerGateIsLenientOnLoad8483(t *testing.T) {
	tree := vrrpTimerTreeHier8483(t,
		`vrrp-group 1 virtual-address 10.0.1.100/24 advertise-interval 256;`)

	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("control failed: the strict path must reject this, or the " +
			"lenient assertion below proves nothing")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant path must not brick the node: %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "advertise-interval 256") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant path must WARN, not swallow; warnings: %v", cfg.Warnings)
	}
	// The value is still carried through, un-narrowed — the tolerant path
	// downgrades the verdict, it does not sanitize the config.
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil || len(ifc.Units[0].VRRPGroups) != 1 {
		t.Fatalf("tolerant path dropped the group: %+v", cfg.Interfaces.Interfaces)
	}
}

// TestAdvertiseIntervalBoundMatchesTheWire8483 asserts the AGREEMENT between
// the config-layer bound and the wire arithmetic that justifies it, rather than
// pinning either one to a literal. A literal on one side encodes which spelling
// is trusted; this asserts they have not drifted apart. The wire side is
// derived from the 12-bit RFC 5798 §5.2.7 Max Advert Int field in
// pkg/vrrp/packet_max_advert_narrowing_8483_test.go.
func TestAdvertiseIntervalBoundMatchesTheWire8483(t *testing.T) {
	// centiseconds that fit in the 12-bit wire field, expressed as whole
	// configured seconds: floor(4095 / 100).
	const wireMaxWholeSeconds = 4095 / 100
	if MaxVRRPAdvertiseInterval != wireMaxWholeSeconds {
		t.Fatalf("the commit-time bound (%d s) and the largest whole second "+
			"that fits the 12-bit Max Advert Int field (%d s) have drifted "+
			"apart; one of them is now wrong",
			MaxVRRPAdvertiseInterval, wireMaxWholeSeconds)
	}
}
