package configstore

import (
	"path/filepath"
	"strings"
	"testing"
)

// #9408 CHANNEL MATRIX for `protocols ospf reference-bandwidth`.
//
// The defect was measured on `configstore.CheckText` — the day-0 /
// commit-check gate — which ACCEPTED `reference-bandwidth 1g` with zero
// warnings while the value compiled to 0 and rendered no `auto-cost` line at
// all. So the channel the defect was reported on is the channel the fix is
// pinned on, rather than only the pkg/config validator it delegates to.
//
// Two halves carry the whole claim, and they must move in OPPOSITE directions:
//
//   - STRICT (CheckText): a value FRR cannot express is now REJECTED. Before
//     #9408 every rejected row below was accepted.
//   - TOLERANT (Store.Load -> compileTreeLenient): the same value must NOT
//     blackout-boot a node. It warns and the leaf compiles to UNSET, so FRR
//     applies its own default rather than receiving a number up to six orders
//     of magnitude outside `auto-cost reference-bandwidth (1-4294967)`.
//
// A test asserting only the strict half would be satisfied by hard-failing the
// tolerant path too, which is the #1319/#1798 doctrine's explicit non-goal.

func refBandwidthText9408(token string) string {
	return `system { host-name fw; }
protocols {
    ospf {
        reference-bandwidth ` + token + `;
        area 0.0.0.0 { interface ge-0/0/1.0; }
    }
}
`
}

func TestOSPFReferenceBandwidthStrictChannel9408(t *testing.T) {
	for _, tc := range []struct {
		token  string
		reject bool
		why    string
	}{
		// CONTROLS: the spellings an operator writing Junos actually uses.
		// Before #9408 these were ACCEPTED AND SILENTLY DROPPED, so an
		// accept-only assertion here would have been green on the defect —
		// which is why each control also asserts the compiled value.
		{"1g", false, "CONTROL: 1 Gbps"},
		{"100m", false, "CONTROL: the Junos default, 100 Mbps"},
		{"1000000000", false, "CONTROL: 1 Gbps written in plain bits/s"},

		// The rows measured on the issue, every one of which used to ACCEPT.
		{"10000", true, "the pre-#9408 Mbps spelling — 10 kbps in Junos units"},
		{"-5", true, "negative"},
		{"99999999999", true, "not a whole number of Mbps"},
		{"4294968", true, "4294968 bits/s is below the 1 Mbps floor"},
	} {
		cfg, err := CheckText(refBandwidthText9408(tc.token), -1)
		if tc.reject {
			if err == nil {
				t.Errorf("CheckText(reference-bandwidth %s) (%s): want REJECT, got ACCEPT (compiled %+v)",
					tc.token, tc.why, cfg.Protocols.OSPF)
			}
			continue
		}
		if err != nil {
			t.Errorf("CheckText(reference-bandwidth %s) (%s): want ACCEPT, got %v", tc.token, tc.why, err)
			continue
		}
		if cfg.Protocols.OSPF == nil || cfg.Protocols.OSPF.ReferenceBandwidthMbps == 0 {
			t.Errorf("CheckText(reference-bandwidth %s) (%s): accepted but compiled to UNSET — that is the "+
				"exact pre-#9408 failure, where the commit reported success and the cost basis silently "+
				"stayed at FRR's default", tc.token, tc.why)
		}
	}
}

// The TOLERANT half, driven through Store.Load (the real ingress) rather than
// config.CompileConfigLenient directly: the downgrade lives in
// configstore.compileTreeLenient, and calling the compiler alone would skip
// the gate whose downgrade is the thing under test.
func TestOSPFReferenceBandwidthTolerantChannel9408(t *testing.T) {
	load := func(t *testing.T, token string) *Store {
		t.Helper()
		cfgPath := filepath.Join(t.TempDir(), "config")
		writeStoredConfig(t, cfgPath,
			"set protocols ospf reference-bandwidth "+token,
			"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0")
		s := newTestStoreAt(t, cfgPath)
		if err := s.Load(); err != nil {
			t.Fatalf("Store.Load must TOLERATE a persisted reference-bandwidth the strict gate rejects — "+
				"hard-failing here leaves the daemon with no active config (operational blackout): %v", err)
		}
		return s
	}

	// A value the strict gate rejects, as an ALREADY-PERSISTED config: the
	// pre-#9408 Mbps spelling of 10 Gbps.
	s := load(t, "10000")
	cfg := s.ActiveConfig()
	if cfg == nil || cfg.Protocols.OSPF == nil {
		t.Fatalf("the tolerated config must still compile its OSPF stanza; got %+v", cfg)
	}
	if got := cfg.Protocols.OSPF.ReferenceBandwidthMbps; got != 0 {
		t.Errorf("a tolerated out-of-range reference-bandwidth must compile to UNSET so FRR applies its own "+
			"default; got %d Mbps, which pkg/frr would write verbatim into `auto-cost reference-bandwidth "+
			"(1-4294967)`", got)
	}

	// The next STRICT operator commit must still reject it loudly, naming the
	// leaf. Without this the tolerance would be indistinguishable from having
	// no gate at all.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must stay strict after a tolerated Load, got nil")
	}
	if !strings.Contains(err.Error(), "reference-bandwidth") {
		t.Errorf("the strict rejection must name the leaf so the operator can find it: %v", err)
	}

	// CONTROL: the tolerant path is not simply dropping every value. One it
	// CAN convert survives the same ingress, so "compiled to 0" is a verdict
	// about the value rather than about the path.
	ctrl := load(t, "1g")
	if got := ctrl.ActiveConfig().Protocols.OSPF.ReferenceBandwidthMbps; got != 1000 {
		t.Errorf("CONTROL: a convertible value must survive the tolerant ingress; got %d Mbps, want 1000", got)
	}
}
