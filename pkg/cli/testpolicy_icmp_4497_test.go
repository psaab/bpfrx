package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// newICMPPolicyCLI builds a committed store with two permit policies:
//   - allow-icmp matches an ICMP echo-request application (protocol icmp,
//     icmp-type 8, icmp-code 0)
//   - allow-tcp matches a TCP web application (protocol tcp, destination-port 80)
//
// with a deny-all default. This lets a `test policy` query exercise BOTH the
// ICMP type/code query surface and the untouched non-ICMP path.
func newICMPPolicyCLI(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
applications {
    application icmp-echo {
        protocol icmp;
        icmp-type 8;
        icmp-code 0;
    }
    application tcp-web {
        protocol tcp;
        destination-port 80;
    }
}
security {
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy allow-icmp {
                match { source-address any; destination-address any; application icmp-echo; }
                then { permit; }
            }
            policy allow-tcp {
                match { source-address any; destination-address any; application tcp-web; }
                then { permit; }
            }
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &CLI{store: store}
}

// TestTestPolicyICMPTypeCodeEcho is the #4497 (avo-001 F3) RED-on-revert guard
// for the local CLI `test policy` ICMP type/code query surface. An ICMP query
// carrying `protocol icmp icmp-type 8 icmp-code 0` must:
//
//   - MATCH the icmp-type/icmp-code-constrained application (the query surface
//     threads Query.ICMPType/ICMPCode into the shared simulator, #3284), and
//   - ECHO the queried type/code in the verdict tuple so the operator sees WHICH
//     ICMP packet was tested, not just `[icmp]`.
//
// The non-ICMP TCP query is the control: it matches its policy and prints the
// bare `[tcp]` tuple with NO type/code annotation.
//
// FAIL-ON-REVERT: dropping the ICMP type/code from the `test policy` query echo
// (formatQueryProtoTail) reduces the ICMP output to `[icmp]`, so the
// `[icmp type 8 code 0]` assertion flips red. The TCP control proves the change
// is scoped to ICMP queries.
func TestTestPolicyICMPTypeCodeEcho(t *testing.T) {
	c := newICMPPolicyCLI(t)

	t.Run("icmp echoes type and code", func(t *testing.T) {
		var err error
		args := []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "icmp", "icmp-type", "8", "icmp-code", "0"}
		out := captureStdout(t, func() { err = c.testPolicy(args) })
		if err != nil {
			t.Fatalf("testPolicy(%v) err = %v", args, err)
		}
		if !strings.Contains(out, "Policy match") {
			t.Fatalf("ICMP type-8/code-0 query did not match the icmp-type-constrained policy:\n%s", out)
		}
		if !strings.Contains(out, "[icmp type 8 code 0]") {
			t.Fatalf("test policy did not surface the queried ICMP type/code in the tuple echo:\n%s", out)
		}
	})

	t.Run("tcp control unaffected", func(t *testing.T) {
		var err error
		args := []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "destination-port", "80"}
		out := captureStdout(t, func() { err = c.testPolicy(args) })
		if err != nil {
			t.Fatalf("testPolicy(%v) err = %v", args, err)
		}
		if !strings.Contains(out, "Policy match") {
			t.Fatalf("TCP dst-80 query did not match the tcp-web policy:\n%s", out)
		}
		if !strings.Contains(out, "[tcp]") {
			t.Fatalf("non-ICMP query lost its bare [tcp] protocol echo:\n%s", out)
		}
		if strings.Contains(out, "type ") || strings.Contains(out, "code ") {
			t.Fatalf("non-ICMP query leaked an ICMP type/code annotation:\n%s", out)
		}
	})
}

// TestFormatQueryProtoTail unit-tests the #4497 tuple-tail formatter directly so
// the ICMP type/code echo rules (and the untouched non-ICMP / empty cases) are
// pinned independent of the surrounding `test policy` output.
func TestFormatQueryProtoTail(t *testing.T) {
	u8 := func(v uint8) *uint8 { return &v }
	cases := []struct {
		name     string
		proto    string
		icmpType *uint8
		icmpCode *uint8
		want     string
	}{
		{"empty", "", nil, nil, ""},
		{"tcp only", "tcp", nil, nil, "[tcp]"},
		{"icmp type and code", "icmp", u8(8), u8(0), "[icmp type 8 code 0]"},
		{"icmp type only", "icmp", u8(3), nil, "[icmp type 3]"},
		{"icmp6 type only", "icmp6", u8(128), nil, "[icmp6 type 128]"},
		{"type without proto", "", u8(8), u8(0), "[type 8 code 0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatQueryProtoTail(tc.proto, tc.icmpType, tc.icmpCode); got != tc.want {
				t.Fatalf("formatQueryProtoTail(%q, %v, %v) = %q, want %q", tc.proto, tc.icmpType, tc.icmpCode, got, tc.want)
			}
		})
	}
}
