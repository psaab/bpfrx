package config_test

// Regression tests for the #2008 Tier-1.5 schema-hardening sweep: leaves
// that were fully parsed + compiled + honored at runtime but whose
// setSchema node carried `children: nil` (or a missing child), so the
// #1319 commit-time typed-leaf gate (SchemaValidate) skipped them and an
// invalid value committed silently. Each "RejectsBad" case FAILS today
// (the gate has nothing to validate) and PASSES once the typed child is
// declared; each "AcceptsValid" case guards against a false-reject of the
// spellings the compilers already accept.
//
// Items covered:
//   - H8: security log stream transport protocol (enum udp|tcp|tls)
//   - M2: IKE / IPsec proposal dh-group, lifetime-seconds,
//     authentication-method
//   - M3: static-NAT rule match source/destination-address (structure)
//   - RA: protocols router-advertisement max/min-advertisement-interval
//   - syslog: system syslog host/file/user <facility> <severity> pairs

import (
	"strings"
	"testing"
)

// --- H8: security log stream transport protocol -------------------------

func TestSchema2008_LogStreamTransportProtocol_RejectsBad(t *testing.T) {
	err := schemaCheck(t, `security {
    log {
        stream s1 {
            host 192.0.2.1;
            transport {
                protocol tpc;
            }
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for transport protocol tpc, got nil")
	}
	if !strings.Contains(err.Error(), "protocol") || !strings.Contains(err.Error(), "tpc") {
		t.Fatalf("error should reference protocol + bad value: %v", err)
	}
}

func TestSchema2008_LogStreamTransportProtocol_AcceptsValid(t *testing.T) {
	for _, proto := range []string{"udp", "tcp", "tls"} {
		if err := schemaCheck(t, `security {
    log {
        stream s1 {
            host 192.0.2.1;
            transport {
                protocol `+proto+`;
            }
        }
    }
}`); err != nil {
			t.Fatalf("unexpected error for protocol %s: %v", proto, err)
		}
	}
}

// --- M2: IKE proposal ---------------------------------------------------

func TestSchema2008_IKEProposalDHGroup_RejectsZero(t *testing.T) {
	err := schemaCheck(t, `security {
    ike {
        proposal p1 {
            authentication-method pre-shared-keys;
            dh-group 0;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for dh-group 0, got nil")
	}
	if !strings.Contains(err.Error(), "dh-group") {
		t.Fatalf("error should reference dh-group: %v", err)
	}
}

func TestSchema2008_IKEProposalAuthMethod_RejectsBad(t *testing.T) {
	err := schemaCheck(t, `security {
    ike {
        proposal p1 {
            authentication-method shared-secret;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for authentication-method shared-secret, got nil")
	}
	if !strings.Contains(err.Error(), "authentication-method") {
		t.Fatalf("error should reference authentication-method: %v", err)
	}
}

func TestSchema2008_IKEProposalLifetime_RejectsZero(t *testing.T) {
	err := schemaCheck(t, `security {
    ike {
        proposal p1 {
            lifetime-seconds 0;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for lifetime-seconds 0, got nil")
	}
	if !strings.Contains(err.Error(), "lifetime-seconds") {
		t.Fatalf("error should reference lifetime-seconds: %v", err)
	}
}

// AcceptsValid guards against false-rejecting the two dh-group spellings the
// compiler accepts (bare integer and the Junos group<N> form) and the real
// configs from parser_security_test.go.
func TestSchema2008_IKEProposal_AcceptsValid(t *testing.T) {
	if err := schemaCheck(t, `security {
    ike {
        proposal ike-aes256 {
            authentication-method pre-shared-keys;
            encryption-algorithm aes-256-cbc;
            authentication-algorithm sha-256;
            dh-group group14;
            lifetime-seconds 28800;
        }
        proposal ike-num {
            dh-group 14;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error for valid IKE proposals: %v", err)
	}
}

// --- M2: IPsec proposal -------------------------------------------------

func TestSchema2008_IPsecProposalDHGroup_RejectsBad(t *testing.T) {
	err := schemaCheck(t, `security {
    ipsec {
        proposal esp1 {
            protocol esp;
            dh-group bogus;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for ipsec dh-group bogus, got nil")
	}
	if !strings.Contains(err.Error(), "dh-group") {
		t.Fatalf("error should reference dh-group: %v", err)
	}
}

// Phase-2 IPsec dh-group must be a PLAIN positive integer: the compiler
// (compiler_ipsec.go compileIPsec) uses a bare strconv.Atoi and does NOT
// strip the "group" prefix, so "group14" would compile to DHGroup=0 and
// silently drop the PFS/modp term. The schema must reject the group<N>
// spelling for Phase-2 to stay compiler-faithful — unlike IKE Phase-1
// below, which DOES strip the prefix and accepts both spellings.
func TestSchema2008_IPsecProposalDHGroup_RejectsGroupSpelling(t *testing.T) {
	err := schemaCheck(t, `security {
    ipsec {
        proposal esp1 {
            protocol esp;
            dh-group group14;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for ipsec dh-group group14 (Phase-2 compiler does not strip group prefix), got nil")
	}
	if !strings.Contains(err.Error(), "dh-group") {
		t.Fatalf("error should reference dh-group: %v", err)
	}
}

func TestSchema2008_IPsecProposalDHGroup_RejectsZero(t *testing.T) {
	err := schemaCheck(t, `security {
    ipsec {
        proposal esp1 {
            protocol esp;
            dh-group 0;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for ipsec dh-group 0, got nil")
	}
	if !strings.Contains(err.Error(), "dh-group") {
		t.Fatalf("error should reference dh-group: %v", err)
	}
}

// Conversely, the IKE Phase-1 dh-group DOES accept the group<N> spelling
// because compiler_ipsec.go compileIKE strips the prefix before Atoi.
// This locks the deliberate IKE-vs-IPsec asymmetry so a future refactor
// cannot silently flip one of the two validators.
func TestSchema2008_IKEProposalDHGroup_AcceptsGroupSpelling(t *testing.T) {
	if err := schemaCheck(t, `security {
    ike {
        proposal p1 {
            dh-group group14;
        }
    }
}`); err != nil {
		t.Fatalf("IKE dh-group group14 should be accepted (compiler strips prefix): %v", err)
	}
}

func TestSchema2008_IPsecProposal_AcceptsValid(t *testing.T) {
	if err := schemaCheck(t, `security {
    ipsec {
        proposal esp-aes256 {
            protocol esp;
            encryption-algorithm aes-256-gcm;
            authentication-algorithm hmac-sha-256-128;
            dh-group 14;
            lifetime-seconds 3600;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error for valid IPsec proposal: %v", err)
	}
}

// --- M3: static-NAT rule match -----------------------------------------

// The static-NAT match children were unreachable by the walker (match
// children == nil), so a structural error inside match (a token trailing a
// presence-only descendant) was silently accepted. After the fix the match
// subtree is walked; the spelling the compiler reads must still validate.
func TestSchema2008_StaticNATMatch_AcceptsValid(t *testing.T) {
	if err := schemaCheck(t, `security {
    nat {
        static {
            rule-set rs1 {
                rule r1 {
                    match {
                        destination-address 203.0.113.5/32;
                    }
                    then {
                        static-nat prefix 10.0.0.5/32;
                    }
                }
            }
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error for valid static-NAT match: %v", err)
	}
}

// --- RA: max/min advertisement interval --------------------------------

func TestSchema2008_RAAdvertisementInterval_RejectsBad(t *testing.T) {
	err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            max-advertisement-interval abc;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for max-advertisement-interval abc, got nil")
	}
	if !strings.Contains(err.Error(), "max-advertisement-interval") {
		t.Fatalf("error should reference max-advertisement-interval: %v", err)
	}
}

func TestSchema2008_RAAdvertisementInterval_AcceptsValid(t *testing.T) {
	if err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            managed-configuration;
            max-advertisement-interval 600;
            min-advertisement-interval 200;
            default-lifetime 1800;
            link-mtu 1500;
            prefix 2001:db8::/64 {
                autonomous;
                valid-lifetime 86400;
            }
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error for valid router-advertisement: %v", err)
	}
}

// Prefix valid-lifetime/preferred-lifetime are now typed as non-negative
// integers. The compiler used a bare strconv.Atoi (garbage silently became
// 0 = SLAAC default), so a misspelled lifetime must now fail at commit.
func TestSchema2008_RAPrefixLifetime_RejectsBad(t *testing.T) {
	for _, leaf := range []string{"valid-lifetime", "preferred-lifetime"} {
		err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            prefix 2001:db8::/64 {
                `+leaf+` abc;
            }
        }
    }
}`)
		if err == nil {
			t.Fatalf("expected error for prefix %s abc, got nil", leaf)
		}
		if !strings.Contains(err.Error(), leaf) {
			t.Fatalf("error should reference %s: %v", leaf, err)
		}
	}
}

// 0 must still be accepted: it is the explicit "use the SLAAC default"
// sentinel the compiler/sender honor (ValidateIntegerMin(0), not Min(1)).
func TestSchema2008_RAPrefixLifetime_AcceptsZero(t *testing.T) {
	if err := schemaCheck(t, `protocols {
    router-advertisement {
        interface ge-0-0-0 {
            prefix 2001:db8::/64 {
                autonomous;
                valid-lifetime 0;
                preferred-lifetime 0;
            }
        }
    }
}`); err != nil {
		t.Fatalf("prefix lifetimes of 0 (= SLAAC default) should be accepted: %v", err)
	}
}

// --- syslog: system syslog facility/severity pairs ----------------------

func TestSchema2008_SyslogSeverity_RejectsBad(t *testing.T) {
	err := schemaCheck(t, `system {
    syslog {
        host 192.0.2.1 {
            kernel informational;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for syslog severity informational, got nil")
	}
	if !strings.Contains(err.Error(), "informational") {
		t.Fatalf("error should quote the bad severity: %v", err)
	}
}

// AcceptsValid mirrors TestSyslogMultiFacilityAndUser: open-ended facility
// keywords (any, daemon, change-log) with valid Junos severities, plus the
// allow-duplicates flag, must all pass.
func TestSchema2008_Syslog_AcceptsValid(t *testing.T) {
	if err := schemaCheck(t, `system {
    syslog {
        user * {
            any emergency;
        }
        host 192.168.1.1 {
            any any;
            daemon info;
            change-log info;
            allow-duplicates;
        }
        file messages {
            any notice;
        }
    }
}`); err != nil {
		t.Fatalf("unexpected error for valid system syslog: %v", err)
	}
}

// Flat-set form must validate identically (the #1319 gate runs against the
// expanded tree built from set commands at commit time).
func TestSchema2008_FlatSet_LogStreamTransport_RejectsBad(t *testing.T) {
	err := flatSchemaCheck(t,
		"set security log stream s1 host 192.0.2.1",
		"set security log stream s1 transport protocol sctp",
	)
	if err == nil {
		t.Fatal("expected error for flat-set transport protocol sctp, got nil")
	}
	if !strings.Contains(err.Error(), "sctp") {
		t.Fatalf("error should quote the bad protocol: %v", err)
	}
}
