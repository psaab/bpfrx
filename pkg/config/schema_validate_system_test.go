package config_test

// #1319 PR 3 — per-leaf validation matrix for the system + services
// typed leaves, plus the hierarchical block-list multi-value shape
// regression (`name-server { 1.1.1.1; }` — the deployed-config
// spelling) that the walker's validateMultiValueLeaf path covers.

import (
	"fmt"
	"strings"
	"testing"
)

type systemLeafCase struct {
	name     string
	template string
	leaf     string
	accept   []string
	reject   []string
}

var systemLeafMatrix = []systemLeafCase{
	{
		name:     "name-server",
		leaf:     "name-server",
		template: "set system name-server %s",
		accept:   []string{"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"},
		reject:   []string{"1.1.1.1/32", "999.1.1.1", "dns.example.com", "asd", ""},
	},
	{
		name:     "ssh-root-login",
		leaf:     "root-login",
		template: "set system services ssh root-login %s",
		accept:   []string{"allow", "deny", "deny-password"},
		// "permit" was the old placeholder's suggestion — the runtime
		// never accepted it (silent no-op).
		reject: []string{"permit", "yes", "asd", ""},
	},
	{
		name:     "dataplane-workers",
		leaf:     "workers",
		template: "set system dataplane workers %s",
		accept:   []string{"1", "4", "6", "64"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		name:     "dataplane-ring-entries",
		leaf:     "ring-entries",
		template: "set system dataplane ring-entries %s",
		// #2524: bounded [1..16384] AND power-of-two. 16384 is the cap;
		// 1 (2^0) is the floor. Non-powers-of-two and over-max OOM the
		// dataplane at bring-up before the fix, so they are rejected.
		accept: []string{"1", "1024", "2048", "8192", "16384"},
		reject: []string{"0", "-1", "asd", "", "16385", "32768", "1000", "3000", "100000"},
	},
	{
		name:     "dataplane-poll-mode",
		leaf:     "poll-mode",
		template: "set system dataplane poll-mode %s",
		accept:   []string{"busy-poll", "interrupt"},
		reject:   []string{"polling", "busy", "asd", ""},
	},
	{
		name:     "dataplane-rss-indirection",
		leaf:     "rss-indirection",
		template: "set system dataplane rss-indirection %s",
		accept:   []string{"enable", "disable"},
		reject:   []string{"off", "true", "asd", ""},
	},
	{
		name:     "dataplane-claim-host-tunables",
		leaf:     "claim-host-tunables",
		template: "set system dataplane claim-host-tunables %s",
		accept:   []string{"true", "false"},
		reject:   []string{"yes", "enable", "asd", ""},
	},
	{
		name:     "dataplane-netdev-budget",
		leaf:     "netdev-budget",
		template: "set system dataplane netdev-budget %s",
		accept:   []string{"1", "600", "5000"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		name:     "dataplane-coalescence-adaptive",
		leaf:     "adaptive",
		template: "set system dataplane coalescence adaptive %s",
		accept:   []string{"enable", "disable"},
		reject:   []string{"on", "off", "asd", ""},
	},
	{
		name:     "dataplane-coalescence-rx-usecs",
		leaf:     "rx-usecs",
		template: "set system dataplane coalescence rx-usecs %s",
		accept:   []string{"1", "8", "128"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		name:     "dataplane-coalescence-tx-usecs",
		leaf:     "tx-usecs",
		template: "set system dataplane coalescence tx-usecs %s",
		accept:   []string{"1", "8", "128"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		name:     "rpm-root-probe-limit",
		leaf:     "probe-limit",
		template: "set services rpm probe-limit %s",
		accept:   []string{"1", "3", "10"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		name:     "rpm-probe-type",
		leaf:     "probe-type",
		template: "set services rpm probe p1 test t1 probe-type %s",
		accept:   []string{"icmp-ping", "tcp-ping", "http-get"},
		reject:   []string{"ping", "udp-ping", "asd", ""},
	},
	{
		name:     "rpm-probe-interval",
		leaf:     "probe-interval",
		template: "set services rpm probe p1 test t1 probe-interval %s",
		accept:   []string{"1", "5", "300"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		name:     "rpm-probe-count",
		leaf:     "probe-count",
		template: "set services rpm probe p1 test t1 probe-count %s",
		accept:   []string{"1", "3", "15"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		name:     "rpm-test-interval",
		leaf:     "test-interval",
		template: "set services rpm probe p1 test t1 test-interval %s",
		accept:   []string{"1", "30", "3600"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		name:     "rpm-successive-loss",
		leaf:     "successive-loss",
		template: "set services rpm probe p1 test t1 thresholds successive-loss %s",
		accept:   []string{"1", "3"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		name:     "rpm-test-probe-limit",
		leaf:     "probe-limit",
		template: "set services rpm probe p1 test t1 probe-limit %s",
		accept:   []string{"1", "3"},
		reject:   []string{"0", "-1", "asd", ""},
	},
	{
		// Compiler enforces only > 0; the TCP port wire field is 16
		// bits — 65536 dialed and failed silently at probe runtime.
		name:     "rpm-destination-port",
		leaf:     "destination-port",
		template: "set services rpm probe p1 test t1 destination-port %s",
		accept:   []string{"1", "443", "65535"},
		reject:   []string{"0", "65536", "-1", "asd", ""},
	},
	{
		// 9223372036 = MaxDurationSeconds; one past overflows the
		// time.Duration conversion (pkg/ipmon/ipmon.go:480).
		name:     "ipmon-hold-down",
		leaf:     "hold-down",
		template: "set services ip-monitoring policy p1 hold-down %s",
		accept:   []string{"0", "5", "30", "9223372036"},
		reject:   []string{"-1", "9223372037", "asd", ""},
	},
	{
		name:     "ipmon-preferred-metric",
		leaf:     "preferred-metric",
		template: "set services ip-monitoring policy p1 then preferred-route route 0.0.0.0/0 preferred-metric %s",
		accept:   []string{"0", "10", "4294967295"},
		reject:   []string{"-1", "asd", ""},
	},
	{
		name:     "ipmon-preferred-metric-routing-instance",
		leaf:     "preferred-metric",
		template: "set services ip-monitoring policy p1 then preferred-route routing-instance vr1 route 0.0.0.0/0 preferred-metric %s",
		accept:   []string{"0", "10"},
		reject:   []string{"-1", "asd", ""},
	},
	{
		// #2008 H17: only read-only / read-write are honored at runtime;
		// any other value silently defaulted to read-only before the enum
		// gate, masking operator typos like "read-wrote".
		name:     "snmp-community-authorization",
		leaf:     "authorization",
		template: "set snmp community public authorization %s",
		accept:   []string{"read-only", "read-write"},
		reject:   []string{"read-wrote", "rw", "full", "asd", ""},
	},
}

func TestSchemaValidate_SystemServices_Matrix(t *testing.T) {
	for _, tc := range systemLeafMatrix {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range tc.accept {
				cmd := strings.TrimSpace(fmt.Sprintf(tc.template, v))
				if err := flatSchemaCheck(t, cmd); err != nil {
					t.Errorf("accept %q: unexpected error: %v", cmd, err)
				}
			}
			for _, v := range tc.reject {
				cmd := strings.TrimSpace(fmt.Sprintf(tc.template, v))
				err := flatSchemaCheck(t, cmd)
				if err == nil {
					t.Errorf("reject %q: expected error, got nil", cmd)
					continue
				}
				if !strings.Contains(err.Error(), tc.leaf) {
					t.Errorf("reject %q: error should reference %q: %v", cmd, tc.leaf, err)
				}
			}
		})
	}
}

// The deployed configs spell name-server as a hierarchical block list
// (`name-server { 1.1.1.1; }`, docs/ha-cluster-userspace.conf) — the
// compiler reads one value per child, so the multi-value walker must
// accept it (and reject garbage in the same spelling).
func TestSchemaValidate_NameServer_BlockListShape(t *testing.T) {
	if err := schemaCheck(t, `system {
    name-server {
        1.1.1.1;
        2001:4860:4860::8888;
    }
}`); err != nil {
		t.Fatalf("block-list name-server must validate, got: %v", err)
	}

	err := schemaCheck(t, `system {
    name-server {
        1.1.1.1;
        not-an-ip;
    }
}`)
	if err == nil {
		t.Fatal("expected garbage block-list name-server entry to reject, got nil")
	}
	if !strings.Contains(err.Error(), "not-an-ip") {
		t.Fatalf("error should quote the bad entry: %v", err)
	}
}

// Same block-list shape for the vrrp virtual-address multi leaf
// (compiler_interfaces.go reads child.Name() entries — #1813).
func TestSchemaValidate_VirtualAddress_BlockListShape(t *testing.T) {
	if err := schemaCheck(t, `interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet {
                address 10.0.1.10/24 {
                    vrrp-group 1 {
                        virtual-address {
                            10.0.1.1/24;
                            10.0.1.2/24;
                        }
                    }
                }
            }
        }
    }
}`); err != nil {
		t.Fatalf("block-list virtual-address must validate, got: %v", err)
	}

	err := schemaCheck(t, `interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet {
                address 10.0.1.10/24 {
                    vrrp-group 1 {
                        virtual-address {
                            10.0.1.1;
                        }
                    }
                }
            }
        }
    }
}`)
	if err == nil {
		t.Fatal("expected bare block-list virtual-address to reject, got nil")
	}
}

// The deployed full system stanza shape keeps validating.
func TestSchemaValidate_SystemServices_DeployedShapeAccepted(t *testing.T) {
	if err := schemaCheck(t, `system {
    host-name fw0;
    name-server {
        1.1.1.1;
    }
    services {
        ssh {
            root-login allow;
        }
    }
    dataplane {
        workers 6;
        poll-mode interrupt;
    }
}
services {
    rpm {
        probe wan-probe {
            test gw {
                probe-type icmp-ping;
                target 172.16.50.1;
                probe-interval 5;
                probe-count 3;
                test-interval 10;
            }
        }
    }
    ip-monitoring {
        policy wan-failover {
            match {
                rpm-probe wan-probe;
            }
            then {
                preferred-route {
                    route 0.0.0.0/0 {
                        next-hop 172.16.50.254;
                        preferred-metric 10;
                    }
                }
            }
            hold-down 5;
        }
    }
}`); err != nil {
		t.Fatalf("deployed system/services shape rejected: %v", err)
	}
}
