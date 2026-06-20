package config

// Differential dual-AST regression harness (#1800 U5a).
//
// The parser produces two AST shapes for the same configuration intent:
// hierarchical text (`vrrp-group 1 { priority 200; }`) yields container
// nodes with Children, while flat-set replay (`set ... vrrp-group 1
// priority 200`) yields whatever structure setSchema knows about — often
// a single leaf with the properties encoded in Keys. Compilers that read
// only node.Children silently drop flat-set properties (#1796 vrrp-group,
// #1797 dhcp-relay).
//
// This harness catches that whole bug class differentially, per fixture:
//
//  1. Parse the hierarchical fixture with NewParser.
//  2. Render it to flat-set lines via tree.FormatSet().
//  3. Re-parse the rendered lines via ParseSetCommand + tree.SetPath,
//     one line at a time (NEVER NewParser on set-lines — the parser
//     treats newlines as whitespace and merges all set lines into one
//     giant node; see CLAUDE.md).
//  4. SANITY GATE: compare canonical FormatSet() of both trees BEFORE
//     compiling. A mismatch is reported as its own failure class
//     (round-trip infidelity) so a FormatSet/SetPath generator bug
//     cannot masquerade as a compiler bug.
//  5. Compile BOTH trees with CompileConfig (the entry the existing
//     compiler tests use) and deep-compare the typed *Config section
//     by section.
//
// Known-broken cases carry expectedFail markers referencing their
// tracking issues; U5b flips the markers as it fixes them. The test
// FAILS if an expectedFail case unexpectedly passes, so a fix cannot
// land without flipping its marker.

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type dualASTCase struct {
	name string
	// hier is the hierarchical configuration text (the reference shape).
	hier string
	// expectedFail marks a case with a known dual-AST gap. The harness
	// requires such a case to fail; when U5b fixes it, the marker must
	// be flipped to false in the same change.
	expectedFail bool
	// failureClass pins WHICH failure class an expectedFail case must
	// produce (a substring of the failure string, e.g. "compiler
	// dual-AST" or "round-trip infidelity (content)"). A different
	// class — a panic, parser error, or new round-trip regression —
	// fails the suite instead of hiding behind the marker (AGY r1 on
	// PR #1811).
	failureClass string
	// reason names the tracking issue / one-line diagnosis for an
	// expectedFail case.
	reason string
}

var dualASTCases = []dualASTCase{
	{
		name: "interfaces-units-vlans",
		hier: `interfaces {
    ge-0/0/0 {
        description "trust uplink port";
        mtu 9000;
        vlan-tagging;
        unit 0 {
            family inet {
                address 10.0.1.10/24;
            }
            family inet6 {
                address 2001:db8:1::10/64;
            }
        }
        unit 50 {
            vlan-id 50;
            family inet {
                address 172.16.50.5/24;
            }
        }
    }
    fxp0 {
        unit 0 {
            family inet {
                dhcp;
            }
        }
    }
}`,
	},
	{
		name: "interfaces-vrrp-group",
		hier: `interfaces {
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        accept-data;
                        advertise-interval 1;
                        track-interface ge-0/0/1;
                    }
                }
            }
        }
    }
}`,
		// Fixed in U5b (#1796): vrrp-group subtree added to setSchema and
		// the compiler now reads properties from both Children and Keys[2:].
		expectedFail: false,
	},
	{
		// Junos multi-value bracketed list spelling: every address in
		// `virtual-address [ a b ];` must survive both AST shapes
		// (AGY review on PR #1813 — nodeVal kept only the first).
		name: "interfaces-vrrp-group-bracketed-virtual-address",
		hier: `interfaces {
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address [ 10.0.61.3 10.0.61.4 ];
                        priority 200;
                    }
                }
            }
        }
    }
}`,
		expectedFail: false,
	},
	{
		// Braced block spelling: `virtual-address { a; b; }` holds one
		// child per address (AGY review on PR #1813 — nodeVal's
		// Children[0] fallback dropped all but the first).
		name: "interfaces-vrrp-group-virtual-address-block",
		hier: `interfaces {
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address {
                            10.0.61.3;
                            10.0.61.4;
                        }
                        priority 200;
                    }
                }
            }
        }
    }
}`,
		expectedFail: false,
	},
	{
		// Nested Junos `track-interface <if> { priority-cost <n>; }`
		// block (#1814) — the standard Junos shape; priority-cost must
		// compile identically from both AST shapes.
		name: "interfaces-vrrp-group-track-interface-nested",
		hier: `interfaces {
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        track-interface ge-0/0/1 {
                            priority-cost 20;
                        }
                    }
                }
            }
        }
    }
}`,
		expectedFail: false,
	},
	{
		name: "security-zones-address-book",
		hier: `security {
    zones {
        security-zone trust {
            description "inside zone";
            interfaces {
                ge-0/0/0.0;
                ge-0/0/1.0;
            }
            host-inbound-traffic {
                system-services {
                    ping;
                    ssh;
                }
                protocols {
                    ospf;
                }
            }
            address-book {
                address web-server 10.0.1.100/32;
                address app-net 10.0.2.0/24;
                address-set servers {
                    address web-server;
                    address app-net;
                }
            }
        }
        security-zone untrust {
            interfaces {
                ge-0/0/2.0;
            }
        }
    }
}`,
	},
	{
		name: "security-policies",
		hier: `security {
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                description "permit outbound web";
                match {
                    source-address any;
                    destination-address any;
                    application junos-http;
                }
                then {
                    permit;
                    log {
                        session-init;
                        session-close;
                    }
                }
            }
            policy deny-rest {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                }
            }
        }
        global {
            policy global-icmp {
                match {
                    source-address any;
                    destination-address any;
                    application junos-icmp-all;
                }
                then {
                    permit;
                }
            }
        }
    }
}`,
	},
	{
		name: "security-nat",
		hier: `security {
    nat {
        source {
            pool snat-pool {
                address 192.0.2.10/32;
            }
            rule-set trust-to-untrust {
                from zone trust;
                to zone untrust;
                rule snat-all {
                    match {
                        source-address 10.0.1.0/24;
                    }
                    then {
                        source-nat {
                            pool {
                                snat-pool;
                            }
                        }
                    }
                }
            }
        }
        destination {
            pool web-pool {
                address 10.0.1.100/32 port 8080;
            }
            rule-set inbound {
                from zone untrust;
                rule dnat-web {
                    match {
                        destination-address 203.0.113.5/32;
                        destination-port 80;
                    }
                    then {
                        destination-nat {
                            pool {
                                web-pool;
                            }
                        }
                    }
                }
            }
        }
        static {
            rule-set static-map {
                from zone untrust;
                rule one-to-one {
                    match {
                        destination-address 203.0.113.6/32;
                    }
                    then {
                        static-nat {
                            prefix {
                                10.0.1.6/32;
                            }
                        }
                    }
                }
            }
        }
    }
}`,
	},
	{
		// Canonical Junos renders SNAT pool addresses in block form
		// (`address { <prefix>; }`). Isolated from the green
		// security-nat case, which uses the leaf form.
		name: "security-nat-pool-address-block",
		hier: `security {
    nat {
        source {
            pool snat-pool {
                address {
                    192.0.2.10/32;
                }
            }
            rule-set trust-to-untrust {
                from zone trust;
                to zone untrust;
                rule snat-all {
                    match {
                        source-address 10.0.1.0/24;
                    }
                    then {
                        source-nat {
                            pool {
                                snat-pool;
                            }
                        }
                    }
                }
            }
        }
    }
}`,
		// Fixed in U5b (#1808): the inline-value path reads prop.Keys[1]
		// directly instead of nodeVal's Children[0] fallback, so the block
		// form is appended only by the children walk.
		expectedFail: false,
	},
	{
		name: "security-screen",
		hier: `security {
    screen {
        ids-option untrust-screen {
            icmp {
                ping-death;
                flood threshold 1000;
            }
            ip {
                tear-drop;
            }
            tcp {
                land;
                syn-flood {
                    attack-threshold 200;
                    alarm-threshold 512;
                    timeout 20;
                }
            }
        }
    }
    zones {
        security-zone untrust {
            screen untrust-screen;
        }
    }
}`,
	},
	{
		name: "security-flow-alg",
		hier: `security {
    flow {
        tcp-mss {
            ipsec-vpn 1350;
            gre-in 1400;
            gre-out 1380;
        }
        allow-dns-reply;
        allow-embedded-icmp;
    }
    alg {
        dns {
            disable;
        }
        ftp {
            disable;
        }
    }
}`,
	},
	{
		name: "applications",
		hier: `applications {
    application custom-dns {
        term t1 protocol udp destination-port 53;
        term t2 protocol tcp destination-port 53;
    }
    application custom-syslog {
        protocol udp;
        destination-port 514;
        inactivity-timeout 120;
    }
    application-set infra-apps {
        application custom-dns;
        application custom-syslog;
    }
}`,
	},
	{
		name: "class-of-service",
		hier: `class-of-service {
    forwarding-classes {
        queue 0 best-effort;
        queue 1 expedited-forwarding;
    }
    classifiers {
        dscp dscp-in {
            forwarding-class expedited-forwarding {
                loss-priority low {
                    code-points ef;
                }
            }
        }
    }
    schedulers {
        be-sched {
            transmit-rate 7g;
            priority low;
            buffer-size 16m;
        }
        ef-sched {
            transmit-rate 3g;
            priority strict-high;
            buffer-size 4m;
        }
    }
    scheduler-maps {
        edge-map {
            forwarding-class best-effort {
                scheduler be-sched;
            }
            forwarding-class expedited-forwarding {
                scheduler ef-sched;
            }
        }
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                shaping-rate 10g {
                    burst-size 125m;
                }
                scheduler-map edge-map;
            }
        }
    }
}
system {
    dataplane-type userspace;
}`,
	},
	{
		// Junos accepts the inline one-liner leaf spelling
		// `loss-priority low code-points ef;` as well as the braced
		// container form used by the green class-of-service case.
		name: "cos-classifier-inline-leaf",
		hier: `class-of-service {
    forwarding-classes {
        queue 1 expedited-forwarding;
    }
    classifiers {
        dscp dscp-in {
            forwarding-class expedited-forwarding {
                loss-priority low code-points ef;
            }
        }
    }
}
system {
    dataplane-type userspace;
}`,
		// Fixed in U5b (#1809): the classifier code-point collectors also
		// scan the loss-priority node's own Keys for the inline leaf form.
		expectedFail: false,
	},
	{
		name: "firewall-filters",
		hier: `firewall {
    policer p-1m {
        if-exceeding {
            bandwidth-limit 1m;
            burst-size-limit 64k;
        }
        then {
            discard;
        }
    }
    family inet {
        filter protect-mgmt {
            term allow-ssh {
                from {
                    source-address {
                        10.0.0.0/8;
                    }
                    protocol tcp;
                    destination-port 22;
                }
                then accept;
            }
            term police-rest {
                then {
                    policer p-1m;
                }
            }
        }
    }
    family inet6 {
        filter block-ra {
            term t1 {
                from {
                    icmp-type 134;
                }
                then discard;
            }
            term t-default {
                then accept;
            }
        }
    }
}`,
	},
	{
		name: "routing-options-static",
		hier: `routing-options {
    autonomous-system 65001;
    static {
        route 0.0.0.0/0 next-hop 172.16.50.1;
        route 10.200.0.0/16 {
            qualified-next-hop 10.0.2.1 {
                metric 10;
            }
        }
        route 10.99.0.0/24 discard;
    }
    rib inet6.0 {
        static {
            route ::/0 next-hop 2001:db8:50::1;
        }
    }
}`,
	},
	{
		name: "routing-instances",
		hier: `routing-instances {
    CUSTOMER-A {
        instance-type virtual-router;
        interface ge-0/0/2.0;
        routing-options {
            static {
                route 0.0.0.0/0 next-hop 10.0.30.1;
            }
        }
    }
}`,
	},
	{
		name: "system",
		hier: `system {
    host-name fw-test;
    name-server {
        8.8.8.8;
    }
    login {
        user admin {
            class super-user;
            authentication {
                encrypted-password "$6$abcdef$0123456789";
            }
        }
    }
    services {
        ssh {
            root-login deny;
        }
        netconf {
            ssh;
        }
    }
    syslog {
        host 10.0.1.50 {
            any warning;
            port 514;
        }
        file messages {
            any notice;
        }
    }
}`,
	},
	{
		// Junos name-server is multi-valued; the green system case
		// carries a single entry, this one isolates the multi case.
		name: "system-name-server-multi",
		hier: `system {
    name-server {
        8.8.8.8;
        2001:4860:4860::8888;
    }
}`,
		// Fixed in U5b (#1810): name-server is multi in setSchema, so
		// SetPath appends distinct values instead of replacing.
		expectedFail: false,
	},
	{
		name: "chassis-cluster",
		hier: `chassis {
    cluster {
        reth-count 2;
        redundancy-group 0 {
            node 0 priority 100;
            node 1 priority 1;
        }
        redundancy-group 1 {
            node 0 priority 100;
            node 1 priority 1;
            gratuitous-arp-count 8;
            interface-monitor {
                ge-0/0/1 weight 255;
            }
        }
    }
}`,
	},
	{
		name: "forwarding-options-sampling",
		hier: `forwarding-options {
    sampling {
        instance sample-1 {
            input {
                rate 10;
            }
            family inet {
                output {
                    flow-server 192.168.99.104 {
                        port 4739;
                        version9-template v9-tmpl;
                        source-address 192.168.99.1;
                    }
                    inline-jflow;
                }
            }
        }
    }
}
services {
    flow-monitoring {
        version9 {
            template v9-tmpl {
                flow-active-timeout 60;
                flow-inactive-timeout 15;
            }
        }
    }
}`,
	},
	{
		name: "forwarding-options-dhcp-relay",
		hier: `forwarding-options {
    dhcp-relay {
        server-group {
            sg1 {
                10.1.1.1;
                10.1.1.2;
            }
        }
        group lan {
            active-server-group sg1;
            interface ge-0/0/0.0;
            interface ge-0/0/1.0;
        }
    }
}`,
		// Fixed in U5b (#1797): dhcp-relay subtree added to setSchema and
		// compileDHCPRelay also reads inline Keys-encoded properties.
		expectedFail: false,
	},
	{
		// Braced block spelling: `interface { a; b; }` holds one child
		// per interface (AGY review on PR #1813 — nodeVal's Children[0]
		// fallback compiled 1 interface hierarchically vs 2 flat, a real
		// dual-AST divergence).
		name: "forwarding-options-dhcp-relay-interface-block",
		hier: `forwarding-options {
    dhcp-relay {
        server-group {
            sg1 {
                10.1.1.1;
            }
        }
        group lan {
            active-server-group sg1;
            interface {
                ge-0/0/0.0;
                ge-0/0/1.0;
            }
        }
    }
}`,
		expectedFail: false,
	},
	{
		// #2076: `overrides always-broadcast` must survive BOTH AST shapes
		// and must NOT be swallowed into the interface list by the inline
		// flat-set consumer. compileDHCPRelay added `overrides` to the
		// interface boundary set and parses the override from both Keys and
		// Children.
		name: "forwarding-options-dhcp-relay-overrides",
		hier: `forwarding-options {
    dhcp-relay {
        server-group {
            sg1 {
                10.1.1.1;
            }
        }
        group lan {
            active-server-group sg1;
            interface ge-0/0/0.0;
            overrides {
                always-broadcast;
            }
        }
    }
}`,
		expectedFail: false,
	},
	{
		name: "protocols-ospf-bgp",
		hier: `protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/1.0;
            interface ge-0/0/2.0 {
                passive;
            }
        }
    }
    bgp {
        group upstream {
            type external;
            peer-as 65000;
            neighbor 172.16.50.1;
        }
    }
}`,
	},
}

// TestDualASTDifferential is the harness entry point. See the file
// header comment for the mechanism.
func TestDualASTDifferential(t *testing.T) {
	var unexpectedFailures []string

	for _, tc := range dualASTCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			failure := runDualASTCase(t, tc)

			if tc.expectedFail {
				if failure == "" {
					t.Fatalf("expectedFail case %q PASSED — the dual-AST gap (%s) "+
						"appears fixed; flip its expectedFail marker to false (U5b contract)",
						tc.name, tc.reason)
				}
				if tc.failureClass != "" && !strings.Contains(failure, tc.failureClass) {
					t.Fatalf("expectedFail case %q failed with the WRONG class — "+
						"expected class %q, got:\n%s\nA different failure class "+
						"means a NEW defect is hiding behind the marker (AGY r1).",
						tc.name, tc.failureClass, failure)
				}
				t.Logf("expected dual-AST failure (tracked: %s):\n%s", tc.reason, failure)
				return
			}

			if failure != "" {
				unexpectedFailures = append(unexpectedFailures, tc.name)
				t.Errorf("dual-AST divergence:\n%s", failure)
			}
		})
	}

	if len(unexpectedFailures) > 0 {
		t.Logf("unexpected dual-AST divergences (U5b work-order candidates): %v",
			unexpectedFailures)
	}
}

// runDualASTCase executes the differential pipeline for one fixture and
// returns "" on success or a human-readable failure description. Fixture
// authoring bugs (hierarchical text that fails to parse or compile) abort
// via t.Fatalf — they are harness defects, not dual-AST findings.
func runDualASTCase(t *testing.T, tc dualASTCase) string {
	t.Helper()

	// Step 1: parse the hierarchical reference shape.
	hierTree, errs := NewParser(tc.hier).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture bug: hierarchical parse errors: %v", errs)
	}

	// Step 2: render to flat-set lines.
	setText := hierTree.FormatSet()
	if strings.TrimSpace(setText) == "" {
		t.Fatalf("fixture bug: FormatSet produced no set lines")
	}

	// Step 3: replay each set line through ParseSetCommand + SetPath.
	flatTree := &ConfigTree{}
	for _, line := range strings.Split(setText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		path, err := ParseSetCommand(line)
		if err != nil {
			return fmt.Sprintf("set-replay failure class: ParseSetCommand(%q): %v", line, err)
		}
		if err := flatTree.SetPath(path); err != nil {
			return fmt.Sprintf("set-replay failure class: SetPath(%q): %v", line, err)
		}
	}

	// Step 4: sanity gate — canonical FormatSet of both trees must agree
	// BEFORE compiling, so generator (FormatSet/SetPath) infidelity is
	// reported as its own failure class and cannot masquerade as a
	// compiler dual-AST bug.
	hierSet := hierTree.FormatSet()
	flatSet := flatTree.FormatSet()
	if hierSet != flatSet {
		if sortedLines(hierSet) == sortedLines(flatSet) {
			// Ordering-only differences are semantically equivalent set
			// programs (SetPath merges repeated/split containers). Warn
			// for visibility and continue to the compiler diff — the
			// actual oracle. Failing here would false-fail legitimate
			// fixtures (AGY r1 on PR #1811).
			t.Logf("note: ordering-only FormatSet round-trip difference (tolerated)")
		} else {
			return fmt.Sprintf("round-trip infidelity (content) failure class: "+
				"FormatSet of re-parsed flat tree differs from hierarchical tree\n"+
				"--- hierarchical FormatSet ---\n%s"+
				"--- flat-replay FormatSet ---\n%s", hierSet, flatSet)
		}
	}

	// Step 5: compile both shapes with the same entry the existing
	// compiler tests use, then deep-compare section by section.
	hierCfg, err := CompileConfig(hierTree)
	if err != nil {
		t.Fatalf("fixture bug: hierarchical CompileConfig: %v", err)
	}
	flatCfg, err := CompileConfig(flatTree)
	if err != nil {
		return fmt.Sprintf("compile-divergence failure class: flat-set tree failed "+
			"CompileConfig while hierarchical compiled: %v", err)
	}

	// Warnings come from map-iteration-order-dependent validators; sort
	// both sides so ordering noise does not register as divergence.
	sort.Strings(hierCfg.Warnings)
	sort.Strings(flatCfg.Warnings)

	if report := diffConfigSections(hierCfg, flatCfg); report != "" {
		return "compiler dual-AST failure class: typed Config differs between " +
			"hierarchical and flat-set compilation\n" + report
	}
	return ""
}

// diffConfigSections compares each top-level Config field separately via
// reflection and returns a per-section report naming every mismatching
// section, or "" when the configs are identical. Iterating the struct
// fields reflectively means new top-level sections are covered
// automatically.
func diffConfigSections(hier, flat *Config) string {
	hv := reflect.ValueOf(*hier)
	fv := reflect.ValueOf(*flat)
	ct := hv.Type()

	var b strings.Builder
	for i := 0; i < ct.NumField(); i++ {
		name := ct.Field(i).Name
		hf := hv.Field(i).Interface()
		ff := fv.Field(i).Interface()
		if !reflect.DeepEqual(hf, ff) {
			fmt.Fprintf(&b, "section %s differs:\n  hierarchical: %+v\n  flat-set:     %+v\n",
				name, hf, ff)
		}
	}
	return b.String()
}

// sortedLines returns the non-empty lines of s sorted lexicographically,
// re-joined — used to distinguish ordering-only round-trip differences
// from content differences.
func sortedLines(s string) string {
	lines := strings.Split(s, "\n")
	out := lines[:0]
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}
