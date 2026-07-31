// #6532 invariant: NO fabric-allowlisted RPC may render a configured operator
// secret verbatim.
//
// The cluster-fabric gRPC listener is the only network-exposed gRPC surface
// (#4122). Its allowlist admits a small set of read/monitor RPCs, which means
// every one of them is reachable from the peer chassis over the fabric IP —
// not merely from loopback. ShowText{Topic:"snmp"} was rendering the SNMPv1/v2c
// community (the v1/v2c authenticator) in cleartext there long after the REST
// (#5315) and CLI (#4111) siblings were hardened, precisely because nothing
// asserted the property across the surface as a whole.
//
// This file asserts it as a property, not per-RPC:
//
//   - TestNoFabricAllowlistedRPCRendersAConfiguredSecret stages one config
//     carrying every secret leaf in the redaction SSOT (pkg/config
//     secretIndices / ast_redact.go), drives every allowlisted RPC, and scans
//     the rendered responses for the cleartext sentinels. The method set is
//     ENUMERATED from the live allowlist maps and the interceptor source — not
//     hardcoded — so a newly-allowlisted RPC fails the completeness gate until
//     it is explicitly audited.
//
//   - TestShowTextTopicAuditCoverageIsComplete extracts the ShowText topic set
//     from the dispatcher source so a newly-added topic must be added to the
//     audit sweep, rather than silently escaping it.
//
//   - TestGRPCAPINeverRevealsSecretCleartext pins the structural reason the
//     sweep finds only one class of leak: every operator secret except the SNMP
//     community is a config.Secret, whose String() masks it under %s/%v, and
//     pkg/grpcapi never calls the Reveal() cleartext accessor that would opt
//     out of that. This covers the render paths the sweep cannot drive
//     in-process (a nil dataplane / IPsec manager / FRR short-circuits some
//     renderers before they format anything).
package grpcapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// fabricSecretConfig stages one instance of every secret leaf the redaction
// SSOT recognises (pkg/config/ast_redact.go secretIndices), each with a
// distinctive cleartext sentinel. It mirrors pkg/config's redactionSecretSet.
//
// The VRRP `authentication-key` leaf from that set is deliberately absent: the
// commit gate REJECTS it outright (#4288 — RFC 5798 VRRPv3 removed
// authentication), so it cannot exist in an active config and staging it makes
// Commit() fail rather than exercising a render.
var fabricSecretConfig = []string{
	"set security ike policy pol1 pre-shared-key ascii-text FAB6532-IKE-PSK",
	"set security ipsec vpn site-a pre-shared-key FAB6532-IPSEC-VPN-PSK",
	"set protocols ospf area 0.0.0.0 interface ge-0-0-1 authentication md5 1 key FAB6532-OSPF-MD5KEY",
	"set protocols ospf area 0.0.0.0 interface ge-0-0-9 authentication simple-password FAB6532-OSPF-SIMPLE",
	"set protocols rip authentication-key FAB6532-RIP-AUTHKEY",
	"set protocols isis authentication-key FAB6532-ISIS-AREA-AUTHKEY",
	"set protocols isis interface ge-0-0-2 authentication-key FAB6532-ISIS-IFACE-AUTHKEY",
	"set protocols bgp group external authentication-key FAB6532-BGP-AUTHPW",
	"set system services web-management api-auth user admin password FAB6532-API-USER-PW",
	"set system services web-management api-auth api-key FAB6532-API-KEY-TOKEN",
	"set snmp v3 usm local-engine user admin authentication-sha256 authentication-password FAB6532-SNMPV3-AUTHPW",
	"set snmp v3 usm local-engine user admin privacy-des privacy-password FAB6532-SNMPV3-PRIVPW",
	"set snmp community FAB6532-SNMP-COMMUNITY authorization read-only",
	"set system services dhcp-local-server dynamic-dns tsig-secret FAB6532-TSIG-SECRET",
	"set system services dynamic-dns provider cf backend cloudflare",
	"set system services dynamic-dns provider cf api-token FAB6532-DDNS-APITOKEN",
	"set system services dynamic-dns provider r53 backend route53",
	"set system services dynamic-dns provider r53 aws-secret-key FAB6532-DDNS-AWSSECRET",
	"set system services dynamic-dns provider dy backend dyndns2",
	"set system services dynamic-dns provider dy password FAB6532-DDNS-HTTP-PW",
	"set interfaces wg0 tunnel wireguard private-key FAB6532-WG-PRIVKEY",
	"set interfaces wg0 tunnel wireguard peer p1 preshared-key FAB6532-WG-PSK",
	`set system root-authentication encrypted-password "$6$FABr$rootHASH6532rootHASH"`,
	`set system login user op authentication encrypted-password "$6$FABl$loginHASH6532loginHASH"`,
}

// fabricSecretSentinels is the cleartext token of each staged secret. Any of
// these appearing in a fabric-reachable render is a credential disclosure.
var fabricSecretSentinels = []string{
	"FAB6532-IKE-PSK", "FAB6532-IPSEC-VPN-PSK", "FAB6532-OSPF-MD5KEY",
	"FAB6532-OSPF-SIMPLE", "FAB6532-RIP-AUTHKEY", "FAB6532-ISIS-AREA-AUTHKEY",
	"FAB6532-ISIS-IFACE-AUTHKEY", "FAB6532-BGP-AUTHPW", "FAB6532-API-USER-PW",
	"FAB6532-API-KEY-TOKEN", "FAB6532-SNMPV3-AUTHPW", "FAB6532-SNMPV3-PRIVPW",
	"FAB6532-SNMP-COMMUNITY", "FAB6532-TSIG-SECRET", "FAB6532-DDNS-APITOKEN",
	"FAB6532-DDNS-AWSSECRET", "FAB6532-DDNS-HTTP-PW", "FAB6532-WG-PRIVKEY",
	"FAB6532-WG-PSK", "rootHASH6532rootHASH", "loginHASH6532loginHASH",
}

// showTextAuditTopics is the ShowText topic sweep. Every topic the dispatcher
// accepts must appear here — TestShowTextTopicAuditCoverageIsComplete derives
// the accepted set from the dispatcher source and fails on any omission.
// Parameterized (prefix:) topics carry a representative argument.
var showTextAuditTopics = []string{
	"address-book", "alarms", "alg", "application-identification-status",
	"applications", "backup-router", "bfd-peers", "buffers", "buffers-detail",
	"chassis", "chassis-cluster", "chassis-cluster-control-plane-statistics",
	"chassis-cluster-data-plane-fairness", "chassis-cluster-data-plane-flows",
	"chassis-cluster-data-plane-interfaces", "chassis-cluster-data-plane-statistics",
	"chassis-cluster-fabric-statistics", "chassis-cluster-information",
	"chassis-cluster-interfaces", "chassis-cluster-ip-monitoring-status",
	"chassis-cluster-statistics", "chassis-cluster-status", "chassis-device-map",
	"chassis-device-map-candidates", "chassis-environment", "chassis-forwarding",
	"chassis-hardware", "commit-history", "core-dumps", "dhcp-relay",
	"dhcp-server", "dhcp-server-detail", "dhcp-server-dynamic-dns",
	"dhcp-server-dynamic-dns-detail", "dynamic-address", "event-options",
	"firewall", "flow-monitoring", "flow-monitoring-statistics",
	"flow-statistics", "flow-timeouts", "flow-traceoptions", "forwarding-options",
	"forwarding-options-port-mirroring", "ike", "interfaces-detail",
	"interfaces-extensive", "interfaces-statistics", "internet-options",
	"ipsec-statistics", "ipv6-router-advertisement", "lldp", "lldp-neighbors",
	"log", "login", "nat64", "nat-dest-rule-detail", "nat-nptv6",
	"nat-source-rule-detail", "nat-static", "ntp", "persistent-nat",
	"persistent-nat-detail", "policies-detail", "policies-hit-count",
	"policy-options", "root-authentication", "route-all", "route-detail",
	"route-instance", "route-map", "route-summary", "route-terse",
	"routing-instances", "routing-instances-detail", "routing-options", "rpm",
	"schedulers", "screen", "security-alarms", "security-alarms-detail",
	"security-log", "services-dynamic-dns", "services-dynamic-dns-detail",
	"services-ip-monitoring-status", "sessions-top:bytes", "sessions-top:packets",
	"snmp", "snmp-v3", "storage", "system-services", "system-syslog", "task",
	"tunnels", "version", "vlans", "wireguard", "wireguard-detail",
	"wireguard-public-key", "zones-detail",

	// Topics matched by equality outside the main switch.
	"class-of-service", "cos-classifier", "cos-forwarding-class",
	"cos-scheduler-map", "firewall-effective", "interfaces-queue",
	"monitor-security-flow", "screen-statistics-all",

	// Parameterized topics, with a representative argument each.
	"class-of-service:ge-0-0-1", "cos-classifier:c1", "cos-scheduler-map:m1",
	"firewall-effective:inet", "firewall-effective-filter:f1",
	"firewall-filter:f1", "interfaces-queue:ge-0-0-1", "log:messages",
	"route-prefix:10.0.0.0/24", "route-protocol:bgp", "route-table:inet.0",
	"screen-ids-option:z", "screen-ids-option-detail:z", "screen-statistics:z",
	"test-policy:from=a,to=b", "test-routing:dest=10.0.0.0/24",
	"test-zone:interface=ge-0-0-1",
}

// fabricRPCProbe is how one fabric-reachable RPC gets audited. Exactly one of
// the two fields is set.
type fabricRPCProbe struct {
	// render drives the RPC and returns every string it emits (response bodies
	// AND error strings — an error message can leak a config value too).
	render func(t *testing.T, s *Server) []string

	// structuralOnly documents why an RPC cannot be driven in-process and what
	// covers it instead. Set only when render is nil.
	structuralOnly string
}

// fabricRPCProbes registers one probe per fabric-reachable RPC. The
// completeness gate in TestNoFabricAllowlistedRPCRendersAConfiguredSecret
// requires an entry for every method the fabric interceptors admit, so
// allowlisting a new RPC fails this file until someone audits it.
func fabricRPCProbes() map[string]fabricRPCProbe {
	return map[string]fabricRPCProbe{
		pb.BpfrxService_ShowText_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				out := make([]string, 0, len(showTextAuditTopics))
				for _, topic := range showTextAuditTopics {
					resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
					if err != nil {
						out = append(out, fmt.Sprintf("topic=%s err=%v", topic, err))
						continue
					}
					out = append(out, fmt.Sprintf("topic=%s\n%s", topic, resp.Output))
				}
				return out
			},
		},
		pb.BpfrxService_GetStatus_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.GetStatus(context.Background(), &pb.GetStatusRequest{})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_GetSessions_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_GetSessionSummary_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_GetZonePairSummary_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_ClearSessions_FullMethodName: {
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_SystemAction_FullMethodName: {
			// Not in fabricAllowedUnaryMethods — admitted by the separate
			// isFabricSafeSystemAction branch for the two cross-node
			// cluster-failover forms only. Audited because it IS fabric
			// reachable; the failover response carries RG ownership state, no
			// config render.
			render: func(t *testing.T, s *Server) []string {
				resp, err := s.SystemAction(context.Background(),
					&pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
				return []string{fmt.Sprintf("%v|%v", resp, err)}
			},
		},
		pb.BpfrxService_MonitorInterface_FullMethodName: {
			// Streams live pcap frames captured off a kernel interface; it
			// renders no configuration, and driving it in-process would exec a
			// real capture. Its config reads are interface-name resolution
			// (ResolveReth / LookupInterface), which touch no secret leaf.
			// Covered structurally by TestGRPCAPINeverRevealsSecretCleartext:
			// a secret can only escape a config.Secret field via Reveal(), and
			// this package has no such call.
			structuralOnly: "streams kernel pcap frames; renders no config. " +
				"Covered by TestGRPCAPINeverRevealsSecretCleartext.",
		},
	}
}

// newFabricSecretServer commits fabricSecretConfig and returns a Server over
// it. The dataplane / IPsec / FRR dependencies stay nil, matching the other
// pkg/grpcapi render tests: the config-render paths under audit read the typed
// active config, not those subsystems.
func newFabricSecretServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet(strings.Join(fabricSecretConfig, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return &Server{store: store}
}

// fabricAdmittedMethods enumerates every method the fabric interceptors can
// admit: the two allowlist maps plus any method the interceptor source
// special-cases by name (today: SystemAction, via isFabricSafeSystemAction).
// Reading the interceptor source closes the hole a map-only enumeration would
// leave — a second special-cased admission would otherwise escape the audit.
func fabricAdmittedMethods(t *testing.T) map[string]bool {
	t.Helper()
	admitted := map[string]bool{}
	for m := range fabricAllowedUnaryMethods {
		admitted[m] = true
	}
	for m := range fabricAllowedStreamMethods {
		admitted[m] = true
	}
	for _, m := range methodsNamedInInterceptors(t) {
		admitted[m] = true
	}
	return admitted
}

// interceptorSrc is the file holding the fabric allowlist interceptors.
const interceptorSrc = "server.go"

// methodsNamedInInterceptors returns the full method names referenced inside
// the two fabric allowlist interceptor bodies.
func methodsNamedInInterceptors(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile(interceptorSrc)
	if err != nil {
		t.Fatalf("read %s (the fabric interceptors moved? update interceptorSrc): %v",
			interceptorSrc, err)
	}
	var out []string
	for _, fn := range []string{
		"func (s *Server) fabricAllowlistUnaryInterceptor(",
		"func (s *Server) fabricAllowlistStreamInterceptor(",
	} {
		body := funcBody(t, string(src), fn)
		for _, m := range regexp.MustCompile(`pb\.BpfrxService_(\w+)_FullMethodName`).FindAllStringSubmatch(body, -1) {
			out = append(out, "/xpf.v1.BpfrxService/"+m[1])
		}
	}
	return out
}

// funcBody returns the source text of the function whose declaration starts
// with decl, up to the closing brace in column 0.
func funcBody(t *testing.T, src, decl string) string {
	t.Helper()
	i := strings.Index(src, decl)
	if i < 0 {
		t.Fatalf("%s: cannot find %q — the fabric interceptors were renamed or "+
			"moved; update this test so the audit keeps enumerating them",
			interceptorSrc, decl)
	}
	rest := src[i:]
	if end := strings.Index(rest, "\n}\n"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// TestFabricSecretStagingIsReal guards the sweep against the worst failure
// mode of a "no secret appeared" assertion: passing because nothing was ever
// staged. A `set` line that the compiler silently drops (renamed leaf, changed
// grammar) would make every downstream scan vacuously green. Assert every
// sentinel is really in the committed active config, in cleartext, BEFORE
// trusting an absence downstream.
func TestFabricSecretStagingIsReal(t *testing.T) {
	s := newFabricSecretServer(t)
	active := s.store.ShowActive()
	for _, sentinel := range fabricSecretSentinels {
		if !strings.Contains(active, sentinel) {
			t.Errorf("secret sentinel %q is NOT in the committed active config — the "+
				"staging `set` line was dropped, so every scan for it downstream is "+
				"vacuous. Fix fabricSecretConfig.", sentinel)
		}
	}
	if n := len(fabricSecretSentinels); n < 20 {
		t.Errorf("only %d secret sentinels staged; the redaction SSOT "+
			"(pkg/config/ast_redact.go secretIndices) covers more — the sweep has "+
			"lost coverage", n)
	}
}

// TestNoFabricAllowlistedRPCRendersAConfiguredSecret is the #6532 invariant:
// drive every fabric-reachable RPC against a config carrying every secret leaf
// and assert no cleartext credential reaches the wire. It goes RED against
// pre-fix code (ShowText{snmp} emits the community).
//
// Its inputs are proven real by TestFabricSecretStagingIsReal above.
func TestNoFabricAllowlistedRPCRendersAConfiguredSecret(t *testing.T) {
	probes := fabricRPCProbes()

	// Completeness gate: a newly-allowlisted RPC must be audited, not silently
	// admitted. This is why the method set is enumerated, not hardcoded.
	for method := range fabricAdmittedMethods(t) {
		if _, ok := probes[method]; !ok {
			t.Fatalf("fabric-reachable RPC %s has no secret-render probe. It is "+
				"admitted on the network-exposed cluster-fabric listener, so it must "+
				"be audited for configured-secret renders (#6532): add an entry to "+
				"fabricRPCProbes.", method)
		}
	}

	s := newFabricSecretServer(t)
	for method, probe := range probes {
		if probe.render == nil {
			if probe.structuralOnly == "" {
				t.Errorf("probe %s has neither a render func nor a structuralOnly "+
					"rationale", method)
			}
			continue
		}
		t.Run(strings.TrimPrefix(method, "/xpf.v1.BpfrxService/"), func(t *testing.T) {
			for _, out := range probe.render(t, s) {
				for _, leak := range fabricSecretSentinels {
					if strings.Contains(out, leak) {
						t.Errorf("%s rendered the cleartext secret %q on the "+
							"network-exposed fabric surface (#6532):\n%s", method, leak, out)
					}
				}
			}
		})
	}
}

// TestShowTextTopicAuditCoverageIsComplete derives the topic set the ShowText
// dispatcher accepts from its source and asserts the audit sweep drives every
// one. Adding a topic that renders a secret without adding it here would
// otherwise slip past the sweep above.
func TestShowTextTopicAuditCoverageIsComplete(t *testing.T) {
	driven := map[string]bool{}
	for _, topic := range showTextAuditTopics {
		driven[topic] = true
		// A parameterized topic is driven as "prefix:arg"; record the bare
		// prefix form too so the source-derived "prefix:" matches it.
		if i := strings.Index(topic, ":"); i >= 0 {
			driven[topic[:i+1]] = true
		}
	}

	for _, topic := range dispatcherTopics(t) {
		if !driven[topic] {
			t.Errorf("ShowText topic %q is dispatched but not driven by the #6532 "+
				"fabric secret-render audit. ShowText is on the cluster-fabric "+
				"allowlist (#4122), so every topic it renders is reachable from the "+
				"peer chassis: add %q to showTextAuditTopics.", topic, topic)
		}
	}
}

// dispatcherTopics extracts every topic literal the ShowText dispatcher
// accepts: the `case` labels of its topic switch (server_show.go holds exactly
// one switch, `switch req.Topic`) plus the equality and prefix tests spread
// across the package's non-test sources.
func dispatcherTopics(t *testing.T) []string {
	t.Helper()

	src, err := os.ReadFile("server_show.go")
	if err != nil {
		t.Fatalf("read server_show.go (the ShowText dispatcher moved? update this "+
			"test so topic coverage keeps being enforced): %v", err)
	}
	if n := strings.Count(string(src), "\tswitch "); n != 1 {
		t.Fatalf("server_show.go has %d switch statements, expected exactly 1 "+
			"(`switch req.Topic`). The case-label extraction below is only "+
			"unambiguous while that holds — update this test.", n)
	}

	var topics []string
	caseRe := regexp.MustCompile(`(?m)^\tcase (.+):$`)
	strRe := regexp.MustCompile(`"([^"]+)"`)
	for _, m := range caseRe.FindAllStringSubmatch(string(src), -1) {
		for _, lit := range strRe.FindAllStringSubmatch(m[1], -1) {
			topics = append(topics, lit[1])
		}
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	topicRe := regexp.MustCompile(`req\.Topic == "([^"]+)"|HasPrefix\(req\.Topic, "([^"]+)"\)`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range topicRe.FindAllStringSubmatch(string(b), -1) {
			if m[1] != "" {
				topics = append(topics, m[1])
			}
			if m[2] != "" {
				topics = append(topics, m[2])
			}
		}
	}

	if len(topics) < 50 {
		t.Fatalf("extracted only %d ShowText topics from source — the dispatcher "+
			"shape changed and this audit is no longer enumerating it", len(topics))
	}
	return topics
}

// TestGRPCAPINeverRevealsSecretCleartext pins the structural property the audit
// above rests on. Every operator secret in the config tree except the SNMP
// community is a config.Secret, whose String() renders "<redacted>" under
// %s/%v (#2053) — so a text renderer cannot leak one by accident. The ONE way
// to defeat that is Reveal(), the explicit cleartext accessor. This package,
// which serves the network-exposed fabric listener, must never call it.
//
// This also covers the renderers the in-process sweep cannot fully drive
// (wireguard / ipsec-statistics / bfd-peers short-circuit on a nil dataplane,
// IPsec manager or FRR before formatting anything).
func TestGRPCAPINeverRevealsSecretCleartext(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		scanned++
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, ".Reveal()") {
				t.Errorf("%s:%d calls the config.Secret cleartext accessor Reveal() "+
					"on the gRPC surface. pkg/grpcapi serves the network-exposed "+
					"cluster-fabric listener (#4122); revealing a secret here risks "+
					"rendering it to the peer chassis (#6532). If a cleartext secret "+
					"is genuinely required, keep it off every render path and "+
					"document it here:\n\t%s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no package sources — the glob is wrong and this guard is vacuous")
	}
}
