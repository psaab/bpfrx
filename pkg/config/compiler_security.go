package config

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

func compileSecurity(node *Node, sec *SecurityConfig) error {
	for _, child := range node.Children {
		switch child.Name() {
		case "zones":
			if err := compileZones(child, sec); err != nil {
				return fmt.Errorf("zones: %w", err)
			}
		case "policies":
			if err := compilePolicies(child, sec); err != nil {
				return fmt.Errorf("policies: %w", err)
			}
		case "screen":
			if err := compileScreen(child, sec); err != nil {
				return fmt.Errorf("screen: %w", err)
			}
		case "nat":
			if err := compileNAT(child, sec); err != nil {
				return fmt.Errorf("nat: %w", err)
			}
		case "address-book":
			if err := compileAddressBook(child, sec); err != nil {
				return fmt.Errorf("address-book: %w", err)
			}
		case "log":
			if err := compileLog(child, sec); err != nil {
				return fmt.Errorf("log: %w", err)
			}
		case "flow":
			if err := compileFlow(child, sec); err != nil {
				return fmt.Errorf("flow: %w", err)
			}
		case "ike":
			if err := compileIKE(child, sec); err != nil {
				return fmt.Errorf("ike: %w", err)
			}
		case "ipsec":
			if err := compileIPsec(child, sec); err != nil {
				return fmt.Errorf("ipsec: %w", err)
			}
		case "dynamic-address":
			if err := compileDynamicAddress(child, sec); err != nil {
				return fmt.Errorf("dynamic-address: %w", err)
			}
		case "alg":
			if err := compileALG(child, sec); err != nil {
				return fmt.Errorf("alg: %w", err)
			}
		case "ssh-known-hosts":
			sec.SSHKnownHosts = make(map[string][]SSHKnownHostKey)
			for _, hostInst := range namedInstances(child.FindChildren("host")) {
				var keys []SSHKnownHostKey
				for _, kp := range hostInst.node.Children {
					name := kp.Name()
					if v := nodeVal(kp); v != "" {
						keys = append(keys, SSHKnownHostKey{Type: name, Key: v})
					}
				}
				sec.SSHKnownHosts[hostInst.name] = keys
			}
		case "policy-stats":
			if sw := child.FindChild("system-wide"); sw != nil {
				sec.PolicyStatsEnabled = nodeVal(sw) == "enable"
			}
		case "pre-id-default-policy":
			sec.PreIDDefaultPolicy = &PreIDDefaultPolicy{}
			// #3850: read EVERY `then {}` block, not just the first via
			// FindChild — a duplicate then block (load merge/override) would
			// otherwise have its session-log modes silently dropped.
			for _, thenNode := range child.FindChildren("then") {
				// #3703: multi-value session-log list leaf. Read every mode via
				// the firewallMatchValues SSOT (Keys[1:] AND/OR one-per-child)
				// across EVERY `log` leaf so a bracket `then log [ session-init
				// session-close ]` keeps BOTH flags AND separate `then log
				// session-init` / `then log session-close` lines (two sibling
				// leaves) both land. The prior single FindChild lookup read only
				// the first leaf and missed the tail (the #2419 collapse bug).
				// Unknown tokens are rejected at commit by SchemaValidate.
				for _, logNode := range thenNode.FindChildren("log") {
					for _, mode := range firewallMatchValues(logNode) {
						switch mode {
						case "session-init":
							sec.PreIDDefaultPolicy.LogSessionInit = true
						case "session-close":
							sec.PreIDDefaultPolicy.LogSessionClose = true
						}
					}
				}
			}
		}
	}
	return nil
}

func compileLog(node *Node, sec *SecurityConfig) error {
	if sec.Log.Streams == nil {
		sec.Log.Streams = make(map[string]*SyslogStream)
	}

	// Top-level log settings
	if modeNode := node.FindChild("mode"); modeNode != nil {
		sec.Log.Mode = nodeVal(modeNode)
	}
	if fmtNode := node.FindChild("format"); fmtNode != nil {
		sec.Log.Format = nodeVal(fmtNode)
	}
	if srcNode := node.FindChild("source-interface"); srcNode != nil {
		sec.Log.SourceInterface = nodeVal(srcNode)
	}
	if node.FindChild("report") != nil {
		sec.Log.Report = true
	}

	for _, inst := range namedInstances(node.FindChildren("stream")) {
		stream := &SyslogStream{
			Name: inst.name,
			Port: 514, // default
		}
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "host":
				// Flat: host 192.168.99.3;
				if v := nodeVal(prop); v != "" {
					stream.Host = v
				}
				// Nested: host { 192.168.99.3; port 9006; }
				for _, hc := range prop.Children {
					switch hc.Name() {
					case "port":
						if v := nodeVal(hc); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								stream.Port = n
							}
						}
					default:
						// IP address as a bare child node
						if stream.Host == "" && len(hc.Keys) >= 1 {
							stream.Host = hc.Keys[0]
						}
					}
				}
			case "port":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						stream.Port = n
					}
				}
			case "severity":
				stream.Severity = nodeVal(prop)
			case "facility":
				stream.Facility = nodeVal(prop)
			case "format":
				stream.Format = nodeVal(prop)
			case "category":
				stream.Category = nodeVal(prop)
			case "source-address":
				stream.SourceAddress = nodeVal(prop)
			case "transport":
				for _, tc := range prop.Children {
					switch tc.Name() {
					case "protocol":
						stream.Transport.Protocol = nodeVal(tc)
					case "tls-profile":
						stream.Transport.TLSProfile = nodeVal(tc)
					}
				}
			}
		}
		if stream.Host != "" {
			sec.Log.Streams[stream.Name] = stream
		}
	}

	// H7 (#2008): `security log profile <name>` log-routing objects. Each
	// names a target stream (`stream-name`), may be marked the default
	// (`default-profile`), and may carry per-category field config. Reads
	// via namedInstances + nodeVal so both hierarchical and flat-set AST
	// shapes work (same as the stream loop). The stream-name cross-
	// reference is enforced after full compile in
	// validateLogProfileStreamReferencesStrict — schema_walk per-leaf
	// validators cannot see sibling stream nodes. `category` is accepted
	// for parse/validation parity; per-category field-extra-name selection
	// is not yet used to alter the emitted structured data (out of scope).
	for _, inst := range namedInstances(node.FindChildren("profile")) {
		p := &LogProfile{Name: inst.name}
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "stream-name":
				p.StreamName = nodeVal(prop)
			case "default-profile":
				p.DefaultProfile = true
			case "category":
				// Accepted for parity; field-extra-name emission is out of
				// scope for this increment (xpf already emits per-stream
				// structured data).
			}
		}
		if sec.Log.Profiles == nil {
			sec.Log.Profiles = make(map[string]*LogProfile)
		}
		sec.Log.Profiles[p.Name] = p
	}
	return nil
}

// validateSecurityLogStreamPortsAST is the #3349 commit-time range gate for
// `security log stream <s> port <p>` and the nested `host { port <p>; }`
// spelling. The syslog port value lives in TWO AST locations — a direct
// `port` child of the stream and a `port` child of a nested `host` block
// (compileLog reads both) — a dual value-location the declarative
// SchemaValidate walker cannot express, the same rationale as tcp-mss
// (validateTCPMSSRanges). compileLog ignores a non-numeric or out-of-range
// port (strconv.Atoi error path) and silently keeps the default 514, so a typo
// such as `port 6514x` commits and quietly logs audit to the wrong port. This
// pass reads the raw tokens before that swallowing and range-checks them.
//
// It mirrors compileLog's traversal exactly (FindChild("log") +
// namedInstances(stream) + per-child switch on host/port) so it validates
// precisely the tokens the compiler consumes. Runs on the group-expanded tree
// so apply-groups-inherited ports are covered.
//
// Strict path (commit / commit-check, lenient=false): a non-numeric or
// out-of-range port is a hard compile error. Lenient path (load / peer-sync,
// lenient=true): downgraded to a warning so an already-persisted or
// peer-synced config that an older binary accepted (and that the compiler
// still maps to 514) still boots (#1960 / #3261 fail-closed-on-load class).
func validateSecurityLogStreamPortsAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	check := func(path, raw string) error {
		if raw == "" {
			// No value token: the compiler keeps the default 514. The
			// missing-value case is the schema walker's concern, not this
			// range gate.
			return nil
		}
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= 65535 {
			return nil
		}
		msg := fmt.Sprintf("%s: invalid syslog port %q (expected an integer in "+
			"[1..65535]; an invalid value silently keeps the default 514)", path, raw)
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}
	for _, n := range nodes {
		if n.Name() != "security" {
			continue
		}
		secPath := joinNodePath(prefix, n.Keys)
		for _, logNode := range n.FindChildren("log") {
			logPath := joinNodePath(secPath, []string{"log"})
			for _, inst := range namedInstances(logNode.FindChildren("stream")) {
				streamPath := joinNodePath(logPath, []string{"stream", inst.name})
				for _, prop := range inst.node.Children {
					switch prop.Name() {
					case "port":
						if err := check(joinNodePath(streamPath, []string{"port"}), nodeVal(prop)); err != nil {
							return warnings, err
						}
					case "host":
						for _, hc := range prop.Children {
							if hc.Name() == "port" {
								if err := check(joinNodePath(streamPath, []string{"host", "port"}), nodeVal(hc)); err != nil {
									return warnings, err
								}
							}
						}
					}
				}
			}
		}
	}
	return warnings, nil
}

// validateSecurityLogStreamTLSProfileAST is the #3350 commit-time gate for
// `security log stream <s> transport tls-profile <name>`. The token is parsed
// (schema_security.go), validated for syntax, and stored on
// stream.Transport.TLSProfile (compileLog) — but it is NEVER resolved into a
// *tls.Config at runtime: daemon_system.go applyLogStreams always passes a nil
// *tls.Config to logging.NewSyslogClientTransport, so the TLS dialer falls back
// to the system CA roots (pkg/logging/syslog.go dialTLS). There is also no
// `tls-profile` DEFINITION stanza anywhere in the config (no local-certificate /
// trusted-ca / SNI source for syslog — only IPsec/IKE define certs), so the
// named profile has nothing to resolve to. An operator who configures
// `tls-profile` believes mutual TLS / a pinned CA is in force when it is not —
// a secure-syslog posture silently downgraded to system roots (a fail-open).
//
// Because the profile can never be honored, this gate REJECTS any
// `transport tls-profile` at commit rather than letting it silently no-op.
// `transport protocol tls` ON ITS OWN is left intact: a TLS stream that trusts
// the system CA roots is a legitimate, fully-honored configuration — only the
// named-but-unapplied profile is rejected.
//
// It descends compileLog's traversal (log + namedInstances(stream) + the
// `transport` child loop) with forEachChild at EVERY container level so it
// gates the token wherever it lives, including a duplicate security/log
// sub-block (#3566, the sub-level sibling of the #3562 duplicate-top-level
// class). Runs on the group-expanded tree so an apply-groups-inherited
// tls-profile is covered.
//
// Strict path (commit / commit-check, lenient=false): a present tls-profile is
// a hard compile error. Lenient path (load / peer-sync, lenient=true):
// downgraded to a warning so an already-persisted or peer-synced config that an
// older binary accepted (and that silently used system roots) still boots
// (#1960 / #3261 fail-closed-on-load class). The runtime behavior is unchanged
// by the lenient downgrade — the profile was never applied either way — so a
// leniently-loaded value is inert, now flagged.
func validateSecurityLogStreamTLSProfileAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	// Descend security > log with forEachChild at EVERY level (and
	// namedInstances over every `stream`) so a tls-profile carried by a stream
	// in a duplicate security/log sub-block is still rejected (#3566); the inner
	// transport / tls-profile checks are unchanged.
	walkErr := forEachChild(nodes, "security", func(n *Node) error {
		secPath := joinNodePath(prefix, n.Keys)
		return forEachChild(n.Children, "log", func(logNode *Node) error {
			logPath := joinNodePath(secPath, []string{"log"})
			for _, inst := range namedInstances(logNode.FindChildren("stream")) {
				streamPath := joinNodePath(logPath, []string{"stream", inst.name})
				for _, prop := range inst.node.Children {
					if prop.Name() != "transport" {
						continue
					}
					for _, tc := range prop.Children {
						if tc.Name() != "tls-profile" {
							continue
						}
						profile := nodeVal(tc)
						path := joinNodePath(streamPath, []string{"transport", "tls-profile"})
						msg := fmt.Sprintf("%s: tls-profile %q is not applied at runtime — "+
							"xpf has no TLS profile definition (certificate / trusted-ca / "+
							"SNI) to resolve it to, so the TLS syslog stream silently falls "+
							"back to the system CA roots instead of the named profile. Remove "+
							"the tls-profile (a `transport protocol tls` stream that trusts the "+
							"system CA roots is honored) until profile resolution is implemented",
							path, profile)
						if lenient {
							warnings = append(warnings, msg)
							continue
						}
						return fmt.Errorf("%s", msg)
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return warnings, walkErr
	}
	return warnings, nil
}

// flowTraceFileNameError reports why an operator-supplied
// `security flow traceoptions file <name>` value is unsafe, or nil if the
// value is an acceptable bare basename. The persistent flow-trace file always
// lives directly under /var/log (NewTraceWriter), so only a bare filename is
// permitted: an absolute path, a path separator, or a "." / ".." component
// would let a committed config steer root-written flow telemetry (internal
// addresses, ports, zones, actions, policy IDs) outside the appliance log area
// — e.g. `file /tmp/x` is kept verbatim and `file ../../tmp/x` cleans to
// /tmp/x (#3420, Codex audit 097 H02). This is the persistent-config sibling
// of the interactive `monitor security flow file` hardening (#3378).
func flowTraceFileNameError(name string) error {
	if name == "" {
		// A missing value token is the schema walker's concern, not this gate.
		return nil
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%q is not a valid trace filename", name)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("trace filename %q must be a bare name, not a path "+
			"(the file is written under /var/log)", name)
	}
	if filepath.IsAbs(name) || name != filepath.Base(name) {
		return fmt.Errorf("trace filename %q must be a bare name, not a path "+
			"(the file is written under /var/log)", name)
	}
	return nil
}

// Flow-trace rotation bounds (#3424). The persistent `security flow
// traceoptions file <name> size <s> files <n>` knob was copied verbatim by the
// compiler with no range check, so a committed `size 1 files 1000000000` made
// every matching trace line exceed the threshold and turned each rotation into
// a ~1e9-iteration rename loop run synchronously from the event callback under
// the writer mutex (a per-event CPU storm). These bounds match the interactive
// `monitor security flow file` limits (pkg/cli/monitor.go) so the persistent
// and on-demand trace paths agree: a minimum size large enough that a normal
// burst of trace lines does not rotate on every write, a 1 GiB ceiling, and a
// small generation count whose rename loop is bounded. They are the single
// source of truth for both the commit-time gate (validateFlowTraceSizeFilesAST)
// and the runtime fail-safe clamp (logging.NewTraceWriter).
const (
	FlowTraceMinFileSize  = 10240      // bytes (10 KiB)
	FlowTraceMaxFileSize  = 1073741824 // bytes (1 GiB)
	FlowTraceMinFileCount = 2
	FlowTraceMaxFileCount = 1000
)

// validateFlowTraceFileAST is the #3420 commit-time path-traversal gate for
// `security flow traceoptions file <name>`. The compiler stores the filename
// verbatim (compileFlow traceoptions: to.File = nodeVal(fileNode)) and
// NewTraceWriter then joins/opens it under /var/log without rejecting an
// absolute path or a ".." escape, so a committed config can append flow trace
// records anywhere the daemon user can write. The filename is a single AST
// value the declarative SchemaValidate walker treats as opaque free text, so —
// like the syslog port and tls-profile gates — it is checked here on the
// group-expanded tree, descending compileFlow's traversal
// (flow > traceoptions > file) with forEachChild at EVERY level so an
// offending value in a duplicate flow/traceoptions/file sub-block is rejected
// (#3566, the sub-level sibling of the #3562 duplicate-top-level class).
//
// Strict path (commit / commit-check, lenient=false): an absolute,
// separator-bearing, or dot-component filename is a hard compile error.
// Lenient path (load / peer-sync, lenient=true): downgraded to a warning so an
// already-persisted or peer-synced config an older binary accepted still boots;
// NewTraceWriter independently refuses the unsafe path at runtime, so a
// leniently-loaded value simply disables tracing rather than writing outside
// /var/log (#1960 / #3261 fail-closed-on-load class).
func validateFlowTraceFileAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	// Descend security > flow > traceoptions > file with forEachChild at EVERY
	// level: the parser appends a repeated block as a sibling, and a first-only
	// FindChild at any level would let an offending `file` value hide in a
	// duplicate flow/traceoptions/file sub-block (#3566). The inner basename
	// check is unchanged.
	walkErr := forEachChild(nodes, "security", func(n *Node) error {
		secPath := joinNodePath(prefix, n.Keys)
		return forEachChild(n.Children, "flow", func(flowNode *Node) error {
			return forEachChild(flowNode.Children, "traceoptions", func(toNode *Node) error {
				return forEachChild(toNode.Children, "file", func(fileNode *Node) error {
					name := nodeVal(fileNode)
					if err := flowTraceFileNameError(name); err != nil {
						path := joinNodePath(secPath, []string{"flow", "traceoptions", "file"})
						msg := fmt.Sprintf("%s: %s", path, err.Error())
						if lenient {
							warnings = append(warnings, msg+
								" (ignored: tracing disabled, not written outside /var/log)")
							return nil
						}
						return fmt.Errorf("%s", msg)
					}
					return nil
				})
			})
		})
	})
	if walkErr != nil {
		return warnings, walkErr
	}
	return warnings, nil
}

// flowTraceImplementedFlags is the set of `security flow traceoptions flag`
// values the persistent trace writer actually honours
// (logging.TraceWriter.matchFlags recognizes exactly these two). Any other
// token is fail-silent at runtime: NewTraceWriter installs it into a non-empty
// flag map, which suppresses the basic-datapath/session defaults, and
// matchFlags then never matches — the daemon reports flow tracing enabled while
// the trace file stays empty (#3422 M02, false evidence during an incident).
// Keep in sync with logging.matchFlags / logging.traceFlagImplemented.
var flowTraceImplementedFlags = map[string]bool{
	"basic-datapath": true,
	"session":        true,
}

// validateFlowTraceFlagsAndFiltersAST is the #3422 commit-time gate for
// `security flow traceoptions { flag <name>; packet-filter <n> { source-prefix
// / destination-prefix <prefix>; } }`. The compiler copies both flag tokens
// (compileFlow: to.Flags = append(...)) and filter prefixes
// (pf.SourcePrefix/DestinationPrefix = nodeVal(...)) verbatim with no
// validation, and the runtime then fails silently in two directions:
//
//   - M01: NewTraceWriter drops a filter whose prefix does not parse, so a
//     config whose every filter is a typo (`source-prefix 10.0.0.999/32`)
//     leaves tw.filters empty and HandleEvent traces EVERYTHING — a filter
//     meant to narrow tracing broadens it.
//   - M02: an unknown flag (`flag sesson`) makes the flag map non-empty,
//     suppressing the defaults, so matchFlags never matches and nothing is
//     traced while the daemon reports tracing enabled.
//
// Both values are single AST leaves SchemaValidate treats as opaque free text,
// so — like the file gate above — they are checked here on the group-expanded
// tree, descending compileFlow's traversal (flow > traceoptions > flag /
// packet-filter children) with forEachChild at EVERY container level so an
// offending stanza in a duplicate flow/traceoptions sub-block is rejected
// (#3566).
//
// Strict path (commit / commit-check, lenient=false): an unparseable
// source/destination prefix or an unimplemented flag is a hard compile error.
// Lenient path (load / peer-sync, lenient=true): downgraded to a warning so an
// already-persisted or peer-synced config an older binary accepted still boots;
// the runtime fixes (NewTraceWriter marks an invalid filter match-none and
// drops an unknown flag so defaults still apply) keep a leniently-loaded value
// fail-safe rather than fail-open (#1960 / #3261 fail-closed-on-load class).
func validateFlowTraceFlagsAndFiltersAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	// Descend security > flow > traceoptions with forEachChild at EVERY level
	// so a flag / packet-filter stanza in a duplicate flow/traceoptions
	// sub-block is still checked (#3566); the inner flag and prefix checks are
	// unchanged.
	walkErr := forEachChild(nodes, "security", func(n *Node) error {
		secPath := joinNodePath(prefix, n.Keys)
		return forEachChild(n.Children, "flow", func(flowNode *Node) error {
			return forEachChild(flowNode.Children, "traceoptions", func(toNode *Node) error {
				toPath := joinNodePath(secPath, []string{"flow", "traceoptions"})

				// flag tokens
				for _, flagNode := range toNode.FindChildren("flag") {
					v := nodeVal(flagNode)
					if v == "" || flowTraceImplementedFlags[v] {
						continue
					}
					path := joinNodePath(toPath, []string{"flag"})
					msg := fmt.Sprintf("%s: unknown flow trace flag %q "+
						"(supported: basic-datapath, session)", path, v)
					if lenient {
						warnings = append(warnings, msg+
							" (ignored: unknown flag dropped, defaults apply)")
						continue
					}
					return fmt.Errorf("%s", msg)
				}

				// packet-filter source/destination prefixes
				for _, pf := range namedInstances(toNode.FindChildren("packet-filter")) {
					pfPath := joinNodePath(toPath, []string{"packet-filter", pf.name})
					for _, leaf := range []string{"source-prefix", "destination-prefix"} {
						pn := pf.node.FindChild(leaf)
						if pn == nil {
							// Absent prefix: a protocol-only filter is legitimate, so
							// leave it alone. This is AST-distinguishable from the
							// present-but-empty case below (node missing vs node
							// present with an empty value).
							continue
						}
						v := nodeVal(pn)
						if v == "" {
							// Present-but-empty (`source-prefix ""`): the node exists
							// but carries no prefix. Accepting it lets the runtime
							// append a fully-unconstrained filter (zero srcNet/dstNet,
							// no proto) that matches EVERY event — the #3422 M01
							// fail-open in a smaller costume. Reject at strict; downgrade
							// to a warning on the lenient load / peer-sync path, where
							// the compiler marks the filter InvalidPrefix and the
							// runtime fails it closed (match-none).
							path := joinNodePath(pfPath, []string{leaf})
							msg := fmt.Sprintf("%s: %s is present but empty; an empty "+
								"prefix would match every event (omit %s for a "+
								"protocol-only filter, or set a CIDR prefix)",
								path, leaf, leaf)
							if lenient {
								warnings = append(warnings, msg+
									" (ignored: filter set to match-none)")
								continue
							}
							return fmt.Errorf("%s", msg)
						}
						if _, err := netip.ParsePrefix(v); err != nil {
							path := joinNodePath(pfPath, []string{leaf})
							msg := fmt.Sprintf("%s: invalid %s %q: %v",
								path, leaf, v, err)
							if lenient {
								warnings = append(warnings, msg+
									" (ignored: filter set to match-none)")
								continue
							}
							return fmt.Errorf("%s", msg)
						}
					}
				}
				return nil
			})
		})
	})
	if walkErr != nil {
		return warnings, walkErr
	}
	return warnings, nil
}

// flowTraceSizeFilesValues extracts the configured `size` and `files` raw
// token strings (and whether each was present) from a
// `security flow traceoptions file <name>` node, across every AST shape the
// parser can produce:
//
//   - single-line hierarchical (`file foo size 100000 files 2;`, NewParser):
//     the tokens land directly in fileNode.Keys[2:].
//   - block hierarchical (`file foo { size 100000; files 2; }`): each token is
//     a separate child node (Keys=["size","100000"], Keys=["files","2"]).
//   - flat set (`set ... file foo size 100000 files 2`): the bracket/flat lexer
//     COLLAPSES the trailing tokens onto ONE child node's Keys
//     (Keys=["size","100000","files","2"]) — the #2419 multi-value-leaf shape.
//
// A single keyword scan over fileNode.Keys[2:] followed by every child node's
// full Keys covers all three: in each shape the `size`/`files` keyword is
// immediately followed by its value in the same Keys slice. The last
// occurrence wins (a child-node value overrides a same-named flat token),
// matching the original compileFlow ordering (children read after the flat
// Keys loop). This is the single source of truth shared by compileFlow (what
// the compiler stores) and validateFlowTraceSizeFilesAST (what the gate
// checks), so the two cannot diverge.
func flowTraceSizeFilesValues(fileNode *Node) (size string, sizeSet bool, files string, filesSet bool) {
	scan := func(keys []string, from int) {
		for i := from; i+1 < len(keys); i++ {
			switch keys[i] {
			case "size":
				size, sizeSet = keys[i+1], true
			case "files":
				files, filesSet = keys[i+1], true
			}
		}
	}
	scan(fileNode.Keys, 2)
	for _, child := range fileNode.Children {
		scan(child.Keys, 0)
	}
	return size, sizeSet, files, filesSet
}

// validateFlowTraceSizeFilesAST is the #3424 commit-time range gate for
// `security flow traceoptions file <name> size <s> files <n>`. The compiler
// (compileFlow) parsed both tokens with strconv.Atoi and stored any positive
// integer with no bounds, so a committed `size 1 files 1000000000` made every
// matching trace line exceed the rotation threshold and turned each rotation
// into a ~1e9-iteration rename loop run synchronously from the event callback
// under the writer mutex — a per-event CPU storm (codex-review-097 M03). Both
// tokens are single AST values SchemaValidate treats as opaque free text and
// live in EITHER the file node's flat Keys[2:] or hierarchical size/files
// children (a dual value-location SchemaValidate cannot express), so — like
// the file/flag/filter gates above — they are range-checked here on the
// group-expanded tree, descending flowTraceSizeFilesValues / compileFlow's
// traversal (flow > traceoptions > file) with forEachChild at EVERY level so a
// duplicate flow/traceoptions/file sub-block cannot hide an out-of-range value
// (#3566).
//
// The bounds (FlowTraceMin/MaxFileSize, FlowTraceMin/MaxFileCount) match the
// interactive `monitor security flow file` limits so the persistent and
// on-demand trace paths agree.
//
// Strict path (commit / commit-check, lenient=false): a non-integer or
// out-of-range size/files is a hard compile error. Lenient path (load /
// peer-sync, lenient=true): downgraded to a warning so an already-persisted or
// peer-synced config an older binary accepted still boots — NewTraceWriter
// clamps an out-of-range value to the same bounds at runtime, so a
// leniently-loaded value cannot trigger the CPU storm (#1960 / #3261
// fail-closed-on-load class).
func validateFlowTraceSizeFilesAST(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	// Descend security > flow > traceoptions > file with forEachChild at EVERY
	// level so an out-of-range size/files in a duplicate flow/traceoptions/file
	// sub-block is range-checked (#3566); the inner bounds checks are unchanged.
	walkErr := forEachChild(nodes, "security", func(n *Node) error {
		secPath := joinNodePath(prefix, n.Keys)
		return forEachChild(n.Children, "flow", func(flowNode *Node) error {
			return forEachChild(flowNode.Children, "traceoptions", func(toNode *Node) error {
				return forEachChild(toNode.Children, "file", func(fileNode *Node) error {
					filePath := joinNodePath(secPath, []string{"flow", "traceoptions", "file"})

					size, sizeSet, files, filesSet := flowTraceSizeFilesValues(fileNode)

					if sizeSet {
						v, err := strconv.ParseInt(size, 10, 64)
						if err != nil || v < FlowTraceMinFileSize || v > FlowTraceMaxFileSize {
							path := joinNodePath(filePath, []string{"size"})
							msg := fmt.Sprintf("%s: invalid trace file size %q "+
								"(must be %d..%d bytes)",
								path, size, FlowTraceMinFileSize, FlowTraceMaxFileSize)
							if lenient {
								warnings = append(warnings, msg+
									" (ignored: clamped to a safe size at runtime)")
							} else {
								return fmt.Errorf("%s", msg)
							}
						}
					}
					if filesSet {
						v, err := strconv.Atoi(files)
						if err != nil || v < FlowTraceMinFileCount || v > FlowTraceMaxFileCount {
							path := joinNodePath(filePath, []string{"files"})
							msg := fmt.Sprintf("%s: invalid trace file count %q "+
								"(must be %d..%d)",
								path, files, FlowTraceMinFileCount, FlowTraceMaxFileCount)
							if lenient {
								warnings = append(warnings, msg+
									" (ignored: clamped to a safe count at runtime)")
							} else {
								return fmt.Errorf("%s", msg)
							}
						}
					}
					return nil
				})
			})
		})
	})
	if walkErr != nil {
		return warnings, walkErr
	}
	return warnings, nil
}

// tcpMSSKinds are the four tcp-mss sub-kinds the compiler reads
// (compileFlow MSS switch). Each carries a u16 MSS value that lands in a
// Rust u16 wire field (TCPMSS{IPsecVPN,GreIn,GreOut}; all-tcp fans out into
// all three) via buildFlowSnapshot (Layer A coerceWireU16, #1977).
var tcpMSSKinds = []string{"ipsec-vpn", "gre-in", "gre-out", "all-tcp"}

// validateTCPMSSRanges is the #1979 Layer-B Tier-3 commit-time range gate
// for `security flow tcp-mss {ipsec-vpn|gre-in|gre-out|all-tcp} <n>`. It is
// the compiler AST pre-walk counterpart of validateVRRPTrackInterfaceAST:
// tcp-mss's MSS value can live in EITHER the kind node's own flat Keys[1]
// (`gre-in 1400`) OR a hierarchical `mss` sub-child (`gre-in { mss 1360; }`),
// a dual value-location the declarative schema walker (SchemaValidate)
// cannot express — so tcp-mss stays OPAQUE in setSchema and is validated
// here instead.
//
// It range-checks the COMPILER-SELECTED token (selectMSSToken, shared with
// parseMSSValue) against [0, 65535] — the same Layer-A bound (coerceWireU16
// out-of-range -> 0). Validating only the selected value means a mixed shape
// like `gre-in 70000 { mss 1360; }` PASSES (the compiler selects the child
// 1360; the flat 70000 is discarded), exactly matching what compileFlow
// reads.
//
// Strict path (commit / commit-check, lenient=false): an out-of-range or
// non-integer selected value is a hard compile error. Lenient path (load /
// peer-sync, lenient=true): it is downgraded to a warning and Layer A coerces
// it — a legacy persisted/peer config carrying `tcp-mss gre-in 70000` (a
// value an older binary accepted) must still boot, exactly like the VRRP
// lenient gate. Runs on the group-expanded tree so apply-groups-inherited
// MSS values are covered.
func validateTCPMSSRanges(nodes []*Node, prefix string, lenient bool) ([]string, error) {
	var warnings []string
	for _, n := range nodes {
		nodePath := joinNodePath(prefix, n.Keys)
		if n.Name() == "security" {
			for _, flow := range n.FindChildren("flow") {
				flowPath := joinNodePath(nodePath, []string{"flow"})
				for _, mss := range flow.FindChildren("tcp-mss") {
					mssPath := joinNodePath(flowPath, []string{"tcp-mss"})
					for _, kind := range tcpMSSKinds {
						for _, kn := range mss.FindChildren(kind) {
							kindPath := joinNodePath(mssPath, []string{kind})
							// #2486: `tcp-mss ipsec-vpn` is rejected at
							// commit. There is no IPsec context in the
							// userspace forward-build path — ESP/AH/IKE is
							// local-delivered to the kernel XFRM stack and the
							// decrypted inner packets re-enter as plain
							// traffic with no IPsec marker — so the clamp can
							// never be enforced. Carrying it silently as dead
							// config (the prior behavior) is worse than
							// rejecting it. Strict (commit/commit-check) is a
							// hard error; lenient (load/peer-sync) downgrades
							// to a warning so a legacy persisted/peer config
							// still boots.
							if kind == "ipsec-vpn" {
								if _, ok := selectMSSToken(kn); ok {
									msg := fmt.Sprintf("%s: tcp-mss ipsec-vpn is not "+
										"supported in the userspace forwarding path "+
										"(IPsec is processed by the kernel XFRM stack, "+
										"so no IPsec context reaches the MSS clamp); "+
										"use 'all-tcp' to clamp all forwarded TCP", kindPath)
									if !lenient {
										return nil, fmt.Errorf("%s", msg)
									}
									warnings = append(warnings, msg+
										" (ignored: clamp not enforced)")
								}
								continue
							}
							w, err := checkTCPMSSKind(kn, kindPath, lenient)
							warnings = append(warnings, w...)
							if err != nil {
								return nil, err
							}
						}
					}
				}
			}
		}
		w, err := validateTCPMSSRanges(n.Children, nodePath, lenient)
		warnings = append(warnings, w...)
		if err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

// checkTCPMSSKind range-checks one tcp-mss kind node's compiler-selected MSS
// value. See validateTCPMSSRanges.
func checkTCPMSSKind(node *Node, nodePath string, lenient bool) ([]string, error) {
	tok, ok := selectMSSToken(node)
	if !ok {
		// No value token in either position — the compiler reads 0 (the
		// "unset" sentinel). Not a range violation; leave it.
		return nil, nil
	}
	if err := ValidateInteger(0, maxWireU16)(tok, nil); err != nil {
		msg := fmt.Sprintf("%s: invalid tcp-mss value: %v", nodePath, err)
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		// Tailor the lenient suffix to the failure kind (Codex/Copilot
		// review). Only a parseable POSITIVE-but-too-large integer reaches
		// Layer A to be clamped (flow.go coerceWireU16) — compileFlow only
		// assigns the MSS when v > 0. A non-integer token OR a negative
		// value yields no MSS: the compiler reads 0 (unset), nothing
		// reaches the dataplane, so "the dataplane coerces it" would
		// mislead. Branch on the parsed value, not just parseability.
		suffix := " (kept; the dataplane coerces it — a strict commit would reject this)"
		if v, perr := strconv.Atoi(tok); perr != nil || v < 0 {
			suffix = " (treated as unset/0 by the compiler — a strict commit would reject this)"
		}
		return []string{msg + suffix}, nil
	}
	return nil, nil
}

func compileFlow(node *Node, sec *SecurityConfig) error {
	// Aggressive session aging
	if agingNode := node.FindChild("aging"); agingNode != nil {
		for _, opt := range agingNode.Children {
			name := opt.Name()
			switch name {
			case "early-ageout", "high-watermark", "low-watermark":
			default:
				// #3440 H2: record an unrecognized aging leaf so
				// validateFlowAgingStrict can reject it at commit instead of
				// the pre-#3440 silent drop (which let `set security flow
				// aging bogus 5` commit cleanly with no effect).
				sec.Flow.AgingUnknownLeaves = append(sec.Flow.AgingUnknownLeaves, name)
				continue
			}
			if len(opt.Keys) < 2 {
				continue
			}
			val, err := strconv.Atoi(opt.Keys[1])
			if err != nil {
				// The schema typed-leaf gate (SchemaValidate) rejects a
				// non-integer / out-of-range value at commit; on the tolerant
				// load path it is left at the zero default (disabled).
				continue
			}
			switch name {
			case "early-ageout":
				sec.Flow.AgingEarlyAgeout = val
			case "high-watermark":
				sec.Flow.AgingHighWatermark = val
			case "low-watermark":
				sec.Flow.AgingLowWatermark = val
			}
		}
	}

	tcpNode := node.FindChild("tcp-session")
	if tcpNode != nil {
		sec.Flow.TCPSession = &TCPSessionConfig{}
		for _, opt := range tcpNode.Children {
			// Handle leaf flags (no value)
			switch opt.Name() {
			case "no-syn-check":
				sec.Flow.TCPSession.NoSynCheck = true
				continue
			case "no-syn-check-in-tunnel":
				sec.Flow.TCPSession.NoSynCheckInTunnel = true
				continue
			case "rst-invalidate-session":
				sec.Flow.TCPSession.RstInvalidateSession = true
				continue
			case "no-sequence-check":
				sec.Flow.TCPSession.NoSequenceCheck = true
				continue
			}
			if len(opt.Keys) < 2 {
				continue
			}
			val, err := strconv.Atoi(opt.Keys[1])
			if err != nil {
				continue
			}
			switch opt.Name() {
			case "established-timeout":
				sec.Flow.TCPSession.EstablishedTimeout = val
			case "initial-timeout":
				sec.Flow.TCPSession.InitialTimeout = val
			case "closing-timeout":
				sec.Flow.TCPSession.ClosingTimeout = val
			case "time-wait-timeout":
				sec.Flow.TCPSession.TimeWaitTimeout = val
			}
		}
	}

	udpNode := node.FindChild("udp-session")
	if udpNode != nil {
		for _, opt := range udpNode.Children {
			if opt.Name() == "timeout" && len(opt.Keys) >= 2 {
				if v, err := strconv.Atoi(opt.Keys[1]); err == nil {
					sec.Flow.UDPSessionTimeout = v
				}
			}
		}
	}

	icmpNode := node.FindChild("icmp-session")
	if icmpNode != nil {
		for _, opt := range icmpNode.Children {
			if opt.Name() == "timeout" && len(opt.Keys) >= 2 {
				if v, err := strconv.Atoi(opt.Keys[1]); err == nil {
					sec.Flow.ICMPSessionTimeout = v
				}
			}
		}
	}

	// TCP MSS clamping
	mssNode := node.FindChild("tcp-mss")
	if mssNode != nil {
		for _, opt := range mssNode.Children {
			switch opt.Name() {
			case "ipsec-vpn":
				// #2486: strict commit rejects this via
				// validateTCPMSSRanges (no IPsec context in the userspace
				// forward path). In lenient load/peer-sync contexts the
				// value IS retained on the typed config below, so `show`
				// output and config round-trip preserve it — but it is
				// NEVER serialized to the dataplane wire (flow.go drops it)
				// and NEVER enforced (no dataplane consumer reads it).
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSIPsecVPN = v
				}
			case "gre-in":
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSGreIn = v
				}
			case "gre-out":
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSGreOut = v
				}
			case "all-tcp":
				// #2486: all-tcp is the context-agnostic clamp — it lands in
				// its own wire field (tcp_mss_all_tcp) and the dataplane
				// applies it to every forwarded TCP SYN (plain + the fallback
				// for gre-in / tunnel egress). Previously it fanned out into
				// IPsecVPN/GreIn/GreOut, but only gre-out was ever enforced,
				// so all-tcp silently behaved as gre-out-only.
				if v := parseMSSValue(opt); v > 0 {
					sec.Flow.TCPMSSAllTCP = v
				}
			}
		}
	}

	// allow-dns-reply
	if node.FindChild("allow-dns-reply") != nil {
		sec.Flow.AllowDNSReply = true
	}

	// allow-embedded-icmp
	if node.FindChild("allow-embedded-icmp") != nil {
		sec.Flow.AllowEmbeddedICMP = true
	}

	// gre-performance-acceleration
	if node.FindChild("gre-performance-acceleration") != nil {
		sec.Flow.GREPerformanceAcceleration = true
	}

	// power-mode-disable
	if node.FindChild("power-mode-disable") != nil {
		sec.Flow.PowerModeDisable = true
	}

	// syn-flood-protection-mode
	if spNode := node.FindChild("syn-flood-protection-mode"); spNode != nil {
		if len(spNode.Keys) >= 2 {
			sec.Flow.SynFloodProtectionMode = spNode.Keys[1]
		}
	}

	// traceoptions
	if toNode := node.FindChild("traceoptions"); toNode != nil {
		to := &FlowTraceoptions{}
		if fileNode := toNode.FindChild("file"); fileNode != nil {
			to.File = nodeVal(fileNode)
			// Read size/files across every AST shape (single-line hierarchical,
			// block hierarchical, and the #2419 flat-set collapsed child). The
			// shared helper is the SSOT with validateFlowTraceSizeFilesAST so the
			// gate checks exactly what is stored here. A non-integer value is left
			// at zero (default applied downstream); the strict commit gate rejects
			// it loudly before reaching here (#3424).
			sizeStr, sizeSet, filesStr, filesSet := flowTraceSizeFilesValues(fileNode)
			if sizeSet {
				if n, err := strconv.Atoi(sizeStr); err == nil {
					to.FileSize = n
				}
			}
			if filesSet {
				if n, err := strconv.Atoi(filesStr); err == nil {
					to.FileCount = n
				}
			}
		}
		for _, flagNode := range toNode.FindChildren("flag") {
			if v := nodeVal(flagNode); v != "" {
				to.Flags = append(to.Flags, v)
			}
		}
		for _, pfInst := range namedInstances(toNode.FindChildren("packet-filter")) {
			pf := &TracePacketFilter{Name: pfInst.name}
			// A prefix node that is PRESENT but empty (`source-prefix ""`) is
			// malformed: an empty prefix is not "no constraint" but a typo that
			// must narrow tracing to nothing, not broaden it to everything
			// (#3422 M01). Record the distinction here (present-but-empty vs the
			// absent protocol-only case) so the runtime can fail it closed; the
			// strict commit gate rejects it outright before it ever lands here.
			if spNode := pfInst.node.FindChild("source-prefix"); spNode != nil {
				pf.SourcePrefix = nodeVal(spNode)
				if pf.SourcePrefix == "" {
					pf.InvalidPrefix = true
				}
			}
			if dpNode := pfInst.node.FindChild("destination-prefix"); dpNode != nil {
				pf.DestinationPrefix = nodeVal(dpNode)
				if pf.DestinationPrefix == "" {
					pf.InvalidPrefix = true
				}
			}
			if protoNode := pfInst.node.FindChild("protocol"); protoNode != nil {
				pf.Protocol = nodeVal(protoNode)
			}
			to.PacketFilters = append(to.PacketFilters, pf)
		}
		sec.Flow.Traceoptions = to
	}

	return nil
}

func compileALG(node *Node, sec *SecurityConfig) error {
	if dnsNode := node.FindChild("dns"); dnsNode != nil {
		if dnsNode.FindChild("disable") != nil {
			sec.ALG.DNSDisable = true
		}
	}
	if ftpNode := node.FindChild("ftp"); ftpNode != nil {
		if ftpNode.FindChild("disable") != nil {
			sec.ALG.FTPDisable = true
		}
	}
	if sipNode := node.FindChild("sip"); sipNode != nil {
		if sipNode.FindChild("disable") != nil {
			sec.ALG.SIPDisable = true
		}
	}
	if tftpNode := node.FindChild("tftp"); tftpNode != nil {
		if tftpNode.FindChild("disable") != nil {
			sec.ALG.TFTPDisable = true
		}
	}
	return nil
}
