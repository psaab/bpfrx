package config

import (
	"fmt"
	"strconv"
	"strings"
)

var supportedRPMProbeTypes = map[string]struct{}{
	DefaultRPMProbeType: {},
	"tcp-ping":          {},
	"http-get":          {},
}

func parseRPMPositiveInt(probeName, testName, field, raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("services rpm probe %q test %q %s: invalid integer %q", probeName, testName, field, raw)
	}
	if n <= 0 {
		return 0, fmt.Errorf("services rpm probe %q test %q %s: must be > 0", probeName, testName, field)
	}
	return n, nil
}

func parseRPMRootPositiveInt(field, raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("services rpm %s: invalid integer %q", field, raw)
	}
	if n <= 0 {
		return 0, fmt.Errorf("services rpm %s: must be > 0", field)
	}
	return n, nil
}

func validateRPMTest(probeName string, test *RPMTest) error {
	if test.Target == "" {
		return fmt.Errorf("services rpm probe %q test %q: target is required", probeName, test.Name)
	}
	if _, ok := supportedRPMProbeTypes[test.EffectiveProbeType()]; !ok {
		return fmt.Errorf(
			"services rpm probe %q test %q: unsupported probe-type %q (want icmp-ping, tcp-ping, or http-get)",
			probeName, test.Name, test.ProbeType,
		)
	}
	if test.DestPort > 65535 {
		return fmt.Errorf("services rpm probe %q test %q destination-port: must be 1-65535", probeName, test.Name)
	}
	return nil
}

func compileDHCPLocalServer(node *Node, dhcp *DHCPServerConfig, isV6 bool) error {
	lsc := &DHCPLocalServerConfig{
		Groups: make(map[string]*DHCPServerGroup),
	}
	if isV6 {
		dhcp.DHCPv6LocalServer = lsc
	} else {
		dhcp.DHCPLocalServer = lsc
	}

	for _, groupInst := range namedInstances(node.FindChildren("group")) {
		group := &DHCPServerGroup{Name: groupInst.name}

		for _, prop := range groupInst.node.Children {
			switch prop.Name() {
			case "interface":
				if v := nodeVal(prop); v != "" {
					group.Interfaces = append(group.Interfaces, v)
				}
			case "pool":
				poolName := nodeVal(prop)
				if poolName != "" {
					pool := &DHCPPool{Name: poolName}
					poolChildren := prop.Children
					if len(prop.Keys) < 2 && len(prop.Children) > 0 {
						poolChildren = prop.Children[0].Children
					}
					for _, pp := range poolChildren {
						switch pp.Name() {
						case "address-range":
							if len(pp.Keys) >= 5 && pp.Keys[1] == "low" && pp.Keys[3] == "high" {
								pool.RangeLow = pp.Keys[2]
								pool.RangeHigh = pp.Keys[4]
							}
						case "subnet":
							pool.Subnet = nodeVal(pp)
						case "router":
							pool.Router = nodeVal(pp)
						case "dns-server":
							if v := nodeVal(pp); v != "" {
								pool.DNSServers = append(pool.DNSServers, v)
							}
						case "lease-time":
							if v := nodeVal(pp); v != "" {
								if n, err := strconv.Atoi(v); err == nil {
									pool.LeaseTime = n
								}
							}
						case "domain-name":
							pool.Domain = nodeVal(pp)
						}
					}
					group.Pools = append(group.Pools, pool)
				}
			}
		}

		lsc.Groups[group.Name] = group
	}
	return nil
}

func compileDynamicAddress(node *Node, sec *SecurityConfig) error {
	if sec.DynamicAddress.FeedServers == nil {
		sec.DynamicAddress.FeedServers = make(map[string]*FeedServer)
	}
	if sec.DynamicAddress.AddressBindings == nil {
		sec.DynamicAddress.AddressBindings = make(map[string]*AddressBinding)
	}

	for _, inst := range namedInstances(node.FindChildren("feed-server")) {
		fs := &FeedServer{Name: inst.name}

		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "url":
				fs.URL = nodeVal(prop)
			case "hostname":
				fs.Hostname = nodeVal(prop)
			case "update-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						fs.UpdateInterval = n
					}
				}
			case "hold-interval":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						fs.HoldInterval = n
					}
				}
			case "feed-name":
				fnName := nodeVal(prop)
				if len(prop.Children) > 0 {
					fe := FeedEntry{Name: fnName}
					for _, c := range prop.Children {
						if c.Name() == "path" {
							fe.Path = nodeVal(c)
						}
					}
					fs.FeedEntries = append(fs.FeedEntries, fe)
				} else {
					fs.FeedName = fnName
				}
			}
		}

		sec.DynamicAddress.FeedServers[fs.Name] = fs
	}

	for _, inst := range namedInstances(node.FindChildren("address-name")) {
		ab := &AddressBinding{Name: inst.name}
		if profile := inst.node.FindChild("profile"); profile != nil {
			for _, c := range profile.Children {
				if c.Name() == "feed-name" {
					if fn := nodeVal(c); fn != "" {
						ab.FeedNames = append(ab.FeedNames, fn)
					}
				}
			}
		}
		sec.DynamicAddress.AddressBindings[ab.Name] = ab
	}

	return nil
}

func compileServices(node *Node, svc *ServicesConfig) error {
	if fmNode := node.FindChild("flow-monitoring"); fmNode != nil {
		if err := compileFlowMonitoring(fmNode, svc); err != nil {
			return err
		}
	}
	if rpmNode := node.FindChild("rpm"); rpmNode != nil {
		if err := compileRPM(rpmNode, svc); err != nil {
			return err
		}
	}
	if node.FindChild("application-identification") != nil {
		svc.ApplicationIdentification = true
	}
	return nil
}

func compileRPM(node *Node, svc *ServicesConfig) error {
	rpmCfg := &RPMConfig{Probes: make(map[string]*RPMProbe)}
	defaultProbeLimit := 0

	if probeLimitNode := node.FindChild("probe-limit"); probeLimitNode != nil {
		if v := nodeVal(probeLimitNode); v != "" {
			n, err := parseRPMRootPositiveInt("probe-limit", v)
			if err != nil {
				return err
			}
			defaultProbeLimit = n
		}
	}

	for _, probeInst := range namedInstances(node.FindChildren("probe")) {
		probe := &RPMProbe{
			Name:  probeInst.name,
			Tests: make(map[string]*RPMTest),
		}

		for _, testInst := range namedInstances(probeInst.node.FindChildren("test")) {
			test := &RPMTest{Name: testInst.name}

			for _, prop := range testInst.node.Children {
				switch prop.Name() {
				case "probe-type":
					test.ProbeType = nodeVal(prop)
				case "target":
					// Handle both "target 1.1.1.1;" and "target url http://1.1.1.1;"
					if len(prop.Keys) >= 3 && prop.Keys[1] == "url" {
						test.Target = prop.Keys[2]
					} else if urlChild := prop.FindChild("url"); urlChild != nil {
						test.Target = nodeVal(urlChild)
					} else {
						test.Target = nodeVal(prop)
					}
				case "source-address":
					test.SourceAddress = nodeVal(prop)
				case "routing-instance":
					test.RoutingInstance = nodeVal(prop)
				case "probe-interval":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "probe-interval", v)
						if err != nil {
							return err
						}
						test.ProbeInterval = n
					}
				case "probe-count":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "probe-count", v)
						if err != nil {
							return err
						}
						test.ProbeCount = n
					}
				case "test-interval":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "test-interval", v)
						if err != nil {
							return err
						}
						test.TestInterval = n
					}
				case "thresholds":
					for _, th := range prop.Children {
						if th.Name() == "successive-loss" {
							if v := nodeVal(th); v != "" {
								n, err := parseRPMPositiveInt(probe.Name, test.Name, "thresholds successive-loss", v)
								if err != nil {
									return err
								}
								test.ThresholdSuccessive = n
							}
						}
					}
				case "probe-limit":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "probe-limit", v)
						if err != nil {
							return err
						}
						test.ProbeLimit = n
					}
				case "destination-port":
					if v := nodeVal(prop); v != "" {
						n, err := parseRPMPositiveInt(probe.Name, test.Name, "destination-port", v)
						if err != nil {
							return err
						}
						test.DestPort = n
					}
				}
			}

			if test.ProbeLimit == 0 && defaultProbeLimit > 0 {
				test.ProbeLimit = defaultProbeLimit
			}

			if err := validateRPMTest(probe.Name, test); err != nil {
				return err
			}

			probe.Tests[test.Name] = test
		}

		rpmCfg.Probes[probe.Name] = probe
	}

	svc.RPM = rpmCfg
	return nil
}

func compileFlowMonitoring(node *Node, svc *ServicesConfig) error {
	fm := &FlowMonitoringConfig{}

	if v9Node := node.FindChild("version9"); v9Node != nil {
		v9cfg := &NetFlowV9Config{
			Templates: make(map[string]*NetFlowV9Template),
		}
		for _, tmplInst := range namedInstances(v9Node.FindChildren("template")) {
			tmpl := &NetFlowV9Template{Name: tmplInst.name}
			for _, prop := range tmplInst.node.Children {
				switch prop.Name() {
				case "flow-active-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowActiveTimeout = n
						}
					}
				case "flow-inactive-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowInactiveTimeout = n
						}
					}
				case "template-refresh-rate":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.TemplateRefreshRate = n
						}
					}
					if secNode := prop.FindChild("seconds"); secNode != nil {
						if v := nodeVal(secNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tmpl.TemplateRefreshRate = n
							}
						}
					}
				case "ipv4-template", "ipv6-template":
					tmpl.ExportExtensions = append(tmpl.ExportExtensions, parseExportExtensions(prop)...)
				}
			}
			if err := rejectUnsupportedFlowExportExtensions("version9", tmpl.Name, tmpl.ExportExtensions); err != nil {
				return err
			}
			v9cfg.Templates[tmpl.Name] = tmpl
		}
		fm.Version9 = v9cfg
	}

	if ipfixNode := node.FindChild("version-ipfix"); ipfixNode != nil {
		ipfixCfg := &NetFlowIPFIXConfig{
			Templates: make(map[string]*NetFlowIPFIXTemplate),
		}
		for _, tmplInst := range namedInstances(ipfixNode.FindChildren("template")) {
			tmpl := &NetFlowIPFIXTemplate{Name: tmplInst.name}
			for _, prop := range tmplInst.node.Children {
				switch prop.Name() {
				case "flow-active-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowActiveTimeout = n
						}
					}
				case "flow-inactive-timeout":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.FlowInactiveTimeout = n
						}
					}
				case "template-refresh-rate":
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							tmpl.TemplateRefreshRate = n
						}
					}
					if secNode := prop.FindChild("seconds"); secNode != nil {
						if v := nodeVal(secNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								tmpl.TemplateRefreshRate = n
							}
						}
					}
				case "ipv4-template", "ipv6-template":
					tmpl.ExportExtensions = append(tmpl.ExportExtensions, parseExportExtensions(prop)...)
				}
			}
			if err := rejectUnsupportedFlowExportExtensions("version-ipfix", tmpl.Name, tmpl.ExportExtensions); err != nil {
				return err
			}
			ipfixCfg.Templates[tmpl.Name] = tmpl
		}
		fm.VersionIPFIX = ipfixCfg
	}

	svc.FlowMonitoring = fm
	return nil
}

func rejectUnsupportedFlowExportExtensions(kind, name string, exts []string) error {
	for _, ext := range exts {
		if ext == "app-id" {
			return fmt.Errorf("services flow-monitoring %s template %q: export-extension app-id unsupported", kind, name)
		}
	}
	return nil
}

func compileForwardingOptions(node *Node, fo *ForwardingOptionsConfig) error {
	sampNode := node.FindChild("sampling")
	if sampNode != nil {
		if err := compileSampling(sampNode, fo); err != nil {
			return err
		}
	}

	relayNode := node.FindChild("dhcp-relay")
	if relayNode != nil {
		if err := compileDHCPRelay(relayNode, fo); err != nil {
			return err
		}
	}

	// Parse family { inet6 { mode <flow-based|packet-based> } }
	if famNode := node.FindChild("family"); famNode != nil {
		if inet6Node := famNode.FindChild("inet6"); inet6Node != nil {
			if modeNode := inet6Node.FindChild("mode"); modeNode != nil {
				fo.FamilyInet6Mode = nodeVal(modeNode)
			}
		}
	}

	if pmNode := node.FindChild("port-mirroring"); pmNode != nil {
		if err := compilePortMirroring(pmNode, fo); err != nil {
			return err
		}
	}

	return nil
}

func compilePortMirroring(node *Node, fo *ForwardingOptionsConfig) error {
	pm := &PortMirroringConfig{
		Instances: make(map[string]*PortMirrorInstance),
	}

	for _, inst := range namedInstances(node.FindChildren("instance")) {
		mi := &PortMirrorInstance{Name: inst.name}

		if inputNode := inst.node.FindChild("input"); inputNode != nil {
			if rateNode := inputNode.FindChild("rate"); rateNode != nil {
				if v := nodeVal(rateNode); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						mi.InputRate = n
					}
				}
			}
			if ingressNode := inputNode.FindChild("ingress"); ingressNode != nil {
				for _, child := range ingressNode.Children {
					if child.Name() == "interface" {
						if v := nodeVal(child); v != "" {
							mi.Input = append(mi.Input, v)
						}
					}
				}
			}
		}

		if outputNode := inst.node.FindChild("output"); outputNode != nil {
			if ifNode := outputNode.FindChild("interface"); ifNode != nil {
				mi.Output = nodeVal(ifNode)
			}
		}

		pm.Instances[mi.Name] = mi
	}

	fo.PortMirroring = pm
	return nil
}

func compileSampling(node *Node, fo *ForwardingOptionsConfig) error {
	sc := &SamplingConfig{
		Instances: make(map[string]*SamplingInstance),
	}

	for _, sampInst := range namedInstances(node.FindChildren("instance")) {
		inst := &SamplingInstance{Name: sampInst.name}

		inputNode := sampInst.node.FindChild("input")
		if inputNode != nil {
			for _, prop := range inputNode.Children {
				if prop.Name() == "rate" {
					if v := nodeVal(prop); v != "" {
						if n, err := strconv.Atoi(v); err == nil {
							inst.InputRate = n
						}
					}
				}
			}
		}

		for _, familyNode := range sampInst.node.FindChildren("family") {
			var afNodes []*Node
			if len(familyNode.Keys) >= 2 {
				afNodes = append(afNodes, familyNode)
			} else {
				afNodes = append(afNodes, familyNode.Children...)
			}
			for _, afNode := range afNodes {
				afName := afNode.Keys[0]
				if len(afNode.Keys) >= 2 {
					afName = afNode.Keys[1]
				}

				sf := compileSamplingFamily(afNode)
				switch afName {
				case "inet":
					inst.FamilyInet = sf
				case "inet6":
					inst.FamilyInet6 = sf
				}
			}
		}

		sc.Instances[inst.Name] = inst
	}

	fo.Sampling = sc
	return nil
}

func compileSamplingFamily(node *Node) *SamplingFamily {
	sf := &SamplingFamily{}

	outputNode := node.FindChild("output")
	if outputNode == nil {
		return sf
	}

	for _, child := range outputNode.Children {
		switch child.Name() {
		case "flow-server":
			fsAddr := nodeVal(child)
			if fsAddr != "" {
				fs := &FlowServer{Address: fsAddr}
				fsChildren := child.Children
				if len(child.Keys) < 2 && len(child.Children) > 0 {
					fsChildren = child.Children[0].Children
				}
				for _, prop := range fsChildren {
					switch prop.Name() {
					case "port":
						if v := nodeVal(prop); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								fs.Port = n
							}
						}
					case "version9-template":
						fs.Version9Template = nodeVal(prop)
					case "version9":
						// Hierarchical: version9 { template { <name>; } }
						if tmplNode := prop.FindChild("template"); tmplNode != nil {
							// Template name is either nodeVal or first child's name
							if v := nodeVal(tmplNode); v != "" {
								fs.Version9Template = v
							} else if len(tmplNode.Children) > 0 {
								fs.Version9Template = tmplNode.Children[0].Name()
							}
						}
					case "source-address":
						sf.SourceAddress = nodeVal(prop)
					}
				}
				sf.FlowServers = append(sf.FlowServers, fs)
			}
		case "inline-jflow":
			sf.InlineJflow = true
			if saNode := child.FindChild("source-address"); saNode != nil {
				sf.InlineJflowSourceAddress = nodeVal(saNode)
			}
			// Also handle inline keys: "inline-jflow source-address X"
			for i := 1; i < len(child.Keys)-1; i++ {
				if child.Keys[i] == "source-address" {
					sf.InlineJflowSourceAddress = child.Keys[i+1]
				}
			}
		}
	}

	return sf
}

func compileDHCPRelay(node *Node, fo *ForwardingOptionsConfig) error {
	relay := &DHCPRelayConfig{
		ServerGroups: make(map[string]*DHCPRelayServerGroup),
		Groups:       make(map[string]*DHCPRelayGroup),
	}

	for _, sgInst := range namedInstances(node.FindChildren("server-group")) {
		sg := &DHCPRelayServerGroup{Name: sgInst.name}
		for _, child := range sgInst.node.Children {
			if len(child.Keys) >= 1 {
				sg.Servers = append(sg.Servers, child.Keys[0])
			}
		}
		relay.ServerGroups[sg.Name] = sg
	}

	for _, gInst := range namedInstances(node.FindChildren("group")) {
		g := &DHCPRelayGroup{Name: gInst.name}
		for _, prop := range gInst.node.Children {
			switch prop.Name() {
			case "interface":
				if v := nodeVal(prop); v != "" {
					g.Interfaces = append(g.Interfaces, v)
				}
			case "active-server-group":
				g.ActiveServerGroup = nodeVal(prop)
			}
		}
		relay.Groups[g.Name] = g
	}

	fo.DHCPRelay = relay
	return nil
}

func compileEventOptions(node *Node, policies *[]*EventPolicy) error {
	for _, pInst := range namedInstances(node.FindChildren("policy")) {
		ep := &EventPolicy{
			Name: pInst.name,
		}

		for _, child := range pInst.node.Children {
			switch child.Name() {
			case "events":
				// Hierarchical: events [ evt1 evt2 ]; → Keys = ["events", "evt1", "evt2"]
				// Hierarchical: events evt1;          → Keys = ["events", "evt1"]
				// Brackets are stripped by the lexer, so just take Keys[1:]
				for i := 1; i < len(child.Keys); i++ {
					ep.Events = append(ep.Events, child.Keys[i])
				}
				// Flat set format: children are individual event name nodes
				for _, evtChild := range child.Children {
					ep.Events = append(ep.Events, evtChild.Name())
				}
			case "within":
				w := &EventWithin{}
				if v := nodeVal(child); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						w.Seconds = n
					}
				}
				if trigNode := child.FindChild("trigger"); trigNode != nil {
					// trigger on N or trigger until N
					for i := 1; i < len(trigNode.Keys)-1; i++ {
						switch trigNode.Keys[i] {
						case "on":
							if n, err := strconv.Atoi(trigNode.Keys[i+1]); err == nil {
								w.TriggerOn = n
							}
						case "until":
							if n, err := strconv.Atoi(trigNode.Keys[i+1]); err == nil {
								w.TriggerUntil = n
							}
						}
					}
					// Also check children
					if onNode := trigNode.FindChild("on"); onNode != nil {
						if v := nodeVal(onNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								w.TriggerOn = n
							}
						}
					}
					if untilNode := trigNode.FindChild("until"); untilNode != nil {
						if v := nodeVal(untilNode); v != "" {
							if n, err := strconv.Atoi(v); err == nil {
								w.TriggerUntil = n
							}
						}
					}
				}
				ep.WithinClauses = append(ep.WithinClauses, w)
			case "attributes-match":
				// Each child is a match line like "ping_test_failed.test-owner matches Comcast"
				for _, amChild := range child.Children {
					// Reconstruct the match expression from keys
					ep.AttributesMatch = append(ep.AttributesMatch, strings.Join(amChild.Keys, " "))
				}
			case "then":
				if ccNode := child.FindChild("change-configuration"); ccNode != nil {
					if cmdsNode := ccNode.FindChild("commands"); cmdsNode != nil {
						for _, cmdChild := range cmdsNode.Children {
							ep.ThenCommands = append(ep.ThenCommands, cmdChild.Name())
						}
					}
				}
			}
		}

		*policies = append(*policies, ep)
	}
	return nil
}

// compileBridgeDomains parses the bridge-domains AST section into typed BridgeDomainConfig structs.
func compileBridgeDomains(node *Node, bds *[]*BridgeDomainConfig) error {
	for _, child := range node.Children {
		if child.IsLeaf {
			continue
		}
		bdName := child.Name()
		bd := &BridgeDomainConfig{
			Name: bdName,
		}

		// Collect VLAN IDs — multi-value leaf: each "vlan-id-list" child is a separate leaf
		for _, vlanNode := range child.FindChildren("vlan-id-list") {
			valStr := nodeVal(vlanNode)
			if valStr == "" {
				continue
			}
			v, err := strconv.Atoi(valStr)
			if err != nil {
				return fmt.Errorf("bridge-domain %s: invalid vlan-id-list value %q: %w", bdName, valStr, err)
			}
			if v < 1 || v > 4094 {
				return fmt.Errorf("bridge-domain %s: vlan-id %d out of range (1-4094)", bdName, v)
			}
			bd.VlanIDs = append(bd.VlanIDs, v)
		}

		// Routing interface (e.g. "irb.0")
		if riNode := child.FindChild("routing-interface"); riNode != nil {
			bd.RoutingInterface = nodeVal(riNode)
		}

		// Domain type
		if dtNode := child.FindChild("domain-type"); dtNode != nil {
			bd.DomainType = nodeVal(dtNode)
		}

		*bds = append(*bds, bd)
	}
	return nil
}
