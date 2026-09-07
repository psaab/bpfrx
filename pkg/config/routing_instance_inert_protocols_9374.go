package config

import (
	"fmt"
	"sort"
)

// #9374: a routing instance may name a protocol the compiler builds and then
// THROWS AWAY.
//
// `compileRoutingInstances`' `case "protocols"` calls the shared
// `compileProtocols` and copies exactly five fields out of the result —
// OSPF, OSPFv3, BGP, RIP, ISIS. `router-advertisement` and `lldp` are compiled
// into the local `ProtocolsConfig` and go out of scope with it. Measured before
// this change:
//
//	routing-instances { V { instance-type vrf; protocols {
//	    router-advertisement { interface ge-0/0/0.0 { max-advertisement-interval 30; } } } } }
//	  -> STRICT COMMIT ACCEPTS, cfg.Warnings = 0
//	  -> ri.OSPF/OSPFv3/BGP/RIP/ISIS all nil, cfg.Protocols.RouterAdvertisement empty
//	  The stanza compiled to NOTHING, anywhere, and nothing said so.
//
// Unlike the 25 lenient-only rows of #9391, this one is OPERATOR-REACHABLE: the
// strict walk admits it. Per-instance `router-advertisement` is a real Junos
// spelling, so an operator can reasonably write it, `show configuration` renders
// it back, and the box does not send RAs on that instance's interfaces.
//
// THE REMEDY IS A WARNING, NOT A REJECTION. A new commit rejection has
// repo-wide blast radius and would refuse a config that boots and forwards
// today; #1960's doctrine is to keep such a config working and say so. The
// warning reaches `show system commit warnings` through cfg.Warnings.
//
// THE SET IS DERIVED, NOT LISTED. It is every child of the per-instance
// `protocols` node that `schemaRoutingInstanceProtocols` does not declare — and
// that node's membership is bound to the compiler's copy set by
// TestRoutingInstanceProtocolsShareTheGlobalGrammar9351, which reads the
// `ri.X = proto.X` assignments out of the source. So wiring a copy is what
// silences the warning, and adding a protocol the compiler discards is what
// raises it, with no list here to fall out of date.
func inertPerInstanceProtocolWarnings9374(instanceName string, protocolsNode *Node) []string {
	if protocolsNode == nil {
		return nil
	}
	declared := schemaRoutingInstanceProtocols
	if declared == nil || len(declared.children) == 0 {
		// The schema node is what this derives from. If it cannot be read, say
		// nothing rather than warn about everything: a broken lookup must not
		// turn into a screen of warnings on every routing instance.
		return nil
	}
	seen := map[string]bool{}
	var inert []string
	for _, child := range protocolsNode.Children {
		if child == nil || len(child.Keys) == 0 {
			continue
		}
		kw := child.Keys[0]
		if seen[kw] || routingInstanceApplyMetaKeyword9323(kw) {
			continue
		}
		seen[kw] = true
		if declared.children[kw] != nil {
			continue // carried into the instance
		}
		inert = append(inert, kw)
	}
	sort.Strings(inert)
	out := make([]string, 0, len(inert))
	for _, kw := range inert {
		out = append(out, fmt.Sprintf(
			"routing-instance %q protocols %s is ACCEPTED but NOT APPLIED: the compiler "+
				"builds it and copies only OSPF/OSPFv3/BGP/RIP/ISIS into the instance, so "+
				"this stanza configures nothing on this instance or globally — `show "+
				"configuration` still displays it (#9374)",
			instanceName, kw))
	}
	return out
}
