package flowexport

import "hash/fnv"

// stableExporterID maps an exporter group's config identity
// (protocol, sampling-instance name, referenced template name) to a
// stable, nonzero 32-bit id used as the NetFlow v9 header SourceID
// (RFC 3954 §5.1) and the IPFIX header Observation Domain ID
// (RFC 7011 §3.1). It mirrors config.StableTunnelEndpointID / #1873:
// FNV-1a 64 over "protocol|instance|template", xor-folded to 32 bits,
// mapped into [1, 0xFFFFFFFF].
//
// WHY (#3740): the resolvers start one exporter per (instance,
// template) group (ResolveV9TemplateGroups / ResolveIPFIXTemplateGroups),
// but every exporter previously stamped SourceID / ObservationID = 1.
// Two groups pointed at the SAME collector then present an identical RFC
// decode key — (exporter source IP, SourceID/ODID, templateID) — with
// template IDs 256/257 shared too, so the collector sees template
// redefinitions and two interleaved sequence streams under one domain
// (false loss / restart reports). A unique per-group id restores the
// RFC scoping key; template IDs 256/257 can stay conventional because
// 256 under ODID-A is a different template from 256 under ODID-B.
//
// HA symmetry (the load-bearing constraint): flow export is NOT gated on
// RG mastership — both cluster nodes run exporters from the same synced
// config. Because the id is a pure function of config-synced fields
// (protocol/instance/template) and of NOTHING node-specific, both nodes
// compute the IDENTICAL id for a given group, so a failover never
// presents the collector a new observation domain. This is the same
// HA-symmetry argument #1873 relies on, satisfied by construction.
//
// The protocol tag ("netflow9" vs "ipfix") is folded in so a v9 group
// and an IPFIX group with the same instance/template never share a value
// (belt-and-braces; a flow-server binds one version per #2136, so they
// never actually co-point).
//
// Degenerate-default guard: a hand-built ExportConfig{} (the singular
// Build* helpers and several unit tests) carries no instance AND no
// template. That truly-degenerate single-default deployment keeps the
// historical SourceID/ODID = 1 (some collectors treat ODID 0 specially,
// and this preserves the pre-#3740 wire for the unnamed default). Real
// multi-group configs always carry a non-empty InstanceName (sampling
// instances are named), so they always get distinct hashed ids.
func stableExporterID(protocol, instance, template string) uint32 {
	if instance == "" && template == "" {
		return 1
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(protocol))
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write([]byte(instance))
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write([]byte(template))
	s := h.Sum64()
	folded := uint32(s) ^ uint32(s>>32)
	return folded%0xFFFFFFFF + 1
}
