package userspace

import (
	"fmt"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// ZoneIDCollision records one StableZoneID collision the snapshot builder
// resolved by QUARANTINING the later-sorting zone (#3719). Survivor keeps the
// numeric ID and stays installed; Quarantined is dropped from the wire (its
// interfaces are unzoned and its policies removed) so the dataplane never
// receives two zones sharing an id. Both names fold to ID.
type ZoneIDCollision struct {
	ID          uint16
	Survivor    string
	Quarantined string
}

// String renders a ZoneIDCollision for the operator alarm and status output.
func (c ZoneIDCollision) String() string {
	return fmt.Sprintf(
		"zone %q QUARANTINED: StableZoneID %d collides with zone %q — rename one zone (#3719)",
		c.Quarantined, c.ID, c.Survivor)
}

// quarantineCollidingZones enforces the StableZoneID zone-isolation invariant on
// a built snapshot: it removes every zone whose numeric id collides with an
// earlier-sorting zone's id, UNZONES any interface bound to a quarantined zone,
// and DROPS any policy whose from/to zone is quarantined, so the published
// snapshot is internally consistent and the dataplane never receives two zones
// that share an id (#3719). Publishing both would merge two security zones — the
// Rust id-keyed maps (zone_id_to_name / zone_host_inbound / zone_tcp_rst) would
// have the later zone overwrite the earlier's reverse name, host-inbound set,
// and tcp-rst bit, and both zones' interfaces/policies would resolve to one id.
//
// The strict commit path REJECTS a collision (config.validateZoneIDCollisionAST,
// #3075). This is the fail-closed backstop for the LENIENT path — a tolerant
// load, an HA config-sync from an un-upgraded peer, or a config a pre-#3075
// binary persisted with no collision check. It preserves the #1960 no-brick
// intent: only the later-sorting colliding zone is dropped; the rest of the
// config still loads. Dropping the zone but LEAVING its policies would trip the
// Rust helper's UnresolvableZoneReference preflight and reject the WHOLE snapshot
// (a brick on a fresh boot), so the scrub is coordinated across zones,
// interfaces, and policies.
//
// The quarantine set is config.QuarantinedZoneNames over the snapshot's own zone
// names — a pure function of the name set, so both HA nodes and a cold-booting
// node resolve the identical set. Returns the collisions it resolved, sorted for
// deterministic operator output (nil in the common no-collision case).
func quarantineCollidingZones(snap *ConfigSnapshot) []ZoneIDCollision {
	if snap == nil || len(snap.Zones) < 2 {
		return nil
	}
	names := make([]string, 0, len(snap.Zones))
	for _, z := range snap.Zones {
		names = append(names, z.Name)
	}
	quarantined := config.QuarantinedZoneNames(names)
	if len(quarantined) == 0 {
		return nil
	}
	collisions := make([]ZoneIDCollision, 0, len(quarantined))
	kept := snap.Zones[:0]
	for _, z := range snap.Zones {
		if _, drop := quarantined[z.Name]; drop {
			collisions = append(collisions, ZoneIDCollision{
				ID:          z.ID,
				Survivor:    config.StableZoneIDOwner(names, z.ID),
				Quarantined: z.Name,
			})
			continue
		}
		kept = append(kept, z)
	}
	snap.Zones = kept
	// Unzone interfaces bound to a quarantined zone. An unzoned interface
	// matches no zone policy -> default-deny (fail closed), and it removes the
	// dangling interface->zone reference from the snapshot.
	//
	// Lifeline note (#3719 review, secondary): if the operator's management zone
	// happens to be the later-sorting collider it is quarantined and its
	// interfaces are unzoned. This does NOT strand management, because lifeline
	// interfaces (fxp0/em0/fab*) never reach the AF_XDP local-delivery
	// classifier (#3682) — their host-bound traffic is served by the kernel
	// path regardless of zone — and the loud operator alarm names both zones. We
	// deliberately keep the quarantine loser purely a function of the sorted
	// name (HA-symmetric, and reused by the reverse-map callers that have no
	// lifeline context) rather than making it lifeline-aware.
	for i := range snap.Interfaces {
		if _, drop := quarantined[snap.Interfaces[i].Zone]; drop {
			snap.Interfaces[i].Zone = ""
		}
	}
	// Drop policies whose from/to zone is quarantined so the snapshot carries no
	// dangling policy->zone reference (which the Rust UnresolvableZoneReference
	// preflight would reject wholesale — a whole-snapshot brick on a fresh boot,
	// the exact failure this quarantine exists to prevent). This MUST include a
	// scoped GLOBAL policy's out-of-band match-zone: a global rule keeps
	// FromZone/ToZone == "junos-global" (never quarantined) but carries its
	// concrete `match from-zone`/`to-zone` in MatchFromZone/MatchToZone (#3148,
	// policies.go). The Rust build_global_zone_scope resolves those against the
	// published zone table for EVERY rule, so a global policy scoped to a
	// quarantined zone would leave a dangling match-zone and brick the snapshot
	// (#3719 review). Empty ("" — the zone-pair case) and "junos-global" are
	// never keys in the quarantine set, so they never match here.
	if len(snap.Policies) > 0 {
		refsQuarantinedZone := func(p PolicyRuleSnapshot) bool {
			for _, z := range [...]string{p.FromZone, p.ToZone, p.MatchFromZone, p.MatchToZone} {
				if _, drop := quarantined[z]; drop {
					return true
				}
			}
			return false
		}
		keptPol := snap.Policies[:0]
		for _, p := range snap.Policies {
			if refsQuarantinedZone(p) {
				continue
			}
			keptPol = append(keptPol, p)
		}
		snap.Policies = keptPol
	}
	sort.Slice(collisions, func(i, j int) bool {
		if collisions[i].ID != collisions[j].ID {
			return collisions[i].ID < collisions[j].ID
		}
		return collisions[i].Quarantined < collisions[j].Quarantined
	})
	return collisions
}
