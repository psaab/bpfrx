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
// and scrubs quarantined zones out of policies — DROPPING a rule whose
// structurally-required zone (a zone-pair FromZone/ToZone, or a scoped-global
// match side left with no surviving member) is quarantined, but PRUNING only the
// colliding member(s) from a scoped-global's plural match-zone SET so a deny
// scoped to several zones SURVIVES for the members that did not collide (#5577,
// fail-closed). The published snapshot is thus internally consistent and the
// dataplane never receives two zones that share an id (#3719). Publishing both
// would merge two security zones — the
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
	// Scrub quarantined zones out of policies so the snapshot carries no dangling
	// policy->zone reference (which the Rust UnresolvableZoneReference preflight
	// would reject wholesale — a whole-snapshot brick on a fresh boot, the exact
	// failure this quarantine exists to prevent). Two cases, treated differently:
	//
	//  1. A STRUCTURALLY-REQUIRED zone is quarantined -> DROP the whole rule. This
	//     is the singular FromZone/ToZone of a zone-pair policy (a rule from/to a
	//     quarantined zone can no longer be applied), OR a scoped-global match side
	//     that is CONFIGURED but has NO surviving member after pruning (every
	//     member collided — leaving the side empty would silently BROADEN the rule
	//     to all zones, a fail-open in the opposite direction). Empty ("" — the
	//     zone-pair case) and "junos-global" are never quarantine keys.
	//
	//  2. A scoped-GLOBAL policy's match-zone context is a zone SET (#4626 M03,
	//     plural MatchFromZones/MatchToZones; singular kept for back-compat). When
	//     only SOME members collide, PRUNE the quarantined member(s) and KEEP the
	//     rule scoped to the survivors. Dropping the whole rule because one member
	//     collides is FAIL-OPEN: a global deny scoped from [z174, z214] where only
	//     z214 collides would vanish entirely, so still-valid z174 traffic no
	//     longer hits the deny and reaches a later/default permit while the
	//     snapshot publishes successfully (#5577). Unzoning z214 makes that member
	//     irrelevant; it does not make retained-z174 traffic irrelevant. After
	//     pruning we regenerate the SINGULAR MatchFromZone/MatchToZone from the
	//     surviving set (config.ScopeSingular) so an old Rust helper that reads
	//     only the singular field also sees a surviving, non-quarantined zone —
	//     never the dropped one (which would re-introduce the dangling reference).
	if len(snap.Policies) > 0 {
		isQuarantined := func(z string) bool {
			_, drop := quarantined[z]
			return drop
		}
		// pruneQuarantined returns a NEW slice with quarantined names removed. It
		// must not compact in place: MatchFromZones/MatchToZones alias the source
		// config's pol.Match slices (policies_lower.go), so in-place mutation would
		// corrupt the live config. This path is a cold fail-closed backstop, so the
		// per-rule allocation is immaterial.
		pruneQuarantined := func(zs []string) []string {
			out := make([]string, 0, len(zs))
			for _, z := range zs {
				if !isQuarantined(z) {
					out = append(out, z)
				}
			}
			return out
		}
		keptPol := snap.Policies[:0]
		for _, p := range snap.Policies {
			// Case 1a: a zone-pair rule's required endpoint is quarantined.
			if isQuarantined(p.FromZone) || isQuarantined(p.ToZone) {
				continue
			}
			drop := false
			// Case 2 / 1b: prune each configured scoped-global match side; drop the
			// rule only if a configured side is emptied by the prune.
			if from := p.effectiveMatchFromZones(); len(from) > 0 {
				kept := pruneQuarantined(from)
				if len(kept) == 0 {
					drop = true
				} else {
					p.MatchFromZones = kept
					p.MatchFromZone = config.ScopeSingular(kept)
				}
			}
			if !drop {
				if to := p.effectiveMatchToZones(); len(to) > 0 {
					kept := pruneQuarantined(to)
					if len(kept) == 0 {
						drop = true
					} else {
						p.MatchToZones = kept
						p.MatchToZone = config.ScopeSingular(kept)
					}
				}
			}
			if drop {
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
