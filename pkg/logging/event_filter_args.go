package logging

import (
	"fmt"
	"strconv"
	"strings"
)

// EventFilterArgsUsage is the canonical usage string for the
// `show security log` argument grammar, shared by the local CLI and the
// remote `cli` gRPC text path so a parse error reads identically on both.
const EventFilterArgsUsage = "usage: show security log [<count>] [zone <name>] " +
	"[protocol <proto>] [action <action>]"

// ParseEventFilterArgs parses the positional `show security log` arguments
// into an event count (default 50) and an EventFilter. It is the single
// source of truth for that grammar so the local CLI (pkg/cli) and the remote
// `cli` gRPC ShowText path (pkg/grpcapi) cannot drift — before #3547 the
// remote path dropped every non-numeric token and silently dumped all events,
// so a zone filter (including the unknown/none/0 zone-0 selector #3338) was a
// no-op there even though the local CLI honored it.
//
// zoneIDs maps a configured zone name to its dataplane ID, taken from the
// active apply result; haveApply reports whether that result exists at all
// (it is nil during early startup or after a failed apply). A NAMED zone
// filter requires haveApply — refusing rather than dropping the filter and
// widening to every zone's events (M02). The unknown/none/0 sentinels select
// zone 0 (the unassigned / pre-classification zone) without needing the apply
// result, because zone IDs are 1-based and 0 can never collide with a
// configured zone.
//
// Parsing fails CLOSED (#3347): an unknown token, a filter keyword with no
// value, a non-positive count, or an unresolvable named zone is an error, not
// a silently-ignored token that falls through to an unfiltered dump.
func ParseEventFilterArgs(args []string, zoneIDs map[string]uint16, haveApply bool) (int, EventFilter, error) {
	n := 50
	var filter EventFilter
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "zone":
			if i+1 >= len(args) {
				return 0, EventFilter{}, fmt.Errorf("missing value for %q\n%s", "zone", EventFilterArgsUsage)
			}
			i++
			zoneName := args[i]
			switch strings.ToLower(zoneName) {
			case "unknown", "none", "0":
				filter.Zone = 0
				filter.HasZone = true
				continue
			}
			if !haveApply {
				return 0, EventFilter{}, fmt.Errorf("cannot filter by zone %q: no active dataplane apply result "+
					"(zone IDs unavailable — retry after a successful commit)", zoneName)
			}
			zid, ok := zoneIDs[zoneName]
			if !ok {
				return 0, EventFilter{}, fmt.Errorf("zone %q not found", zoneName)
			}
			filter.Zone = zid
			filter.HasZone = true
		case "protocol":
			if i+1 >= len(args) {
				return 0, EventFilter{}, fmt.Errorf("missing value for %q\n%s", "protocol", EventFilterArgsUsage)
			}
			i++
			filter.Protocol = args[i]
		case "action":
			if i+1 >= len(args) {
				return 0, EventFilter{}, fmt.Errorf("missing value for %q\n%s", "action", EventFilterArgsUsage)
			}
			i++
			filter.Action = args[i]
		default:
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return 0, EventFilter{}, fmt.Errorf("unknown argument %q\n%s", args[i], EventFilterArgsUsage)
			}
			if v <= 0 {
				return 0, EventFilter{}, fmt.Errorf("event count must be a positive integer, got %d", v)
			}
			n = v
		}
	}
	return n, filter, nil
}
