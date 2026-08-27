package userspace

import (
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// FilterTermSyslogMap projects the firewall-filter snapshot into the #6859
// (filter_id, term_id) -> `then syslog` map the event reader gates its syslog
// fan-out on.
//
// WHY IT IS A PROJECTION OF THE SNAPSHOT, not a second walk of cfg. The ids in
// a FILTER_LOG event are positional: the Rust side assigns filter_id from the
// snapshot filter's index and term_id from the term's index within it
// (userspace-dp/src/filter/compiler.rs, parse_filter_table). Any second walk of
// cfg would be a duplicate encoding of that ordering — and a divergence between
// the two is ALWAYS a bug, silently routing one term's hits under another
// term's spelling with nothing failing. So this builds from
// buildFirewallFilterSnapshots, the same function whose output is pushed to the
// dataplane, and the ordering has exactly one source.
//
// The nil-skip in buildFilterTermSnapshots matters here and is inherited for
// free by iterating the built terms rather than cfg's: a nil term is dropped
// from the snapshot, so every later term's index shifts. Walking cfg.Firewall
// directly would key the map off pre-skip indices and mis-attribute every term
// after a nil one.
//
// The result is non-nil even when empty, which is the signal the event reader
// uses to distinguish "wired, and this config has no syslog terms" from "never
// wired" — see EventReader.SetFilterTermSyslog. A nil cfg returns nil, so a
// caller with nothing applied yet leaves the pre-#6859 fan-out in place.
func FilterTermSyslogMap(cfg *config.Config) map[uint64]bool {
	if cfg == nil {
		return nil
	}
	filters := buildFirewallFilterSnapshots(cfg)
	out := make(map[uint64]bool, len(filters))
	for filterIdx, f := range filters {
		for termIdx, t := range f.Terms {
			if !t.Syslog {
				// Only `then syslog` terms need an entry; absent == suppressed.
				continue
			}
			out[logging.FilterTermSyslogKey(uint32(filterIdx), uint32(termIdx))] = true
		}
	}
	return out
}
