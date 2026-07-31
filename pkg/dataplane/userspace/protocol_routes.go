package userspace

type RouteSnapshot struct {
	Table       string   `json:"table"`
	Family      string   `json:"family"`
	Destination string   `json:"destination"`
	NextHops    []string `json:"next_hops,omitempty"`
	Discard     bool     `json:"discard"`
	NextTable   string   `json:"next_table,omitempty"`
	// Preference is the Junos route preference (administrative distance;
	// lower = more preferred, default 5). The Rust FIB tie-breaks two
	// same-prefix routes in a table by preference BEFORE insertion order
	// (#2390); without it, two competing same-prefix statics selected by
	// insertion order, ignoring operator intent. Additive: an old Rust
	// helper ignores it (insertion-order tie-break, the pre-#2390 behavior)
	// and an old Go binary omits it (Rust sees 0, the most-preferred value,
	// which for the common single-route-per-prefix case is a no-op). 0 is a
	// legitimate value (it deserializes back to 0 under serde default), so
	// omitempty only suppresses the wire byte for an explicit preference 0.
	Preference int `json:"preference,omitempty"`
}

type NeighborSnapshot struct {
	Interface string `json:"interface,omitempty"`
	Ifindex   int    `json:"ifindex,omitempty"`
	Family    string `json:"family"`
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	State     string `json:"state,omitempty"`
	Router    bool   `json:"router,omitempty"`
	LinkLocal bool   `json:"link_local,omitempty"`
}
