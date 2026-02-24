package ra

import "golang.org/x/net/ipv6"

// ipv6Filter wraps ipv6.ICMPFilter for convenience.
type ipv6Filter struct {
	f ipv6.ICMPFilter
}

// setAllowRS configures the filter to block all ICMPv6 types except
// Router Solicitation (type 133).
func (f *ipv6Filter) setAllowRS() {
	f.f.SetAll(true) // Block all.
	f.f.Accept(ipv6.ICMPTypeRouterSolicitation)
}

// filter returns the underlying ipv6.ICMPFilter.
func (f *ipv6Filter) filter() *ipv6.ICMPFilter {
	return &f.f
}
