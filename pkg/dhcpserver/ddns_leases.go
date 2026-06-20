package dhcpserver

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"
)

// ddns_leases.go: a STATE-AWARE Kea memfile lease parser for the #1387
// DDNS reconciler (plan §5 invariant 3). The existing parseLeaseCSV is
// display-only — it has no active/expired filtering, no Kea `state`
// column, and no v6 DUID/IAID identity. Reusing it for DDNS would publish
// or retain stale records, the exact bug this feature is about. This
// parser is separate and intentionally does NOT replace the display one.

// Kea lease state column values (memfile CSV `state`).
const (
	keaStateDefault  = 0 // active
	keaStateDeclined = 1
	keaStateExpired  = 2 // expired-reclaimed
)

// ddnsLease is one active lease as the reconciler needs it: a stable
// owner identity, the address, the offered name(s), the subnet, and the
// expiry. Inactive/expired/declined rows are dropped at parse time.
type ddnsLease struct {
	Family     int // 4 or 6
	Address    string
	Identity   string // v4: client-id||hwaddr ; v6: DUID/IAID
	SubnetID   string
	HostName   string // host-name option
	ClientFQDN string // client-supplied FQDN option (fqdn_fwd implied)
	Expire     int64  // unix epoch
}

// parseActiveLeases4 reads the Kea v4 memfile and returns only active
// leases (state default, not yet expired). now is the reference time for
// the expiry check (injected for tests).
func parseActiveLeases4(path string, now time.Time) ([]ddnsLease, error) {
	return parseActiveLeases(path, 4, now)
}

// parseActiveLeases6 reads the Kea v6 memfile and returns only active
// leases (state default, not yet expired).
func parseActiveLeases6(path string, now time.Time) ([]ddnsLease, error) {
	return parseActiveLeases(path, 6, now)
}

func parseActiveLeases(path string, family int, now time.Time) ([]ddnsLease, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // memfile rows vary across Kea versions
	r.Comment = '#'
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(records) < 2 {
		return nil, nil
	}

	cols := make(map[string]int)
	for i, h := range records[0] {
		cols[h] = i
	}
	get := func(fields []string, name string) string {
		if idx, ok := cols[name]; ok && idx >= 0 && idx < len(fields) {
			return fields[idx]
		}
		return ""
	}

	// Kea appends rows; the LAST row for an address is authoritative (lease
	// renewal / state change). We keep the last seen row per address and
	// emit in first-appearance order. The map value carries the row's final
	// disposition: a non-empty Address is an active lease to publish, an
	// empty (zero) value is a tombstone (the last row was inactive/expired)
	// and is filtered from the output. CRITICAL (#1387 MAJOR-3): an active
	// row must be able to RECLAIM an address that an earlier row tombstoned
	// (declined/expired/reclaimed then re-allocated), so we recompute the
	// disposition on every row and ensure the address is recorded in `order`
	// whenever it first appears, tombstone or not. Output order is stable;
	// the tombstone filter at emit time is what drops still-inactive ones.
	latest := map[string]ddnsLease{}
	order := []string{}
	inOrder := map[string]struct{}{}
	noteAddr := func(addr string) {
		if _, ok := inOrder[addr]; !ok {
			inOrder[addr] = struct{}{}
			order = append(order, addr)
		}
	}
	for _, fields := range records[1:] {
		addr := get(fields, "address")
		if addr == "" {
			continue
		}
		noteAddr(addr)

		// State filter: only "default" (active) rows are publishable;
		// declined / expired-reclaimed rows must NOT have DNS records.
		// An unparseable/absent state is treated as active (Kea's
		// default), matching the display parser's lenient stance.
		if s := get(fields, "state"); s != "" {
			if st, e := strconv.Atoi(s); e == nil && st != keaStateDefault {
				// A non-default state for an address supersedes any earlier
				// row for it: write a tombstone (the address stays in
				// `order` so a LATER active row can reclaim it).
				latest[addr] = ddnsLease{}
				continue
			}
		}

		var expire int64
		if e := get(fields, "expire"); e != "" {
			if v, err := strconv.ParseInt(e, 10, 64); err == nil {
				expire = v
			}
		}
		// Expiry filter: a lease whose expire epoch is in the past is
		// stale regardless of state column lag. Tombstone it (a later
		// active row with a future expire can still reclaim the address).
		if expire > 0 && now.Unix() >= expire {
			latest[addr] = ddnsLease{}
			continue
		}

		hostName, clientFQDN := splitLeaseNames(get(fields, "hostname"), get(fields, "fqdn_fwd"))
		l := ddnsLease{
			Family:     family,
			Address:    addr,
			SubnetID:   get(fields, "subnet_id"),
			HostName:   hostName,
			ClientFQDN: clientFQDN,
			Expire:     expire,
		}
		if family == 6 {
			l.Identity = identity6(get(fields, "duid"), get(fields, "iaid"))
		} else {
			l.Identity = identity4(get(fields, "client_id"), get(fields, "hwaddr"))
		}
		latest[addr] = l
	}

	out := make([]ddnsLease, 0, len(order))
	for _, addr := range order {
		l, ok := latest[addr]
		if !ok || l.Address == "" {
			continue // tombstoned by the FINAL inactive/expired row
		}
		out = append(out, l)
	}
	return out, nil
}

func splitLeaseNames(hostname, fqdnFwd string) (hostName, clientFQDN string) {
	if hostname == "" {
		return "", ""
	}
	if v, err := strconv.Atoi(fqdnFwd); err == nil && v != 0 {
		return "", hostname
	}
	return hostname, ""
}

// identity4 returns the stable v4 owner identity: client-id when present
// (RFC 2131 client identifier survives a NIC swap), else the hardware
// address. Empty inputs yield "" (the lease is then keyed on address
// only by the caller, which still cleans on reassign because the address
// is the reverse key).
func identity4(clientID, hwaddr string) string {
	if clientID != "" {
		return "cid:" + clientID
	}
	if hwaddr != "" {
		return "mac:" + hwaddr
	}
	return ""
}

// identity6 returns the stable v6 owner identity from DUID + IAID.
func identity6(duid, iaid string) string {
	if duid == "" {
		return ""
	}
	if iaid != "" {
		return "duid:" + duid + "/" + iaid
	}
	return "duid:" + duid
}
