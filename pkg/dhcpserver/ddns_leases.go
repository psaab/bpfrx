package dhcpserver

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
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

// requiredLeaseColumns lists, per family, the Kea memfile header columns the
// reconciler MUST be able to read to compute the desired DNS state and run a
// SAFE destructive diff. The mass-delete / record-loss class is NOT specific
// to address/state: ANY column whose absence silently changes whether a lease
// is published, how it is keyed for ownership, or whether it is active is
// destructive, because a mangled header parses with no error and the
// reconciler then deletes owned records on the basis of an empty or
// wrongly-keyed desired set. So the required set covers every such column; if
// any is MISSING from the header the parser returns an error and Reconcile
// marks the family untrusted and SKIPS the destructive diff. The fail
// direction (over-mark-untrusted for an exotic header → no publish/clean,
// operator-visible) is SAFE; silent mass-delete / record-loss is not.
//
// Required (both families):
//   - address  — keys every lease AND is the ownership key fallback; absent ⇒
//     every row reads "" ⇒ empty lease set ⇒ Pass-1 deletes all owned.
//   - state    — separates an active lease from a declined/expired-reclaimed
//     one; absent ⇒ active and tombstoned rows are indistinguishable (a
//     reclaimed/declined address would be published or a publishable one lost).
//   - hostname — the naming source; absent ⇒ deriveFQDN errors for every lease
//     ⇒ all leases skipped as unnamed ⇒ empty desired set ⇒ mass-delete
//     (MAJOR A). An empty hostname VALUE is fine; we require the COLUMN.
//
// Required (v4 identity): client_id AND hwaddr — the ownership key derives
// from client-id||hwaddr; absent ⇒ identity collapses to the address-fallback
// ⇒ owned records keyed by the prior real identity no longer match desired ⇒
// delete + re-add churn; if the delete succeeds and the re-add upsert fails
// the active record is LOST (MAJOR B).
//
// Required (v6 identity): duid AND iaid — same record-loss as v4 for the
// DUID/IAID identity.
//
// Deliberately OPTIONAL (absence degrades safely, no record loss):
//   - fqdn_fwd  — only routes the hostname value into HostName vs ClientFQDN;
//     absent ⇒ splitLeaseNames defaults to host-name semantics, still named.
//   - expire    — absent ⇒ no expiry-based tombstoning (state still gates
//     active-vs-tombstone); over-RETAIN of a stale lease, never a delete.
//   - subnet_id — pure metadata stored on the owned record; recordsEqual does
//     NOT compare it, so its absence changes no destructive computation.
//
// Names are matched case-insensitively (cols keys + get() lookups are
// lower-cased).
var requiredLeaseColumns = map[int][]string{
	4: {"address", "state", "hostname", "client_id", "hwaddr"},
	6: {"address", "state", "hostname", "duid", "iaid"},
}

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

	// Fail-safe (#1387 + Codex r4): the trusted-empty result (nil, nil) is
	// what PERMITS Reconcile to delete a family's owned records, so it must
	// be returned ONLY when we can prove the lease set is genuinely empty —
	// never when the header is unrecognizable. Order matters:
	//
	//   1. An existing-but-0-record file (no header at all) is anomalous —
	//      Kea always writes a header line when it creates the memfile, so a
	//      headerless existing file is a mid-write / truncated / corrupt read.
	//      We cannot validate columns, so fail SAFE (error → untrusted →
	//      Reconcile SKIPS the destructive diff), not trusted-empty. (A
	//      genuinely MISSING file already returned nil,nil above via
	//      os.IsNotExist — "no leases yet" is a legitimate trusted-empty.)
	//   2. A present header is ALWAYS validated BEFORE any trusted-empty
	//      return, so a mangled header (missing required column) errors even
	//      for a header-only / zero-data-row file. This closes the Codex-r4
	//      hole where len(records) < 2 short-circuited ahead of validation,
	//      re-opening the mass-delete via a header-only mangled file.
	//   3. Only AFTER the header validates as GOOD is a header-with-zero-data
	//      -rows treated as a legitimate trusted zero-lease (nil, nil): a
	//      healthy header + no active rows genuinely means "no active
	//      leases", and clearing owned DNS records is then correct.
	if len(records) == 0 {
		return nil, fmt.Errorf("parse %s: Kea %s lease file has no header (anomalous: mid-write or corrupt)",
			path, familyLabel(family))
	}

	// Build the header->index map with CASE-INSENSITIVE keys. Kea's real
	// memfile headers are lower-case, but normalizing defends against a
	// mangled header ("Address"/"ADDRESS") silently resolving to no column.
	// Only the header KEYS and the get() lookup name are lower-cased; field
	// VALUES (addresses, identities, hostnames) are data and stay verbatim.
	cols := make(map[string]int)
	for i, h := range records[0] {
		cols[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(fields []string, name string) string {
		return leaseColumnValue(cols, fields, name)
	}

	// Header validation (#1387 MAJOR-4 + Codex r3 MAJOR-A/B + r4): the
	// reconciler's destructive delete pass treats an EMPTY (or wrongly-keyed)
	// desired set as ground truth. A mangled header — a required column
	// missing or renamed — parses with NO error but silently changes whether
	// leases are published (naming), how they are keyed (identity), or whether
	// they are active (state), so Reconcile would mass-delete or churn
	// (delete+re-add, losing the record on a failed re-add) owned records. So
	// any MISSING required column for this family is a hard parse error —
	// checked BEFORE the zero-data-row return so a header-only mangled file
	// also errors; Reconcile then marks the family untrusted and SKIPS the
	// destructive diff. See requiredLeaseColumns for the per-column rationale.
	var missing []string
	for _, req := range requiredLeaseColumns[family] {
		if _, ok := cols[req]; !ok {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("parse %s: missing required column(s) %v in Kea %s lease header",
			path, missing, familyLabel(family))
	}

	// Header is present AND valid. A file with only a header (zero data rows)
	// is now a LEGITIMATE trusted zero-lease result — return early before the
	// per-row loop so a genuinely-empty Kea correctly clears owned records.
	if len(records) < 2 {
		return nil, nil
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

// leaseColumnValue looks up a field by header name, CASE-INSENSITIVELY. It
// lower-cases the lookup name so the case-insensitivity invariant holds at the
// call site (cols keys are already lower-cased when the map is built), not just
// because callers happen to pass lower-case literals. Field VALUES are never
// touched — only the header name is normalized. Returns "" when the column is
// absent or the row is short.
func leaseColumnValue(cols map[string]int, fields []string, name string) string {
	if idx, ok := cols[strings.ToLower(name)]; ok && idx >= 0 && idx < len(fields) {
		return fields[idx]
	}
	return ""
}

// familyLabel renders a family number for error messages.
func familyLabel(family int) string {
	if family == 6 {
		return "v6"
	}
	return "v4"
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
