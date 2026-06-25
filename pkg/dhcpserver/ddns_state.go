package dhcpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// ddns_state.go: the persistent ownership state store for #1387 DDNS — the
// PROTECTION BOUNDARY for the never-delete-a-record-xpf-did-not-create
// invariant (plan §4.2, §5 invariant 1, risk table "cardinal sin"). Every
// record this firewall publishes is recorded here with the EXACT
// (name, type, address) it wrote; the reconciler issues a delete only for
// an entry present in this store, re-deriving that exact tuple. Records
// not in the store are never touched.
//
// Persisted as JSON via fsatomic.WriteFileDurable (fsync-on-write): the
// reconciler is slow-path, so durability per write is affordable and the
// store must survive restart / failover to keep the boundary intact.

// defaultDDNSStatePath is the on-disk location of the ownership store.
const defaultDDNSStatePath = "/var/lib/xpf/dhcp-ddns-state.json"

// defaultDDNSTTL is the record TTL when the operator does not set one.
const defaultDDNSTTL = 300

// ownedRecord is the exact record set this firewall published for one
// owner identity. A delete re-derives precisely these fields; a mismatch
// (address moved, name changed) means the desired and owned differ and
// the reconciler must clean the OLD owned tuple before adding the new one.
type ownedRecord struct {
	Family      int    `json:"family"`       // 4 or 6
	Identity    string `json:"identity"`     // stable owner id (subnet+client/duid)
	SubnetID    string `json:"subnet_id"`    // pool/subnet metadata
	Address     string `json:"address"`      // textual leased address
	FQDN        string `json:"fqdn"`         // forward name published
	ForwardType string `json:"forward_type"` // "A" | "AAAA"
	PTRName     string `json:"ptr_name"`     // reverse name published
	TTL         int    `json:"ttl"`          // TTL written
	OwnerID     string `json:"owner_id"`     // deterministic node-stable watermark
	// ClientID is the RAW DHCP client identity (v4 client-id||hwaddr, v6
	// DUID/IAID) — the input to the RFC 4701 DHCID digest the live RFC 2136
	// backend writes under replace-owned. It is stored verbatim (NOT the
	// address-fallback identity used for keying) so a later delete recomputes
	// the SAME DHCID and the DHCID-match prerequisite proves xpf created the
	// record before it is removed. Empty when the lease had no stable
	// identity (the backend then publishes no DHCID and uses the
	// name-not-in-use add prerequisite instead). Omitted from older stores;
	// an absent value degrades to the no-DHCID path on delete (safe — the
	// exact-RR delete still only removes the firewall's own tuple).
	ClientID string `json:"client_id,omitempty"`
}

// ownedRecordKey is the in-memory map key for an owned record: a lease's
// stable identity plus its address, so the same client moving to a new
// address is a distinct entry (cleanup of the old address is explicit).
func ownedRecordKey(identity, address string) string {
	return identity + "|" + address
}

// ddnsState is the in-memory + on-disk ownership store. records is keyed
// by ownedRecordKey. It is NOT goroutine-safe on its own; the DDNS
// manager serializes all access under its own mutex.
type ddnsState struct {
	path    string
	records map[string]ownedRecord
}

// ddnsStateFile is the serialized on-disk shape (a stable, sorted slice
// so the JSON diffs cleanly across reconciles).
type ddnsStateFile struct {
	Version int           `json:"version"`
	Records []ownedRecord `json:"records"`
}

const ddnsStateVersion = 1

// loadDDNSState reads the ownership store from path. A missing file yields
// an empty store (first run). A CORRUPT file is FAIL-OPEN per plan §5
// invariant 4: log-and-reset to empty rather than wedge the reconciler —
// the caller logs; this returns (emptyStore, err) so the caller can count
// and warn without aborting.
func loadDDNSState(path string) (*ddnsState, error) {
	s := &ddnsState{path: path, records: map[string]ownedRecord{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return s, fmt.Errorf("read ddns state %s: %w", path, err)
	}
	var f ddnsStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		// Corrupt store: keep the empty (fresh) store. The boundary is only
		// weakened to "may leak previously-owned records" — those records
		// stay in DNS until something authoritatively removes them (TTL only
		// controls resolver CACHING, not removal), so the worst case is
		// stale-but-present records, never "deletes unowned records".
		return s, fmt.Errorf("parse ddns state %s (resetting to empty): %w", path, err)
	}
	// Version validation: an unknown (future / unsupported) non-zero version
	// means a format we cannot safely decode — its records may carry a
	// different tuple shape, so trusting them could drive WRONG-tuple
	// deletes. Treat it like a corrupt store: fail-open to an empty store +
	// surface the error so the caller warns. Version 0 is tolerated as a
	// pre-versioning / zero-value store (the field was absent or defaulted).
	if f.Version != 0 && f.Version != ddnsStateVersion {
		return s, fmt.Errorf("ddns state %s has unsupported version %d (want %d); resetting to empty",
			path, f.Version, ddnsStateVersion)
	}
	for _, r := range f.Records {
		s.records[ownedRecordKey(r.Identity, r.Address)] = r
	}
	return s, nil
}

// save persists the store durably (fsync-on-write). Records are sorted by
// key for a deterministic file.
func (s *ddnsState) save() error {
	keys := make([]string, 0, len(s.records))
	for k := range s.records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	recs := make([]ownedRecord, 0, len(keys))
	for _, k := range keys {
		recs = append(recs, s.records[k])
	}
	data, err := json.MarshalIndent(ddnsStateFile{
		Version: ddnsStateVersion,
		Records: recs,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(s.path), 0o755); err != nil {
		return fmt.Errorf("create ddns state dir: %w", err)
	}
	return fsatomic.WriteFileDurable(s.path, data, 0o600)
}

// put records ownership of a published record.
func (s *ddnsState) put(r ownedRecord) {
	s.records[ownedRecordKey(r.Identity, r.Address)] = r
}

// get returns the owned record for identity+address, if any.
func (s *ddnsState) get(identity, address string) (ownedRecord, bool) {
	r, ok := s.records[ownedRecordKey(identity, address)]
	return r, ok
}

// delete removes an ownership entry (after a successful DNS delete).
func (s *ddnsState) delete(identity, address string) {
	delete(s.records, ownedRecordKey(identity, address))
}

// all returns a stable-ordered copy of every owned record.
func (s *ddnsState) all() []ownedRecord {
	out := make([]ownedRecord, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return ownedRecordKey(out[i].Identity, out[i].Address) <
			ownedRecordKey(out[j].Identity, out[j].Address)
	})
	return out
}

// dirOf is filepath.Dir without importing path/filepath here twice; kept
// local so the rest of the file reads cleanly.
func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return "."
}
