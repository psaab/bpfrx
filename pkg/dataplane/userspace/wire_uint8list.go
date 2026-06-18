package userspace

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

// WireUint8List is a list of small unsigned integers (DSCP code points 0-63
// and 802.1p code points) carried on the userspace-dp control-socket snapshot
// wire.
//
// It exists solely to override Go's default `encoding/json` behavior for
// `[]uint8`/`[]byte`: the standard library special-cases byte slices and
// marshals them as a base64 STRING (e.g. DSCP EF 46 -> "Lg=="). The Rust
// helper's `ConfigSnapshot` deserializes these fields as `Vec<u8>` — a numeric
// JSON ARRAY (a serde sequence) — with no base64 adapter. A base64 string
// therefore fails serde with `invalid type: string "...", expected a sequence`,
// which aborts the ENTIRE `apply_snapshot` decode on the Rust side. The helper
// returns an error before writing any response and closes the control socket;
// the Go side sees a bare EOF, the helper never leaves bootstrap
// (`enabled:false`), and the dataplane forwards nothing. Because the affected
// fields carry `,omitempty`, an empty list is dropped from the wire entirely,
// so the failure only manifests on configs that actually set DSCP/code-point
// values (a DSCP firewall filter, or a DSCP/802.1p CoS classifier) — which is
// why it stayed hidden on the loss-cluster smoke config. See #1961.
//
// MarshalJSON emits a numeric array and never base64. UnmarshalJSON accepts a
// numeric array (the canonical form) and, defensively, a legacy base64 string
// so any older persisted blob still loads.
type WireUint8List []uint8

// MarshalJSON renders the list as a numeric JSON array, e.g. [46,10]. It builds
// the array text directly and MUST NOT delegate to json.Marshal on a []uint8 /
// []byte value — that re-triggers the stdlib base64 special-case and recreates
// the #1961 bug. An empty or nil list renders as `[]` (always a valid serde
// sequence) rather than `null`, so the Rust `Vec<u8>` decodes it cleanly even
// if a caller drops `,omitempty`.
func (w WireUint8List) MarshalJSON() ([]byte, error) {
	if len(w) == 0 {
		return []byte("[]"), nil
	}
	b := make([]byte, 0, 2+len(w)*4)
	b = append(b, '[')
	for i, v := range w {
		if i > 0 {
			b = append(b, ',')
		}
		b = strconv.AppendUint(b, uint64(v), 10)
	}
	b = append(b, ']')
	return b, nil
}

// UnmarshalJSON accepts the canonical numeric array form ([46,10]) and, for
// backward compatibility with any blob written by the old default marshaler, a
// base64 string ("Lgo=" is the base64 of bytes 46,10). A JSON null decodes to a
// nil list.
func (w *WireUint8List) UnmarshalJSON(data []byte) error {
	// Trim leading ASCII whitespace without pulling in bytes just for this.
	i := 0
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\n', '\r':
			i++
			continue
		}
		break
	}
	rest := data[i:]
	if len(rest) == 0 {
		*w = nil
		return nil
	}
	switch rest[0] {
	case 'n': // null
		*w = nil
		return nil
	case '[':
		// Canonical numeric array. Decode through []uint16 so an out-of-range
		// element is rejected explicitly rather than silently wrapping.
		var nums []uint16
		if err := json.Unmarshal(rest, &nums); err != nil {
			return fmt.Errorf("wire uint8 list: %w", err)
		}
		out := make(WireUint8List, len(nums))
		for j, n := range nums {
			if n > 255 {
				return fmt.Errorf("wire uint8 list: element %d out of range: %d", j, n)
			}
			out[j] = uint8(n)
		}
		*w = out
		return nil
	case '"':
		// Legacy base64 string emitted by the pre-#1961 default marshaler.
		var s string
		if err := json.Unmarshal(rest, &s); err != nil {
			return fmt.Errorf("wire uint8 list: %w", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return fmt.Errorf("wire uint8 list: invalid legacy base64 %q: %w", s, err)
		}
		*w = WireUint8List(decoded)
		return nil
	default:
		return fmt.Errorf("wire uint8 list: expected array, base64 string, or null; got %q", rest[0])
	}
}
