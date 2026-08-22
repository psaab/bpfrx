package userspace

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestWireUint8ListMarshalsNumericArray is the core #1961 regression: the wire
// form MUST be a numeric JSON array, never a base64 string (which Go's default
// []uint8 marshaler would emit and the Rust Vec<u8> deserializer would reject).
func TestWireUint8ListMarshalsNumericArray(t *testing.T) {
	cases := map[string]struct {
		in   WireUint8List
		want string
	}{
		"ef":    {WireUint8List{46}, "[46]"},
		"multi": {WireUint8List{46, 10, 0, 63}, "[46,10,0,63]"},
		"empty": {WireUint8List{}, "[]"},
		"nil":   {nil, "[]"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(b) != tc.want {
				t.Fatalf("marshal = %s, want %s", b, tc.want)
			}
			// Hard guard: the value must not be a JSON string (base64).
			if len(b) > 0 && b[0] == '"' {
				t.Fatalf("marshal produced a base64 string %s — the #1961 bug", b)
			}
		})
	}
}

func TestWireUint8ListUnmarshal(t *testing.T) {
	// Canonical numeric array.
	var w WireUint8List
	if err := json.Unmarshal([]byte("[46,10,63]"), &w); err != nil {
		t.Fatalf("numeric: %v", err)
	}
	if !reflect.DeepEqual(w, WireUint8List{46, 10, 63}) {
		t.Fatalf("numeric decode = %v", w)
	}
	// Legacy base64 ("Lgo=" == bytes 0x2E,0x0A == 46,10) must still load so an
	// older persisted blob is tolerated.
	var legacy WireUint8List
	if err := json.Unmarshal([]byte(`"Lgo="`), &legacy); err != nil {
		t.Fatalf("legacy base64: %v", err)
	}
	if !reflect.DeepEqual(legacy, WireUint8List{46, 10}) {
		t.Fatalf("legacy base64 decode = %v, want [46 10]", legacy)
	}
	// null -> nil.
	w = WireUint8List{1}
	if err := json.Unmarshal([]byte("null"), &w); err != nil || w != nil {
		t.Fatalf("null decode: err=%v w=%v", err, w)
	}
	// Out-of-range element rejected.
	if err := json.Unmarshal([]byte("[256]"), &w); err == nil {
		t.Fatalf("expected error for out-of-range element")
	}
}

// TestSnapshotWireStructsCarryNumericDSCP exercises the three real snapshot
// structs end to end through the wire encoding.
func TestSnapshotWireStructsCarryNumericDSCP(t *testing.T) {
	for _, v := range []any{
		CoSDSCPClassifierEntrySnapshot{ForwardingClass: "ef", DSCPValues: WireUint8List{46}},
		CoSIEEE8021ClassifierEntrySnapshot{ForwardingClass: "ef", CodePoints: WireUint8List{5}},
		FirewallTermSnapshot{Name: "mark-ef", DSCPValues: WireUint8List{46}, Action: "accept"},
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal %T: %v", v, err)
		}
		s := string(b)
		if strings.Contains(s, `"dscp_values":"`) || strings.Contains(s, `"code_points":"`) {
			t.Fatalf("%T marshaled a base64 string (the #1961 bug): %s", v, s)
		}
		if !strings.Contains(s, "[46]") && !strings.Contains(s, "[5]") {
			t.Fatalf("%T did not marshal a numeric array: %s", v, s)
		}
	}
}

var jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()

// rawConfigPassthroughType is ConfigSnapshot.Config (`json:"config"`): the full
// compiled Junos config carried verbatim on the wire. The Rust helper decodes
// THIS field as an opaque `serde_json::Value` (snapshot.rs `pub config:
// serde_json::Value`) and never re-parses it into typed structs, so a base64
// []uint8 inside it (e.g. config.ClassOfService DSCP classifier values) is
// harmless — it is never deserialized as a Rust Vec<u8>. The guard below skips
// this subtree because it is not part of the typed wire contract; everything
// else IS, and must stay numeric.
var rawConfigPassthroughType = reflect.TypeOf((*config.Config)(nil))

// TestNoRawUint8SliceWireFields is the class-level guard (#1961): walk the full
// control-socket wire type graph (request + response) and fail if any field is
// a raw []uint8/[]byte slice without a custom MarshalJSON. Such a field would
// be base64-encoded by Go's default marshaler and rejected by the Rust Vec<u8>
// deserializer, silently aborting apply_snapshot. WireUint8List passes because
// it implements json.Marshaler; a future raw []byte field would fail here
// instead of in production.
func TestNoRawUint8SliceWireFields(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var bad []string
	var walk func(t reflect.Type, path string)
	walk = func(rt reflect.Type, path string) {
		if rt == nil || seen[rt] {
			return
		}
		seen[rt] = true
		switch rt.Kind() {
		case reflect.Pointer:
			walk(rt.Elem(), path)
		case reflect.Map:
			walk(rt.Elem(), path+"[]")
		case reflect.Slice, reflect.Array:
			if rt.Elem().Kind() == reflect.Uint8 && !rt.Implements(jsonMarshalerType) {
				bad = append(bad, path+" ("+rt.String()+")")
				return
			}
			walk(rt.Elem(), path+"[]")
		case reflect.Struct:
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				if f.PkgPath != "" { // unexported — not on the wire
					continue
				}
				if f.Tag.Get("json") == "-" {
					continue
				}
				if f.Type == rawConfigPassthroughType {
					continue // opaque serde_json::Value on the Rust side — see above
				}
				walk(f.Type, path+"."+f.Name)
			}
		}
	}
	walk(reflect.TypeOf(ControlRequest{}), "ControlRequest")
	walk(reflect.TypeOf(ControlResponse{}), "ControlResponse")
	if len(bad) > 0 {
		t.Fatalf("raw []uint8/[]byte wire field(s) found — these base64-encode and "+
			"break the Rust Vec<u8> decode (#1961). Wrap with WireUint8List or a "+
			"json.Marshaler:\n  %s", strings.Join(bad, "\n  "))
	}
}

// TestBuildSnapshotFromFullConfigDecodes is the integration regression: build
// the apply_snapshot request from the real standalone config (which carries a
// DSCP firewall filter) and confirm the dscp_values land as a numeric array,
// not the base64 string that aborted the Rust decode in #1961.
func TestBuildSnapshotFromFullConfigDecodes(t *testing.T) {
	content, err := os.ReadFile("../../../test/incus/xpf-test.conf")
	if err != nil {
		t.Skipf("config fixture unavailable: %v", err)
	}
	tree, _ := config.NewParser(string(content)).Parse()
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{Workers: 4, RingEntries: 1024}, 3, 3)
	buf, err := json.Marshal(&ControlRequest{Type: "apply_snapshot", Snapshot: snap})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	s := string(buf)
	if !strings.Contains(s, `"dscp_values":[`) {
		t.Fatalf("expected a numeric dscp_values array in the snapshot; got none")
	}
	if strings.Contains(s, `"dscp_values":"`) || strings.Contains(s, `"code_points":"`) {
		t.Fatalf("snapshot still emits a base64 dscp_values/code_points string (#1961)")
	}
}
