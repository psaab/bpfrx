package frr

import (
	"reflect"
	"strings"
	"testing"
)

// #6468 / #6579. bgpPeerJSON's DECLARED FIELD SET is documented at its
// definition as a load-bearing security boundary: with `bgp default
// show-hostname` configured, FRR adds a "hostname" key to every peer object
// carrying the name the PEER advertised via the BGP hostname capability —
// attacker-controlled free text. encoding/json ignores object keys that have no
// matching declared field, so NOT declaring it is what keeps that text out of
// BGPPeerSummary and off the operator's terminal.
//
// That was documented but unpinned. These tests bind it: adding a hostname
// field to bgpPeerJSON and plumbing it into BGPPeerSummary fails here rather
// than silently widening the taint into every render site.

// bgpSummaryHostileHostnameJSON6468 is the shipped fixture's shape with a
// hostile string in the "hostname" key: a CSI erase-line escape (\u001b — raw
// control bytes are a JSON syntax error, so it must be escaped here) plus a
// complete fake column set, so a test can tell "the value never arrived" from
// "the value arrived and was escaped". Every other key is a DECLARED field, so
// a vacuous pass (parser returned nothing) is distinguishable from a real one.
const bgpSummaryHostileHostnameJSON6468 = `{
  "ipv4Unicast": {
    "routerId": "10.0.0.1",
    "as": 65001,
    "vrfName": "default",
    "peers": {
      "10.0.0.2": {
        "hostname": "r2\u001b[2K  ipv4-unicast  65099  0  0  never  Established  0",
        "remoteAs": 65002,
        "msgRcvd": 124,
        "msgSent": 130,
        "peerUptime": "01:05:12",
        "pfxRcd": 3,
        "pfxSnt": 4,
        "state": "Established"
      }
    }
  }
}`

func TestBGPSummaryDropsPeerAdvertisedHostname_6468(t *testing.T) {
	peers, err := parseBGPSummaryJSON(bgpSummaryHostileHostnameJSON6468)
	if err != nil {
		t.Fatalf("parseBGPSummaryJSON: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("fixture must parse to exactly 1 peer (else this test is vacuous), got %d", len(peers))
	}
	p := peers[0]

	// Reflective sweep: walk EVERY string field, so adding a Hostname field to
	// BGPPeerSummary (or repurposing an existing one) is caught here instead of
	// widening peer-controlled text into all 10 render sites unnoticed.
	v := reflect.ValueOf(p)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.String {
			continue
		}
		got := f.String()
		if strings.Contains(got, "\x1b") || strings.Contains(got, "65099") {
			t.Fatalf("BGPPeerSummary.%s carries the peer-advertised hostname %q.\n"+
				"bgpPeerJSON deliberately does NOT declare a \"hostname\" field: encoding/json "+
				"ignores undeclared keys, and that is the documented boundary keeping this text "+
				"out of the struct (#6468). If the hostname is now wanted, every display site "+
				"must sanitize it AND this test must be replaced with one asserting the escaped "+
				"form — do not just delete it.",
				v.Type().Field(i).Name, got)
		}
	}

	// Non-vacuous: DECLARED keys really did carry through, so a clean sweep
	// means "the hostname was dropped", not "nothing was parsed". Checked AFTER
	// the sweep so a tainted field reports the sweep's message, not this one.
	if !strings.HasPrefix(p.State, "Established") || p.AS != "65002" || p.Neighbor != "10.0.0.2" {
		t.Fatalf("declared fields must be populated, else the drop above proves nothing: %+v", p)
	}
}

// TestBGPSummaryDeclaredFieldSetIsTheBoundary_6468 pins the MECHANISM, not just
// the outcome. If bgpPeerJSON ever gains `json:"-"`-less catch-all decoding (a
// map[string]any, json.RawMessage, or DisallowUnknownFields inversion), the
// "undeclared keys are dropped" reasoning stops holding and this fails.
func TestBGPSummaryDeclaredFieldSetIsTheBoundary_6468(t *testing.T) {
	tj := reflect.TypeOf(bgpPeerJSON{})
	for i := 0; i < tj.NumField(); i++ {
		f := tj.Field(i)
		switch f.Type.Kind() {
		case reflect.Map, reflect.Interface, reflect.Slice:
			t.Fatalf("bgpPeerJSON.%s is a %s: a catch-all decode target defeats the declared-field "+
				"boundary that keeps the peer-advertised \"hostname\" out of BGPPeerSummary (#6468). "+
				"Every field must be a concrete scalar.", f.Name, f.Type.Kind())
		}
		if strings.EqualFold(f.Name, "hostname") || strings.Contains(f.Tag.Get("json"), "hostname") {
			t.Fatalf("bgpPeerJSON declares %s (tag %q) — that is the peer-advertised BGP hostname "+
				"capability string, attacker-controlled free text. Declaring it pulls it into "+
				"BGPPeerSummary and onto every terminal render site (#6468).", f.Name, f.Tag.Get("json"))
		}
	}
}
