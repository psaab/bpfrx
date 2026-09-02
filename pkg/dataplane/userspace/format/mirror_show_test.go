package format

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7357: the SUBSTANCE tests for the port-mirroring render, which moved here
// when the two byte-identical CLI/gRPC copies were single-sourced.
//
// Moving the render without moving a test for it is how single-sourcing
// quietly decommissions a guard: the two surface tests in pkg/cli and
// pkg/grpcapi still pass, but they now exercise two thin wrappers around one
// function, so they bind the WIRING rather than the behaviour. Both are worth
// having; this file is the half that would otherwise have been lost.
func mirrorCfg7357() *config.Config {
	return &config.Config{
		ForwardingOptions: config.ForwardingOptionsConfig{
			PortMirroring: &config.PortMirroringConfig{
				Instances: map[string]*config.PortMirrorInstance{
					// Deliberately inserted in NON-alphabetical order, and named
					// so a map-order render would be seen: Go randomizes map
					// iteration per run, so an unsorted renderer fails this
					// only SOMETIMES. The assertion is on relative position,
					// which is deterministic under the sort.
					"zeta-healthy": {Input: []string{"ge-0/0/1.0"}, Output: "ge-0/0/9.0", InputRate: 100},
					// Rate 0 renders as "all packets" — the maximally permissive
					// reading, and the case where an un-annotated row is most
					// misleading: the dataplane mirrors NOTHING at all.
					"alpha-dropped": {Input: []string{"ge-0/0/2.0"}, InputRate: 0},
				},
			},
		},
	}
}

func TestFormatPortMirroringAnnotatesOnlyTheDroppedInstance_7357(t *testing.T) {
	out := FormatPortMirroring(mirrorCfg7357(), nil)

	// The dropped instance (no `output interface`) must be annotated...
	if !strings.Contains(out, "NOT INSTALLED") {
		t.Fatalf("no NOT INSTALLED annotation; the builder drops `alpha-dropped` and the "+
			"render would claim it is in effect. got:\n%s", out)
	}
	// ...and the HEALTHY one must not be. Without this control a renderer that
	// printed the annotation unconditionally would pass the assertion above.
	if got := strings.Count(out, "NOT INSTALLED"); got != 1 {
		t.Errorf("NOT INSTALLED appears %d times, want exactly 1 — the healthy instance "+
			"must not be annotated. got:\n%s", got, out)
	}

	// The dropped instance renders "all packets" — the maximally permissive
	// reading, while the dataplane mirrors nothing. The annotation is the only
	// thing that stops that line being believed, which is why the two are
	// asserted together rather than separately.
	dropped := out[strings.Index(out, "Instance: alpha-dropped"):]
	dropped = dropped[:strings.Index(dropped, "Instance: zeta-healthy")]
	if !strings.Contains(dropped, "Input rate: all packets") {
		t.Errorf("the dropped instance must still render its permissive rate line; got:\n%s", dropped)
	}
	if !strings.Contains(dropped, "NOT INSTALLED") {
		t.Errorf("the permissive rate line above must be annotated; got:\n%s", dropped)
	}
}

func TestFormatPortMirroringSortsInstances_7357(t *testing.T) {
	out := FormatPortMirroring(mirrorCfg7357(), nil)
	alpha := strings.Index(out, "Instance: alpha-dropped")
	zeta := strings.Index(out, "Instance: zeta-healthy")
	if alpha < 0 || zeta < 0 {
		t.Fatalf("both instances must render; got:\n%s", out)
	}
	if alpha > zeta {
		t.Errorf("instances are not in a stable sorted order (#8166): alpha-dropped at %d "+
			"must precede zeta-healthy at %d\n%s", alpha, zeta, out)
	}
}

func TestFormatPortMirroringEmptyAndNil_7357(t *testing.T) {
	const want = "No port-mirroring instances configured\n"
	if got := FormatPortMirroring(nil, nil); got != want {
		t.Errorf("FormatPortMirroring(nil, nil) = %q, want %q", got, want)
	}
	if got := FormatPortMirroring(&config.Config{}, nil); got != want {
		t.Errorf("FormatPortMirroring(empty) = %q, want %q", got, want)
	}
}
