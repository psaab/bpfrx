package frr

import (
	"strings"
	"testing"
)

// #9136: renderDHCPDefaults interpolated the BARE routing-instance name behind
// `vrf`, while every other `vrf` interpolation in this package resolves the
// instance to its KERNEL namespace first — `InstanceConfig.VRFName`
// ("vrf-<name>", the device pkg/routing/vrf.go creates) for a virtual-router,
// and `table <TableID>` for an `instance-type forwarding` instance, which has
// no VRF device at all.
//
// Two defects in one clause:
//  1. `vrf vr1` names a VRF that does not exist (the device is `vrf-vr1`), so
//     the DHCP-learned default never reaches the tenant's table;
//  2. a forwarding instance gets a `vrf` clause it can never have.
//
// The siblings are the evidence, not the absence: generateStaticRouteInTable
// and renderPreferredRoutes render the SAME kind of object, for the SAME
// instances, into the correct namespace.
//
// COUPLING (#9135): before that fix `dr.VRF` was non-empty only for a
// dash-authored config, so this clause was rarely exercised. #9135 makes it
// live for EVERY VRF DHCP route, which is why these land together.
func TestDHCPRouteRendersKernelVRFNamespace9136(t *testing.T) {
	fc := &FullConfig{
		Instances: []InstanceConfig{
			{Name: "vr1", VRFName: "vrf-vr1"},
			{Name: "fwd1", VRFName: "", TableID: 4242},
		},
		DHCPRoutes: []DHCPRoute{
			{Gateway: "10.0.2.1", Interface: "ge-0-0-1", VRF: "vr1"},
			{Gateway: "10.0.3.1", Interface: "ge-0-0-2", VRF: "fwd1"},
			{Gateway: "10.9.9.1", Interface: "ge-0-0-3"},
			{Gateway: "2001:db8:2::1", Interface: "ge-0-0-1", IsIPv6: true, VRF: "vr1"},
		},
	}
	var b strings.Builder
	renderDHCPDefaults(&b, fc)
	out := b.String()
	if out == "" {
		t.Fatal("NON-VACUITY: the renderer emitted nothing, so no assertion below " +
			"can distinguish a wrong vrf clause from a missing route")
	}

	for _, tc := range []struct {
		want, why string
	}{
		{"ip route 0.0.0.0/0 10.0.2.1 ge-0-0-1 200 vrf vrf-vr1\n",
			"SUBJECT: a virtual-router instance is backed by the kernel device " +
				"`vrf-vr1`. `vrf vr1` names nothing, so the route does not reach " +
				"the tenant's table — the exact loss #8963 was filed against."},
		{"ip route 0.0.0.0/0 10.0.3.1 ge-0-0-2 200 table 4242\n",
			"SUBJECT: an `instance-type forwarding` instance has NO VRF device " +
				"(daemon_ipmon.go sets VRFName=\"\"), so its routes render into the " +
				"instance's kernel table — which is also what the FBF ip rules and " +
				"the dataplane's <ri>.inet.0 snapshot target (#1827 PR-2)."},
		{"ip route 0.0.0.0/0 10.9.9.1 ge-0-0-3 200\n",
			"CONTROL: a default-context DHCP route must acquire neither a vrf " +
				"clause nor a table clause."},
		{"ipv6 route ::/0 2001:db8:2::1 ge-0-0-1 200 vrf vrf-vr1\n",
			"SUBJECT: the v6 emission path is a separate Fprintf and must resolve " +
				"the same way."},
	} {
		if !strings.Contains(out, tc.want) {
			t.Errorf("#9136 %s\n  want line: %q\n  got:\n%s", tc.why, tc.want, out)
		}
	}
	// A negative that the four positives above cannot express: the bare name
	// must not survive anywhere. Without it, a renderer emitting BOTH the old
	// and the new clause would pass every Contains assertion.
	if strings.Contains(out, "vrf vr1\n") || strings.Contains(out, "vrf fwd1") {
		t.Errorf("#9136: the BARE instance name still reaches the `vrf` clause.\n"+
			"got:\n%s", out)
	}
}

// An instance name that the FullConfig does not carry must keep rendering the
// historical "vrf-<name>", exactly as renderPreferredRoutes does on a lookup
// miss (InstanceConfig.Name doc: "May be empty on legacy callers; lookup misses
// fall back to the historical vrf-<name> rendering"). Pins that the resolution
// is a LOOKUP with a defined miss, not a required table.
func TestDHCPRouteInstanceLookupMissFallsBack9136(t *testing.T) {
	fc := &FullConfig{
		DHCPRoutes: []DHCPRoute{{Gateway: "10.0.2.1", Interface: "ge-0-0-1", VRF: "vr1"}},
	}
	var b strings.Builder
	renderDHCPDefaults(&b, fc)
	if got := b.String(); !strings.Contains(got, "200 vrf vrf-vr1\n") {
		t.Errorf("#9136: a DHCP route whose instance is absent from fc.Instances must "+
			"fall back to the historical `vrf-<name>` spelling (the kernel device "+
			"name), not to the bare name and not to no clause at all.\n  got:\n%s", got)
	}
}

// THREE states need three signals. An InstanceConfig with neither a VRF device
// nor a kernel table is the third — InstanceConfig.VRFName's doc calls
// VRFName=="" "(and, historically, the master table)". The compiler never
// produces it (StableRoutingInstanceTableID always returns a value in the
// reserved band, so a forwarding instance always has TableID > 0), but a
// hand-built or legacy FullConfig can, and the sibling renderPreferredRoutes
// renders it into the master table.
//
// This cell exists so a future fix cannot collapse the third state into the
// second and emit `table 0`, which is not a valid FRR operand and would poison
// the whole managed-section reload (#6795: one bad line fails the batch).
func TestDHCPRouteInstanceWithNoVRFAndNoTableRendersMaster9136(t *testing.T) {
	fc := &FullConfig{
		Instances:  []InstanceConfig{{Name: "legacy", VRFName: "", TableID: 0}},
		DHCPRoutes: []DHCPRoute{{Gateway: "10.0.2.1", Interface: "ge-0-0-1", VRF: "legacy"}},
	}
	var b strings.Builder
	renderDHCPDefaults(&b, fc)
	got := b.String()
	if !strings.Contains(got, "ip route 0.0.0.0/0 10.0.2.1 ge-0-0-1 200\n") {
		t.Errorf("an instance carrying neither a VRF device nor a kernel table must "+
			"render into the master table, exactly as renderPreferredRoutes does.\n"+
			"  got:\n%s", got)
	}
	if strings.Contains(got, "table 0") {
		t.Errorf("`table 0` is not a valid FRR operand and fails the whole managed-"+
			"section reload (#6795).\n  got:\n%s", got)
	}
}

// The #5557/#8963 control-character belt on the DHCP `vrf` clause was
// UNGUARDED: deleting sanitizeFRRValue from it survived the whole pkg/frr
// suite. Deleting a control is a no-op unless something drives the input the
// control rejects, so this cell drives it rather than asserting the call is
// present.
//
// #9136 also moved WHAT is sanitized. The belt used to see dr.VRF; it now sees
// the resolver's output, which is `"vrf-" + name` on a lookup MISS and
// InstanceConfig.VRFName on a HIT. Both carry the operator-supplied instance
// name (daemon_ipmon.go builds VRFName as "vrf-"+ri.Name), so both are driven
// here — a belt proven only on the miss path would say nothing about the path
// every real config takes.
//
// The name is validated at commit; the tolerant load / HA config-sync paths
// only warn (#1960 no-brick), so a control character can still reach the
// renderer, where a newline would inject a second statement into the managed
// frr.conf.
func TestDHCPRouteVRFClauseSanitizesControlChars9136(t *testing.T) {
	for _, tc := range []struct {
		name      string
		instances []InstanceConfig
		path      string
	}{
		{"lookup miss", nil, "the miss path sanitizes `vrf-` + the bare name"},
		{"lookup hit", []InstanceConfig{{Name: "bad\nname", VRFName: "vrf-bad\nname"}},
			"the hit path sanitizes InstanceConfig.VRFName, which daemon_ipmon.go " +
				"builds from the same operator-supplied instance name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &FullConfig{
				Instances:  tc.instances,
				DHCPRoutes: []DHCPRoute{{Gateway: "10.0.2.1", Interface: "ge-0-0-1", VRF: "bad\nname"}},
			}
			var b strings.Builder
			renderDHCPDefaults(&b, fc)
			got := b.String()
			// POSITIVE CONTROL: without this, a renderer that emitted nothing
			// at all would satisfy the newline assertion vacuously.
			if !strings.Contains(got, "10.0.2.1") {
				t.Fatalf("NON-VACUITY: the route was not rendered, so the assertion "+
					"below cannot distinguish a sanitized clause from no clause.\n  got:\n%s", got)
			}
			if strings.Contains(got, "bad\nname") {
				t.Errorf("#5557/#8963 belt breached (%s): a control character in the "+
					"routing-instance name reached the managed frr.conf, where the "+
					"newline injects a second vtysh statement.\n  got:\n%q", tc.path, got)
			}
			if !strings.Contains(got, "bad name") {
				t.Errorf("the control character must be REPLACED with a space, not "+
					"dropped or escaped (sanitizeFRRValue's contract).\n  got:\n%q", got)
			}
		})
	}
}
