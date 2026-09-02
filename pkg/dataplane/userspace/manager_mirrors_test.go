package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildMirrorConfigSnapshots(t *testing.T) {
	cfg := &config.Config{}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"span1": {
				Name:      "span1",
				InputRate: 50,
				Input:     []string{"ge-0/0/0.0"},
				Output:    "ge-0/0/1.0",
			},
		},
	}
	interfaces := []InterfaceSnapshot{
		{Name: "ge-0/0/0.0", LinuxName: "ge-0-0-0.0", Ifindex: 11},
		{Name: "ge-0/0/1.0", LinuxName: "ge-0-0-1.0", Ifindex: 22},
	}

	got, _ := buildMirrorConfigSnapshots(cfg, interfaces)
	want := []MirrorConfigSnapshot{{IngressIfindex: 11, OutputIfindex: 22, Rate: 50}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mirror snapshots = %+v, want %+v", got, want)
	}
}

func TestBuildSnapshotIncludesMirrorConfigsFromRealInterfaceSnapshot(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"lo": {Name: "lo"},
	}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"span-loopback": {
				Name:      "span-loopback",
				InputRate: 7,
				Input:     []string{"lo"},
				Output:    "lo",
			},
		},
	}

	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	var loIfindex int
	for _, iface := range snap.Interfaces {
		if iface.Name == "lo" {
			loIfindex = iface.Ifindex
			break
		}
	}
	if loIfindex <= 0 {
		t.Fatalf("buildSnapshot did not resolve loopback ifindex in interfaces: %+v", snap.Interfaces)
	}
	want := []MirrorConfigSnapshot{{IngressIfindex: loIfindex, OutputIfindex: loIfindex, Rate: 7}}
	if !reflect.DeepEqual(snap.MirrorConfigs, want) {
		t.Fatalf("MirrorConfigs = %+v, want %+v", snap.MirrorConfigs, want)
	}
}

// #3972: a duplicate ingress ifindex is now a SCOPE-DROP at snapshot build
// (the commit gate hard-rejects it up front). The first instance by sorted
// name owns the ingress; the conflicting one is skipped and the valid mirror
// table is still published, rather than the whole table being fail-closed.
func TestBuildMirrorConfigSnapshotsScopeDropsDuplicateIngressIfindex(t *testing.T) {
	cfg := &config.Config{}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"span1": {
				Name:   "span1",
				Input:  []string{"ge-0/0/0.0"},
				Output: "ge-0/0/1.0",
			},
			"span2": {
				Name:   "span2",
				Input:  []string{"ge-0-0-0.0"},
				Output: "ge-0/0/1.0",
			},
		},
	}
	interfaces := []InterfaceSnapshot{
		{Name: "ge-0/0/0.0", LinuxName: "ge-0-0-0.0", Ifindex: 11},
		{Name: "ge-0/0/1.0", LinuxName: "ge-0-0-1.0", Ifindex: 22},
	}

	got, _ := buildMirrorConfigSnapshots(cfg, interfaces)
	want := []MirrorConfigSnapshot{{IngressIfindex: 11, OutputIfindex: 22, Rate: 0}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mirror snapshots = %+v, want first-owner entry kept, duplicate scope-dropped %+v", got, want)
	}
}

func TestBuildMirrorConfigSnapshotsSkipsMissingOutputIfindex(t *testing.T) {
	cfg := &config.Config{}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"span1": {
				Name:   "span1",
				Input:  []string{"ge-0/0/0.0"},
				Output: "ge-0/0/9.0",
			},
		},
	}
	interfaces := []InterfaceSnapshot{
		{Name: "ge-0/0/0.0", LinuxName: "ge-0-0-0.0", Ifindex: 11},
		{Name: "ge-0/0/9.0", LinuxName: "ge-0-0-9.0", Ifindex: 0},
	}

	got, _ := buildMirrorConfigSnapshots(cfg, interfaces)
	if len(got) != 0 {
		t.Fatalf("mirror snapshots = %+v, want missing output ifindex skipped", got)
	}
}

// #3972: a negative rate is scope-dropped at snapshot build (commit gate
// rejects it up front); the other instances survive. Here the lone instance
// is skipped, yielding an empty table without a whole-table fail-close.
func TestBuildMirrorConfigSnapshotsScopeDropsNegativeInputRate(t *testing.T) {
	cfg := &config.Config{}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"bad": {
				Name:      "bad",
				InputRate: -1,
				Input:     []string{"ge-0/0/0.0"},
				Output:    "ge-0/0/1.0",
			},
			"good": {
				Name:      "good",
				InputRate: 5,
				Input:     []string{"ge-0/0/2.0"},
				Output:    "ge-0/0/1.0",
			},
		},
	}
	interfaces := []InterfaceSnapshot{
		{Name: "ge-0/0/0.0", LinuxName: "ge-0-0-0.0", Ifindex: 11},
		{Name: "ge-0/0/1.0", LinuxName: "ge-0-0-1.0", Ifindex: 22},
		{Name: "ge-0/0/2.0", LinuxName: "ge-0-0-2.0", Ifindex: 33},
	}

	got, _ := buildMirrorConfigSnapshots(cfg, interfaces)
	want := []MirrorConfigSnapshot{{IngressIfindex: 33, OutputIfindex: 22, Rate: 5}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mirror snapshots = %+v, want negative-rate instance dropped, valid one kept %+v", got, want)
	}
}
