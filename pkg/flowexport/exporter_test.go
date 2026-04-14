package flowexport

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildExportConfig_InlineJflowSourceAddress(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						InlineJflow:              true,
						InlineJflowSourceAddress: "10.0.1.10",
					},
				},
			},
		},
	}

	ec := BuildExportConfig(nil, fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if len(ec.Collectors) != 1 {
		t.Fatalf("expected 1 collector, got %d", len(ec.Collectors))
	}
	if ec.Collectors[0].SourceAddress != "10.0.1.10" {
		t.Errorf("SourceAddress = %q, want %q", ec.Collectors[0].SourceAddress, "10.0.1.10")
	}
}

func TestBuildSamplingZones(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust": {
					Interfaces: []string{"eth0.0"},
				},
				"untrust": {
					Interfaces: []string{"eth1.0"},
				},
				"dmz": {
					Interfaces: []string{"eth2.0"},
				},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"eth0": {
					Units: map[int]*config.InterfaceUnit{
						0: {SamplingInput: true, SamplingOutput: true},
					},
				},
				"eth1": {
					Units: map[int]*config.InterfaceUnit{
						0: {SamplingInput: true},
					},
				},
				"eth2": {
					Units: map[int]*config.InterfaceUnit{
						0: {}, // no sampling
					},
				},
			},
		},
	}

	// Deterministic zone IDs: dmz=1, trust=2, untrust=3 (sorted)
	zoneIDs := map[string]uint16{"dmz": 1, "trust": 2, "untrust": 3}
	sz := BuildSamplingZones(cfg, zoneIDs)

	// trust (id=2) should have both input and output
	if d, ok := sz[2]; !ok || !d.Input || !d.Output {
		t.Errorf("trust zone: got %+v, want Input=true Output=true", sz[2])
	}
	// untrust (id=3) should have input only
	if d, ok := sz[3]; !ok || !d.Input || d.Output {
		t.Errorf("untrust zone: got %+v, want Input=true Output=false", sz[3])
	}
	// dmz (id=1) should not be in the map (no sampling)
	if _, ok := sz[1]; ok {
		t.Errorf("dmz zone should not have sampling, got %+v", sz[1])
	}
}

func TestShouldExport(t *testing.T) {
	ec := &ExportConfig{
		SamplingZones: map[uint16]SamplingDir{
			2: {Input: true, Output: true},  // trust
			3: {Input: true, Output: false}, // untrust
		},
	}

	// Ingress zone has sampling input -> export
	if !ec.ShouldExport(2, 1) {
		t.Error("should export when ingress zone has sampling input")
	}
	// Egress zone has sampling output -> export
	if !ec.ShouldExport(1, 2) {
		t.Error("should export when egress zone has sampling output")
	}
	// Ingress zone=untrust (input only), egress zone=dmz (no sampling) -> export
	if !ec.ShouldExport(3, 1) {
		t.Error("should export when ingress zone has sampling input")
	}
	// Ingress zone=dmz (no sampling), egress zone=untrust (no output) -> skip
	if ec.ShouldExport(1, 3) {
		t.Error("should not export when neither zone has matching sampling")
	}
	// No sampling zones configured -> export all
	ecNone := &ExportConfig{}
	if !ecNone.ShouldExport(1, 2) {
		t.Error("should export all when no sampling zones configured")
	}
}

func TestParseIfaceRef(t *testing.T) {
	tests := []struct {
		ref      string
		wantName string
		wantUnit int
	}{
		{"eth0.0", "eth0", 0},
		{"trust0.5", "trust0", 5},
		{"enp6s0", "enp6s0", 0},
		{"ge-0/0/0.100", "ge-0/0/0", 100},
	}
	for _, tt := range tests {
		name, unit := parseIfaceRef(tt.ref)
		if name != tt.wantName || unit != tt.wantUnit {
			t.Errorf("parseIfaceRef(%q) = (%q, %d), want (%q, %d)",
				tt.ref, name, unit, tt.wantName, tt.wantUnit)
		}
	}
}

func TestBuildExportConfig_FlowServerSourceAddressTakesPrecedence(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						SourceAddress:            "10.0.1.20",
						InlineJflow:              true,
						InlineJflowSourceAddress: "10.0.1.10",
					},
				},
			},
		},
	}

	ec := BuildExportConfig(nil, fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if ec.Collectors[0].SourceAddress != "10.0.1.20" {
		t.Errorf("SourceAddress = %q, want flow-server source-address %q", ec.Collectors[0].SourceAddress, "10.0.1.20")
	}
}

func TestBuildExportConfig_DistinctSourceAddressesAreNotDeduped(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						SourceAddress: "10.0.1.10",
					},
					FamilyInet6: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						SourceAddress: "10.0.1.11",
					},
				},
			},
		},
	}

	ec := BuildExportConfig(nil, fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if len(ec.Collectors) != 2 {
		t.Fatalf("expected 2 collectors, got %d", len(ec.Collectors))
	}
}

func TestIPFIXHeader(t *testing.T) {
	h := ipfixHeader{
		Version:        10,
		Length:         100,
		ExportTime:     1700000000,
		SequenceNumber: 42,
		ObservationID:  1,
	}
	b := encodeIPFIXHeader(h)
	if len(b) != 16 {
		t.Fatalf("header len = %d, want 16", len(b))
	}
	if v := binary.BigEndian.Uint16(b[0:2]); v != 10 {
		t.Errorf("version = %d, want 10", v)
	}
	if v := binary.BigEndian.Uint16(b[2:4]); v != 100 {
		t.Errorf("length = %d, want 100", v)
	}
	if v := binary.BigEndian.Uint32(b[4:8]); v != 1700000000 {
		t.Errorf("export time = %d, want 1700000000", v)
	}
	if v := binary.BigEndian.Uint32(b[8:12]); v != 42 {
		t.Errorf("seq = %d, want 42", v)
	}
	if v := binary.BigEndian.Uint32(b[12:16]); v != 1 {
		t.Errorf("observation ID = %d, want 1", v)
	}
}

func TestIPFIXTemplateSet(t *testing.T) {
	b := encodeIPFIXTemplateSet()
	if len(b) < 4 {
		t.Fatalf("template set too short: %d bytes", len(b))
	}
	// Set ID should be 2 (template)
	setID := binary.BigEndian.Uint16(b[0:2])
	if setID != ipfixSetIDTemplate {
		t.Errorf("set ID = %d, want %d", setID, ipfixSetIDTemplate)
	}
	setLen := binary.BigEndian.Uint16(b[2:4])
	if int(setLen) != len(b) {
		t.Errorf("set length = %d, want %d", setLen, len(b))
	}
	// First template ID should be 256 (v4)
	tmplID := binary.BigEndian.Uint16(b[4:6])
	if tmplID != ipfixTemplateIDv4 {
		t.Errorf("first template ID = %d, want %d", tmplID, ipfixTemplateIDv4)
	}
}

func TestIPFIXDataSetV4(t *testing.T) {
	now := time.Now()
	records := []FlowRecord{
		{
			SrcIP:     net.IPv4(10, 0, 1, 100),
			DstIP:     net.IPv4(10, 0, 2, 200),
			SrcPort:   12345,
			DstPort:   80,
			Protocol:  6,
			Packets:   100,
			Bytes:     50000,
			StartTime: now.Add(-time.Second),
			EndTime:   now,
			IsIPv6:    false,
		},
	}

	ds := encodeIPFIXDataSet(records)
	if ds == nil {
		t.Fatal("expected non-nil data set")
	}
	// Set header: template ID 256
	setID := binary.BigEndian.Uint16(ds[0:2])
	if setID != ipfixTemplateIDv4 {
		t.Errorf("data set ID = %d, want %d", setID, ipfixTemplateIDv4)
	}
	// Length should be 4 (header) + 57 (one record) = 61
	setLen := binary.BigEndian.Uint16(ds[2:4])
	if setLen != 4+ipfixRecordSizeV4 {
		t.Errorf("data set length = %d, want %d", setLen, 4+ipfixRecordSizeV4)
	}
	// Verify source IP at offset 4
	srcIP := net.IP(ds[4:8])
	if !srcIP.Equal(net.IPv4(10, 0, 1, 100).To4()) {
		t.Errorf("src IP = %s, want 10.0.1.100", srcIP)
	}
}

func TestIPFIXDataSetV6(t *testing.T) {
	now := time.Now()
	records := []FlowRecord{
		{
			SrcIP:     net.ParseIP("2001:db8::1"),
			DstIP:     net.ParseIP("2001:db8::2"),
			SrcPort:   443,
			DstPort:   54321,
			Protocol:  6,
			Packets:   50,
			Bytes:     25000,
			StartTime: now.Add(-time.Second),
			EndTime:   now,
			IsIPv6:    true,
		},
	}

	ds := encodeIPFIXDataSet(records)
	if ds == nil {
		t.Fatal("expected non-nil data set")
	}
	setID := binary.BigEndian.Uint16(ds[0:2])
	if setID != ipfixTemplateIDv6 {
		t.Errorf("data set ID = %d, want %d", setID, ipfixTemplateIDv6)
	}
	setLen := binary.BigEndian.Uint16(ds[2:4])
	if setLen != 4+ipfixRecordSizeV6 {
		t.Errorf("data set length = %d, want %d", setLen, 4+ipfixRecordSizeV6)
	}
}

func TestBuildIPFIXExportConfig(t *testing.T) {
	svc := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			VersionIPFIX: &config.NetFlowIPFIXConfig{
				Templates: map[string]*config.NetFlowIPFIXTemplate{
					"t1": {
						FlowActiveTimeout:   120,
						FlowInactiveTimeout: 30,
						TemplateRefreshRate: 90,
					},
				},
			},
		},
	}
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name:      "test",
					InputRate: 100,
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 4739},
						},
					},
				},
			},
		},
	}

	ec := BuildIPFIXExportConfig(svc, fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if ec.FlowActiveTimeout != 120*time.Second {
		t.Errorf("active timeout = %v, want 120s", ec.FlowActiveTimeout)
	}
	if ec.FlowInactiveTimeout != 30*time.Second {
		t.Errorf("inactive timeout = %v, want 30s", ec.FlowInactiveTimeout)
	}
	if ec.TemplateRefreshRate != 90*time.Second {
		t.Errorf("refresh rate = %v, want 90s", ec.TemplateRefreshRate)
	}
	if ec.SamplingRate != 100 {
		t.Errorf("sampling rate = %d, want 100", ec.SamplingRate)
	}
	if len(ec.Collectors) != 1 {
		t.Fatalf("collectors = %d, want 1", len(ec.Collectors))
	}
	if ec.Collectors[0].Address != "10.0.0.1:4739" {
		t.Errorf("collector address = %q, want %q", ec.Collectors[0].Address, "10.0.0.1:4739")
	}
}

func TestBuildIPFIXExportConfig_NilIPFIX(t *testing.T) {
	svc := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{},
		},
	}
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
					},
				},
			},
		},
	}
	ec := BuildIPFIXExportConfig(svc, fo)
	if ec != nil {
		t.Error("expected nil ExportConfig when VersionIPFIX is not set")
	}
}

func TestBuildIPFIXExportConfig_DistinctSourceAddressesAreNotDeduped(t *testing.T) {
	svc := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			VersionIPFIX: &config.NetFlowIPFIXConfig{
				Templates: map[string]*config.NetFlowIPFIXTemplate{
					"tmpl": {Name: "tmpl"},
				},
			},
		},
	}
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						SourceAddress: "10.0.1.10",
					},
					FamilyInet6: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
						SourceAddress: "10.0.1.11",
					},
				},
			},
		},
	}

	ec := BuildIPFIXExportConfig(svc, fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if len(ec.Collectors) != 2 {
		t.Fatalf("expected 2 collectors, got %d", len(ec.Collectors))
	}
}

func TestV9TemplateFlowDirConditional(t *testing.T) {
	// With flow-dir enabled, template should include fieldDirection
	opts := V9TemplateOptions{IncludeFlowDir: true}
	fieldsV4 := buildTemplateFieldsV4(opts)
	hasDir := false
	for _, f := range fieldsV4 {
		if f.fieldType == fieldDirection {
			hasDir = true
		}
	}
	if !hasDir {
		t.Error("expected fieldDirection in v4 template when IncludeFlowDir=true")
	}

	// Without flow-dir, template should NOT include fieldDirection
	opts2 := V9TemplateOptions{IncludeFlowDir: false}
	fieldsV4no := buildTemplateFieldsV4(opts2)
	for _, f := range fieldsV4no {
		if f.fieldType == fieldDirection {
			t.Error("fieldDirection should not appear when IncludeFlowDir=false")
		}
	}

	// Same check for v6
	fieldsV6 := buildTemplateFieldsV6(opts)
	hasDir = false
	for _, f := range fieldsV6 {
		if f.fieldType == fieldDirection {
			hasDir = true
		}
	}
	if !hasDir {
		t.Error("expected fieldDirection in v6 template when IncludeFlowDir=true")
	}

	fieldsV6no := buildTemplateFieldsV6(opts2)
	for _, f := range fieldsV6no {
		if f.fieldType == fieldDirection {
			t.Error("fieldDirection should not appear in v6 when IncludeFlowDir=false")
		}
	}
}

func TestV9TemplateEncodeWithoutFlowDir(t *testing.T) {
	opts := V9TemplateOptions{IncludeFlowDir: false}
	tmplFS := encodeTemplateFlowSet(opts)
	if len(tmplFS) < 4 {
		t.Fatalf("template flowset too short: %d bytes", len(tmplFS))
	}

	// FlowSet header: ID=0
	setID := binary.BigEndian.Uint16(tmplFS[0:2])
	if setID != 0 {
		t.Errorf("flowset ID = %d, want 0", setID)
	}

	// Verify no fieldDirection (61) appears in the template field entries
	// Skip flowset header (4), then parse template headers + fields
	off := 4
	for off < len(tmplFS) {
		if off+4 > len(tmplFS) {
			break
		}
		off += 2 // skip template ID
		fieldCount := int(binary.BigEndian.Uint16(tmplFS[off : off+2]))
		off += 2
		for i := 0; i < fieldCount; i++ {
			ft := binary.BigEndian.Uint16(tmplFS[off : off+2])
			if ft == fieldDirection {
				t.Errorf("fieldDirection found in template when IncludeFlowDir=false")
			}
			off += 4
		}
	}
}

func TestV9DataRecordSizeConsistency(t *testing.T) {
	now := time.Now()
	boot := now.Add(-time.Hour)

	for _, includeDir := range []bool{true, false} {
		opts := V9TemplateOptions{IncludeFlowDir: includeDir}
		records := []FlowRecord{
			{
				SrcIP: net.IPv4(10, 0, 1, 1), DstIP: net.IPv4(10, 0, 2, 2),
				SrcPort: 1234, DstPort: 80, Protocol: 6,
				Direction: 1, Packets: 10, Bytes: 1000,
				StartTime: now.Add(-time.Second), EndTime: now,
			},
		}
		ds := encodeDataFlowSet(records, boot, opts)
		if ds == nil {
			t.Fatalf("encodeDataFlowSet returned nil (includeDir=%v)", includeDir)
		}
		fields := buildTemplateFieldsV4(opts)
		expectedRecSize := recordSize(fields)
		// data flowset = 4 (header) + N * recordSize (padded to 4)
		expectedLen := 4 + expectedRecSize
		// Pad to 4
		expectedLen += (4 - expectedLen%4) % 4
		dataLen := int(binary.BigEndian.Uint16(ds[2:4]))
		if dataLen != expectedLen {
			t.Errorf("includeDir=%v: data set length = %d, want %d", includeDir, dataLen, expectedLen)
		}
	}
}

func TestBuildExportConfig_V9Extensions(t *testing.T) {
	svc := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{
					"t1": {
						Name:              "t1",
						FlowActiveTimeout: 60,
						ExportExtensions:  []string{"flow-dir"},
					},
				},
			},
		},
	}
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"test": {
					Name: "test",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055},
						},
					},
				},
			},
		},
	}
	ec := BuildExportConfig(svc, fo)
	if ec == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if !ec.V9TemplateOpts.IncludeFlowDir {
		t.Error("V9TemplateOpts.IncludeFlowDir should be true when flow-dir extension is set")
	}

	// Without flow-dir extension
	svc2 := &config.ServicesConfig{
		FlowMonitoring: &config.FlowMonitoringConfig{
			Version9: &config.NetFlowV9Config{
				Templates: map[string]*config.NetFlowV9Template{
					"t2": {
						Name:             "t2",
						ExportExtensions: nil,
					},
				},
			},
		},
	}
	ec2 := BuildExportConfig(svc2, fo)
	if ec2 == nil {
		t.Fatal("expected non-nil ExportConfig")
	}
	if ec2.V9TemplateOpts.IncludeFlowDir {
		t.Error("V9TemplateOpts.IncludeFlowDir should be false when no extensions set")
	}
}
