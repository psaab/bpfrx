package dhcpserver

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// stubKea is an in-test Kea control-socket server: it accepts one connection
// per dial, decodes a single keaCommand, hands it to a handler, and writes the
// JSON response. It captures every command for assertions.
type stubKea struct {
	mu       sync.Mutex
	commands []keaCommand
	handler  func(cmd keaCommand) keaResponse
}

func (s *stubKea) record(cmd keaCommand) {
	s.mu.Lock()
	s.commands = append(s.commands, cmd)
	s.mu.Unlock()
}

func (s *stubKea) seen() []keaCommand {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]keaCommand, len(s.commands))
	copy(out, s.commands)
	return out
}

// startStubKea spins a unix-socket server at path serving the stub handler. It
// returns a dialer suitable for SetLeaseSyncSeamsForTesting and a stop func.
func startStubKea(t *testing.T, path string, s *stubKea) (keaSocketDialer, func()) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix %s: %v", path, err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				dec := json.NewDecoder(c)
				var cmd keaCommand
				if err := dec.Decode(&cmd); err != nil {
					return
				}
				s.record(cmd)
				resp := s.handler(cmd)
				b, _ := json.Marshal(resp)
				_, _ = c.Write(b)
			}(conn)
		}
	}()
	dial := func(ctx context.Context, socketPath string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}
	return dial, func() { close(done); ln.Close() }
}

func tmpSocket(t *testing.T, name string) string {
	t.Helper()
	// unix socket paths are length-limited (~108); use a short tmp dir.
	dir, err := os.MkdirTemp("", "ks")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func leaseGetAllResponse(leases []keaLeaseJSON) keaResponse {
	args, _ := json.Marshal(keaLeaseGetAllArgs{Leases: leases})
	return keaResponse{Result: keaResultSuccess, Text: "ok", Arguments: args}
}

// Test (a): read leases via the control socket (lease4-get-all).
func TestGetSyncLeases4_ViaSocket(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command != "lease4-get-all" {
			t.Errorf("unexpected command %q", cmd.Command)
		}
		return leaseGetAllResponse([]keaLeaseJSON{
			{
				IPAddress: "10.0.61.50", HWAddress: "aa:bb:cc:dd:ee:01",
				ClientID: "01:aa:bb:cc:dd:ee:01", SubnetID: 1,
				ValidLft: 3600, CLTT: now.Unix() - 600, State: keaStateDefault,
				Hostname: "host-a",
			},
			// An expired lease (cltt+valid-lft in the past) must be dropped.
			{
				IPAddress: "10.0.61.51", HWAddress: "aa:bb:cc:dd:ee:02",
				SubnetID: 1, ValidLft: 100, CLTT: now.Unix() - 1000, State: keaStateDefault,
			},
			// A declined lease (non-default state) must be dropped.
			{
				IPAddress: "10.0.61.52", HWAddress: "aa:bb:cc:dd:ee:03",
				SubnetID: 1, ValidLft: 3600, CLTT: now.Unix(), State: keaStateDeclined,
			},
		})
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")

	leases, err := m.GetSyncLeases4(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases4: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("expected 1 active lease, got %d: %+v", len(leases), leases)
	}
	l := leases[0]
	if l.Address != "10.0.61.50" {
		t.Errorf("address = %q", l.Address)
	}
	// Remaining = (cltt+valid-lft) - now = (now-600+3600) - now = 3000.
	if l.Remaining != 3000 {
		t.Errorf("remaining = %d, want 3000", l.Remaining)
	}
	if l.Hostname != "host-a" {
		t.Errorf("hostname = %q", l.Hostname)
	}
}

// Test (a) fallback: socket absent → memfile parser.
func TestGetSyncLeases4_MemfileFallback(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	expire := now.Unix() + 1800
	csv := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n" +
		"10.0.61.70,aa:bb:cc:dd:ee:70,01:aa:bb:cc:dd:ee:70,3600," +
		strconv.FormatInt(expire, 10) + ",2,0,0,host-mem,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	// Point the control socket at a non-existent path so the socket read
	// errors and the memfile fallback is taken.
	m.SetLeaseSyncSeamsForTesting(nil, filepath.Join(dir, "missing.sock"), "", memfile, "")

	leases, err := m.GetSyncLeases4(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases4 (fallback): %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("expected 1 lease from memfile, got %d", len(leases))
	}
	if leases[0].Address != "10.0.61.70" || leases[0].Remaining != 1800 {
		t.Errorf("memfile lease = %+v", leases[0])
	}
	if leases[0].ClientID != "01:aa:bb:cc:dd:ee:70" {
		t.Errorf("client-id not recovered: %q", leases[0].ClientID)
	}
}

// Test (b): seed re-anchors Remaining to the LOCAL clock — a skewed peer "now"
// must NOT influence the seeded expiry (clock-skew immunity).
func TestSeedSyncLeases4_ClockSkewImmune(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k4add.sock")
	var addArgs keaLeaseJSON
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command == "lease4-add" {
			b, _ := json.Marshal(cmd.Arguments)
			_ = json.Unmarshal(b, &addArgs)
			return keaResponse{Result: keaResultSuccess, Text: "added"}
		}
		return keaResponse{Result: keaResultError, Text: "unexpected"}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")

	// The lease was synced from a peer whose clock was 1 HOUR ahead, but the
	// SyncLease only carries Remaining (1800s) — never the peer's absolute
	// expiry. The seeded expire must be localNow+1800, ignoring peer skew.
	in := []SyncLease{{
		Family: 4, Address: "10.0.61.90", HWAddress: "aa:bb:cc:dd:ee:90",
		SubnetID: 1, ValidLife: 3600, Remaining: 1800, State: keaStateDefault,
	}}
	n, err := m.SeedSyncLeases4(context.Background(), in, localNow)
	if err != nil {
		t.Fatalf("SeedSyncLeases4: %v", err)
	}
	if n != 1 {
		t.Fatalf("seeded = %d, want 1", n)
	}
	wantExpire := localNow.Unix() + 1800
	if addArgs.Expire != wantExpire {
		t.Errorf("seeded expire = %d, want %d (local-clock re-anchor)", addArgs.Expire, wantExpire)
	}
	if addArgs.ValidLft != 1800 {
		t.Errorf("seeded valid-lft = %d, want 1800 (remaining)", addArgs.ValidLft)
	}
	if addArgs.IPAddress != "10.0.61.90" {
		t.Errorf("seeded address = %q", addArgs.IPAddress)
	}
}

// Test (b) v6: seed carries DUID/IAID/type/prefix-len faithfully (Q5).
func TestSeedSyncLeases6_IdentityAndPD(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	sock := tmpSocket(t, "k6add.sock")
	var got []keaLeaseJSON
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		if cmd.Command == "lease6-add" {
			b, _ := json.Marshal(cmd.Arguments)
			var kl keaLeaseJSON
			_ = json.Unmarshal(b, &kl)
			got = append(got, kl)
			return keaResponse{Result: keaResultSuccess}
		}
		return keaResponse{Result: keaResultError, Text: "unexpected"}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, "", sock, "", "")

	in := []SyncLease{
		{Family: 6, Address: "2001:db8::100", DUID: "00:01:00:01", IAID: 42,
			LeaseType: "IA_NA", SubnetID: 1, Remaining: 1200, State: keaStateDefault},
		{Family: 6, Address: "2001:db8:abcd::", DUID: "00:01:00:02", IAID: 7,
			LeaseType: "IA_PD", PrefixLen: 56, SubnetID: 1, Remaining: 2400, State: keaStateDefault},
	}
	n, err := m.SeedSyncLeases6(context.Background(), in, localNow)
	if err != nil {
		t.Fatalf("SeedSyncLeases6: %v", err)
	}
	if n != 2 {
		t.Fatalf("seeded = %d, want 2", n)
	}
	if len(got) != 2 {
		t.Fatalf("captured %d lease6-add", len(got))
	}
	if got[0].DUID != "00:01:00:01" || got[0].IAID != 42 || got[0].Type != "IA_NA" {
		t.Errorf("NA lease wrong: %+v", got[0])
	}
	if got[1].Type != "IA_PD" || got[1].PrefixLen != 56 {
		t.Errorf("PD lease wrong: %+v", got[1])
	}
}

// Test (b) collision → update fallback (idempotent seed).
func TestSeedSyncLeases4_ConflictUpdates(t *testing.T) {
	sock := tmpSocket(t, "kconf.sock")
	var sawUpdate bool
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		switch cmd.Command {
		case "lease4-add":
			return keaResponse{Result: keaResultConflict, Text: "lease already exists"}
		case "lease4-update":
			sawUpdate = true
			return keaResponse{Result: keaResultSuccess}
		}
		return keaResponse{Result: keaResultError}
	}}
	dial, stop := startStubKea(t, sock, stub)
	defer stop()

	m := New()
	m.SetLeaseSyncSeamsForTesting(dial, sock, "", "", "")
	n, err := m.SeedSyncLeases4(context.Background(),
		[]SyncLease{{Family: 4, Address: "10.0.61.5", HWAddress: "a", SubnetID: 1, Remaining: 60}},
		time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if n != 1 || !sawUpdate {
		t.Fatalf("expected conflict→update path: n=%d sawUpdate=%v", n, sawUpdate)
	}
}

// Test (c): the Kea config gains control-socket + lease_cmds hook ONLY when
// lease sync is enabled (the config knob gate).
func TestKeaConfig_LeaseSyncStanza_Gated(t *testing.T) {
	dir := t.TempDir()
	conf4 := filepath.Join(dir, "kea4.conf")
	conf6 := filepath.Join(dir, "kea6.conf")
	m := NewManagerForTesting(conf4, conf6,
		func(...string) error { return nil },
		func(string) bool { return false })

	cfg := &config.DHCPServerConfig{
		DHCPLocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"g0": {Interfaces: []string{"eth0"}, Pools: []*config.DHCPPool{
					{Subnet: "10.0.61.0/24", RangeLow: "10.0.61.10", RangeHigh: "10.0.61.200"},
				}},
			},
		},
	}

	// Disabled → no stanza.
	if err := m.generateKea4Config(cfg); err != nil {
		t.Fatal(err)
	}
	off, _ := os.ReadFile(conf4)
	if strings.Contains(string(off), "control-socket") || strings.Contains(string(off), "lease_cmds") {
		t.Errorf("disabled config must not contain control-socket/lease_cmds:\n%s", off)
	}

	// Enabled → stanza present.
	m.SetLeaseSyncEnabled(true)
	if err := m.generateKea4Config(cfg); err != nil {
		t.Fatal(err)
	}
	on, _ := os.ReadFile(conf4)
	if !strings.Contains(string(on), "control-socket") {
		t.Errorf("enabled config missing control-socket:\n%s", on)
	}
	if !strings.Contains(string(on), "libdhcp_lease_cmds.so") {
		t.Errorf("enabled config missing lease_cmds hook:\n%s", on)
	}
	// Validate it is still well-formed JSON.
	var parsed map[string]any
	if err := json.Unmarshal(on, &parsed); err != nil {
		t.Errorf("enabled config not valid JSON: %v", err)
	}
}

// Test (d): the memfile pre-seed round-trips through the destructive-safe
// parser (so a starting Kea will load it), and re-anchors to the local clock.
func TestPreSeedMemfile4_RoundTrip(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", "", memfile, "")

	in := []SyncLease{
		{Family: 4, Address: "10.0.61.42", HWAddress: "aa:bb:cc:dd:ee:42",
			ClientID: "01:aa:bb:cc:dd:ee:42", SubnetID: 3, Remaining: 900,
			Hostname: "pre-seeded", State: keaStateDefault},
	}
	if err := m.PreSeedMemfile4(in, localNow); err != nil {
		t.Fatalf("PreSeedMemfile4: %v", err)
	}
	// Re-read via the destructive-safe parser → must see the lease.
	got, err := parseActiveLeases4(memfile, localNow)
	if err != nil {
		t.Fatalf("parseActiveLeases4 on pre-seeded file: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("pre-seeded memfile parsed %d leases, want 1", len(got))
	}
	if got[0].Address != "10.0.61.42" {
		t.Errorf("address = %q", got[0].Address)
	}
	if got[0].Expire != localNow.Unix()+900 {
		t.Errorf("expire = %d, want %d (local re-anchor)", got[0].Expire, localNow.Unix()+900)
	}
}
