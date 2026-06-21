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

// Test (a) v6 fallback (#2262): the memfile-fallback read path must PRESERVE
// the v6 lease kind (IA_NA vs IA_PD) and the PD prefix length from the Kea v6
// memfile, not hardcode IA_NA. A memfile holding BOTH an IA_NA and an IA_PD row
// must round-trip each lease's type (and the PD prefix-len) — mirroring the
// faithful control-socket path (TestSeedSyncLeases6_IdentityAndPD). Fail-on-
// revert: re-hardcoding LeaseType="IA_NA" makes the IA_PD assertions fail.
func TestGetSyncLeases6_MemfileFallback_PreservesType(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	expire := strconv.FormatInt(now.Unix()+1800, 10)
	// Canonical Kea v6 memfile header + one IA_NA (lease_type 0, prefix_len 128)
	// and one IA_PD (lease_type 2, prefix_len 56) row.
	//   address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,
	//   lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,
	//   state,user_context,hwtype,hwaddr_source,pool_id
	csv := keaMemfileHeader6 + "\n" +
		"2001:db8::100,00:01:00:01,3600," + expire + ",1,3600,0,42,128,0,0,host-na,,0,,,,0\n" +
		"2001:db8:abcd::,00:01:00:02,3600," + expire + ",1,3600,2,7,56,0,0,host-pd,,0,,,,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	// Missing socket → memfile fallback; leaseFile6 = our fixture.
	m.SetLeaseSyncSeamsForTesting(nil, "", filepath.Join(dir, "missing.sock"), "", memfile)

	leases, err := m.GetSyncLeases6(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases6 (fallback): %v", err)
	}
	if len(leases) != 2 {
		t.Fatalf("expected 2 leases from v6 memfile, got %d: %+v", len(leases), leases)
	}

	byAddr := map[string]SyncLease{}
	for _, l := range leases {
		byAddr[l.Address] = l
	}

	na, ok := byAddr["2001:db8::100"]
	if !ok {
		t.Fatalf("IA_NA lease missing from fallback result: %+v", leases)
	}
	if na.LeaseType != "IA_NA" {
		t.Errorf("IA_NA lease type = %q, want IA_NA", na.LeaseType)
	}
	if na.PrefixLen != 0 {
		t.Errorf("IA_NA lease PrefixLen = %d, want 0", na.PrefixLen)
	}
	if na.DUID != "00:01:00:01" || na.IAID != 42 {
		t.Errorf("IA_NA identity wrong: DUID=%q IAID=%d", na.DUID, na.IAID)
	}

	pd, ok := byAddr["2001:db8:abcd::"]
	if !ok {
		t.Fatalf("IA_PD lease missing from fallback result: %+v", leases)
	}
	// This is the #2262 regression guard: pre-fix the fallback hardcoded
	// LeaseType="IA_NA" and dropped the prefix length, so a PD lease arrived as
	// an address lease on the peer.
	if pd.LeaseType != "IA_PD" {
		t.Errorf("IA_PD lease mis-typed as %q (want IA_PD) — #2262 regression", pd.LeaseType)
	}
	if pd.PrefixLen != 56 {
		t.Errorf("IA_PD lease PrefixLen = %d, want 56 — #2262 regression", pd.PrefixLen)
	}
	if pd.DUID != "00:01:00:02" || pd.IAID != 7 {
		t.Errorf("IA_PD identity wrong: DUID=%q IAID=%d", pd.DUID, pd.IAID)
	}
}

// Test (a) v6 fallback skip-malformed (#2262): a PRESENT-but-unparseable
// lease_type column must cause the row to be SKIPPED (fail-closed), not
// defaulted to IA_NA, so a corrupt row can never silently mis-seed an address
// lease on the peer. A well-formed IA_PD row in the same file still parses.
func TestGetSyncLeases6_MemfileFallback_SkipMalformedType(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	expire := strconv.FormatInt(now.Unix()+1800, 10)
	// First row: lease_type column is garbage ("PD") → unparseable → skipped.
	// Second row: a valid IA_PD lease that must still survive.
	csv := keaMemfileHeader6 + "\n" +
		"2001:db8::bad,00:01:00:09,3600," + expire + ",1,3600,PD,9,64,0,0,host-bad,,0,,,,0\n" +
		"2001:db8:cafe::,00:01:00:0a,3600," + expire + ",1,3600,2,10,60,0,0,host-good,,0,,,,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, "", filepath.Join(dir, "missing.sock"), "", memfile)

	leases, err := m.GetSyncLeases6(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases6 (fallback): %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("expected 1 lease (malformed-type row skipped), got %d: %+v", len(leases), leases)
	}
	if leases[0].Address != "2001:db8:cafe::" {
		t.Errorf("surviving lease = %q, want the valid IA_PD row", leases[0].Address)
	}
	if leases[0].LeaseType != "IA_PD" || leases[0].PrefixLen != 60 {
		t.Errorf("surviving IA_PD lease wrong: %+v", leases[0])
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

// Test (#2268): the v6 memfile pre-seed must round-trip the lease KIND
// symmetrically with the read path — an IA_TA (temporary-address) lease read
// and held as IA_TA must be written back as lease_type=1 (IA_TA), never silently
// downgraded to lease_type=0 (IA_NA). Before the fix writeMemfile6 only encoded
// IA_PD vs "everything-else as IA_NA", so an IA_TA lease lost its kind across a
// failover. IA_NA and IA_PD rows in the same file prove no regression.
//
// Fail-on-revert: reverting writeMemfile6 to the IA_PD-vs-IA_NA-only writer
// makes the IA_TA assertions fail (the row would read back as IA_NA with
// prefix_len=128, never IA_TA).
func TestPreSeedMemfile6_RoundTrip_PreservesIATA(t *testing.T) {
	localNow := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases6.csv")
	m := New()
	// Pre-seed writes to memfile6; the read-back fallback (no socket) reads it.
	m.SetLeaseSyncSeamsForTesting(nil, "", filepath.Join(dir, "missing.sock"), "", memfile)

	in := []SyncLease{
		{Family: 6, Address: "2001:db8::1", DUID: "00:01:00:01", IAID: 10,
			LeaseType: "IA_NA", SubnetID: 1, Remaining: 1200, State: keaStateDefault},
		{Family: 6, Address: "2001:db8::ta", DUID: "00:01:00:02", IAID: 20,
			LeaseType: "IA_TA", SubnetID: 1, Remaining: 1800, State: keaStateDefault},
		{Family: 6, Address: "2001:db8:abcd::", DUID: "00:01:00:03", IAID: 30,
			LeaseType: "IA_PD", PrefixLen: 56, SubnetID: 1, Remaining: 2400, State: keaStateDefault},
	}
	if err := m.PreSeedMemfile6(in, localNow); err != nil {
		t.Fatalf("PreSeedMemfile6: %v", err)
	}

	// Direct byte-level assertion: the IA_TA row must carry lease_type=1. This is
	// the tightest fail-on-revert guard — an IA_PD-vs-IA_NA-only writer would
	// emit lease_type=0 for the IA_TA address. The Kea v6 memfile lease_type is
	// the 7th column (index 6).
	raw, err := os.ReadFile(memfile)
	if err != nil {
		t.Fatalf("read pre-seeded memfile: %v", err)
	}
	var sawTAColumn bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if !strings.HasPrefix(line, "2001:db8::ta,") {
			continue
		}
		cols := strings.Split(line, ",")
		if len(cols) < 9 {
			t.Fatalf("IA_TA row has too few columns: %q", line)
		}
		if cols[6] != "1" {
			t.Errorf("IA_TA row lease_type column = %q, want 1 (#2268 downgrade regression): %q", cols[6], line)
		}
		// IA_TA is a full /128 address binding, not a delegated prefix.
		if cols[8] != "128" {
			t.Errorf("IA_TA row prefix_len column = %q, want 128: %q", cols[8], line)
		}
		sawTAColumn = true
	}
	if !sawTAColumn {
		t.Fatalf("IA_TA row not found in pre-seeded memfile:\n%s", raw)
	}

	// Full round trip: read the pre-seeded memfile back through the production
	// read path (socket missing → memfile fallback) and assert each kind survives.
	got, err := m.GetSyncLeases6(context.Background(), localNow)
	if err != nil {
		t.Fatalf("GetSyncLeases6 (read-back): %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read back %d leases, want 3: %+v", len(got), got)
	}
	byAddr := map[string]SyncLease{}
	for _, l := range got {
		byAddr[l.Address] = l
	}

	ta, ok := byAddr["2001:db8::ta"]
	if !ok {
		t.Fatalf("IA_TA lease missing after round trip: %+v", got)
	}
	if ta.LeaseType != "IA_TA" {
		t.Errorf("IA_TA lease round-tripped as %q, want IA_TA (#2268 downgrade)", ta.LeaseType)
	}
	if ta.PrefixLen != 0 {
		t.Errorf("IA_TA lease PrefixLen = %d, want 0 (address, not prefix)", ta.PrefixLen)
	}
	if ta.DUID != "00:01:00:02" || ta.IAID != 20 {
		t.Errorf("IA_TA identity wrong: DUID=%q IAID=%d", ta.DUID, ta.IAID)
	}

	// No regression: IA_NA and IA_PD still round-trip.
	if na := byAddr["2001:db8::1"]; na.LeaseType != "IA_NA" || na.PrefixLen != 0 {
		t.Errorf("IA_NA lease regressed: %+v", na)
	}
	if pd := byAddr["2001:db8:abcd::"]; pd.LeaseType != "IA_PD" || pd.PrefixLen != 56 {
		t.Errorf("IA_PD lease regressed: %+v", pd)
	}
}

// Test (#2268): the lease-type read↔write mapping is a single total inverse —
// keaLeaseTypeToString and stringToKeaLeaseType must agree on every value so the
// pair can never drift to re-introduce an asymmetric downgrade. Every numeric
// type the reader produces must invert back to the same number, and every string
// the writer accepts must come from the reader. The empty string (unknown kind)
// defaults to IA_NA on the write side.
func TestKeaLeaseTypeInverseTotality(t *testing.T) {
	for _, n := range []int{keaLeaseTypeIANA, keaLeaseTypeIATA, keaLeaseTypeIAPD} {
		s, ok := keaLeaseTypeToString(n)
		if !ok {
			t.Fatalf("keaLeaseTypeToString(%d) not ok", n)
		}
		back, ok := stringToKeaLeaseType(s)
		if !ok {
			t.Fatalf("stringToKeaLeaseType(%q) not ok", s)
		}
		if back != n {
			t.Errorf("inverse drift: %d -> %q -> %d", n, s, back)
		}
	}
	// Empty string is the write-side default (unknown kind) → IA_NA.
	if v, ok := stringToKeaLeaseType(""); !ok || v != keaLeaseTypeIANA {
		t.Errorf(`stringToKeaLeaseType("") = %d ok=%v, want %d true`, v, ok, keaLeaseTypeIANA)
	}
	// An unknown non-empty string is rejected (ok=false) and falls back to IA_NA.
	if v, ok := stringToKeaLeaseType("IA_BOGUS"); ok || v != keaLeaseTypeIANA {
		t.Errorf(`stringToKeaLeaseType("IA_BOGUS") = %d ok=%v, want %d false`, v, ok, keaLeaseTypeIANA)
	}
	// An unknown numeric type is rejected (mirrors the read side fail-closed).
	if _, ok := keaLeaseTypeToString(99); ok {
		t.Errorf("keaLeaseTypeToString(99) ok=true, want false")
	}
}
