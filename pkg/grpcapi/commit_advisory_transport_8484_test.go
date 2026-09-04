package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #8484: the commit RPCs must carry EVERY advisory the compiler raises, not
// the one advisory that happened to have a cell.
//
// #6515 gated this transport with a single advisory (host-inbound narrowing).
// That proves the carrier exists; it does not prove a LATER advisory reaches
// it. #8484 was filed believing two newer ones (#7509, #8402) were produced
// and then dropped somewhere on the remote path.
//
// Measured here, they are not dropped — which is the point of pinning it. The
// delivery mechanism is generic: configWarnings() projects cfg.Warnings
// wholesale, so an advisory needs no per-advisory wiring. These cells make
// that genericity falsifiable instead of assumed, across advisories owned by
// three different subsystems (zones, trunk zoning, login-class RBAC).

func advisoryServer8484(t *testing.T, lines []string) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range lines {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q): %v", line, err)
		}
	}
	// Wired the way the daemon wires them; see the #6515 file's SCOPE note —
	// a nil seam yields "commit handler not wired", which is a fixture fault,
	// not evidence about warning delivery.
	return &Server{
		store: store,
		commitFn: func(_ context.Context, _ configstore.CommitAuthority, comment string) (*config.Config, error) {
			if comment != "" {
				return store.CommitWithDescription(comment)
			}
			return store.Commit()
		},
	}
}

func countMentioning(warnings []string, substr string) int {
	n := 0
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			n++
		}
	}
	return n
}

func TestCommitRPCsCarryEveryAdvisory_8484(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		want  string // substring identifying the advisory
	}{
		{
			name: "#7509 shared-device unzoned unit",
			lines: []string{
				"set interfaces gr-0/0/0 tunnel source 10.1.1.1",
				"set interfaces gr-0/0/0 tunnel destination 10.1.1.2",
				"set interfaces gr-0/0/0 unit 0 family inet address 10.255.192.42/30",
				"set interfaces gr-0/0/0 unit 1 family inet address 10.255.193.42/30",
				"set security zones security-zone sfmix interfaces gr-0/0/0.0",
			},
			want: "gr-0/0/0.1",
		},
		{
			name: "#8402 contested trunk",
			lines: []string{
				"set interfaces ge-0/0/9 vlan-tagging",
				"set interfaces ge-0/0/9 unit 100 vlan-id 100",
				"set interfaces ge-0/0/9 unit 100 family inet address 10.100.9.1/24",
				"set interfaces ge-0/0/9 unit 200 vlan-id 200",
				"set interfaces ge-0/0/9 unit 200 family inet address 10.200.9.1/24",
				"set security zones security-zone lan interfaces ge-0/0/9.100",
				"set security zones security-zone dmz interfaces ge-0/0/9.200",
			},
			want: "more than one security zone",
		},
		{
			// #8189, a third subsystem: an advisory added AFTER #8484 was
			// filed needed zero delivery work, which is the genericity claim.
			name: "#8189 unenforceable deny-commands",
			lines: []string{
				"set system login class ops permissions all",
				`set system login class ops deny-commands "^zzz-not-a-real-command$"`,
			},
			want: "matches no command in the REGISTERED command set",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := advisoryServer8484(t, tc.lines)

			chk, err := s.CommitCheck(context.Background(), &pb.CommitCheckRequest{})
			if err != nil {
				t.Fatalf("CommitCheck RPC: %v", err)
			}
			if n := countMentioning(chk.Warnings, tc.want); n != 1 {
				t.Errorf("CommitCheck delivered %d advisory mentioning %q, want 1; got %v",
					n, tc.want, chk.Warnings)
			}

			cm, err := s.Commit(context.Background(), &pb.CommitRequest{})
			if err != nil {
				t.Fatalf("Commit RPC: %v", err)
			}
			if n := countMentioning(cm.Warnings, tc.want); n != 1 {
				t.Errorf("Commit delivered %d advisory mentioning %q, want 1; got %v",
					n, tc.want, cm.Warnings)
			}
		})
	}
}

// ACCEPT-SIDE CONTROL: a candidate raising no advisory must deliver none.
// Without it, a handler that attached a constant warning would satisfy every
// cell above.
func TestCommitRPCsStaySilentWithoutAdvisories_8484(t *testing.T) {
	s := advisoryServer8484(t, []string{
		"set interfaces ge-0/0/8 unit 0 family inet address 10.8.8.1/24",
		"set security zones security-zone trust interfaces ge-0/0/8.0",
	})

	chk, err := s.CommitCheck(context.Background(), &pb.CommitCheckRequest{})
	if err != nil {
		t.Fatalf("CommitCheck RPC: %v", err)
	}
	if len(chk.Warnings) != 0 {
		t.Errorf("CommitCheck on a clean candidate delivered %d warning(s): %v",
			len(chk.Warnings), chk.Warnings)
	}

	cm, err := s.Commit(context.Background(), &pb.CommitRequest{})
	if err != nil {
		t.Fatalf("Commit RPC: %v", err)
	}
	if len(cm.Warnings) != 0 {
		t.Errorf("Commit on a clean candidate delivered %d warning(s): %v",
			len(cm.Warnings), cm.Warnings)
	}
}
