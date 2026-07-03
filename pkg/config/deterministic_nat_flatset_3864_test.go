package config

import (
	"strings"
	"testing"
)

// #3864: deterministic (CGNAT) source NAT was un-configurable via flat-set.
// The block-size and host address arrive on SEPARATE `set` lines; before the
// fix each sibling `port deterministic ...` leaf reset pool.Deterministic to a
// fresh struct (last-wins) and the host address was never read off Keys, so
// the documented quick-start was spuriously rejected ("deterministic
// block-size must be > 0" / "deterministic host address required") while the
// hierarchical block form worked. The fix models `port deterministic { ... }`
// in setSchema (flat-set grouping + completion) AND accumulates the
// deterministic fields across BOTH the flat-set (Keys) and hierarchical
// (children) shapes in compiler_nat.go (the #2419 dual-AST-shape class).
//
// All tests drive the production ParseSetCommand + SetPath path (buildTree)
// per the CLAUDE.md flat-set gotcha — never NewParser for flat-set.

// deterministicNAT builds a source-pool config. hostPrefix "" omits the host
// line (genuine-incomplete case); blockSize "" omits the block-size line.
func deterministicNATLines(blockSize, hostPrefix string) []string {
	base := "set security nat source pool CGNAT-POOL "
	lines := []string{
		"set security zones security-zone trust",
		base + "address 203.0.113.1/32 to 203.0.113.4/32",
		base + "port range low 1024 high 65535",
	}
	if blockSize != "" {
		lines = append(lines, base+"port deterministic block-size "+blockSize)
	}
	if hostPrefix != "" {
		lines = append(lines, base+"port deterministic host address "+hostPrefix)
	}
	return lines
}

// TestDeterministicNATFlatSetCommits is the #3864 FAIL-ON-REVERT proof: the
// documented CGNAT quick-start, entered as flat-set with block-size and host
// on separate `set` lines, must COMMIT CLEAN and compile the deterministic
// mapping. Pre-fix the sibling `port deterministic ...` leaves overwrote each
// other (last-wins) and the host was never parsed off Keys, so this config was
// spuriously rejected "deterministic block-size must be > 0". 100.64.0.0/25 =
// 128 hosts fits the 4-IP x 32-block = 128 block capacity exactly.
func TestDeterministicNATFlatSetCommits(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, deterministicNATLines("2016", "100.64.0.0/25")))
	if err != nil {
		t.Fatalf("documented flat-set CGNAT quick-start must commit clean (#3864); got: %v", err)
	}
	det := poolDeterministic(t, cfg, "CGNAT-POOL")
	if det.BlockSize != 2016 {
		t.Fatalf("block-size must be read off the flat-set leaf: want 2016, got %d", det.BlockSize)
	}
	if det.HostAddress != "100.64.0.0/25" {
		t.Fatalf("host address must be read off the flat-set Keys: want 100.64.0.0/25, got %q", det.HostAddress)
	}
}

// TestDeterministicNATFlatSetReversedOrder proves the accumulate is
// order-independent: host line BEFORE the block-size line must also commit
// clean (pre-fix this reversed order was rejected "deterministic host address
// required" because the block-size leaf overwrote the host leaf's struct).
func TestDeterministicNATFlatSetReversedOrder(t *testing.T) {
	base := "set security nat source pool CGNAT-POOL "
	lines := []string{
		"set security zones security-zone trust",
		base + "address 203.0.113.1/32 to 203.0.113.4/32",
		base + "port deterministic host address 100.64.0.0/25",
		base + "port deterministic block-size 2016",
		base + "port range low 1024 high 65535",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("reversed-order flat-set CGNAT config must commit clean (#3864); got: %v", err)
	}
	det := poolDeterministic(t, cfg, "CGNAT-POOL")
	if det.BlockSize != 2016 || det.HostAddress != "100.64.0.0/25" {
		t.Fatalf("reversed order must still accumulate both fields, got block-size=%d host=%q",
			det.BlockSize, det.HostAddress)
	}
}

// TestDeterministicNATFlatSetReadsRange proves the modeled `port` container
// still parses `port range low N high M` (a non-default range) after the
// grouping change, so the range did not regress into a dropped nested leaf.
func TestDeterministicNATFlatSetReadsRange(t *testing.T) {
	base := "set security nat source pool CGNAT-POOL "
	lines := []string{
		"set security zones security-zone trust",
		base + "address 203.0.113.1/32 to 203.0.113.32/32",
		base + "port range low 2000 high 40000",
		base + "port deterministic block-size 1000",
		base + "port deterministic host address 100.64.0.0/25",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("config must compile: %v", err)
	}
	pool := sourcePool(t, cfg, "CGNAT-POOL")
	if pool.PortLow != 2000 || pool.PortHigh != 40000 {
		t.Fatalf("port range must be read from the modeled container: want 2000-40000, got %d-%d",
			pool.PortLow, pool.PortHigh)
	}
}

// TestDeterministicNATMissingBlockSizeRejected is the genuine-incomplete guard:
// a deterministic config with a host but NO block-size is STILL rejected. The
// #3864 fix repairs only the SPURIOUS rejection of a well-formed config — a
// truly incomplete config must keep failing.
func TestDeterministicNATMissingBlockSizeRejected(t *testing.T) {
	_, err := CompileConfig(buildTree(t, deterministicNATLines("", "100.64.0.0/25")))
	if err == nil {
		t.Fatal("deterministic config missing block-size must be rejected (#3864 must not weaken validation)")
	}
	if !strings.Contains(err.Error(), "block-size must be > 0") {
		t.Fatalf("error must name the missing block-size, got: %v", err)
	}
}

// TestDeterministicNATMissingHostRejected is the sibling genuine-incomplete
// guard: a deterministic config with a block-size but NO host is STILL
// rejected.
func TestDeterministicNATMissingHostRejected(t *testing.T) {
	_, err := CompileConfig(buildTree(t, deterministicNATLines("2016", "")))
	if err == nil {
		t.Fatal("deterministic config missing host address must be rejected (#3864 must not weaken validation)")
	}
	if !strings.Contains(err.Error(), "host address required") {
		t.Fatalf("error must name the missing host address, got: %v", err)
	}
}

// TestDeterministicNATHierarchicalPreserved proves the genuine hierarchical
// (brace) block form still compiles and parses both fields — the flat-set fix
// must not regress the pre-existing hierarchical path.
func TestDeterministicNATHierarchicalPreserved(t *testing.T) {
	blockCfg := `security {
  zones { security-zone trust; }
  nat {
    source {
      pool CGNAT-POOL {
        address 203.0.113.1/32 to 203.0.113.4/32;
        port {
          range low 1024 high 65535;
          deterministic {
            block-size 2016;
            host address 100.64.0.0/25;
          }
        }
      }
    }
  }
}`
	p := NewParser(blockCfg)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("hierarchical CGNAT block form must still compile: %v", err)
	}
	det := poolDeterministic(t, cfg, "CGNAT-POOL")
	if det.BlockSize != 2016 || det.HostAddress != "100.64.0.0/25" {
		t.Fatalf("hierarchical form must parse both fields, got block-size=%d host=%q",
			det.BlockSize, det.HostAddress)
	}
}

// TestDeterministicNATIPv6DocExample proves the documented IPv6/NAPT64 flat-set
// quick-start commits clean (8 IPs, /32 host prefix).
func TestDeterministicNATIPv6DocExample(t *testing.T) {
	base := "set security nat source pool CGNAT64-POOL "
	lines := []string{
		"set security zones security-zone trust",
		base + "address 203.0.113.1/32 to 203.0.113.8/32",
		base + "port deterministic block-size 2016",
		base + "port deterministic host address 2001:db8::/32",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("documented IPv6 CGNAT quick-start must commit clean (#3864); got: %v", err)
	}
	det := poolDeterministic(t, cfg, "CGNAT64-POOL")
	if det.BlockSize != 2016 || det.HostAddress != "2001:db8::/32" {
		t.Fatalf("IPv6 flat-set must accumulate both fields, got block-size=%d host=%q",
			det.BlockSize, det.HostAddress)
	}
}

func sourcePool(t *testing.T, cfg *Config, name string) *NATPool {
	t.Helper()
	for _, p := range cfg.Security.NAT.SourcePools {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("source pool %q not found", name)
	return nil
}

func poolDeterministic(t *testing.T, cfg *Config, name string) *DeterministicNATConfig {
	t.Helper()
	pool := sourcePool(t, cfg, name)
	if pool.Deterministic == nil {
		t.Fatalf("pool %q: deterministic config not parsed (nil)", name)
	}
	return pool.Deterministic
}
