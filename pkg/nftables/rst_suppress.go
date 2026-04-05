// Package nftables manages nftables rules via the kernel netlink API.
// It does NOT shell out to the nft binary.
package nftables

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const rstTableName = "bpfrx_dp_rst"

// InstallRSTSuppression creates nftables rules to DROP outgoing TCP RSTs
// from interface-NAT (SNAT) addresses. These addresses are owned by the
// userspace dataplane; the kernel has no sockets for them and should never
// emit RSTs.
//
// The delete + create is performed in a single atomic netlink batch to
// eliminate the race window where no rules exist between the old table
// deletion and new table creation. This is critical for HA failover:
// during the microseconds of RG demotion, the kernel may generate RSTs
// for connections it doesn't own (#450).
func InstallRSTSuppression(v4Addrs []netip.Addr, v6Addrs []netip.Addr) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}

	// Delete + create in a single atomic flush. The kernel applies the
	// entire netlink batch atomically, so the RST suppression rules are
	// never absent — the old table is replaced by the new one in one shot.
	// On fresh boot the table doesn't exist yet; the kernel silently
	// ignores the delete for non-existent tables in a batch.
	removeRSTTable(c)

	if len(v4Addrs) == 0 && len(v6Addrs) == 0 {
		// Flush the delete only — no rules needed.
		if err := c.Flush(); err != nil {
			return fmt.Errorf("nftables flush (delete-only): %w", err)
		}
		return nil
	}

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   rstTableName,
	})

	chain := c.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   ptrPolicy(nftables.ChainPolicyAccept),
	})

	for _, addr := range v4Addrs {
		addRSTDropRuleV4(c, table, chain, addr.As4())
	}
	for _, addr := range v6Addrs {
		addRSTDropRuleV6(c, table, chain, addr.As16())
	}

	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}

	slog.Info("RST suppression: installed nftables rules via netlink",
		"v4", len(v4Addrs), "v6", len(v6Addrs))
	return nil
}

// RemoveRSTSuppression removes the RST suppression table.
func RemoveRSTSuppression() {
	c, err := nftables.New()
	if err != nil {
		return
	}
	removeRSTTable(c)
	_ = c.Flush()
}

// RSTSuppressionCounters reads the nftables counter values from the RST
// suppression rules. Returns total packets and bytes dropped across all
// rules. This is useful for diagnosing whether kernel RSTs are being
// caught during HA failover (#456).
func RSTSuppressionCounters() (packets uint64, bytes uint64, err error) {
	c, err := nftables.New()
	if err != nil {
		return 0, 0, fmt.Errorf("nftables conn: %w", err)
	}
	rules, err := c.GetRules(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   rstTableName,
	}, &nftables.Chain{Name: "output"})
	if err != nil {
		return 0, 0, fmt.Errorf("get rules: %w", err)
	}
	for _, rule := range rules {
		for _, e := range rule.Exprs {
			if counter, ok := e.(*expr.Counter); ok {
				packets += counter.Packets
				bytes += counter.Bytes
			}
		}
	}
	return packets, bytes, nil
}

func removeRSTTable(c *nftables.Conn) {
	c.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   rstTableName,
	})
}

func addRSTDropRuleV4(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, addr [4]byte) {
	addRSTDropRule(c, table, chain, net.IP(addr[:]), uint32(4), 12, unix.NFPROTO_IPV4)
}

func addRSTDropRuleV6(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, addr [16]byte) {
	addRSTDropRule(c, table, chain, net.IP(addr[:]), uint32(16), 8, unix.NFPROTO_IPV6)
}

// addRSTDropRule adds: meta nfproto <family> ip/ip6 saddr <addr> tcp flags & rst != 0 counter drop
func addRSTDropRule(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, addrBytes net.IP, addrLen uint32, saddrOffset uint32, family byte) {
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// meta nfproto ipv4/ipv6
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{family},
			},
			// ip/ip6 saddr == addr
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       saddrOffset,
				Len:          addrLen,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     addrBytes,
			},
			// meta l4proto tcp
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			// tcp flags & RST != 0
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       13, // TCP flags byte
				Len:          1,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            1,
				Mask:           []byte{0x04}, // RST flag
				Xor:            []byte{0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00},
			},
			// counter
			&expr.Counter{},
			// drop
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})
}

func ptrPolicy(p nftables.ChainPolicy) *nftables.ChainPolicy {
	return &p
}
