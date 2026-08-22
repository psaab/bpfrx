// NAT-related ShowText case bodies.
//
// #1687: the six byte-identical NAT renderers (static, nptv6,
// persistent-nat, persistent-nat-detail, source-rule-detail,
// dest-rule-detail) were extracted to the shared pkg/natshow package so
// the gRPC ShowText path and the CLI show path single-source them. The
// methods below are thin sink-binding wrappers that pass the gRPC
// *strings.Builder as the io.Writer. showNAT64 stays here: its empty
// message diverges from the CLI ("...configured" vs "...configured."),
// so it is intentionally NOT shared.
//
// History: Phase 3 of #1043 first extracted these case bodies from the
// ShowText switch into dedicated methods (verbatim, no behavior change).

package grpcapi

import (
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/natshow"
)

// showNATStatic renders `cli show security nat static` — static NAT and
// NPTv6 rule-sets from configuration.
func (s *Server) showNATStatic(cfg *config.Config, buf *strings.Builder) {
	natshow.RenderStatic(buf, cfg)
}

// showNATNPTv6 renders `cli show security nat nptv6` — only the NPTv6
// rules within the static rule-sets.
func (s *Server) showNATNPTv6(cfg *config.Config, buf *strings.Builder) {
	natshow.RenderNPTv6(buf, cfg)
}

// acquireNATShowWalk takes a sessionWalkLimiter slot for a `show security nat`
// topic that drives a full v4+v6 conntrack walk inside pkg/natshow (#6553).
//
// These four topics are reachable over the FABRIC listener (ShowText is on
// fabricAllowedUnaryMethods), unlike the loopback-only NAT RPCs, and they were
// walking the whole table with no admission at all. The plain Acquire (not
// AcquireCtx) matches the existing ShowText precedent in server_show_flow.go
// and server_show_system.go: pkg/natshow's Render* helpers take no context and
// are shared with pkg/cli, so threading a lease context through them is a
// cross-surface signature change tracked separately rather than smuggled in
// here. The ADMISSION half is what stops a scrape flood from multiplying
// concurrent table walks; the cancellation half is the stated residual.
//
// ShowText returns this handler error verbatim, so an over-cap topic surfaces
// as codes.ResourceExhausted.
func (s *Server) acquireNATShowWalk(what string) (func(), error) {
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		return nil, status.Errorf(codes.ResourceExhausted,
			"%s: session scan concurrency limit reached; retry shortly", what)
	}
	return release, nil
}

// showPersistentNAT renders the persistent-NAT bindings table with
// remaining timeout per binding.
func (s *Server) showPersistentNAT(buf *strings.Builder) error {
	release, err := s.acquireNATShowWalk("persistent-nat")
	if err != nil {
		return err
	}
	defer release()
	natshow.RenderPersistent(buf, s.dp)
	return nil
}

// showNATSourceRuleDetail renders detailed source NAT rule information,
// including pool details, translation hit counters, and active session
// counts per rule-set.
func (s *Server) showNATSourceRuleDetail(cfg *config.Config, buf *strings.Builder) error {
	release, err := s.acquireNATShowWalk("nat-source-rule-detail")
	if err != nil {
		return err
	}
	defer release()
	natshow.RenderSourceRuleDetail(buf, cfg, s.dp, s.applyResult)
	return nil
}

// showNATDestRuleDetail renders detailed destination NAT rule
// information, including pool address/port, translation hit counters,
// and active session counts per rule-set.
func (s *Server) showNATDestRuleDetail(cfg *config.Config, buf *strings.Builder) error {
	release, err := s.acquireNATShowWalk("nat-dest-rule-detail")
	if err != nil {
		return err
	}
	defer release()
	natshow.RenderDestRuleDetail(buf, cfg, s.dp, s.applyResult)
	return nil
}

// showPersistentNATDetail renders per-binding detail for persistent-NAT
// bindings, including current session counts per (NAT IP, NAT port).
func (s *Server) showPersistentNATDetail(buf *strings.Builder) error {
	release, err := s.acquireNATShowWalk("persistent-nat-detail")
	if err != nil {
		return err
	}
	defer release()
	natshow.RenderPersistentDetail(buf, s.dp)
	return nil
}

// showNAT64 renders `cli show security nat nat64` — NAT64 rule-sets
// from configuration.
func (s *Server) showNAT64(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.Security.NAT.NAT64) == 0 {
		buf.WriteString("No NAT64 rule-sets configured\n")
		return
	}
	for _, rs := range cfg.Security.NAT.NAT64 {
		fmt.Fprintf(buf, "NAT64 rule-set: %s\n", rs.Name)
		if rs.Prefix != "" {
			fmt.Fprintf(buf, "  Prefix:      %s\n", rs.Prefix)
		}
		if rs.SourcePool != "" {
			fmt.Fprintf(buf, "  Source pool:  %s\n", rs.SourcePool)
		}
		buf.WriteString("\n")
	}
}
