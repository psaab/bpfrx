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
	"context"
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
// topic that drives a full v4+v6 conntrack walk inside pkg/natshow (#6553),
// and returns the ADMISSION-LEASE context the walk must run under (#7315).
//
// These topics are reachable over the FABRIC listener (ShowText is on
// fabricAllowedUnaryMethods), unlike the loopback-only NAT RPCs, and before
// #6553 they walked the whole table with no admission at all.
//
// #6553 could only land the ADMISSION half: pkg/natshow's Render* helpers took
// no context and are shared with pkg/cli, so it used the plain Acquire and
// disclosed cancellation as a residual. #7315 threads the context through
// pkg/natshow, so this now AcquireCtx's and hands the lease context down.
// Admission bounds CONCURRENCY; the lease bounds DURATION under a
// disconnected client — and the two fail independently, because a handler can
// hold its slot correctly and still run the walk to completion after the
// client is gone. That matters here specifically because REST and gRPC alias
// ONE 4-slot diagcmd.SessionWalkLimiter: the slot a departed client's walk
// keeps is a slot the REST surfaces that DO honour cancellation are queueing
// for.
//
// AcquireCtx rather than Acquire also makes these topics consistent with
// GetNATPoolStats / GetNATDestination (server_nat.go), which have taken the
// lease form since #6553. There is no in-process delegation under ShowText
// today, so the lease-REUSE arm of AcquireCtx is not exercised from here; it
// is the cancellation propagation that is load-bearing.
//
// ShowText returns this handler error verbatim, so an over-cap topic surfaces
// as codes.ResourceExhausted.
func (s *Server) acquireNATShowWalk(ctx context.Context, what string) (func(), context.Context, error) {
	release, walkCtx, err := sessionWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		return nil, ctx, status.Errorf(codes.ResourceExhausted,
			"%s: session scan concurrency limit reached; retry shortly", what)
	}
	return release, walkCtx, nil
}

// showPersistentNAT renders the persistent-NAT bindings table with
// remaining timeout per binding.
//
// It passes NO context to the renderer because RenderPersistent drives no
// conntrack walk — its only dataplane read is an O(bindings) snapshot copy of
// the in-process persistent-NAT map under that table's own RWMutex. #7315's
// premise counted it among the four walking topics, citing two persistent.go
// line numbers that are both inside RenderPersistentDetail. Giving it a
// context would be a cancellation guarantee over nothing.
//
// The admission slot is KEPT even so: the snapshot is still an O(bindings)
// allocation on a fabric-reachable surface, and dropping a bound that exists
// is a separate judgement from adding the cancellation this change is about.
func (s *Server) showPersistentNAT(ctx context.Context, buf *strings.Builder) error {
	release, _, err := s.acquireNATShowWalk(ctx, "persistent-nat")
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
func (s *Server) showNATSourceRuleDetail(ctx context.Context, cfg *config.Config, buf *strings.Builder) error {
	release, walkCtx, err := s.acquireNATShowWalk(ctx, "nat-source-rule-detail")
	if err != nil {
		return err
	}
	defer release()
	natshow.RenderSourceRuleDetail(walkCtx, buf, cfg, s.dp, s.applyResult)
	return nil
}

// showNATDestRuleDetail renders detailed destination NAT rule
// information, including pool address/port, translation hit counters,
// and active session counts per rule-set.
func (s *Server) showNATDestRuleDetail(ctx context.Context, cfg *config.Config, buf *strings.Builder) error {
	release, walkCtx, err := s.acquireNATShowWalk(ctx, "nat-dest-rule-detail")
	if err != nil {
		return err
	}
	defer release()
	natshow.RenderDestRuleDetail(walkCtx, buf, cfg, s.dp, s.applyResult)
	return nil
}

// showPersistentNATDetail renders per-binding detail for persistent-NAT
// bindings, including current session counts per (NAT IP, NAT port).
func (s *Server) showPersistentNATDetail(ctx context.Context, buf *strings.Builder) error {
	release, walkCtx, err := s.acquireNATShowWalk(ctx, "persistent-nat-detail")
	if err != nil {
		return err
	}
	defer release()
	natshow.RenderPersistentDetail(walkCtx, buf, s.dp)
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
