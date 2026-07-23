package cluster

import (
	"context"
	"log/slog"
)

// nextConfigGen draws the next strictly-monotonic config generation stamped
// on an outgoing config-sync message (#3931). The counter is seeded from
// CLOCK_MONOTONIC nanos at construction so it never regresses below a value
// the peer may already hold across this node's restarts within a boot.
func (s *SessionSync) nextConfigGen() uint64 {
	return s.configGenCounter.Add(1)
}

// QueueConfig sends the full config text to the peer for configuration
// synchronization. The payload carries a monotonic config generation (#3931)
// so the receiver can order a rapid commit pair and refuse a reordered older
// config.
func (s *SessionSync) QueueConfig(configText string) {
	conn := s.getActiveConn()
	if conn == nil {
		return
	}
	gen := s.nextConfigGen()
	payload := encodeConfigPayload(configText, gen)
	s.writeMu.Lock()
	err := writeMsg(conn, syncMsgConfig, payload)
	s.writeMu.Unlock()
	if err != nil {
		slog.Warn("cluster sync: config send error", "err", err)
		s.stats.Errors.Add(1)
		s.handleDisconnect(conn)
		return
	}
	s.stats.ConfigsSent.Add(1)
	slog.Info("cluster sync: config sent to peer", "size", len(configText), "gen", gen)
}

// shouldApplyConfigGen is the admission half of the #3931 receiver-side config
// ordering guard. It returns true if a config with generation gen should be
// ATTEMPTED — gen==0 (a legacy sender / unknown, applied unconditionally) or
// strictly newer than the last SUCCESSFULLY-applied generation — and false if
// it is an out-of-order older / duplicate config that must be dropped.
//
// It deliberately does NOT advance the high-water mark; the caller advances via
// recordAppliedConfigGen ONLY after the apply succeeds (M-2/#4151). Advancing
// on admission (the pre-#4151 behavior) meant an apply failure left the
// high-water ahead of the actually-applied config, so the primary's re-push of
// the same generation was dropped as stale and the standby stayed silently
// stranded on the prior config. It is called ONLY from the single-consumer
// configApplyLoop, so the load needs no CAS.
func (s *SessionSync) shouldApplyConfigGen(gen uint64) bool {
	if gen == 0 {
		return true
	}
	last := s.lastAppliedConfigGen.Load()
	return last == 0 || gen > last
}

// recordAppliedConfigGen advances the config high-water mark after a config of
// generation gen has been SUCCESSFULLY applied. gen==0 (legacy / unconditional)
// never advances the mark, mirroring the pre-#3931 behavior. It is called ONLY
// from the single-consumer configApplyLoop after OnConfigReceived returns nil,
// so the load/store pair needs no CAS.
func (s *SessionSync) recordAppliedConfigGen(gen uint64) {
	if gen == 0 {
		return
	}
	if gen > s.lastAppliedConfigGen.Load() {
		s.lastAppliedConfigGen.Store(gen)
	}
}

// beginConfigApply raises the apply-in-progress fence to gen for the duration
// of an apply (#6284, item 2). It is set BEFORE OnConfigReceived runs — so it
// covers the whole apply, including the receiver's clearSessionsForDeletedPolicies
// sweep — and configEpochStale folds max(fence, high-water) into its refusal
// threshold. A gen==0 (legacy/unconditional) apply carries no comparable epoch,
// so the fence stays 0 and no install is refused on its account. Called ONLY
// from the single-consumer configApplyLoop, so the store needs no CAS.
func (s *SessionSync) beginConfigApply(gen uint64) {
	s.applyingConfigGen.Store(gen)
}

// endConfigApply lowers the apply-in-progress fence (#6284, item 2). On a
// SUCCESSFUL apply the caller advances the high-water (recordAppliedConfigGen)
// FIRST and only then calls this, so the effective refusal threshold
// max(fence, high-water) never dips between the sweep and the high-water
// advance — closing the residual window. On an apply FAILURE the high-water
// deliberately stays put (M-2/#4151) and the fence is simply dropped, restoring
// the pre-apply admission posture (the transiently-refused installs are re-sent
// by the peer's next sweep). Called ONLY from configApplyLoop.
func (s *SessionSync) endConfigApply() {
	s.applyingConfigGen.Store(0)
}

// configApplyLoop is the single ordered consumer of config-sync messages
// (#3931). It drains configApplyCh in receive order and attempts a config only
// when shouldApplyConfigGen accepts its generation, so a reordered older config
// from a rapid commit pair (C1 after C2) is dropped and the standby always
// converges to the newest config. Replaces the pre-#3931 racing
// `go OnConfigReceived` per message.
//
// The config high-water mark (lastAppliedConfigGen) advances ONLY after the
// apply succeeds (recordAppliedConfigGen, gated on OnConfigReceived returning
// nil). An apply failure counts ConfigsApplyFailed and leaves the high-water at
// the last-applied generation, so the primary's re-push of the same generation
// is re-admitted and the standby re-converges instead of being silently
// stranded on the prior config (M-2/#4151).
func (s *SessionSync) configApplyLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-s.configApplyCh:
			if !s.shouldApplyConfigGen(item.gen) {
				s.stats.ConfigsStaleIgnored.Add(1)
				slog.Warn("cluster sync: dropping out-of-order config sync (stale generation) — standby retains newer config",
					"incoming_gen", item.gen, "last_applied_gen", s.lastAppliedConfigGen.Load(), "size", len(item.text))
				continue
			}
			if s.OnConfigReceived == nil {
				// No apply handler wired — the config cannot be applied, so the
				// high-water must NOT advance (M-2/#4151). A later wired handler
				// re-applies on the primary's next push of this generation.
				continue
			}
			// #6284 item 2: fence installs against the generation being applied
			// for the ENTIRE apply. The clearSessionsForDeletedPolicies sweep
			// runs inside OnConfigReceived, so a synced session stamped with an
			// older epoch that races the sub-µs gap between the sweep and the
			// high-water advance must be refused now — the fence makes
			// configEpochStale refuse it against the applying generation rather
			// than admit it against the not-yet-advanced high-water.
			s.beginConfigApply(item.gen)
			if err := s.OnConfigReceived(item.text); err != nil {
				// The apply did not take effect (compile/promote failure or a
				// transient RG0-primary rejection). Do NOT advance the
				// high-water: leaving it at the last-applied generation keeps
				// the standby eligible for the primary's re-push so it
				// re-converges instead of being silently stranded (M-2/#4151).
				s.stats.ConfigsApplyFailed.Add(1)
				// Debug, not Warn: handleConfigSync (the callback) already logs
				// the authoritative one-time reason WHY the apply failed
				// (RG0-primary rejection at Warn, compile/promote failure at
				// Error). This line is the per-retry diagnostic detail of the
				// M-2/#4151 high-water retention, and the same generation may be
				// re-pushed on every reconnect while the condition persists — a
				// Warn here would spam (CLAUDE.md logging rule). The
				// rate-independent observable is the ConfigsApplyFailed counter
				// above (surfaced in cluster status), not this log.
				slog.Debug("cluster sync: config apply failed — retaining prior high-water so the peer re-push re-converges",
					"incoming_gen", item.gen, "last_applied_gen", s.lastAppliedConfigGen.Load(), "size", len(item.text), "err", err)
				// #6284: drop the fence — the high-water intentionally stays put
				// (M-2/#4151), so restore the pre-apply admission posture.
				s.endConfigApply()
				continue
			}
			// Apply confirmed — advance the high-water so a duplicate re-push of
			// the same generation is correctly skipped as stale, THEN drop the
			// fence. Advancing first keeps the effective refusal threshold
			// max(fence, high-water) from dipping in the release window (#6284).
			s.recordAppliedConfigGen(item.gen)
			s.endConfigApply()
		}
	}
}
