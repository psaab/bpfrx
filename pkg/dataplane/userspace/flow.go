package userspace

import "github.com/psaab/xpf/pkg/config"

func buildFlowSnapshot(cfg *config.Config) FlowSnapshot {
	snap := FlowSnapshot{
		AllowDNSReply:      cfg.Security.Flow.AllowDNSReply,
		AllowEmbeddedICMP:  cfg.Security.Flow.AllowEmbeddedICMP,
		TCPMSSIPsecVPN:     cfg.Security.Flow.TCPMSSIPsecVPN,
		TCPMSSGreIn:        cfg.Security.Flow.TCPMSSGreIn,
		TCPMSSGreOut:       cfg.Security.Flow.TCPMSSGreOut,
		UDPSessionTimeout:  cfg.Security.Flow.UDPSessionTimeout,
		ICMPSessionTimeout: cfg.Security.Flow.ICMPSessionTimeout,
		GREAcceleration:    cfg.Security.Flow.GREPerformanceAcceleration,
		Lo0FilterInputV4:   cfg.System.Lo0FilterInputV4,
		Lo0FilterInputV6:   cfg.System.Lo0FilterInputV6,
	}
	if cfg.Security.Flow.TCPSession != nil {
		snap.TCPSessionTimeout = cfg.Security.Flow.TCPSession.EstablishedTimeout
	}
	return snap
}

func buildFlowExportSnapshot(cfg *config.Config) *FlowExportSnapshot {
	if cfg == nil || cfg.Services.FlowMonitoring == nil {
		return nil
	}
	fm := cfg.Services.FlowMonitoring
	if fm.Version9 == nil || len(fm.Version9.Templates) == 0 {
		return nil
	}
	// Find sampling config for flow server
	if cfg.ForwardingOptions.Sampling == nil {
		return nil
	}
	for _, inst := range cfg.ForwardingOptions.Sampling.Instances {
		if inst == nil {
			continue
		}
		rate := inst.InputRate
		if rate <= 0 {
			rate = 1
		}
		families := []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6}
		for _, fam := range families {
			if fam == nil {
				continue
			}
			for _, server := range fam.FlowServers {
				if server == nil || server.Address == "" || server.Port == 0 {
					continue
				}
				snap := &FlowExportSnapshot{
					CollectorAddress: server.Address,
					CollectorPort:    server.Port,
					SamplingRate:     rate,
				}
				// Use template config if the server references one
				if server.Version9Template != "" && fm.Version9.Templates != nil {
					if tmpl, ok := fm.Version9.Templates[server.Version9Template]; ok {
						snap.ActiveTimeout = tmpl.FlowActiveTimeout
						snap.InactiveTimeout = tmpl.FlowInactiveTimeout
					}
				}
				return snap
			}
		}
	}
	return nil
}
