package api

import (
	"net/http"

	"github.com/psaab/xpf/pkg/vrrp"
)

func (s *Server) vrrpHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	resp := VRRPStatusResponse{
		Instances: []VRRPInstanceInfo{},
	}

	if cfg != nil {
		instances := vrrp.CollectInstances(cfg)
		// #8321 finding 15: on a chassis cluster the VIPs live on RETH
		// instances, and this handler collected only the generic
		// per-interface `vrrp-group` ones — so the REST endpoint returned an
		// EMPTY instance list on exactly the deployments that have VRRP. The
		// gRPC GetVRRPStatus (grpcapi/server_nat.go) has appended these all
		// along; this is a parity gap with it, not a missing feature.
		// CollectRethInstances itself returns nil for a non-clustered config
		// and for `no-reth-vrrp` / private-RG election, so the append is a
		// no-op wherever RETH VRRP is not in play.
		if s.vrrpLocalPrioritiesFn != nil {
			instances = append(instances, vrrp.CollectRethInstances(cfg, s.vrrpLocalPrioritiesFn())...)
		}
		var states map[string]string
		if s.vrrpMgr != nil {
			states = s.vrrpMgr.States()
		}
		for _, inst := range instances {
			addrs := inst.VirtualAddresses
			if addrs == nil {
				addrs = []string{}
			}
			key := vrrp.StateKey(inst.Interface, inst.GroupID, inst.Family)
			state := "INIT"
			if st, ok := states[key]; ok {
				state = st
			}
			resp.Instances = append(resp.Instances, VRRPInstanceInfo{
				Interface:        inst.Interface,
				GroupID:          inst.GroupID,
				State:            state,
				Priority:         inst.Priority,
				VirtualAddresses: addrs,
				Preempt:          inst.Preempt,
			})
		}
	}

	if s.vrrpMgr != nil {
		resp.ServiceStatus = s.vrrpMgr.Status()
	} else {
		resp.ServiceStatus = "VRRP: not running\n"
	}
	writeOK(w, resp)
}
