package api

import (
	"fmt"
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
		var states map[string]string
		if s.vrrpMgr != nil {
			states = s.vrrpMgr.States()
		}
		for _, inst := range instances {
			addrs := inst.VirtualAddresses
			if addrs == nil {
				addrs = []string{}
			}
			key := fmt.Sprintf("VI_%s_%d", inst.Interface, inst.GroupID)
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
