package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func (s *Server) dhcpLeasesHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dhcp == nil {
		writeOK(w, []DHCPLeaseInfo{})
		return
	}

	leases := s.dhcp.Leases()
	result := make([]DHCPLeaseInfo, len(leases))
	for i, l := range leases {
		family := "inet"
		if l.Family == 6 {
			family = "inet6"
		}
		info := DHCPLeaseInfo{
			Interface: l.Interface,
			Family:    family,
			Address:   l.Address.String(),
			LeaseTime: l.LeaseTime.String(),
			Obtained:  l.Obtained.Format(time.RFC3339),
		}
		if l.Gateway.IsValid() {
			info.Gateway = l.Gateway.String()
		}
		for _, dns := range l.DNS {
			info.DNS = append(info.DNS, dns.String())
		}
		if info.DNS == nil {
			info.DNS = []string{}
		}
		result[i] = info
	}
	writeOK(w, result)
}

func (s *Server) dhcpIdentifiersHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dhcp == nil {
		writeOK(w, []DHCPClientIdentifierInfo{})
		return
	}

	duids := s.dhcp.DUIDs()
	result := make([]DHCPClientIdentifierInfo, len(duids))
	for i, d := range duids {
		result[i] = DHCPClientIdentifierInfo{
			Interface: d.Interface,
			Type:      d.Type,
			Display:   d.Display,
			Hex:       d.HexBytes,
		}
	}
	writeOK(w, result)
}

func (s *Server) clearDHCPIdentifiersHandler(w http.ResponseWriter, r *http.Request) {
	if s.dhcp == nil {
		writeOK(w, map[string]string{"message": "No DHCP clients running"})
		return
	}

	var req ClearDHCPIdentifierRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	if req.Interface != "" {
		if err := s.dhcp.ClearDUID(req.Interface); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeOK(w, map[string]string{"message": fmt.Sprintf("DHCPv6 DUID cleared for %s", req.Interface)})
		return
	}

	s.dhcp.ClearAllDUIDs()
	writeOK(w, map[string]string{"message": "All DHCPv6 DUIDs cleared"})
}
