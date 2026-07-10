package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// #4794: gate on ContentLength != 0, not > 0. A chunked-encoded request
	// (Transfer-Encoding: chunked) reports ContentLength == -1 (unknown
	// length), so the old "> 0" gate skipped the body decode entirely and
	// fell through to ClearAllDUIDs() below even when the operator's body
	// asked to clear a single interface -- wiping every DHCPv6 DUID instead.
	// ContentLength == 0 (a genuinely empty body, no Transfer-Encoding) still
	// skips the decode, matching the documented "no interface = clear all"
	// contract. A chunked request that happens to carry zero bytes hits
	// io.EOF on Decode, which is tolerated below (not a 400) for the same
	// reason.
	if r.ContentLength != 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
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

	if err := s.dhcp.ClearAllDUIDs(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]string{"message": "All DHCPv6 DUIDs cleared"})
}
