package api

import (
	"fmt"
	"net/http"
	"strings"
)

func (s *Server) ipsecSAHandler(w http.ResponseWriter, _ *http.Request) {
	if s.ipsec == nil {
		writeOK(w, TextResponse{Output: "IPsec not available"})
		return
	}
	sas, err := s.ipsec.GetSAStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var b strings.Builder
	for _, sa := range sas {
		fmt.Fprintf(&b, "SA: %s  State: %s", sa.Name, sa.State)
		if sa.LocalAddr != "" {
			fmt.Fprintf(&b, "  Local: %s", sa.LocalAddr)
		}
		if sa.RemoteAddr != "" {
			fmt.Fprintf(&b, "  Remote: %s", sa.RemoteAddr)
		}
		b.WriteString("\n")
	}
	writeOK(w, TextResponse{Output: b.String()})
}
