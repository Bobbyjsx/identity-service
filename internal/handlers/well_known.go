package handlers

import (
	"net/http"
)

func (s *Server) WellKnownJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=2592000, stale-while-revalidate=604800")
	w.Header().Set("Content-Type", "application/json")
	data, err := s.keyManager.GetJWKSBytes(r.Context())
	if err != nil {
		handleError(w, err, true)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) WellKnownOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=604800, stale-while-revalidate=86400")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.openidConfigJSON)
}
