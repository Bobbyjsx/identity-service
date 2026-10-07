package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"identity-service/internal/core"
)

func (s *Server) PublicApplicationConfiguration(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "client_id")
	config, err := s.oauthService.GetPublicConfiguration(r.Context(), clientID)
	if err != nil {
		handleError(w, err, true)
		return
	}

	core.WriteJSON(w, http.StatusOK, config)
}
