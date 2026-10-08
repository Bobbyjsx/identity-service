package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"identity-service/internal/core"
	"identity-service/internal/services"
)

func (s *Server) AdminCreateApplication(w http.ResponseWriter, r *http.Request) {
	var req services.ApplicationCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	creds, err := s.appService.RegisterApplication(r.Context(), req)
	if err != nil {
		handleError(w, err, false)
		return
	}

	core.WriteJSON(w, http.StatusOK, creds)
}

func (s *Server) AdminGetApplication(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "client_id")
	app, err := s.appService.GetByClientID(r.Context(), clientID)
	if err != nil {
		handleError(w, err, false)
		return
	}
	if app == nil {
		core.WriteDetail(w, http.StatusNotFound, "Application not found")
		return
	}

	core.WriteJSON(w, http.StatusOK, app)
}

func (s *Server) AdminUpdateApplicationConfig(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "client_id")
	var updates map[string]interface{}
	if err := decodeJSON(r, &updates); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	app, err := s.appService.UpdateApplicationConfig(r.Context(), clientID, updates)
	if err != nil {
		handleError(w, err, false)
		return
	}

	core.WriteJSON(w, http.StatusOK, app)
}

func (s *Server) AdminCreateAuthSession(w http.ResponseWriter, r *http.Request) {
	var req services.AuthorizationRequest
	if err := decodeJSON(r, &req); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	tx, err := s.oauthService.CreateSession(r.Context(), req)
	if err != nil {
		handleError(w, err, true)
		return
	}

	core.WriteJSON(w, http.StatusOK, map[string]string{
		"session_id": tx.ID,
		"status":     tx.Status,
	})
}
