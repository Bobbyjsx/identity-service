package handlers

import (
	"net/http"

	"identity-service/internal/core"
	"identity-service/internal/models"
	"identity-service/internal/services"
)

func (s *Server) RBACCreatePermission(w http.ResponseWriter, r *http.Request, app *models.Application) {
	var req services.PermissionCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	perm, err := s.rbacService.CreatePermission(r.Context(), app.ID, req)
	if err != nil {
		handleError(w, err, false)
		return
	}

	core.WriteJSON(w, http.StatusOK, perm)
}

func (s *Server) RBACListPermissions(w http.ResponseWriter, r *http.Request, app *models.Application) {
	perms, err := s.rbacService.GetPermissions(r.Context(), app.ID)
	if err != nil {
		handleError(w, err, false)
		return
	}

	core.WriteJSON(w, http.StatusOK, perms)
}

func (s *Server) RBACCreateRole(w http.ResponseWriter, r *http.Request, app *models.Application) {
	var req services.RoleCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	role, err := s.rbacService.CreateRole(r.Context(), app.ID, req)
	if err != nil {
		handleError(w, err, false)
		return
	}

	core.WriteJSON(w, http.StatusOK, role)
}

func (s *Server) RBACListRoles(w http.ResponseWriter, r *http.Request, app *models.Application) {
	roles, err := s.rbacService.GetRoles(r.Context(), app.ID)
	if err != nil {
		handleError(w, err, false)
		return
	}

	core.WriteJSON(w, http.StatusOK, roles)
}
