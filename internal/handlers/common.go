package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"identity-service/internal/config"
	"identity-service/internal/core"
	"identity-service/internal/models"
	"identity-service/internal/services"
)

type Server struct {
	cfg         *config.Config
	appService  *services.ApplicationService
	authService *services.AuthService
	oauthService *services.OAuthService
	rbacService *services.RBACService
	keyManager  *services.KeyManager
}

func NewServer(
	cfg *config.Config,
	appService *services.ApplicationService,
	authService *services.AuthService,
	oauthService *services.OAuthService,
	rbacService *services.RBACService,
	keyManager *services.KeyManager,
) *Server {
	return &Server{
		cfg:          cfg,
		appService:   appService,
		authService:  authService,
		oauthService: oauthService,
		rbacService:  rbacService,
		keyManager:   keyManager,
	}
}

func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, v)
}

func (s *Server) verifyAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			core.WriteValidationError(w, "Field required: X-Admin-Token")
			return
		}
		if token != s.cfg.AdminSecret {
			core.WriteDetail(w, http.StatusForbidden, "Invalid admin token")
			return
		}
		next(w, r)
	}
}

func (s *Server) verifyApp(next func(w http.ResponseWriter, r *http.Request, app *models.Application)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appID := r.Header.Get("X-Application-Id")
		if appID == "" {
			core.WriteValidationError(w, "Field required: X-Application-Id")
			return
		}
		app, err := s.appService.GetByClientID(r.Context(), appID)
		if err != nil || app == nil {
			core.WriteDetail(w, http.StatusUnauthorized, "Invalid application ID")
			return
		}
		next(w, r, app)
	}
}

func (s *Server) authenticateBearer(next func(w http.ResponseWriter, r *http.Request, user *models.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			core.WriteDetail(w, http.StatusUnauthorized, "Not authenticated")
			return
		}
		tokenStr := strings.TrimSpace(authHeader[7:])
		claims, err := s.keyManager.VerifyJWT(tokenStr, []string{"application_api", "target-service"})
		if err != nil {
			core.WriteDetail(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		sub, _ := claims["sub"].(string)
		appID, _ := claims["app_id"].(string)
		if sub == "" || appID == "" {
			core.WriteDetail(w, http.StatusUnauthorized, "Invalid token payload")
			return
		}

		user, err := s.authService.GetUserByID(r.Context(), appID, sub)
		if err != nil || user == nil {
			core.WriteDetail(w, http.StatusUnauthorized, "User not found")
			return
		}

		next(w, r, user)
	}
}

func handleError(w http.ResponseWriter, err error, isOAuthPath bool) {
	if oauthErr, ok := err.(*core.OAuthError); ok {
		core.WriteOAuthError(w, oauthErr)
		return
	}
	if httpErr, ok := err.(*core.HTTPError); ok {
		if httpErr.StatusCode == http.StatusUnprocessableEntity {
			core.WriteValidationError(w, httpErr.Detail)
			return
		}
		core.WriteDetail(w, httpErr.StatusCode, httpErr.Detail)
		return
	}
	if isOAuthPath {
		core.WriteOAuthError(w, core.NewOAuthError("server_error", "An unexpected error occurred", http.StatusInternalServerError))
		return
	}
	core.WriteDetail(w, http.StatusInternalServerError, "Internal server error")
}
