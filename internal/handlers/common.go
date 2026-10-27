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
	cfg              *config.Config
	appService       *services.ApplicationService
	authService      *services.AuthService
	oauthService     *services.OAuthService
	rbacService      *services.RBACService
	keyManager       *services.KeyManager
	openidConfigJSON []byte
}

func NewServer(
	cfg *config.Config,
	appService *services.ApplicationService,
	authService *services.AuthService,
	oauthService *services.OAuthService,
	rbacService *services.RBACService,
	keyManager *services.KeyManager,
) *Server {
	base := strings.TrimRight(cfg.PublicBaseURL, "/")
	configMap := map[string]interface{}{
		"issuer":                                cfg.IdentityIssuer,
		"authorization_endpoint":                base + "/api/v1/oauth/authorize",
		"token_endpoint":                        base + "/api/v1/oauth/token",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"scopes_supported":                      []string{"email", "openid", "profile"},
		"claims_supported": []string{
			"iss",
			"sub",
			"aud",
			"iat",
			"exp",
			"jti",
			"nonce",
			"email",
			"email_verified",
			"name",
			"preferred_username",
		},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
	}
	openidJSON, _ := json.Marshal(configMap)

	return &Server{
		cfg:              cfg,
		appService:       appService,
		authService:      authService,
		oauthService:     oauthService,
		rbacService:      rbacService,
		keyManager:       keyManager,
		openidConfigJSON: openidJSON,
	}
}

func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	err := json.NewDecoder(io.LimitReader(r.Body, 1048576)).Decode(v)
	if err == io.EOF {
		return nil
	}
	return err
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
			core.SetRequestApp(r.Context(), appID, "")
			core.WriteDetail(w, http.StatusForbidden, "Invalid application context")
			return
		}
		core.SetRequestApp(r.Context(), app.ClientID, app.Name)
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

		if app, _ := s.appService.GetByClientID(r.Context(), appID); app != nil {
			core.SetRequestApp(r.Context(), app.ClientID, app.Name)
		} else {
			core.SetRequestApp(r.Context(), appID, "")
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
