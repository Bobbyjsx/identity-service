package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"identity-service/internal/core"
)

func (s *Server) WellKnownJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300, stale-while-revalidate=86400")
	jwks, err := s.keyManager.GetJWKS(r.Context())
	if err != nil {
		handleError(w, err, true)
		return
	}
	core.WriteJSON(w, http.StatusOK, jwks)
}

func (s *Server) WellKnownOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300, stale-while-revalidate=86400")
	base := strings.TrimRight(s.cfg.PublicBaseURL, "/")

	config := map[string]interface{}{
		"issuer":                                s.cfg.IdentityIssuer,
		"authorization_endpoint":                fmt.Sprintf("%s/api/v1/oauth/authorize", base),
		"token_endpoint":                        fmt.Sprintf("%s/api/v1/oauth/token", base),
		"jwks_uri":                              fmt.Sprintf("%s/.well-known/jwks.json", base),
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

	core.WriteJSON(w, http.StatusOK, config)
}
