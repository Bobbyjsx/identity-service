package handlers

import (
	"net/http"
	"strings"

	"identity-service/internal/core"
	"identity-service/internal/services"
)

func (s *Server) OAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	if responseType == "" {
		responseType = "code"
	}
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}
	if codeChallengeMethod != "S256" {
		core.WriteValidationError(w, "only the S256 code challenge method is supported")
		return
	}

	if clientID == "" || redirectURI == "" || codeChallenge == "" {
		core.WriteValidationError(w, "client_id, redirect_uri, and code_challenge are required")
		return
	}

	var scope *string
	if val := q.Get("scope"); val != "" {
		scope = &val
	}
	var state *string
	if val := q.Get("state"); val != "" {
		state = &val
	}
	var nonce *string
	if val := q.Get("nonce"); val != "" {
		nonce = &val
	}

	app, err := s.oauthService.ResolveClient(r.Context(), clientID)
	if err != nil {
		handleError(w, err, true)
		return
	}

	if err := s.oauthService.ValidateRedirect(app, redirectURI); err != nil {
		handleError(w, err, true)
		return
	}

	req := services.AuthorizationRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scope:               scope,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
	}

	tx, err := s.oauthService.CreateSession(r.Context(), req)
	if err != nil {
		if oauthErr, ok := err.(*core.OAuthError); ok {
			redirectURL := s.oauthService.BuildErrorRedirect(redirectURI, state, oauthErr.ErrorType, oauthErr.ErrorDescription)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		handleError(w, err, true)
		return
	}

	targetURL := s.oauthService.BuildIdentityUIRedirect(tx.ID)
	http.Redirect(w, r, targetURL, http.StatusFound)
}

func (s *Server) OAuthToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		core.WriteOAuthError(w, core.NewOAuthError("invalid_request", "Failed to parse form body", http.StatusBadRequest))
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")
	audience := r.FormValue("audience")

	if grantType == "" || clientID == "" {
		core.WriteOAuthError(w, core.NewOAuthError("invalid_request", "grant_type and client_id are required", http.StatusBadRequest))
		return
	}

	if grantType == "client_credentials" {
		if clientSecret == "" {
			core.WriteOAuthError(w, core.NewOAuthError("invalid_client", "client_secret is required", http.StatusBadRequest))
			return
		}
		if audience == "" {
			core.WriteOAuthError(w, core.NewOAuthError("invalid_request", "audience is required for client_credentials", http.StatusBadRequest))
			return
		}

		app, err := s.oauthService.ResolveClient(r.Context(), clientID)
		if err != nil {
			handleError(w, err, true)
			return
		}
		if err := s.oauthService.ValidateGrantAllowed(app, "client_credentials"); err != nil {
			handleError(w, err, true)
			return
		}

		appID, err := s.appService.VerifyClientCredentials(r.Context(), clientID, clientSecret)
		if err != nil {
			core.WriteOAuthError(w, core.NewOAuthError("invalid_client", "Invalid client credentials", http.StatusUnauthorized))
			return
		}

		tokens, err := s.authService.GenerateServiceToken(appID, audience)
		if err != nil {
			handleError(w, err, true)
			return
		}

		core.WriteJSON(w, http.StatusOK, tokens)
		return
	}

	if grantType == "authorization_code" {
		if code == "" || redirectURI == "" || codeVerifier == "" {
			core.WriteOAuthError(w, core.NewOAuthError("invalid_request", "code, redirect_uri, and code_verifier are required for authorization_code", http.StatusBadRequest))
			return
		}

		var cs *string
		if clientSecret != "" {
			cs = &clientSecret
		}

		tokens, err := s.oauthService.ExchangeAuthorizationCode(r.Context(), code, clientID, redirectURI, codeVerifier, cs)
		if err != nil {
			handleError(w, err, true)
			return
		}

		core.WriteJSON(w, http.StatusOK, tokens)
		return
	}

	core.WriteOAuthError(w, core.NewOAuthError("unsupported_grant_type", "Unsupported grant_type: "+strings.TrimSpace(grantType), http.StatusBadRequest))
}
