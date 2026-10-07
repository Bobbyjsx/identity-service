package handlers_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"identity-service/internal/models"
)

func TestAuthorizeValidRequestRedirectsToIdentityUI(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	authURL := fmt.Sprintf("/api/v1/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+profile+email&code_challenge=%s&code_challenge_method=S256&state=abc123",
		clientID, url.QueryEscape(redirectURI), challenge)
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("Expected 302, got %d: %s", w.Code, w.Body.String())
	}

	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, cfg.IdentityUIBaseURL+"/auth/") {
		t.Fatalf("Expected location prefix %s/auth/, got %s", cfg.IdentityUIBaseURL, loc)
	}

	parts := strings.Split(loc, "/auth/")
	sessionID := strings.Split(parts[1], "/")[0]

	// Verify session persisted in database
	snap, err := testDB.Collection("auth_sessions").Doc(sessionID).Get(context.Background())
	if err != nil {
		t.Fatalf("Failed to fetch session from DB: %v", err)
	}

	var sess models.AuthSession
	_ = snap.DataTo(&sess)
	if sess.ClientID != clientID {
		t.Errorf("Expected client_id %s, got %s", clientID, sess.ClientID)
	}
	if sess.RedirectURI != redirectURI {
		t.Errorf("Expected redirect_uri %s, got %s", redirectURI, sess.RedirectURI)
	}
	if sess.State == nil || *sess.State != "abc123" {
		t.Errorf("Expected state abc123, got %v", sess.State)
	}
	if sess.Status != "pending" {
		t.Errorf("Expected status pending, got %s", sess.Status)
	}
}

func TestAuthorizeUnknownClientRejected(t *testing.T) {
	setupTest(t)
	_, challenge := pkcePair()
	authURL := fmt.Sprintf("/api/v1/oauth/authorize?client_id=app_nonexistent&redirect_uri=https://example.com/cb&response_type=code&code_challenge=%s&code_challenge_method=S256", challenge)
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d", w.Code)
	}
}

func TestAuthorizeInactiveApplicationRejected(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	// Set application status inactive
	iter := testDB.Collection("applications").Where("client_id", "==", clientID).Documents(context.Background())
	doc, err := iter.Next()
	if err == nil {
		_, _ = doc.Ref.Update(context.Background(), []firestore.Update{
			{Path: "status", Value: "inactive"},
		})
	}

	authURL := fmt.Sprintf("/api/v1/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256",
		clientID, url.QueryEscape(redirectURI), challenge)
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for inactive app, got %d", w.Code)
	}
}

func TestAuthorizeLocalhostHTTPRedirectAllowed(t *testing.T) {
	setupTest(t)
	localhost := "http://localhost:3000/callback"
	clientID, _ := createTestApp(t, localhost)
	_, challenge := pkcePair()

	sessionID := authorizeAndGetSession(t, clientID, localhost, "xyz", challenge)
	if !strings.HasPrefix(sessionID, "tx_") {
		t.Errorf("Expected session ID prefix tx_, got %s", sessionID)
	}
}

func TestAuthorizeUnregisteredRedirectURIsRejected(t *testing.T) {
	setupTest(t)
	clientID, _ := createTestApp(t, "https://example.com/callback")
	_, challenge := pkcePair()

	tamperedURIs := []string{
		"https://evil.example.com/callback",
		"https://example.com/callback/extra",
		"https://example.com/callback?foo=bar",
		"https://example.com/callbackx",
		"https://example.com/Callback",
	}

	for _, uri := range tamperedURIs {
		authURL := fmt.Sprintf("/api/v1/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256",
			clientID, url.QueryEscape(uri), challenge)
		req := httptest.NewRequest(http.MethodGet, authURL, nil)
		w := httptest.NewRecorder()
		testRouter.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 for unregistered URI %s, got %d", uri, w.Code)
		}
	}
}

func TestAuthorizeInvalidScopeRedirectsWithError(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	authURL := fmt.Sprintf("/api/v1/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+admin:everything&code_challenge=%s&code_challenge_method=S256&state=state123",
		clientID, url.QueryEscape(redirectURI), challenge)
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("Expected 302, got %d", w.Code)
	}

	loc := w.Header().Get("Location")
	u, _ := url.Parse(loc)
	if u.Query().Get("error") != "invalid_scope" {
		t.Errorf("Expected error=invalid_scope, got %s", u.Query().Get("error"))
	}
	if u.Query().Get("state") != "state123" {
		t.Errorf("Expected state=state123, got %s", u.Query().Get("state"))
	}
}

func TestAuthorizeUnsupportedResponseTypeRedirectsWithError(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	for _, respType := range []string{"token", "code id_token"} {
		authURL := fmt.Sprintf("/api/v1/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=%s&code_challenge=%s&code_challenge_method=S256&state=state123",
			clientID, url.QueryEscape(redirectURI), url.QueryEscape(respType), challenge)
		req := httptest.NewRequest(http.MethodGet, authURL, nil)
		w := httptest.NewRecorder()
		testRouter.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("Expected 302 for unsupported response type %s, got %d", respType, w.Code)
		}
		loc := w.Header().Get("Location")
		u, _ := url.Parse(loc)
		if u.Query().Get("error") != "unsupported_response_type" {
			t.Errorf("Expected unsupported_response_type, got %s", u.Query().Get("error"))
		}
	}
}

func TestAuthorizeMissingPKCERejected(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)

	authURL := fmt.Sprintf("/api/v1/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code",
		clientID, url.QueryEscape(redirectURI))
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected 422 for missing PKCE, got %d", w.Code)
	}
}

func TestAuthorizePlainCodeChallengeMethodRejected(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)

	authURL := fmt.Sprintf("/api/v1/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=plainval&code_challenge_method=plain",
		clientID, url.QueryEscape(redirectURI))
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected 422 for plain code_challenge_method, got %d", w.Code)
	}
}

func TestLoadSessionReturnsSafeContext(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestAppWithConfig(t, map[string]interface{}{
		"name": "Branded Test App",
		"branding": map[string]interface{}{
			"logo_url":      "https://cdn.example.com/logo.png",
			"primary_color": "#112233",
		},
		"oauth": map[string]interface{}{
			"redirect_uris":  []string{redirectURI},
			"allowed_scopes": []string{"openid", "profile", "email"},
		},
	})
	_, challenge := pkcePair()

	sessionID := authorizeAndGetSession(t, clientID, redirectURI, "client-state", challenge)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth-sessions/"+sessionID, nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	for _, secret := range []string{"client_secret", "code_challenge", "hashed_secret", "state"} {
		if strings.Contains(body, secret) {
			t.Errorf("Session response must not leak %s", secret)
		}
	}
}

func TestCancelledSessionReuseRejected(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessionID := authorizeAndGetSession(t, clientID, redirectURI, "sample-state", challenge)

	// Cancel session
	reqCancel := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/cancel", nil)
	wCancel := httptest.NewRecorder()
	testRouter.ServeHTTP(wCancel, reqCancel)

	if wCancel.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", wCancel.Code)
	}

	// Login on cancelled session must be rejected
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/login", strings.NewReader(`{"email":"a@example.com","password":"pwd"}`))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	testRouter.ServeHTTP(wLogin, reqLogin)

	if wLogin.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 on cancelled session login, got %d", wLogin.Code)
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessionID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	// Update expires_at into past
	pastTime := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	_, _ = testDB.Collection("auth_sessions").Doc(sessionID).Update(context.Background(), []firestore.Update{
		{Path: "expires_at", Value: pastTime},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth-sessions/"+sessionID, nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"expired"`) {
		t.Errorf("Expected status expired in session response: %s", w.Body.String())
	}
}

func TestInternalSessionCreationAdminProtected(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	body := fmt.Sprintf(`{"client_id":%q,"redirect_uri":%q,"response_type":"code","code_challenge":%q,"code_challenge_method":"S256"}`,
		clientID, redirectURI, challenge)

	// Unauthorized
	reqUnauth := httptest.NewRequest(http.MethodPost, "/api/v1/admin/auth-sessions", strings.NewReader(body))
	reqUnauth.Header.Set("Content-Type", "application/json")
	wUnauth := httptest.NewRecorder()
	testRouter.ServeHTTP(wUnauth, reqUnauth)
	if wUnauth.Code != http.StatusForbidden && wUnauth.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected 403 or 422, got %d", wUnauth.Code)
	}

	// Authorized
	reqAuth := httptest.NewRequest(http.MethodPost, "/api/v1/admin/auth-sessions", strings.NewReader(body))
	reqAuth.Header.Set("Content-Type", "application/json")
	reqAuth.Header.Set("X-Admin-Token", cfg.AdminSecret)
	wAuth := httptest.NewRecorder()
	testRouter.ServeHTTP(wAuth, reqAuth)
	if wAuth.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", wAuth.Code, wAuth.Body.String())
	}
}
