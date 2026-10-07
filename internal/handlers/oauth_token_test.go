package handlers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"identity-service/internal/models"
)

func TestTokenAuthorizationCodeSuccess(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	verifier, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state123", challenge)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	code := loginAndGetCode(t, sessID, email, "password123")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Token exchange failed: %d, %s", w.Code, w.Body.String())
	}

	var res models.TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}

	if res.AccessToken == "" {
		t.Errorf("Missing access_token")
	}
	if res.IDToken == nil || *res.IDToken == "" {
		t.Errorf("Missing id_token")
	}
	if res.RefreshToken == nil || *res.RefreshToken == "" {
		t.Errorf("Missing refresh_token")
	}
	if strings.ToLower(res.TokenType) != "bearer" {
		t.Errorf("Expected token_type=Bearer, got %s", res.TokenType)
	}
}

func TestTokenCodeReuseRejected(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	verifier, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state123", challenge)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	code := loginAndGetCode(t, sessID, email, "password123")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)

	// First exchange succeeds
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(form.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	testRouter.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("First token exchange failed: %d", w1.Code)
	}

	// Replay must be rejected
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	testRouter.ServeHTTP(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for code replay, got %d", w2.Code)
	}
}

func TestTokenWrongParametersRejected(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	verifier, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state123", challenge)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	code := loginAndGetCode(t, sessID, email, "password123")

	cases := []struct {
		name string
		vals url.Values
	}{
		{
			name: "wrong client_id",
			vals: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"app_wrongclient123"},
				"code":          {code},
				"redirect_uri":  {redirectURI},
				"code_verifier": {verifier},
			},
		},
		{
			name: "wrong redirect_uri",
			vals: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {clientID},
				"code":          {code},
				"redirect_uri":  {"https://wrong.example.com/cb"},
				"code_verifier": {verifier},
			},
		},
		{
			name: "wrong code_verifier",
			vals: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {clientID},
				"code":          {code},
				"redirect_uri":  {redirectURI},
				"code_verifier": {"wrong_code_verifier_12345678901234567890"},
			},
		},
	}

	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(c.vals.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		testRouter.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("[%s] Expected 400, got %d: %s", c.name, w.Code, w.Body.String())
		}
	}
}

func TestTokenClientCredentialsFlow(t *testing.T) {
	setupTest(t)
	clientID, clientSecret := createTestApp(t, "https://example.com/cb")

	// Valid client_credentials grant
	ccForm := url.Values{}
	ccForm.Set("grant_type", "client_credentials")
	ccForm.Set("client_id", clientID)
	ccForm.Set("client_secret", clientSecret)
	ccForm.Set("audience", "https://api.example.com")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(ccForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Client credentials grant failed: %d, %s", w.Code, w.Body.String())
	}

	var res models.TokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res.AccessToken == "" {
		t.Errorf("Missing access_token in client_credentials response")
	}

	// Invalid client secret rejected
	badForm := url.Values{}
	badForm.Set("grant_type", "client_credentials")
	badForm.Set("client_id", clientID)
	badForm.Set("client_secret", "wrong_secret")

	reqBad := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(badForm.Encode()))
	reqBad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wBad := httptest.NewRecorder()
	testRouter.ServeHTTP(wBad, reqBad)

	if wBad.Code != http.StatusUnauthorized && wBad.Code != http.StatusBadRequest {
		t.Errorf("Expected 401 or 400 for bad client_secret, got %d", wBad.Code)
	}
}

func TestTokenRefreshTokenGrantAndRotation(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	verifier, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state123", challenge)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	code := loginAndGetCode(t, sessID, email, "password123")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	var tokRes models.TokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &tokRes)
	oldRefresh := *tokRes.RefreshToken

	// Use refresh token flow via /api/v1/auth/refresh
	refBody := fmt.Sprintf(`{"refresh_token":%q}`, oldRefresh)
	reqRef := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(refBody))
	reqRef.Header.Set("Content-Type", "application/json")
	wRef := httptest.NewRecorder()
	testRouter.ServeHTTP(wRef, reqRef)

	if wRef.Code != http.StatusOK {
		t.Fatalf("Refresh token flow failed: %d, %s", wRef.Code, wRef.Body.String())
	}

	var rotatedRes models.TokenResponse
	_ = json.Unmarshal(wRef.Body.Bytes(), &rotatedRes)
	if rotatedRes.AccessToken == "" {
		t.Errorf("Missing access_token in refreshed response")
	}
	if rotatedRes.RefreshToken == nil || *rotatedRes.RefreshToken == "" {
		t.Errorf("Missing rotated refresh_token")
	}
	if *rotatedRes.RefreshToken == oldRefresh {
		t.Errorf("Refresh token was not rotated")
	}

	// Reusing old refresh token must be rejected
	reqOld := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(refBody))
	reqOld.Header.Set("Content-Type", "application/json")
	wOld := httptest.NewRecorder()
	testRouter.ServeHTTP(wOld, reqOld)

	if wOld.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 on reused refresh token, got %d", wOld.Code)
	}
}

func TestTokenUnsupportedGrantType(t *testing.T) {
	setupTest(t)
	form := url.Values{}
	form.Set("grant_type", "password")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for unsupported grant type, got %d", w.Code)
	}
}
