package handlers_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/google/uuid"

	"identity-service/internal/config"
	"identity-service/internal/database"
	"identity-service/internal/handlers"
	"identity-service/internal/models"
	"identity-service/internal/services"
)

var (
	testServer *handlers.Server
	testRouter http.Handler
	testDB     *firestore.Client
	testNotif  *mockNotificationService
	cfg        *config.Config
)

type mockNotificationService struct {
	mu           sync.Mutex
	lastResetURL string
	lastOTP      string
}

func (m *mockNotificationService) SendPasswordResetEmail(ctx context.Context, to, resetURL, appName, appID string, firstName *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastResetURL = resetURL
	return nil
}

func (m *mockNotificationService) SendWelcomeEmail(ctx context.Context, to, appName, appID string, firstName *string) error {
	return nil
}

func (m *mockNotificationService) SendVerificationEmail(ctx context.Context, to, otp, appName, appID string, firstName *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastOTP = otp
	return nil
}

func setupTest(t *testing.T) {
	os.Setenv("ENVIRONMENT", "testing")
	os.Setenv("IDENTITY_ENVIRONMENT", "testing")
	os.Setenv("TURNSTILE_ENABLED", "false")
	os.Setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:8080")
	os.Setenv("GOOGLE_CLOUD_PROJECT", "test-project")

	cfg = config.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbClient, err := database.NewFirestoreClient(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to initialize Firestore test client: %v", err)
	}
	testDB = dbClient

	km := services.NewKeyManager(cfg)
	if err := km.Initialize(ctx, dbClient); err != nil {
		t.Fatalf("Failed to initialize KeyManager: %v", err)
	}

	testNotif = &mockNotificationService{}
	appSvc := services.NewApplicationService(dbClient)
	authSvc := services.NewAuthService(cfg, dbClient, appSvc, km)
	oauthSvc := services.NewOAuthService(cfg, dbClient, appSvc, authSvc, km, testNotif)
	rbacSvc := services.NewRBACService(dbClient)

	testServer = handlers.NewServer(cfg, appSvc, authSvc, oauthSvc, rbacSvc, km)
	testRouter = testServer.Routes()
}

func pkcePair() (string, string) {
	raw := make([]byte, 32)
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge
}

func createTestApp(t *testing.T, redirectURI string) (string, string) {
	return createTestAppWithConfig(t, map[string]interface{}{
		"name": "Test Application",
		"oauth": map[string]interface{}{
			"redirect_uris":  []string{redirectURI},
			"allowed_scopes": []string{"openid", "profile", "email"},
			"allowed_grants": []string{"authorization_code", "client_credentials"},
		},
	})
}

func createTestAppWithConfig(t *testing.T, appConfig map[string]interface{}) (string, string) {
	bodyBytes, _ := json.Marshal(appConfig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/applications", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", cfg.AdminSecret)

	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to create test app: %d, %s", w.Code, w.Body.String())
	}

	var creds models.ApplicationCredentials
	if err := json.Unmarshal(w.Body.Bytes(), &creds); err != nil {
		t.Fatalf("Failed to parse app creds: %v", err)
	}
	return creds.ClientID, creds.ClientSecret
}

func authorizeAndGetSession(t *testing.T, clientID, redirectURI, state, challenge string) string {
	return authorizeAndGetSessionWithScope(t, clientID, redirectURI, "openid profile email", state, challenge)
}

func authorizeAndGetSessionWithScope(t *testing.T, clientID, redirectURI, scope, state, challenge string) string {
	authURL := fmt.Sprintf("/api/v1/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&code_challenge=%s&code_challenge_method=S256&state=%s",
		clientID, url.QueryEscape(redirectURI), url.QueryEscape(scope), challenge, state)
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("Authorize expected 302, got %d: %s", w.Code, w.Body.String())
	}

	loc := w.Header().Get("Location")
	parts := strings.Split(loc, "/auth/")
	if len(parts) < 2 {
		t.Fatalf("Invalid location redirect: %s", loc)
	}
	return strings.Split(parts[1], "/")[0]
}

func loginAndGetCode(t *testing.T, sessionID, email, password string) string {
	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/login", strings.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Session login failed: %d, %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	redirURL, ok := resp["redirect_url"].(string)
	if !ok || redirURL == "" {
		t.Fatalf("No redirect_url in login response: %v", resp)
	}

	parsed, err := url.Parse(redirURL)
	if err != nil {
		t.Fatalf("Failed to parse redirect_url: %v", err)
	}
	return parsed.Query().Get("code")
}

func TestHealth(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var res map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res["status"] != "ok" {
		t.Errorf("Expected status ok, got %s", res["status"])
	}
}

func TestDiscovery(t *testing.T) {
	setupTest(t)

	// JWKS
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("JWKS expected 200, got %d", w.Code)
	}
	var jwks map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &jwks)
	keys, ok := jwks["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Errorf("Expected at least 1 key in JWKS")
	}

	// OpenID Configuration
	reqOidc := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	wOidc := httptest.NewRecorder()
	testRouter.ServeHTTP(wOidc, reqOidc)
	if wOidc.Code != http.StatusOK {
		t.Errorf("OpenID config expected 200, got %d", wOidc.Code)
	}
}

func TestApplicationLifecycleAndValidation(t *testing.T) {
	setupTest(t)

	// Unauthorized
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/applications", bytes.NewReader([]byte(`{"name":"App"}`)))
	req.Header.Set("X-Admin-Token", "wrong")
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}

	// Authorized creation
	clientID, _ := createTestApp(t, "https://example.com/callback")

	// Get Application
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/admin/applications/"+clientID, nil)
	reqGet.Header.Set("X-Admin-Token", cfg.AdminSecret)
	wGet := httptest.NewRecorder()
	testRouter.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", wGet.Code)
	}

	// Public Config
	reqPub := httptest.NewRequest(http.MethodGet, "/api/v1/applications/"+clientID+"/configuration", nil)
	wPub := httptest.NewRecorder()
	testRouter.ServeHTTP(wPub, reqPub)
	if wPub.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", wPub.Code)
	}

	// Update Config
	patchBody := []byte(`{"branding":{"primary_color":"#123456"}}`)
	reqPatch := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/applications/"+clientID+"/configuration", bytes.NewReader(patchBody))
	reqPatch.Header.Set("X-Admin-Token", cfg.AdminSecret)
	wPatch := httptest.NewRecorder()
	testRouter.ServeHTTP(wPatch, reqPatch)
	if wPatch.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d: %s", wPatch.Code, wPatch.Body.String())
	}

	// Reject dangerous value
	badPatch := []byte(`{"branding":{"primary_color":"invalid_color"}}`)
	reqBad := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/applications/"+clientID+"/configuration", bytes.NewReader(badPatch))
	reqBad.Header.Set("X-Admin-Token", cfg.AdminSecret)
	wBad := httptest.NewRecorder()
	testRouter.ServeHTTP(wBad, reqBad)
	if wBad.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected 422 for invalid color, got %d", wBad.Code)
	}
}

func TestAuthFlow(t *testing.T) {
	setupTest(t)
	clientID, _ := createTestApp(t, "https://example.com/callback")

	email := fmt.Sprintf("user_%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123","first_name":"Jane","last_name":"Doe"}`, email)

	// Signup
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)
	if wSignup.Code != http.StatusOK {
		t.Fatalf("Signup failed: %d, %s", wSignup.Code, wSignup.Body.String())
	}

	// Duplicate Signup fails
	reqDup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqDup.Header.Set("Content-Type", "application/json")
	reqDup.Header.Set("X-Application-Id", clientID)
	wDup := httptest.NewRecorder()
	testRouter.ServeHTTP(wDup, reqDup)
	if wDup.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 on duplicate signup, got %d", wDup.Code)
	}

	// Login
	loginBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.Header.Set("X-Application-Id", clientID)
	wLogin := httptest.NewRecorder()
	testRouter.ServeHTTP(wLogin, reqLogin)
	if wLogin.Code != http.StatusOK {
		t.Fatalf("Login failed: %d, %s", wLogin.Code, wLogin.Body.String())
	}

	var tokens models.TokenResponse
	_ = json.Unmarshal(wLogin.Body.Bytes(), &tokens)
	if tokens.AccessToken == "" || tokens.RefreshToken == nil {
		t.Fatalf("Tokens not received")
	}

	// Get Me
	reqMe := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqMe.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	wMe := httptest.NewRecorder()
	testRouter.ServeHTTP(wMe, reqMe)
	if wMe.Code != http.StatusOK {
		t.Errorf("Get Me failed: %d, %s", wMe.Code, wMe.Body.String())
	}

	// Refresh token
	refreshBody := fmt.Sprintf(`{"refresh_token":%q}`, *tokens.RefreshToken)
	reqRef := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(refreshBody))
	reqRef.Header.Set("Content-Type", "application/json")
	wRef := httptest.NewRecorder()
	testRouter.ServeHTTP(wRef, reqRef)
	if wRef.Code != http.StatusOK {
		t.Fatalf("Refresh token failed: %d, %s", wRef.Code, wRef.Body.String())
	}
}

func TestOAuthAuthorizationCodeAndTokenExchange(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, clientSecret := createTestApp(t, redirectURI)

	verifier, challenge := pkcePair()

	// 1. Authorize Request
	authURL := fmt.Sprintf("/api/v1/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+profile+email&code_challenge=%s&code_challenge_method=S256&state=xyz123",
		clientID, url.QueryEscape(redirectURI), challenge)
	reqAuth := httptest.NewRequest(http.MethodGet, authURL, nil)
	wAuth := httptest.NewRecorder()
	testRouter.ServeHTTP(wAuth, reqAuth)

	if wAuth.Code != http.StatusFound {
		t.Fatalf("Authorize expected 302, got %d: %s", wAuth.Code, wAuth.Body.String())
	}

	loc := wAuth.Header().Get("Location")
	if !strings.Contains(loc, "/auth/") {
		t.Fatalf("Unexpected Location header: %s", loc)
	}

	// Extract session ID
	parts := strings.Split(loc, "/auth/")
	sessionID := strings.Split(parts[1], "/")[0]

	// 2. Load Session
	reqSession := httptest.NewRequest(http.MethodGet, "/api/v1/auth-sessions/"+sessionID, nil)
	wSession := httptest.NewRecorder()
	testRouter.ServeHTTP(wSession, reqSession)
	if wSession.Code != http.StatusOK {
		t.Fatalf("Load session failed: %d", wSession.Code)
	}

	// 3. Signup / Login within Session
	email := fmt.Sprintf("oauth_user_%s@example.com", uuid.New().String()[:8])
	sessionSignupBody := fmt.Sprintf(`{"email":%q,"password":"password123","first_name":"Alice","last_name":"Smith"}`, email)
	reqSessSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/signup", strings.NewReader(sessionSignupBody))
	reqSessSignup.Header.Set("Content-Type", "application/json")
	wSessSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSessSignup, reqSessSignup)

	if wSessSignup.Code != http.StatusOK {
		t.Fatalf("Session signup failed: %d, %s", wSessSignup.Code, wSessSignup.Body.String())
	}

	var sessResp map[string]interface{}
	_ = json.Unmarshal(wSessSignup.Body.Bytes(), &sessResp)
	redirURL, ok := sessResp["redirect_url"].(string)
	if !ok || redirURL == "" {
		t.Fatalf("Missing redirect_url in session signup response: %v", sessResp)
	}

	// Parse code from redirect_url
	parsedRedir, err := url.Parse(redirURL)
	if err != nil {
		t.Fatalf("Failed to parse callback url: %v", err)
	}
	code := parsedRedir.Query().Get("code")
	if code == "" {
		t.Fatalf("No code in callback url: %s", redirURL)
	}

	// 4. Exchange code for tokens at /api/v1/oauth/token
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)

	reqToken := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(form.Encode()))
	reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wToken := httptest.NewRecorder()
	testRouter.ServeHTTP(wToken, reqToken)

	if wToken.Code != http.StatusOK {
		t.Fatalf("Token exchange failed: %d, %s", wToken.Code, wToken.Body.String())
	}

	var tokenRes models.TokenResponse
	_ = json.Unmarshal(wToken.Body.Bytes(), &tokenRes)
	if tokenRes.AccessToken == "" {
		t.Errorf("Missing access_token in token exchange")
	}
	if tokenRes.IDToken == nil || *tokenRes.IDToken == "" {
		t.Errorf("Missing id_token in openid token exchange")
	}

	// 5. Code reuse must be rejected (single use guarantee)
	reqReplay := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(form.Encode()))
	reqReplay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wReplay := httptest.NewRecorder()
	testRouter.ServeHTTP(wReplay, reqReplay)

	if wReplay.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for code replay, got %d", wReplay.Code)
	}

	// 6. Test Client Credentials grant
	ccForm := url.Values{}
	ccForm.Set("grant_type", "client_credentials")
	ccForm.Set("client_id", clientID)
	ccForm.Set("client_secret", clientSecret)
	ccForm.Set("audience", "https://api.example.com")

	reqCC := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader(ccForm.Encode()))
	reqCC.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wCC := httptest.NewRecorder()
	testRouter.ServeHTTP(wCC, reqCC)

	if wCC.Code != http.StatusOK {
		t.Errorf("Client credentials grant failed: %d, %s", wCC.Code, wCC.Body.String())
	}
}

func TestRBAC(t *testing.T) {
	setupTest(t)
	clientID, _ := createTestApp(t, "https://example.com/callback")

	// Create Permission
	permBody := `{"name":"read:users","description":"Read users"}`
	reqPerm := httptest.NewRequest(http.MethodPost, "/api/v1/rbac/permissions", strings.NewReader(permBody))
	reqPerm.Header.Set("Content-Type", "application/json")
	reqPerm.Header.Set("X-Application-Id", clientID)
	wPerm := httptest.NewRecorder()
	testRouter.ServeHTTP(wPerm, reqPerm)

	if wPerm.Code != http.StatusOK {
		t.Fatalf("Create permission failed: %d, %s", wPerm.Code, wPerm.Body.String())
	}

	// List Permissions
	reqListPerm := httptest.NewRequest(http.MethodGet, "/api/v1/rbac/permissions", nil)
	reqListPerm.Header.Set("X-Application-Id", clientID)
	wListPerm := httptest.NewRecorder()
	testRouter.ServeHTTP(wListPerm, reqListPerm)

	if wListPerm.Code != http.StatusOK {
		t.Fatalf("List permissions failed: %d", wListPerm.Code)
	}

	// Create Role
	roleBody := `{"name":"admin","description":"Administrator","permissions":["read:users"]}`
	reqRole := httptest.NewRequest(http.MethodPost, "/api/v1/rbac/roles", strings.NewReader(roleBody))
	reqRole.Header.Set("Content-Type", "application/json")
	reqRole.Header.Set("X-Application-Id", clientID)
	wRole := httptest.NewRecorder()
	testRouter.ServeHTTP(wRole, reqRole)

	if wRole.Code != http.StatusOK {
		t.Fatalf("Create role failed: %d, %s", wRole.Code, wRole.Body.String())
	}

	// List Roles
	reqListRole := httptest.NewRequest(http.MethodGet, "/api/v1/rbac/roles", nil)
	reqListRole.Header.Set("X-Application-Id", clientID)
	wListRole := httptest.NewRecorder()
	testRouter.ServeHTTP(wListRole, reqListRole)

	if wListRole.Code != http.StatusOK {
		t.Fatalf("List roles failed: %d", wListRole.Code)
	}
}

func TestDocumentationRoutes(t *testing.T) {
	if testRouter == nil {
		setupTest(t)
	}

	// 1. /docs
	reqDocs := httptest.NewRequest(http.MethodGet, "/docs", nil)
	wDocs := httptest.NewRecorder()
	testRouter.ServeHTTP(wDocs, reqDocs)
	if wDocs.Code != http.StatusOK {
		t.Fatalf("/docs returned status %d", wDocs.Code)
	}
	if !strings.Contains(wDocs.Body.String(), "SwaggerUIBundle") {
		t.Fatalf("/docs did not contain SwaggerUIBundle: %s", wDocs.Body.String())
	}

	// 2. /openapi.json
	reqOpenAPI := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	wOpenAPI := httptest.NewRecorder()
	testRouter.ServeHTTP(wOpenAPI, reqOpenAPI)
	if wOpenAPI.Code != http.StatusOK {
		t.Fatalf("/openapi.json returned status %d", wOpenAPI.Code)
	}
	var openAPISpec map[string]interface{}
	if err := json.Unmarshal(wOpenAPI.Body.Bytes(), &openAPISpec); err != nil {
		t.Fatalf("/openapi.json is not valid JSON: %v", err)
	}
	if openAPISpec["openapi"] != "3.0.3" {
		t.Fatalf("/openapi.json has unexpected version: %v", openAPISpec["openapi"])
	}

	// 3. /redoc
	reqRedoc := httptest.NewRequest(http.MethodGet, "/redoc", nil)
	wRedoc := httptest.NewRecorder()
	testRouter.ServeHTTP(wRedoc, reqRedoc)
	if wRedoc.Code != http.StatusOK {
		t.Fatalf("/redoc returned status %d", wRedoc.Code)
	}
	if !strings.Contains(wRedoc.Body.String(), "<redoc") {
		t.Fatalf("/redoc did not contain <redoc tag: %s", wRedoc.Body.String())
	}
}

