package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/stretchr/testify/require"

	"identity-service/internal/config"
	"identity-service/internal/core"
	"identity-service/internal/database"
	"identity-service/internal/handlers"
	"identity-service/internal/services"
)

const (
	RedirectURI = "https://app.example.com/callback"
)

var ClientCredentialsOAuth = map[string]interface{}{
	"allowed_grants": []string{"authorization_code", "client_credentials"},
}

type MockNotificationService struct {
	mu           sync.Mutex
	LastResetURL string
	LastOTP      string
	SentOTPs     []string
}

func (m *MockNotificationService) SendPasswordResetEmail(ctx context.Context, to, resetURL, appName, appID string, firstName *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LastResetURL = resetURL
	return nil
}

func (m *MockNotificationService) SendWelcomeEmail(ctx context.Context, to, appName, appID string, firstName *string) error {
	return nil
}

func (m *MockNotificationService) SendVerificationEmail(ctx context.Context, to, otp, appName, appID string, firstName *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LastOTP = otp
	m.SentOTPs = append(m.SentOTPs, otp)
	return nil
}

type TestHarness struct {
	Client        *TestClient
	DB            *firestore.Client
	Config        *config.Config
	Notifications *MockNotificationService
	Server        *handlers.Server
	KeyManager    *services.KeyManager
	OAuthService  *services.OAuthService
	AuthService   *services.AuthService
	AppService    *services.ApplicationService
}

type TestClient struct {
	handler http.Handler
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (r *Response) JSON(dest interface{}) error {
	return json.Unmarshal(r.Body, dest)
}

func (r *Response) JSONMap() map[string]interface{} {
	var m map[string]interface{}
	_ = json.Unmarshal(r.Body, &m)
	return m
}

func (r *Response) Text() string {
	return string(r.Body)
}

func (r *Response) Location() string {
	return r.Header.Get("Location")
}

func (c *TestClient) Do(req *http.Request) *Response {
	w := httptest.NewRecorder()
	c.handler.ServeHTTP(w, req)
	return &Response{
		StatusCode: w.Code,
		Header:     w.Header(),
		Body:       w.Body.Bytes(),
	}
}

func (c *TestClient) Get(path string, query url.Values, headers map[string]string) *Response {
	reqURL := path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.Do(req)
}

func (c *TestClient) Post(path string, body interface{}, headers map[string]string) *Response {
	var bodyReader io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			bodyReader = strings.NewReader(b)
		case []byte:
			bodyReader = bytes.NewReader(b)
		default:
			data, _ := json.Marshal(body)
			bodyReader = bytes.NewReader(data)
		}
	}
	req := httptest.NewRequest(http.MethodPost, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.Do(req)
}

func (c *TestClient) PostForm(path string, form url.Values, headers map[string]string) *Response {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.Do(req)
}

func (c *TestClient) Patch(path string, body interface{}, headers map[string]string) *Response {
	var bodyReader io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			bodyReader = strings.NewReader(b)
		case []byte:
			bodyReader = bytes.NewReader(b)
		default:
			data, _ := json.Marshal(body)
			bodyReader = bytes.NewReader(data)
		}
	}
	req := httptest.NewRequest(http.MethodPatch, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.Do(req)
}

func (c *TestClient) Delete(path string, headers map[string]string) *Response {
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.Do(req)
}

func setup(t *testing.T) *TestHarness {
	os.Setenv("ENVIRONMENT", "testing")
	os.Setenv("IDENTITY_ENVIRONMENT", "testing")
	os.Setenv("TURNSTILE_ENABLED", "false")
	os.Setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:8080")
	os.Setenv("GOOGLE_CLOUD_PROJECT", "test-project")

	cfg := config.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbClient, err := database.NewFirestoreClient(ctx, cfg)
	require.NoError(t, err, "Failed to connect to Firestore emulator")

	km := services.NewKeyManager(cfg)
	err = km.Initialize(ctx, dbClient)
	require.NoError(t, err, "Failed to initialize KeyManager")

	notif := &MockNotificationService{}
	appSvc := services.NewApplicationService(dbClient)
	authSvc := services.NewAuthService(cfg, dbClient, appSvc, km)
	oauthSvc := services.NewOAuthService(cfg, dbClient, appSvc, authSvc, km, notif)
	rbacSvc := services.NewRBACService(dbClient)

	server := handlers.NewServer(cfg, appSvc, authSvc, oauthSvc, rbacSvc, km)
	client := &TestClient{handler: server.Routes()}

	return &TestHarness{
		Client:        client,
		DB:            dbClient,
		Config:        cfg,
		Notifications: notif,
		Server:        server,
		KeyManager:    km,
		OAuthService:  oauthSvc,
		AuthService:   authSvc,
		AppService:    appSvc,
	}
}

func pkcePair() (string, string) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge
}

func pkcePairCustom(verifier string) (string, string) {
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge
}

func createApplication(t *testing.T, h *TestHarness, name string, configMap map[string]interface{}, clientType string) map[string]interface{} {
	appName := name
	if appName == "" {
		appName = fmt.Sprintf("Test App %s", uuid.New().String()[:8])
	}
	body := map[string]interface{}{
		"name": appName,
	}
	if clientType != "" {
		body["client_type"] = clientType
	}
	if configMap != nil {
		for k, v := range configMap {
			body[k] = v
		}
	}

	resp := h.Client.Post("/api/v1/admin/applications", body, map[string]string{
		"X-Admin-Token": h.Config.AdminSecret,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "createApplication failed: %s", resp.Text())

	var data map[string]interface{}
	_ = resp.JSON(&data)
	clientID := data["client_id"].(string)

	detailResp := h.Client.Get(fmt.Sprintf("/api/v1/admin/applications/%s", clientID), nil, map[string]string{
		"X-Admin-Token": h.Config.AdminSecret,
	})
	require.Equal(t, http.StatusOK, detailResp.StatusCode, "get application failed: %s", detailResp.Text())

	var detail map[string]interface{}
	_ = detailResp.JSON(&detail)
	for k, v := range data {
		detail[k] = v
	}
	return detail
}

func authorizeParams(clientID string, overrides map[string]string) url.Values {
	_, challenge := pkcePair()
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", RedirectURI)
	v.Set("response_type", "code")
	v.Set("scope", "openid profile email")
	v.Set("state", "abc123")
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")

	for key, val := range overrides {
		if val == "" {
			v.Del(key)
		} else {
			v.Set(key, val)
		}
	}
	return v
}

func authorizeAndGetTransaction(t *testing.T, h *TestHarness, clientID string, overrides map[string]string) (string, string, *Response) {
	verifier, challenge := pkcePair()
	if overrides != nil && overrides["code_challenge"] != "" {
		challenge = overrides["code_challenge"]
	}
	if overrides != nil && overrides["code_verifier"] != "" {
		verifier = overrides["code_verifier"]
	}

	params := authorizeParams(clientID, overrides)
	params.Set("code_challenge", challenge)

	resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
	require.Equal(t, http.StatusFound, resp.StatusCode, "authorize expected 302: %s", resp.Text())

	loc := resp.Location()
	require.True(t, strings.Contains(loc, "/auth/"), "expected /auth/ in location: %s", loc)

	parts := strings.Split(loc, "/auth/")
	txID := strings.Split(parts[1], "/")[0]
	return txID, verifier, resp
}

func signupUser(t *testing.T, h *TestHarness, clientID string, email string) string {
	if email == "" {
		email = fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	}
	resp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{
		"X-Application-Id": clientID,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "signup failed: %s", resp.Text())
	return email
}

func loginAndGetCode(t *testing.T, h *TestHarness, txID, email, password string) string {
	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]interface{}{
		"email":    email,
		"password": password,
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login failed: %s", resp.Text())

	data := resp.JSONMap()
	redirURL, ok := data["redirect_url"].(string)
	require.True(t, ok && redirURL != "", "redirect_url missing in login response: %v", data)

	parsed, err := url.Parse(redirURL)
	require.NoError(t, err)
	code := parsed.Query().Get("code")
	require.NotEmpty(t, code, "code missing in redirect_url: %s", redirURL)
	return code
}

func extractResetToken(resetURL string) string {
	u, err := url.Parse(resetURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("token")
}

func hashToken(token string) string {
	return core.HashToken(token)
}
