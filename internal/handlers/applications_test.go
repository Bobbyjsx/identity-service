package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestApplicationCreationUnauthorized(t *testing.T) {
	setupTest(t)

	body := []byte(`{"name":"Test App"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/applications", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", "wrong_token")

	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestApplicationCreationAuthorized(t *testing.T) {
	setupTest(t)

	body := []byte(`{"name":"Authorized Test App"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/applications", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", cfg.AdminSecret)

	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if res["client_id"] == nil || res["client_secret"] == nil {
		t.Fatalf("Expected client_id and client_secret in response: %v", res)
	}
}

func TestApplicationConfigDefaults(t *testing.T) {
	setupTest(t)
	clientID, _ := createTestApp(t, "https://example.com/callback")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications/"+clientID+"/configuration", nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var conf map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &conf); err != nil {
		t.Fatalf("Failed to decode json: %v", err)
	}

	if conf["allow_signup"] != true {
		t.Errorf("Expected allow_signup=true, got %v", conf["allow_signup"])
	}
	if conf["allow_password_login"] != true {
		t.Errorf("Expected allow_password_login=true, got %v", conf["allow_password_login"])
	}
	if conf["require_email_verification"] != false {
		t.Errorf("Expected require_email_verification=false, got %v", conf["require_email_verification"])
	}
	if _, ok := conf["client_secret"]; ok {
		t.Errorf("client_secret must not leak in public configuration")
	}
	if _, ok := conf["redirect_uris"]; ok {
		t.Errorf("redirect_uris must not leak in public configuration")
	}
}

func TestApplicationConfigPersisted(t *testing.T) {
	setupTest(t)
	clientID, _ := createTestAppWithConfig(t, map[string]interface{}{
		"name": "Persisted App",
		"branding": map[string]interface{}{
			"logo_url":        "https://cdn.example.com/logo.png",
			"primary_color":   "#112233",
			"secondary_color": "#445566",
		},
		"authentication": map[string]interface{}{
			"allow_signup":                false,
			"allow_password_login":        true,
			"require_email_verification":  true,
		},
		"oauth": map[string]interface{}{
			"redirect_uris":  []string{"https://example.com/cb", "http://localhost:3000/callback"},
			"allowed_scopes": []string{"openid", "email"},
			"allowed_grants": []string{"authorization_code"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications/"+clientID+"/configuration", nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var conf map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &conf)

	if conf["logo_url"] != "https://cdn.example.com/logo.png" {
		t.Errorf("Expected logo_url persisted, got %v", conf["logo_url"])
	}
	if conf["primary_color"] != "#112233" {
		t.Errorf("Expected primary_color persisted, got %v", conf["primary_color"])
	}
	if conf["allow_signup"] != false {
		t.Errorf("Expected allow_signup=false, got %v", conf["allow_signup"])
	}
	if conf["require_email_verification"] != true {
		t.Errorf("Expected require_email_verification=true, got %v", conf["require_email_verification"])
	}
}

func TestApplicationConfigValidationRejectsDangerousValues(t *testing.T) {
	setupTest(t)
	clientID, _ := createTestApp(t, "https://example.com/callback")

	cases := []map[string]interface{}{
		{"branding": map[string]interface{}{"logo_url": "javascript:alert(1)"}},
		{"branding": map[string]interface{}{"primary_color": "red"}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"https://evil.example.com/*"}}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"javascript:alert(1)"}}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"data:text/html,<script>"}}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"file:///etc/passwd"}}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"https://example.com/cb#fragment"}}},
		{"oauth": map[string]interface{}{"redirect_uris": []string{"http://notlocalhost.example.com/cb"}}},
		{"oauth": map[string]interface{}{"allowed_scopes": []string{"admin:everything"}}},
		{"oauth": map[string]interface{}{"allowed_scopes": []string{"offline_access"}}},
		{"oauth": map[string]interface{}{"allowed_grants": []string{"password"}}},
		{"name": "<script>alert(1)</script>"},
		{"description": "ok <img src=x onerror=alert(1)>"},
	}

	for _, c := range cases {
		body, _ := json.Marshal(c)
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/applications/"+clientID+"/configuration", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", cfg.AdminSecret)
		w := httptest.NewRecorder()
		testRouter.ServeHTTP(w, req)

		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("Expected 422 for dangerous payload %v, got %d: %s", c, w.Code, w.Body.String())
		}
	}
}

func TestApplicationConfigPartialUpdateMerges(t *testing.T) {
	setupTest(t)
	clientID, _ := createTestApp(t, "https://example.com/callback")

	// 1. Update branding
	patch1 := []byte(`{"branding":{"primary_color":"#aabbcc"}}`)
	req1 := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/applications/"+clientID+"/configuration", bytes.NewReader(patch1))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Admin-Token", cfg.AdminSecret)
	w1 := httptest.NewRecorder()
	testRouter.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("Patch 1 failed: %d, %s", w1.Code, w1.Body.String())
	}

	// 2. Update authentication
	patch2 := []byte(`{"authentication":{"allow_signup":false}}`)
	req2 := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/applications/"+clientID+"/configuration", bytes.NewReader(patch2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Admin-Token", cfg.AdminSecret)
	w2 := httptest.NewRecorder()
	testRouter.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("Patch 2 failed: %d, %s", w2.Code, w2.Body.String())
	}

	// Check merged result
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/applications/"+clientID+"/configuration", nil)
	wGet := httptest.NewRecorder()
	testRouter.ServeHTTP(wGet, reqGet)

	var conf map[string]interface{}
	_ = json.Unmarshal(wGet.Body.Bytes(), &conf)
	if conf["primary_color"] != "#aabbcc" {
		t.Errorf("Expected primary_color=#aabbcc to survive merge, got %v", conf["primary_color"])
	}
	if conf["allow_signup"] != false {
		t.Errorf("Expected allow_signup=false, got %v", conf["allow_signup"])
	}
}

func TestPublicConfigurationUnknownClient(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications/app_nonexistent/configuration", nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for unknown client, got %d", w.Code)
	}
}

func TestApplicationThemeConfiguration(t *testing.T) {
	setupTest(t)
	clientID, _ := createTestAppWithConfig(t, map[string]interface{}{
		"name": "Theme App",
		"branding": map[string]interface{}{
			"themes": []string{"light"},
		},
		"oauth": map[string]interface{}{
			"redirect_uris": []string{"https://example.com/callback"},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications/"+clientID+"/configuration", nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Failed to get config: %d", w.Code)
	}

	var conf map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &conf)
	themes, _ := conf["themes"].([]interface{})
	if len(themes) != 1 || themes[0] != "light" {
		t.Errorf("Expected themes=[light], got %v", conf["themes"])
	}

	// Reject invalid theme
	badTheme := []byte(`{"branding":{"themes":["neon"]}}`)
	reqBad := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/applications/"+clientID+"/configuration", bytes.NewReader(badTheme))
	reqBad.Header.Set("Content-Type", "application/json")
	reqBad.Header.Set("X-Admin-Token", cfg.AdminSecret)
	wBad := httptest.NewRecorder()
	testRouter.ServeHTTP(wBad, reqBad)
	if wBad.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected 422 for invalid theme, got %d", wBad.Code)
	}
}
