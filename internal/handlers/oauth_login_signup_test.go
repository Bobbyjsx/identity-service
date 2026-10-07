package handlers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSessionLoginSuccess(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessionID := authorizeAndGetSession(t, clientID, redirectURI, "abc123state", challenge)

	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	// Sign up user directly
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)
	if wSignup.Code != http.StatusOK {
		t.Fatalf("Signup failed: %d", wSignup.Code)
	}

	// Session login
	code := loginAndGetCode(t, sessionID, email, "password123")
	if !strings.HasPrefix(code, "code_") {
		t.Errorf("Expected code prefix code_, got %s", code)
	}
}

func TestSessionLoginInvalidPassword(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessionID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	// Wrong password
	loginBody := fmt.Sprintf(`{"email":%q,"password":"wrong_password"}`, email)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/login", strings.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	testRouter.ServeHTTP(wLogin, reqLogin)

	if wLogin.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong password, got %d", wLogin.Code)
	}
}

func TestSessionLoginUnknownUser(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessionID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	loginBody := `{"email":"nobody@example.com","password":"password123"}`
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/login", strings.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	testRouter.ServeHTTP(wLogin, reqLogin)

	if wLogin.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unknown user, got %d", wLogin.Code)
	}
}

func TestSessionLoginWrongApplication(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientA, _ := createTestApp(t, redirectURI)
	clientB, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	// Signup user under app B
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientB)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)
	if wSignup.Code != http.StatusOK {
		t.Fatalf("Signup under app B failed: %d", wSignup.Code)
	}

	// Authorize session for app A
	sessA := authorizeAndGetSession(t, clientA, redirectURI, "state", challenge)

	// Attempt login with user from app B
	loginBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessA+"/login", strings.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	testRouter.ServeHTTP(wLogin, reqLogin)

	// App separation: user does not exist in app A
	if wLogin.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 when cross-tenant user tries to log in, got %d", wLogin.Code)
	}
}

func TestSessionSignupDisabledRejected(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestAppWithConfig(t, map[string]interface{}{
		"name": "No Signup App",
		"authentication": map[string]interface{}{
			"allow_signup": false,
		},
		"oauth": map[string]interface{}{
			"redirect_uris":  []string{redirectURI},
			"allowed_scopes": []string{"openid"},
		},
	})
	_, challenge := pkcePair()
	sessionID := authorizeAndGetSessionWithScope(t, clientID, redirectURI, "openid", "state", challenge)

	signupBody := `{"email":"new@example.com","password":"password123"}`
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	if wSignup.Code != http.StatusBadRequest && wSignup.Code != http.StatusForbidden {
		t.Errorf("Expected 400 or 403 when signup is disabled, got %d", wSignup.Code)
	}
}

func TestSessionSignupDuplicateEmail(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()
	sessionID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	email := fmt.Sprintf("dup-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/signup", strings.NewReader(signupBody))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	testRouter.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("First signup failed: %d", w1.Code)
	}

	// Second session signup with same email must fail
	sess2 := authorizeAndGetSession(t, clientID, redirectURI, "state2", challenge)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sess2+"/signup", strings.NewReader(signupBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	testRouter.ServeHTTP(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for duplicate signup, got %d", w2.Code)
	}
}

func TestEmailVerificationOTPLifecycle(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestAppWithConfig(t, map[string]interface{}{
		"name": "Verify App",
		"authentication": map[string]interface{}{
			"allow_signup":               true,
			"require_email_verification": true,
		},
		"oauth": map[string]interface{}{
			"redirect_uris":  []string{redirectURI},
			"allowed_scopes": []string{"openid", "email"},
		},
	})
	_, challenge := pkcePair()
	sessionID := authorizeAndGetSessionWithScope(t, clientID, redirectURI, "openid email", "state", challenge)

	email := fmt.Sprintf("verify-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	if wSignup.Code != http.StatusOK {
		t.Fatalf("Signup failed: %d, %s", wSignup.Code, wSignup.Body.String())
	}

	var signupResp map[string]interface{}
	_ = json.Unmarshal(wSignup.Body.Bytes(), &signupResp)
	if signupResp["email_verification_required"] != true {
		t.Errorf("Expected email_verification_required=true, got %v", signupResp["email_verification_required"])
	}

	// Capture sent OTP from test notification service
	testNotif.mu.Lock()
	otp := testNotif.lastOTP
	testNotif.mu.Unlock()
	if otp == "" {
		t.Fatalf("Expected OTP to be sent via notification service")
	}

	// 1. Invalid OTP
	invReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/verify-email", strings.NewReader(`{"verification_token":"000000"}`))
	invReq.Header.Set("Content-Type", "application/json")
	wInv := httptest.NewRecorder()
	testRouter.ServeHTTP(wInv, invReq)
	if wInv.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid OTP, got %d", wInv.Code)
	}

	// 2. Resend OTP
	resendReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/resend-otp", strings.NewReader(`{}`))
	resendReq.Header.Set("Content-Type", "application/json")
	wResend := httptest.NewRecorder()
	testRouter.ServeHTTP(wResend, resendReq)
	if wResend.Code != http.StatusOK {
		t.Fatalf("Resend OTP failed: %d, %s", wResend.Code, wResend.Body.String())
	}

	testNotif.mu.Lock()
	newOTP := testNotif.lastOTP
	testNotif.mu.Unlock()
	if newOTP == "" {
		t.Fatalf("Expected new OTP after resend")
	}

	// 3. Valid OTP completes the flow
	validReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessionID+"/verify-email", strings.NewReader(fmt.Sprintf(`{"verification_token":%q}`, newOTP)))
	validReq.Header.Set("Content-Type", "application/json")
	wValid := httptest.NewRecorder()
	testRouter.ServeHTTP(wValid, validReq)
	if wValid.Code != http.StatusOK {
		t.Fatalf("Valid OTP failed: %d, %s", wValid.Code, wValid.Body.String())
	}

	var validResp map[string]interface{}
	_ = json.Unmarshal(wValid.Body.Bytes(), &validResp)
	redirURL, _ := validResp["redirect_url"].(string)
	if !strings.Contains(redirURL, "code=") {
		t.Errorf("Expected redirect_url with code after OTP verification, got %s", redirURL)
	}
}
