package handlers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/google/uuid"

	"identity-service/internal/models"
)

func extractResetToken(resetURL string) string {
	u, err := url.Parse(resetURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("token")
}

func TestForgotPasswordEnumerationSafe(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	// Existing user
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)
	if wSignup.Code != http.StatusOK {
		t.Fatalf("Signup failed: %d", wSignup.Code)
	}

	// Forgot password with existing email
	reqExist := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/forgot-password", strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	reqExist.Header.Set("Content-Type", "application/json")
	wExist := httptest.NewRecorder()
	testRouter.ServeHTTP(wExist, reqExist)

	// Forgot password with non-existing email
	reqUnknown := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/forgot-password", strings.NewReader(`{"email":"nobody@example.com"}`))
	reqUnknown.Header.Set("Content-Type", "application/json")
	wUnknown := httptest.NewRecorder()
	testRouter.ServeHTTP(wUnknown, reqUnknown)

	if wExist.Code != http.StatusOK || wUnknown.Code != http.StatusOK {
		t.Fatalf("Expected 200 for both, got %d and %d", wExist.Code, wUnknown.Code)
	}
	if wExist.Body.String() != wUnknown.Body.String() {
		t.Errorf("Enumeration leak: responses differ between existing and unknown email")
	}
	if strings.Contains(wExist.Body.String(), "token") || strings.Contains(wExist.Body.String(), "pr_") {
		t.Errorf("Reset token leaked in forgot-password response body")
	}
}

func TestForgotPasswordCreatesHashedTokenOnly(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	// Forgot password
	reqFP := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/forgot-password", strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	reqFP.Header.Set("Content-Type", "application/json")
	wFP := httptest.NewRecorder()
	testRouter.ServeHTTP(wFP, reqFP)

	testNotif.mu.Lock()
	rawResetURL := testNotif.lastResetURL
	testNotif.mu.Unlock()
	rawToken := extractResetToken(rawResetURL)
	if rawToken == "" {
		t.Fatalf("Raw reset token not found in sent email URL: %s", rawResetURL)
	}

	// Verify token document in Firestore
	iter := testDB.Collection("password_reset_tokens").Where("app_id", "==", clientID).Documents(context.Background())
	defer iter.Stop()
	doc, err := iter.Next()
	if err != nil {
		t.Fatalf("Password reset token doc not found in DB: %v", err)
	}

	var tok models.PasswordResetToken
	_ = doc.DataTo(&tok)
	if tok.Status != "active" {
		t.Errorf("Expected token status active, got %s", tok.Status)
	}
	if tok.TokenHash == "" {
		t.Errorf("Missing token_hash in DB")
	}
	if tok.TokenHash == rawToken {
		t.Errorf("Raw token stored in plaintext in DB!")
	}
}

func TestResetPasswordCompletesTransactionFlow(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	// Forgot password
	reqFP := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/forgot-password", strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	reqFP.Header.Set("Content-Type", "application/json")
	wFP := httptest.NewRecorder()
	testRouter.ServeHTTP(wFP, reqFP)

	testNotif.mu.Lock()
	rawToken := extractResetToken(testNotif.lastResetURL)
	testNotif.mu.Unlock()

	// Reset password on session
	resetBody := fmt.Sprintf(`{"reset_token":%q,"new_password":"newpassword456"}`, rawToken)
	reqReset := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/reset-password", strings.NewReader(resetBody))
	reqReset.Header.Set("Content-Type", "application/json")
	wReset := httptest.NewRecorder()
	testRouter.ServeHTTP(wReset, reqReset)

	if wReset.Code != http.StatusOK {
		t.Fatalf("Reset password failed: %d, %s", wReset.Code, wReset.Body.String())
	}

	// Login with new password succeeds
	code := loginAndGetCode(t, sessID, email, "newpassword456")
	if code == "" {
		t.Errorf("Expected authorization code after login with new password")
	}

	// Old password no longer works
	sess2 := authorizeAndGetSession(t, clientID, redirectURI, "state2", challenge)
	oldLoginBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqOld := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sess2+"/login", strings.NewReader(oldLoginBody))
	reqOld.Header.Set("Content-Type", "application/json")
	wOld := httptest.NewRecorder()
	testRouter.ServeHTTP(wOld, reqOld)

	if wOld.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 with old password, got %d", wOld.Code)
	}
}

func TestResetPasswordStandalone(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	reqFP := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/forgot-password", strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	reqFP.Header.Set("Content-Type", "application/json")
	wFP := httptest.NewRecorder()
	testRouter.ServeHTTP(wFP, reqFP)

	testNotif.mu.Lock()
	rawToken := extractResetToken(testNotif.lastResetURL)
	testNotif.mu.Unlock()

	// Standalone reset via /api/v1/auth/password/reset
	standaloneBody := fmt.Sprintf(`{"reset_token":%q,"new_password":"standalonepass123"}`, rawToken)
	reqStandalone := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset", strings.NewReader(standaloneBody))
	reqStandalone.Header.Set("Content-Type", "application/json")
	wStandalone := httptest.NewRecorder()
	testRouter.ServeHTTP(wStandalone, reqStandalone)

	if wStandalone.Code != http.StatusOK {
		t.Fatalf("Standalone reset failed: %d, %s", wStandalone.Code, wStandalone.Body.String())
	}

	// Login directly via /api/v1/auth/login
	loginBody := fmt.Sprintf(`{"email":%q,"password":"standalonepass123"}`, email)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.Header.Set("X-Application-Id", clientID)
	wLogin := httptest.NewRecorder()
	testRouter.ServeHTTP(wLogin, reqLogin)

	if wLogin.Code != http.StatusOK {
		t.Fatalf("Direct login with reset password failed: %d, %s", wLogin.Code, wLogin.Body.String())
	}
}

func TestResetPasswordInvalidToken(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	resetBody := `{"reset_token":"pr_bogus_token_123456","new_password":"newpassword456"}`
	reqReset := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/reset-password", strings.NewReader(resetBody))
	reqReset.Header.Set("Content-Type", "application/json")
	wReset := httptest.NewRecorder()
	testRouter.ServeHTTP(wReset, reqReset)

	if wReset.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for bogus reset token, got %d", wReset.Code)
	}
}

func TestResetPasswordExpiredToken(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	reqFP := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/forgot-password", strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	reqFP.Header.Set("Content-Type", "application/json")
	wFP := httptest.NewRecorder()
	testRouter.ServeHTTP(wFP, reqFP)

	testNotif.mu.Lock()
	rawToken := extractResetToken(testNotif.lastResetURL)
	testNotif.mu.Unlock()

	// Update token to expired in DB
	iter := testDB.Collection("password_reset_tokens").Where("app_id", "==", clientID).Documents(context.Background())
	doc, _ := iter.Next()
	iter.Stop()
	pastTime := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	_, _ = doc.Ref.Update(context.Background(), []firestore.Update{{Path: "expires_at", Value: pastTime}})

	resetBody := fmt.Sprintf(`{"reset_token":%q,"new_password":"newpassword456"}`, rawToken)
	reqReset := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/reset-password", strings.NewReader(resetBody))
	reqReset.Header.Set("Content-Type", "application/json")
	wReset := httptest.NewRecorder()
	testRouter.ServeHTTP(wReset, reqReset)

	if wReset.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for expired reset token, got %d", wReset.Code)
	}
}

func TestResetPasswordWrongApplicationToken(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientA, _ := createTestApp(t, redirectURI)
	clientB, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	// Mint token on app B
	sessB := authorizeAndGetSession(t, clientB, redirectURI, "state", challenge)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientB)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	reqFP := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessB+"/forgot-password", strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	reqFP.Header.Set("Content-Type", "application/json")
	wFP := httptest.NewRecorder()
	testRouter.ServeHTTP(wFP, reqFP)

	testNotif.mu.Lock()
	rawTokenB := extractResetToken(testNotif.lastResetURL)
	testNotif.mu.Unlock()

	// Try using token B on session A
	sessA := authorizeAndGetSession(t, clientA, redirectURI, "state", challenge)
	resetBody := fmt.Sprintf(`{"reset_token":%q,"new_password":"newpassword456"}`, rawTokenB)
	reqReset := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessA+"/reset-password", strings.NewReader(resetBody))
	reqReset.Header.Set("Content-Type", "application/json")
	wReset := httptest.NewRecorder()
	testRouter.ServeHTTP(wReset, reqReset)

	if wReset.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 when using token minted for other app, got %d", wReset.Code)
	}
}

func TestResetPasswordReusedTokenRejected(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	reqFP := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/forgot-password", strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	reqFP.Header.Set("Content-Type", "application/json")
	wFP := httptest.NewRecorder()
	testRouter.ServeHTTP(wFP, reqFP)

	testNotif.mu.Lock()
	rawToken := extractResetToken(testNotif.lastResetURL)
	testNotif.mu.Unlock()

	// First reset succeeds
	resetBody := fmt.Sprintf(`{"reset_token":%q,"new_password":"newpassword456"}`, rawToken)
	reqReset1 := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/reset-password", strings.NewReader(resetBody))
	reqReset1.Header.Set("Content-Type", "application/json")
	wReset1 := httptest.NewRecorder()
	testRouter.ServeHTTP(wReset1, reqReset1)

	if wReset1.Code != http.StatusOK {
		t.Fatalf("First reset failed: %d", wReset1.Code)
	}

	// Reusing token must be rejected
	sess2 := authorizeAndGetSession(t, clientID, redirectURI, "state2", challenge)
	reqReset2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sess2+"/reset-password", strings.NewReader(resetBody))
	reqReset2.Header.Set("Content-Type", "application/json")
	wReset2 := httptest.NewRecorder()
	testRouter.ServeHTTP(wReset2, reqReset2)

	if wReset2.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for reused reset token, got %d", wReset2.Code)
	}
}

func TestResetPasswordRevokesRefreshTokens(t *testing.T) {
	setupTest(t)
	redirectURI := "https://example.com/oauth/callback"
	clientID, _ := createTestApp(t, redirectURI)
	_, challenge := pkcePair()

	sessID := authorizeAndGetSession(t, clientID, redirectURI, "state", challenge)

	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(signupBody))
	reqSignup.Header.Set("Content-Type", "application/json")
	reqSignup.Header.Set("X-Application-Id", clientID)
	wSignup := httptest.NewRecorder()
	testRouter.ServeHTTP(wSignup, reqSignup)

	// Login directly to get refresh token
	loginBody := fmt.Sprintf(`{"email":%q,"password":"password123"}`, email)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	reqLogin.Header.Set("X-Application-Id", clientID)
	wLogin := httptest.NewRecorder()
	testRouter.ServeHTTP(wLogin, reqLogin)

	var tokRes models.TokenResponse
	_ = json.Unmarshal(wLogin.Body.Bytes(), &tokRes)
	if tokRes.RefreshToken == nil {
		t.Fatalf("No refresh token returned on login")
	}
	oldRefresh := *tokRes.RefreshToken

	// Forgot password & reset
	reqFP := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/forgot-password", strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	reqFP.Header.Set("Content-Type", "application/json")
	wFP := httptest.NewRecorder()
	testRouter.ServeHTTP(wFP, reqFP)

	testNotif.mu.Lock()
	rawToken := extractResetToken(testNotif.lastResetURL)
	testNotif.mu.Unlock()

	resetBody := fmt.Sprintf(`{"reset_token":%q,"new_password":"newpassword456"}`, rawToken)
	reqReset := httptest.NewRequest(http.MethodPost, "/api/v1/auth-sessions/"+sessID+"/reset-password", strings.NewReader(resetBody))
	reqReset.Header.Set("Content-Type", "application/json")
	wReset := httptest.NewRecorder()
	testRouter.ServeHTTP(wReset, reqReset)
	if wReset.Code != http.StatusOK {
		t.Fatalf("Reset password failed: %d", wReset.Code)
	}

	// Old refresh token must now be invalid
	refreshBody := fmt.Sprintf(`{"refresh_token":%q}`, oldRefresh)
	reqRef := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(refreshBody))
	reqRef.Header.Set("Content-Type", "application/json")
	wRef := httptest.NewRecorder()
	testRouter.ServeHTTP(wRef, reqRef)

	if wRef.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 using revoked refresh token after password reset, got %d", wRef.Code)
	}
}
