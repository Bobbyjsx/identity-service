package tests

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createApplicationResetToken(t *testing.T, h *TestHarness, appData map[string]interface{}, email string) (string, string) {
	txID, _, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)
	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/forgot-password", txID), map[string]interface{}{
		"email": email,
	}, nil)
	require.Equal(t, 200, resp.StatusCode)

	h.Notifications.mu.Lock()
	resetURL := h.Notifications.LastResetURL
	h.Notifications.mu.Unlock()

	parsed, err := url.Parse(resetURL)
	require.NoError(t, err)
	rawToken := parsed.Query().Get("token")
	require.NotEmpty(t, rawToken)
	return txID, rawToken
}

func tokensFor(ctx context.Context, db *firestore.Client, clientID string) ([]*firestore.DocumentSnapshot, error) {
	return db.Collection("password_reset_tokens").Where("app_id", "==", clientID).Documents(ctx).GetAll()
}

func TestForgotPasswordEnumerationSafe(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	txID, _, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)

	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	respExisting := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/forgot-password", txID), map[string]interface{}{
		"email": email,
	}, nil)

	respUnknown := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/forgot-password", txID), map[string]interface{}{
		"email": "nobody@example.com",
	}, nil)

	assert.Equal(t, 200, respExisting.StatusCode)
	assert.Equal(t, 200, respUnknown.StatusCode)
	assert.Equal(t, respExisting.Text(), respUnknown.Text())
	assert.NotContains(t, respExisting.Text(), "token")
	assert.NotContains(t, respExisting.Text(), "pr_")
}

func TestForgotPasswordCreatesHashedTokenOnly(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	_, rawToken := createApplicationResetToken(t, h, appData, email)

	docs, err := tokensFor(context.Background(), h.DB, appData["client_id"].(string))
	require.NoError(t, err)
	assert.Len(t, docs, 1)

	doc := docs[0].Data()
	assert.Equal(t, appData["client_id"], doc["app_id"])
	assert.Equal(t, "active", doc["status"])
	assert.NotEmpty(t, doc["token_hash"])
	for _, v := range doc {
		assert.NotEqual(t, rawToken, v)
	}
	assert.NotEqual(t, rawToken, doc["token_hash"])
}

func TestResetPasswordCompletesTransactionFlow(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	txID, rawToken := createApplicationResetToken(t, h, appData, email)

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/reset-password", txID), map[string]interface{}{
		"reset_token":  rawToken,
		"new_password": "newpassword456",
	}, nil)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, resp.JSONMap()["detail"].(string), "Password has been reset")

	docs, err := tokensFor(context.Background(), h.DB, appData["client_id"].(string))
	require.NoError(t, err)
	assert.Equal(t, "used", docs[0].Data()["status"])

	loginResp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]interface{}{
		"email":    email,
		"password": "newpassword456",
	}, nil)
	assert.Equal(t, 200, loginResp.StatusCode)
	assert.NotEmpty(t, loginResp.JSONMap()["redirect_url"])

	tx2, _, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)
	loginOldResp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", tx2), map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, nil)
	assert.Equal(t, 401, loginOldResp.StatusCode)
	assert.Equal(t, "invalid_credentials", loginOldResp.JSONMap()["error"])
}

func TestResetPasswordStandalone(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	_, rawToken := createApplicationResetToken(t, h, appData, email)

	resp := h.Client.Post("/api/v1/auth/password/reset", map[string]interface{}{
		"reset_token":  rawToken,
		"new_password": "standalone456",
	}, nil)
	assert.Equal(t, 200, resp.StatusCode)

	loginResp := h.Client.Post("/api/v1/auth/login", map[string]interface{}{
		"email":    email,
		"password": "standalone456",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	assert.Equal(t, 200, loginResp.StatusCode)
}

func TestResetPasswordInvalidToken(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	txID, _, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/reset-password", txID), map[string]interface{}{
		"reset_token":  "pr_bogus_token_123456",
		"new_password": "newpassword456",
	}, nil)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "invalid_reset_token", resp.JSONMap()["error"])
}

func TestResetPasswordExpiredToken(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	txID, rawToken := createApplicationResetToken(t, h, appData, email)

	docs, err := tokensFor(context.Background(), h.DB, appData["client_id"].(string))
	require.NoError(t, err)
	_, err = docs[0].Ref.Update(context.Background(), []firestore.Update{
		{Path: "expires_at", Value: time.Now().Add(-time.Minute).Format(time.RFC3339)},
	})
	require.NoError(t, err)

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/reset-password", txID), map[string]interface{}{
		"reset_token":  rawToken,
		"new_password": "newpassword456",
	}, nil)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "reset_token_expired", resp.JSONMap()["error"])
}

func TestResetPasswordWrongApplicationToken(t *testing.T) {
	h := setup(t)

	appA := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	appB := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")

	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appB["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	_, rawToken := createApplicationResetToken(t, h, appB, email)

	txA, _, _ := authorizeAndGetTransaction(t, h, appA["client_id"].(string), nil)
	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/reset-password", txA), map[string]interface{}{
		"reset_token":  rawToken,
		"new_password": "newpassword456",
	}, nil)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "invalid_reset_token", resp.JSONMap()["error"])
}

func TestResetPasswordReusedTokenRejected(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	txID, rawToken := createApplicationResetToken(t, h, appData, email)

	first := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/reset-password", txID), map[string]interface{}{
		"reset_token":  rawToken,
		"new_password": "newpassword456",
	}, nil)
	assert.Equal(t, 200, first.StatusCode)

	txID2, _, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)
	second := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/reset-password", txID2), map[string]interface{}{
		"reset_token":  rawToken,
		"new_password": "anotherpass789",
	}, nil)
	assert.Equal(t, 400, second.StatusCode)
	assert.Equal(t, "invalid_reset_token", second.JSONMap()["error"])
}

func TestResetPasswordRevokesRefreshTokens(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	loginResp := h.Client.Post("/api/v1/auth/login", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, loginResp.StatusCode)
	oldRefresh := loginResp.JSONMap()["refresh_token"]

	txID, rawToken := createApplicationResetToken(t, h, appData, email)
	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/reset-password", txID), map[string]interface{}{
		"reset_token":  rawToken,
		"new_password": "newpassword456",
	}, nil)
	assert.Equal(t, 200, resp.StatusCode)

	refreshResp := h.Client.Post("/api/v1/auth/refresh", map[string]interface{}{
		"refresh_token": oldRefresh,
	}, nil)
	assert.Equal(t, 401, refreshResp.StatusCode)
}
