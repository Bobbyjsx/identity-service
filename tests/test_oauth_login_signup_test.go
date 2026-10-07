package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/iterator"
)

func TestTransactionLoginSuccess(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]string{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": clientID})
	require.Equal(t, http.StatusOK, signupResp.StatusCode)

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
		"email":    email,
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	data := resp.JSONMap()
	assert.NotEmpty(t, data["redirect_url"])
	assert.Equal(t, false, data["email_verification_required"])

	parsed, err := url.Parse(data["redirect_url"].(string))
	require.NoError(t, err)
	assert.Equal(t, "https", parsed.Scheme)
	assert.Equal(t, "app.example.com", parsed.Host)
	assert.Equal(t, "/callback", parsed.Path)
	query := parsed.Query()
	assert.True(t, strings.HasPrefix(query.Get("code"), "code_"))
	assert.Equal(t, "abc123", query.Get("state"))
	assert.Empty(t, query.Get("access_token"))
	assert.Empty(t, query.Get("refresh_token"))
	assert.Empty(t, query.Get("id_token"))

	snap, err := h.DB.Collection("auth_sessions").Doc(txID).Get(context.Background())
	require.NoError(t, err)
	doc := snap.Data()
	assert.Equal(t, "completed", doc["status"])
	assert.NotEmpty(t, doc["user_id"])
	assert.NotEmpty(t, doc["completed_at"])

	// Raw code is never persisted, only hash
	iter := h.DB.Collection("authorization_codes").Documents(context.Background())
	defer iter.Stop()
	for {
		d, err := iter.Next()
		if err == iterator.Done {
			break
		}
		require.NoError(t, err)
		assert.NotContains(t, fmt.Sprintf("%v", d.Data()), query.Get("code"))
	}
}

func TestTransactionLoginInvalidPassword(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	email := signupUser(t, h, clientID, "")

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
		"email":    email,
		"password": "wrong-password",
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "invalid_credentials", resp.JSONMap()["error"])
}

func TestTransactionLoginUnknownUser(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
		"email":    "nobody@example.com",
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "invalid_credentials", resp.JSONMap()["error"])
}

func TestTransactionLoginUnknownTransaction(t *testing.T) {
	h := setup(t)
	resp := h.Client.Post("/api/v1/auth-sessions/tx_nonexistent/login", map[string]string{
		"email":    "a@example.com",
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "invalid_session", resp.JSONMap()["error"])
}

func TestTransactionLoginWrongApplication(t *testing.T) {
	h := setup(t)
	appA := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	appB := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")

	txA, _, _ := authorizeAndGetTransaction(t, h, appA["client_id"].(string), nil)
	email := signupUser(t, h, appB["client_id"].(string), "")

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txA), map[string]string{
		"email":    email,
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "invalid_credentials", resp.JSONMap()["error"])
}

func TestTransactionLoginDisabledForApplication(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth":          map[string]interface{}{"redirect_uris": []string{RedirectURI}},
		"authentication": map[string]interface{}{"allow_password_login": false},
	}, "")

	txID, _, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)
	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
		"email":    "a@example.com",
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "password_login_disabled", resp.JSONMap()["error"])
}

func TestTransactionSignupSuccess(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	email := fmt.Sprintf("newuser-%s@example.com", uuid.New().String()[:8])

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/signup", txID), map[string]string{
		"email":    email,
		"password": "password123",
		"username": "alice",
	}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	data := resp.JSONMap()
	assert.NotEmpty(t, data["redirect_url"])
	parsed, _ := url.Parse(data["redirect_url"].(string))
	assert.NotEmpty(t, parsed.Query().Get("code"))

	iter := h.DB.Collection("users").Where("app_id", "==", clientID).Documents(context.Background())
	defer iter.Stop()
	found := false
	for {
		d, err := iter.Next()
		if err == iterator.Done {
			break
		}
		require.NoError(t, err)
		if d.Data()["email"] == email {
			found = true
		}
	}
	assert.True(t, found)
}

func TestTransactionSignupDisabled(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth":          map[string]interface{}{"redirect_uris": []string{RedirectURI}},
		"authentication": map[string]interface{}{"allow_signup": false},
	}, "")

	txID, _, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)
	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/signup", txID), map[string]string{
		"email":    fmt.Sprintf("x-%s@example.com", uuid.New().String()[:8]),
		"password": "password123",
	}, nil)
	assert.Contains(t, []int{http.StatusForbidden, http.StatusBadRequest}, resp.StatusCode)
	assert.Equal(t, "signup_disabled", resp.JSONMap()["error"])
}

func TestTransactionSignupDuplicateAccount(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	email := signupUser(t, h, clientID, "")

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/signup", txID), map[string]string{
		"email":    email,
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "user_already_exists", resp.JSONMap()["error"])
}

func TestTransactionSignupExpiredTransaction(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	past := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)
	_, err := h.DB.Collection("auth_sessions").Doc(txID).Update(context.Background(), []firestore.Update{
		{Path: "expires_at", Value: past},
	})
	require.NoError(t, err)

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/signup", txID), map[string]string{
		"email":    fmt.Sprintf("e-%s@example.com", uuid.New().String()[:8]),
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "session_expired", resp.JSONMap()["error"])
}

func TestGenericSignupRespectsApplicationSignupPolicy(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth":          map[string]interface{}{"redirect_uris": []string{RedirectURI}},
		"authentication": map[string]interface{}{"allow_signup": false},
	}, "")

	resp := h.Client.Post("/api/v1/auth/signup", map[string]string{
		"email":    fmt.Sprintf("x-%s@example.com", uuid.New().String()[:8]),
		"password": "password123",
	}, map[string]string{
		"X-Application-Id": appData["client_id"].(string),
	})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "Signup is disabled for this application", resp.JSONMap()["detail"])
}

func TestEmailVerificationRequiredBlocksCodeIssuance(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth":          map[string]interface{}{"redirect_uris": []string{RedirectURI}},
		"authentication": map[string]interface{}{"require_email_verification": true},
	}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	email := fmt.Sprintf("v-%s@example.com", uuid.New().String()[:8])

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/signup", txID), map[string]string{
		"email":    email,
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	data := resp.JSONMap()
	assert.Nil(t, data["redirect_url"])
	assert.Equal(t, true, data["email_verification_required"])

	snap, err := h.DB.Collection("auth_sessions").Doc(txID).Get(context.Background())
	require.NoError(t, err)
	doc := snap.Data()
	assert.Equal(t, "authenticated", doc["status"])
	assert.NotEmpty(t, doc["user_id"])

	iter := h.DB.Collection("authorization_codes").Where("session_id", "==", txID).Documents(context.Background())
	defer iter.Stop()
	codesCount := 0
	for {
		_, err := iter.Next()
		if err == iterator.Done {
			break
		}
		require.NoError(t, err)
		codesCount++
	}
	assert.Equal(t, 0, codesCount)

	loginResp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
		"email":    email,
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, loginResp.StatusCode)
	assert.Equal(t, "email_verification_required", loginResp.JSONMap()["error"])
}

func TestEmailVerificationCompletesFlow(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth":          map[string]interface{}{"redirect_uris": []string{RedirectURI}},
		"authentication": map[string]interface{}{"require_email_verification": true},
	}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	email := fmt.Sprintf("v-%s@example.com", uuid.New().String()[:8])

	respSignup := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/signup", txID), map[string]string{
		"email":    email,
		"password": "password123",
	}, nil)
	require.Equal(t, http.StatusOK, respSignup.StatusCode)
	assert.Equal(t, true, respSignup.JSONMap()["email_verification_required"])

	h.Notifications.mu.Lock()
	rawToken := h.Notifications.LastOTP
	h.Notifications.mu.Unlock()
	require.NotEmpty(t, rawToken)

	// Raw token never stored in plaintext
	iter := h.DB.Collection("email_verification_tokens").Documents(context.Background())
	defer iter.Stop()
	for {
		d, err := iter.Next()
		if err == iterator.Done {
			break
		}
		require.NoError(t, err)
		assert.NotContains(t, fmt.Sprintf("%v", d.Data()), rawToken)
	}

	respVerify := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/verify-email", txID), map[string]string{
		"verification_token": rawToken,
	}, nil)
	assert.Equal(t, http.StatusOK, respVerify.StatusCode)
	data := respVerify.JSONMap()
	require.NotEmpty(t, data["redirect_url"])
	parsed, _ := url.Parse(data["redirect_url"].(string))
	assert.True(t, strings.HasPrefix(parsed.Query().Get("code"), "code_"))

	snap, err := h.DB.Collection("auth_sessions").Doc(txID).Get(context.Background())
	require.NoError(t, err)
	userID := snap.Data()["user_id"].(string)
	userSnap, err := h.DB.Collection("users").Doc(userID).Get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, true, userSnap.Data()["email_verified"])
	assert.Equal(t, "completed", snap.Data()["status"])
}

func TestCallbackURLPreservesClientState(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, map[string]string{"state": "custom-state-value"})
	email := signupUser(t, h, clientID, "")

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
		"email":    email,
		"password": "password123",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	parsed, _ := url.Parse(resp.JSONMap()["redirect_url"].(string))
	assert.Equal(t, "custom-state-value", parsed.Query().Get("state"))
}
