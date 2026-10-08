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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidAuthorizationRequestRedirectsToIdentityUI(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	clientID := appData["client_id"].(string)

	txID, _, resp := authorizeAndGetTransaction(t, h, clientID, nil)
	assert.True(t, strings.HasPrefix(resp.Location(), h.Config.IdentityUIBaseURL+"/auth/"))

	snap, err := h.DB.Collection("auth_sessions").Doc(txID).Get(context.Background())
	require.NoError(t, err)
	doc := snap.Data()
	assert.Equal(t, clientID, doc["client_id"])
	assert.Equal(t, RedirectURI, doc["redirect_uri"])
	assert.Equal(t, "code", doc["response_type"])
	assert.Equal(t, []interface{}{"openid", "profile", "email"}, doc["scopes"])
	assert.Equal(t, "abc123", doc["state"])
	assert.Equal(t, "pending", doc["status"])
	assert.NotEmpty(t, doc["code_challenge"])
	assert.Equal(t, "S256", doc["code_challenge_method"])
	assert.Nil(t, doc["user_id"])
}

func TestAuthorizeUnknownClientRejected(t *testing.T) {
	h := setup(t)
	params := authorizeParams("app_nonexistent", nil)
	resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_client", resp.JSONMap()["error"])
}

func TestAuthorizeInactiveApplicationRejected(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	clientID := appData["client_id"].(string)

	iter := h.DB.Collection("applications").Where("client_id", "==", clientID).Documents(context.Background())
	doc, err := iter.Next()
	require.NoError(t, err)
	_, err = doc.Ref.Update(context.Background(), []firestore.Update{{Path: "status", Value: "inactive"}})
	require.NoError(t, err)

	params := authorizeParams(clientID, nil)
	resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_client", resp.JSONMap()["error"])
}

func TestAuthorizeLocalhostHTTPRedirectAllowed(t *testing.T) {
	h := setup(t)
	localhost := "http://localhost:3000/callback"
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{localhost}},
	}, "")

	txID, _, resp := authorizeAndGetTransaction(t, h, appData["client_id"].(string), map[string]string{
		"redirect_uri": localhost,
	})
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.True(t, strings.HasPrefix(txID, "tx_"))
}

func TestAuthorizeUnregisteredRedirectURIRejected(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")

	params := authorizeParams(appData["client_id"].(string), map[string]string{
		"redirect_uri": "https://evil.example.com/callback",
	})
	resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_redirect_uri", resp.JSONMap()["error"])
}

func TestAuthorizeRedirectURIExactMatchRequired(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	clientID := appData["client_id"].(string)

	tamperedURIs := []string{
		RedirectURI + "/extra",
		"https://app.example.com/callback?foo=bar",
		"https://app.example.com/callbackx",
		strings.ReplaceAll(RedirectURI, "callback", "Callback"),
		fmt.Sprintf("https://app.example.com/%s", RedirectURI),
	}

	for _, tampered := range tamperedURIs {
		params := authorizeParams(clientID, map[string]string{"redirect_uri": tampered})
		resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s should be rejected", tampered)
		assert.Equal(t, "invalid_redirect_uri", resp.JSONMap()["error"])
	}
}

func TestAuthorizeInvalidScopeRedirectsWithError(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")

	params := authorizeParams(appData["client_id"].(string), map[string]string{
		"scope": "openid admin:everything",
	})
	resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Location()
	assert.True(t, strings.HasPrefix(loc, RedirectURI))
	u, _ := url.Parse(loc)
	assert.Equal(t, "invalid_scope", u.Query().Get("error"))
	assert.Equal(t, "abc123", u.Query().Get("state"))
}

func TestAuthorizeScopeNotAllowedByApplication(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{
			"redirect_uris":  []string{RedirectURI},
			"allowed_scopes": []string{"openid"},
		},
	}, "")

	params := authorizeParams(appData["client_id"].(string), map[string]string{
		"scope": "openid email",
	})
	resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	u, _ := url.Parse(resp.Location())
	assert.Equal(t, "invalid_scope", u.Query().Get("error"))
}

func TestAuthorizeUnsupportedResponseType(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	clientID := appData["client_id"].(string)

	for _, rt := range []string{"token", "code id_token"} {
		params := authorizeParams(clientID, map[string]string{"response_type": rt})
		resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		u, _ := url.Parse(resp.Location())
		assert.Equal(t, "unsupported_response_type", u.Query().Get("error"))
	}
}

func TestAuthorizeMissingPKCERejected(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")

	params := authorizeParams(appData["client_id"].(string), nil)
	params.Del("code_challenge")
	resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}

func TestAuthorizePlainCodeChallengeMethodRejected(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")

	params := authorizeParams(appData["client_id"].(string), map[string]string{
		"code_challenge":        "short",
		"code_challenge_method": "plain",
	})
	resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}

func TestLoadTransactionReturnsSafeContext(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
		"branding": map[string]interface{}{
			"logo_url":      "https://cdn.example.com/logo.png",
			"primary_color": "#112233",
		},
	}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)

	resp := h.Client.Get(fmt.Sprintf("/api/v1/auth-sessions/%s", txID), nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	data := resp.JSONMap()
	assert.Equal(t, txID, data["session_id"])
	assert.Equal(t, "pending", data["status"])
	assert.Equal(t, []interface{}{"openid", "profile", "email"}, data["scopes"])
	app := data["application"].(map[string]interface{})
	assert.Equal(t, appData["name"], app["name"])
	assert.Equal(t, "https://cdn.example.com/logo.png", app["logo_url"])
	assert.Equal(t, "#112233", app["primary_color"])
	assert.Equal(t, true, app["allow_signup"])

	body := resp.Text()
	for _, secret := range []string{"client_secret", "code_challenge", "state", "hashed_secret", "nonce"} {
		assert.NotContains(t, body, secret)
	}
}

func TestLoadTransactionUnknownTransaction(t *testing.T) {
	h := setup(t)
	resp := h.Client.Get("/api/v1/auth-sessions/tx_nonexistent", nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "invalid_session", resp.JSONMap()["error"])
}

func TestExpiredTransactionReportedAndUnusable(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)

	past := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)
	_, err := h.DB.Collection("auth_sessions").Doc(txID).Update(context.Background(), []firestore.Update{
		{Path: "expires_at", Value: past},
	})
	require.NoError(t, err)

	resp := h.Client.Get(fmt.Sprintf("/api/v1/auth-sessions/%s", txID), nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "expired", resp.JSONMap()["status"])

	loginResp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
		"email":    "a@example.com",
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, loginResp.StatusCode)
	assert.Equal(t, "session_expired", loginResp.JSONMap()["error"])
}

func TestCompletedTransactionReuseRejected(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	clientID := appData["client_id"].(string)

	txID, verifier, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	email := signupUser(t, h, clientID, "")
	code := loginAndGetCode(t, h, txID, email, "password123")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {RedirectURI},
		"code_verifier": {verifier},
	}
	resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	loginResp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
		"email":    email,
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, loginResp.StatusCode)
	assert.Equal(t, "session_completed", loginResp.JSONMap()["error"])
}

func TestCancelledTransactionReuseRejected(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, map[string]string{"state": "sample-state"})

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/cancel", txID), nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	data := resp.JSONMap()
	assert.Equal(t, "cancelled", data["status"])
	redirURL := data["redirect_url"].(string)
	assert.Contains(t, redirURL, "error=access_denied")
	assert.Contains(t, redirURL, "state=sample-state")

	loadResp := h.Client.Get(fmt.Sprintf("/api/v1/auth-sessions/%s", txID), nil, nil)
	assert.Equal(t, http.StatusOK, loadResp.StatusCode)
	loadData := loadResp.JSONMap()
	assert.Equal(t, "cancelled", loadData["status"])
	assert.Contains(t, loadData["redirect_url"].(string), "error=access_denied")
	assert.Contains(t, loadData["redirect_url"].(string), "state=sample-state")

	loginResp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
		"email":    "a@example.com",
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, loginResp.StatusCode)
	assert.Equal(t, "session_cancelled", loginResp.JSONMap()["error"])
}

func TestTransactionApplicationBinding(t *testing.T) {
	h := setup(t)
	appA := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	appB := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")

	txID, _, _ := authorizeAndGetTransaction(t, h, appA["client_id"].(string), nil)

	snap, err := h.DB.Collection("auth_sessions").Doc(txID).Get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, appA["id"], snap.Data()["application_id"])

	loginResp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
		"email":    "user@example.com",
		"password": "password123",
	}, map[string]string{
		"X-Application-Id": appB["client_id"].(string),
	})
	assert.Contains(t, []int{http.StatusBadRequest, http.StatusUnauthorized}, loginResp.StatusCode)

	snap2, _ := h.DB.Collection("auth_sessions").Doc(txID).Get(context.Background())
	assert.Equal(t, appA["id"], snap2.Data()["application_id"])
	assert.Equal(t, appA["client_id"], snap2.Data()["client_id"])
}

func TestAuthorizePreservesStateAndNonceInTransaction(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, map[string]string{
		"state": "client-state-42",
		"nonce": "nonce-7",
	})

	snap, err := h.DB.Collection("auth_sessions").Doc(txID).Get(context.Background())
	require.NoError(t, err)
	doc := snap.Data()
	assert.Equal(t, "client-state-42", doc["state"])
	assert.Equal(t, "nonce-7", doc["nonce"])
}

func TestInternalTransactionCreationAdminProtected(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	_, challenge := pkcePair()
	params := map[string]string{
		"client_id":             clientID,
		"redirect_uri":          RedirectURI,
		"response_type":         "code",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}

	respUnauth := h.Client.Post("/api/v1/admin/auth-sessions", params, nil)
	assert.Contains(t, []int{http.StatusForbidden, http.StatusUnprocessableEntity}, respUnauth.StatusCode)

	respAuth := h.Client.Post("/api/v1/admin/auth-sessions", params, map[string]string{
		"X-Admin-Token": h.Config.AdminSecret,
	})
	assert.Equal(t, http.StatusOK, respAuth.StatusCode)
	data := respAuth.JSONMap()
	assert.True(t, strings.HasPrefix(data["session_id"].(string), "tx_"))
	assert.Equal(t, "pending", data["status"])
}
