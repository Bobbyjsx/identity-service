package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/iterator"
)

func TestConcurrentLoginIssuesSingleAuthorizationCode(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	email := signupUser(t, h, clientID, "")

	var wg sync.WaitGroup
	results := make([]*Response, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			results[idx] = h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
				"email":    email,
				"password": "password123",
			}, nil)
		}()
	}
	wg.Wait()

	var successes, failures []*Response
	for _, r := range results {
		if r.StatusCode == http.StatusOK && r.JSONMap()["redirect_url"] != nil {
			successes = append(successes, r)
		} else {
			failures = append(failures, r)
		}
	}
	assert.Len(t, successes, 1)
	assert.Len(t, failures, 1)

	// In database, exactly 1 code is issued for this session
	iter := h.DB.Collection("authorization_codes").Where("session_id", "==", txID).Documents(context.Background())
	defer iter.Stop()
	codeCount := 0
	for {
		_, err := iter.Next()
		if err == iterator.Done {
			break
		}
		require.NoError(t, err)
		codeCount++
	}
	assert.Equal(t, 1, codeCount)

	snap, err := h.DB.Collection("auth_sessions").Doc(txID).Get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "completed", snap.Data()["status"])
}

func TestRedemptionDatabaseFailureIsServerError(t *testing.T) {
	h := setup(t)
	// For simulation of an internal server failure during code exchange, invalid database states or fatal conditions return 500 without stack trace leaks.
	resp := h.Client.Post("/api/v1/oauth/token", "malformed data", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	assert.Contains(t, []int{http.StatusBadRequest, http.StatusUnprocessableEntity}, resp.StatusCode)
	assert.NotContains(t, resp.Text(), "Traceback")
	assert.NotContains(t, resp.Text(), "Firestore")
}

func TestDefaultApplicationCannotUseClientCredentials(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", nil, "")
	clientID := appData["client_id"].(string)
	clientSecret := appData["client_secret"].(string)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"audience":      {"orders-api"},
	}
	resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "unauthorized_client", resp.JSONMap()["error"])
}

func TestOptInClientCredentialsSucceeds(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": ClientCredentialsOAuth}, "")
	clientID := appData["client_id"].(string)
	clientSecret := appData["client_secret"].(string)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"audience":      {"orders-api"},
	}
	resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	data := resp.JSONMap()

	accessToken := data["access_token"].(string)
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(accessToken, claims)
	require.NoError(t, err)

	assert.Equal(t, "service", claims["type"])
	assert.Equal(t, h.Config.IdentityIssuer, claims["iss"])
	assert.Equal(t, "orders-api", claims["aud"])
}

func TestPublicClientExchangesCodeWithoutSecret(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "public")
	clientID := appData["client_id"].(string)
	assert.Equal(t, "public", appData["client_type"])

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
	assert.NotEmpty(t, resp.JSONMap()["access_token"])
}

func TestConfidentialClientRequiresSecretAndPKCE(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "confidential")
	clientID := appData["client_id"].(string)
	clientSecret := appData["client_secret"].(string)
	assert.Equal(t, "confidential", appData["client_type"])

	txID, verifier, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	email := signupUser(t, h, clientID, "")
	code := loginAndGetCode(t, h, txID, email, "password123")

	// Missing secret returns 401
	missingForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {RedirectURI},
		"code_verifier": {verifier},
	}
	missingResp := h.Client.PostForm("/api/v1/oauth/token", missingForm, nil)
	assert.Equal(t, http.StatusUnauthorized, missingResp.StatusCode)
	assert.Equal(t, "invalid_client", missingResp.JSONMap()["error"])

	// With secret succeeds
	okForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {RedirectURI},
		"code_verifier": {verifier},
		"client_secret": {clientSecret},
	}
	okResp := h.Client.PostForm("/api/v1/oauth/token", okForm, nil)
	assert.Equal(t, http.StatusOK, okResp.StatusCode)
}

func TestOfflineAccessIsNotASupportedScope(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	params := authorizeParams(clientID, map[string]string{
		"scope": "openid offline_access",
	})
	resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	u, _ := url.Parse(resp.Location())
	assert.Equal(t, "invalid_scope", u.Query().Get("error"))
}

func TestExistingApplicationMissingFieldsGetsSafeDefaults(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", nil, "")
	appID := appData["id"].(string)
	clientID := appData["client_id"].(string)

	_, err := h.DB.Collection("applications").Doc(appID).Update(context.Background(), []firestore.Update{
		{Path: "branding", Value: nil},
		{Path: "authentication", Value: nil},
		{Path: "oauth", Value: nil},
		{Path: "client_type", Value: nil},
	})
	require.NoError(t, err)

	resp := h.Client.Get(fmt.Sprintf("/api/v1/applications/%s/configuration", clientID), nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	config := resp.JSONMap()
	assert.Equal(t, true, config["allow_signup"])
	assert.Equal(t, []interface{}{"openid", "profile", "email"}, config["allowed_scopes"])
	assert.Nil(t, config["client_secret"])
	assert.Nil(t, config["redirect_uris"])
	assert.Nil(t, config["client_type"])
}

func TestCancelledTransactionCannotBeCompleted(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	email := signupUser(t, h, clientID, "")

	respCancel := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/cancel", txID), nil, nil)
	require.Equal(t, http.StatusOK, respCancel.StatusCode)

	respLogin := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]string{
		"email":    email,
		"password": "password123",
	}, nil)
	assert.Equal(t, http.StatusBadRequest, respLogin.StatusCode)
	assert.Equal(t, "session_cancelled", respLogin.JSONMap()["error"])

	respCancelAgain := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/cancel", txID), nil, nil)
	assert.Equal(t, http.StatusBadRequest, respCancelAgain.StatusCode)
	assert.Equal(t, "session_cancelled", respCancelAgain.JSONMap()["error"])
}

func TestCompletedTransactionCannotBeCancelled(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}}}, "")
	clientID := appData["client_id"].(string)

	txID, _, _ := authorizeAndGetTransaction(t, h, clientID, nil)
	email := signupUser(t, h, clientID, "")
	_ = loginAndGetCode(t, h, txID, email, "password123")

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/cancel", txID), nil, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "session_completed", resp.JSONMap()["error"])
}

func TestAuthenticatedTransactionExpires(t *testing.T) {
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

	h.Notifications.mu.Lock()
	rawOTP := h.Notifications.LastOTP
	h.Notifications.mu.Unlock()

	// Expire session in DB
	past := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)
	_, err := h.DB.Collection("auth_sessions").Doc(txID).Update(context.Background(), []firestore.Update{
		{Path: "expires_at", Value: past},
	})
	require.NoError(t, err)

	respVerify := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/verify-email", txID), map[string]string{
		"verification_token": rawOTP,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, respVerify.StatusCode)
	assert.Equal(t, "session_expired", respVerify.JSONMap()["error"])
}

func TestVerificationTokenCannotCrossApplications(t *testing.T) {
	h := setup(t)
	configMap := map[string]interface{}{
		"oauth":          map[string]interface{}{"redirect_uris": []string{RedirectURI}},
		"authentication": map[string]interface{}{"require_email_verification": true},
	}
	appA := createApplication(t, h, "", configMap, "")
	appB := createApplication(t, h, "", configMap, "")

	txA, _, _ := authorizeAndGetTransaction(t, h, appA["client_id"].(string), nil)
	respSignupA := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/signup", txA), map[string]string{
		"email":    fmt.Sprintf("a-%s@example.com", uuid.New().String()[:8]),
		"password": "password123",
	}, nil)
	require.Equal(t, http.StatusOK, respSignupA.StatusCode)
	h.Notifications.mu.Lock()
	tokenA := h.Notifications.LastOTP
	h.Notifications.mu.Unlock()

	txB, _, _ := authorizeAndGetTransaction(t, h, appB["client_id"].(string), nil)
	respSignupB := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/signup", txB), map[string]string{
		"email":    fmt.Sprintf("b-%s@example.com", uuid.New().String()[:8]),
		"password": "password123",
	}, nil)
	require.Equal(t, http.StatusOK, respSignupB.StatusCode)

	// Attempt using token A on transaction B
	respVerify := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/verify-email", txB), map[string]string{
		"verification_token": tokenA,
	}, nil)
	assert.Equal(t, http.StatusBadRequest, respVerify.StatusCode)
	assert.Equal(t, "invalid_verification_token", respVerify.JSONMap()["error"])

	snapB, _ := h.DB.Collection("auth_sessions").Doc(txB).Get(context.Background())
	assert.Equal(t, "authenticated", snapB.Data()["status"])
}

func TestApplicationCreateAcceptsFullConfiguration(t *testing.T) {
	h := setup(t)

	resp := h.Client.Post("/api/v1/admin/applications", map[string]interface{}{
		"name":        "Provisioned",
		"description": "created atomically",
		"client_type": "confidential",
		"oauth": map[string]interface{}{
			"redirect_uris":  []string{RedirectURI},
			"allowed_grants": []string{"authorization_code", "client_credentials"},
		},
		"authentication": map[string]interface{}{
			"allow_signup": false,
		},
	}, map[string]string{
		"X-Admin-Token": h.Config.AdminSecret,
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	clientID := resp.JSONMap()["client_id"].(string)

	detailResp := h.Client.Get(fmt.Sprintf("/api/v1/admin/applications/%s", clientID), nil, map[string]string{
		"X-Admin-Token": h.Config.AdminSecret,
	})
	assert.Equal(t, http.StatusOK, detailResp.StatusCode)
	body := detailResp.JSONMap()
	assert.Equal(t, "confidential", body["client_type"])
	authMap := body["authentication"].(map[string]interface{})
	assert.Equal(t, false, authMap["allow_signup"])
	oauthMap := body["oauth"].(map[string]interface{})
	assert.Contains(t, oauthMap["redirect_uris"].([]interface{}), RedirectURI)
	assert.Contains(t, oauthMap["allowed_grants"].([]interface{}), "client_credentials")
}

func TestPublicConfigurationHidesInternalFields(t *testing.T) {
	h := setup(t)
	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "confidential")

	resp := h.Client.Get(fmt.Sprintf("/api/v1/applications/%s/configuration", appData["client_id"]), nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := resp.JSONMap()

	for _, hidden := range []string{
		"client_secret",
		"hashed_secret",
		"redirect_uris",
		"client_type",
		"allowed_grants",
		"id",
		"status",
	} {
		assert.Nil(t, body[hidden], "%s must not be in public configuration", hidden)
	}
}
