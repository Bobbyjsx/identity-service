package tests

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"identity-service/internal/core"
)

func fullFlow(t *testing.T, h *TestHarness, appData map[string]interface{}, scope, nonce string) (string, string, string) {
	overrides := map[string]string{}
	if scope != "" {
		overrides["scope"] = scope
	} else if scope == "" && nonce != "" {
		overrides["scope"] = ""
	}
	if nonce != "" {
		overrides["nonce"] = nonce
	}
	txID, verifier, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), overrides)
	email := signupUser(t, h, appData["client_id"].(string), "")
	code := loginAndGetCode(t, h, txID, email, "password123")
	return code, verifier, email
}

func exchange(h *TestHarness, code, verifier, clientID, redirectURI string, extra map[string]string) *Response {
	if redirectURI == "" {
		redirectURI = RedirectURI
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	for k, v := range extra {
		form.Set(k, v)
	}
	return h.Client.PostForm("/api/v1/oauth/token", form, nil)
}

func TestValidAuthorizationCodeExchange(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, verifier, _ := fullFlow(t, h, appData, "openid profile email", "abc123")

	resp := exchange(h, code, verifier, appData["client_id"].(string), RedirectURI, nil)
	assert.Equal(t, 200, resp.StatusCode, resp.Text())
	data := resp.JSONMap()
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])
	assert.Equal(t, "bearer", data["token_type"])
	assert.Equal(t, float64(h.Config.JWTExpirationMinutes*60), data["expires_in"])
	assert.NotEmpty(t, data["id_token"])

	accessParsed, _, err := jwt.NewParser().ParseUnverified(data["access_token"].(string), jwt.MapClaims{})
	require.NoError(t, err)
	access := accessParsed.Claims.(jwt.MapClaims)
	assert.Equal(t, h.Config.IdentityIssuer, access["iss"])
	assert.Equal(t, "user", access["type"])
	assert.Equal(t, "application_api", access["aud"])
	assert.Equal(t, appData["client_id"], access["app_id"])
	assert.Equal(t, "openid profile email", access["scope"])
	roles := access["roles"].([]interface{})
	assert.Empty(t, roles)

	idParsed, _, err := jwt.NewParser().ParseUnverified(data["id_token"].(string), jwt.MapClaims{})
	require.NoError(t, err)
	idToken := idParsed.Claims.(jwt.MapClaims)
	assert.Equal(t, h.Config.IdentityIssuer, idToken["iss"])
	assert.Equal(t, access["iss"], idToken["iss"])
	assert.Equal(t, appData["client_id"], idToken["aud"])
	assert.Equal(t, access["sub"], idToken["sub"])
	assert.Greater(t, idToken["exp"].(float64), idToken["iat"].(float64))
	assert.NotEmpty(t, idToken["email"])
	assert.NotNil(t, idToken["email_verified"])
	assert.Equal(t, "abc123", idToken["nonce"])
}

func TestAccessTokenVerifiableAndUseful(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, verifier, _ := fullFlow(t, h, appData, "openid profile email", "abc123")
	data := exchange(h, code, verifier, appData["client_id"].(string), RedirectURI, nil).JSONMap()

	resp := h.Client.Get("/api/v1/auth/me", nil, map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", data["access_token"].(string)),
	})
	assert.Equal(t, 200, resp.StatusCode)
	me := resp.JSONMap()
	assert.NotEmpty(t, me["email"])
}

func TestRefreshTokenFromExchangeWorks(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, verifier, _ := fullFlow(t, h, appData, "openid profile email", "abc123")
	data := exchange(h, code, verifier, appData["client_id"].(string), RedirectURI, nil).JSONMap()

	resp := h.Client.Post("/api/v1/auth/refresh", map[string]interface{}{
		"refresh_token": data["refresh_token"],
	}, nil)
	assert.Equal(t, 200, resp.StatusCode)
	newTokens := resp.JSONMap()
	assert.NotEmpty(t, newTokens["access_token"])
	assert.NotEqual(t, data["refresh_token"], newTokens["refresh_token"])
}

func TestNoOpenIDScopeNoIDToken(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, verifier, _ := fullFlow(t, h, appData, "", "abc123")
	data := exchange(h, code, verifier, appData["client_id"].(string), RedirectURI, nil).JSONMap()
	assert.Nil(t, data["id_token"])

	accessParsed, _, err := jwt.NewParser().ParseUnverified(data["access_token"].(string), jwt.MapClaims{})
	require.NoError(t, err)
	access := accessParsed.Claims.(jwt.MapClaims)
	if s, ok := access["scope"]; ok {
		assert.Equal(t, "", s)
	}
}

func TestInvalidCodeRejected(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	_, verifier, _ := fullFlow(t, h, appData, "openid profile email", "abc123")
	resp := exchange(h, "code_fake", verifier, appData["client_id"].(string), RedirectURI, nil)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "invalid_grant", resp.JSONMap()["error"])
}

func TestExpiredCodeRejected(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, verifier, _ := fullFlow(t, h, appData, "openid profile email", "abc123")

	codeHash := core.HashToken(code)
	docs, err := h.DB.Collection("authorization_codes").Where("code_hash", "==", codeHash).Documents(context.Background()).GetAll()
	require.NoError(t, err)
	for _, doc := range docs {
		_, err := doc.Ref.Update(context.Background(), []firestore.Update{
			{Path: "expires_at", Value: time.Now().Add(-time.Minute).Format(time.RFC3339)},
		})
		require.NoError(t, err)
	}

	resp := exchange(h, code, verifier, appData["client_id"].(string), RedirectURI, nil)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "invalid_grant", resp.JSONMap()["error"])
}

func TestReusedCodeRejected(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, verifier, _ := fullFlow(t, h, appData, "openid profile email", "abc123")

	first := exchange(h, code, verifier, appData["client_id"].(string), RedirectURI, nil)
	assert.Equal(t, 200, first.StatusCode)

	second := exchange(h, code, verifier, appData["client_id"].(string), RedirectURI, nil)
	assert.Equal(t, 400, second.StatusCode)
	assert.Equal(t, "invalid_grant", second.JSONMap()["error"])
}

func TestWrongClientRejected(t *testing.T) {
	h := setup(t)

	appA := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	appB := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, verifier, _ := fullFlow(t, h, appA, "openid profile email", "abc123")

	resp := exchange(h, code, verifier, appB["client_id"].(string), RedirectURI, nil)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "invalid_grant", resp.JSONMap()["error"])
}

func TestWrongRedirectURIARejected(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, verifier, _ := fullFlow(t, h, appData, "openid profile email", "abc123")

	resp := exchange(h, code, verifier, appData["client_id"].(string), "https://evil.example.com/callback", nil)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "invalid_grant", resp.JSONMap()["error"])
}

func TestWrongPKCEVerifierRejected(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, _, _ := fullFlow(t, h, appData, "openid profile email", "abc123")
	wrongVerifier, _ := pkcePair()

	resp := exchange(h, code, wrongVerifier, appData["client_id"].(string), RedirectURI, nil)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "invalid_grant", resp.JSONMap()["error"])
}

func TestMissingPKCEVerifierRejected(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, _, _ := fullFlow(t, h, appData, "openid profile email", "abc123")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", appData["client_id"].(string))
	form.Set("redirect_uri", RedirectURI)

	resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "invalid_request", resp.JSONMap()["error"])
}

func TestMalformedTokenRequest(t *testing.T) {
	h := setup(t)

	form := url.Values{}
	form.Set("grant_type", "bogus")

	resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
	assert.Equal(t, 422, resp.StatusCode)
}

func TestUnsupportedGrantType(t *testing.T) {
	h := setup(t)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "app_x")
	form.Set("username", "a")
	form.Set("password", "b")

	resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "unsupported_grant_type", resp.JSONMap()["error"])
}

func TestClientCredentialsFlowStillWorks(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{"oauth": ClientCredentialsOAuth}, "")

	for _, endpoint := range []string{"/api/v1/oauth/token", "/api/v1/oauth/token"} {
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", appData["client_id"].(string))
		form.Set("client_secret", appData["client_secret"].(string))
		form.Set("audience", "custom_file_service")

		resp := h.Client.PostForm(endpoint, form, nil)
		assert.Equal(t, 200, resp.StatusCode, resp.Text())
		data := resp.JSONMap()
		tokenParsed, _, err := jwt.NewParser().ParseUnverified(data["access_token"].(string), jwt.MapClaims{})
		require.NoError(t, err)
		token := tokenParsed.Claims.(jwt.MapClaims)
		assert.Equal(t, "service", token["type"])
		assert.Equal(t, "custom_file_service", token["aud"])
		assert.Equal(t, appData["id"], token["app_id"])
	}
}

func TestClientCredentialsBadSecretStillRejected(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{"oauth": ClientCredentialsOAuth}, "")

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", appData["client_id"].(string))
	form.Set("client_secret", "wrong")
	form.Set("audience", "svc")

	resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
	assert.Equal(t, 401, resp.StatusCode)
	assert.Equal(t, "invalid_client", resp.JSONMap()["error"])
}

func TestAuthorizationCodeWithClientSecret(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, verifier, _ := fullFlow(t, h, appData, "openid profile email", "abc123")

	resp := exchange(h, code, verifier, appData["client_id"].(string), RedirectURI, map[string]string{
		"client_secret": appData["client_secret"].(string),
	})
	assert.Equal(t, 200, resp.StatusCode)

	code2, verifier2, _ := fullFlow(t, h, appData, "openid profile email", "abc123")
	resp2 := exchange(h, code2, verifier2, appData["client_id"].(string), RedirectURI, map[string]string{
		"client_secret": "wrong-secret",
	})
	assert.Equal(t, 401, resp2.StatusCode)
	assert.Equal(t, "invalid_client", resp2.JSONMap()["error"])
}

func TestAuthorizationCodeGrantDisabledRejectedAtAuthorize(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{
			"redirect_uris":  []string{RedirectURI},
			"allowed_grants": []string{"client_credentials"},
		},
	}, "")

	params := authorizeParams(appData["client_id"].(string), nil)
	resp := h.Client.Get("/api/v1/oauth/authorize", params, nil)
	assert.Equal(t, 302, resp.StatusCode)

	loc := resp.Location()
	parsed, err := url.Parse(loc)
	require.NoError(t, err)
	assert.Equal(t, "unauthorized_client", parsed.Query().Get("error"))
}

func TestUserDeletedAfterCodeIssued(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, verifier, email := fullFlow(t, h, appData, "openid profile email", "abc123")

	users, err := h.DB.Collection("users").Where("app_id", "==", appData["client_id"]).Documents(context.Background()).GetAll()
	require.NoError(t, err)
	for _, u := range users {
		if u.Data()["email"] == email {
			_, err := u.Ref.Delete(context.Background())
			require.NoError(t, err)
		}
	}

	resp := exchange(h, code, verifier, appData["client_id"].(string), RedirectURI, nil)
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "invalid_grant", resp.JSONMap()["error"])
}

func TestConcurrentRedemptionSingleUse(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	code, verifier, _ := fullFlow(t, h, appData, "openid profile email", "abc123")

	var wg sync.WaitGroup
	statuses := make([]int, 2)
	var failedResp *Response
	var mu sync.Mutex

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r := exchange(h, code, verifier, appData["client_id"].(string), RedirectURI, nil)
			mu.Lock()
			statuses[idx] = r.StatusCode
			if r.StatusCode == 400 {
				failedResp = r
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	sort.Ints(statuses)
	assert.Equal(t, []int{200, 400}, statuses)
	require.NotNil(t, failedResp)
	assert.Equal(t, "invalid_grant", failedResp.JSONMap()["error"])
}
