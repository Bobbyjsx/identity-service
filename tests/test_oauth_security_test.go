package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"identity-service/internal/core"
)

func TestCrossApplicationTransactionIsolation(t *testing.T) {
	h := setup(t)

	appA := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	appB := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")

	txA, _, _ := authorizeAndGetTransaction(t, h, appA["client_id"].(string), nil)

	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appB["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	// App B's user cannot authenticate through app A's transaction
	loginResp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txA), map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, nil)
	assert.Equal(t, 401, loginResp.StatusCode)
	loginErr := loginResp.JSONMap()
	assert.Equal(t, "invalid_credentials", loginErr["error"])

	// A signup through app A's transaction creates an isolated user in app A only
	txA2, _, _ := authorizeAndGetTransaction(t, h, appA["client_id"].(string), nil)
	signupTxResp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/signup", txA2), map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, nil)
	assert.Equal(t, 200, signupTxResp.StatusCode)
	signupTxData := signupTxResp.JSONMap()
	assert.NotEmpty(t, signupTxData["redirect_url"])
}

func TestCrossApplicationCodeRedemptionImpossible(t *testing.T) {
	h := setup(t)

	appA := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	appB := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")

	txA, verifier, _ := authorizeAndGetTransaction(t, h, appA["client_id"].(string), nil)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appA["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	code := loginAndGetCode(t, h, txA, email, "password123")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", appB["client_id"].(string))
	form.Set("redirect_uri", RedirectURI)
	form.Set("code_verifier", verifier)

	// App B presents app A's code with app B's client_id
	resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
	assert.Equal(t, 400, resp.StatusCode)
	errData := resp.JSONMap()
	assert.Equal(t, "invalid_grant", errData["error"])
}

func TestCrossApplicationConfigurationIsolation(t *testing.T) {
	h := setup(t)

	createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
		"branding": map[string]interface{}{
			"primary_color": "#111111",
		},
	}, "")
	appB := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")

	resp := h.Client.Get(fmt.Sprintf("/api/v1/applications/%s/configuration", appB["client_id"].(string)), nil, nil)
	assert.Equal(t, 200, resp.StatusCode)
	configB := resp.JSONMap()
	assert.Nil(t, configB["primary_color"])
	assert.NotEqual(t, "#111111", configB["primary_color"])
}

func TestRedirectUriManipulationAtExchange(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	txID, verifier, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	code := loginAndGetCode(t, h, txID, email, "password123")

	tamperedURIs := []string{
		fmt.Sprintf("%s/suffix", RedirectURI),
		strings.Replace(RedirectURI, "https", "http", 1),
		"https://app.example.com/other",
		fmt.Sprintf("%s?x=1", RedirectURI),
	}

	for _, tampered := range tamperedURIs {
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("client_id", appData["client_id"].(string))
		form.Set("redirect_uri", tampered)
		form.Set("code_verifier", verifier)

		resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
		assert.Equal(t, 400, resp.StatusCode, "%s should be rejected", tampered)
		errData := resp.JSONMap()
		assert.Equal(t, "invalid_grant", errData["error"])
	}
}

func TestAuthorizeRejectsUnregisteredDomain(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	_, challenge := pkcePair()

	query := url.Values{}
	query.Set("client_id", appData["client_id"].(string))
	query.Set("redirect_uri", "https://attacker.example.com/cb")
	query.Set("response_type", "code")
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	query.Set("state", "x")

	resp := h.Client.Get("/api/v1/oauth/authorize", query, nil)
	assert.Equal(t, 400, resp.StatusCode)
	errData := resp.JSONMap()
	assert.Equal(t, "invalid_redirect_uri", errData["error"])
}

func TestAuthorizeRejectsJavascriptURI(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	_, challenge := pkcePair()

	query := url.Values{}
	query.Set("client_id", appData["client_id"].(string))
	query.Set("redirect_uri", "javascript:alert(1)")
	query.Set("response_type", "code")
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")

	resp := h.Client.Get("/api/v1/oauth/authorize", query, nil)
	assert.Equal(t, 400, resp.StatusCode)
	errData := resp.JSONMap()
	assert.Equal(t, "invalid_redirect_uri", errData["error"])
}

func TestTransactionIdIsOpaqueAndHighEntropy(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	seen := make(map[string]bool)
	for i := 0; i < 5; i++ {
		txID, _, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)
		assert.True(t, strings.HasPrefix(txID, "tx_"))
		assert.Greater(t, len(txID), 30)
		seen[txID] = true
	}
	assert.Len(t, seen, 5)
}

func TestIDTokenAudienceIsClient(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	txID, verifier, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	code := loginAndGetCode(t, h, txID, email, "password123")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", appData["client_id"].(string))
	form.Set("redirect_uri", RedirectURI)
	form.Set("code_verifier", verifier)

	resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
	assert.Equal(t, 200, resp.StatusCode)
	data := resp.JSONMap()

	parsedToken, _, err := jwt.NewParser().ParseUnverified(data["id_token"].(string), jwt.MapClaims{})
	require.NoError(t, err)
	claims := parsedToken.Claims.(jwt.MapClaims)

	assert.Equal(t, appData["client_id"], claims["aud"])
	assert.NotEqual(t, "application_api", claims["aud"])
	assert.Nil(t, claims["hashed_secret"])
	assert.Nil(t, claims["client_secret"])
	assert.Nil(t, claims["private_key"])
}

func TestIDTokenSignatureVerifiesWithJWKS(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	txID, verifier, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	code := loginAndGetCode(t, h, txID, email, "password123")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", appData["client_id"].(string))
	form.Set("redirect_uri", RedirectURI)
	form.Set("code_verifier", verifier)

	resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
	assert.Equal(t, 200, resp.StatusCode)
	data := resp.JSONMap()

	jwksResp := h.Client.Get("/.well-known/jwks.json", nil, nil)
	assert.Equal(t, 200, jwksResp.StatusCode)
	jwks := jwksResp.JSONMap()

	parsedUnverified, _, err := jwt.NewParser().ParseUnverified(data["id_token"].(string), jwt.MapClaims{})
	require.NoError(t, err)
	kid := parsedUnverified.Header["kid"].(string)

	keys := jwks["keys"].([]interface{})
	var foundKey map[string]interface{}
	for _, k := range keys {
		km := k.(map[string]interface{})
		if km["kid"] == kid {
			foundKey = km
			break
		}
	}
	require.NotNil(t, foundKey, "Key %s not found in JWKS", kid)

	pubBytes, err := base64.RawURLEncoding.DecodeString(foundKey["x"].(string))
	require.NoError(t, err)
	pubKey := ed25519.PublicKey(pubBytes)

	parsedVerified, err := jwt.Parse(data["id_token"].(string), func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	}, jwt.WithAudience(appData["client_id"].(string)), jwt.WithIssuer(h.Config.IdentityIssuer))
	require.NoError(t, err)
	claims := parsedVerified.Claims.(jwt.MapClaims)
	assert.NotEmpty(t, claims["sub"])
}

func TestJWKSEndpointUnchanged(t *testing.T) {
	h := setup(t)

	resp := h.Client.Get("/.well-known/jwks.json", nil, nil)
	assert.Equal(t, 200, resp.StatusCode)
	res := resp.JSONMap()
	keys := res["keys"].([]interface{})
	assert.GreaterOrEqual(t, len(keys), 1)
	first := keys[0].(map[string]interface{})
	assert.Equal(t, "OKP", first["kty"])
	assert.Equal(t, "Ed25519", first["crv"])
}

func TestOIDCDiscoveryDocument(t *testing.T) {
	h := setup(t)

	resp := h.Client.Get("/.well-known/openid-configuration", nil, nil)
	assert.Equal(t, 200, resp.StatusCode)
	doc := resp.JSONMap()

	assert.Equal(t, h.Config.IdentityIssuer, doc["issuer"])
	assert.Equal(t, fmt.Sprintf("%s/api/v1/oauth/authorize", h.Config.PublicBaseURL), doc["authorization_endpoint"])
	assert.Equal(t, fmt.Sprintf("%s/api/v1/oauth/token", h.Config.PublicBaseURL), doc["token_endpoint"])

	respTypes := doc["response_types_supported"].([]interface{})
	assert.Contains(t, respTypes, "code")
	assert.NotContains(t, respTypes, "token")

	grantTypes := doc["grant_types_supported"].([]interface{})
	assert.Contains(t, grantTypes, "authorization_code")
	assert.Contains(t, grantTypes, "client_credentials")

	codeChallengeMethods := doc["code_challenge_methods_supported"].([]interface{})
	assert.Contains(t, codeChallengeMethods, "S256")
	assert.NotContains(t, codeChallengeMethods, "plain")

	scopes := doc["scopes_supported"].([]interface{})
	assert.NotContains(t, scopes, "offline_access")
	expectedScopes := map[string]bool{"openid": true, "profile": true, "email": true}
	actualScopes := make(map[string]bool)
	for _, s := range scopes {
		actualScopes[s.(string)] = true
	}
	assert.Equal(t, expectedScopes, actualScopes)

	claims := doc["claims_supported"].([]interface{})
	assert.Contains(t, claims, "iss")
	assert.Contains(t, claims, "nonce")
}

func TestInvalidSignatureRejectedByAPI(t *testing.T) {
	h := setup(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	bogusToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss":    h.Config.IdentityIssuer,
		"sub":    "user_x",
		"aud":    "application_api",
		"app_id": "app_x",
		"type":   "user",
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	bogusStr, err := bogusToken.SignedString(priv)
	require.NoError(t, err)

	resp := h.Client.Get("/api/v1/auth/me", nil, map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", bogusStr),
	})
	assert.Equal(t, 401, resp.StatusCode)
}

func TestIncorrectAudienceRejected(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{
			"allowed_grants": []string{"authorization_code", "client_credentials"},
		},
	}, "")

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", appData["client_id"].(string))
	form.Set("client_secret", appData["client_secret"].(string))
	form.Set("audience", "file_service_a")

	resp := h.Client.PostForm("/api/v1/oauth/token", form, nil)
	assert.Equal(t, 200, resp.StatusCode)
	data := resp.JSONMap()
	token := data["access_token"].(string)

	_, err := h.KeyManager.VerifyJWT(token, []string{"file_service_b"})
	assert.Error(t, err)

	verified, err := h.KeyManager.VerifyJWT(token, []string{"file_service_a"})
	assert.NoError(t, err)
	assert.Equal(t, "service", verified["type"])
}

func TestErrorResponsesDoNotLeakStackTraces(t *testing.T) {
	h := setup(t)

	resp := h.Client.Get("/api/v1/auth-sessions/tx_nonexistent", nil, nil)
	body := string(resp.Body)
	assert.NotContains(t, body, "Traceback")
	assert.NotContains(t, body, "File \"")
	errData := resp.JSONMap()
	assert.Equal(t, "invalid_session", errData["error"])
}

func TestRawAuthorizationCodeNeverPersisted(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	txID, _, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	code := loginAndGetCode(t, h, txID, email, "password123")

	docs, err := h.DB.Collection("authorization_codes").Where("session_id", "==", txID).Documents(context.Background()).GetAll()
	require.NoError(t, err)
	assert.Len(t, docs, 1)
	stored := docs[0].Data()
	assert.Equal(t, core.HashToken(code), stored["code_hash"])
	for _, v := range stored {
		assert.NotEqual(t, code, v)
	}
}

func TestTransactionSecretsNotExposedInDocuments(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	txID, _, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)

	resp := h.Client.Get(fmt.Sprintf("/api/v1/auth-sessions/%s", txID), nil, nil)
	body := string(resp.Body)
	for _, secret := range []string{"code_challenge", "client_secret", "nonce", "state", "hashed_secret"} {
		assert.NotContains(t, body, secret)
	}

	configResp := h.Client.Get(fmt.Sprintf("/api/v1/applications/%s/configuration", appData["client_id"].(string)), nil, nil)
	configBody := string(configResp.Body)
	for _, secret := range []string{"client_secret", "hashed_secret", "redirect_uris"} {
		assert.NotContains(t, configBody, secret)
	}
}

func TestCallbackRedirectContainsOnlyCodeAndState(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "", map[string]interface{}{
		"oauth": map[string]interface{}{"redirect_uris": []string{RedirectURI}},
	}, "")
	txID, _, _ := authorizeAndGetTransaction(t, h, appData["client_id"].(string), nil)
	email := fmt.Sprintf("user-%s@example.com", uuid.New().String()[:8])
	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, map[string]string{"X-Application-Id": appData["client_id"].(string)})
	require.Equal(t, 200, signupResp.StatusCode)

	resp := h.Client.Post(fmt.Sprintf("/api/v1/auth-sessions/%s/login", txID), map[string]interface{}{
		"email":    email,
		"password": "password123",
	}, nil)
	assert.Equal(t, 200, resp.StatusCode)
	data := resp.JSONMap()
	redirectURL := data["redirect_url"].(string)

	parsed, err := url.Parse(redirectURL)
	require.NoError(t, err)
	query := parsed.Query()

	expectedParams := map[string]bool{"code": true, "state": true}
	actualParams := make(map[string]bool)
	for k := range query {
		actualParams[k] = true
	}
	assert.Equal(t, expectedParams, actualParams)

	for _, forbidden := range []string{"access_token", "refresh_token", "id_token", "client_secret", "tx_"} {
		assert.NotContains(t, redirectURL, forbidden)
	}
}
