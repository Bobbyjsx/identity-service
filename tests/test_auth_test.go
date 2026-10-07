package tests

import (
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvalidApplicationContextSignup(t *testing.T) {
	h := setup(t)

	resp := h.Client.Post("/api/v1/auth/signup", map[string]string{
		"email":    "test@example.com",
		"password": "password123",
	}, map[string]string{
		"X-Application-Id": "invalid_app_id",
	})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "Invalid application context", resp.JSONMap()["detail"])
}

func TestValidSignupAndTokenFormat(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "Test App", nil, "")
	clientID := appData["client_id"].(string)

	signupResp := h.Client.Post("/api/v1/auth/signup", map[string]string{
		"email":    "test2@example.com",
		"password": "password123",
	}, map[string]string{
		"X-Application-Id": clientID,
	})
	require.Equal(t, http.StatusOK, signupResp.StatusCode)

	loginResp := h.Client.Post("/api/v1/auth/login", map[string]string{
		"email":    "test2@example.com",
		"password": "password123",
	}, map[string]string{
		"X-Application-Id": clientID,
	})
	require.Equal(t, http.StatusOK, loginResp.StatusCode)
	tokenData := loginResp.JSONMap()
	assert.NotEmpty(t, tokenData["access_token"])
	assert.NotEmpty(t, tokenData["refresh_token"])

	accessToken := tokenData["access_token"].(string)
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(accessToken, claims)
	require.NoError(t, err)

	assert.Equal(t, h.Config.IdentityIssuer, claims["iss"])
	assert.Equal(t, "user", claims["type"])
	assert.Equal(t, "application_api", claims["aud"])
}

func TestServiceTokenAudience(t *testing.T) {
	h := setup(t)

	appData := createApplication(t, h, "Test App", map[string]interface{}{
		"oauth": map[string]interface{}{
			"allowed_grants": []string{"authorization_code", "client_credentials"},
		},
	}, "")
	clientID := appData["client_id"].(string)
	clientSecret := appData["client_secret"].(string)

	form := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"audience":      "custom_file_service",
	}
	v := authorizeParams("", nil)
	v.Del("scope")
	v.Del("state")
	v.Del("code_challenge")
	v.Del("code_challenge_method")
	v.Del("redirect_uri")
	v.Del("response_type")
	for k, val := range form {
		v.Set(k, val)
	}

	tokenResp := h.Client.PostForm("/api/v1/oauth/token", v, nil)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	tokenData := tokenResp.JSONMap()

	accessToken := tokenData["access_token"].(string)
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(accessToken, claims)
	require.NoError(t, err)

	assert.Equal(t, h.Config.IdentityIssuer, claims["iss"])
	assert.Equal(t, "service", claims["type"])
	assert.Equal(t, "custom_file_service", claims["aud"])
}
