package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"identity-service/internal/config"
	"identity-service/internal/core"
)

const turnstileTestToken = "0xvalid-turnstile-token"

func callTurnstileWith(t *testing.T, token string, payload map[string]interface{}, expectedActions []string, isUnreachable bool) (*http.Request, error) {
	origURL := core.TurnstileSiteverifyURL
	defer func() {
		core.TurnstileSiteverifyURL = origURL
	}()

	var capturedReq *http.Request
	if isUnreachable {
		core.TurnstileSiteverifyURL = "http://127.0.0.1:59999/unreachable"
	} else {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			capturedReq = r.Clone(context.Background())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(payload)
		}))
		defer ts.Close()
		core.TurnstileSiteverifyURL = ts.URL
	}

	cfg := &config.Config{
		TurnstileEnabled:   true,
		TurnstileSecretKey: "secret",
		TurnstileHostnames: "localhost,127.0.0.1",
	}

	err := core.VerifyTurnstileToken(context.Background(), cfg, token, expectedActions, "127.0.0.1")
	return capturedReq, err
}

func validTurnstilePayload(overrides map[string]interface{}) map[string]interface{} {
	p := map[string]interface{}{
		"success":  true,
		"action":   "login",
		"hostname": "localhost",
	}
	for k, v := range overrides {
		p[k] = v
	}
	return p
}

func TestDisabledSkipsVerification(t *testing.T) {
	cfg := &config.Config{
		TurnstileEnabled: false,
	}
	err := core.VerifyTurnstileToken(context.Background(), cfg, "", []string{"login"}, "")
	assert.NoError(t, err)
}

func TestMissingTokenRejected(t *testing.T) {
	cfg := &config.Config{
		TurnstileEnabled: true,
	}
	err := core.VerifyTurnstileToken(context.Background(), cfg, "", []string{"login"}, "")
	require.Error(t, err)
	httpErr, ok := err.(*core.HTTPError)
	require.True(t, ok)
	assert.Equal(t, 400, httpErr.StatusCode)
	assert.Contains(t, httpErr.Detail, "Turnstile security token")
}

func TestTokenTooLongRejected(t *testing.T) {
	cfg := &config.Config{
		TurnstileEnabled: true,
	}
	longToken := strings.Repeat("x", 2049)
	err := core.VerifyTurnstileToken(context.Background(), cfg, longToken, []string{"login"}, "")
	require.Error(t, err)
	httpErr, ok := err.(*core.HTTPError)
	require.True(t, ok)
	assert.Equal(t, 400, httpErr.StatusCode)
}

func TestSiteverifyUnreachableReturns502(t *testing.T) {
	_, err := callTurnstileWith(t, turnstileTestToken, nil, []string{"login"}, true)
	require.Error(t, err)
	httpErr, ok := err.(*core.HTTPError)
	require.True(t, ok)
	assert.Equal(t, 502, httpErr.StatusCode)
}

func TestSuccessFalseRejected(t *testing.T) {
	_, err := callTurnstileWith(t, turnstileTestToken, map[string]interface{}{"success": false}, []string{"login"}, false)
	require.Error(t, err)
	httpErr, ok := err.(*core.HTTPError)
	require.True(t, ok)
	assert.Equal(t, 403, httpErr.StatusCode)
	assert.Equal(t, "Security verification failed.", httpErr.Detail)
}

func TestActionMismatchRejected(t *testing.T) {
	_, err := callTurnstileWith(t, turnstileTestToken, validTurnstilePayload(map[string]interface{}{"action": "signup"}), []string{"login"}, false)
	require.Error(t, err)
	httpErr, ok := err.(*core.HTTPError)
	require.True(t, ok)
	assert.Equal(t, 403, httpErr.StatusCode)
	assert.Equal(t, "Security verification action mismatch.", httpErr.Detail)
}

func TestMultipleActionsAccepted(t *testing.T) {
	for _, tokenAction := range []string{"verify-email", "resend-otp"} {
		_, err := callTurnstileWith(t, turnstileTestToken, validTurnstilePayload(map[string]interface{}{"action": tokenAction}), []string{"verify-email", "resend-otp"}, false)
		assert.NoError(t, err)
	}
}

func TestMultipleActionsRejectsOtherAction(t *testing.T) {
	_, err := callTurnstileWith(t, turnstileTestToken, validTurnstilePayload(map[string]interface{}{"action": "login"}), []string{"verify-email", "resend-otp"}, false)
	require.Error(t, err)
	httpErr, ok := err.(*core.HTTPError)
	require.True(t, ok)
	assert.Equal(t, 403, httpErr.StatusCode)
	assert.Equal(t, "Security verification action mismatch.", httpErr.Detail)
}

func TestHostnameMismatchRejected(t *testing.T) {
	_, err := callTurnstileWith(t, turnstileTestToken, validTurnstilePayload(map[string]interface{}{"hostname": "attacker.example.com"}), []string{"login"}, false)
	require.Error(t, err)
	httpErr, ok := err.(*core.HTTPError)
	require.True(t, ok)
	assert.Equal(t, 403, httpErr.StatusCode)
	assert.Equal(t, "Security verification hostname mismatch.", httpErr.Detail)
}

func TestValidTokenPasses(t *testing.T) {
	req, err := callTurnstileWith(t, turnstileTestToken, validTurnstilePayload(nil), []string{"login"}, false)
	assert.NoError(t, err)
	require.NotNil(t, req)
	assert.Equal(t, turnstileTestToken, req.FormValue("response"))
	assert.Equal(t, "127.0.0.1", req.FormValue("remoteip"))
}

func TestExtractClientIPPrefersCFConnectingIP(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("CF-Connecting-IP", "198.51.100.7")
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	req.RemoteAddr = "127.0.0.1:1234"
	assert.Equal(t, "198.51.100.7", core.ExtractClientIP(req))
}

func TestExtractClientIPPrefersXForwardedFor(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	req.RemoteAddr = "127.0.0.1:1234"
	assert.Equal(t, "203.0.113.9", core.ExtractClientIP(req))
}

func TestExtractClientIPFallsBackToPeer(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	assert.Equal(t, "127.0.0.1", core.ExtractClientIP(req))
}

func TestExtractClientIPReturnsNoneWithoutClient(t *testing.T) {
	req := &http.Request{Method: "POST", URL: &url.URL{Path: "/"}, Header: http.Header{}}
	assert.Equal(t, "", core.ExtractClientIP(req))
}
