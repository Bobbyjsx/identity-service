package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-service/internal/config"
	"identity-service/internal/core"
)

func TestTurnstileDisabledSkipsVerification(t *testing.T) {
	c := &config.Config{TurnstileEnabled: false}
	err := core.VerifyTurnstileToken(context.Background(), c, "", []string{"login"}, "127.0.0.1")
	if err != nil {
		t.Errorf("Expected nil error when Turnstile is disabled, got %v", err)
	}
}

func TestTurnstileMissingTokenRejectedWhenEnabled(t *testing.T) {
	c := &config.Config{TurnstileEnabled: true, TurnstileSecretKey: "secret"}
	err := core.VerifyTurnstileToken(context.Background(), c, "", []string{"login"}, "127.0.0.1")
	if err == nil {
		t.Errorf("Expected error for missing token when Turnstile is enabled")
	}
	if httpErr, ok := err.(*core.HTTPError); !ok || httpErr.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected HTTP 400 for missing token, got %v", err)
	}
}

func TestTurnstileTokenTooLongRejected(t *testing.T) {
	c := &config.Config{TurnstileEnabled: true, TurnstileSecretKey: "secret"}
	tooLong := strings.Repeat("x", 2049)
	err := core.VerifyTurnstileToken(context.Background(), c, tooLong, []string{"login"}, "127.0.0.1")
	if err == nil {
		t.Errorf("Expected error for oversized token")
	}
	if httpErr, ok := err.(*core.HTTPError); !ok || httpErr.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected HTTP 400 for oversized token, got %v", err)
	}
}

func TestExtractClientIP(t *testing.T) {
	// 1. CF-Connecting-IP takes highest priority
	req1 := httptest.NewRequest(http.MethodPost, "/", nil)
	req1.Header.Set("CF-Connecting-IP", "198.51.100.7")
	req1.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	req1.RemoteAddr = "127.0.0.1:1234"
	if ip := core.ExtractClientIP(req1); ip != "198.51.100.7" {
		t.Errorf("Expected 198.51.100.7, got %s", ip)
	}

	// 2. X-Forwarded-For is second priority
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	req2.RemoteAddr = "127.0.0.1:1234"
	if ip := core.ExtractClientIP(req2); ip != "203.0.113.9" {
		t.Errorf("Expected 203.0.113.9, got %s", ip)
	}

	// 3. Fallback to RemoteAddr (stripping port)
	req3 := httptest.NewRequest(http.MethodPost, "/", nil)
	req3.RemoteAddr = "192.168.1.50:5678"
	if ip := core.ExtractClientIP(req3); ip != "192.168.1.50" {
		t.Errorf("Expected 192.168.1.50, got %s", ip)
	}
}
