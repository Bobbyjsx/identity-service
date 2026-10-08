package core

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"identity-service/internal/config"
)

var TurnstileSiteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type TurnstileResponse struct {
	Success  bool     `json:"success"`
	Action   string   `json:"action"`
	Hostname string   `json:"hostname"`
	Errors   []string `json:"error-codes"`
}

func ExtractClientIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return strings.TrimSpace(cf)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			first := strings.TrimSpace(parts[0])
			if first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func VerifyTurnstileToken(ctx context.Context, cfg *config.Config, token string, expectedActions []string, clientIP string) error {
	if !cfg.TurnstileEnabled {
		return nil
	}

	if token == "" || len(token) > 2048 {
		return NewHTTPError(http.StatusBadRequest, "Invalid or missing Turnstile security token.")
	}

	data := url.Values{}
	data.Set("secret", cfg.TurnstileSecretKey)
	data.Set("response", token)
	if clientIP != "" {
		data.Set("remoteip", clientIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TurnstileSiteverifyURL, strings.NewReader(data.Encode()))
	if err != nil {
		return NewHTTPError(http.StatusBadGateway, "Turnstile verification service unreachable.")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return NewHTTPError(http.StatusBadGateway, "Turnstile verification service unreachable.")
	}
	defer resp.Body.Close()

	var result TurnstileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return NewHTTPError(http.StatusBadGateway, "Turnstile verification service unreachable.")
	}

	if !result.Success {
		return NewHTTPError(http.StatusForbidden, "Security verification failed.")
	}

	if len(expectedActions) > 0 {
		matched := false
		for _, action := range expectedActions {
			if result.Action == action {
				matched = true
				break
			}
		}
		if !matched {
			return NewHTTPError(http.StatusForbidden, "Security verification action mismatch.")
		}
	}

	if cfg.TurnstileHostnames != "" {
		hostnames := strings.Split(cfg.TurnstileHostnames, ",")
		matched := false
		for _, h := range hostnames {
			if strings.TrimSpace(h) != "" && strings.TrimSpace(h) == result.Hostname {
				matched = true
				break
			}
		}
		if !matched {
			return NewHTTPError(http.StatusForbidden, "Security verification hostname mismatch.")
		}
	}

	return nil
}
