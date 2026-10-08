package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/alexedwards/argon2id"
)

var (
	dangerousSchemes = map[string]bool{
		"javascript": true,
		"data":       true,
		"file":       true,
		"vbscript":   true,
		"blob":       true,
	}

	localhostHosts = map[string]bool{
		"localhost": true,
		"127.0.0.1": true,
		"[::1]":     true,
		"::1":       true,
	}

	colorRegex        = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	unsafeTextRegex   = regexp.MustCompile(`(?i)[<>]|javascript:`)
	pkceChallengeRegex = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)
)

func IsTestEnvironment() bool {
	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = os.Getenv("IDENTITY_ENVIRONMENT")
	}
	return env == "test" || env == "testing"
}

func HashPassword(password string) (string, error) {
	if IsTestEnvironment() {
		params := &argon2id.Params{
			Memory:      512,
			Iterations:  1,
			Parallelism: 1,
			SaltLength:  16,
			KeyLength:   32,
		}
		return argon2id.CreateHash(password, params)
	}
	return argon2id.CreateHash(password, argon2id.DefaultParams)
}

func VerifyPassword(password, hash string) bool {
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return false
	}
	return match
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func ValidateRedirectURI(uri string) error {
	if strings.TrimSpace(uri) == "" {
		return fmt.Errorf("redirect URI is required")
	}
	if len(uri) > 2048 {
		return fmt.Errorf("redirect URI is too long")
	}
	if strings.Contains(uri, "*") {
		return fmt.Errorf("wildcard redirect URIs are not supported")
	}

	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" {
		return fmt.Errorf("redirect URI must be an absolute URI")
	}

	scheme := strings.ToLower(parsed.Scheme)
	if dangerousSchemes[scheme] {
		return fmt.Errorf("redirect URI scheme '%s' is not allowed", scheme)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("redirect URIs must not contain a fragment")
	}

	if scheme == "http" || scheme == "https" {
		if parsed.Host == "" {
			return fmt.Errorf("redirect URI must include a host")
		}
		if scheme == "http" {
			host := strings.ToLower(parsed.Hostname())
			if !localhostHosts[host] {
				return fmt.Errorf("http redirect URIs are only allowed for localhost")
			}
		}
	}

	return nil
}

func RejectUnsafeText(s string) error {
	if unsafeTextRegex.MatchString(s) {
		return fmt.Errorf("contains characters that are not allowed")
	}
	return nil
}

func ValidateColor(color string) bool {
	return colorRegex.MatchString(color)
}

func ValidatePKCEChallenge(challenge string) error {
	if !pkceChallengeRegex.MatchString(challenge) {
		return fmt.Errorf("code_challenge must be a valid base64url-encoded value (43-128 chars)")
	}
	return nil
}

func PKCEVerifierToChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
