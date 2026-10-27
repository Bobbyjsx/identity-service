package core_test

import (
	"testing"

	"identity-service/internal/core"
)

func TestSecurityPasswordHashing(t *testing.T) {
	password := "my-secret-password-123"
	hash, err := core.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if !core.VerifyPassword(password, hash) {
		t.Errorf("Password verification failed for correct password")
	}

	if core.VerifyPassword("wrong-password", hash) {
		t.Errorf("Password verification succeeded for wrong password")
	}
}

func TestTokenHashing(t *testing.T) {
	token := "some-high-entropy-token"
	h1 := core.HashToken(token)
	h2 := core.HashToken(token)
	if h1 != h2 {
		t.Errorf("HashToken should be deterministic")
	}
	if len(h1) != 64 {
		t.Errorf("Expected 64-char sha256 hex string, got %d", len(h1))
	}
}

func TestRedirectURIValidation(t *testing.T) {
	valid := []string{
		"https://example.com/callback",
		"http://localhost:3000/callback",
		"http://127.0.0.1:8080/callback",
		"myapp://oauth/callback",
	}
	for _, u := range valid {
		if err := core.ValidateRedirectURI(u); err != nil {
			t.Errorf("Expected valid URI %s, got error: %v", u, err)
		}
	}

	invalid := []string{
		"",
		"javascript:alert(1)",
		"data:text/html,test",
		"file:///etc/passwd",
		"https://example.com/callback#fragment",
		"http://insecure.example.com/callback",
		"https://example.com/*",
	}
	for _, u := range invalid {
		if err := core.ValidateRedirectURI(u); err == nil {
			t.Errorf("Expected error for invalid URI %s, got nil", u)
		}
	}
}

func TestRejectUnsafeText(t *testing.T) {
	if err := core.RejectUnsafeText("Safe text"); err != nil {
		t.Errorf("Expected safe text to pass, got: %v", err)
	}
	if err := core.RejectUnsafeText("<script>alert(1)</script>"); err == nil {
		t.Errorf("Expected <script> to fail, got nil")
	}
	if err := core.RejectUnsafeText("javascript:void(0)"); err == nil {
		t.Errorf("Expected javascript: to fail, got nil")
	}
}

func TestPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := core.PKCEVerifierToChallenge(verifier)
	if challenge == "" {
		t.Errorf("PKCE challenge should not be empty")
	}
	if err := core.ValidatePKCEChallenge(challenge); err != nil {
		t.Errorf("Generated challenge failed validation: %v", err)
	}
}

func BenchmarkHashPassword_DefaultParams(b *testing.B) {
	b.ReportAllocs()
	password := "p@ssw0rd123!SecureEnough"
	for i := 0; i < b.N; i++ {
		_, err := core.HashPasswordWithParams(password, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPassword_DefaultParams(b *testing.B) {
	b.ReportAllocs()
	password := "p@ssw0rd123!SecureEnough"
	hash, err := core.HashPasswordWithParams(password, false)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !core.VerifyPassword(password, hash) {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkHashPassword_TestParams(b *testing.B) {
	b.ReportAllocs()
	password := "p@ssw0rd123!SecureEnough"
	for i := 0; i < b.N; i++ {
		_, err := core.HashPasswordWithParams(password, true)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPassword_TestParams(b *testing.B) {
	b.ReportAllocs()
	password := "p@ssw0rd123!SecureEnough"
	hash, err := core.HashPasswordWithParams(password, true)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !core.VerifyPassword(password, hash) {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkTokenHashing(b *testing.B) {
	b.ReportAllocs()
	token := "some-high-entropy-token-1234567890abcdef"
	for i := 0; i < b.N; i++ {
		_ = core.HashToken(token)
	}
}

func BenchmarkPKCE(b *testing.B) {
	b.ReportAllocs()
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	for i := 0; i < b.N; i++ {
		_ = core.PKCEVerifierToChallenge(verifier)
	}
}
