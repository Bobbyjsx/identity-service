package services_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"identity-service/internal/config"
	"identity-service/internal/database"
	"identity-service/internal/services"
)

func TestKeyManagerSignAndVerify(t *testing.T) {
	os.Setenv("ENVIRONMENT", "testing")
	os.Setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:8080")
	cfg := config.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dbClient, err := database.NewFirestoreClient(ctx, cfg)
	if err != nil {
		t.Fatalf("Failed to init firestore: %v", err)
	}

	km := services.NewKeyManager(cfg)
	if err := km.Initialize(ctx, dbClient); err != nil {
		t.Fatalf("Failed to init key manager: %v", err)
	}

	claims := jwt.MapClaims{
		"iss": cfg.IdentityIssuer,
		"sub": "user-123",
		"aud": "application_api",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}

	tokenStr, err := km.SignJWT(claims)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	verifiedClaims, err := km.VerifyJWT(tokenStr, []string{"application_api"})
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}

	if verifiedClaims["sub"] != "user-123" {
		t.Errorf("Expected sub 'user-123', got %v", verifiedClaims["sub"])
	}

	jwks, err := km.GetJWKS(ctx)
	if err != nil {
		t.Fatalf("GetJWKS failed: %v", err)
	}
	keys := jwks["keys"].([]map[string]interface{})
	if len(keys) == 0 {
		t.Errorf("Expected at least one active key in JWKS")
	}
}
