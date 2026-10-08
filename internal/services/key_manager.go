package services

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/api/iterator"
	"identity-service/internal/config"
)

type KeyManager struct {
	cfg           *config.Config
	db            *firestore.Client
	CurrentKeyID  string
	PrivateKey    ed25519.PrivateKey
	PublicKey     ed25519.PublicKey
	CollectionKey string
}

func NewKeyManager(cfg *config.Config) *KeyManager {
	return &KeyManager{
		cfg:           cfg,
		CollectionKey: "signing_keys",
	}
}

func (km *KeyManager) Initialize(ctx context.Context, db *firestore.Client) error {
	km.db = db
	return km.loadOrGenerateKey(ctx)
}

func (km *KeyManager) loadOrGenerateKey(ctx context.Context) error {
	keyPEM := km.cfg.PrivateKey
	if keyPEM != "" {
		keyPEM = strings.ReplaceAll(keyPEM, `\n`, "\n")
		block, _ := pem.Decode([]byte(keyPEM))
		if block == nil {
			return fmt.Errorf("failed to decode private key PEM block")
		}
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		edKey, ok := parsedKey.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("key is not an Ed25519 private key")
		}
		km.PrivateKey = edKey
		km.PublicKey = edKey.Public().(ed25519.PublicKey)
	} else {
		if km.cfg.Environment == "production" {
			return fmt.Errorf("private key not found in settings in production")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate ed25519 key: %w", err)
		}
		km.PrivateKey = priv
		km.PublicKey = pub
	}

	pubBytes := []byte(km.PublicKey)
	km.CurrentKeyID = fmt.Sprintf("key_%s", base64.RawURLEncoding.EncodeToString(pubBytes[:16]))

	docRef := km.db.Collection(km.CollectionKey).Doc(km.CurrentKeyID)
	doc, err := docRef.Get(ctx)
	if err != nil || !doc.Exists() {
		pubPKIX, err := x509.MarshalPKIXPublicKey(km.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to marshal public key: %w", err)
		}
		pubPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubPKIX,
		})
		_, err = docRef.Set(ctx, map[string]interface{}{
			"public_key": string(pubPEM),
			"status":     "active",
			"created_at": time.Now().UTC().Format(time.RFC3339),
		})
		if err != nil {
			return fmt.Errorf("failed to store public key in firestore: %w", err)
		}
	}

	return nil
}

func (km *KeyManager) SignJWT(claims jwt.MapClaims) (string, error) {
	if km.PrivateKey == nil {
		return "", fmt.Errorf("private key is not loaded")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = km.CurrentKeyID
	return token.SignedString(km.PrivateKey)
}

func (km *KeyManager) VerifyJWT(tokenString string, audience []string) (jwt.MapClaims, error) {
	if km.PublicKey == nil {
		return nil, fmt.Errorf("public key is not loaded")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(km.cfg.IdentityIssuer),
	)

	token, err := parser.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return km.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Verify audience
	if len(audience) > 0 {
		audClaim, ok := claims["aud"]
		if !ok {
			return nil, fmt.Errorf("missing audience claim")
		}
		matched := false
		switch v := audClaim.(type) {
		case string:
			for _, expected := range audience {
				if v == expected {
					matched = true
					break
				}
			}
		case []interface{}:
			for _, audItem := range v {
				if str, ok := audItem.(string); ok {
					for _, expected := range audience {
						if str == expected {
							matched = true
							break
						}
					}
				}
			}
		}
		if !matched {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	return claims, nil
}

func (km *KeyManager) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	iter := km.db.Collection(km.CollectionKey).Where("status", "==", "active").Documents(ctx)
	defer iter.Stop()

	var keys []map[string]interface{}
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		data := doc.Data()
		pubPEMStr, ok := data["public_key"].(string)
		if !ok {
			continue
		}

		block, _ := pem.Decode([]byte(pubPEMStr))
		if block == nil {
			continue
		}

		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}

		edPub, ok := parsed.(ed25519.PublicKey)
		if !ok {
			continue
		}

		rawBytes := []byte(edPub)
		xB64 := base64.RawURLEncoding.EncodeToString(rawBytes)

		keys = append(keys, map[string]interface{}{
			"kty": "OKP",
			"crv": "Ed25519",
			"kid": doc.Ref.ID,
			"x":   xB64,
		})
	}

	if keys == nil {
		keys = []map[string]interface{}{}
	}

	return map[string]interface{}{"keys": keys}, nil
}
