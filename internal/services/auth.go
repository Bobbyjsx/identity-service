package services

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"

	"identity-service/internal/config"
	"identity-service/internal/core"
	"identity-service/internal/models"
)

type AuthService struct {
	cfg        *config.Config
	db         *firestore.Client
	appService *ApplicationService
	keyManager *KeyManager
}

func NewAuthService(cfg *config.Config, db *firestore.Client, appService *ApplicationService, keyManager *KeyManager) *AuthService {
	return &AuthService{
		cfg:        cfg,
		db:         db,
		appService: appService,
		keyManager: keyManager,
	}
}

type UserCreateRequest struct {
	Email          string  `json:"email"`
	Password       string  `json:"password"`
	Username       *string `json:"username"`
	FirstName      *string `json:"first_name"`
	LastName       *string `json:"last_name"`
	TurnstileToken *string `json:"turnstile_token"`
}

func (s *AuthService) GetUserByEmail(ctx context.Context, appID, email string) (*models.User, error) {
	emailLower := strings.ToLower(strings.TrimSpace(email))
	iter := s.db.Collection("users").
		Where("app_id", "==", appID).
		Where("email", "==", emailLower).
		Limit(1).
		Documents(ctx)
	defer iter.Stop()

	doc, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var user models.User
	if err := doc.DataTo(&user); err != nil {
		return nil, err
	}
	user.ID = doc.Ref.ID
	return &user, nil
}

func (s *AuthService) GetUserByID(ctx context.Context, appID, userID string) (*models.User, error) {
	doc, err := s.db.Collection("users").Doc(userID).Get(ctx)
	if err != nil || !doc.Exists() {
		return nil, nil
	}
	var user models.User
	if err := doc.DataTo(&user); err != nil {
		return nil, err
	}
	user.ID = doc.Ref.ID
	if user.AppID != appID {
		return nil, nil
	}
	return &user, nil
}

func (s *AuthService) CreateUser(ctx context.Context, appID string, req UserCreateRequest) (*models.User, error) {
	app, err := s.appService.GetByClientID(ctx, appID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, core.NewHTTPError(http.StatusForbidden, "Invalid application context")
	}

	if !app.Authentication.AllowSignup {
		return nil, core.NewHTTPError(http.StatusForbidden, "Signup is disabled for this application")
	}

	emailLower := strings.ToLower(strings.TrimSpace(req.Email))
	existing, err := s.GetUserByEmail(ctx, appID, emailLower)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, core.NewHTTPError(http.StatusBadRequest, "User already exists")
	}

	hashed, err := core.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	userID := strings.ReplaceAll(uuid.New().String(), "-", "")
	now := time.Now().UTC().Format(time.RFC3339)

	user := models.User{
		ID:             userID,
		AppID:          appID,
		Email:          emailLower,
		HashedPassword: hashed,
		Username:       req.Username,
		FirstName:      req.FirstName,
		LastName:       req.LastName,
		Roles:          []string{},
		EmailVerified:  false,
		CreatedAt:      now,
	}

	if _, err := s.db.Collection("users").Doc(userID).Set(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to store user in firestore: %w", err)
	}

	return &user, nil
}

func (s *AuthService) AuthenticateUser(ctx context.Context, appID, email, password string) (*models.User, error) {
	app, err := s.appService.GetByClientID(ctx, appID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, core.NewHTTPError(http.StatusForbidden, "Invalid application context")
	}

	emailLower := strings.ToLower(strings.TrimSpace(email))
	user, err := s.GetUserByEmail(ctx, appID, emailLower)
	if err != nil {
		return nil, err
	}
	if user == nil || !core.VerifyPassword(password, user.HashedPassword) {
		return nil, core.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	return user, nil
}

func (s *AuthService) BuildUserAccessToken(user *models.User, appID string, scope *string) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(time.Duration(s.cfg.JWTExpirationMinutes) * time.Minute)

	roles := user.Roles
	if roles == nil {
		roles = []string{}
	}

	claims := jwt.MapClaims{
		"iss":    s.cfg.IdentityIssuer,
		"sub":    user.ID,
		"aud":    "application_api",
		"app_id": appID,
		"type":   "user",
		"roles":  roles,
		"iat":    now.Unix(),
		"exp":    exp.Unix(),
		"jti":    strings.ReplaceAll(uuid.New().String(), "-", ""),
	}
	if scope != nil && *scope != "" {
		claims["scope"] = *scope
	}

	return s.keyManager.SignJWT(claims)
}

func (s *AuthService) CreateRefreshToken(ctx context.Context, userID, appID string) (string, error) {
	now := time.Now().UTC()
	expiresAt := now.AddDate(0, 0, 7).Format(time.RFC3339)
	tokenStr := strings.ReplaceAll(uuid.New().String(), "-", "")
	refID := strings.ReplaceAll(uuid.New().String(), "-", "")

	rt := models.RefreshToken{
		ID:        refID,
		UserID:    userID,
		AppID:     appID,
		Token:     tokenStr,
		ExpiresAt: expiresAt,
	}

	if _, err := s.db.Collection("refresh_tokens").Doc(refID).Set(ctx, rt); err != nil {
		return "", err
	}

	return tokenStr, nil
}

func (s *AuthService) IssueUserTokens(ctx context.Context, user *models.User, appID string, scope *string) (*models.TokenResponse, error) {
	accessToken, err := s.BuildUserAccessToken(user, appID, scope)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.CreateRefreshToken(ctx, user.ID, appID)
	if err != nil {
		return nil, err
	}

	return &models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		ExpiresIn:    s.cfg.JWTExpirationMinutes * 60,
		RefreshToken: &refreshToken,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, appID string, req UserCreateRequest) (*models.TokenResponse, error) {
	user, err := s.AuthenticateUser(ctx, appID, req.Email, req.Password)
	if err != nil {
		return nil, err
	}
	return s.IssueUserTokens(ctx, user, appID, nil)
}

func (s *AuthService) GenerateServiceToken(appID, audience string) (*models.TokenResponse, error) {
	now := time.Now().UTC()
	exp := now.Add(time.Duration(s.cfg.JWTExpirationMinutes) * time.Minute)

	claims := jwt.MapClaims{
		"iss":    s.cfg.IdentityIssuer,
		"sub":    fmt.Sprintf("service:%s", appID),
		"aud":    audience,
		"app_id": appID,
		"type":   "service",
		"iat":    now.Unix(),
		"exp":    exp.Unix(),
		"jti":    strings.ReplaceAll(uuid.New().String(), "-", ""),
	}

	tokenStr, err := s.keyManager.SignJWT(claims)
	if err != nil {
		return nil, err
	}

	return &models.TokenResponse{
		AccessToken: tokenStr,
		TokenType:   "bearer",
		ExpiresIn:   s.cfg.JWTExpirationMinutes * 60,
	}, nil
}

func (s *AuthService) RefreshAccessToken(ctx context.Context, refreshTokenStr string) (*models.TokenResponse, error) {
	iter := s.db.Collection("refresh_tokens").Where("token", "==", refreshTokenStr).Limit(1).Documents(ctx)
	defer iter.Stop()

	doc, err := iter.Next()
	if err == iterator.Done {
		return nil, core.NewHTTPError(http.StatusUnauthorized, "Invalid refresh token")
	}
	if err != nil {
		return nil, err
	}

	var rt models.RefreshToken
	if err := doc.DataTo(&rt); err != nil {
		return nil, err
	}
	rt.ID = doc.Ref.ID

	expiresAt, err := time.Parse(time.RFC3339, rt.ExpiresAt)
	if err != nil || time.Now().UTC().After(expiresAt) {
		_, _ = doc.Ref.Delete(ctx)
		return nil, core.NewHTTPError(http.StatusUnauthorized, "Refresh token expired")
	}

	user, err := s.GetUserByID(ctx, rt.AppID, rt.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, core.NewHTTPError(http.StatusUnauthorized, "User no longer exists")
	}

	_, _ = doc.Ref.Delete(ctx)

	return s.IssueUserTokens(ctx, user, rt.AppID, nil)
}

func (s *AuthService) RevokeUserTokens(ctx context.Context, userID, appID string) error {
	iter := s.db.Collection("refresh_tokens").
		Where("user_id", "==", userID).
		Where("app_id", "==", appID).
		Documents(ctx)
	defer iter.Stop()

	batch := s.db.Batch()
	count := 0
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		batch.Delete(doc.Ref)
		count++
		if count >= 400 {
			if _, err := batch.Commit(ctx); err != nil {
				return err
			}
			batch = s.db.Batch()
			count = 0
		}
	}
	if count > 0 {
		_, err := batch.Commit(ctx)
		return err
	}
	return nil
}
