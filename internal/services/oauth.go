package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
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

type OAuthService struct {
	cfg           *config.Config
	db            *firestore.Client
	appService    *ApplicationService
	authService   *AuthService
	keyManager    *KeyManager
	notifications NotificationService
}

func NewOAuthService(
	cfg *config.Config,
	db *firestore.Client,
	appService *ApplicationService,
	authService *AuthService,
	keyManager *KeyManager,
	notifications NotificationService,
) *OAuthService {
	return &OAuthService{
		cfg:           cfg,
		db:            db,
		appService:    appService,
		authService:   authService,
		keyManager:    keyManager,
		notifications: notifications,
	}
}

type AuthorizationRequest struct {
	ClientID            string  `json:"client_id"`
	RedirectURI         string  `json:"redirect_uri"`
	ResponseType        string  `json:"response_type"`
	Scope               *string `json:"scope"`
	State               *string `json:"state"`
	CodeChallenge       string  `json:"code_challenge"`
	CodeChallengeMethod string  `json:"code_challenge_method"`
	Nonce               *string `json:"nonce"`
}

type SessionLoginRequest struct {
	Email          string  `json:"email"`
	Password       string  `json:"password"`
	TurnstileToken *string `json:"turnstile_token"`
}

type SessionSignupRequest struct {
	Email          string  `json:"email"`
	Password       string  `json:"password"`
	Username       *string `json:"username"`
	FirstName      *string `json:"first_name"`
	LastName       *string `json:"last_name"`
	TurnstileToken *string `json:"turnstile_token"`
}

func GenerateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return fmt.Sprintf("tx_%s", base64.RawURLEncoding.EncodeToString(b))
}

func GenerateAuthorizationCode() string {
	b := make([]byte, 48)
	_, _ = rand.Read(b)
	return fmt.Sprintf("code_%s", base64.RawURLEncoding.EncodeToString(b))
}

func GenerateVerificationOTP() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

func GeneratePasswordResetToken() string {
	return fmt.Sprintf("pr_%s%s", strings.ReplaceAll(uuid.New().String(), "-", ""), strings.ReplaceAll(uuid.New().String(), "-", ""))
}

func (s *OAuthService) ResolveClient(ctx context.Context, clientID string) (*models.Application, error) {
	app, err := s.appService.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, core.NewOAuthError("invalid_client", "Unknown client_id", http.StatusBadRequest)
	}
	if app.Status != "active" {
		return nil, core.NewOAuthError("invalid_client", "Application is not active", http.StatusBadRequest)
	}
	return app, nil
}

func (s *OAuthService) ValidateRedirect(app *models.Application, redirectURI string) error {
	for _, registered := range app.OAuth.RedirectURIs {
		if registered == redirectURI {
			return nil
		}
	}
	return core.NewOAuthError("invalid_redirect_uri", "The redirect URI is not registered for this application", http.StatusBadRequest)
}

func (s *OAuthService) ValidateResponseType(responseType string) error {
	if responseType != "code" {
		return core.NewOAuthError("unsupported_response_type", "Only the authorization code response type is supported", http.StatusBadRequest)
	}
	return nil
}

func (s *OAuthService) ValidateScopes(app *models.Application, scopes []string) error {
	allowed := make(map[string]bool)
	for _, sc := range app.OAuth.AllowedScopes {
		if KnownOAuthScopes[sc] {
			allowed[sc] = true
		}
	}
	var invalid []string
	for _, sc := range scopes {
		if !allowed[sc] {
			invalid = append(invalid, sc)
		}
	}
	if len(invalid) > 0 {
		return core.NewOAuthError("invalid_scope", fmt.Sprintf("Requested scopes not allowed for this application: %s", strings.Join(invalid, ", ")), http.StatusBadRequest)
	}
	return nil
}

func (s *OAuthService) ValidateGrantAllowed(app *models.Application, grant string) error {
	for _, g := range app.OAuth.AllowedGrants {
		if g == grant {
			return nil
		}
	}
	return core.NewOAuthError("unauthorized_client", fmt.Sprintf("The %s grant is not enabled for this application", grant), http.StatusBadRequest)
}

func (s *OAuthService) BuildIdentityUIRedirect(sessionID string) string {
	return fmt.Sprintf("%s/auth/%s/login", s.cfg.IdentityUIBaseURL, sessionID)
}

func (s *OAuthService) BuildErrorRedirect(redirectURI string, state *string, errType, errDesc string) string {
	params := url.Values{}
	params.Set("error", errType)
	params.Set("error_description", errDesc)
	if state != nil {
		params.Set("state", *state)
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%s%s", redirectURI, sep, params.Encode())
}

func (s *OAuthService) CreateSession(ctx context.Context, req AuthorizationRequest) (*models.AuthSession, error) {
	app, err := s.ResolveClient(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	if err := s.ValidateRedirect(app, req.RedirectURI); err != nil {
		return nil, err
	}
	if err := s.ValidateResponseType(req.ResponseType); err != nil {
		return nil, err
	}
	if err := s.ValidateGrantAllowed(app, "authorization_code"); err != nil {
		return nil, err
	}
	if req.CodeChallengeMethod != "S256" {
		return nil, core.NewOAuthError("invalid_request", "only the S256 code challenge method is supported", http.StatusBadRequest)
	}
	if err := core.ValidatePKCEChallenge(req.CodeChallenge); err != nil {
		return nil, core.NewOAuthError("invalid_request", err.Error(), http.StatusBadRequest)
	}

	var scopes []string
	if req.Scope != nil && *req.Scope != "" {
		scopes = strings.Fields(*req.Scope)
	}
	if err := s.ValidateScopes(app, scopes); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(s.cfg.AuthSessionExpirationMinutes) * time.Minute).Format(time.RFC3339)
	sessionID := GenerateSessionID()

	tx := models.AuthSession{
		ID:                  sessionID,
		ApplicationID:       app.ID,
		ClientID:            app.ClientID,
		RedirectURI:         req.RedirectURI,
		ResponseType:        req.ResponseType,
		Scopes:              scopes,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		Status:              "pending",
		ExpiresAt:           expiresAt,
	}

	if _, err := s.db.Collection("auth_sessions").Doc(sessionID).Set(ctx, tx); err != nil {
		return nil, fmt.Errorf("failed to save auth session: %w", err)
	}

	return &tx, nil
}

func (s *OAuthService) EffectiveStatus(tx *models.AuthSession) string {
	if tx.Status == "cancelled" || tx.Status == "completed" {
		return tx.Status
	}
	t, err := time.Parse(time.RFC3339, tx.ExpiresAt)
	if err != nil || time.Now().UTC().After(t) {
		return "expired"
	}
	if tx.Status == "" {
		return "pending"
	}
	return tx.Status
}

func (s *OAuthService) GetSession(ctx context.Context, sessionID string) (*models.AuthSession, error) {
	doc, err := s.db.Collection("auth_sessions").Doc(sessionID).Get(ctx)
	if err != nil || !doc.Exists() {
		return nil, nil
	}
	var tx models.AuthSession
	if err := doc.DataTo(&tx); err != nil {
		return nil, err
	}
	tx.ID = doc.Ref.ID
	return &tx, nil
}

func (s *OAuthService) LoadSession(ctx context.Context, sessionID string) (*models.AuthSessionResponse, error) {
	tx, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, core.NewOAuthError("invalid_session", "Session not found", http.StatusNotFound)
	}

	effStatus := s.EffectiveStatus(tx)
	if effStatus == "expired" && tx.Status != "expired" {
		_, _ = s.db.Collection("auth_sessions").Doc(tx.ID).Update(ctx, []firestore.Update{
			{Path: "status", Value: "expired"},
		})
	}

	app, err := s.appService.GetByID(ctx, tx.ApplicationID)
	if err != nil || app == nil {
		return nil, core.NewOAuthError("invalid_application", "Application not found", http.StatusNotFound)
	}

	appMap := map[string]interface{}{
		"name":                       app.Name,
		"description":                app.Description,
		"logo_url":                   app.Branding.LogoURL,
		"logo_with_text":             app.Branding.LogoWithText,
		"primary_color":              app.Branding.PrimaryColor,
		"secondary_color":            app.Branding.SecondaryColor,
		"themes":                     app.Branding.Themes,
		"allow_signup":               app.Authentication.AllowSignup,
		"allow_password_login":       app.Authentication.AllowPasswordLogin,
		"require_email_verification": app.Authentication.RequireEmailVerification,
	}

	var redirectURL *string
	if effStatus == "expired" {
		urlStr := s.BuildErrorRedirect(tx.RedirectURI, tx.State, "session_expired", "The authorization session has expired")
		redirectURL = &urlStr
	} else if effStatus == "cancelled" {
		urlStr := s.BuildErrorRedirect(tx.RedirectURI, tx.State, "access_denied", "The authorization request was cancelled")
		redirectURL = &urlStr
	}

	scopes := tx.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	return &models.AuthSessionResponse{
		SessionID:   tx.ID,
		Status:      effStatus,
		Application: appMap,
		Scopes:      scopes,
		RedirectURL: redirectURL,
	}, nil
}

func (s *OAuthService) CancelSession(ctx context.Context, sessionID string) (map[string]interface{}, error) {
	tx, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, core.NewOAuthError("invalid_session", "Session not found", http.StatusNotFound)
	}

	effStatus := s.EffectiveStatus(tx)
	if effStatus == "expired" {
		return nil, core.NewOAuthError("session_expired", "Session has expired")
	}
	if effStatus == "completed" {
		return nil, core.NewOAuthError("session_completed", "Session is already completed")
	}
	if effStatus == "cancelled" {
		return nil, core.NewOAuthError("session_cancelled", "Session is already cancelled")
	}
	if effStatus != "pending" && effStatus != "authenticated" {
		return nil, core.NewOAuthError("invalid_session_state", fmt.Sprintf("Session is already %s", effStatus))
	}

	_, err = s.db.Collection("auth_sessions").Doc(sessionID).Update(ctx, []firestore.Update{
		{Path: "status", Value: "cancelled"},
	})
	if err != nil {
		return nil, err
	}

	redirectURL := s.BuildErrorRedirect(tx.RedirectURI, tx.State, "access_denied", "The user cancelled the authorization request")
	return map[string]interface{}{
		"session_id":   sessionID,
		"status":       "cancelled",
		"redirect_url": redirectURL,
	}, nil
}

func (s *OAuthService) loadSessionForOperation(ctx context.Context, sessionID string, allowedStatuses map[string]bool) (*models.AuthSession, *models.Application, error) {
	tx, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return nil, nil, err
	}
	if tx == nil {
		return nil, nil, core.NewOAuthError("invalid_session", "Session not found", http.StatusNotFound)
	}

	status := s.EffectiveStatus(tx)
	if status == "expired" {
		return nil, nil, core.NewOAuthError("session_expired", "Authorization session has expired")
	}
	if status == "completed" {
		return nil, nil, core.NewOAuthError("session_completed", "Session is already completed")
	}
	if status == "cancelled" {
		return nil, nil, core.NewOAuthError("session_cancelled", "Session is already cancelled")
	}
	if status == "authenticated" && !allowedStatuses["authenticated"] {
		return nil, nil, core.NewOAuthError("email_verification_required", "The user must verify their email before continuing")
	}
	if !allowedStatuses[status] {
		return nil, nil, core.NewOAuthError("invalid_session_state", "Operation not allowed in the current session state")
	}

	app, err := s.appService.GetByID(ctx, tx.ApplicationID)
	if err != nil || app == nil || app.Status != "active" {
		return nil, nil, core.NewOAuthError("invalid_application", "Application is not active")
	}

	return tx, app, nil
}

func (s *OAuthService) Login(ctx context.Context, sessionID, email, password string) (map[string]interface{}, error) {
	tx, app, err := s.loadSessionForOperation(ctx, sessionID, map[string]bool{"pending": true})
	if err != nil {
		return nil, err
	}

	if !app.Authentication.AllowPasswordLogin {
		return nil, core.NewOAuthError("password_login_disabled", "Password login is disabled for this application")
	}

	user, err := s.authService.AuthenticateUser(ctx, tx.ClientID, email, password)
	if err != nil {
		return nil, core.NewOAuthError("invalid_credentials", "Invalid email or password", http.StatusUnauthorized)
	}

	return s.completeAuthentication(ctx, tx, app, user)
}

func (s *OAuthService) Signup(ctx context.Context, sessionID string, req SessionSignupRequest) (map[string]interface{}, error) {
	tx, _, err := s.loadSessionForOperation(ctx, sessionID, map[string]bool{"pending": true})
	if err != nil {
		return nil, err
	}

	userCreate := UserCreateRequest{
		Email:          req.Email,
		Password:       req.Password,
		Username:       req.Username,
		FirstName:      req.FirstName,
		LastName:       req.LastName,
		TurnstileToken: req.TurnstileToken,
	}

	user, err := s.authService.CreateUser(ctx, tx.ClientID, userCreate)
	if err != nil {
		if httpErr, ok := err.(*core.HTTPError); ok {
			errType := "signup_disabled"
			if httpErr.StatusCode == http.StatusBadRequest {
				errType = "user_already_exists"
			}
			return nil, core.NewOAuthError(errType, httpErr.Detail, httpErr.StatusCode)
		}
		return nil, err
	}

	app, _ := s.appService.GetByID(ctx, tx.ApplicationID)
	return s.completeAuthentication(ctx, tx, app, user)
}

func (s *OAuthService) completeAuthentication(ctx context.Context, tx *models.AuthSession, app *models.Application, user *models.User) (map[string]interface{}, error) {
	if app.Authentication.RequireEmailVerification && !user.EmailVerified {
		// Atomic claim from pending -> authenticated
		sessionRef := s.db.Collection("auth_sessions").Doc(tx.ID)
		err := s.db.RunTransaction(ctx, func(ctx context.Context, firestoreTx *firestore.Transaction) error {
			doc, err := firestoreTx.Get(sessionRef)
			if err != nil {
				return err
			}
			var current models.AuthSession
			if err := doc.DataTo(&current); err != nil {
				return err
			}
			if current.Status != "pending" {
				return core.NewOAuthError("invalid_session_state", "Session is already in progress")
			}
			return firestoreTx.Update(sessionRef, []firestore.Update{
				{Path: "status", Value: "authenticated"},
				{Path: "user_id", Value: user.ID},
			})
		})
		if err != nil {
			return nil, err
		}

		tx.UserID = &user.ID
		if err := s.issueVerificationToken(ctx, tx, app, user); err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"redirect_url":                nil,
			"email_verification_required": true,
		}, nil
	}

	rawCode, err := s.IssueAuthorizationCode(ctx, tx, app, user, "pending")
	if err != nil {
		return nil, err
	}

	callbackURL := s.buildCallbackURL(tx, rawCode)
	return map[string]interface{}{
		"redirect_url":                callbackURL,
		"email_verification_required": false,
	}, nil
}

func (s *OAuthService) issueVerificationToken(ctx context.Context, tx *models.AuthSession, app *models.Application, user *models.User) error {
	rawToken := GenerateVerificationOTP()
	tokenHash := core.HashToken(rawToken)
	tokenID := fmt.Sprintf("evt_%s", strings.ReplaceAll(uuid.New().String(), "-", "")[:16])
	now := time.Now().UTC()
	expiresAt := now.Add(30 * time.Minute).Format(time.RFC3339)

	token := models.EmailVerificationToken{
		ID:          tokenID,
		TokenHash:   tokenHash,
		AppID:       tx.ClientID,
		UserID:      user.ID,
		Status:      "active",
		Attempts:    0,
		MaxAttempts: 5,
		CreatedAt:   now.Format(time.RFC3339),
		ExpiresAt:   expiresAt,
	}

	if _, err := s.db.Collection("email_verification_tokens").Doc(tokenID).Set(ctx, token); err != nil {
		return err
	}

	return s.notifications.SendVerificationEmail(ctx, user.Email, rawToken, app.Name, tx.ClientID, user.FirstName)
}

func (s *OAuthService) buildCallbackURL(tx *models.AuthSession, rawCode string) string {
	params := url.Values{}
	params.Set("code", rawCode)
	if tx.State != nil {
		params.Set("state", *tx.State)
	}
	sep := "?"
	if strings.Contains(tx.RedirectURI, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%s%s", tx.RedirectURI, sep, params.Encode())
}

func (s *OAuthService) IssueAuthorizationCode(ctx context.Context, tx *models.AuthSession, app *models.Application, user *models.User, expectedStatus string) (string, error) {
	rawCode := GenerateAuthorizationCode()
	codeHash := core.HashToken(rawCode)
	codeID := strings.ReplaceAll(uuid.New().String(), "-", "")
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(s.cfg.OAuthAuthorizationCodeExpirationMinutes) * time.Minute).Format(time.RFC3339)

	codeDoc := models.AuthorizationCode{
		ID:                  codeID,
		CodeHash:            codeHash,
		SessionID:           tx.ID,
		ApplicationID:       tx.ApplicationID,
		ClientID:            tx.ClientID,
		UserID:              user.ID,
		RedirectURI:         tx.RedirectURI,
		Scopes:              tx.Scopes,
		CodeChallenge:       tx.CodeChallenge,
		CodeChallengeMethod: tx.CodeChallengeMethod,
		Nonce:               tx.Nonce,
		Status:              "active",
		CreatedAt:           now.Format(time.RFC3339),
		ExpiresAt:           expiresAt,
	}

	sessionRef := s.db.Collection("auth_sessions").Doc(tx.ID)
	codeRef := s.db.Collection("authorization_codes").Doc(codeID)

	err := s.db.RunTransaction(ctx, func(ctx context.Context, firestoreTx *firestore.Transaction) error {
		snap, err := firestoreTx.Get(sessionRef)
		if err != nil {
			return err
		}
		var current models.AuthSession
		if err := snap.DataTo(&current); err != nil {
			return err
		}
		effStatus := s.EffectiveStatus(&current)
		if effStatus != expectedStatus {
			if effStatus == "completed" {
				return core.NewOAuthError("session_completed", "Session is already completed")
			}
			return core.NewOAuthError("invalid_session_state", fmt.Sprintf("Session is %s", effStatus))
		}

		completedAt := now.Format(time.RFC3339)
		if err := firestoreTx.Update(sessionRef, []firestore.Update{
			{Path: "status", Value: "completed"},
			{Path: "user_id", Value: user.ID},
			{Path: "completed_at", Value: completedAt},
		}); err != nil {
			return err
		}

		return firestoreTx.Set(codeRef, codeDoc)
	})
	if err != nil {
		return "", err
	}

	return rawCode, nil
}

func (s *OAuthService) VerifyEmail(ctx context.Context, sessionID, verificationToken string) (map[string]interface{}, error) {
	tx, app, err := s.loadSessionForOperation(ctx, sessionID, map[string]bool{"pending": true, "authenticated": true})
	if err != nil {
		return nil, err
	}
	if tx.UserID == nil || *tx.UserID == "" {
		return nil, core.NewOAuthError("invalid_session_state", "No user is associated with this session")
	}

	tokenHash := core.HashToken(verificationToken)
	iter := s.db.Collection("email_verification_tokens").Where("token_hash", "==", tokenHash).Limit(1).Documents(ctx)
	defer iter.Stop()

	doc, err := iter.Next()
	var token *models.EmailVerificationToken
	if err == nil {
		var tok models.EmailVerificationToken
		if err := doc.DataTo(&tok); err == nil {
			tok.ID = doc.Ref.ID
			token = &tok
		}
	}

	boundCorrectly := token != nil && token.AppID == tx.ClientID && token.UserID == *tx.UserID
	if !boundCorrectly {
		sessionRef := s.db.Collection("auth_sessions").Doc(sessionID)
		var attempts int
		_ = s.db.RunTransaction(ctx, func(ctx context.Context, ftx *firestore.Transaction) error {
			snap, err := ftx.Get(sessionRef)
			if err != nil {
				return err
			}
			var current models.AuthSession
			if err := snap.DataTo(&current); err != nil {
				return err
			}
			attempts = current.OTPAttempts + 1
			newStatus := current.Status
			if attempts >= 5 {
				newStatus = "cancelled"
			}
			return ftx.Update(sessionRef, []firestore.Update{
				{Path: "otp_attempts", Value: attempts},
				{Path: "status", Value: newStatus},
			})
		})
		if attempts >= 5 {
			return nil, core.NewOAuthError("otp_attempts_exceeded", "Too many incorrect attempts. Please start a new login.")
		}
		return nil, core.NewOAuthError("invalid_verification_token", "Verification token is invalid")
	}

	tExp, err := time.Parse(time.RFC3339, token.ExpiresAt)
	if err != nil || time.Now().UTC().After(tExp) {
		return nil, core.NewOAuthError("verification_token_expired", "Verification token has expired")
	}
	if token.Status != "active" {
		return nil, core.NewOAuthError("invalid_verification_token", "Verification token has already been used")
	}

	user, err := s.authService.GetUserByID(ctx, tx.ClientID, *tx.UserID)
	if err != nil || user == nil {
		return nil, core.NewOAuthError("invalid_session_state", "User no longer exists")
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	_, _ = s.db.Collection("users").Doc(user.ID).Update(ctx, []firestore.Update{
		{Path: "email_verified", Value: true},
	})
	_, _ = s.db.Collection("email_verification_tokens").Doc(token.ID).Update(ctx, []firestore.Update{
		{Path: "status", Value: "used"},
		{Path: "used_at", Value: nowStr},
	})

	_ = s.notifications.SendWelcomeEmail(ctx, user.Email, app.Name, tx.ClientID, user.FirstName)

	rawCode, err := s.IssueAuthorizationCode(ctx, tx, app, user, "authenticated")
	if err != nil {
		return nil, err
	}

	callbackURL := s.buildCallbackURL(tx, rawCode)
	return map[string]interface{}{"redirect_url": callbackURL}, nil
}

func (s *OAuthService) ResendOTP(ctx context.Context, sessionID string) (map[string]interface{}, error) {
	tx, app, err := s.loadSessionForOperation(ctx, sessionID, map[string]bool{"authenticated": true})
	if err != nil {
		return nil, err
	}
	if tx.UserID == nil || *tx.UserID == "" {
		return nil, core.NewOAuthError("invalid_session_state", "No user is associated with this session")
	}

	user, err := s.authService.GetUserByID(ctx, tx.ClientID, *tx.UserID)
	if err != nil || user == nil {
		return nil, core.NewOAuthError("invalid_session_state", "User no longer exists")
	}

	// Invalidate any active token
	iter := s.db.Collection("email_verification_tokens").
		Where("user_id", "==", *tx.UserID).
		Where("app_id", "==", tx.ClientID).
		Where("status", "==", "active").
		Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		_, _ = doc.Ref.Update(ctx, []firestore.Update{{Path: "status", Value: "used"}})
	}
	iter.Stop()

	// Reset attempts
	_, _ = s.db.Collection("auth_sessions").Doc(sessionID).Update(ctx, []firestore.Update{
		{Path: "otp_attempts", Value: 0},
	})

	if err := s.issueVerificationToken(ctx, tx, app, user); err != nil {
		return nil, err
	}

	return map[string]interface{}{"detail": "A new verification code has been sent to your email."}, nil
}

func (s *OAuthService) ForgotPassword(ctx context.Context, sessionID, email string) (map[string]interface{}, error) {
	tx, app, err := s.loadSessionForOperation(ctx, sessionID, map[string]bool{"pending": true})
	if err != nil {
		return nil, err
	}

	user, _ := s.authService.GetUserByEmail(ctx, tx.ClientID, email)
	if user != nil {
		rawToken := GeneratePasswordResetToken()
		tokenHash := core.HashToken(rawToken)
		tokenID := fmt.Sprintf("prt_%s", strings.ReplaceAll(uuid.New().String(), "-", "")[:16])
		now := time.Now().UTC()
		expiresAt := now.Add(time.Duration(s.cfg.PasswordResetTokenExpirationMinutes) * time.Minute).Format(time.RFC3339)

		resetDoc := models.PasswordResetToken{
			ID:        tokenID,
			TokenHash: tokenHash,
			AppID:     tx.ClientID,
			UserID:    user.ID,
			Status:    "active",
			CreatedAt: now.Format(time.RFC3339),
			ExpiresAt: expiresAt,
		}

		_, _ = s.db.Collection("password_reset_tokens").Doc(tokenID).Set(ctx, resetDoc)
		resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.cfg.IdentityUIBaseURL, rawToken)
		_ = s.notifications.SendPasswordResetEmail(ctx, user.Email, resetURL, app.Name, app.ClientID, user.FirstName)
	}

	return map[string]interface{}{"detail": "If the email has an account, a password reset link has been sent."}, nil
}

func (s *OAuthService) loadResetToken(ctx context.Context, resetToken string) (*models.PasswordResetToken, *models.User, error) {
	tokenHash := core.HashToken(resetToken)
	iter := s.db.Collection("password_reset_tokens").Where("token_hash", "==", tokenHash).Limit(1).Documents(ctx)
	defer iter.Stop()

	doc, err := iter.Next()
	if err == iterator.Done {
		return nil, nil, core.NewOAuthError("invalid_reset_token", "Password reset token is invalid")
	}
	if err != nil {
		return nil, nil, err
	}

	var tok models.PasswordResetToken
	if err := doc.DataTo(&tok); err != nil {
		return nil, nil, err
	}
	tok.ID = doc.Ref.ID

	tExp, err := time.Parse(time.RFC3339, tok.ExpiresAt)
	if err != nil || time.Now().UTC().After(tExp) {
		return nil, nil, core.NewOAuthError("reset_token_expired", "Password reset token has expired")
	}
	if tok.Status != "active" {
		return nil, nil, core.NewOAuthError("invalid_reset_token", "Password reset token has already been used")
	}

	user, err := s.authService.GetUserByID(ctx, tok.AppID, tok.UserID)
	if err != nil || user == nil {
		return nil, nil, core.NewOAuthError("invalid_reset_token", "Password reset token is invalid")
	}

	return &tok, user, nil
}

func (s *OAuthService) applyPasswordReset(ctx context.Context, tok *models.PasswordResetToken, user *models.User, newPassword string) error {
	hashed, err := core.HashPassword(newPassword)
	if err != nil {
		return err
	}
	nowStr := time.Now().UTC().Format(time.RFC3339)
	_, err = s.db.Collection("users").Doc(user.ID).Update(ctx, []firestore.Update{
		{Path: "hashed_password", Value: hashed},
	})
	if err != nil {
		return err
	}

	_, _ = s.db.Collection("password_reset_tokens").Doc(tok.ID).Update(ctx, []firestore.Update{
		{Path: "status", Value: "used"},
		{Path: "used_at", Value: nowStr},
	})

	_ = s.authService.RevokeUserTokens(ctx, user.ID, tok.AppID)
	return nil
}

func (s *OAuthService) ResetPassword(ctx context.Context, sessionID, resetToken, newPassword string) (map[string]interface{}, error) {
	tx, _, err := s.loadSessionForOperation(ctx, sessionID, map[string]bool{"pending": true})
	if err != nil {
		return nil, err
	}
	tok, user, err := s.loadResetToken(ctx, resetToken)
	if err != nil {
		return nil, err
	}
	if tok.AppID != tx.ClientID {
		return nil, core.NewOAuthError("invalid_reset_token", "Password reset token does not match this session")
	}
	if err := s.applyPasswordReset(ctx, tok, user, newPassword); err != nil {
		return nil, err
	}
	return map[string]interface{}{"detail": "Password has been reset. You can now sign in."}, nil
}

func (s *OAuthService) ResetPasswordStandalone(ctx context.Context, resetToken, newPassword string) (map[string]interface{}, error) {
	tok, user, err := s.loadResetToken(ctx, resetToken)
	if err != nil {
		return nil, err
	}
	if err := s.applyPasswordReset(ctx, tok, user, newPassword); err != nil {
		return nil, err
	}
	return map[string]interface{}{"detail": "Password has been reset. You can now sign in."}, nil
}

func (s *OAuthService) ExchangeResetTokenForSession(ctx context.Context, resetToken string) (map[string]interface{}, error) {
	tok, _, err := s.loadResetToken(ctx, resetToken)
	if err != nil {
		return nil, err
	}
	app, err := s.ResolveClient(ctx, tok.AppID)
	if err != nil {
		return nil, err
	}

	redirectURI := "http://localhost"
	if len(app.OAuth.RedirectURIs) > 0 {
		redirectURI = app.OAuth.RedirectURIs[0]
	}

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(s.cfg.AuthSessionExpirationMinutes) * time.Minute).Format(time.RFC3339)
	sessionID := GenerateSessionID()

	tx := models.AuthSession{
		ID:                  sessionID,
		ApplicationID:       app.ID,
		ClientID:            app.ClientID,
		RedirectURI:         redirectURI,
		ResponseType:        "code",
		Scopes:              []string{},
		State:               nil,
		CodeChallenge:       "dummy_challenge_for_reset_flow_only_not_for_pkce",
		CodeChallengeMethod: "S256",
		Status:              "pending",
		UserID:              &tok.UserID,
		ExpiresAt:           expiresAt,
	}

	if _, err := s.db.Collection("auth_sessions").Doc(sessionID).Set(ctx, tx); err != nil {
		return nil, err
	}

	return map[string]interface{}{"session_id": tx.ID}, nil
}

func (s *OAuthService) ExchangeAuthorizationCode(
	ctx context.Context,
	code, clientID, redirectURI, codeVerifier string,
	clientSecret *string,
) (*models.TokenResponse, error) {
	codeHash := core.HashToken(code)
	iter := s.db.Collection("authorization_codes").Where("code_hash", "==", codeHash).Limit(1).Documents(ctx)
	defer iter.Stop()

	doc, err := iter.Next()
	if err == iterator.Done {
		return nil, core.NewOAuthError("invalid_grant", "Invalid authorization code")
	}
	if err != nil {
		return nil, core.NewOAuthError("server_error", "An unexpected error occurred", http.StatusInternalServerError)
	}

	var codeDoc models.AuthorizationCode
	if err := doc.DataTo(&codeDoc); err != nil {
		return nil, core.NewOAuthError("server_error", "An unexpected error occurred", http.StatusInternalServerError)
	}
	codeDoc.ID = doc.Ref.ID

	tExp, err := time.Parse(time.RFC3339, codeDoc.ExpiresAt)
	if err != nil || time.Now().UTC().After(tExp) {
		return nil, core.NewOAuthError("invalid_grant", "Authorization code has expired")
	}
	if codeDoc.Status != "active" {
		return nil, core.NewOAuthError("invalid_grant", "Authorization code has already been used")
	}
	if codeDoc.ClientID != clientID {
		return nil, core.NewOAuthError("invalid_grant", "Authorization code was issued for a different client")
	}
	if codeDoc.RedirectURI != redirectURI {
		return nil, core.NewOAuthError("invalid_grant", "Redirect URI does not match the authorization request")
	}

	app, err := s.appService.GetByID(ctx, codeDoc.ApplicationID)
	if err != nil || app == nil || app.Status != "active" {
		return nil, core.NewOAuthError("invalid_grant", "Application is not active")
	}
	if codeDoc.ClientID != app.ClientID {
		return nil, core.NewOAuthError("invalid_grant", "Authorization code does not match the application")
	}

	if err := s.ValidateGrantAllowed(app, "authorization_code"); err != nil {
		return nil, err
	}

	if app.ClientType == "confidential" && (clientSecret == nil || *clientSecret == "") {
		return nil, core.NewOAuthError("invalid_client", "client_secret is required for confidential clients", http.StatusUnauthorized)
	}
	if clientSecret != nil && *clientSecret != "" {
		if _, err := s.appService.VerifyClientCredentials(ctx, clientID, *clientSecret); err != nil {
			return nil, core.NewOAuthError("invalid_client", "Invalid client credentials", http.StatusUnauthorized)
		}
	}

	challenge := core.PKCEVerifierToChallenge(codeVerifier)
	if challenge != codeDoc.CodeChallenge {
		return nil, core.NewOAuthError("invalid_grant", "PKCE verification failed")
	}

	tx, err := s.GetSession(ctx, codeDoc.SessionID)
	if err != nil || tx == nil {
		return nil, core.NewOAuthError("invalid_grant", "Authorization session not found")
	}
	if tx.ApplicationID != codeDoc.ApplicationID {
		return nil, core.NewOAuthError("invalid_grant", "Authorization session mismatch")
	}
	if s.EffectiveStatus(tx) != "completed" {
		return nil, core.NewOAuthError("invalid_grant", "Authorization session is not completed")
	}

	user, err := s.authService.GetUserByID(ctx, codeDoc.ClientID, codeDoc.UserID)
	if err != nil || user == nil {
		return nil, core.NewOAuthError("invalid_grant", "User no longer exists")
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	codeRef := s.db.Collection("authorization_codes").Doc(codeDoc.ID)

	// Atomic mark used
	err = s.db.RunTransaction(ctx, func(ctx context.Context, ftx *firestore.Transaction) error {
		snap, err := ftx.Get(codeRef)
		if err != nil {
			return err
		}
		var current models.AuthorizationCode
		if err := snap.DataTo(&current); err != nil {
			return err
		}
		if current.Status != "active" {
			return core.NewOAuthError("invalid_grant", "Authorization code has already been used")
		}
		return ftx.Update(codeRef, []firestore.Update{
			{Path: "status", Value: "used"},
			{Path: "used_at", Value: nowStr},
		})
	})
	if err != nil {
		if oauthErr, ok := err.(*core.OAuthError); ok {
			return nil, oauthErr
		}
		return nil, core.NewOAuthError("server_error", "An unexpected error occurred", http.StatusInternalServerError)
	}

	scopeStr := strings.Join(codeDoc.Scopes, " ")
	tokens, err := s.authService.IssueUserTokens(ctx, user, clientID, &scopeStr)
	if err != nil {
		return nil, err
	}

	hasOpenID := false
	for _, sc := range codeDoc.Scopes {
		if sc == "openid" {
			hasOpenID = true
			break
		}
	}

	if hasOpenID {
		idToken, err := s.buildIDToken(user, &codeDoc)
		if err != nil {
			return nil, err
		}
		tokens.IDToken = &idToken
	}

	return tokens, nil
}

func (s *OAuthService) buildIDToken(user *models.User, codeDoc *models.AuthorizationCode) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(time.Duration(s.cfg.JWTExpirationMinutes) * time.Minute)

	claims := jwt.MapClaims{
		"iss": s.cfg.IdentityIssuer,
		"sub": user.ID,
		"aud": codeDoc.ClientID,
		"iat": now.Unix(),
		"exp": exp.Unix(),
		"jti": strings.ReplaceAll(uuid.New().String(), "-", ""),
	}

	if codeDoc.Nonce != nil {
		claims["nonce"] = *codeDoc.Nonce
	}

	scopesMap := make(map[string]bool)
	for _, sc := range codeDoc.Scopes {
		scopesMap[sc] = true
	}

	if scopesMap["email"] {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerified
	}

	if scopesMap["profile"] {
		first := ""
		if user.FirstName != nil {
			first = *user.FirstName
		}
		last := ""
		if user.LastName != nil {
			last = *user.LastName
		}
		fullName := strings.TrimSpace(first + " " + last)
		if fullName != "" {
			claims["name"] = fullName
		}
		if user.Username != nil {
			claims["preferred_username"] = *user.Username
		}
	}

	return s.keyManager.SignJWT(claims)
}

func (s *OAuthService) GetPublicConfiguration(ctx context.Context, clientID string) (*models.PublicApplicationConfig, error) {
	app, err := s.ResolveClient(ctx, clientID)
	if err != nil {
		return nil, core.NewOAuthError("invalid_client", "Unknown client_id", http.StatusNotFound)
	}

	themes := app.Branding.Themes
	if len(themes) == 0 {
		themes = []string{"light", "dark"}
	}

	allowedScopes := app.OAuth.AllowedScopes
	if len(allowedScopes) == 0 {
		allowedScopes = []string{"openid", "profile", "email"}
	}

	return &models.PublicApplicationConfig{
		Name:                     app.Name,
		Description:              app.Description,
		LogoURL:                  app.Branding.LogoURL,
		LogoWithText:             app.Branding.LogoWithText,
		PrimaryColor:             app.Branding.PrimaryColor,
		SecondaryColor:           app.Branding.SecondaryColor,
		Themes:                   themes,
		AllowSignup:              app.Authentication.AllowSignup,
		AllowPasswordLogin:       app.Authentication.AllowPasswordLogin,
		RequireEmailVerification: app.Authentication.RequireEmailVerification,
		AllowedScopes:            allowedScopes,
	}, nil
}
