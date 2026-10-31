package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"

	"identity-service/internal/core"
	"identity-service/internal/models"
)

var (
	KnownOAuthScopes = map[string]bool{"openid": true, "profile": true, "email": true}
	KnownGrantTypes  = map[string]bool{"authorization_code": true, "client_credentials": true}
	KnownThemes      = map[string]bool{"light": true, "dark": true}
)

type cachedApp struct {
	app       *models.Application
	expiresAt time.Time
}

type ApplicationService struct {
	db              *firestore.Client
	mu              sync.RWMutex
	cacheByClientID map[string]cachedApp
	cacheByID       map[string]cachedApp
	cacheTTL        time.Duration
}

func NewApplicationService(db *firestore.Client) *ApplicationService {
	return &ApplicationService{
		db:              db,
		cacheByClientID: make(map[string]cachedApp),
		cacheByID:       make(map[string]cachedApp),
		cacheTTL:        5 * time.Minute,
	}
}

func (s *ApplicationService) cacheApp(app *models.Application) {
	if app == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := cachedApp{
		app:       app,
		expiresAt: time.Now().Add(s.cacheTTL),
	}
	s.cacheByClientID[app.ClientID] = entry
	s.cacheByID[app.ID] = entry
}

func (s *ApplicationService) InvalidateCache(clientID, appID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if clientID != "" {
		delete(s.cacheByClientID, clientID)
	}
	if appID != "" {
		delete(s.cacheByID, appID)
	}
}

type ApplicationAuthenticationRequest struct {
	AllowSignup              *bool `json:"allow_signup"`
	AllowPasswordLogin       *bool `json:"allow_password_login"`
	RequireEmailVerification *bool `json:"require_email_verification"`
}

type ApplicationCreateRequest struct {
	Name           string                            `json:"name"`
	Description    *string                           `json:"description"`
	ClientType     string                            `json:"client_type"`
	Branding       *models.ApplicationBranding       `json:"branding"`
	Authentication *ApplicationAuthenticationRequest `json:"authentication"`
	OAuth          *models.ApplicationOAuthConfig    `json:"oauth"`
	Legal          *models.ApplicationLegalConfig    `json:"legal"`
	Theme          interface{}                       `json:"theme"`
	Themes         interface{}                       `json:"themes"`
}

func validateLegalURL(urlStr string) error {
	trimmed := strings.TrimSpace(urlStr)
	if trimmed == "" {
		return fmt.Errorf("URL cannot be empty")
	}
	if len(trimmed) > 2048 {
		return fmt.Errorf("URL is too long")
	}
	if err := core.RejectUnsafeText(trimmed); err != nil {
		return err
	}
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		return fmt.Errorf("URL must start with http:// or https://")
	}
	return nil
}

func GenerateSecureToken(byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *ApplicationService) RegisterApplication(ctx context.Context, req ApplicationCreateRequest) (*models.ApplicationCredentials, error) {
	if strings.TrimSpace(req.Name) == "" || len(req.Name) > 120 {
		return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Name must be between 1 and 120 characters")
	}
	if err := core.RejectUnsafeText(req.Name); err != nil {
		return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Name "+err.Error())
	}
	if req.Description != nil {
		if len(*req.Description) > 1000 {
			return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Description is too long")
		}
		if err := core.RejectUnsafeText(*req.Description); err != nil {
			return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Description "+err.Error())
		}
	}

	clientType := req.ClientType
	if clientType == "" {
		clientType = "public"
	}
	if clientType != "public" && clientType != "confidential" {
		return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid client_type")
	}

	branding := models.ApplicationBranding{
		Themes: []string{"light", "dark"},
	}
	if req.Branding != nil {
		if req.Branding.LogoURL != nil {
			if err := core.RejectUnsafeText(*req.Branding.LogoURL); err != nil || !strings.HasPrefix(*req.Branding.LogoURL, "http") {
				return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid logo_url")
			}
			branding.LogoURL = req.Branding.LogoURL
		}
		if req.Branding.LogoWithText != nil {
			if err := core.RejectUnsafeText(*req.Branding.LogoWithText); err != nil || !strings.HasPrefix(*req.Branding.LogoWithText, "http") {
				return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid logo_with_text")
			}
			branding.LogoWithText = req.Branding.LogoWithText
		}
		if req.Branding.PrimaryColor != nil {
			if !core.ValidateColor(*req.Branding.PrimaryColor) {
				return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid primary_color")
			}
			branding.PrimaryColor = req.Branding.PrimaryColor
		}
		if req.Branding.SecondaryColor != nil {
			if !core.ValidateColor(*req.Branding.SecondaryColor) {
				return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid secondary_color")
			}
			branding.SecondaryColor = req.Branding.SecondaryColor
		}
		if len(req.Branding.Themes) > 0 {
			for _, t := range req.Branding.Themes {
				if !KnownThemes[t] {
					return nil, core.NewHTTPError(http.StatusUnprocessableEntity, fmt.Sprintf("Invalid theme '%s'", t))
				}
			}
			branding.Themes = req.Branding.Themes
		}
	}

	// Handle top-level theme or themes alias
	var topThemes []string
	if req.Themes != nil {
		topThemes = parseThemes(req.Themes)
	} else if req.Theme != nil {
		topThemes = parseThemes(req.Theme)
	}
	if len(topThemes) > 0 {
		for _, t := range topThemes {
			if !KnownThemes[t] {
				return nil, core.NewHTTPError(http.StatusUnprocessableEntity, fmt.Sprintf("Invalid theme '%s'", t))
			}
		}
		branding.Themes = topThemes
	}

	authConfig := models.ApplicationAuthenticationConfig{
		AllowSignup:              true,
		AllowPasswordLogin:       true,
		RequireEmailVerification: false,
	}
	if req.Authentication != nil {
		if req.Authentication.AllowSignup != nil {
			authConfig.AllowSignup = *req.Authentication.AllowSignup
		}
		if req.Authentication.AllowPasswordLogin != nil {
			authConfig.AllowPasswordLogin = *req.Authentication.AllowPasswordLogin
		}
		if req.Authentication.RequireEmailVerification != nil {
			authConfig.RequireEmailVerification = *req.Authentication.RequireEmailVerification
		}
	}

	oauthConfig := models.ApplicationOAuthConfig{
		RedirectURIs:  []string{},
		AllowedScopes: []string{"openid", "profile", "email"},
		AllowedGrants: []string{"authorization_code"},
	}
	if req.OAuth != nil {
		if req.OAuth.RedirectURIs != nil {
			for _, u := range req.OAuth.RedirectURIs {
				if err := core.ValidateRedirectURI(u); err != nil {
					return nil, core.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
				}
			}
			oauthConfig.RedirectURIs = req.OAuth.RedirectURIs
		}
		if len(req.OAuth.AllowedScopes) > 0 {
			for _, sc := range req.OAuth.AllowedScopes {
				if !KnownOAuthScopes[sc] {
					return nil, core.NewHTTPError(http.StatusUnprocessableEntity, fmt.Sprintf("Invalid scope '%s'", sc))
				}
			}
			oauthConfig.AllowedScopes = req.OAuth.AllowedScopes
		}
		if len(req.OAuth.AllowedGrants) > 0 {
			for _, gr := range req.OAuth.AllowedGrants {
				if !KnownGrantTypes[gr] {
					return nil, core.NewHTTPError(http.StatusUnprocessableEntity, fmt.Sprintf("Invalid grant '%s'", gr))
				}
			}
			oauthConfig.AllowedGrants = req.OAuth.AllowedGrants
		}
	}

	var legal *models.ApplicationLegalConfig
	if req.Legal != nil {
		l := &models.ApplicationLegalConfig{}
		if req.Legal.Privacy != nil {
			pStr := strings.TrimSpace(*req.Legal.Privacy)
			if pStr != "" {
				if err := validateLegalURL(pStr); err != nil {
					return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid privacy URL: "+err.Error())
				}
				l.Privacy = &pStr
			}
		}
		if req.Legal.Terms != nil {
			tStr := strings.TrimSpace(*req.Legal.Terms)
			if tStr != "" {
				if err := validateLegalURL(tStr); err != nil {
					return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid terms URL: "+err.Error())
				}
				l.Terms = &tStr
			}
		}
		if l.Privacy != nil || l.Terms != nil {
			legal = l
		}
	}

	appID := uuid.New().String()
	clientID := fmt.Sprintf("app_%s", strings.ReplaceAll(uuid.New().String(), "-", ""))
	now := time.Now().UTC().Format(time.RFC3339)

	app := models.Application{
		ID:             appID,
		Name:           req.Name,
		Description:    req.Description,
		ClientID:       clientID,
		ClientType:     clientType,
		Status:         "active",
		CreatedAt:      now,
		Branding:       branding,
		Authentication: authConfig,
		OAuth:          oauthConfig,
		Legal:          legal,
	}

	clientSecret := GenerateSecureToken(32)
	hashedSecret, err := core.HashPassword(clientSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to hash client secret: %w", err)
	}

	cred := models.ApplicationCredential{
		ID:           uuid.New().String(),
		AppID:        appID,
		HashedSecret: hashedSecret,
		CreatedAt:    now,
		Status:       "active",
	}

	batch := s.db.Batch()
	appRef := s.db.Collection("applications").Doc(appID)
	batch.Set(appRef, app)

	credRef := s.db.Collection("application_credentials").Doc(cred.ID)
	batch.Set(credRef, cred)

	if _, err := batch.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to save application in firestore: %w", err)
	}

	return &models.ApplicationCredentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, nil
}

func parseThemes(v interface{}) []string {
	var result []string
	switch val := v.(type) {
	case string:
		result = append(result, strings.TrimSpace(val))
	case []interface{}:
		for _, item := range val {
			if str, ok := item.(string); ok {
				result = append(result, strings.TrimSpace(str))
			}
		}
	case []string:
		result = val
	}
	return result
}

func (s *ApplicationService) GetByClientID(ctx context.Context, clientID string) (*models.Application, error) {
	if !core.IsTestEnvironment() {
		s.mu.RLock()
		if entry, ok := s.cacheByClientID[clientID]; ok {
			if time.Now().Before(entry.expiresAt) {
				s.mu.RUnlock()
				core.SetRequestApp(ctx, entry.app.ClientID, entry.app.Name)
				return entry.app, nil
			}
		}
		s.mu.RUnlock()
	}

	iter := s.db.Collection("applications").Where("client_id", "==", clientID).Limit(1).Documents(ctx)
	defer iter.Stop()

	doc, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var app models.Application
	data := doc.Data()
	if err := doc.DataTo(&app); err != nil {
		return nil, err
	}
	app.ID = doc.Ref.ID
	applyApplicationDefaults(data, &app)

	if !core.IsTestEnvironment() {
		s.cacheApp(&app)
	}
	core.SetRequestApp(ctx, app.ClientID, app.Name)
	return &app, nil
}

func (s *ApplicationService) GetByID(ctx context.Context, appID string) (*models.Application, error) {
	if !core.IsTestEnvironment() {
		s.mu.RLock()
		if entry, ok := s.cacheByID[appID]; ok {
			if time.Now().Before(entry.expiresAt) {
				s.mu.RUnlock()
				core.SetRequestApp(ctx, entry.app.ClientID, entry.app.Name)
				return entry.app, nil
			}
		}
		s.mu.RUnlock()
	}

	doc, err := s.db.Collection("applications").Doc(appID).Get(ctx)
	if err != nil || !doc.Exists() {
		return nil, nil
	}
	var app models.Application
	data := doc.Data()
	if err := doc.DataTo(&app); err != nil {
		return nil, err
	}
	app.ID = doc.Ref.ID
	applyApplicationDefaults(data, &app)

	if !core.IsTestEnvironment() {
		s.cacheApp(&app)
	}
	core.SetRequestApp(ctx, app.ClientID, app.Name)
	return &app, nil
}

func applyApplicationDefaults(data map[string]interface{}, app *models.Application) {
	if authMap, ok := data["authentication"].(map[string]interface{}); ok {
		if val, has := authMap["allow_signup"]; !has || val == nil {
			app.Authentication.AllowSignup = true
		}
		if val, has := authMap["allow_password_login"]; !has || val == nil {
			app.Authentication.AllowPasswordLogin = true
		}
	} else {
		app.Authentication.AllowSignup = true
		app.Authentication.AllowPasswordLogin = true
	}

	if oauthMap, ok := data["oauth"].(map[string]interface{}); ok {
		if val, has := oauthMap["allowed_scopes"]; !has || val == nil || len(app.OAuth.AllowedScopes) == 0 {
			app.OAuth.AllowedScopes = []string{"openid", "profile", "email"}
		}
	} else {
		app.OAuth.AllowedScopes = []string{"openid", "profile", "email"}
	}

	if legalMap, ok := data["legal"].(map[string]interface{}); ok {
		if app.Legal == nil {
			app.Legal = &models.ApplicationLegalConfig{}
		}
		if p, ok := legalMap["privacy"].(string); ok && p != "" {
			app.Legal.Privacy = &p
		}
		if t, ok := legalMap["terms"].(string); ok && t != "" {
			app.Legal.Terms = &t
		}
	}
}

func (s *ApplicationService) UpdateApplicationConfig(ctx context.Context, clientID string, updates map[string]interface{}) (*models.Application, error) {
	app, err := s.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, core.NewHTTPError(http.StatusNotFound, "Application not found")
	}

	patch := make(map[string]interface{})

	if nameRaw, ok := updates["name"]; ok && nameRaw != nil {
		nameStr, ok := nameRaw.(string)
		if !ok || strings.TrimSpace(nameStr) == "" || len(nameStr) > 120 {
			return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid name")
		}
		if err := core.RejectUnsafeText(nameStr); err != nil {
			return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Name "+err.Error())
		}
		patch["name"] = nameStr
		app.Name = nameStr
	}

	if descRaw, ok := updates["description"]; ok && descRaw != nil {
		descStr, ok := descRaw.(string)
		if !ok || len(descStr) > 1000 {
			return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid description")
		}
		if err := core.RejectUnsafeText(descStr); err != nil {
			return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Description "+err.Error())
		}
		patch["description"] = descStr
		app.Description = &descStr
	}

	if ctRaw, ok := updates["client_type"]; ok && ctRaw != nil {
		ctStr, ok := ctRaw.(string)
		if !ok || (ctStr != "public" && ctStr != "confidential") {
			return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid client_type")
		}
		patch["client_type"] = ctStr
		app.ClientType = ctStr
	}

	if brandRaw, ok := updates["branding"]; ok && brandRaw != nil {
		if brandMap, ok := brandRaw.(map[string]interface{}); ok {
			b := app.Branding
			if lu, ok := brandMap["logo_url"]; ok {
				if lu != nil {
					luStr := lu.(string)
					if err := core.RejectUnsafeText(luStr); err != nil || !strings.HasPrefix(luStr, "http") {
						return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid logo_url")
					}
					b.LogoURL = &luStr
				} else {
					b.LogoURL = nil
				}
			}
			if pc, ok := brandMap["primary_color"]; ok {
				if pc != nil {
					pcStr := pc.(string)
					if !core.ValidateColor(pcStr) {
						return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid primary_color")
					}
					b.PrimaryColor = &pcStr
				} else {
					b.PrimaryColor = nil
				}
			}
			if sc, ok := brandMap["secondary_color"]; ok {
				if sc != nil {
					scStr := sc.(string)
					if !core.ValidateColor(scStr) {
						return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid secondary_color")
					}
					b.SecondaryColor = &scStr
				} else {
					b.SecondaryColor = nil
				}
			}
			if th, ok := brandMap["themes"]; ok && th != nil {
				thList := parseThemes(th)
				for _, t := range thList {
					if !KnownThemes[t] {
						return nil, core.NewHTTPError(http.StatusUnprocessableEntity, fmt.Sprintf("Invalid theme '%s'", t))
					}
				}
				b.Themes = thList
			}
			patch["branding"] = b
			app.Branding = b
		}
	}

	if authRaw, ok := updates["authentication"]; ok && authRaw != nil {
		if authMap, ok := authRaw.(map[string]interface{}); ok {
			a := app.Authentication
			if v, ok := authMap["allow_signup"].(bool); ok {
				a.AllowSignup = v
			}
			if v, ok := authMap["allow_password_login"].(bool); ok {
				a.AllowPasswordLogin = v
			}
			if v, ok := authMap["require_email_verification"].(bool); ok {
				a.RequireEmailVerification = v
			}
			patch["authentication"] = a
			app.Authentication = a
		}
	}

	if oauthRaw, ok := updates["oauth"]; ok && oauthRaw != nil {
		if oauthMap, ok := oauthRaw.(map[string]interface{}); ok {
			o := app.OAuth
			if ru, ok := oauthMap["redirect_uris"].([]interface{}); ok {
				var uris []string
				for _, u := range ru {
					uStr, ok := u.(string)
					if !ok {
						return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid redirect_uri")
					}
					if err := core.ValidateRedirectURI(uStr); err != nil {
						return nil, core.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
					}
					uris = append(uris, uStr)
				}
				o.RedirectURIs = uris
			}
			if sc, ok := oauthMap["allowed_scopes"].([]interface{}); ok {
				var scopes []string
				for _, s := range sc {
					sStr, ok := s.(string)
					if !ok || !KnownOAuthScopes[sStr] {
						return nil, core.NewHTTPError(http.StatusUnprocessableEntity, fmt.Sprintf("Invalid scope '%v'", s))
					}
					scopes = append(scopes, sStr)
				}
				o.AllowedScopes = scopes
			}
			if gr, ok := oauthMap["allowed_grants"].([]interface{}); ok {
				var grants []string
				for _, g := range gr {
					gStr, ok := g.(string)
					if !ok || !KnownGrantTypes[gStr] {
						return nil, core.NewHTTPError(http.StatusUnprocessableEntity, fmt.Sprintf("Invalid grant '%v'", g))
					}
					grants = append(grants, gStr)
				}
				o.AllowedGrants = grants
			}
			patch["oauth"] = o
			app.OAuth = o
		}
	}

	if legalRaw, ok := updates["legal"]; ok {
		if legalRaw == nil {
			patch["legal"] = nil
			app.Legal = nil
		} else if legalMap, ok := legalRaw.(map[string]interface{}); ok {
			l := app.Legal
			if l == nil {
				l = &models.ApplicationLegalConfig{}
			}
			if p, exists := legalMap["privacy"]; exists {
				if p != nil {
					pStr, ok := p.(string)
					if !ok {
						return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid privacy URL")
					}
					pStr = strings.TrimSpace(pStr)
					if pStr != "" {
						if err := validateLegalURL(pStr); err != nil {
							return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid privacy URL: "+err.Error())
						}
						l.Privacy = &pStr
					} else {
						l.Privacy = nil
					}
				} else {
					l.Privacy = nil
				}
			}
			if t, exists := legalMap["terms"]; exists {
				if t != nil {
					tStr, ok := t.(string)
					if !ok {
						return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid terms URL")
					}
					tStr = strings.TrimSpace(tStr)
					if tStr != "" {
						if err := validateLegalURL(tStr); err != nil {
							return nil, core.NewHTTPError(http.StatusUnprocessableEntity, "Invalid terms URL: "+err.Error())
						}
						l.Terms = &tStr
					} else {
						l.Terms = nil
					}
				} else {
					l.Terms = nil
				}
			}
			patch["legal"] = l
			app.Legal = l
		}
	}

	if len(patch) > 0 {
		var firestoreUpdates []firestore.Update
		for k, v := range patch {
			firestoreUpdates = append(firestoreUpdates, firestore.Update{Path: k, Value: v})
		}
		if _, err := s.db.Collection("applications").Doc(app.ID).Update(ctx, firestoreUpdates); err != nil {
			return nil, fmt.Errorf("failed to update application in firestore: %w", err)
		}
	}

	s.cacheApp(app)

	return app, nil
}

func (s *ApplicationService) VerifyClientCredentials(ctx context.Context, clientID, clientSecret string) (string, error) {
	app, err := s.GetByClientID(ctx, clientID)
	if err != nil {
		return "", err
	}
	if app == nil {
		return "", core.NewHTTPError(http.StatusUnauthorized, "Invalid client credentials")
	}

	return s.VerifyClientCredentialsWithApp(ctx, app, clientSecret)
}

func (s *ApplicationService) VerifyClientCredentialsWithApp(ctx context.Context, app *models.Application, clientSecret string) (string, error) {
	iter := s.db.Collection("application_credentials").Where("app_id", "==", app.ID).Documents(ctx)
	defer iter.Stop()

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return "", err
		}

		var cred models.ApplicationCredential
		if err := doc.DataTo(&cred); err != nil {
			continue
		}

		if cred.Status == "active" && core.VerifyPassword(clientSecret, cred.HashedSecret) {
			return app.ID, nil
		}
	}

	return "", core.NewHTTPError(http.StatusUnauthorized, "Invalid client credentials")
}
