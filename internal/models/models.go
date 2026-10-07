package models

type ApplicationBranding struct {
	LogoURL        *string  `json:"logo_url" firestore:"logo_url"`
	LogoWithText   *string  `json:"logo_with_text" firestore:"logo_with_text"`
	PrimaryColor   *string  `json:"primary_color" firestore:"primary_color"`
	SecondaryColor *string  `json:"secondary_color" firestore:"secondary_color"`
	Themes         []string `json:"themes" firestore:"themes"`
}

type ApplicationAuthenticationConfig struct {
	AllowSignup              bool `json:"allow_signup" firestore:"allow_signup"`
	AllowPasswordLogin       bool `json:"allow_password_login" firestore:"allow_password_login"`
	RequireEmailVerification bool `json:"require_email_verification" firestore:"require_email_verification"`
}

type ApplicationOAuthConfig struct {
	RedirectURIs  []string `json:"redirect_uris" firestore:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes" firestore:"allowed_scopes"`
	AllowedGrants []string `json:"allowed_grants" firestore:"allowed_grants"`
}

type Application struct {
	ID             string                          `json:"id" firestore:"id"`
	Name           string                          `json:"name" firestore:"name"`
	Description    *string                         `json:"description" firestore:"description"`
	ClientID       string                          `json:"client_id" firestore:"client_id"`
	ClientType     string                          `json:"client_type,omitempty" firestore:"client_type"`
	Status         string                          `json:"status" firestore:"status"`
	CreatedAt      string                          `json:"created_at" firestore:"created_at"`
	Branding       ApplicationBranding             `json:"branding" firestore:"branding"`
	Authentication ApplicationAuthenticationConfig `json:"authentication" firestore:"authentication"`
	OAuth          ApplicationOAuthConfig          `json:"oauth" firestore:"oauth"`
}

type ApplicationCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type ApplicationCredential struct {
	ID           string `json:"id" firestore:"id"`
	AppID        string `json:"app_id" firestore:"app_id"`
	HashedSecret string `json:"hashed_secret" firestore:"hashed_secret"`
	CreatedAt    string `json:"created_at" firestore:"created_at"`
	Status       string `json:"status" firestore:"status"`
}

type PublicApplicationConfig struct {
	Name                     string   `json:"name"`
	Description              *string  `json:"description"`
	LogoURL                  *string  `json:"logo_url"`
	LogoWithText             *string  `json:"logo_with_text"`
	PrimaryColor             *string  `json:"primary_color"`
	SecondaryColor           *string  `json:"secondary_color"`
	Themes                   []string `json:"themes"`
	AllowSignup              bool     `json:"allow_signup"`
	AllowPasswordLogin       bool     `json:"allow_password_login"`
	RequireEmailVerification bool     `json:"require_email_verification"`
	AllowedScopes            []string `json:"allowed_scopes"`
}

type User struct {
	ID             string   `json:"id" firestore:"id"`
	AppID          string   `json:"app_id" firestore:"app_id"`
	Email          string   `json:"email" firestore:"email"`
	HashedPassword string   `json:"-" firestore:"hashed_password"`
	Username       *string  `json:"username" firestore:"username"`
	FirstName      *string  `json:"first_name" firestore:"first_name"`
	LastName       *string  `json:"last_name" firestore:"last_name"`
	Roles          []string `json:"roles" firestore:"roles"`
	EmailVerified  bool     `json:"email_verified" firestore:"email_verified"`
	CreatedAt      string   `json:"created_at" firestore:"created_at"`
}

type UserResponse struct {
	ID            string   `json:"id"`
	AppID         string   `json:"app_id"`
	Email         string   `json:"email"`
	Username      *string  `json:"username"`
	FirstName     *string  `json:"first_name"`
	LastName      *string  `json:"last_name"`
	CreatedAt     string   `json:"created_at"`
	Roles         []string `json:"roles"`
	EmailVerified bool     `json:"email_verified"`
}

type RefreshToken struct {
	ID        string `json:"id" firestore:"id"`
	UserID    string `json:"user_id" firestore:"user_id"`
	AppID     string `json:"app_id" firestore:"app_id"`
	Token     string `json:"token" firestore:"token"`
	ExpiresAt string `json:"expires_at" firestore:"expires_at"`
}

type AuthSession struct {
	ID                  string   `json:"session_id" firestore:"id"`
	ApplicationID       string   `json:"application_id" firestore:"application_id"`
	ClientID            string   `json:"client_id" firestore:"client_id"`
	RedirectURI         string   `json:"redirect_uri" firestore:"redirect_uri"`
	ResponseType        string   `json:"response_type" firestore:"response_type"`
	Scopes              []string `json:"scopes" firestore:"scopes"`
	State               *string  `json:"state" firestore:"state"`
	CodeChallenge       string   `json:"code_challenge" firestore:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method" firestore:"code_challenge_method"`
	Nonce               *string  `json:"nonce" firestore:"nonce"`
	Status              string   `json:"status" firestore:"status"`
	UserID              *string  `json:"user_id,omitempty" firestore:"user_id"`
	ExpiresAt           string   `json:"expires_at" firestore:"expires_at"`
	OTPAttempts         int      `json:"otp_attempts,omitempty" firestore:"otp_attempts"`
	CompletedAt         *string  `json:"completed_at,omitempty" firestore:"completed_at"`
}

type AuthSessionResponse struct {
	SessionID   string                 `json:"session_id"`
	Status      string                 `json:"status"`
	Application map[string]interface{} `json:"application"`
	Scopes      []string               `json:"scopes"`
	RedirectURL *string                `json:"redirect_url"`
}

type AuthorizationCode struct {
	ID                  string   `json:"id" firestore:"id"`
	CodeHash            string   `json:"code_hash" firestore:"code_hash"`
	SessionID           string   `json:"session_id" firestore:"session_id"`
	ApplicationID       string   `json:"application_id" firestore:"application_id"`
	ClientID            string   `json:"client_id" firestore:"client_id"`
	UserID              string   `json:"user_id" firestore:"user_id"`
	RedirectURI         string   `json:"redirect_uri" firestore:"redirect_uri"`
	Scopes              []string `json:"scopes" firestore:"scopes"`
	CodeChallenge       string   `json:"code_challenge" firestore:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method" firestore:"code_challenge_method"`
	Nonce               *string  `json:"nonce" firestore:"nonce"`
	Status              string   `json:"status" firestore:"status"`
	CreatedAt           string   `json:"created_at" firestore:"created_at"`
	ExpiresAt           string   `json:"expires_at" firestore:"expires_at"`
	UsedAt              *string  `json:"used_at" firestore:"used_at"`
}

type PasswordResetToken struct {
	ID        string  `json:"id" firestore:"id"`
	TokenHash string  `json:"token_hash" firestore:"token_hash"`
	AppID     string  `json:"app_id" firestore:"app_id"`
	UserID    string  `json:"user_id" firestore:"user_id"`
	Status    string  `json:"status" firestore:"status"`
	CreatedAt string  `json:"created_at" firestore:"created_at"`
	ExpiresAt string  `json:"expires_at" firestore:"expires_at"`
	UsedAt    *string `json:"used_at" firestore:"used_at"`
}

type EmailVerificationToken struct {
	ID          string  `json:"id" firestore:"id"`
	TokenHash   string  `json:"token_hash" firestore:"token_hash"`
	AppID       string  `json:"app_id" firestore:"app_id"`
	UserID      string  `json:"user_id" firestore:"user_id"`
	Status      string  `json:"status" firestore:"status"`
	Attempts    int     `json:"attempts" firestore:"attempts"`
	MaxAttempts int     `json:"max_attempts" firestore:"max_attempts"`
	CreatedAt   string  `json:"created_at" firestore:"created_at"`
	ExpiresAt   string  `json:"expires_at" firestore:"expires_at"`
	UsedAt      *string `json:"used_at" firestore:"used_at"`
}

type Role struct {
	ID          string   `json:"id" firestore:"id"`
	AppID       string   `json:"app_id" firestore:"app_id"`
	Name        string   `json:"name" firestore:"name"`
	Description string   `json:"description" firestore:"description"`
	Permissions []string `json:"permissions" firestore:"permissions"`
	CreatedAt   string   `json:"created_at" firestore:"created_at"`
}

type Permission struct {
	ID          string `json:"id" firestore:"id"`
	AppID       string `json:"app_id" firestore:"app_id"`
	Name        string `json:"name" firestore:"name"`
	Description string `json:"description" firestore:"description"`
	CreatedAt   string `json:"created_at" firestore:"created_at"`
}

type TokenResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int     `json:"expires_in"`
	RefreshToken *string `json:"refresh_token,omitempty"`
	IDToken      *string `json:"id_token,omitempty"`
}
