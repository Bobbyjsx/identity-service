package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Environment                             string
	FirestoreDatabase                       string
	FirestoreEmulatorHost                   string
	GoogleCloudProject                      string
	GoogleApplicationCredentials            string
	FirebaseCredentialsJSON                 string
	AdminSecret                             string
	IdentityIssuer                          string
	PrivateKey                              string
	JWTExpirationMinutes                    int
	RefreshTokenExpirationDays              int
	IdentityUIBaseURL                       string
	PublicBaseURL                           string
	AuthSessionExpirationMinutes            int
	OAuthAuthorizationCodeExpirationMinutes int
	PasswordResetTokenExpirationMinutes     int
	TurnstileSecretKey                      string
	TurnstileHostnames                      string
	TurnstileEnabled                        bool
	GCPProjectID                            string
	PubSubTopicID                           string
	Port                                    string
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		lower := strings.ToLower(strings.TrimSpace(val))
		return lower == "true" || lower == "1" || lower == "yes"
	}
	return defaultVal
}

func loadDotEnv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			v = strings.Trim(v, `"'`)
			if os.Getenv(k) == "" {
				os.Setenv(k, v)
			}
		}
	}
}

func Load() *Config {
	loadDotEnv()

	env := getEnv("ENVIRONMENT", "development")
	if env == "development" && os.Getenv("IDENTITY_ENVIRONMENT") != "" {
		env = os.Getenv("IDENTITY_ENVIRONMENT")
	}

	return &Config{
		Environment:                             env,
		FirestoreDatabase:                       getEnv("FIRESTORE_DATABASE", "(default)"),
		FirestoreEmulatorHost:                   os.Getenv("FIRESTORE_EMULATOR_HOST"),
		GoogleCloudProject:                      getEnv("GOOGLE_CLOUD_PROJECT", "project-atlas-501612"),
		GoogleApplicationCredentials:            getEnv("GOOGLE_APPLICATION_CREDENTIALS", "firebase-credentials.json"),
		FirebaseCredentialsJSON:                 os.Getenv("FIREBASE_CREDENTIALS_JSON"),
		AdminSecret:                             getEnv("ADMIN_SECRET", "changeme-in-prod"),
		IdentityIssuer:                          getEnv("IDENTITY_ISSUER", "http://localhost:8002"),
		PrivateKey:                              os.Getenv("PRIVATE_KEY"),
		JWTExpirationMinutes:                    getEnvInt("JWT_EXPIRATION_MINUTES", 15),
		RefreshTokenExpirationDays:              getEnvInt("REFRESH_TOKEN_EXPIRATION_DAYS", 30),
		IdentityUIBaseURL:                       getEnv("IDENTITY_UI_BASE_URL", "http://localhost:3000"),
		PublicBaseURL:                           getEnv("PUBLIC_BASE_URL", "http://localhost:8002"),
		AuthSessionExpirationMinutes:            getEnvInt("AUTH_SESSION_EXPIRATION_MINUTES", 10),
		OAuthAuthorizationCodeExpirationMinutes: getEnvInt("OAUTH_AUTHORIZATION_CODE_EXPIRATION_MINUTES", 5),
		PasswordResetTokenExpirationMinutes:     getEnvInt("PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES", 30),
		TurnstileSecretKey:                      os.Getenv("TURNSTILE_SECRET_KEY"),
		TurnstileHostnames:                      getEnv("TURNSTILE_HOSTNAMES", "localhost,127.0.0.1"),
		TurnstileEnabled:                        getEnvBool("TURNSTILE_ENABLED", true),
		GCPProjectID:                            getEnv("GCP_PROJECT_ID", "project-atlas-501612"),
		PubSubTopicID:                           getEnv("PUBSUB_TOPIC_ID", "platform-events"),
		Port:                                    getEnv("PORT", "8002"),
	}
}
