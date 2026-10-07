package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"identity-service/internal/core"
)

func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Use(SecurityHeadersMiddleware)

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		core.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Discovery
	r.Get("/.well-known/jwks.json", s.WellKnownJWKS)
	r.Get("/.well-known/openid-configuration", s.WellKnownOpenIDConfiguration)

	// API v1
	r.Route("/api/v1", func(r chi.Router) {
		// Admin
		r.Route("/admin", func(r chi.Router) {
			r.Post("/applications", s.verifyAdmin(s.AdminCreateApplication))
			r.Get("/applications/{client_id}", s.verifyAdmin(s.AdminGetApplication))
			r.Patch("/applications/{client_id}/configuration", s.verifyAdmin(s.AdminUpdateApplicationConfig))
			r.Post("/auth-sessions", s.verifyAdmin(s.AdminCreateAuthSession))
		})

		// Applications
		r.Route("/applications", func(r chi.Router) {
			r.Get("/{client_id}/configuration", s.PublicApplicationConfiguration)
		})

		// Auth
		r.Route("/auth", func(r chi.Router) {
			r.Post("/signup", s.verifyApp(s.AuthSignup))
			r.Post("/login", s.verifyApp(s.AuthLogin))
			r.Post("/refresh", s.AuthRefresh)
			r.Get("/me", s.authenticateBearer(s.AuthGetMe))
			r.Post("/password/exchange-reset-token", s.AuthExchangeResetToken)
			r.Post("/password/reset", s.AuthPasswordReset)
		})

		// Auth sessions
		r.Route("/auth-sessions", func(r chi.Router) {
			r.Get("/{session_id}", s.LoadAuthSession)
			r.Post("/{session_id}/login", s.SessionLogin)
			r.Post("/{session_id}/signup", s.SessionSignup)
			r.Post("/{session_id}/forgot-password", s.SessionForgotPassword)
			r.Post("/{session_id}/reset-password", s.SessionResetPassword)
			r.Post("/{session_id}/verify-email", s.SessionVerifyEmail)
			r.Post("/{session_id}/resend-otp", s.SessionResendOTP)
			r.Post("/{session_id}/cancel", s.SessionCancel)
		})

		// OAuth
		r.Route("/oauth", func(r chi.Router) {
			r.Get("/authorize", s.OAuthAuthorize)
			r.Post("/token", s.OAuthToken)
		})

		// RBAC
		r.Route("/rbac", func(r chi.Router) {
			r.Post("/permissions", s.verifyApp(s.RBACCreatePermission))
			r.Get("/permissions", s.verifyApp(s.RBACListPermissions))
			r.Post("/roles", s.verifyApp(s.RBACCreateRole))
			r.Get("/roles", s.verifyApp(s.RBACListRoles))
		})
	})

	return r
}
