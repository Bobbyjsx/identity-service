package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"identity-service/internal/core"
	"identity-service/internal/services"
)

type ForgotPasswordBody struct {
	Email          string  `json:"email"`
	TurnstileToken *string `json:"turnstile_token"`
}

type ResetPasswordBody struct {
	ResetToken     string  `json:"reset_token"`
	NewPassword    string  `json:"new_password"`
	TurnstileToken *string `json:"turnstile_token"`
}

type VerifyEmailBody struct {
	VerificationToken string  `json:"verification_token"`
	TurnstileToken    *string `json:"turnstile_token"`
}

type ResendOTPBody struct {
	TurnstileToken *string `json:"turnstile_token"`
}

func (s *Server) LoadAuthSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	resp, err := s.oauthService.LoadSession(r.Context(), sessionID)
	if err != nil {
		handleError(w, err, true)
		return
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) SessionLogin(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	var body services.SessionLoginRequest
	if err := decodeJSON(r, &body); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	tokenStr := ""
	if body.TurnstileToken != nil {
		tokenStr = *body.TurnstileToken
	}
	clientIP := core.ExtractClientIP(r)
	if err := core.VerifyTurnstileToken(r.Context(), s.cfg, tokenStr, []string{"login"}, clientIP); err != nil {
		handleError(w, err, false)
		return
	}

	res, err := s.oauthService.Login(r.Context(), sessionID, body.Email, body.Password)
	if err != nil {
		handleError(w, err, true)
		return
	}
	core.WriteJSON(w, http.StatusOK, res)
}

func (s *Server) SessionSignup(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	var body services.SessionSignupRequest
	if err := decodeJSON(r, &body); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	tokenStr := ""
	if body.TurnstileToken != nil {
		tokenStr = *body.TurnstileToken
	}
	clientIP := core.ExtractClientIP(r)
	if err := core.VerifyTurnstileToken(r.Context(), s.cfg, tokenStr, []string{"signup"}, clientIP); err != nil {
		handleError(w, err, false)
		return
	}

	res, err := s.oauthService.Signup(r.Context(), sessionID, body)
	if err != nil {
		handleError(w, err, true)
		return
	}
	core.WriteJSON(w, http.StatusOK, res)
}

func (s *Server) SessionForgotPassword(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	var body ForgotPasswordBody
	if err := decodeJSON(r, &body); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	tokenStr := ""
	if body.TurnstileToken != nil {
		tokenStr = *body.TurnstileToken
	}
	clientIP := core.ExtractClientIP(r)
	if err := core.VerifyTurnstileToken(r.Context(), s.cfg, tokenStr, []string{"forgot-password"}, clientIP); err != nil {
		handleError(w, err, false)
		return
	}

	res, err := s.oauthService.ForgotPassword(r.Context(), sessionID, body.Email)
	if err != nil {
		handleError(w, err, true)
		return
	}
	core.WriteJSON(w, http.StatusOK, res)
}

func (s *Server) SessionResetPassword(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	var body ResetPasswordBody
	if err := decodeJSON(r, &body); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	tokenStr := ""
	if body.TurnstileToken != nil {
		tokenStr = *body.TurnstileToken
	}
	clientIP := core.ExtractClientIP(r)
	if err := core.VerifyTurnstileToken(r.Context(), s.cfg, tokenStr, []string{"reset-password"}, clientIP); err != nil {
		handleError(w, err, false)
		return
	}

	res, err := s.oauthService.ResetPassword(r.Context(), sessionID, body.ResetToken, body.NewPassword)
	if err != nil {
		handleError(w, err, true)
		return
	}
	core.WriteJSON(w, http.StatusOK, res)
}

func (s *Server) SessionVerifyEmail(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	var body VerifyEmailBody
	if err := decodeJSON(r, &body); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	tokenStr := ""
	if body.TurnstileToken != nil {
		tokenStr = *body.TurnstileToken
	}
	clientIP := core.ExtractClientIP(r)
	if err := core.VerifyTurnstileToken(r.Context(), s.cfg, tokenStr, []string{"verify-email"}, clientIP); err != nil {
		handleError(w, err, false)
		return
	}

	res, err := s.oauthService.VerifyEmail(r.Context(), sessionID, body.VerificationToken)
	if err != nil {
		handleError(w, err, true)
		return
	}
	core.WriteJSON(w, http.StatusOK, res)
}

func (s *Server) SessionResendOTP(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	var body ResendOTPBody
	if err := decodeJSON(r, &body); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	tokenStr := ""
	if body.TurnstileToken != nil {
		tokenStr = *body.TurnstileToken
	}
	clientIP := core.ExtractClientIP(r)
	if err := core.VerifyTurnstileToken(r.Context(), s.cfg, tokenStr, []string{"verify-email", "resend-otp"}, clientIP); err != nil {
		handleError(w, err, false)
		return
	}

	res, err := s.oauthService.ResendOTP(r.Context(), sessionID)
	if err != nil {
		handleError(w, err, true)
		return
	}
	core.WriteJSON(w, http.StatusOK, res)
}

func (s *Server) SessionCancel(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	res, err := s.oauthService.CancelSession(r.Context(), sessionID)
	if err != nil {
		handleError(w, err, true)
		return
	}
	core.WriteJSON(w, http.StatusOK, res)
}
