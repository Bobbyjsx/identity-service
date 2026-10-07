package handlers

import (
	"net/http"

	"identity-service/internal/core"
	"identity-service/internal/models"
	"identity-service/internal/services"
)

type RefreshTokenBody struct {
	RefreshToken string `json:"refresh_token"`
}

type ExchangeResetTokenBody struct {
	ResetToken string `json:"reset_token"`
}

type ResetPasswordStandaloneBody struct {
	ResetToken     string  `json:"reset_token"`
	NewPassword    string  `json:"new_password"`
	TurnstileToken *string `json:"turnstile_token"`
}

func (s *Server) AuthSignup(w http.ResponseWriter, r *http.Request, app *models.Application) {
	var req services.UserCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	tokenStr := ""
	if req.TurnstileToken != nil {
		tokenStr = *req.TurnstileToken
	}
	clientIP := core.ExtractClientIP(r)
	if err := core.VerifyTurnstileToken(r.Context(), s.cfg, tokenStr, []string{"signup"}, clientIP); err != nil {
		handleError(w, err, false)
		return
	}

	user, err := s.authService.CreateUser(r.Context(), app.ClientID, req)
	if err != nil {
		handleError(w, err, false)
		return
	}

	resp := models.UserResponse{
		ID:            user.ID,
		AppID:         user.AppID,
		Email:         user.Email,
		Username:      user.Username,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		CreatedAt:     user.CreatedAt,
		Roles:         user.Roles,
		EmailVerified: user.EmailVerified,
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) AuthLogin(w http.ResponseWriter, r *http.Request, app *models.Application) {
	var req services.UserCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		core.WriteValidationError(w, "Invalid JSON payload")
		return
	}

	tokenStr := ""
	if req.TurnstileToken != nil {
		tokenStr = *req.TurnstileToken
	}
	clientIP := core.ExtractClientIP(r)
	if err := core.VerifyTurnstileToken(r.Context(), s.cfg, tokenStr, []string{"login"}, clientIP); err != nil {
		handleError(w, err, false)
		return
	}

	tokens, err := s.authService.Login(r.Context(), app.ClientID, req)
	if err != nil {
		handleError(w, err, false)
		return
	}

	core.WriteJSON(w, http.StatusOK, tokens)
}

func (s *Server) AuthRefresh(w http.ResponseWriter, r *http.Request) {
	var body RefreshTokenBody
	if err := decodeJSON(r, &body); err != nil || body.RefreshToken == "" {
		core.WriteValidationError(w, "Invalid JSON payload or missing refresh_token")
		return
	}

	tokens, err := s.authService.RefreshAccessToken(r.Context(), body.RefreshToken)
	if err != nil {
		handleError(w, err, false)
		return
	}

	core.WriteJSON(w, http.StatusOK, tokens)
}

func (s *Server) AuthGetMe(w http.ResponseWriter, r *http.Request, user *models.User) {
	resp := models.UserResponse{
		ID:            user.ID,
		AppID:         user.AppID,
		Email:         user.Email,
		Username:      user.Username,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		CreatedAt:     user.CreatedAt,
		Roles:         user.Roles,
		EmailVerified: user.EmailVerified,
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) AuthExchangeResetToken(w http.ResponseWriter, r *http.Request) {
	var body ExchangeResetTokenBody
	if err := decodeJSON(r, &body); err != nil || body.ResetToken == "" {
		core.WriteValidationError(w, "Invalid JSON payload or missing reset_token")
		return
	}

	res, err := s.oauthService.ExchangeResetTokenForSession(r.Context(), body.ResetToken)
	if err != nil {
		handleError(w, err, true)
		return
	}

	core.WriteJSON(w, http.StatusOK, res)
}

func (s *Server) AuthPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body ResetPasswordStandaloneBody
	if err := decodeJSON(r, &body); err != nil || body.ResetToken == "" || body.NewPassword == "" {
		core.WriteValidationError(w, "Invalid JSON payload or missing fields")
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

	res, err := s.oauthService.ResetPasswordStandalone(r.Context(), body.ResetToken, body.NewPassword)
	if err != nil {
		handleError(w, err, true)
		return
	}

	core.WriteJSON(w, http.StatusOK, res)
}
