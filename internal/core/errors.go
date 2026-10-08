package core

import (
	"encoding/json"
	"net/http"
)

type OAuthError struct {
	StatusCode       int    `json:"-"`
	ErrorType        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (e *OAuthError) Error() string {
	return e.ErrorDescription
}

func NewOAuthError(errType, desc string, statusCode ...int) *OAuthError {
	code := http.StatusBadRequest
	if len(statusCode) > 0 && statusCode[0] != 0 {
		code = statusCode[0]
	}
	return &OAuthError{
		StatusCode:       code,
		ErrorType:        errType,
		ErrorDescription: desc,
	}
}

type HTTPError struct {
	StatusCode int    `json:"-"`
	Detail     string `json:"detail"`
}

func (e *HTTPError) Error() string {
	return e.Detail
}

func NewHTTPError(statusCode int, detail string) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Detail:     detail,
	}
}

func WriteJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func WriteOAuthError(w http.ResponseWriter, err *OAuthError) {
	WriteJSON(w, err.StatusCode, err)
}

func WriteDetail(w http.ResponseWriter, statusCode int, detail string) {
	WriteJSON(w, statusCode, map[string]string{"detail": detail})
}

func WriteValidationError(w http.ResponseWriter, detail string) {
	WriteJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{
		"detail": []map[string]interface{}{
			{"msg": detail},
		},
	})
}
