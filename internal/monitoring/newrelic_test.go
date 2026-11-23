package monitoring

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"identity-service/internal/config"
	"identity-service/internal/core"
)

func TestInitNewRelic_Disabled(t *testing.T) {
	cfg := &config.Config{
		NewRelicEnabled:    false,
		NewRelicLicenseKey: "0123456789abcdef0123456789abcdef01234567",
		NewRelicAppName:    "test-app",
	}

	app, err := InitNewRelic(cfg)
	assert.NoError(t, err)
	assert.Nil(t, app)
}

func TestInitNewRelic_NoLicenseKey(t *testing.T) {
	cfg := &config.Config{
		NewRelicEnabled:    true,
		NewRelicLicenseKey: "",
		NewRelicAppName:    "test-app",
	}

	app, err := InitNewRelic(cfg)
	assert.NoError(t, err)
	assert.Nil(t, app)
}

func TestInitNewRelic_Enabled(t *testing.T) {
	cfg := &config.Config{
		NewRelicEnabled:    true,
		NewRelicLicenseKey: "0123456789abcdef0123456789abcdef01234567",
		NewRelicAppName:    "identity-service-test",
		Environment:        "testing",
	}

	app, err := InitNewRelic(cfg)
	assert.NoError(t, err)
	require.NotNil(t, app)
}

func TestMiddleware_NilApp(t *testing.T) {
	mw := Middleware(nil)
	handlerCalled := false

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	h.ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}

func TestMiddleware_WithApp(t *testing.T) {
	app, err := newrelic.NewApplication(
		newrelic.ConfigAppName("test-service"),
		newrelic.ConfigLicense("0123456789abcdef0123456789abcdef01234567"),
		newrelic.ConfigEnabled(false), // Disable harvest connection for testing
	)
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Use(Middleware(app, "staging"))

	r.Get("/api/v1/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		// Verify context contains transaction
		txn := FromContext(r.Context())
		assert.NotNil(t, txn)

		SetUserID(r.Context(), "user-123")
		AddAttribute(r.Context(), "custom.flag", true)

		// Set request app context
		core.SetRequestApp(r.Context(), "client-xyz", "TestApp")

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("found"))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/users/42", nil)
	req.Header.Set("X-Request-Id", "req-test-123")
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "found", rec.Body.String())
}

func TestMiddleware_HealthCheckSkipped(t *testing.T) {
	app, err := newrelic.NewApplication(
		newrelic.ConfigAppName("test-service"),
		newrelic.ConfigLicense("0123456789abcdef0123456789abcdef01234567"),
		newrelic.ConfigEnabled(false),
	)
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Use(Middleware(app, "staging"))

	healthCalled := false
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		healthCalled = true
		// Verify no active transaction on /health
		txn := FromContext(r.Context())
		assert.Nil(t, txn)
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	r.ServeHTTP(rec, req)

	assert.True(t, healthCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_PanicCapture(t *testing.T) {
	app, err := newrelic.NewApplication(
		newrelic.ConfigAppName("test-service"),
		newrelic.ConfigLicense("0123456789abcdef0123456789abcdef01234567"),
		newrelic.ConfigEnabled(false),
	)
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Use(Middleware(app, "staging"))

	r.Get("/panic", func(w http.ResponseWriter, r *http.Request) {
		panic("simulated critical crash")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/panic", nil)

	assert.Panics(t, func() {
		r.ServeHTTP(rec, req)
	})
}

func TestHelperFunctions_NilContext(t *testing.T) {
	assert.Nil(t, FromContext(nil))
	// Should not panic
	NoticeError(nil, errors.New("sample error"))
	SetUserID(nil, "user-abc")
	AddAttribute(nil, "key", "val")
}

func TestHelperFunctions_NonNilContext(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, FromContext(ctx))

	NoticeError(ctx, errors.New("sample error"))
	NoticeError(ctx, nil)
	SetUserID(ctx, "user-abc")
	SetUserID(ctx, "")
	AddAttribute(ctx, "key", "val")
	AddAttribute(ctx, "", "val")
}

func TestRecordLog(t *testing.T) {
	RecordLog(nil, "INFO", "msg")
	RecordLog(context.Background(), "INFO", "")
	RecordLog(context.Background(), "INFO", "valid message", map[string]any{"key": "val"})

	app, err := newrelic.NewApplication(
		newrelic.ConfigAppName("test-service"),
		newrelic.ConfigLicense("0123456789abcdef0123456789abcdef01234567"),
		newrelic.ConfigEnabled(false),
	)
	require.NoError(t, err)

	txn := app.StartTransaction("test-txn")
	defer txn.End()
	ctx := newrelic.NewContext(context.Background(), txn)

	RecordLog(ctx, "INFO", "transaction message", map[string]any{"status": 200})
}

func TestLogWriter(t *testing.T) {
	var buf bytes.Buffer
	lw := &logWriter{output: &buf, app: nil}

	n, err := lw.Write([]byte("hello world\n"))
	assert.NoError(t, err)
	assert.Equal(t, 12, n)
	assert.Equal(t, "hello world\n", buf.String())
}
