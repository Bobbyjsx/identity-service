package monitoring

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/newrelic/go-agent/v3/newrelic"

	"identity-service/internal/config"
	"identity-service/internal/core"
)

// InitNewRelic initializes the New Relic Application from configuration.
// If New Relic is not enabled or the license key is missing, it returns nil, nil.
func InitNewRelic(cfg *config.Config) (*newrelic.Application, error) {
	if !cfg.NewRelicEnabled || cfg.NewRelicLicenseKey == "" {
		log.Println("[NewRelic] Monitoring is disabled (license key not provided or NEW_RELIC_ENABLED=false)")
		return nil, nil
	}

	opts := []newrelic.ConfigOption{
		newrelic.ConfigAppName(cfg.NewRelicAppName),
		newrelic.ConfigLicense(cfg.NewRelicLicenseKey),
		newrelic.ConfigDistributedTracerEnabled(true),
		newrelic.ConfigAppLogForwardingEnabled(true),
		newrelic.ConfigLabels(map[string]string{
			"environment": cfg.Environment,
		}),
	}

	app, err := newrelic.NewApplication(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize New Relic: %w", err)
	}

	log.Printf("[NewRelic] Monitoring initialized for application %q (environment: %s)", cfg.NewRelicAppName, cfg.Environment)
	return app, nil
}

// Middleware creates a Chi-compatible middleware that instruments HTTP transactions for New Relic.
func Middleware(app *newrelic.Application, env ...string) func(http.Handler) http.Handler {
	environment := ""
	if len(env) > 0 {
		environment = env[0]
	}

	return func(next http.Handler) http.Handler {
		if app == nil {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip health checks to avoid skewing throughput, error rates, and Apdex
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			// 1. Start New Relic transaction with method and initial request path
			txn := app.StartTransaction(r.Method + " " + r.URL.Path)
			defer txn.End()

			// 2. Wrap response writer and request with New Relic transaction
			wrappedWriter := txn.SetWebResponse(w)
			txn.SetWebRequestHTTP(r)
			r = newrelic.RequestWithTransactionContext(r, txn)

			// 3. Attach incoming request attributes (Environment, Request ID and Client IP)
			if environment != "" {
				txn.AddAttribute("environment", environment)
			}
			if reqID := middleware.GetReqID(r.Context()); reqID != "" {
				txn.AddAttribute("request.id", reqID)
			}
			if ip := core.ExtractClientIP(r); ip != "" {
				txn.AddAttribute("client.ip", ip)
			}

			// 4. Capture any panic and record to New Relic before re-panicking for Chi Recoverer
			defer func() {
				if rec := recover(); rec != nil {
					var err error
					if e, ok := rec.(error); ok {
						err = e
					} else {
						err = fmt.Errorf("panic: %v", rec)
					}
					txn.NoticeError(err)
					panic(rec)
				}
			}()

			// 5. Execute downstream handlers
			next.ServeHTTP(wrappedWriter, r)

			// 6. Update transaction name with Chi's parameterized route pattern (e.g. /users/{id})
			if rctx := chi.RouteContext(r.Context()); rctx != nil {
				if pattern := rctx.RoutePattern(); pattern != "" {
					txn.SetName(r.Method + " " + pattern)
				}
			}

			// 7. Attach application context attributes if identified during handler processing
			if clientID, appName := core.GetRequestApp(r.Context()); clientID != "" || appName != "" {
				if clientID != "" {
					txn.AddAttribute("app.client_id", clientID)
				}
				if appName != "" {
					txn.AddAttribute("app.name", appName)
				}
			}
		})
	}
}

// FromContext returns the active New Relic Transaction from context, or nil if not present.
func FromContext(ctx context.Context) *newrelic.Transaction {
	if ctx == nil {
		return nil
	}
	return newrelic.FromContext(ctx)
}

// NoticeError records an error in the active New Relic transaction if present.
func NoticeError(ctx context.Context, err error) {
	if err == nil || ctx == nil {
		return
	}
	if txn := newrelic.FromContext(ctx); txn != nil {
		txn.NoticeError(err)
	}
}

// SetUserID sets the authenticated user ID on the active New Relic transaction.
func SetUserID(ctx context.Context, userID string) {
	if userID == "" || ctx == nil {
		return
	}
	if txn := newrelic.FromContext(ctx); txn != nil {
		txn.SetUserID(userID)
	}
}

// AddAttribute attaches a custom key-value attribute to the active New Relic transaction.
func AddAttribute(ctx context.Context, key string, val any) {
	if key == "" || ctx == nil {
		return
	}
	if txn := newrelic.FromContext(ctx); txn != nil {
		txn.AddAttribute(key, val)
	}
}
