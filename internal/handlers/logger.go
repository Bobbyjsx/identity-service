package handlers

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"identity-service/internal/core"
)

var logChan = make(chan string, 20000)

func init() {
	go func() {
		for msg := range logChan {
			log.Print(msg)
		}
	}()
}

func formatRequestDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.0fµs", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000.0)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func AppLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		defaultClientID := ""
		if appID := r.Header.Get("X-Application-Id"); appID != "" {
			defaultClientID = appID
		} else if clientID := r.URL.Query().Get("client_id"); clientID != "" {
			defaultClientID = clientID
		}

		ctx, _ := core.InitRequestApp(r.Context(), defaultClientID)
		r = r.WithContext(ctx)

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()

		next.ServeHTTP(ww, r)

		elapsed := time.Since(start)

		clientID, appName := core.GetRequestApp(r.Context())
		if clientID == "" && defaultClientID != "" {
			clientID = defaultClientID
		}

		appDesc := "-"
		if appName != "" && clientID != "" {
			appDesc = fmt.Sprintf("%q (%s)", appName, clientID)
		} else if clientID != "" {
			appDesc = clientID
		} else if appName != "" {
			appDesc = fmt.Sprintf("%q", appName)
		}

		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}

		ip := core.ExtractClientIP(r)
		reqID := middleware.GetReqID(r.Context())

		var msg string
		if reqID != "" {
			msg = fmt.Sprintf("[HTTP] %s %s -> %d (%dB) in %s [app: %s] [ip: %s] [req: %s]",
				r.Method, r.URL.Path, status, ww.BytesWritten(), formatRequestDuration(elapsed), appDesc, ip, reqID)
		} else {
			msg = fmt.Sprintf("[HTTP] %s %s -> %d (%dB) in %s [app: %s] [ip: %s]",
				r.Method, r.URL.Path, status, ww.BytesWritten(), formatRequestDuration(elapsed), appDesc, ip)
		}

		select {
		case logChan <- msg:
		default:
			// If buffer is saturated during high-pressure load spikes, don't stall request execution
		}
	})
}
