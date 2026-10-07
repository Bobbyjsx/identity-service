package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type BenchResult struct {
	Name        string
	Concurrency int
	TotalReqs   int
	Duration    time.Duration
	RPS         float64
	Min         time.Duration
	Mean        time.Duration
	P50         time.Duration
	P90         time.Duration
	P95         time.Duration
	P99         time.Duration
	Max         time.Duration
	Errors      int
}

func runBenchmark(name string, totalReqs int, concurrency int, reqFn func() (*http.Request, error)) BenchResult {
	latencies := make([]time.Duration, 0, totalReqs)
	var mu sync.Mutex
	var errCount int

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        concurrency * 2,
			MaxIdleConnsPerHost: concurrency * 2,
			IdleConnTimeout:     30 * time.Second,
		},
		Timeout: 10 * time.Second,
	}

	workChan := make(chan int, totalReqs)
	for i := 0; i < totalReqs; i++ {
		workChan <- i
	}
	close(workChan)

	start := time.Now()
	var wg sync.WaitGroup

	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range workChan {
				req, err := reqFn()
				if err != nil {
					mu.Lock()
					errCount++
					mu.Unlock()
					continue
				}

				t0 := time.Now()
				resp, err := client.Do(req)
				dur := time.Since(t0)

				if err != nil || resp.StatusCode >= 400 {
					mu.Lock()
					errCount++
					mu.Unlock()
				} else {
					_, _ = io.Copy(io.Discard, resp.Body)
				}
				if resp != nil {
					_ = resp.Body.Close()
				}

				mu.Lock()
				latencies = append(latencies, dur)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	totalDur := time.Since(start)

	if len(latencies) == 0 {
		return BenchResult{Name: name, Concurrency: concurrency, TotalReqs: totalReqs, Errors: errCount}
	}

	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}

	mean := sum / time.Duration(len(latencies))
	min := latencies[0]
	max := latencies[len(latencies)-1]
	p50 := latencies[int(float64(len(latencies))*0.50)]
	p90 := latencies[int(float64(len(latencies))*0.90)]
	p95 := latencies[int(float64(len(latencies))*0.95)]
	p99 := latencies[int(float64(len(latencies))*0.99)]

	rps := float64(len(latencies)) / totalDur.Seconds()

	return BenchResult{
		Name:        name,
		Concurrency: concurrency,
		TotalReqs:   totalReqs,
		Duration:    totalDur,
		RPS:         rps,
		Min:         min,
		Mean:        mean,
		P50:         p50,
		P90:         p90,
		P95:         p95,
		P99:         p99,
		Max:         max,
		Errors:      errCount,
	}
}

func setupFixtures(baseURL, adminToken string) (clientID, clientSecret, sessionID string, err error) {
	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Create Application
	appBody := []byte(`{
		"name": "Benchmark App",
		"oauth": {
			"redirect_uris": ["https://example.com/callback"],
			"allowed_scopes": ["openid", "profile", "email"],
			"allowed_grants": ["authorization_code", "client_credentials"]
		}
	}`)
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/admin/applications", bytes.NewReader(appBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", adminToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("create app error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", "", fmt.Errorf("create app failed (HTTP %d): %s", resp.StatusCode, string(body))
	}
	var creds struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return "", "", "", fmt.Errorf("decode app error: %w", err)
	}
	clientID = creds.ClientID
	clientSecret = creds.ClientSecret

	// 2. Create Auth Session
	sessBody := []byte(fmt.Sprintf(`{
		"client_id": %q,
		"redirect_uri": "https://example.com/callback",
		"response_type": "code",
		"code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		"code_challenge_method": "S256"
	}`, clientID))
	reqSess, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/admin/auth-sessions", bytes.NewReader(sessBody))
	reqSess.Header.Set("Content-Type", "application/json")
	reqSess.Header.Set("X-Admin-Token", adminToken)

	respSess, err := client.Do(reqSess)
	if err != nil {
		return clientID, clientSecret, "", fmt.Errorf("create session error: %w", err)
	}
	defer respSess.Body.Close()
	if respSess.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respSess.Body)
		return clientID, clientSecret, "", fmt.Errorf("create session failed (HTTP %d): %s", respSess.StatusCode, string(body))
	}
	var sess struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(respSess.Body).Decode(&sess); err != nil {
		return clientID, clientSecret, "", fmt.Errorf("decode session error: %w", err)
	}
	sessionID = sess.SessionID

	return clientID, clientSecret, sessionID, nil
}

func main() {
	baseURL := flag.String("url", "http://127.0.0.1:8002", "Target server base URL")
	label := flag.String("label", "Target", "Label for target")
	adminToken := flag.String("admin-token", "v7Ea08wdPPjU+v/PpBF92K/GB3WnWUPAeJ/Mw0apJ6Y=", "Admin secret token")
	jsonOutput := flag.Bool("json", false, "Output results as JSON")
	flag.Parse()

	if envToken := os.Getenv("ADMIN_SECRET"); envToken != "" && *adminToken == "v7Ea08wdPPjU+v/PpBF92K/GB3WnWUPAeJ/Mw0apJ6Y=" {
		*adminToken = envToken
	}

	// Wait for server ready
	client := &http.Client{Timeout: 2 * time.Second}
	var ready bool
	for i := 0; i < 30; i++ {
		resp, err := client.Get(*baseURL + "/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			ready = true
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ready {
		fmt.Fprintf(os.Stderr, "Server at %s not ready\n", *baseURL)
		os.Exit(1)
	}

	clientID, clientSecret, sessionID, err := setupFixtures(*baseURL, *adminToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup fixtures: %v\n", err)
		os.Exit(1)
	}

	var results []BenchResult

	// Benchmark 1: GET /health (Concurrency 1)
	results = append(results, runBenchmark("GET /health (c=1)", 1000, 1, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, *baseURL+"/health", nil)
	}))

	// Benchmark 2: GET /health (Concurrency 20)
	results = append(results, runBenchmark("GET /health (c=20)", 2000, 20, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, *baseURL+"/health", nil)
	}))

	// Benchmark 3: GET /.well-known/openid-configuration (Concurrency 20)
	results = append(results, runBenchmark("GET /.well-known/openid-configuration (c=20)", 1000, 20, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, *baseURL+"/.well-known/openid-configuration", nil)
	}))

	// Benchmark 4: GET /.well-known/jwks.json (Firestore read, Concurrency 10)
	results = append(results, runBenchmark("GET /.well-known/jwks.json (c=10)", 500, 10, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, *baseURL+"/.well-known/jwks.json", nil)
	}))

	// Benchmark 5: GET /api/v1/auth-sessions/{id} (Multi-doc read, Concurrency 10)
	results = append(results, runBenchmark("GET /api/v1/auth-sessions/{id} (c=10)", 500, 10, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, *baseURL+"/api/v1/auth-sessions/"+sessionID, nil)
	}))

	// Benchmark 6: POST /api/v1/oauth/token client_credentials (DB check + Ed25519 signing, Concurrency 10)
	results = append(results, runBenchmark("POST /api/v1/oauth/token [client_credentials] (c=10)", 300, 10, func() (*http.Request, error) {
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
		data.Set("audience", "https://api.example.com")
		req, err := http.NewRequest(http.MethodPost, *baseURL+"/api/v1/oauth/token", strings.NewReader(data.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		return req, err
	}))

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}

	fmt.Printf("\n### Benchmark Results: %s (%s)\n\n", *label, *baseURL)
	fmt.Println("| Endpoint & Concurrency | Requests | Req/Sec | Mean | Median (p50) | p95 | p99 | Errors |")
	fmt.Println("|---|---|---|---|---|---|---|---|")
	for _, r := range results {
		fmt.Printf("| %s | %d | %.1f | %v | %v | %v | %v | %d |\n",
			r.Name, r.TotalReqs, r.RPS, formatDuration(r.Mean), formatDuration(r.P50), formatDuration(r.P95), formatDuration(r.P99), r.Errors)
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.0fµs", float64(d.Microseconds()))
	}
	return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000.0)
}
