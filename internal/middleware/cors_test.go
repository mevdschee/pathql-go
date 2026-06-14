package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCORSAllowedOrigin(t *testing.T) {
	h := CORS([]string{"https://app.example.com", "https://admin.example.com"})(okHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q, want echoed origin", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestCORSDisallowedOrigin(t *testing.T) {
	h := CORS([]string{"https://app.example.com"})(okHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty for disallowed origin", got)
	}
	// Must never emit a wildcard.
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Errorf("Allow-Origin must never be '*'")
	}
}

func TestCORSPreflight(t *testing.T) {
	h := CORS([]string{"https://app.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("preflight should not reach the next handler")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("preflight Allow-Origin = %q", got)
	}
	methods := rec.Header().Get("Access-Control-Allow-Methods")
	if !strings.Contains(methods, "POST") || !strings.Contains(methods, "OPTIONS") {
		t.Errorf("Allow-Methods = %q, want POST and OPTIONS", methods)
	}
	headers := rec.Header().Get("Access-Control-Allow-Headers")
	for _, want := range []string{"Authorization", "Content-Type", "X-API-Key"} {
		if !strings.Contains(headers, want) {
			t.Errorf("Allow-Headers = %q, missing %q", headers, want)
		}
	}
}

func TestCORSNoOrigin(t *testing.T) {
	h := CORS([]string{"https://app.example.com"})(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty when no Origin", got)
	}
}
