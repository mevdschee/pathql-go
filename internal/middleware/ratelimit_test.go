package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/mevdschee/pathql-go/internal/cache"
)

func newTestCache(t *testing.T) cache.Cache {
	t.Helper()
	c, err := cache.NewEmbedded(8)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRateLimitPerIP(t *testing.T) {
	c := newTestCache(t)
	const perMinute = 3
	h := RateLimitPerIP(c, perMinute, nil)(okHandler())

	do := func(remoteAddr string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = remoteAddr
		h.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < perMinute; i++ {
		if rec := do("198.51.100.1:1111"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rec.Code)
		}
	}

	rec := do("198.51.100.1:1111")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit status = %d, want 429", rec.Code)
	}
	ra := rec.Header().Get("Retry-After")
	if ra == "" {
		t.Errorf("missing Retry-After header")
	} else if secs, err := strconv.Atoi(ra); err != nil || secs < 0 || secs > 60 {
		t.Errorf("Retry-After = %q, want 0..60 seconds", ra)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// A different IP is independent.
	if rec := do("198.51.100.2:2222"); rec.Code != http.StatusOK {
		t.Errorf("different IP status = %d, want 200", rec.Code)
	}
}

func TestRateLimitPerIPDisabled(t *testing.T) {
	c := newTestCache(t)
	h := RateLimitPerIP(c, 0, nil)(okHandler())
	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.RemoteAddr = "198.51.100.9:1111"
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("disabled limiter blocked request %d: %d", i+1, rec.Code)
		}
	}
}
