package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHSTS(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	HSTS(okHandler()).ServeHTTP(rec, req)

	got := rec.Header().Get("Strict-Transport-Security")
	if got != "max-age=31536000; includeSubDomains" {
		t.Errorf("HSTS header = %q", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequireContentTypeJSON(t *testing.T) {
	h := RequireContentTypeJSON(okHandler())

	t.Run("text/plain POST rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x"))
		req.Header.Set("Content-Type", "text/plain")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("status = %d, want 415", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("error Content-Type = %q, want application/json", ct)
		}
	})

	t.Run("application/json POST passes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("application/json with charset passes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("GET passes without Content-Type", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("PUT with wrong type rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader("x"))
		req.Header.Set("Content-Type", "text/xml")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("status = %d, want 415", rec.Code)
		}
	})

	t.Run("POST with missing Content-Type rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
		req.Header.Del("Content-Type")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("status = %d, want 415", rec.Code)
		}
	})
}
