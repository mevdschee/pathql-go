package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecover(t *testing.T) {
	const secret = "boom-secret-panic-value"

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(secret)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	Recover(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Fatalf("response body leaked panic value: %q", body)
	}
	if !strings.Contains(body, `"type":"Error"`) {
		t.Errorf("body missing error type marker: %q", body)
	}
	if !strings.Contains(body, "internal error") {
		t.Errorf("body missing generic message: %q", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestRecoverNoPanicPassesThrough(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "ok")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	Recover(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
	if got := rec.Body.String(); got != "ok" {
		t.Fatalf("body = %q, want %q", got, "ok")
	}
}

func TestRecoverAfterPartialWrite(t *testing.T) {
	// Handler already wrote a header/body, then panics. Recover must not panic
	// itself trying to write the header twice.
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "partial")
		panic("late panic")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	// Must not panic.
	Recover(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (already committed)", rec.Code, http.StatusOK)
	}
	if strings.Contains(rec.Body.String(), "late panic") {
		t.Fatalf("response leaked panic value: %q", rec.Body.String())
	}
}

const bodyReadErrMarker = "BODY_READ_ERROR"

// bodyReadingHandler reads the entire request body and writes a marker if the
// read fails (e.g. MaxBytesReader tripped).
func bodyReadingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, bodyReadErrMarker, http.StatusRequestEntityTooLarge)
			return
		}
		_, _ = io.WriteString(w, "READ_OK")
	})
}

func TestBodyLimitOversized(t *testing.T) {
	const cap = 16
	h := BodyLimit(cap)(bodyReadingHandler())

	big := strings.NewReader(strings.Repeat("x", cap+100))
	req := httptest.NewRequest(http.MethodPost, "/", big)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), bodyReadErrMarker) {
		t.Fatalf("oversized body did not trigger read error; body = %q", rec.Body.String())
	}
}

func TestBodyLimitSmallPasses(t *testing.T) {
	const cap = 1024
	h := BodyLimit(cap)(bodyReadingHandler())

	small := strings.NewReader("hello")
	req := httptest.NewRequest(http.MethodPost, "/", small)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "READ_OK") {
		t.Fatalf("small body did not pass; body = %q", rec.Body.String())
	}
}

func TestSecurityHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(next).ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func TestRequestIDGeneratedWhenAbsent(t *testing.T) {
	var seenInHandler string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenInHandler = w.Header().Get("X-Request-Id")
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	RequestID(next).ServeHTTP(rec, req)

	got := rec.Header().Get("X-Request-Id")
	if got == "" {
		t.Fatalf("X-Request-Id response header is empty, want generated value")
	}
	if seenInHandler != got {
		t.Errorf("handler saw %q but response had %q", seenInHandler, got)
	}
	// hex-only check (crypto/rand hex output).
	for _, c := range got {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("generated id %q contains non-hex char %q", got, c)
		}
	}
}

func TestRequestIDUnique(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		RequestID(next).ServeHTTP(rec, req)
		id := rec.Header().Get("X-Request-Id")
		if id == "" {
			t.Fatalf("empty id on iteration %d", i)
		}
		if ids[id] {
			t.Fatalf("duplicate generated id %q", id)
		}
		ids[id] = true
	}
}

func TestRequestIDPreservedWhenSupplied(t *testing.T) {
	const inbound = "client-supplied-request-id-123"

	var seenInHandler string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenInHandler = w.Header().Get("X-Request-Id")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", inbound)

	RequestID(next).ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-Id"); got != inbound {
		t.Errorf("response X-Request-Id = %q, want preserved %q", got, inbound)
	}
	if seenInHandler != inbound {
		t.Errorf("handler saw X-Request-Id %q, want %q", seenInHandler, inbound)
	}
}
