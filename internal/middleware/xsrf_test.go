package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// xsrfTokenFromSetCookie extracts the XSRF-TOKEN value from a recorder's
// Set-Cookie headers, or "" if none was set.
func xsrfTokenFromSetCookie(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == xsrfCookieName {
			return c.Value
		}
	}
	return ""
}

func TestXSRFDisabledIsPassthrough(t *testing.T) {
	h := XSRF(false)(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/pathql", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected passthrough 200 when disabled, got %d", rec.Code)
	}
	if xsrfTokenFromSetCookie(rec) != "" {
		t.Errorf("disabled middleware should not set a cookie")
	}
}

func TestXSRFSafeMethodSeedsCookie(t *testing.T) {
	h := XSRF(true)(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/schema", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("safe method should pass, got %d", rec.Code)
	}
	if xsrfTokenFromSetCookie(rec) == "" {
		t.Errorf("expected a seeded XSRF-TOKEN cookie on a safe request without one")
	}
}

func TestXSRFUnsafeWithoutTokenRejected(t *testing.T) {
	h := XSRF(true)(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/pathql", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unsafe request without a token, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "XSRF") {
		t.Errorf("expected an XSRF error body, got %s", rec.Body.String())
	}
}

func TestXSRFUnsafeWithMatchingTokenPasses(t *testing.T) {
	h := XSRF(true)(okHandler())
	const token = "deadbeefcafebabedeadbeefcafebabe"

	req := httptest.NewRequest(http.MethodPost, "/pathql", nil)
	req.AddCookie(&http.Cookie{Name: xsrfCookieName, Value: token})
	req.Header.Set(xsrfHeaderName, token)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when header matches cookie, got %d", rec.Code)
	}
}

func TestXSRFUnsafeWithMismatchedTokenRejected(t *testing.T) {
	h := XSRF(true)(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/pathql", nil)
	req.AddCookie(&http.Cookie{Name: xsrfCookieName, Value: "cookie-token"})
	req.Header.Set(xsrfHeaderName, "different-header-token")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when header and cookie differ, got %d", rec.Code)
	}
}

// TestXSRFBootstrapFlow checks the intended client flow: a GET seeds the token,
// then a POST that echoes it is accepted.
func TestXSRFBootstrapFlow(t *testing.T) {
	h := XSRF(true)(okHandler())

	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/schema", nil))
	token := xsrfTokenFromSetCookie(getRec)
	if token == "" {
		t.Fatal("bootstrap GET did not seed a token")
	}

	postReq := httptest.NewRequest(http.MethodPost, "/pathql", nil)
	postReq.AddCookie(&http.Cookie{Name: xsrfCookieName, Value: token})
	postReq.Header.Set(xsrfHeaderName, token)
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusOK {
		t.Fatalf("expected the echoed token to be accepted, got %d", postRec.Code)
	}
}
