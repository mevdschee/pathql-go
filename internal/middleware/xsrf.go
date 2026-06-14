package middleware

import (
	"crypto/subtle"
	"net/http"
)

// xsrfCookieName / xsrfHeaderName are the double-submit pair: the server seeds a
// random token in the cookie, and a browser client must echo it back in the
// header on every state-changing request. These names match the de-facto
// convention used by Angular and others.
const (
	xsrfCookieName = "XSRF-TOKEN"
	xsrfHeaderName = "X-XSRF-TOKEN"
)

// xsrfForbidden is the generic 403 body returned when the token is missing or
// does not match.
const xsrfForbidden = `{"type":"Error","message":"missing or invalid XSRF token"}`

// XSRF returns double-submit-cookie CSRF protection middleware. When enabled, a
// safe request (GET/HEAD/OPTIONS) that arrives without the token cookie is given
// a fresh one, so a browser client can read it and echo it back. A state-changing
// request (POST/PUT/PATCH/DELETE) is rejected with 403 unless it carries an
// X-XSRF-TOKEN header equal to the XSRF-TOKEN cookie. Because the same-origin
// policy stops a cross-site page from reading the cookie, only first-party code
// can produce a matching header. When disabled it is a no-op passthrough.
//
// This is defense in depth for cookie/Basic-credentialed browser deployments;
// the JSON content-type requirement and the locked-down CORS policy already make
// the API hard to drive from a cross-site form.
func XSRF(enabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ""
			if c, err := r.Cookie(xsrfCookieName); err == nil {
				token = c.Value
			}
			// Seed a token when none is present so a client can bootstrap by reading
			// the cookie from a safe request before issuing an unsafe one.
			if token == "" {
				token = newRequestID()
				setXSRFCookie(w, r, token)
			}

			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			sent := r.Header.Get(xsrfHeaderName)
			if sent == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(token)) != 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(xsrfForbidden))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// setXSRFCookie sets the token cookie. It is intentionally NOT HttpOnly because
// the client must read it to echo it in the header; SameSite=Strict and the
// Secure flag (over TLS) keep it from leaking cross-site.
func setXSRFCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     xsrfCookieName,
		Value:    token,
		Path:     "/",
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

// isSafeMethod reports whether the HTTP method is read-only and so exempt from
// the CSRF token check (per RFC 7231 safe methods).
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}
