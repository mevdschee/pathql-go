package middleware

import (
	"mime"
	"net/http"
)

// hstsValue is the Strict-Transport-Security policy: one year, all subdomains.
const hstsValue = "max-age=31536000; includeSubDomains"

// genericUnsupportedMedia is the body returned when a write request does not
// carry a JSON Content-Type.
const genericUnsupportedMedia = `{"type":"Error","message":"unsupported media type"}`

// HSTS sets the Strict-Transport-Security header instructing browsers to use
// HTTPS for this host (and subdomains) for a year. It is only meaningful over
// TLS; the integration applies it when TLS is enabled.
func HSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", hstsValue)
		next.ServeHTTP(w, r)
	})
}

// RequireContentTypeJSON rejects write requests (POST/PUT/PATCH) whose body is
// not declared as application/json with 415 and a generic JSON body. A
// "; charset=..." parameter is tolerated. Read and other methods (GET, OPTIONS,
// DELETE, HEAD) pass through regardless of Content-Type.
func RequireContentTypeJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mediaType != "application/json" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnsupportedMediaType)
				_, _ = w.Write([]byte(genericUnsupportedMedia))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
