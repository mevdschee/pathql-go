package middleware

import "net/http"

// corsAllowMethods and corsAllowHeaders are the fixed CORS allowances for the
// pathql endpoint: it only accepts POST (and OPTIONS preflight), and the auth /
// content headers the client may send.
const (
	corsAllowMethods = "POST, OPTIONS"
	corsAllowHeaders = "Authorization, Content-Type, X-API-Key"
)

// CORS returns middleware that echoes the request Origin in
// Access-Control-Allow-Origin only when it exactly matches one of
// allowedOrigins, and sets the allowed methods/headers. A cross-origin preflight
// (OPTIONS) is answered directly with 204. The wildcard "*" is never emitted, so
// the response is always safe to combine with credentialed requests. Requests
// without an Origin, or with a disallowed Origin, pass through unchanged (the
// missing CORS header causes the browser to block the cross-origin read).
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o != "" && o != "*" {
			allowed[o] = struct{}{}
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if _, ok := allowed[origin]; ok {
					h := w.Header()
					// Vary so caches key the CORS decision per Origin.
					h.Add("Vary", "Origin")
					h.Set("Access-Control-Allow-Origin", origin)
					h.Set("Access-Control-Allow-Methods", corsAllowMethods)
					h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
				}
			}

			if r.Method == http.MethodOptions {
				// Preflight (or any OPTIONS): answer directly, never reaching the
				// downstream handler.
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
