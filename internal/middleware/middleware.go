// Package middleware provides small, independent HTTP middlewares used by the
// pathql-server request lifecycle: panic recovery, request body size limiting,
// security headers, and request-id propagation. None of these depend on other
// internal packages so they can be built and tested in isolation.
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"runtime/debug"
)

// genericInternalError is the only thing a client ever sees when a downstream
// handler panics. The panic value itself is logged server-side, never returned.
const genericInternalError = `{"type":"Error","message":"internal error"}`

// requestIDHeader is the canonical header carrying the per-request id.
const requestIDHeader = "X-Request-Id"

// recoverResponseWriter wraps http.ResponseWriter to track whether the response
// header has already been committed. Once a handler has started writing, Recover
// must not attempt to overwrite the status code or it would log a spurious
// "superfluous WriteHeader" and corrupt the response.
type recoverResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *recoverResponseWriter) WriteHeader(code int) {
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *recoverResponseWriter) Write(b []byte) (int, error) {
	// An implicit WriteHeader(200) happens on first Write; mark it committed.
	w.wroteHeader = true
	return w.ResponseWriter.Write(b)
}

// Recover catches panics in downstream handlers, logs them (with a stack trace
// via log.Printf), and writes a generic 500 JSON body. The panic value is never
// leaked to the client. If the downstream handler had already written the
// response header before panicking, Recover does not attempt to rewrite it.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &recoverResponseWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("middleware: recovered panic: %v\n%s", rec, debug.Stack())
				if !rw.wroteHeader {
					rw.Header().Set("Content-Type", "application/json")
					rw.WriteHeader(http.StatusInternalServerError)
					// Best effort; nothing useful to do if this fails.
					_, _ = rw.ResponseWriter.Write([]byte(genericInternalError))
				}
			}
		}()
		next.ServeHTTP(rw, r)
	})
}

// BodyLimit returns middleware that wraps the request body in
// http.MaxBytesReader(maxBytes) so that reads past the cap fail with an error
// and the connection is protected from oversized payloads.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders sets X-Content-Type-Options: nosniff and Cache-Control:
// no-store on every response so sensitive JSON is not sniffed or cached.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// RequestID ensures an X-Request-Id response header is present. An inbound
// X-Request-Id is preserved; otherwise a new one is generated from crypto/rand
// and hex-encoded. The header is set on the response (and visible to downstream
// handlers via w.Header) before next runs. Never uses math/rand or time seeds.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r)
	})
}

// newRequestID returns a 32-hex-char (16 byte) random id from crypto/rand.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read does not fail on supported platforms; if it ever
		// does, panic rather than emit a predictable/empty id. The Recover
		// middleware (outermost in the chain) turns this into a 500.
		panic("middleware: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
