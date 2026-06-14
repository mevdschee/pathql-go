package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mevdschee/pathql-go/internal/cache"
)

// genericLockedOut is the body returned when a credential is temporarily locked
// out. It is generic so it leaks nothing about thresholds or which credential.
const genericLockedOut = `{"type":"Error","message":"too many failed attempts"}`

// BruteForceLockout limits authentication failures per credential within a fixed
// one-minute window. Before auth it derives a stable identifier from the request
// (API-key prefix, HTTP Basic username, or client IP). If that identifier has
// already failed maxFailures times this minute it rejects with 429 and a
// Retry-After header without running the auth chain. After auth it inspects the
// downstream status and, on a 401, increments the failure counter.
//
// It must wrap the auth middleware so it can observe the 401 the chain writes.
// maxFailures <= 0 or a nil cache disables it.
func BruteForceLockout(c cache.Cache, maxFailures int, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if maxFailures <= 0 || c == nil {
			return next
		}
		limit := uint64(maxFailures)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now := time.Now()
			minute := now.Unix() / 60
			id := lockoutID(r, trustedProxies)
			key := "authfail:" + id + ":" + strconv.FormatInt(minute, 10)

			// Read the running total without adding to it: delta 0 seeds the
			// window to 0 on first use and returns the current count.
			if count, err := c.Increment(key, 0, time.Minute); err == nil && count >= limit {
				retryAfter := secondsToNextMinute(now)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(genericLockedOut))
				return
			}

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			if sw.status == http.StatusUnauthorized {
				_, _ = c.Increment(key, 1, time.Minute)
			}
		})
	}
}

// statusWriter records the status code written by a downstream handler.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// lockoutID derives a stable per-credential identifier for the failure counter.
// It keys on the credential being presented (so one bad key or username is
// locked out regardless of source IP) and falls back to the client IP when no
// recognizable credential is present. A bearer token's identity is opaque before
// verification, so those fall back to the IP key rather than trusting an
// attacker-chosen value.
func lockoutID(r *http.Request, trustedProxies []*net.IPNet) string {
	if h := r.Header.Get("Authorization"); h != "" {
		lower := strings.ToLower(h)
		switch {
		case strings.HasPrefix(lower, "apikey "):
			if rest := strings.TrimSpace(h[len("apikey"):]); rest != "" {
				return "k:" + keyPrefix(rest)
			}
		case strings.HasPrefix(lower, "basic "):
			if user, _, ok := r.BasicAuth(); ok && user != "" {
				return "u:" + user
			}
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-API-Key")); v != "" {
		return "k:" + keyPrefix(v)
	}
	return "ip:" + ClientIP(r, trustedProxies)
}

// keyPrefix returns the first 8 characters of an API key (the same non-secret
// prefix used to look it up), so the counter key never holds a full secret.
func keyPrefix(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}
