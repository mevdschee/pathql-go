package middleware

import (
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/mevdschee/pathql-go/internal/cache"
)

// genericRateLimited is the body returned on a 429 from the rate limiter. It is
// intentionally generic so it leaks nothing about limits or internal state.
const genericRateLimited = `{"type":"Error","message":"too many requests"}`

// RateLimitPerIP returns a fixed-window per-IP rate limiter. It allows up to
// perMinute requests per client IP per calendar minute, keying the counter as
// "ratelimit:<ip>:<unix-minute>" and seeding it with a one-minute TTL via
// cache.Increment. When the returned count exceeds perMinute it responds 429
// with a Retry-After header giving the seconds remaining until the next minute
// boundary and a generic JSON body. perMinute <= 0 disables limiting.
func RateLimitPerIP(c cache.Cache, perMinute int, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if perMinute <= 0 || c == nil {
			return next
		}
		limit := uint64(perMinute)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			now := time.Now()
			minute := now.Unix() / 60
			ip := ClientIP(r, trustedProxies)
			key := "ratelimit:" + ip + ":" + strconv.FormatInt(minute, 10)

			count, err := c.Increment(key, 1, time.Minute)
			if err != nil {
				// Fail open on cache errors: a cache hiccup should not take the
				// whole endpoint down, and the global/per-user caps still apply.
				next.ServeHTTP(w, r)
				return
			}
			if count > limit {
				retryAfter := secondsToNextMinute(now)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(genericRateLimited))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// secondsToNextMinute returns the whole seconds remaining until the next minute
// boundary (1..60), used for the Retry-After hint.
func secondsToNextMinute(now time.Time) int {
	next := now.Truncate(time.Minute).Add(time.Minute)
	secs := int(next.Sub(now).Seconds())
	if secs < 1 {
		secs = 1
	}
	return secs
}
