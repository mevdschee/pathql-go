package middleware

import (
	"net/http"
	"sync"
)

// genericConcurrencyLimited is the body returned when a per-user concurrency cap
// is exceeded. genericOverloaded is returned when the global in-flight cap is
// reached. Both are intentionally generic.
const (
	genericConcurrencyLimited = `{"type":"Error","message":"too many concurrent requests"}`
	genericOverloaded         = `{"type":"Error","message":"server busy"}`
)

// retryAfterShort is the Retry-After hint (seconds) for transient concurrency
// rejections, where the client should retry almost immediately.
const retryAfterShort = "1"

// GlobalInflight caps the total number of concurrently in-flight requests using
// a buffered-channel semaphore of capacity max. A request that cannot acquire a
// slot immediately is rejected with 503 and a Retry-After header rather than
// queueing. max <= 0 disables the cap.
func GlobalInflight(max int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if max <= 0 {
			return next
		}
		sem := make(chan struct{}, max)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				next.ServeHTTP(w, r)
			default:
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", retryAfterShort)
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(genericOverloaded))
			}
		})
	}
}

// perUserState holds the per-key semaphore map for a PerUserConcurrency limiter.
// Each key maps to a buffered channel acting as a counting semaphore; the map
// entry is created lazily on first use and removed once the key's in-flight
// count returns to zero so memory stays bounded by the number of *active* keys.
type perUserState struct {
	max     int
	keyFunc func(*http.Request) string

	mu   sync.Mutex
	sems map[string]chan struct{}
}

// perUserMiddleware is the middleware constructor returned by perUserLimiter. It
// is a callable func type (so it composes like every other middleware here) that
// also carries an activeKeys method for test introspection.
type perUserMiddleware struct {
	st *perUserState
}

// apply applies the limiter to next. The constructor is a struct (rather than a
// bare func) so the activeKeys introspection method stays reachable.
func (m perUserMiddleware) apply(next http.Handler) http.Handler {
	return m.st.handler(next)
}

// activeKeys reports the number of keys currently holding a semaphore. After all
// requests for every key complete this must be zero.
func (m perUserMiddleware) activeKeys() int {
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	return len(m.st.sems)
}

// perUserLimiter builds the limiter state and returns its middleware
// constructor. It is the internal entry point; PerUserConcurrency adapts it to
// the package's standard func(http.Handler) http.Handler shape.
func perUserLimiter(maxPerUser int, keyFunc func(*http.Request) string) perUserMiddleware {
	return perUserMiddleware{st: &perUserState{
		max:     maxPerUser,
		keyFunc: keyFunc,
		sems:    make(map[string]chan struct{}),
	}}
}

// acquire attempts to take a slot for key. It returns ok=false when the key is
// already at capacity. A successfully acquired slot must be paired with release.
func (s *perUserState) acquire(key string) bool {
	s.mu.Lock()
	sem, exists := s.sems[key]
	if !exists {
		sem = make(chan struct{}, s.max)
		s.sems[key] = sem
	}
	s.mu.Unlock()

	select {
	case sem <- struct{}{}:
		return true
	default:
		// Could not acquire. If we just created an empty semaphore, drop it so a
		// failed acquire on a brand-new key does not leak a map entry.
		s.mu.Lock()
		if !exists && len(sem) == 0 {
			if cur, ok := s.sems[key]; ok && cur == sem {
				delete(s.sems, key)
			}
		}
		s.mu.Unlock()
		return false
	}
}

// release returns a slot for key and removes the map entry once the key has no
// in-flight requests, bounding memory to the set of currently active keys.
func (s *perUserState) release(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sem, ok := s.sems[key]
	if !ok {
		return
	}
	<-sem
	if len(sem) == 0 {
		delete(s.sems, key)
	}
}

// handler wraps next with the per-key concurrency cap.
func (s *perUserState) handler(next http.Handler) http.Handler {
	if s.max <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := s.keyFunc(r)
		if key == "" {
			// No key => not limited (e.g. unauthenticated requests).
			next.ServeHTTP(w, r)
			return
		}
		if !s.acquire(key) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", retryAfterShort)
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(genericConcurrencyLimited))
			return
		}
		defer s.release(key)
		next.ServeHTTP(w, r)
	})
}

// PerUserConcurrency caps concurrent in-flight requests per key. keyFunc extracts
// the key from each request; an empty key means the request is not limited. Over
// the cap a request is rejected with 429 and a Retry-After header. Per-key
// semaphores are created lazily and removed when a key's in-flight count returns
// to zero. maxPerUser <= 0 disables limiting.
func PerUserConcurrency(maxPerUser int, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	mw := perUserLimiter(maxPerUser, keyFunc)
	return mw.apply
}
