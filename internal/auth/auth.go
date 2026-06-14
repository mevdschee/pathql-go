// Package auth implements pluggable authentication for pathql-server. It
// resolves an incoming HTTP request to a Principal using a chain of
// Authenticators (API key, HTTP Basic). It does NOT push the identity into the
// database; that is the RLS / session-variable concern of a later phase.
//
// Security properties:
//   - Uniform ErrUnauthorized for every failure; the client never learns which
//     field was wrong (no user/key enumeration).
//   - Constant-time comparison of secrets (crypto/subtle for API-key hashes,
//     bcrypt's own constant-time compare for passwords, with a dummy compare on
//     unknown/empty-hash users to keep timing roughly constant).
//   - Fail closed: any error path denies.
package auth

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
)

// Principal is the authenticated identity resolved from a request.
type Principal struct {
	AppUser string   // value destined for the RLS session variable
	UserID  int64    // database id of the user row
	Scopes  []string // reserved for future scope-based authorization
}

// ErrNoCredentials means this method does not apply to the request, so the
// chain should try the next method.
var ErrNoCredentials = errors.New("auth: no credentials for this method")

// ErrUnauthorized is the generic auth failure (bad key, bad password, disabled,
// expired, unknown user). NEVER distinguish these to the client.
var ErrUnauthorized = errors.New("auth: unauthorized")

// Authenticator resolves a request to a Principal, or returns ErrNoCredentials
// if the method does not apply (so the chain can try the next method).
type Authenticator interface {
	Authenticate(r *http.Request) (*Principal, error)
}

// ---- metrics ----

var (
	authSuccess uint64
	authFailure uint64
)

// AuthSuccessCount returns the number of successful authentications.
func AuthSuccessCount() uint64 { return atomic.LoadUint64(&authSuccess) }

// AuthFailureCount returns the number of failed authentications.
func AuthFailureCount() uint64 { return atomic.LoadUint64(&authFailure) }

// ---- context helpers ----

type principalCtxKey struct{}

// WithPrincipal returns a copy of ctx carrying the given Principal.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// FromContext extracts the Principal stored by WithPrincipal, if any.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(*Principal)
	return p, ok
}

// ---- chain ----

// Chain tries each authenticator in order; the first that returns a Principal
// wins.
type Chain struct {
	auths []Authenticator
}

// NewChain builds a Chain over the given authenticators, tried in order.
func NewChain(auths ...Authenticator) *Chain {
	return &Chain{auths: auths}
}

// Authenticate runs the chain. A method returning ErrNoCredentials is skipped.
// The first method that returns a Principal wins. If every method returns
// ErrNoCredentials the result is ErrNoCredentials. If at least one method
// returned a non-ErrNoCredentials error and none succeeded, the result is the
// generic ErrUnauthorized.
func (c *Chain) Authenticate(r *http.Request) (*Principal, error) {
	sawFailure := false
	for _, a := range c.auths {
		p, err := a.Authenticate(r)
		if err == nil {
			return p, nil
		}
		if errors.Is(err, ErrNoCredentials) {
			continue
		}
		// A real failure (bad credentials). Keep trying later methods in case
		// another scheme on the same request succeeds, but remember the failure.
		sawFailure = true
	}
	if sawFailure {
		return nil, ErrUnauthorized
	}
	return nil, ErrNoCredentials
}

// Middleware enforces authentication. On success it stores the Principal on the
// request context and calls next. Otherwise it writes a 401 with a generic JSON
// body, a WWW-Authenticate header, and Content-Type application/json. It tracks
// success/failure counters.
func (c *Chain) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := c.Authenticate(r)
		if err != nil {
			atomic.AddUint64(&authFailure, 1)
			writeUnauthorized(w)
			return
		}
		atomic.AddUint64(&authSuccess, 1)
		ctx := WithPrincipal(r.Context(), p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// unauthorizedBody is the fixed generic 401 body. It carries no information
// about which credential failed.
const unauthorizedBody = `{"type":"Error","message":"unauthorized"}`

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	// A WWW-Authenticate header is required on a 401. Advertise both supported
	// challenge schemes without leaking any realm-specific detail.
	w.Header().Set("WWW-Authenticate", `Basic realm="pathql", ApiKey`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(unauthorizedBody))
}
