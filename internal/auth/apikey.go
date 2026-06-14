package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"
)

// apiKeyPrefixLen is the number of leading characters of an API key used as the
// (non-secret) lookup prefix. The full key is still hashed and compared in
// constant time.
const apiKeyPrefixLen = 8

// apiKeyScheme is the Authorization scheme for API keys.
const apiKeyScheme = "ApiKey"

// APIKeyAuthenticator authenticates requests bearing an API key, either as
// "Authorization: ApiKey <key>" or in a configurable header (e.g. X-API-Key).
type APIKeyAuthenticator struct {
	store      UserStore
	headerName string
}

// NewAPIKeyAuthenticator builds an APIKeyAuthenticator backed by store. The key
// may be presented as "Authorization: ApiKey <key>" or in the header named
// headerName.
func NewAPIKeyAuthenticator(store UserStore, headerName string) *APIKeyAuthenticator {
	return &APIKeyAuthenticator{store: store, headerName: headerName}
}

// Authenticate resolves an API key to a Principal. Missing key ->
// ErrNoCredentials. Any verification failure -> ErrUnauthorized (generic, so the
// caller cannot tell unknown-prefix from bad-hash from disabled from expired).
func (a *APIKeyAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	key := a.extractKey(r)
	if key == "" {
		return nil, ErrNoCredentials
	}

	// A key shorter than the prefix length can never match a stored key.
	if len(key) < apiKeyPrefixLen {
		return nil, ErrUnauthorized
	}
	prefix := key[:apiKeyPrefixLen]

	rec, err := a.store.LookupAPIKeyByPrefix(r.Context(), prefix)
	if err != nil {
		// ErrNotFound or any store error -> generic failure.
		return nil, ErrUnauthorized
	}

	// Constant-time compare of the SHA-256 of the full key against the stored
	// hash. ConstantTimeCompare returns 0 on length mismatch, which is fine.
	sum := sha256.Sum256([]byte(key))
	if subtle.ConstantTimeCompare(sum[:], rec.KeyHash) != 1 {
		return nil, ErrUnauthorized
	}

	if !rec.Enabled {
		return nil, ErrUnauthorized
	}

	if rec.ExpiresAt != nil && !time.Now().Before(*rec.ExpiresAt) {
		return nil, ErrUnauthorized
	}

	// Best-effort, asynchronous last-used update. Use a detached context so it
	// is not cancelled when the request completes.
	a.touchAsync(rec.UserID, prefix)

	return &Principal{
		AppUser: rec.AppUser,
		UserID:  rec.UserID,
	}, nil
}

// extractKey returns the API key from the Authorization header (ApiKey scheme)
// or the configured header, or "" if neither is present.
func (a *APIKeyAuthenticator) extractKey(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		// Case-insensitive scheme match, e.g. "ApiKey <key>".
		if len(h) > len(apiKeyScheme) && strings.EqualFold(h[:len(apiKeyScheme)], apiKeyScheme) {
			rest := strings.TrimSpace(h[len(apiKeyScheme):])
			if rest != "" {
				return rest
			}
		}
	}
	if a.headerName != "" {
		if v := strings.TrimSpace(r.Header.Get(a.headerName)); v != "" {
			return v
		}
	}
	return ""
}

// touchAsync records last-used in the background. Errors are intentionally
// ignored (best effort) and must never affect the auth result.
func (a *APIKeyAuthenticator) touchAsync(userID int64, prefix string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.store.TouchAPIKey(ctx, userID, prefix)
	}()
}
