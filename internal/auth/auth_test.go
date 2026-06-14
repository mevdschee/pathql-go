package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// fakeStore is an in-memory UserStore for tests.
type fakeStore struct {
	mu sync.Mutex

	// keys indexed by prefix
	keys map[string]*APIKeyRecord
	// users indexed by username
	users map[string]*UserRecord

	touchCalls int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		keys:  map[string]*APIKeyRecord{},
		users: map[string]*UserRecord{},
	}
}

func (f *fakeStore) LookupAPIKeyByPrefix(ctx context.Context, prefix string) (*APIKeyRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.keys[prefix]
	if !ok {
		return nil, ErrNotFound
	}
	// return a copy
	cp := *rec
	return &cp, nil
}

func (f *fakeStore) LookupUserByUsername(ctx context.Context, username string) (*UserRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.users[username]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *rec
	return &cp, nil
}

func (f *fakeStore) TouchAPIKey(ctx context.Context, userID int64, prefix string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touchCalls++
	return nil
}

func (f *fakeStore) touched() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.touchCalls
}

// helper: build an APIKeyRecord for the given full key.
func (f *fakeStore) addKey(fullKey string, userID int64, appUser string, enabled bool, expiresAt *time.Time) {
	sum := sha256.Sum256([]byte(fullKey))
	prefix := fullKey[:apiKeyPrefixLen]
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[prefix] = &APIKeyRecord{
		UserID:    userID,
		AppUser:   appUser,
		KeyHash:   sum[:],
		Enabled:   enabled,
		ExpiresAt: expiresAt,
	}
}

func (f *fakeStore) addUser(username, password, appUser string, userID int64, enabled bool) {
	var hash string
	if password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			panic(err)
		}
		hash = string(h)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[username] = &UserRecord{
		UserID:       userID,
		Username:     username,
		PasswordHash: hash,
		AppUser:      appUser,
		Enabled:      enabled,
	}
}

// ---- API key authenticator ----

func TestAPIKey_HappyPath_AuthorizationHeader(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	const key = "abcd1234supersecretkeyvalue"
	store.addKey(key, 7, "alice", true, nil)

	a := NewAPIKeyAuthenticator(store, "X-API-Key")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "ApiKey "+key)

	p, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil || p.AppUser != "alice" || p.UserID != 7 {
		t.Fatalf("unexpected principal: %+v", p)
	}

	// TouchAPIKey is async; wait briefly for it to land.
	deadline := time.Now().Add(time.Second)
	for store.touched() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if store.touched() == 0 {
		t.Fatalf("expected TouchAPIKey to be called asynchronously")
	}
}

func TestAPIKey_HappyPath_CustomHeader(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	const key = "headerkey0123456789abcdef"
	store.addKey(key, 1, "bob", true, nil)

	a := NewAPIKeyAuthenticator(store, "X-API-Key")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("X-API-Key", key)

	p, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.AppUser != "bob" {
		t.Fatalf("unexpected principal: %+v", p)
	}
}

func TestAPIKey_WrongKeySamePrefix(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	const realKey = "prefix12-real-key-material-here"
	store.addKey(realKey, 1, "alice", true, nil)

	// Wrong key sharing the same 8-char prefix.
	wrong := "prefix12-WRONG-key-material-xxxx"
	if wrong[:apiKeyPrefixLen] != realKey[:apiKeyPrefixLen] {
		t.Fatalf("test setup: prefixes differ")
	}

	a := NewAPIKeyAuthenticator(store, "X-API-Key")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "ApiKey "+wrong)

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestAPIKey_UnknownPrefix(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	a := NewAPIKeyAuthenticator(store, "X-API-Key")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "ApiKey unknownkey0000000000")

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestAPIKey_Disabled(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	const key = "disabled1234567890abcdef"
	store.addKey(key, 1, "alice", false, nil)

	a := NewAPIKeyAuthenticator(store, "X-API-Key")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "ApiKey "+key)

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestAPIKey_Expired(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	const key = "expired12345678901234567"
	past := time.Now().Add(-time.Hour)
	store.addKey(key, 1, "alice", true, &past)

	a := NewAPIKeyAuthenticator(store, "X-API-Key")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "ApiKey "+key)

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestAPIKey_NotExpired_FutureExpiry(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	const key = "future123456789012345678"
	future := time.Now().Add(time.Hour)
	store.addKey(key, 3, "carol", true, &future)

	a := NewAPIKeyAuthenticator(store, "X-API-Key")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "ApiKey "+key)

	p, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.AppUser != "carol" {
		t.Fatalf("unexpected principal: %+v", p)
	}
}

func TestAPIKey_MissingHeader(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	a := NewAPIKeyAuthenticator(store, "X-API-Key")
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("expected ErrNoCredentials, got %v", err)
	}
}

func TestAPIKey_KeyShorterThanPrefix(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	a := NewAPIKeyAuthenticator(store, "X-API-Key")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "ApiKey short")

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for too-short key, got %v", err)
	}
}

// ---- Basic authenticator ----

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestBasic_HappyPath(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.addUser("alice", "s3cret", "alice-app", 42, true)

	a := NewBasicAuthenticator(store)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", basicHeader("alice", "s3cret"))

	p, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.AppUser != "alice-app" || p.UserID != 42 {
		t.Fatalf("unexpected principal: %+v", p)
	}
}

func TestBasic_WrongPassword(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.addUser("alice", "s3cret", "alice-app", 42, true)

	a := NewBasicAuthenticator(store)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", basicHeader("alice", "wrong"))

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestBasic_UnknownUser(t *testing.T) {
	t.Parallel()
	store := newFakeStore()

	a := NewBasicAuthenticator(store)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", basicHeader("ghost", "whatever"))

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestBasic_EmptyPasswordHashUser(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	// user exists but has no password hash (Basic disabled for them)
	store.addUser("alice", "", "alice-app", 42, true)

	a := NewBasicAuthenticator(store)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", basicHeader("alice", "anything"))

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestBasic_Disabled(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.addUser("alice", "s3cret", "alice-app", 42, false)

	a := NewBasicAuthenticator(store)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", basicHeader("alice", "s3cret"))

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestBasic_MissingHeader(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	a := NewBasicAuthenticator(store)
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("expected ErrNoCredentials, got %v", err)
	}
}

func TestBasic_NotBasicScheme(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	a := NewBasicAuthenticator(store)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "Bearer sometoken")

	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("expected ErrNoCredentials for non-Basic scheme, got %v", err)
	}
}

// ---- Chain ----

func TestChain_APIKeyWins(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	const key = "chainkey0123456789abcdef"
	store.addKey(key, 1, "keyuser", true, nil)
	store.addUser("alice", "pw", "basicuser", 2, true)

	chain := NewChain(
		NewAPIKeyAuthenticator(store, "X-API-Key"),
		NewBasicAuthenticator(store),
	)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "ApiKey "+key)

	p, err := chain.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.AppUser != "keyuser" {
		t.Fatalf("expected API key to win, got %+v", p)
	}
}

func TestChain_FallsThroughToBasic(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.addUser("alice", "pw", "basicuser", 2, true)

	chain := NewChain(
		NewAPIKeyAuthenticator(store, "X-API-Key"),
		NewBasicAuthenticator(store),
	)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", basicHeader("alice", "pw"))

	p, err := chain.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.AppUser != "basicuser" {
		t.Fatalf("expected Basic to handle, got %+v", p)
	}
}

func TestChain_AllAbsent(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	chain := NewChain(
		NewAPIKeyAuthenticator(store, "X-API-Key"),
		NewBasicAuthenticator(store),
	)
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	_, err := chain.Authenticate(r)
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("expected ErrNoCredentials when no method applies, got %v", err)
	}
}

func TestChain_FailureBecomesUnauthorized(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.addUser("alice", "pw", "basicuser", 2, true)

	// Basic header with wrong password; API key not present.
	chain := NewChain(
		NewAPIKeyAuthenticator(store, "X-API-Key"),
		NewBasicAuthenticator(store),
	)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", basicHeader("alice", "nope"))

	_, err := chain.Authenticate(r)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestChain_EmptyChain(t *testing.T) {
	t.Parallel()
	chain := NewChain()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	_, err := chain.Authenticate(r)
	if !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("expected ErrNoCredentials for empty chain, got %v", err)
	}
}

// ---- Middleware ----

func TestMiddleware_SuccessSetsPrincipalAndCallsNext(t *testing.T) {
	store := newFakeStore()
	store.addUser("alice", "pw", "alice-app", 9, true)
	chain := NewChain(NewBasicAuthenticator(store))

	before := AuthSuccessCount()

	var gotPrincipal *Principal
	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		p, ok := FromContext(r.Context())
		if !ok {
			t.Errorf("principal not in context")
			return
		}
		gotPrincipal = p
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", basicHeader("alice", "pw"))

	chain.Middleware(next).ServeHTTP(rec, r)

	if !called {
		t.Fatalf("next handler not called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotPrincipal == nil || gotPrincipal.AppUser != "alice-app" {
		t.Fatalf("unexpected principal: %+v", gotPrincipal)
	}
	if AuthSuccessCount() != before+1 {
		t.Fatalf("expected success counter to increment")
	}
}

func TestMiddleware_FailureReturns401(t *testing.T) {
	store := newFakeStore()
	store.addUser("alice", "pw", "alice-app", 9, true)
	chain := NewChain(NewBasicAuthenticator(store))

	before := AuthFailureCount()

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Authorization", basicHeader("alice", "wrong"))

	chain.Middleware(next).ServeHTTP(rec, r)

	if called {
		t.Fatalf("next handler should not be called on failure")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatalf("expected WWW-Authenticate header")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json content type, got %q", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not valid JSON: %v (%q)", err, rec.Body.String())
	}
	if body["type"] != "Error" || body["message"] != "unauthorized" {
		t.Fatalf("unexpected body: %v", body)
	}
	if AuthFailureCount() != before+1 {
		t.Fatalf("expected failure counter to increment")
	}
}

func TestMiddleware_NoCredentialsReturns401(t *testing.T) {
	store := newFakeStore()
	chain := NewChain(NewBasicAuthenticator(store))

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	chain.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("next should not be called")
	})).ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no credentials, got %d", rec.Code)
	}
}

// ---- context helpers ----

func TestContextRoundTrip(t *testing.T) {
	t.Parallel()
	p := &Principal{AppUser: "x", UserID: 1}
	ctx := WithPrincipal(context.Background(), p)
	got, ok := FromContext(ctx)
	if !ok || got != p {
		t.Fatalf("round trip failed: %+v %v", got, ok)
	}

	if _, ok := FromContext(context.Background()); ok {
		t.Fatalf("expected no principal in empty context")
	}
}

// ---- NewSQLUserStore validation (no DB needed) ----

func TestNewSQLUserStore_InvalidPrefix(t *testing.T) {
	t.Parallel()
	bad := []string{"", "1abc", "a-b", "a;b", "drop table", "a b", "with$"}
	for _, p := range bad {
		if _, err := NewSQLUserStore(nil, p); err == nil {
			t.Errorf("expected error for invalid prefix %q", p)
		}
	}
}

func TestNewSQLUserStore_ValidPrefix(t *testing.T) {
	t.Parallel()
	good := []string{"pathql_auth_", "auth", "A1_b2", "_x"}
	for _, p := range good {
		// db is nil but construction should still succeed (no query run).
		if _, err := NewSQLUserStore(nil, p); err != nil {
			t.Errorf("unexpected error for valid prefix %q: %v", p, err)
		}
	}
}
