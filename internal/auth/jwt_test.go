package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mevdschee/pathql-go/internal/cache"
)

// --- helpers ---

// signHS256 builds and signs an HS256 token with the given claims and secret.
func signHS256(t *testing.T, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign HS256: %v", err)
	}
	return s
}

// bearer wraps a token string in an http.Request with an Authorization header.
func bearer(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/pathql", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// fakeUserStore is a minimal UserStore for RequireUserRow tests.
type fakeUserStore struct {
	users map[string]*UserRecord
}

func (f *fakeUserStore) LookupAPIKeyByPrefix(_ context.Context, _ string) (*APIKeyRecord, error) {
	return nil, ErrNotFound
}

func (f *fakeUserStore) LookupUserByUsername(_ context.Context, username string) (*UserRecord, error) {
	if u, ok := f.users[username]; ok {
		return u, nil
	}
	return nil, ErrNotFound
}

func (f *fakeUserStore) TouchAPIKey(_ context.Context, _ int64, _ string) error { return nil }

// --- HS256 tests ---

func TestJWT_HS256_Success(t *testing.T) {
	secret := []byte("super-secret-hs256-key")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
		UserClaim:   "sub",
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}

	token := signHS256(t, secret, jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	p, err := a.Authenticate(bearer(token))
	if err != nil {
		t.Fatalf("Authenticate: unexpected error %v", err)
	}
	if p.AppUser != "alice" {
		t.Fatalf("AppUser = %q, want %q", p.AppUser, "alice")
	}
}

func TestJWT_HS256_DefaultUserClaimIsSub(t *testing.T) {
	secret := []byte("super-secret-hs256-key")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
		// UserClaim intentionally empty -> default "sub".
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"sub": "bob",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	p, err := a.Authenticate(bearer(token))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.AppUser != "bob" {
		t.Fatalf("AppUser = %q, want %q", p.AppUser, "bob")
	}
}

func TestJWT_HS256_CustomUserClaim(t *testing.T) {
	secret := []byte("super-secret-hs256-key")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
		UserClaim:   "email",
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"sub":   "ignored",
		"email": "carol@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	p, err := a.Authenticate(bearer(token))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.AppUser != "carol@example.com" {
		t.Fatalf("AppUser = %q, want %q", p.AppUser, "carol@example.com")
	}
}

func TestJWT_HS256_WrongSecret(t *testing.T) {
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: []byte("the-real-secret"),
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, []byte("a-different-secret"), jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	_, err = a.Authenticate(bearer(token))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestJWT_HS256_AlgConfusion(t *testing.T) {
	// A token signed with a non-allowed algorithm must be rejected, even though
	// the authenticator only configured HS256. We sign with HS512 here; the
	// WithValidMethods restriction must reject it.
	secret := []byte("super-secret-hs256-key")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign HS512: %v", err)
	}
	_, err = a.Authenticate(bearer(token))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestJWT_HS256_NoneAlg(t *testing.T) {
	// The "none" algorithm must never be accepted.
	secret := []byte("super-secret-hs256-key")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	_, err = a.Authenticate(bearer(token))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestJWT_HS256_Expired(t *testing.T) {
	secret := []byte("super-secret-hs256-key")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	_, err = a.Authenticate(bearer(token))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestJWT_HS256_NotYetValid(t *testing.T) {
	secret := []byte("super-secret-hs256-key")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"sub": "alice",
		"nbf": time.Now().Add(time.Hour).Unix(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
	})
	_, err = a.Authenticate(bearer(token))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestJWT_HS256_WrongIssuer(t *testing.T) {
	secret := []byte("super-secret-hs256-key")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
		Issuer:      "https://issuer.example.com",
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"sub": "alice",
		"iss": "https://evil.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	_, err = a.Authenticate(bearer(token))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestJWT_HS256_GoodIssuer(t *testing.T) {
	secret := []byte("super-secret-hs256-key")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
		Issuer:      "https://issuer.example.com",
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"sub": "alice",
		"iss": "https://issuer.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := a.Authenticate(bearer(token)); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

func TestJWT_HS256_WrongAudience(t *testing.T) {
	secret := []byte("super-secret-hs256-key")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
		Audience:    "my-api",
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"sub": "alice",
		"aud": "some-other-api",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	_, err = a.Authenticate(bearer(token))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestJWT_HS256_GoodAudience(t *testing.T) {
	secret := []byte("super-secret-hs256-key")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
		Audience:    "my-api",
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"sub": "alice",
		"aud": "my-api",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := a.Authenticate(bearer(token)); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

func TestJWT_NoBearer(t *testing.T) {
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: []byte("secret"),
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}

	// No Authorization header at all.
	if _, err := a.Authenticate(bearer("")); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("no header: err = %v, want ErrNoCredentials", err)
	}

	// Non-Bearer scheme.
	r := httptest.NewRequest(http.MethodPost, "/pathql", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	if _, err := a.Authenticate(r); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("basic header: err = %v, want ErrNoCredentials", err)
	}

	// Bearer with empty token.
	r2 := httptest.NewRequest(http.MethodPost, "/pathql", nil)
	r2.Header.Set("Authorization", "Bearer ")
	if _, err := a.Authenticate(r2); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("empty bearer: err = %v, want ErrNoCredentials", err)
	}
}

func TestJWT_Garbage(t *testing.T) {
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: []byte("secret"),
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	if _, err := a.Authenticate(bearer("not-a-jwt")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

// --- config validation tests ---

func TestJWT_Config_HS256NoSecret(t *testing.T) {
	_, err := NewJWTAuthenticator(JWTConfig{
		Algorithms: []string{"HS256"},
	}, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for HS256 without secret")
	}
}

func TestJWT_Config_RS256NoJWKS(t *testing.T) {
	_, err := NewJWTAuthenticator(JWTConfig{
		Algorithms: []string{"RS256"},
	}, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for RS256 without JWKS URL")
	}
}

func TestJWT_Config_NoAlgorithms(t *testing.T) {
	_, err := NewJWTAuthenticator(JWTConfig{}, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for empty algorithms")
	}
}

func TestJWT_Config_RequireUserRowNoStore(t *testing.T) {
	_, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:     []string{"HS256"},
		HS256Secret:    []byte("secret"),
		RequireUserRow: true,
	}, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for RequireUserRow without a store")
	}
}

// --- RS256 / JWKS tests ---

// jwks is the minimal JWK Set document we serve from the test server.
type testJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type testJWKS struct {
	Keys []testJWK `json:"keys"`
}

func rsaJWKS(t *testing.T, kid string, pub *rsa.PublicKey) []byte {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := testJWKS{Keys: []testJWK{{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   n,
		E:   e,
	}}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign RS256: %v", err)
	}
	return s
}

func TestJWT_RS256_SuccessAndCaching(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	const kid = "test-key-1"
	jwksDoc := rsaJWKS(t, kid, &key.PublicKey)

	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksDoc)
	}))
	defer srv.Close()

	c, err := cache.NewEmbedded(8)
	if err != nil {
		t.Fatalf("cache.NewEmbedded: %v", err)
	}
	defer c.Close()

	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms: []string{"RS256"},
		JWKSURL:    srv.URL,
		JWKSTTL:    time.Hour,
		UserClaim:  "sub",
	}, nil, c, srv.Client())
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}

	token := signRS256(t, key, kid, jwt.MapClaims{
		"sub": "dave",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	p, err := a.Authenticate(bearer(token))
	if err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}
	if p.AppUser != "dave" {
		t.Fatalf("AppUser = %q, want %q", p.AppUser, "dave")
	}

	// Second call must be served from cache: no additional JWKS fetch.
	if _, err := a.Authenticate(bearer(token)); err != nil {
		t.Fatalf("second Authenticate: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("JWKS fetch count = %d, want 1 (second call should hit cache)", got)
	}
}

func TestJWT_RS256_UnknownKid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	jwksDoc := rsaJWKS(t, "the-known-kid", &key.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwksDoc)
	}))
	defer srv.Close()

	c, _ := cache.NewEmbedded(8)
	defer c.Close()

	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms: []string{"RS256"},
		JWKSURL:    srv.URL,
		JWKSTTL:    time.Hour,
	}, nil, c, srv.Client())
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}

	token := signRS256(t, key, "a-different-kid", jwt.MapClaims{
		"sub": "dave",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := a.Authenticate(bearer(token)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestJWT_RS256_WrongKey(t *testing.T) {
	// JWKS advertises one key; the token is signed by a different private key.
	serveKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	const kid = "shared-kid"
	jwksDoc := rsaJWKS(t, kid, &serveKey.PublicKey)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(jwksDoc)
	}))
	defer srv.Close()

	c, _ := cache.NewEmbedded(8)
	defer c.Close()

	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms: []string{"RS256"},
		JWKSURL:    srv.URL,
		JWKSTTL:    time.Hour,
	}, nil, c, srv.Client())
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}

	token := signRS256(t, signKey, kid, jwt.MapClaims{
		"sub": "dave",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := a.Authenticate(bearer(token)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestJWT_RS256_NoCache(t *testing.T) {
	// With a nil cache, JWKS is fetched on every call (no caching), but auth
	// still succeeds.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	const kid = "k"
	jwksDoc := rsaJWKS(t, kid, &key.PublicKey)
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write(jwksDoc)
	}))
	defer srv.Close()

	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms: []string{"RS256"},
		JWKSURL:    srv.URL,
		JWKSTTL:    time.Hour,
	}, nil, nil, srv.Client())
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signRS256(t, key, kid, jwt.MapClaims{
		"sub": "dave",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := a.Authenticate(bearer(token)); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := a.Authenticate(bearer(token)); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Fatalf("JWKS fetch count = %d, want 2 (no cache)", got)
	}
}

// --- RequireUserRow tests ---

func TestJWT_RequireUserRow_KnownEnabled(t *testing.T) {
	secret := []byte("secret")
	store := &fakeUserStore{users: map[string]*UserRecord{
		"alice": {UserID: 42, Username: "alice", AppUser: "app_alice", Enabled: true},
	}}
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:     []string{"HS256"},
		HS256Secret:    secret,
		RequireUserRow: true,
	}, store, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	p, err := a.Authenticate(bearer(token))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.AppUser != "app_alice" {
		t.Fatalf("AppUser = %q, want %q (from the row, not the claim)", p.AppUser, "app_alice")
	}
	if p.UserID != 42 {
		t.Fatalf("UserID = %d, want 42", p.UserID)
	}
}

func TestJWT_RequireUserRow_Unknown(t *testing.T) {
	secret := []byte("secret")
	store := &fakeUserStore{users: map[string]*UserRecord{}}
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:     []string{"HS256"},
		HS256Secret:    secret,
		RequireUserRow: true,
	}, store, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"sub": "nobody",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := a.Authenticate(bearer(token)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestJWT_RequireUserRow_Disabled(t *testing.T) {
	secret := []byte("secret")
	store := &fakeUserStore{users: map[string]*UserRecord{
		"alice": {UserID: 42, Username: "alice", AppUser: "app_alice", Enabled: false},
	}}
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:     []string{"HS256"},
		HS256Secret:    secret,
		RequireUserRow: true,
	}, store, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := a.Authenticate(bearer(token)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestJWT_RequireUserRow_EmptyClaim(t *testing.T) {
	// A token with no/empty user claim must not map to an empty AppUser.
	secret := []byte("secret")
	a, err := NewJWTAuthenticator(JWTConfig{
		Algorithms:  []string{"HS256"},
		HS256Secret: secret,
	}, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewJWTAuthenticator: %v", err)
	}
	token := signHS256(t, secret, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := a.Authenticate(bearer(token)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized for missing user claim", err)
	}
}

// satisfy the Authenticator interface at compile time.
var _ Authenticator = (*JWTAuthenticator)(nil)
