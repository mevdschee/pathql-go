package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mevdschee/pathql-go/internal/cache"
)

// bearerPrefix is the (case-insensitive) Authorization scheme for JWTs.
const bearerPrefix = "Bearer "

// defaultUserClaim is the claim mapped to Principal.AppUser when none is set.
const defaultUserClaim = "sub"

// maxJWKSBytes caps the JWKS document we will read from the network, defending
// against an oversized or malicious endpoint.
const maxJWKSBytes = 1 << 20 // 1 MiB

// JWTConfig configures the JWT bearer authenticator.
type JWTConfig struct {
	Algorithms     []string      // allowed alg(s), e.g. ["HS256"] or ["RS256"]
	Issuer         string        // expected iss ("" = skip)
	Audience       string        // expected aud ("" = skip)
	UserClaim      string        // claim mapped to AppUser (default "sub")
	HS256Secret    []byte        // for HS256
	JWKSURL        string        // for RS256/ES256
	JWKSTTL        time.Duration // cache TTL for fetched JWKS
	RequireUserRow bool          // claim must match an enabled user row
}

// JWTAuthenticator authenticates requests bearing a JWT access token. It
// verifies the signature against the configured algorithm(s) (HS256 with a
// shared secret, or RS256/ES256 with a public key fetched from a JWKS endpoint),
// enforces exp/nbf and optional iss/aud, then maps a claim to the Principal.
//
// Every verification failure collapses to the generic ErrUnauthorized so the
// client never learns which check failed.
type JWTAuthenticator struct {
	cfg        JWTConfig
	store      UserStore
	cache      cache.Cache
	httpClient *http.Client

	// usesSecret is true when any configured algorithm is HMAC-based (HS*),
	// meaning HS256Secret is the verification key. usesJWKS is true when any is
	// asymmetric (RS*/ES*/PS*), meaning the key comes from JWKSURL.
	usesSecret bool
	usesJWKS   bool

	// parserOpts are the jwt/v5 parser options (valid methods + iss/aud).
	parserOpts []jwt.ParserOption
}

// NewJWTAuthenticator builds a JWTAuthenticator. store may be nil when
// RequireUserRow is false. cache may be nil to disable JWKS caching. httpClient
// may be nil (http.DefaultClient is used) and is only consulted for JWKS.
//
// It returns an error if the configuration is internally inconsistent: no
// algorithms, an HMAC algorithm without a secret, an asymmetric algorithm
// without a JWKS URL, or RequireUserRow without a store.
func NewJWTAuthenticator(cfg JWTConfig, store UserStore, c cache.Cache, httpClient *http.Client) (*JWTAuthenticator, error) {
	if len(cfg.Algorithms) == 0 {
		return nil, errors.New("auth: jwt: at least one algorithm must be configured")
	}

	a := &JWTAuthenticator{
		cfg:        cfg,
		store:      store,
		cache:      c,
		httpClient: httpClient,
	}
	if a.httpClient == nil {
		a.httpClient = http.DefaultClient
	}
	if a.cfg.UserClaim == "" {
		a.cfg.UserClaim = defaultUserClaim
	}

	for _, alg := range cfg.Algorithms {
		switch {
		case strings.HasPrefix(alg, "HS"):
			a.usesSecret = true
		case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "ES"), strings.HasPrefix(alg, "PS"):
			a.usesJWKS = true
		case strings.EqualFold(alg, "none"):
			// The unsecured "none" algorithm is never acceptable.
			return nil, fmt.Errorf("auth: jwt: algorithm %q is not allowed", alg)
		default:
			return nil, fmt.Errorf("auth: jwt: unsupported algorithm %q", alg)
		}
	}

	if a.usesSecret && len(cfg.HS256Secret) == 0 {
		return nil, errors.New("auth: jwt: an HS* algorithm is configured but no HS256 secret was provided")
	}
	if a.usesJWKS && cfg.JWKSURL == "" {
		return nil, errors.New("auth: jwt: an RS*/ES* algorithm is configured but no JWKS URL was provided")
	}
	if cfg.RequireUserRow && store == nil {
		return nil, errors.New("auth: jwt: RequireUserRow is set but no user store was provided")
	}

	// Restrict accepted signing methods to exactly those configured. This is the
	// primary defense against algorithm-confusion attacks.
	opts := []jwt.ParserOption{jwt.WithValidMethods(cfg.Algorithms)}
	if cfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(cfg.Issuer))
	}
	if cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(cfg.Audience))
	}
	a.parserOpts = opts

	return a, nil
}

// Authenticate resolves a Bearer JWT to a Principal. A missing or non-Bearer
// Authorization header -> ErrNoCredentials so the chain tries the next method.
// Any verification failure -> ErrUnauthorized (generic).
func (a *JWTAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	tokenStr := extractBearer(r)
	if tokenStr == "" {
		return nil, ErrNoCredentials
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, a.keyFunc(r), a.parserOpts...)
	if err != nil || !token.Valid {
		return nil, ErrUnauthorized
	}

	// Belt-and-suspenders enforcement of iss/aud in addition to the parser
	// options above. The parser already rejects mismatches when configured;
	// this guards against any future change to the option wiring.
	if a.cfg.Issuer != "" {
		if iss, _ := claims.GetIssuer(); iss != a.cfg.Issuer {
			return nil, ErrUnauthorized
		}
	}
	if a.cfg.Audience != "" {
		aud, _ := claims.GetAudience()
		if !containsString(aud, a.cfg.Audience) {
			return nil, ErrUnauthorized
		}
	}

	claimValue, ok := stringClaim(claims, a.cfg.UserClaim)
	if !ok || claimValue == "" {
		// No usable identity in the token.
		return nil, ErrUnauthorized
	}

	if a.cfg.RequireUserRow {
		rec, err := a.store.LookupUserByUsername(r.Context(), claimValue)
		if err != nil || rec == nil || !rec.Enabled {
			return nil, ErrUnauthorized
		}
		return &Principal{AppUser: rec.AppUser, UserID: rec.UserID}, nil
	}

	return &Principal{AppUser: claimValue}, nil
}

// keyFunc returns the jwt/v5 key-resolution function for this request. It
// selects the verification key based on the token's signing method: the shared
// secret for HMAC, or a JWKS-derived public key for RSA/ECDSA. The token header
// alg has already been constrained by WithValidMethods, so the method type here
// is one of the configured algorithms.
func (a *JWTAuthenticator) keyFunc(r *http.Request) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			if !a.usesSecret {
				return nil, errors.New("hmac not configured")
			}
			return a.cfg.HS256Secret, nil
		case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodECDSA:
			if !a.usesJWKS {
				return nil, errors.New("asymmetric algorithm not configured")
			}
			kid, _ := token.Header["kid"].(string)
			return a.publicKeyForKid(r, kid)
		default:
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
	}
}

// publicKeyForKid fetches (or reads from cache) the JWKS document and returns
// the public key whose kid matches. When the token carries no kid and the set
// has exactly one key, that key is used.
func (a *JWTAuthenticator) publicKeyForKid(r *http.Request, kid string) (any, error) {
	raw, err := a.fetchJWKS(r)
	if err != nil {
		return nil, err
	}
	var set jwkSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, err
	}

	var match *jwk
	for i := range set.Keys {
		k := &set.Keys[i]
		if kid != "" {
			if k.Kid == kid {
				match = k
				break
			}
			continue
		}
		// No kid in the token: only acceptable if the set has a single key.
		if len(set.Keys) == 1 {
			match = k
			break
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no JWKS key matches kid %q", kid)
	}
	return match.publicKey()
}

// fetchJWKS returns the raw JWKS bytes, using the cache when available. On a
// cache miss it performs a single fetch and stores the result.
func (a *JWTAuthenticator) fetchJWKS(r *http.Request) ([]byte, error) {
	cacheKey := jwksCacheKey(a.cfg.JWKSURL)

	if a.cache != nil {
		if v, ok, err := a.cache.Get(cacheKey); err == nil && ok && len(v) > 0 {
			return v, nil
		}
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return nil, err
	}

	if a.cache != nil {
		// Best effort: a cache write failure must not fail authentication.
		_ = a.cache.Set(cacheKey, body, a.cfg.JWKSTTL)
	}
	return body, nil
}

// --- JWKS parsing (stdlib only) ---

// jwkSet is a JSON Web Key Set document.
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// jwk is a single JSON Web Key. Only the fields needed for RSA and EC public
// keys are decoded.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	X string `json:"x"`
	Y string `json:"y"`
}

// publicKey builds the crypto public key for this JWK using only the stdlib.
func (k *jwk) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		return k.rsaPublicKey()
	case "EC":
		return k.ecPublicKey()
	default:
		return nil, fmt.Errorf("unsupported JWK key type %q", k.Kty)
	}
}

func (k *jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	if k.N == "" || k.E == "" {
		return nil, errors.New("RSA JWK missing n or e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode RSA n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode RSA e: %w", err)
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() > (1<<31-1) || e.Int64() <= 0 {
		return nil, errors.New("RSA JWK exponent out of range")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}, nil
}

func (k *jwk) ecPublicKey() (*ecdsa.PublicKey, error) {
	if k.X == "" || k.Y == "" {
		return nil, errors.New("EC JWK missing x or y")
	}
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode EC x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode EC y: %w", err)
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("EC JWK point is not on the curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// --- small helpers ---

// extractBearer returns the token from an "Authorization: Bearer <token>"
// header, or "" if absent, not Bearer, or empty.
func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) <= len(bearerPrefix) {
		return ""
	}
	if !strings.EqualFold(h[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(h[len(bearerPrefix):])
}

// jwksCacheKey derives a stable cache key from the JWKS URL.
func jwksCacheKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return "jwks:" + hex.EncodeToString(sum[:])
}

// stringClaim reads a string-valued claim from a MapClaims.
func stringClaim(claims jwt.MapClaims, name string) (string, bool) {
	v, ok := claims[name]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// containsString reports whether s is in list.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
