package auth

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// dummyBcryptHash is a fixed, valid bcrypt hash used to perform a throwaway
// comparison when a user is unknown or has no password set. Running the compare
// anyway keeps the response timing of "unknown user" close to that of "known
// user, wrong password", frustrating username enumeration via timing.
//
// It is computed once at package init from a constant password (and is never a
// valid credential for any real account).
var dummyBcryptHash []byte

func init() {
	h, err := bcrypt.GenerateFromPassword(
		[]byte("pathql-auth-dummy-constant-time-password"),
		bcrypt.DefaultCost,
	)
	if err != nil {
		// bcrypt.GenerateFromPassword on a short constant cannot fail in
		// practice; panic so a broken build is caught immediately rather than
		// silently weakening the timing defense.
		panic("auth: failed to precompute dummy bcrypt hash: " + err.Error())
	}
	dummyBcryptHash = h
}

// BasicAuthenticator authenticates requests using HTTP Basic credentials.
type BasicAuthenticator struct {
	store UserStore
}

// NewBasicAuthenticator builds a BasicAuthenticator backed by store.
func NewBasicAuthenticator(store UserStore) *BasicAuthenticator {
	return &BasicAuthenticator{store: store}
}

// Authenticate resolves HTTP Basic credentials to a Principal. A missing or
// non-Basic Authorization header -> ErrNoCredentials. Any verification failure
// -> ErrUnauthorized (generic). For unknown users or users without a password
// hash, a dummy bcrypt compare is still run to keep timing roughly constant.
func (a *BasicAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, ErrNoCredentials
	}

	rec, err := a.store.LookupUserByUsername(r.Context(), username)
	if err != nil || rec == nil || rec.PasswordHash == "" {
		// Unknown user or Basic disabled for this user: still spend the time of
		// a bcrypt compare, then fail generically.
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
		return nil, ErrUnauthorized
	}

	if bcrypt.CompareHashAndPassword([]byte(rec.PasswordHash), []byte(password)) != nil {
		return nil, ErrUnauthorized
	}

	if !rec.Enabled {
		return nil, ErrUnauthorized
	}

	return &Principal{
		AppUser: rec.AppUser,
		UserID:  rec.UserID,
	}, nil
}
