package db

import "testing"

// TestNewPoolStore checks that NewPoolStore accepts a valid auth table prefix
// and builds the expected table names from it, and rejects prefixes that are
// not identifier-safe (which is the only part interpolated into SQL). The
// DB-backed methods need a real database, so they are not exercised here; this
// test only needs the validated prefix and the constructed table names, neither
// of which touches the *sqlx.DB.
func TestNewPoolStore(t *testing.T) {
	tests := []struct {
		name         string
		prefix       string
		wantErr      bool
		wantSettings string
		wantUsers    string
	}{
		{
			name:         "default prefix",
			prefix:       "pathql_auth_",
			wantSettings: "pathql_auth_pool_settings",
			wantUsers:    "pathql_auth_users",
		},
		{
			name:         "custom prefix",
			prefix:       "myauth_",
			wantSettings: "myauth_pool_settings",
			wantUsers:    "myauth_users",
		},
		{
			name:         "leading underscore",
			prefix:       "_x_",
			wantSettings: "_x_pool_settings",
			wantUsers:    "_x_users",
		},
		{name: "leading digit", prefix: "1bad", wantErr: true},
		{name: "hyphen", prefix: "bad-prefix", wantErr: true},
		{name: "quote injection", prefix: `x"; DROP`, wantErr: true},
		{name: "empty", prefix: "", wantErr: true},
		{name: "space", prefix: "bad prefix", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// A nil *sqlx.DB is fine: NewPoolStore only validates the prefix and
			// builds the table names, it does not touch the database.
			s, err := NewPoolStore(nil, tc.prefix)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewPoolStore(%q) error = nil, want error", tc.prefix)
				}
				if s != nil {
					t.Fatalf("NewPoolStore(%q) store = %v, want nil on error", tc.prefix, s)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewPoolStore(%q) error = %v, want nil", tc.prefix, err)
			}
			if s.settingsTable != tc.wantSettings {
				t.Errorf("settingsTable = %q, want %q", s.settingsTable, tc.wantSettings)
			}
			if s.usersTable != tc.wantUsers {
				t.Errorf("usersTable = %q, want %q", s.usersTable, tc.wantUsers)
			}
		})
	}
}
