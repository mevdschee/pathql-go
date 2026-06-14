package auth

import "testing"

// TestNewUserAdminValidPrefix checks that a valid table prefix is accepted and
// the resulting UserAdmin derives the expected table names.
func TestNewUserAdminValidPrefix(t *testing.T) {
	// db is nil here; the constructor only validates the prefix and stores
	// derived names, so it never touches the database.
	a, err := NewUserAdmin(nil, "pathql_auth_")
	if err != nil {
		t.Fatalf("NewUserAdmin returned error for valid prefix: %v", err)
	}
	if a == nil {
		t.Fatal("NewUserAdmin returned nil UserAdmin for valid prefix")
	}
	if got, want := a.usersTable, "pathql_auth_users"; got != want {
		t.Errorf("usersTable = %q, want %q", got, want)
	}
	if got, want := a.keysTable, "pathql_auth_api_keys"; got != want {
		t.Errorf("keysTable = %q, want %q", got, want)
	}
}

// TestNewUserAdminInvalidPrefix checks that prefixes which are not strict,
// identifier-safe tokens are rejected, including ones that would be unsafe to
// interpolate into a table name.
func TestNewUserAdminInvalidPrefix(t *testing.T) {
	bad := []string{
		"",
		"1bad",
		"bad-prefix",
		`x"; DROP`,
		"with space",
		"semi;colon",
	}
	for _, prefix := range bad {
		a, err := NewUserAdmin(nil, prefix)
		if err == nil {
			t.Errorf("NewUserAdmin(%q) = nil error, want error", prefix)
		}
		if a != nil {
			t.Errorf("NewUserAdmin(%q) returned non-nil UserAdmin on error", prefix)
		}
	}
}
