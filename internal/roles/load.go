package roles

import (
	"context"
	"fmt"
	"regexp"

	"github.com/jmoiron/sqlx"
)

// authPrefixRe validates the auth table prefix before it is interpolated into a
// table name. Mirrors internal/auth's tablePrefixRe: it permits upper case
// because it names a table, not a managed role.
var authPrefixRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// LoadAndCompute reads the catalog and auth tables over db, assembles Inputs,
// and returns the diff from Compute. It only reads the catalog, which the
// baseline connection can do; it never executes role DDL.
//
// authPrefix is the auth table prefix (e.g. "pathql_auth_") and is validated
// against ^[A-Za-z_][A-Za-z0-9_]*$ before being interpolated into the users
// table name; every other value is bound. managedPrefix is the managed-role
// prefix and readerRole is the shared read group, both passed through to
// Compute. password is passed through to Inputs.Password (non-nil to make the
// DDL set each role's login password).
func LoadAndCompute(ctx context.Context, db *sqlx.DB, authPrefix, managedPrefix, readerRole string, password func(role string) string) (Plan, error) {
	if !authPrefixRe.MatchString(authPrefix) {
		return Plan{}, fmt.Errorf("roles: invalid auth prefix %q: must match %s", authPrefix, authPrefixRe.String())
	}

	// Existing managed roles: pg_roles names matching the managed prefix.
	var existingRoles []string
	if err := db.SelectContext(ctx, &existingRoles,
		`SELECT rolname FROM pg_roles WHERE rolname LIKE $1`,
		managedPrefix+"%",
	); err != nil {
		return Plan{}, fmt.Errorf("roles: loading existing roles: %w", err)
	}

	// Expected users: ids of enabled rows in <authPrefix>users. The prefix is
	// validated above and interpolated; nothing else is.
	usersTable := authPrefix + "users"
	var expectedUserIDs []int64
	if err := db.SelectContext(ctx, &expectedUserIDs,
		fmt.Sprintf(`SELECT id FROM %s WHERE enabled`, usersTable),
	); err != nil {
		return Plan{}, fmt.Errorf("roles: loading expected users: %w", err)
	}

	// Reader members: managed roles already granted the reader group.
	var memberRoles []string
	if err := db.SelectContext(ctx, &memberRoles,
		`SELECT m.rolname
		   FROM pg_auth_members am
		   JOIN pg_roles g ON g.oid = am.roleid
		   JOIN pg_roles m ON m.oid = am.member
		  WHERE g.rolname = $1`,
		readerRole,
	); err != nil {
		return Plan{}, fmt.Errorf("roles: loading reader members: %w", err)
	}

	readerMembers := make(map[string]bool, len(memberRoles))
	for _, name := range memberRoles {
		readerMembers[name] = true
	}

	return Compute(Inputs{
		Prefix:          managedPrefix,
		ReaderRole:      readerRole,
		ExistingRoles:   existingRoles,
		ExpectedUserIDs: expectedUserIDs,
		ReaderMembers:   readerMembers,
		Password:        password,
	})
}
