module github.com/mevdschee/pathql-go

go 1.24.0

require (
	dbml-tools v0.9.2
	github.com/BurntSushi/toml v0.3.1
	github.com/go-sql-driver/mysql v1.8.1
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/jmoiron/sqlx v1.2.0
	github.com/lib/pq v1.10.9
	github.com/mevdschee/pathsqlx v0.2.1
	github.com/mevdschee/tqmemory v0.0.1
	golang.org/x/crypto v0.47.0
)

// dbml-tools publishes its module under the bare path "dbml-tools", so it is
// pulled from its GitHub repository at a tagged version via a versioned replace
// rather than required by URL.
replace dbml-tools => github.com/mevdschee/dbml-tools v0.9.2

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/iancoleman/orderedmap v0.0.0-20190318233801-ac98e3ecb4b0 // indirect
	github.com/xwb1989/sqlparser v0.0.0-20180606152119-120387863bf2 // indirect
)
