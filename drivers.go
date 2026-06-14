package main

// Database drivers are blank-imported so their database/sql driver names are
// registered for whatever Driver the config selects. PostgreSQL ("postgres",
// via lib/pq) is the primary target; MySQL/MariaDB ("mysql") is also supported.
import (
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)
